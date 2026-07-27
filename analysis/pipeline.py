"""The CP8 analysis pipeline, wired (CLAUDE.md CP8, edges 33-37).

One entry point that runs the five stages in the order section 3.2 gives them:

    A5 crashes -> dedup -> classify -> replay -> trace -> reverse

and writes each stage's output as JSON so every stage stays independently
runnable and testable (section 6). Triage (CP9) consumes these files; it does not
re-run any of this.

**NO LLM ANYWHERE IN THIS MODULE OR ANYTHING IT CALLS**, except
:mod:`llm.ghidra_mcp`, which is a decompiler client (see analysis/reverse.py).
GATE 8 asserts this.

Cost, and why the order matters
-------------------------------
Dedup runs first and is nearly free: it needs one batched symbolizer-rs call over
the fault addresses, measured at 52 addresses in 0.0 s. Everything after it runs
**per bucket**, and replay plus tracing costs seconds of emulation each. On the
measured set that is the difference between 4 units of work and 53 -- which is
the whole reason section 10 lists "sending un-deduplicated crashes onward" as an
anti-pattern, and it applies to our own expensive stages, not just to the LLM.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from arch.addr import AddressSpace
from arch.contracts import CrashBucket, SnapshotRef, TraceRef
from analysis.classify import Classification, classify
from analysis.dedup import SymbolizingResolver, bucket_crashes
from analysis.replay import ReplayPlan, replay_bucket
from analysis.reverse import CrashContext, assemble_context
from analysis.trace import (
    TraceError,
    TraceTarget,
    generate_trace,
    symbolize,
)
from arch.contracts import ReplayResult
from engine_bridge.crash_watch import CrashWatcher
from fuzzer.run import CampaignConfig, harness_env
from prep.pseudoc_cache import PseudoCCache

REPO_ROOT = Path(__file__).resolve().parents[1]

__all__ = ["AnalysisConfig", "AnalysisResult", "analyse"]


@dataclass
class AnalysisConfig:
    target_dir: Path
    module: str
    campaign: CampaignConfig
    space: AddressSpace
    out_dir: Path
    workdir: Path
    a2_cache: Path
    data_symbols: Path | None = None
    replays: int = 3
    entry_symbol: str = "ProcessPacket"
    max_buckets: int | None = None
    # The target's PE on disk, for disassembling a fault that lands inside it.
    # None disables disassembly rather than reading bytes we cannot vouch for
    # (analysis/classify.py read_module_bytes).
    target_binary: Path | None = None
    # Prefix symbolizer-rs uses for our module, e.g. "tlv_server" matches
    # "tlv_server.exe!ProcessPacket+0x5". Not the same string as `module`, which
    # is wtf's --name.
    module_prefix: str = "tlv_server"

    @property
    def state_dir(self) -> Path:
        return self.target_dir / "state"

    @property
    def crash_dump(self) -> Path:
        return self.state_dir / "mem.dmp"

    def trace_target(self) -> TraceTarget:
        return TraceTarget(
            wtf_exe=self.campaign.wtf_exe,
            target_dir=self.target_dir,
            name=self.module,
            state_dir=self.state_dir,
            symbol_paths=self.campaign.symbol_paths,
        )


@dataclass
class AnalysisResult:
    buckets: list[CrashBucket]
    classifications: list[Classification]
    replays: list[ReplayResult]
    traces: list[TraceRef]
    contexts: list[CrashContext]
    crash_count: int

    def summary(self) -> dict:
        return {
            "crashes": self.crash_count,
            "buckets": len(self.buckets),
            "reproduced": sum(1 for r in self.replays if r.reproduced),
            "deterministic": sum(1 for r in self.replays if r.deterministic),
            "traces": len(self.traces),
            "reached_fuzz_entry": sum(1 for t in self.traces if t.reached_fuzz_entry),
            "contexts_with_pseudo_c": sum(
                1 for c in self.contexts if c.pseudo_c is not None
            ),
        }


def _representative_path(bucket: CrashBucket, crashes_dir: Path) -> Path | None:
    """Find the file a bucket's representative came from.

    Matched on the fault address in the filename plus the exact bytes, because the
    address alone can repeat across fault types. Returning None is meaningful --
    the file may have been pruned -- and callers must not treat it as "did not
    reproduce" (see analysis/replay.py).
    """
    needle = f"{bucket.representative.fault_runtime_addr:#x}"
    for path in sorted(crashes_dir.glob("*")):
        if not path.is_file() or needle not in path.name:
            continue
        if path.read_bytes() == bucket.representative.input_bytes:
            return path
    return None


def analyse(config: AnalysisConfig) -> AnalysisResult:
    """Run the whole CP8 chain and write per-stage artifacts."""
    config.out_dir.mkdir(parents=True, exist_ok=True)
    config.workdir.mkdir(parents=True, exist_ok=True)
    crashes_dir = config.target_dir / "crashes"

    # --- edge 33: A5 -> dedup ------------------------------------------
    watcher = CrashWatcher(
        crashes_dir=crashes_dir, space=config.space, backend="bochscpu"
    )
    records = watcher.collect_all()
    resolver = SymbolizingResolver(
        crash_dump=config.crash_dump,
        workdir=config.workdir / "symbols",
        symbol_paths=config.campaign.symbol_paths,
    )
    buckets = bucket_crashes(records, resolver=resolver, space=config.space)
    if config.max_buckets is not None:
        buckets = buckets[: config.max_buckets]

    fault_symbols = resolver.resolve([r.fault_runtime_addr for r in records])

    classifications: list[Classification] = []
    replays: list[ReplayResult] = []
    traces: list[TraceRef] = []
    contexts: list[CrashContext] = []

    target = config.trace_target()
    plan_workdir = config.workdir / "replay"

    with PseudoCCache(config.a2_cache) as cache:
        for bucket in buckets:
            record = bucket.representative
            symbol = fault_symbols.get(record.fault_runtime_addr)

            # --- edge 34: dedup -> classification ----------------------
            classifications.append(
                classify(
                    record,
                    bucket_id=bucket.bucket_id,
                    space=config.space,
                    target_binary=config.target_binary,
                    fault_symbol=symbol.function_key if symbol else None,
                )
            )

            input_path = _representative_path(bucket, crashes_dir)
            if input_path is None:
                replays.append(
                    ReplayResult(
                        bucket_id=bucket.bucket_id,
                        reproduced=False,
                        deterministic=False,
                        replays=0,
                        backend="bochscpu",
                        notes=(
                            "the representative's crash file could not be located, "
                            "so it was NOT replayed. This is an absence of "
                            "evidence, not a non-reproduction."
                        ),
                    )
                )
                contexts.append(
                    CrashContext(
                        bucket_id=bucket.bucket_id,
                        notes=["no input file, so no trace and no static context"],
                    )
                )
                continue

            # --- edge 35: classification -> replay ---------------------
            replays.append(
                replay_bucket(
                    bucket,
                    input_path,
                    ReplayPlan(
                        target=target,
                        workdir=plan_workdir / bucket.bucket_id,
                        replays=config.replays,
                    ),
                )
            )

            # --- edges 36/36b: replay -> trace -> symbolize ------------
            trace_ref = _trace_bucket(bucket, input_path, config, target)
            if trace_ref is not None:
                traces.append(trace_ref)

            # --- edges 37/37b: -> reverse-engineering context ----------
            contexts.append(
                assemble_context(
                    record,
                    bucket_id=bucket.bucket_id,
                    cache=cache,
                    trace_ref=trace_ref,
                    space=config.space,
                    module_prefix=config.module_prefix,
                    data_symbols=config.data_symbols,
                )
            )

    result = AnalysisResult(
        buckets=buckets,
        classifications=classifications,
        replays=replays,
        traces=traces,
        contexts=contexts,
        crash_count=len(records),
    )
    _write(config.out_dir, result)
    return result


def _trace_bucket(
    bucket: CrashBucket,
    input_path: Path,
    config: AnalysisConfig,
    target: TraceTarget,
) -> TraceRef | None:
    """rip trace + symbolization for one bucket. Returns None on failure."""
    trace_dir = config.workdir / "traces" / bucket.bucket_id
    try:
        raw = generate_trace(
            target, input_path, trace_dir, trace_type="rip", backend="bochscpu",
            limit=200_000_000,
        )
        symbolized = symbolize(
            raw,
            config.out_dir / "traces" / f"{bucket.bucket_id}.rip.txt",
            crash_dump=config.crash_dump,
            symbol_paths=config.campaign.symbol_paths,
            style="full",
        )
    except TraceError:
        return None

    # reached_fuzz_entry is a SANITY CHECK, never a default: a harness that runs
    # and reports coverage without entering the parser is the classic silent
    # failure (CP4), and a trace that never mentions the entry means this crash
    # says nothing about the target.
    text = symbolized.read_text(encoding="utf-8", errors="replace")
    return TraceRef(
        bucket_id=bucket.bucket_id,
        trace_type="rip",
        raw_path=str(raw),
        symbolized_path=str(symbolized),
        reached_fuzz_entry=config.entry_symbol in text,
    )


def _write(out_dir: Path, result: AnalysisResult) -> None:
    def dump(name: str, models) -> None:
        (out_dir / name).write_text(
            json.dumps([json.loads(m.model_dump_json()) for m in models], indent=2),
            encoding="utf-8",
        )

    dump("buckets.json", result.buckets)
    dump("classifications.json", result.classifications)
    dump("replays.json", result.replays)
    dump("traces.json", result.traces)
    dump("contexts.json", result.contexts)
    (out_dir / "summary.json").write_text(
        json.dumps(result.summary(), indent=2), encoding="utf-8"
    )


class TargetMismatch(RuntimeError):
    """`config/target.yaml` describes a different target than the one being analysed.

    Its own class because the alternative is what this function used to do, and what
    it used to do was the worst defect in the project: continue, quietly, on the
    wrong program (D-073).
    """


def build_config(
    *,
    target_dir: Path,
    module: str = "snapfuzz",
    label: str = "gate8",
    a1: Path | None = None,
    replays: int = 3,
    max_buckets: int | None = None,
    repo_root: Path = REPO_ROOT,
    # THE TARGET'S IDENTITY. Supplied by the caller for any target other than the
    # one `config/target.yaml` describes; see the docstring for why these exist.
    binary: Path | None = None,
    entry_symbol: str | None = None,
    module_prefix: str | None = None,
    a2_cache: Path | None = None,
    data_symbols: Path | None = None,
    artifacts_dir: Path | None = None,
    # Opt in to reading the target's identity from `config/target.yaml` when A1 does
    # not record it. Deliberately not the default: this was the default, and it is
    # D-073. A caller that sets it is asserting "the snapshot I am pointing at really
    # is the target that file describes", which only the caller can know.
    allow_config_fallback: bool = False,
) -> AnalysisConfig:
    """AnalysisConfig for **the target named by the arguments**, not for whichever
    target `config/target.yaml` happens to describe.

    This function's docstring used to read "from the committed config files, nothing
    hardcoded", which was true and beside the point. Nothing was hardcoded *here*;
    the target's identity was read from `config/target.yaml`, which describes
    `tlv_server` specifically, and no caller could override it. Analysing any other
    target therefore produced four confident, wrong outputs and no error (D-073):

    * `module_prefix` stayed `tlv_server`, so symbolizer-rs frames reading
      `othertarget.exe!Func` matched nothing and **every crash classified as outside
      our module** -- the one signal triage leans on hardest;
    * `target_binary` pointed at `targets/tlv_server/target/tlv_server.exe`, so the
      disassembly at the fault address came from **a different PE**, producing
      plausible instructions belonging to another program;
    * `a2_cache` was tlv_server's pseudo-C, handed to the triage model as the source
      of the crash site;
    * `entry_symbol` was tlv_server's `ProcessPacket`, so "reached the fuzz entry"
      answered a question about a function the target may not even have.

    Nothing raised. The advisory came out looking exactly like a real one. That is
    why the identity is now parameters, and why disagreeing with `target.yaml` is a
    :class:`TargetMismatch` rather than a preference.
    """
    import yaml

    campaign = CampaignConfig.from_yaml(
        repo_root / "config" / "fuzz.yaml", repo_root / "config" / "target.yaml"
    )
    artifacts = artifacts_dir or (repo_root / "artifacts")
    a1 = a1 or artifacts / "a1_snapshot.json"
    ref = SnapshotRef.model_validate_json(a1.read_text(encoding="utf-8"))

    # IDENTITY RESOLUTION, in strict order of authority:
    #   1. what the caller passed -- it knows what it is analysing;
    #   2. what A1 recorded -- this run's own snapshot, written by the ingest stage;
    #   3. config/target.yaml -- ONLY when it is describing this same snapshot.
    #
    # Step 3 used to be step 1, unconditionally, which is the whole of D-073. Note
    # that `target_dir.name` is deliberately NOT the discriminator: the CP7 evidence
    # lives in `targets/snapfuzz-gate7/` and is genuinely a tlv_server snapshot, so
    # comparing directory names would reject a correct configuration. The module the
    # snapshot records is the fact that matters.
    #
    # READING config/target.yaml CORRECTLY, which is harder than it looks and which
    # the previous version of this function got wrong twice:
    #
    #   target.name    = the subject under test        -> "tlv_server"
    #   target.module  = wtf's --name, OUR Target_t    -> "snapfuzz"
    #   entry.module   = the subject under test again  -> "tlv_server"
    #   entry.symbol   = the fuzz entry                -> "ProcessPacket"
    #
    # So `module` means the FUZZER module under `target:` and the TARGET module under
    # `entry:` -- the same overload the pipeline's own `--module` flag carries. Taking
    # `target.module` as the symbolization prefix yields "snapfuzz", which matches no
    # frame symbolizer-rs will ever print.
    #
    # And the old code read `target.entry_symbol` / `target.symbol`, NEITHER of which
    # exists in this file -- both lookups missed and it fell through to the literal
    # `"ProcessPacket"` every time. It read like configuration and behaved like a
    # constant, while the `entry:` block holding the real answer went untouched.
    parsed = yaml.safe_load(
        (repo_root / "config" / "target.yaml").read_text(encoding="utf-8")
    )
    target_yaml = parsed["target"]
    entry_yaml = parsed.get("entry") or {}
    configured_binary = target_yaml.get("binary")
    # The TARGET's module, from the binary's own filename -- the string symbolizer-rs
    # prints. Never `target.module`.
    configured_module = entry_yaml.get("module") or (
        Path(configured_binary).stem if configured_binary else None
    )

    a1_module = ref.module_prefix
    prefix = module_prefix or a1_module
    if prefix is None:
        # A1 predates the module field. target.yaml is the only source left, and
        # using it is safe only if nothing contradicts it -- which, with no recorded
        # module and no explicit argument, we cannot check. So this is allowed but
        # must be a deliberate act by the caller, not a default.
        if configured_module and allow_config_fallback:
            prefix = configured_module
        else:
            raise TargetMismatch(
                f"cannot tell which module {a1.name} describes: it records no "
                f"`module` (it predates that field), and no module_prefix was "
                f"passed. Guessing from config/target.yaml would silently analyse "
                f"{configured_module!r} -- wrong symbolization prefix, wrong PE "
                f"disassembled, wrong pseudo-C handed to triage, no error (D-073). "
                f"Re-run the ingest stage to record it, pass "
                f"module_prefix=/--module-prefix, or pass "
                f"allow_config_fallback=True to accept target.yaml explicitly."
            )
    elif a1_module and configured_module and a1_module != configured_module:
        # Both sources spoke and disagreed. Whatever else is true, one of them is
        # about a different program, so nothing downstream should proceed on a guess.
        if module_prefix is None:
            raise TargetMismatch(
                f"{a1.name} is a snapshot of {a1_module!r} but config/target.yaml "
                f"describes {configured_module!r}. These are different programs; "
                f"analysing one with the other's binary and pseudo-C is D-073. Pass "
                f"module_prefix= explicitly to say which you mean."
            )

    a1_binary = Path(ref.binary) if ref.binary else None
    if a1_binary is not None and not a1_binary.is_absolute():
        a1_binary = repo_root / a1_binary
    resolved_binary = Path(binary) if binary else a1_binary
    if resolved_binary is None and configured_module == prefix and configured_binary:
        # Only when target.yaml is demonstrably describing THIS module.
        resolved_binary = repo_root / configured_binary

    entry = entry_symbol or ref.entry_symbol
    if entry is None and configured_module == prefix:
        entry = entry_yaml.get("symbol")
    if entry is None:
        raise TargetMismatch(
            f"no fuzz entry symbol for module {prefix!r}: A1 does not record one and "
            f"config/target.yaml's `entry:` block describes "
            f"{configured_module!r}. The previous version defaulted to the literal "
            f"'ProcessPacket' here, which silently answered "
            f"'did the crash reach the fuzz entry?' about a function this target may "
            f"not have (D-073). Pass entry_symbol=/--entry-symbol."
        )
    entry = entry.split("!", 1)[-1]

    # THE HARNESS ENVIRONMENT, exported process-wide so every `wtf run` this stage spawns
    # inherits it. Derived by fuzzer.run.harness_env, which is the single owner: the same
    # omission cost the campaign nothing, cost the analysis stage its trace, and cost the
    # harness-validation stage its whole purpose (D-085).
    os.environ.update(harness_env(a1, artifacts / "harness_spec.json"))

    return AnalysisConfig(
        target_dir=target_dir,
        module=module,
        campaign=campaign,
        space=AddressSpace(prefix, ref.module_base, ref.ghidra_image_base),
        out_dir=repo_root / "artifacts" / "runs" / label,
        workdir=repo_root / "artifacts" / "analysis" / label,
        a2_cache=a2_cache or (artifacts / "a2_pseudoc_module.sqlite"),
        data_symbols=data_symbols or (artifacts / "a6_data_symbols.json"),
        replays=replays,
        entry_symbol=entry,
        max_buckets=max_buckets,
        target_binary=resolved_binary,
        module_prefix=prefix,
    )


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target-dir", type=Path, required=True)
    ap.add_argument(
        "--module",
        default="snapfuzz",
        help="wtf's --name, i.e. the FUZZER module compiled into wtf.exe. NOT the "
             "target's debugger module name -- that is --module-prefix",
    )
    # The target's identity. Absent, it comes from A1; A1 not recording it is an
    # error rather than a licence to read config/target.yaml (D-073).
    ap.add_argument(
        "--module-prefix",
        default=None,
        help="the TARGET's debugger module name, e.g. 'tlv_server' for frames "
             "printed as 'tlv_server.exe!Func'. Defaults to what A1 recorded",
    )
    ap.add_argument("--target-binary", type=Path, default=None)
    ap.add_argument("--entry-symbol", default=None)
    ap.add_argument("--a1", type=Path, default=None)
    ap.add_argument("--a2-cache", type=Path, default=None)
    ap.add_argument("--data-symbols", type=Path, default=None)
    ap.add_argument(
        "--allow-config-fallback",
        action="store_true",
        help="permit reading the target's identity from config/target.yaml when A1 "
             "does not record it. Only correct if that file describes this snapshot",
    )
    ap.add_argument("--label", default="gate8")
    ap.add_argument("--replays", type=int, default=3)
    ap.add_argument(
        "--max-buckets",
        type=int,
        help="cap the buckets analysed; replay and tracing are seconds each",
    )
    args = ap.parse_args(argv)

    config = build_config(
        target_dir=args.target_dir,
        module=args.module,
        label=args.label,
        replays=args.replays,
        max_buckets=args.max_buckets,
        a1=args.a1,
        binary=args.target_binary,
        entry_symbol=args.entry_symbol,
        module_prefix=args.module_prefix,
        a2_cache=args.a2_cache,
        data_symbols=args.data_symbols,
        allow_config_fallback=args.allow_config_fallback,
    )
    result = analyse(config)

    print(f"crashes            : {result.crash_count}")
    print(f"buckets            : {len(result.buckets)}")
    for bucket in result.buckets:
        print(
            f"  {bucket.bucket_id}  hits={bucket.hit_count:<3} "
            f"[{bucket.key_kind}] {bucket.key_detail}"
        )
    summary = result.summary()
    print(f"reproduced         : {summary['reproduced']}/{len(result.replays)}")
    print(f"deterministic      : {summary['deterministic']}/{len(result.replays)}")
    print(
        f"traces             : {summary['traces']}, reached entry "
        f"{summary['reached_fuzz_entry']}"
    )
    print(f"contexts w/ pseudo-C: {summary['contexts_with_pseudo_c']}")
    print(f"wrote {config.out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
