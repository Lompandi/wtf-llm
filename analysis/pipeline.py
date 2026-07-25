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
from fuzzer.run import CampaignConfig
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


def build_config(
    *,
    target_dir: Path,
    module: str = "snapfuzz",
    label: str = "gate8",
    a1: Path | None = None,
    replays: int = 3,
    max_buckets: int | None = None,
    repo_root: Path = REPO_ROOT,
) -> AnalysisConfig:
    """AnalysisConfig from the committed config files, nothing hardcoded."""
    import yaml

    campaign = CampaignConfig.from_yaml(
        repo_root / "config" / "fuzz.yaml", repo_root / "config" / "target.yaml"
    )
    a1 = a1 or repo_root / "artifacts" / "a1_snapshot.json"
    ref = SnapshotRef.model_validate_json(a1.read_text(encoding="utf-8"))

    target_yaml = yaml.safe_load(
        (repo_root / "config" / "target.yaml").read_text(encoding="utf-8")
    )["target"]
    binary = target_yaml.get("binary")
    entry = target_yaml.get("entry_symbol") or target_yaml.get("symbol") or "ProcessPacket"

    # symbolizer-rs prints "tlv_server.exe!Func"; the module prefix is the binary's
    # own filename, not wtf's --name.
    prefix = Path(binary).stem if binary else module

    return AnalysisConfig(
        target_dir=target_dir,
        module=module,
        campaign=campaign,
        space=AddressSpace(prefix, ref.module_base, ref.ghidra_image_base),
        out_dir=repo_root / "artifacts" / "runs" / label,
        workdir=repo_root / "artifacts" / "analysis" / label,
        a2_cache=repo_root / "artifacts" / "a2_pseudoc_module.sqlite",
        data_symbols=repo_root / "artifacts" / "a6_data_symbols.json",
        replays=replays,
        entry_symbol=entry,
        max_buckets=max_buckets,
        target_binary=(repo_root / binary) if binary else None,
        module_prefix=prefix,
    )


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target-dir", type=Path, required=True)
    ap.add_argument("--module", default="snapfuzz")
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
