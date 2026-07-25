"""The slow clock, as a separate process (CLAUDE.md CP7, section 12.2).

Watches aggregate coverage, and on plateau generates seeds and publishes them to
the spool the master's `CustomMutator_t` drains.

**Why a separate process, restated because it is the whole design.** The master
is on the fast path -- it serves test-cases to every worker -- so an LLM call
inside it stalls the entire pool. A worker is wrong too: each sees only its own
coverage, so a plateau judged there is judged on a fraction of the campaign. A
separate process can also be restarted or paused without stopping the campaign.

**Event-driven, never a fixed timer** (CP7). The trigger is a plateau measured in
executions, or a crash-bucket count over threshold.

Coverage is read the only way it can be (D-021, D-033): new-coverage events are
counted from ``outputs/``, and the frontier is computed from `--trace-type=cov`
traces regenerated over the corpus. Both are master-side and therefore aggregate.

The timing log is not decoration. GATE 7 requires showing the fast loop never
stalled on the LLM, and since this process is the only place an LLM call happens,
its own latencies plus the fuzzer's uninterrupted throughput are the evidence.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from arch.addr import AddressSpace
from arch.contracts import SeedRecord, SnapshotRef
from engine_bridge.plateau import (
    BlockGraph,
    PlateauDetector,
    compute_frontier,
    parse_cov_traces,
    summarise,
)
from fuzzer.corpus import Corpus
from llm.client import LlmClient, LlmError
from llm.seed_gen import (
    SeedGenError,
    SeedGenRequest,
    generate_seeds,
    parse_target,
)
from llm.spool import SeedPublisher, SpoolFull
from prep.data_symbols import format_globals, load_globals
from prep.pseudoc_cache import PseudoCCache

REPO_ROOT = Path(__file__).resolve().parents[1]

__all__ = ["SidecarConfig", "Sidecar"]


@dataclass
class SidecarConfig:
    target_dir: Path
    wtf_exe: Path
    module: str
    a3_export: Path
    a2_cache: Path
    spool_path: Path
    artifacts_dir: Path
    space: AddressSpace
    symbol_paths: list[str] = field(default_factory=list)
    # ExportDataSymbols.java output. Optional: absent means the prompt simply
    # carries no global bounds, which degrades reasoning rather than breaking it.
    a6_data_symbols: Path | None = None

    plateau_execs_threshold: int = 50_000
    wall_clock_bound_s: float = 900.0
    tick_interval_s: float = 15.0
    seeds_per_call: int = 8
    # Independent LLM samples per plateau, unioned. >1 because a single draw at
    # the temperature this role uses is high-variance (D-048).
    samples_per_round: int = 3
    max_calls: int = 20
    backend: str = "bochscpu"
    example_seed: bytes = b""
    # Harness fields the example seed does not exhibit. Passed to the prompt
    # because a capability the model does not know about is one it cannot use.
    format_notes: str = ""


@dataclass
class Sidecar:
    config: SidecarConfig
    detector: PlateauDetector = field(init=False)
    publisher: SeedPublisher = field(init=False)
    graph: BlockGraph = field(init=False)
    events: list[dict] = field(default_factory=list, init=False)
    calls_made: int = field(default=0, init=False)
    covered_at_last_gen: int = field(default=0, init=False)
    # static_addr -> rounds that aimed at it without it ever becoming covered.
    # Retired as soon as coverage proves a branch was reached (D-044).
    attempted: dict[int, int] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        cfg = self.config
        self.detector = PlateauDetector(
            threshold_executions=cfg.plateau_execs_threshold,
            wall_clock_bound_s=cfg.wall_clock_bound_s,
        )
        self.publisher = SeedPublisher(
            spool_path=cfg.spool_path,
            provenance_log=cfg.artifacts_dir / "seed_provenance.jsonl",
        )
        self.graph = BlockGraph.from_export(cfg.a3_export)
        self.attempted = self._load_attempts()

    def _load_attempts(self) -> dict[int, int]:
        """Rebuild the attempt counter from the durable event log.

        Section 12.2 requires the sidecar to be restartable without stopping the
        campaign. A counter that lived only in memory would make a restarted
        sidecar re-try the same dead branches from scratch, so it is recovered
        from `sidecar_events.jsonl` -- which is written anyway, for provenance.
        """
        path = self.config.artifacts_dir / "sidecar_events.jsonl"
        counts: dict[int, int] = {}
        if not path.exists():
            return counts

        # Normalise to static addresses. Rounds logged before D-045 recorded
        # RVAs, because that is what the prompt showed the model; they are real
        # evidence and worth keeping, so an address that is not a known static
        # address is retried as an RVA before being discarded.
        statics = {b["static_addr"] for b in self.graph.blocks.values()}
        static_of_rva = {
            rva: b["static_addr"] for rva, b in self.graph.blocks.items()
        }

        def normalise(addr: int) -> int | None:
            if addr in statics:
                return addr
            return static_of_rva.get(addr)

        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("event") != "seeds_published":
                continue
            for raw in record.get("targets", []):
                # Older rounds logged "targets 0x12de"; newer log "0x12de".
                addr = parse_target(raw) if str(raw).startswith("targets") else None
                if addr is None:
                    try:
                        addr = int(str(raw), 16)
                    except ValueError:
                        continue
                resolved = normalise(addr)
                if resolved is None:
                    continue  # not a block we know; nothing to aim at or retire
                counts[resolved] = counts.get(resolved, 0) + 1
        return counts

    # --- coverage measurement -------------------------------------------

    def measure_coverage(self, *, label: str) -> set[int]:
        """Regenerate cov traces over the corpus and return covered RVAs.

        Runs `wtf run --trace-type=cov` over ``outputs/``. Slow -- seconds to
        minutes -- which is exactly why it belongs on the slow clock and never
        near the fast loop.
        """
        import subprocess

        cfg = self.config
        corpus = Corpus(cfg.target_dir)
        source = corpus.outputs if corpus.output_count() else corpus.inputs
        trace_dir = cfg.artifacts_dir / "cov-traces" / label
        trace_dir.mkdir(parents=True, exist_ok=True)
        for stale in trace_dir.glob("*.trace"):
            stale.unlink()  # wtf refuses to overwrite an existing trace

        import os

        env = dict(os.environ)
        parts = (p.strip().strip('"') for p in env.get("PATH", "").split(os.pathsep))
        env["PATH"] = os.pathsep.join(p for p in parts if p)
        if cfg.symbol_paths:
            env["_NT_SYMBOL_PATH"] = ";".join(cfg.symbol_paths)

        completed = subprocess.run(
            [
                str(cfg.wtf_exe), "run",
                "--name", cfg.module,
                "--state", str((cfg.target_dir / "state").resolve()),
                f"--backend={cfg.backend}",
                "--input", str(source.resolve()),
                "--limit", "10000000",
                "--trace-type=cov",
                f"--trace-path={trace_dir.resolve()}",
            ],
            cwd=cfg.target_dir,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=3600,
        )

        # Fail loudly on no traces. Returning an empty set here is the worst
        # possible outcome: the frontier comes out empty, seed generation is
        # skipped, and the campaign looks like it simply had nothing to explore.
        # Measured cause was a missing _NT_SYMBOL_PATH, which makes wtf die in
        # Init with "Could not set a breakpoint" while still exiting quietly
        # enough to look like a normal run (D-042).
        produced = list(trace_dir.glob("*.trace"))
        if not produced:
            tail = (completed.stdout or completed.stderr or "").strip()[-500:]
            raise RuntimeError(
                f"wtf run --trace-type=cov produced no traces over {source} "
                f"(rc={completed.returncode}). Coverage cannot be measured, so "
                f"the frontier would be empty and seed generation would be "
                f"skipped for the wrong reason. wtf said:\n{tail}"
            )

        return parse_cov_traces(trace_dir, cfg.space)

    # --- the loop --------------------------------------------------------

    def _log(self, kind: str, **fields) -> None:
        record = {"ts": time.time(), "clock": "slow", "event": kind, **fields}
        self.events.append(record)
        path = self.config.artifacts_dir / "sidecar_events.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fd:
            fd.write(json.dumps(record) + "\n")

    def _retire_reached_attempts(self, covered: set[int]) -> dict[int, int]:
        """Drop attempted branches that are now covered; return what is still open.

        Retiring on measured coverage is what makes the attempt counter honest:
        a branch that a seed genuinely reached must stop being reported as a
        failure, or the next round is told to avoid the one thing that worked.
        """
        static_of = {r: b["static_addr"] for r, b in self.graph.blocks.items()}
        covered_static = {static_of[r] for r in covered if r in static_of}
        reached = [addr for addr in self.attempted if addr in covered_static]
        for addr in reached:
            del self.attempted[addr]
        if reached:
            self._log("attempts_retired", reached=[hex(a) for a in reached])
        return dict(self.attempted)

    def _globals_table(self) -> str:
        """Global bounds for the prompt, or "" if the export is unavailable.

        Deliberately non-fatal. This is reasoning context, not a contract: a
        missing A6 costs the model the capacity of a table it will then have to
        guess at, which is exactly the pre-CP7 situation (D-047) and not a
        correctness failure.
        """
        path = self.config.a6_data_symbols
        if path is None or not path.exists():
            return ""
        try:
            return format_globals(load_globals(path))
        except (json.JSONDecodeError, KeyError, OSError) as exc:
            self._log("globals_unavailable", error=str(exc), path=str(path))
            return ""

    def generate_and_publish(self, *, label: str, trigger: str = "plateau") -> int:
        """One seed-generation round. Returns how many seeds were published.

        ``trigger`` records WHY the round happened and is written into the event
        log. GATE 7 asserts one round per plateau, and a hand-run ``--once`` round
        appended to the same log is indistinguishable from the detector re-firing
        unless the two are labelled apart -- which is a false alarm on a real
        check, the worst kind, because the reflex is to relax the check.
        """
        cfg = self.config
        t0 = time.time()

        covered = self.measure_coverage(label=label)
        frontier = compute_frontier(covered, self.graph, limit=12)
        attempted = self._retire_reached_attempts(covered)
        measure_s = time.time() - t0

        self._log(
            "frontier_computed",
            covered_blocks=len(covered & set(self.graph.blocks)),
            frontier=len(frontier),
            still_unreached_after_attempts=len(attempted),
            measure_seconds=round(measure_s, 2),
        )
        if not frontier:
            self._log("skipped", reason="frontier is empty")
            return 0

        corpus = Corpus(cfg.target_dir)
        summary = summarise(
            tick=self.calls_made + 1,
            covered=covered,
            frontier=frontier,
            corpus_size=corpus.output_count() or corpus.input_count(),
            crash_buckets=0,
            previous_covered=self.covered_at_last_gen,
        )

        request = SeedGenRequest(
            summary=summary,
            frontier=frontier,
            example_seed=cfg.example_seed,
            want=cfg.seeds_per_call,
            format_notes=cfg.format_notes,
            attempted=attempted,
            globals_table=self._globals_table(),
        )

        # A round is SEVERAL independent samples, unioned -- not one call.
        #
        # seed_gen runs at a high temperature because diversity of inputs is what
        # the role is for. The cost is that the *reasoning* varies as much as the
        # output: measured on consecutive rounds against an identical frontier,
        # one sample worked out that the branch needed a global table exhausted
        # and proposed a 5-packet sequence, and the next reasoned only about a
        # single command and proposed nothing longer than one packet (D-048).
        #
        # Independent samples recover the diversity without betting the round on
        # one draw, and they are free in the sense that matters: this is the slow
        # clock, so the fuzzer never waits for any of it (RULE 1).
        llm_t0 = time.time()
        records: list[SeedRecord] = []
        seen: set[bytes] = set()
        failures: list[str] = []

        with PseudoCCache(cfg.a2_cache) as cache, LlmClient.from_config() as client:
            for sample in range(1, cfg.samples_per_round + 1):
                try:
                    produced = generate_seeds(request, client, cache)
                except (SeedGenError, LlmError) as exc:
                    failures.append(f"sample {sample}: {exc}")
                    continue
                fresh = [r for r in produced if r.seed_bytes not in seen]
                seen.update(r.seed_bytes for r in fresh)
                records.extend(fresh)
                self._log(
                    "sample_done",
                    sample=sample,
                    of=cfg.samples_per_round,
                    produced=len(produced),
                    new=len(fresh),
                )

        llm_s = time.time() - llm_t0

        if not records:
            self._log("seed_gen_failed", error="; ".join(failures) or "no seeds")
            return 0
        if failures:
            self._log("samples_failed", count=len(failures), detail=failures[:3])

        try:
            result = self.publisher.publish(records)
        except SpoolFull as exc:
            self._log("spool_full", error=str(exc))
            return 0

        self.calls_made += 1
        self.covered_at_last_gen = len(covered)

        # Count what this round aimed at, so the next round can be told what did
        # not land. Only addresses the model actually named are counted.
        aimed: list[int] = []
        for record in records:
            addr = parse_target(record.rationale or "")
            if addr is not None:
                self.attempted[addr] = self.attempted.get(addr, 0) + 1
                aimed.append(addr)

        self._log(
            "seeds_published",
            call=self.calls_made,
            trigger=trigger,
            seeds=result.count,
            samples=cfg.samples_per_round,
            duplicates_skipped=result.skipped_duplicates,
            llm_seconds=round(llm_s, 2),
            spool_depth=result.spool_depth,
            targets=[hex(a) for a in aimed],
        )
        return result.count

    def watch_state_file(self, state_path: Path, *, deadline: float) -> None:
        """Poll a campaign state file until ``deadline``.

        The interface between scheduler and sidecar is a **file**, not IPC,
        because section 12.2 requires the sidecar to be a separate process and a
        file keeps that boundary trivial: the scheduler owns the master and knows
        the execution count, and writes it; the sidecar reads it.

        Executions come from the scheduler rather than being measured here
        because the master's stdout is unreliable (D-033) and only the scheduler
        sees whatever stat lines do arrive.
        """

        def read_state() -> tuple[int, int]:
            try:
                data = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return 0, 0
            return int(data.get("executions", 0)), int(
                data.get("new_coverage_events", 0)
            )

        self.run(deadline=deadline, execs_of=read_state)

    def run(self, *, deadline: float, execs_of) -> None:
        """Watch for plateau until ``deadline``.

        ``execs_of`` returns (executions, new_coverage_events) from the campaign
        -- injected so the sidecar does not need to own the master.
        """
        self._log(
            "started",
            plateau_execs_threshold=self.config.plateau_execs_threshold,
            spool=str(self.config.spool_path),
        )

        while time.time() < deadline:
            time.sleep(self.config.tick_interval_s)
            executions, events = execs_of()
            state = self.detector.observe(executions, events, time.time())

            if not self.detector.should_fire(state):
                continue
            if self.calls_made >= self.config.max_calls:
                self._log("budget_exhausted", calls=self.calls_made)
                continue

            self._log("plateau", reason=state.reason, executions=executions)
            self.generate_and_publish(label=f"gen{self.calls_made + 1:02d}")

        self._log("stopped", calls=self.calls_made)


def build_config(
    *,
    target_dir: Path,
    module: str,
    a1: Path,
    repo_root: Path = REPO_ROOT,
    **overrides,
) -> SidecarConfig:
    import yaml

    from fuzzer.run import resolve_symbol_paths

    fuzz = yaml.safe_load((repo_root / "config" / "fuzz.yaml").read_text("utf-8"))
    target = yaml.safe_load((repo_root / "config" / "target.yaml").read_text("utf-8"))
    ref = SnapshotRef.model_validate_json(a1.read_text(encoding="utf-8"))
    space = AddressSpace(module, ref.module_base, ref.ghidra_image_base)

    symbol_paths = resolve_symbol_paths(
        fuzz, target["target"], target_dir=target_dir, repo_root=repo_root
    )
    if os.name == "nt" and not symbol_paths:
        raise RuntimeError(
            "config/fuzz.yaml has no symbols.nt_symbol_path, so the sidecar "
            "cannot measure coverage: wtf resolves breakpoints by symbol name "
            "and would die in Init (D-023, D-042)"
        )

    inputs = sorted((target_dir / "inputs").glob("*"))
    example = inputs[0].read_bytes() if inputs else b"{}"

    cfg = SidecarConfig(
        target_dir=target_dir,
        wtf_exe=repo_root / fuzz["wtf"]["binary"],
        module=module,
        a3_export=repo_root / "artifacts" / "a3_ghidra_blocks_module.json",
        a2_cache=repo_root / "artifacts" / "a2_pseudoc_module.sqlite",
        a6_data_symbols=repo_root / "artifacts" / "a6_data_symbols.json",
        spool_path=repo_root / fuzz["seed_spool"]["path"],
        artifacts_dir=repo_root / "artifacts",
        space=space,
        symbol_paths=symbol_paths,
        plateau_execs_threshold=int(fuzz["plateau"]["plateau_execs_threshold"]),
        wall_clock_bound_s=float(fuzz["plateau"]["wall_clock_bound_s"]),
        tick_interval_s=float(fuzz["plateau"]["tick_interval_s"]),
        seeds_per_call=int(fuzz["plateau"]["seeds_per_call"]),
        max_calls=int(fuzz["plateau"]["max_seed_gen_calls_per_run"]),
        example_seed=example,
        format_notes=(
            'Each packet may carry an optional integer field "WireSize". It sets '
            "how many bytes the target is TOLD arrived, independent of how many "
            "the harness actually wrote. Omit it, or use 0, for the natural size "
            "(8-byte header + body). Set it BELOW 8 to model a truncated read "
            "and exercise a header-too-small guard; set it above the real size "
            "to make the target read past the data.\n\n"
            "MULTI-PACKET SEQUENCES. The Packets array may hold MANY packets -- "
            "there is no limit but total size. They are delivered one after "
            "another to the SAME live process, and every effect the target has "
            "on its own state -- objects allocated, table slots filled, ids "
            "registered, counters advanced -- PERSISTS from one packet to the "
            "next within a single input. Two consequences are worth exploiting. "
            "A branch that needs an object to already exist is reached by "
            "creating it in an earlier packet and referring to it by a matching "
            "id in a later one. A branch guarded by a fixed-size table being "
            "full, or by a counter having passed a bound, is reached only by "
            "REPEATING the same kind of packet enough times in one input. "
            "Treat sequence LENGTH as a variable in its own right, not just the "
            "contents of one packet."
        ),
    )
    for key, value in overrides.items():
        if value is not None:
            setattr(cfg, key, value)
    return cfg


def main(argv: list[str] | None = None) -> int:
    """Run one generation round immediately -- for testing the slow clock alone."""
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target-dir", type=Path, required=True)
    ap.add_argument("--module", default="snapfuzz")
    ap.add_argument("--a1", type=Path, default=REPO_ROOT / "artifacts/a1_snapshot.json")
    ap.add_argument("--once", action="store_true", help="generate now, ignore plateau")
    ap.add_argument("--seeds", type=int)
    ap.add_argument(
        "--watch",
        type=Path,
        help="campaign state file to poll; runs the supervised plateau loop",
    )
    ap.add_argument("--minutes", type=float, default=10.0)
    ap.add_argument("--plateau-execs", type=int)
    ap.add_argument(
        "--samples",
        type=int,
        help="independent LLM samples per plateau, unioned (D-048)",
    )
    args = ap.parse_args(argv)

    # symbol_paths comes from config/fuzz.yaml via build_config. It used to be
    # assigned here as a literal, which quietly overrode the config file -- and
    # then hid D-042, because the sidecar looked configured when it was not.
    cfg = build_config(
        target_dir=args.target_dir,
        module=args.module,
        a1=args.a1,
        seeds_per_call=args.seeds,
        samples_per_round=args.samples,
        plateau_execs_threshold=args.plateau_execs,
    )

    sidecar = Sidecar(cfg)

    if args.once:
        published = sidecar.generate_and_publish(label="manual", trigger="manual")
        print(f"published {published} seeds to {cfg.spool_path}")
        for event in sidecar.events:
            print(f"  {event['event']}: "
                  + ", ".join(f"{k}={v}" for k, v in event.items()
                              if k not in ("ts", "clock", "event")))
        return 0 if published else 1

    if args.watch:
        print(f"sidecar watching {args.watch} for {args.minutes:.0f} min "
              f"(plateau at {cfg.plateau_execs_threshold} execs)", flush=True)
        sidecar.watch_state_file(args.watch, deadline=time.time() + args.minutes * 60)
        print(f"sidecar done; {sidecar.calls_made} generation round(s)", flush=True)
        return 0

    print("pass --once or --watch <state file>")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
