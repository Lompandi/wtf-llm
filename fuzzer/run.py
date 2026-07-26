"""Campaign entry point: one master plus N workers (CLAUDE.md CP4).

Wires the three interfaces from section 3.2:

* **interface 1** -- startup seeds in ``inputs/``, read by the MASTER only;
* **interface 2** -- the snapshot (``state/``) and the module (``--name``),
  delivered to the master *and* every worker (edges 21a and 21b);
* **interface 3** -- the coverage ``.cov`` files, delivered to every worker by
  their presence in ``targets/<name>/coverage/``, because ``fuzz`` has no
  ``--coverage`` flag (D-017).

This module owns the child environment, because two pieces of it are
non-optional on this host and neither is wtf's fault:

* ``_NT_SYMBOL_PATH`` -- wtf resolves breakpoints by symbol name through dbgeng
  and sets no symbol path itself. Without it every worker dies in ``Init``
  (D-023).
* a ``PATH`` with stray quotes stripped (D-020).

**NO LLM ANYWHERE IN THIS MODULE.** Master and workers are both fast clock
(section 12.2). The slow clock is a separate process, arriving at CP7.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from arch.addr import AddressSpace
from arch.contracts import CoverageSummary, SnapshotRef
from engine_bridge.coverage import CoverageTracker
from engine_bridge.crash_watch import CrashWatcher
from fuzzer.corpus import Corpus, SeedSpool
from fuzzer.master import MasterProcess
from fuzzer.workers import WorkerPool

REPO_ROOT = Path(__file__).resolve().parents[1]

__all__ = ["CampaignConfig", "Campaign", "build_env", "resolve_symbol_paths"]


def resolve_symbol_paths(
    fuzz: dict,
    target: dict,
    *,
    target_dir: Path,
    repo_root: Path = REPO_ROOT,
) -> list[str]:
    """`config/fuzz.yaml` symbols.nt_symbol_path with placeholders substituted.

    Shared with the sidecar rather than duplicated. wtf resolves breakpoints by
    symbol name through dbgeng and sets no symbol path itself, so **every**
    process that launches wtf needs this -- including the sidecar's coverage
    measurement, which otherwise produces no traces and hands seed generation an
    empty frontier (D-042).

    The PDB lives beside the binary, which need not be under ``target_dir``: ours
    is a junction to another target's state.
    """
    pdb_dir = (
        (repo_root / target["binary"]).parent if target.get("binary") else target_dir
    )
    return [
        str(p)
        .replace("{pdb_dir}", str(pdb_dir))
        .replace("{target_dir}", str(target_dir))
        for p in (fuzz.get("symbols", {}).get("nt_symbol_path", []) or [])
    ]


def build_env(
    *, symbol_paths: list[str] | None = None, seed_spool: Path | None = None
) -> dict[str, str]:
    """The environment every wtf child needs."""
    env = dict(os.environ)

    # D-020: one unbalanced quote in PATH makes batch-based tooling abort, and
    # a corrupted PATH can break DLL resolution for the child too.
    parts = (p.strip().strip('"') for p in env.get("PATH", "").split(os.pathsep))
    env["PATH"] = os.pathsep.join(p for p in parts if p)

    if symbol_paths:
        env["_NT_SYMBOL_PATH"] = ";".join(symbol_paths)

    if seed_spool is not None:
        # Read by CustomMutator_t on the master (section 12.1). Harmless on a
        # worker, which never looks at it.
        env["SNAPFUZZ_SEED_SPOOL"] = str(seed_spool)

    return env


@dataclass
class CampaignConfig:
    """Everything a run needs, loaded from config rather than hardcoded."""

    wtf_exe: Path
    target_dir: Path
    name: str
    backend: str
    limit: int
    max_len: int
    runs: int
    worker_count: int
    symbol_paths: list[str]
    seed_spool: Path
    artifacts_dir: Path
    address: str | None = None
    edges: bool = False
    # Names an evidence directory under artifacts/runs/. Without it every run
    # overwrites the last one's artifacts, and one gate's evidence silently
    # destroys another's -- GATE 4b's 4-worker run clobbered GATE 4's
    # single-worker one and made GATE 4 fail retroactively.
    label: str | None = None

    @classmethod
    def from_yaml(
        cls,
        fuzz_yaml: Path,
        target_yaml: Path,
        *,
        repo_root: Path = REPO_ROOT,
        worker_count: int | None = None,
        backend: str | None = None,
        runs: int | None = None,
        module: str | None = None,
    ) -> CampaignConfig:
        fuzz = yaml.safe_load(fuzz_yaml.read_text(encoding="utf-8"))
        target = yaml.safe_load(target_yaml.read_text(encoding="utf-8"))

        wtf_cfg = fuzz["wtf"]
        topology = fuzz["topology"]
        chosen_backend = backend or topology["workers"]["backend"]

        # `name` is the subject, `module` is OUR wtf --name, `target_dir` is the
        # tree wtf reads. Conflating them made a campaign silently run wtf's own
        # tlv_server module instead of snapfuzz.
        tgt = target["target"]
        # An explicit override wins. Without one there is no way to run a
        # DIFFERENT wtf target than config/target.yaml names -- and a campaign
        # that silently loads the wrong module reports perfectly healthy numbers
        # about code you did not mean to test (D-056).
        module = module or tgt.get("module") or tgt["name"]
        target_dir = repo_root / tgt.get("target_dir", f"targets/{module}")

        # --limit means different things per backend and the values are orders
        # of magnitude apart (wtf.cc:267-268), so it is keyed by backend. A
        # missing key is an error, not something to default.
        limits = wtf_cfg["limit"]
        if chosen_backend not in limits:
            raise KeyError(
                f"config/fuzz.yaml wtf.limit has no entry for {chosen_backend!r}; "
                f"it means instructions on bochscpu and seconds on whv/kvm, so "
                f"there is no safe default"
            )

        symbol_paths = resolve_symbol_paths(
            fuzz, tgt, target_dir=target_dir, repo_root=repo_root
        )

        return cls(
            wtf_exe=repo_root / wtf_cfg["binary"],
            target_dir=target_dir,
            name=module,
            backend=chosen_backend,
            limit=int(limits[chosen_backend]),
            max_len=int(wtf_cfg["max_len"]),
            runs=int(runs if runs is not None else 10_000_000),
            worker_count=int(
                worker_count
                if worker_count is not None
                else topology["workers"]["count"]
            ),
            symbol_paths=symbol_paths,
            seed_spool=repo_root / fuzz["seed_spool"]["path"],
            artifacts_dir=repo_root / "artifacts",
            edges=bool(wtf_cfg.get("edges", False)),
        )


@dataclass
class Campaign:
    config: CampaignConfig
    space: AddressSpace

    master: MasterProcess | None = field(default=None, init=False)
    pool: WorkerPool | None = field(default=None, init=False)
    tracker: CoverageTracker = field(default_factory=CoverageTracker, init=False)
    watcher: CrashWatcher | None = field(default=None, init=False)
    ticks: list[CoverageSummary] = field(default_factory=list, init=False)
    started_at: float | None = field(default=None, init=False)
    ended_at: float | None = field(default=None, init=False)
    outputs_before: int = field(default=0, init=False)
    crashes_before: int = field(default=0, init=False)
    # outputs/ count per tick -- the unbuffered coverage-growth signal.
    new_coverage_events: list[int] = field(default_factory=list, init=False)

    @classmethod
    def from_snapshot_ref(
        cls, config: CampaignConfig, a1: Path, module: str | None = None
    ) -> Campaign:
        ref = SnapshotRef.model_validate_json(a1.read_text(encoding="utf-8"))
        return cls(
            config=config,
            space=AddressSpace(
                module or config.name, ref.module_base, ref.ghidra_image_base
            ),
        )

    def preflight(self) -> list[str]:
        """Check what would otherwise fail late, quietly, or confusingly."""
        problems: list[str] = []
        cfg = self.config

        if not cfg.wtf_exe.exists():
            problems.append(f"{cfg.wtf_exe} missing -- run `python -m fuzzer.build`")
        if not (cfg.target_dir / "state" / "mem.dmp").exists():
            problems.append(f"{cfg.target_dir / 'state' / 'mem.dmp'} missing (CP3)")

        corpus = Corpus(cfg.target_dir)
        if corpus.input_count() == 0:
            problems.append(
                f"{corpus.inputs} is empty: interface 1 supplies the master's "
                f"startup seeds and the mutator has nothing to build on"
            )
        if not corpus.coverage_files() and cfg.backend != "bochscpu":
            # Only whv/kvm consume .cov files; bochscpu derives coverage itself
            # (D-004), so an empty coverage/ is expected there.
            problems.append(
                f"no *.cov in {corpus.coverage}: the {cfg.backend} backend gets "
                f"coverage from breakpoints, and wtf only WARNS about this -- the "
                f"run would report almost no coverage instead of failing"
            )
        if os.name == "nt" and not cfg.symbol_paths:
            problems.append(
                "no _NT_SYMBOL_PATH configured: workers will fail in Init when "
                "they cannot resolve breakpoint symbols (D-023)"
            )
        return problems

    def start(self) -> None:
        cfg = self.config
        env = build_env(symbol_paths=cfg.symbol_paths, seed_spool=cfg.seed_spool)
        SeedSpool(cfg.seed_spool).ensure()

        corpus = Corpus(cfg.target_dir)
        self.outputs_before = corpus.output_count()
        self.crashes_before = corpus.crash_count()
        self.started_at = time.time()

        logs = cfg.artifacts_dir / "logs"

        # Module bases, so a fault can be attributed rather than blindly
        # de-slid with our module's offset (see CrashWatcher).
        module_ranges: dict[str, int] = {}
        symbol_store = cfg.target_dir / "state" / "symbol-store.json"
        if symbol_store.exists():
            module_ranges = {
                name: int(addr, 16)
                for name, addr in json.loads(
                    symbol_store.read_text(encoding="utf-8")
                ).items()
            }

        self.watcher = CrashWatcher(
            crashes_dir=cfg.target_dir / "crashes",
            space=self.space,
            backend=cfg.backend,  # type: ignore[arg-type]
            module_ranges=module_ranges,
        )
        self.watcher.prime()  # do not attribute pre-existing crashes to this run

        self.master = MasterProcess(
            wtf_exe=cfg.wtf_exe,
            target_dir=cfg.target_dir,
            name=cfg.name,
            max_len=cfg.max_len,
            runs=cfg.runs,
            env=env,
            log_path=logs / "master.log",
            address=cfg.address,
        )
        self.master.start()

        # Let the master bind its socket before workers dial in.
        time.sleep(3.0)

        self.pool = WorkerPool(
            wtf_exe=cfg.wtf_exe,
            target_dir=cfg.target_dir,
            name=cfg.name,
            backend=cfg.backend,
            limit=cfg.limit,
            env=env,
            log_dir=logs / "workers",
            count=cfg.worker_count,
            address=cfg.address,
            edges=cfg.edges,
        )
        self.pool.start()

    def sample_new_coverage_events(self) -> int:
        """Count new-coverage events from the filesystem.

        **This is the reliable coverage-growth signal.** The master saves a
        testcase into ``outputs/`` exactly when a testcase produced NEW coverage
        (``server.h:830-836`` -> ``Corpus_t::SaveTestcase``), and a file
        appearing on disk is not buffered.

        Its stdout is: wtf block-buffers through C stdio and does not flush on
        exit, so a 123-second run left a **0-byte** master log while the fuzzer
        was healthily saving 30 new-coverage testcases (D-033). Ctrl+Break does
        not help. So the stat lines are a bonus when they arrive, and this is the
        signal that is always there.

        What it measures, precisely: the number of *new-coverage events*, not the
        number of covered edges. Monotonic, and enough to answer "is coverage
        growing" and to detect a plateau.
        """
        return Corpus(self.config.target_dir).output_count()

    def tick(self) -> CoverageSummary | None:
        """One sample: master stat lines if flushed, plus the filesystem signal."""
        assert self.master is not None
        events = self.sample_new_coverage_events()
        self.new_coverage_events.append(events)

        stats = self.master.latest()
        if stats is None:
            return None
        summary = self.tracker.observe(stats)
        self.ticks.append(summary)
        return summary

    def stop(self) -> None:
        if self.pool is not None:
            self.pool.stop()
        if self.master is not None:
            self.master.stop()
        self.ended_at = time.time()

    def rebuild_history(self) -> CoverageTracker:
        """Rebuild the coverage history from EVERY master stat line.

        The per-tick sampling in :meth:`tick` is for live display only and
        systematically under-resolves: the master block-buffers its log
        (D-033), so one tick can absorb several minutes of stat lines and the
        growth inside them becomes invisible. Measured -- a 663-second run with
        30 new-coverage saves reported no growth at all when judged from ticks.

        The log has every line, so the log is what the artifacts come from.
        """
        # The backend goes in so the summaries say what their numbers count
        # (D-068): the same integer means edges on one backend and breakpoint hits
        # on another, and CP10 compares them.
        tracker = CoverageTracker(backend=self.cfg.backend)
        if self.master is not None:
            for stats in self.master.snapshot_stats():
                tracker.observe(stats)
        return tracker

    @property
    def evidence_dir(self) -> Path:
        """Where this run's artifacts live.

        A labelled run gets its own directory so gates do not overwrite each
        other's evidence. Unlabelled runs share the top level, which is fine for
        exploration but not for anything a gate reads.
        """
        if self.config.label:
            return self.config.artifacts_dir / "runs" / self.config.label
        return self.config.artifacts_dir

    def write_artifacts(self) -> dict[str, Path]:
        out: dict[str, Path] = {}
        target = self.evidence_dir
        target.mkdir(parents=True, exist_ok=True)

        # Replace the sampled history with the full one before writing.
        rebuilt = self.rebuild_history()
        if rebuilt.history:
            self.tracker = rebuilt
        if self.tracker.history:
            out["coverage"] = self.tracker.write_jsonl(
                target / "coverage_summaries.jsonl"
            )
        if self.watcher is not None:
            records = self.watcher.collect_all()
            if records:
                out["crashes"] = self.watcher.write_jsonl(
                    records, target / "a5_crashes.jsonl"
                )
        out["metadata"] = self.write_metadata()

        # The master writes its log live and cannot be redirected after the
        # fact, so copy it in alongside the rest of the evidence.
        if self.master is not None and self.master.log_path.exists():
            archived = target / "master.log"
            if archived != self.master.log_path:
                archived.write_bytes(self.master.log_path.read_bytes())
            out["master_log"] = archived
        return out

    def write_metadata(self) -> Path:
        """Record what this run actually was.

        Duration is measured by us, not read from the master's ``uptime``: the
        master block-buffers stdout, and terminating it never flushes the last
        buffer, so its final few minutes of stat lines are simply lost. Proving
        a >=10-minute run from a number that can silently truncate would be a
        bad way to satisfy GATE 4.
        """
        cfg = self.config
        corpus = Corpus(cfg.target_dir)
        stats = self.master.snapshot_stats() if self.master else []

        payload = {
            "module": cfg.name,
            "target_dir": str(cfg.target_dir),
            "backend": cfg.backend,
            "worker_count": cfg.worker_count,
            "limit": cfg.limit,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration_s": (
                (self.ended_at - self.started_at)
                if self.started_at and self.ended_at
                else None
            ),
            "ticks": len(self.tracker.history),
            "peak_coverage": max((s.coverage for s in stats), default=0),
            "peak_corpus": max((s.corpus_size for s in stats), default=0),
            "crash_events_observed": max((s.crash_events for s in stats), default=0),
            "outputs_before": self.outputs_before,
            "outputs_after": corpus.output_count(),
            "crashes_before": self.crashes_before,
            "crashes_after": corpus.crash_count(),
            # PRIMARY growth evidence: new-coverage events counted from the
            # filesystem, which is unbuffered. See sample_new_coverage_events.
            "new_coverage_events": corpus.output_count() - self.outputs_before,
            "new_coverage_events_series": self.new_coverage_events,
            "coverage_grew": (
                corpus.output_count() > self.outputs_before or self.tracker.is_growing
            ),
            # Secondary, and only meaningful when the master happened to flush.
            "coverage_grew_per_stat_lines": self.tracker.is_growing,
            "coverage_grew_after_first_sample": (
                self.tracker.grew_after_the_first_sample
            ),
            "master_stat_lines_observed": len(stats),
            # If Ctrl+Break was ignored we had to terminate, and the master's
            # buffered tail was lost (D-033). Flagged so a short observed
            # history is not read as a short run.
            "master_log_truncated": (
                self.master.terminated_without_flush if self.master else None
            ),
            "worker_restarts": (
                sum(w.restarts for w in self.pool.workers) if self.pool else 0
            ),
        }
        payload["label"] = cfg.label
        path = self.evidence_dir / "run_metadata.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--minutes", type=float, default=10.0)
    ap.add_argument("--workers", type=int, help="override topology.workers.count")
    ap.add_argument("--backend", help="override topology.workers.backend")
    ap.add_argument("--tick-seconds", type=float, default=15.0)
    ap.add_argument("--a1", type=Path, default=REPO_ROOT / "artifacts/a1_snapshot.json")
    ap.add_argument(
        "--label",
        help="write evidence to artifacts/runs/<label>/ so a later run cannot "
        "overwrite it; required for anything a gate reads",
    )
    args = ap.parse_args(argv)

    config = CampaignConfig.from_yaml(
        REPO_ROOT / "config" / "fuzz.yaml",
        REPO_ROOT / "config" / "target.yaml",
        worker_count=args.workers,
        backend=args.backend,
    )
    if args.label:
        config = dataclasses.replace(config, label=args.label)
    campaign = Campaign.from_snapshot_ref(config, args.a1)

    problems = campaign.preflight()
    if problems:
        for problem in problems:
            print(f"PREFLIGHT: {problem}")
        return 1

    print(
        f"campaign: {config.name} on {config.backend}, "
        f"{config.worker_count} worker(s), {args.minutes:.0f} min"
    )
    campaign.start()

    deadline = time.time() + args.minutes * 60
    try:
        while time.time() < deadline:
            time.sleep(args.tick_seconds)
            summary = campaign.tick()
            if summary is not None:
                print(
                    f"tick {summary.tick:>3}  cov={summary.coverage_units:<7}"
                    f" +{summary.new_units:<5} corpus={summary.corpus_size:<5}"
                    f" plateau={summary.plateau_ticks}"
                )
            assert campaign.pool is not None
            if died := campaign.pool.check(restart=True):
                for worker in died:
                    print(f"  worker {worker.worker_id} died; restarted")
                for wid, reason in campaign.pool.failure_reasons().items():
                    print(f"  {wid}: {reason}")
            if not campaign.pool.alive():
                print("all workers dead; aborting")
                break
    except KeyboardInterrupt:
        print("interrupted")
    finally:
        campaign.stop()

    written = campaign.write_artifacts()
    for kind, path in written.items():
        print(f"{kind}: {path}")
    print(f"coverage grew: {campaign.tracker.is_growing}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
