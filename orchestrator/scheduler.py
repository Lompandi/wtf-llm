"""Supervise the two clocks: master + N workers + the slow-clock sidecar (§12.2).

Three kinds of process, and the separation is the point:

* **one master** -- owns the corpus, generates test-cases through our
  `Mutator_t`, aggregates coverage. Fast clock.
* **N workers** -- execute and report. Fast clock.
* **one sidecar** -- watches for plateau and calls the LLM. Slow clock, and a
  **separate process** so its latency can never stall the pool.

The scheduler talks to the sidecar through a small **state file** rather than
IPC. It writes `{executions, new_coverage_events, elapsed_s}` each tick; the
sidecar polls it. That keeps the process boundary trivial and puts the execution
count where it can actually be observed -- the scheduler owns the master, so it
sees whatever stat lines survive buffering (D-033), and it counts new-coverage
events from `outputs/`, which is unbuffered and genuinely aggregate.

GATE 7 wants proof the fast loop never stalled on the LLM. The evidence is the
combination of this scheduler's per-tick throughput log and the sidecar's own
event log: a generation round taking ~65 s of LLM time with throughput unchanged
across it is what "did not stall" looks like.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from arch.addr import AddressSpace
from arch.contracts import SnapshotRef
from fuzzer.corpus import Corpus
from fuzzer.run import Campaign, CampaignConfig

REPO_ROOT = Path(__file__).resolve().parents[1]

__all__ = ["Scheduler", "SchedulerResult"]


@dataclass
class SchedulerResult:
    label: str
    duration_s: float
    worker_count: int
    ticks: int
    peak_executions: int
    new_coverage_events: int
    outputs_before: int
    outputs_after: int
    seeds_consumed: int
    sidecar_rounds: int
    throughput_samples: list[float] = field(default_factory=list)

    @property
    def min_throughput(self) -> float:
        return min(self.throughput_samples) if self.throughput_samples else 0.0

    @property
    def mean_throughput(self) -> float:
        s = self.throughput_samples
        return sum(s) / len(s) if s else 0.0


@dataclass
class Scheduler:
    campaign: Campaign
    label: str
    artifacts_dir: Path
    sidecar_cmd: list[str] | None = None

    state_path: Path = field(init=False)
    sidecar: subprocess.Popen | None = field(default=None, init=False)
    throughput: list[float] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        self.state_path = self.artifacts_dir / f"campaign_state_{self.label}.json"

    def _write_state(self, executions: int, events: int, elapsed: float) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "label": self.label,
            "executions": executions,
            "new_coverage_events": events,
            "elapsed_s": round(elapsed, 1),
            "ts": time.time(),
        }
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        tmp.replace(self.state_path)  # atomic: the sidecar may read at any moment

    def _start_sidecar(self) -> None:
        if not self.sidecar_cmd:
            return
        log = self.artifacts_dir / "logs" / f"sidecar_{self.label}.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        handle = log.open("w", encoding="utf-8", errors="replace")

        env = dict(os.environ)
        parts = (p.strip().strip('"') for p in env.get("PATH", "").split(os.pathsep))
        env["PATH"] = os.pathsep.join(p for p in parts if p)

        self.sidecar = subprocess.Popen(
            self.sidecar_cmd,
            cwd=REPO_ROOT,
            env=env,
            stdout=handle,
            stderr=subprocess.STDOUT,
        )
        print(f"sidecar pid {self.sidecar.pid} -> {log}", flush=True)

    def run(self, *, minutes: float, tick_seconds: float = 20.0) -> SchedulerResult:
        cfg = self.campaign.config
        corpus = Corpus(cfg.target_dir)
        outputs_before = corpus.output_count()

        self._write_state(0, outputs_before, 0.0)
        self.campaign.start()
        self._start_sidecar()

        started = time.time()
        deadline = started + minutes * 60
        ticks = 0
        peak_executions = 0
        last_executions = 0
        last_time = started

        try:
            while time.time() < deadline:
                time.sleep(tick_seconds)
                ticks += 1
                now = time.time()

                assert self.campaign.master is not None
                stats = self.campaign.master.latest()
                executions = stats.execs if stats else 0
                peak_executions = max(peak_executions, executions)

                events = corpus.output_count()
                self._write_state(peak_executions, events, now - started)

                # Throughput between ticks, from the master's own counter when
                # available. A dip across a generation round would be the fast
                # loop stalling on the LLM.
                if executions > last_executions and now > last_time:
                    rate = (executions - last_executions) / (now - last_time)
                    self.throughput.append(rate)
                    last_executions, last_time = executions, now

                spool = self.campaign.config.seed_spool
                pending = (
                    len([p for p in spool.iterdir() if p.suffix != ".tmp"])
                    if spool.is_dir()
                    else 0
                )
                print(
                    f"tick {ticks:>3}  execs={peak_executions:<9} "
                    f"cov_events={events:<5} spool={pending:<3} "
                    f"exec/s~{self.throughput[-1] if self.throughput else 0:.0f}",
                    flush=True,
                )

                if died := self.campaign.pool.check(restart=True):
                    for worker in died:
                        print(f"  worker {worker.worker_id} died; restarted", flush=True)
                if not self.campaign.pool.alive():
                    print("all workers dead; aborting", flush=True)
                    break
        except KeyboardInterrupt:
            print("interrupted", flush=True)
        finally:
            self.campaign.stop()
            self._stop_sidecar()

        outputs_after = corpus.output_count()
        return SchedulerResult(
            label=self.label,
            duration_s=time.time() - started,
            worker_count=cfg.worker_count,
            ticks=ticks,
            peak_executions=peak_executions,
            new_coverage_events=outputs_after - outputs_before,
            outputs_before=outputs_before,
            outputs_after=outputs_after,
            seeds_consumed=self._seeds_consumed(),
            sidecar_rounds=self._sidecar_rounds(),
            throughput_samples=list(self.throughput),
        )

    def _stop_sidecar(self, timeout: float = 30.0) -> None:
        if self.sidecar is None:
            return
        if self.sidecar.poll() is None:
            self.sidecar.terminate()
            try:
                self.sidecar.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.sidecar.kill()

    def _sidecar_events(self) -> list[dict]:
        path = self.artifacts_dir / "sidecar_events.jsonl"
        if not path.exists():
            return []
        out = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out

    def _sidecar_rounds(self) -> int:
        return sum(1 for e in self._sidecar_events() if e["event"] == "seeds_published")

    def _seeds_consumed(self) -> int:
        published = sum(
            e.get("seeds", 0)
            for e in self._sidecar_events()
            if e["event"] == "seeds_published"
        )
        spool = self.campaign.config.seed_spool
        remaining = (
            len([p for p in spool.iterdir() if p.suffix != ".tmp"])
            if spool.is_dir()
            else 0
        )
        return max(0, published - remaining)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--minutes", type=float, default=10.0)
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--tick-seconds", type=float, default=20.0)
    ap.add_argument("--label", required=True)
    ap.add_argument("--target-dir", type=Path, help="override config target_dir")
    ap.add_argument("--a1", type=Path, default=REPO_ROOT / "artifacts/a1_snapshot.json")
    ap.add_argument("--plateau-execs", type=int, default=20000)
    ap.add_argument("--seeds", type=int, default=8)
    ap.add_argument("--samples", type=int, default=3)
    ap.add_argument("--no-sidecar", action="store_true", help="baseline run")
    args = ap.parse_args(argv)

    import dataclasses

    config = CampaignConfig.from_yaml(
        REPO_ROOT / "config" / "fuzz.yaml",
        REPO_ROOT / "config" / "target.yaml",
        worker_count=args.workers,
    )
    if args.target_dir:
        config = dataclasses.replace(config, target_dir=args.target_dir)
    config = dataclasses.replace(config, label=args.label)

    campaign = Campaign.from_snapshot_ref(config, args.a1)
    problems = campaign.preflight()
    if problems:
        for problem in problems:
            print(f"PREFLIGHT: {problem}")
        return 1

    sidecar_cmd = None
    if not args.no_sidecar:
        state = REPO_ROOT / "artifacts" / f"campaign_state_{args.label}.json"
        sidecar_cmd = [
            str(REPO_ROOT / ".venv" / "Scripts" / "python.exe"), "-u",
            "-m", "llm.sidecar",
            "--target-dir", str(config.target_dir),
            "--module", config.name,
            "--a1", str(args.a1),
            "--watch", str(state),
            "--minutes", str(args.minutes),
            "--plateau-execs", str(args.plateau_execs),
            "--seeds", str(args.seeds),
            "--samples", str(args.samples),
        ]

    scheduler = Scheduler(
        campaign=campaign,
        label=args.label,
        artifacts_dir=config.artifacts_dir,
        sidecar_cmd=sidecar_cmd,
    )

    mode = "baseline (no sidecar)" if args.no_sidecar else "LLM-guided"
    print(
        f"campaign [{args.label}] {mode}: {config.name} on {config.backend}, "
        f"{config.worker_count} worker(s), {args.minutes:.0f} min",
        flush=True,
    )

    result = scheduler.run(minutes=args.minutes, tick_seconds=args.tick_seconds)

    out = config.artifacts_dir / "runs" / args.label
    out.mkdir(parents=True, exist_ok=True)
    (out / "scheduler_result.json").write_text(
        json.dumps(
            {
                **{k: v for k, v in result.__dict__.items()},
                "min_throughput": result.min_throughput,
                "mean_throughput": result.mean_throughput,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    campaign.write_artifacts()

    print()
    print(f"label              : {result.label}")
    print(f"duration           : {result.duration_s:.0f}s")
    print(f"workers            : {result.worker_count}")
    print(f"peak executions    : {result.peak_executions}")
    print(f"new coverage events: {result.new_coverage_events} "
          f"({result.outputs_before} -> {result.outputs_after})")
    print(f"sidecar rounds     : {result.sidecar_rounds}")
    print(f"seeds consumed     : {result.seeds_consumed}")
    print(f"throughput exec/s  : mean {result.mean_throughput:.0f}, "
          f"min {result.min_throughput:.0f}")
    print(f"wrote {out / 'scheduler_result.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
