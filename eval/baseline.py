"""Baseline vs LLM-guided comparison (CLAUDE.md CP10, GATE 10).

Section 10 of the checkpoint list: **without this comparison the project's central
claim is unsupported.** So this measures it, and reports the answer whichever way
it comes out.

What is compared
----------------
Same target, same snapshot, same wall-clock budget, same single poor seed, same
worker count. The arms differ in exactly one thing each:

* ``baseline-libfuzzer`` -- wtf's built-in libFuzzer mutator, no sidecar.
* ``baseline-honggfuzz`` -- wtf's built-in honggfuzz mutator, no sidecar.
  Both built-ins are run because a single one could be dismissed as a straw man
  (section 10 of CP10 says exactly that).
* ``llm-guided`` -- our ``CustomMutator_t`` plus the slow-clock sidecar.
* ``ablation-no-seedgen`` -- our module, sidecar disabled. Isolates the mutator
  from the seed generation.
* ``ablation-no-pseudoc`` -- sidecar enabled but the prompt carries no pseudo-C.
  Isolates *reasoning over decompiled code* from merely having an LLM produce
  structurally valid inputs.

Metrics: coverage growth over time, time to first crash, and distinct crash
buckets (via :mod:`analysis.dedup`, so "unique crashes" means the same thing in
every arm).

Corpus minset between runs
--------------------------
Section 13.2: ``master --runs=0 --inputs=outputs --outputs=minset``. Every arm
starts from the same single seed and an empty corpus, so minsetting *between* arms
is unnecessary here -- but a long campaign still wants it, and section 10 lists
skipping it as an anti-pattern, so :func:`minset_corpus` exists and is used when an
arm is resumed rather than started fresh.

**NO LLM IN THIS MODULE.** It launches arms; the LLM lives in the sidecar the
scheduler starts.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from analysis.dedup import SymbolizingResolver, bucket_crashes
from arch.addr import AddressSpace
from arch.contracts import SnapshotRef
from engine_bridge.coverage import iter_stat_lines
from engine_bridge.crash_watch import CrashWatcher
from fuzzer.corpus import Corpus
from fuzzer.run import CampaignConfig

REPO_ROOT = Path(__file__).resolve().parents[1]

__all__ = ["Arm", "ArmResult", "ARMS", "run_arm", "minset_corpus"]

# The deliberately poor seed every arm starts from: structurally valid, exercising
# one command with an empty body. Identical across arms so the comparison is of
# the search, not of the starting point.
POOR_SEED = b'{"Packets":[{"Id":1,"Command":0,"BodySize":0,"Body":[]}]}'

# The same idea for the second real target, whose wire format is different: magic correct
# so the parser's first four comparisons pass, and a zero length so nothing further is
# reached. `fuzzme` then finds strlen == 4, fails `4 < len`, and performs no memset -- it
# walks the whole compare chain and triggers nothing, which is what "deliberately poor"
# has to mean for a comparison to be about the SEARCH rather than the starting point.
POOR_SEEDS: dict[str, bytes] = {
    "snapfuzz": POOR_SEED,
}

# KEYED ON THE MODULE WAS WRONG, and only a third target showed it: every generated harness
# is registered as `snapfuzz_gen`, so two targets share the key while having completely
# different wire formats. Target 2's magic is "test" and target 3's is "FUZZ", so target 3
# would have started from a seed that fails its own memcmp -- every arm exploring nothing,
# and the comparison measuring the seed rather than the search.
#
# So the seed is a CLI argument now. `--poor-seed` for an explicit file, and the caller is
# the only thing that knows which target it is pointing at.


class ArmDidNotRun(RuntimeError):
    """An arm produced no corpus and no executions, so it measured nothing.

    Distinct from "this arm found nothing", which is a legitimate result and the reason
    the two must not share a representation.
    """


@dataclass(frozen=True)
class Arm:
    """One experimental condition."""

    name: str
    module: str
    sidecar: bool
    description: str
    # Extra environment for the arm. SNAPFUZZ_MUTATOR selects which built-in our
    # module delegates to; SNAPFUZZ_NO_PSEUDOC drops pseudo-C from the prompt.
    env: dict[str, str] = field(default_factory=dict)


ARMS: tuple[Arm, ...] = (
    Arm(
        name="baseline-libfuzzer",
        module="snapfuzz",
        sidecar=False,
        description="wtf's built-in libFuzzer mutator, no LLM anywhere",
        env={"SNAPFUZZ_MUTATOR": "libfuzzer"},
    ),
    Arm(
        name="baseline-honggfuzz",
        module="snapfuzz",
        sidecar=False,
        description="wtf's built-in honggfuzz mutator, no LLM anywhere",
        env={"SNAPFUZZ_MUTATOR": "honggfuzz"},
    ),
    Arm(
        name="llm-guided",
        module="snapfuzz",
        sidecar=True,
        description="our mutator plus the slow-clock sidecar",
    ),
    Arm(
        name="ablation-no-seedgen",
        module="snapfuzz",
        sidecar=False,
        description="our mutator, sidecar disabled -- isolates seed generation",
    ),
    Arm(
        name="ablation-no-pseudoc",
        module="snapfuzz",
        sidecar=True,
        description="sidecar on, but the prompt carries no pseudo-C",
        env={"SNAPFUZZ_NO_PSEUDOC": "1"},
    ),
)


@dataclass
class ArmResult:
    arm: str
    description: str
    duration_s: float
    workers: int
    peak_executions: int
    corpus_size: int
    crash_events: int
    crash_files: int
    distinct_buckets: int | None
    seconds_to_first_crash: float | None
    coverage_curve: list[tuple[float, int]]
    sidecar_rounds: int
    seeds_consumed: int
    mean_exec_per_s: float

    def to_json(self) -> dict:
        return dataclasses.asdict(self)


def prepare_target(
    *,
    name: str,
    source_state: Path,
    cov_file: Path,
    seed: bytes = POOR_SEED,
    repo_root: Path = REPO_ROOT,
) -> Path:
    """A fresh five-directory tree (section 13.1) with one poor seed.

    Fresh every time so a re-run is a re-run and not a continuation of whatever a
    previous arm left behind -- which would make the second arm look better for
    no reason. ``state/`` is a junction: copying a 1.8 GB dump per arm is absurd.
    """
    target = repo_root / "targets" / name
    if target.exists():
        state = target / "state"
        if state.is_dir():
            # rmdir, never rmtree: the junction points at another target's
            # snapshot and rmtree would follow it.
            subprocess.run(["cmd", "/c", "rmdir", str(state)], check=False)
        shutil.rmtree(target, ignore_errors=True)

    for sub in ("inputs", "outputs", "coverage", "crashes"):
        (target / sub).mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(target / "state"), str(source_state)],
        capture_output=True, text=True, check=False,
    )
    shutil.copy(cov_file, target / "coverage" / cov_file.name)
    (target / "inputs" / "poor.json").write_bytes(seed)
    return target


def minset_corpus(
    config: CampaignConfig, target_dir: Path, *, timeout_s: int = 1800
) -> int:
    """``master --runs=0`` corpus minimisation (section 13.2).

    Needs a server plus clients like any other master run, so this launches both.
    Returns the resulting minset size. Skipping this is listed as an anti-pattern:
    a bloated corpus slows the master and makes any coverage summary noisier.
    """
    minset = target_dir / "minset"
    minset.mkdir(parents=True, exist_ok=True)
    for stale in minset.glob("*"):
        stale.unlink()

    from fuzzer.run import build_env

    env = build_env(symbol_paths=config.symbol_paths)
    master = subprocess.Popen(
        [
            str(config.wtf_exe), "master",
            "--name", config.name,
            f"--max_len={config.max_len}",
            "--runs=0",
            "--inputs", "outputs",
            "--outputs", "minset",
        ],
        cwd=target_dir, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    worker = subprocess.Popen(
        [
            str(config.wtf_exe), "fuzz",
            "--name", config.name,
            f"--backend={config.backend}",
            f"--limit={config.limit}",
        ],
        cwd=target_dir, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        master.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        master.kill()
    finally:
        worker.kill()
    return len(list(minset.glob("*")))


def _coverage_curve(master_log: Path) -> list[tuple[float, int]]:
    """(uptime seconds, aggregate coverage) from the master's own stat lines."""
    if not master_log.exists():
        return []
    text = master_log.read_text(encoding="utf-8", errors="replace")
    return [(round(s.uptime_s, 1), s.coverage) for s in iter_stat_lines(text)]


def _first_crash_seconds(master_log: Path) -> float | None:
    """Uptime at the first stat line reporting a nonzero crash count.

    Resolution is the master's stat interval, so this is an upper bound rather
    than an exact time -- stated because a reader would otherwise take it as
    precise.
    """
    if not master_log.exists():
        return None
    text = master_log.read_text(encoding="utf-8", errors="replace")
    for stats in iter_stat_lines(text):
        if stats.crash_events > 0:
            return round(stats.uptime_s, 1)
    return None


def run_arm(
    arm: Arm,
    *,
    minutes: float,
    workers: int,
    a1: Path,
    cov_file: Path,
    source_state: Path,
    plateau_execs: int,
    seeds: int,
    samples: int,
    dedup: bool = True,
    label_prefix: str = "cmp",
    seed_bytes: bytes = POOR_SEED,
) -> ArmResult:
    """Run one arm end to end and measure it."""
    import os

    from orchestrator.scheduler import Scheduler
    from fuzzer.run import Campaign

    # PREFIXED, because a second target's arms would otherwise write to `cmp-<arm>` and
    # destroy the first target's evidence -- the same way GATE 4b's run once clobbered
    # GATE 4's and made a passing gate fail retroactively (D-057).
    label = f"{label_prefix}-{arm.name}"
    target_dir = prepare_target(
        name=label,
        source_state=source_state,
        cov_file=cov_file,
        seed=POOR_SEEDS.get(arm.module, POOR_SEED),
    )

    config = CampaignConfig.from_yaml(
        REPO_ROOT / "config" / "fuzz.yaml",
        REPO_ROOT / "config" / "target.yaml",
        worker_count=workers,
        # The ARM's module, not config/target.yaml's. Without this every arm loaded
        # `snapfuzz` -- the dev target's hand-written harness -- whatever module was asked
        # for, and against another target's snapshot it died in Init with "Could not set a
        # breakpoint at tlv_server!ProcessPacket": the dev target's entry symbol, while
        # analysing a different program. from_yaml already accepts the override and D-056
        # records why it exists; this call simply was not using it.
        module=arm.module,
    )
    # artifacts_dir POINTS AT THE TARGET'S OWN ARTIFACTS, derived from the A1 the caller
    # passed -- that file identifies which target this is, and its directory holds
    # harness_spec.json.
    #
    # Without this it resolved to the repo-level `artifacts/`, where there is no
    # harness_spec.json since artifacts became per-target. So input_buffer_bytes was None,
    # the harness relocated the test-case to the tail of the pointer's page, and on a stack
    # pointer that lands above rsp among the caller frames: __security_check_cookie then
    # fails on EVERY input and the arm reports a crash for every test-case it runs (D-083).
    #
    # The numbers would have looked excellent. That is the point -- a fabricated crash is
    # worse than a missed one, and here it would have gone straight into the comparison
    # that carries the project's central claim.
    config = dataclasses.replace(
        config, target_dir=target_dir, label=label, artifacts_dir=a1.parent
    )

    previous = {k: os.environ.get(k) for k in arm.env}
    os.environ.update(arm.env)
    try:
        campaign = Campaign.from_snapshot_ref(config, a1)
        problems = campaign.preflight()
        if problems:
            raise SystemExit(f"{arm.name} preflight: {problems}")

        sidecar_cmd = None
        if arm.sidecar:
            state_file = config.artifacts_dir / f"campaign_state_{label}.json"
            sidecar_cmd = [
                str(REPO_ROOT / ".venv" / "Scripts" / "python.exe"), "-u",
                "-m", "llm.sidecar",
                "--target-dir", str(target_dir),
                "--module", config.name,
                "--a1", str(a1),
                "--watch", str(state_file),
                "--minutes", str(minutes),
                "--plateau-execs", str(plateau_execs),
                "--seeds", str(seeds),
                "--samples", str(samples),
                "--label", label,
            ]

        scheduler = Scheduler(
            campaign=campaign,
            label=label,
            artifacts_dir=config.artifacts_dir,
            sidecar_cmd=sidecar_cmd,
        )
        started = time.time()
        result = scheduler.run(minutes=minutes, tick_seconds=20.0)
        campaign.write_artifacts()
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    master_log = config.artifacts_dir / "runs" / label / "master.log"
    if not master_log.exists():
        master_log = config.artifacts_dir / "logs" / "master.log"

    corpus = Corpus(target_dir)
    curve = _coverage_curve(master_log)

    # Executions and crash counts come from the FINAL master log, not from the
    # scheduler's live ticks.
    #
    # The master prints through C stdio, which block-buffers to a file (D-033), so
    # `latest()` during the run lags by up to a buffer -- and the lag depends on
    # how much the arm printed. A baseline arm finding thousands of crashes fills
    # the buffer with "Saving crash in ..." lines and lags differently from a quiet
    # arm. Taking these numbers from the live ticks would therefore bias the
    # comparison by arm, which is exactly the kind of difference that looks like a
    # result. Measured: an arm at 8.3k exec/s showed 82,831 in the state file for
    # ten consecutive ticks.
    stats = list(
        iter_stat_lines(master_log.read_text(encoding="utf-8", errors="replace"))
    )
    peak_executions = max((s.execs for s in stats), default=result.peak_executions)
    crash_events = max((s.crash_events for s in stats), default=0)
    mean_rate = (
        sum(s.execs_per_sec for s in stats if 0 < s.execs_per_sec < 1e6)
        / max(1, sum(1 for s in stats if 0 < s.execs_per_sec < 1e6))
    )

    buckets: int | None = None
    if dedup:
        ref = SnapshotRef.model_validate_json(a1.read_text(encoding="utf-8"))
        space = AddressSpace("tlv_server", ref.module_base, ref.ghidra_image_base)
        records = CrashWatcher(
            crashes_dir=target_dir / "crashes", space=space, backend=config.backend
        ).collect_all()
        if records:
            # The SAME dedup the pipeline uses, so "unique crashes" means the
            # same thing in every arm. Counting crash FILES instead would compare
            # wtf's filename collapsing, which is not a bug count (D-024).
            buckets = len(
                bucket_crashes(
                    records,
                    resolver=SymbolizingResolver(
                        crash_dump=target_dir / "state" / "mem.dmp",
                        workdir=config.artifacts_dir / "analysis" / label,
                        symbol_paths=config.symbol_paths,
                    ),
                    space=space,
                )
            )
        else:
            buckets = 0

    # AN ARM THAT DID NOT FUZZ IS NOT A RESULT OF ZERO. Measured: two arms recorded
    # `execs 0 corpus 0 buckets 0` because their workers died in a loop -- a stale wtf.exe
    # from an earlier run still held port 31337, so the new master could not bind. The
    # comparison table then printed
    #
    #     baseline-libfuzzer   0   0   0   None   0
    #
    # which reads as "libFuzzer found nothing" and is a statement about the port, not the
    # mutator. On the arm that carries the project's central claim that is the worst
    # possible confusion, and it is the same rule the pipeline learned at CP12: exit 0 is
    # not evidence, and an empty artifact is not a measurement.
    #
    # Raised rather than recorded, because a comparison missing an arm is obviously
    # incomplete while a comparison containing a fabricated zero looks finished.
    if corpus.output_count() == 0 and peak_executions == 0:
        raise ArmDidNotRun(
            f"arm {arm.name!r} produced no corpus and no executions in "
            f"{round(time.time() - started)}s. It did not fuzz, so there is nothing to "
            f"compare. Check {config.artifacts_dir / 'logs' / 'workers'} -- the usual "
            f"cause is a stale wtf.exe holding the master's port, which makes every "
            f"worker fail to dial and be restarted forever."
        )

    return ArmResult(
        arm=arm.name,
        description=arm.description,
        duration_s=round(time.time() - started, 1),
        workers=workers,
        peak_executions=peak_executions,
        corpus_size=corpus.output_count(),
        crash_events=crash_events,
        crash_files=corpus.crash_count(),
        distinct_buckets=buckets,
        seconds_to_first_crash=_first_crash_seconds(master_log),
        coverage_curve=curve,
        sidecar_rounds=result.sidecar_rounds,
        seeds_consumed=result.seeds_consumed,
        mean_exec_per_s=round(mean_rate, 1),
    )


def recompute_from_logs(out_dir: Path) -> list[ArmResult]:
    """Re-derive the log-based metrics from each arm's archived master log.

    Re-analysis without re-measurement. It exists because the live tick counter
    lags behind the master's buffered output by an arm-dependent amount (see
    ``run_arm``), so a comparison recorded before that was understood carries a
    biased ``peak_executions``. The fuzzing does not need repeating to fix it --
    ``campaign.write_artifacts()`` archives the full master log per arm, and the
    log is the authority.

    Only log-derived fields are touched. Corpus size, bucket counts and seed
    counts came from the filesystem and the sidecar's own log and are already
    right.
    """
    results: list[ArmResult] = []
    for arm in ARMS:
        path = out_dir / f"{arm.name}.json"
        if not path.exists():
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))

        master_log = REPO_ROOT / "artifacts" / "runs" / f"cmp-{arm.name}" / "master.log"
        if not master_log.exists():
            print(f"  {arm.name}: no archived master log, left as recorded")
            results.append(ArmResult(**payload))
            continue

        stats = list(
            iter_stat_lines(master_log.read_text(encoding="utf-8", errors="replace"))
        )
        if not stats:
            print(f"  {arm.name}: archived log has no parseable stat lines")
            results.append(ArmResult(**payload))
            continue

        # An arm with no sidecar cannot have run a generation round. The event log
        # was shared across arms, so the baselines had been credited with a
        # previous arm's rounds and seeds (D-053); the arm definition is the
        # authority here, not the log.
        if not arm.sidecar and (payload["sidecar_rounds"] or payload["seeds_consumed"]):
            print(
                f"  {arm.name}: clearing {payload['sidecar_rounds']} round(s) / "
                f"{payload['seeds_consumed']} seed(s) wrongly credited to a "
                f"no-sidecar arm"
            )
            payload["sidecar_rounds"] = 0
            payload["seeds_consumed"] = 0

        rates = [s.execs_per_sec for s in stats if 0 < s.execs_per_sec < 1e6]
        before = payload["peak_executions"]
        payload["peak_executions"] = max(s.execs for s in stats)
        payload["crash_events"] = max(s.crash_events for s in stats)
        payload["coverage_curve"] = [
            [round(s.uptime_s, 1), s.coverage] for s in stats
        ]
        payload["mean_exec_per_s"] = round(sum(rates) / len(rates), 1) if rates else 0.0
        payload["seconds_to_first_crash"] = next(
            (round(s.uptime_s, 1) for s in stats if s.crash_events > 0), None
        )

        print(
            f"  {arm.name}: execs {before} -> {payload['peak_executions']}, "
            f"{len(payload['coverage_curve'])} curve point(s)"
        )
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        results.append(ArmResult(**payload))
    return results


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--minutes", type=float, default=6.0)
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--plateau-execs", type=int, default=20000)
    ap.add_argument("--seeds", type=int, default=6)
    ap.add_argument("--samples", type=int, default=2)
    ap.add_argument("--a1", type=Path, default=REPO_ROOT / "artifacts/a1_snapshot.json")
    ap.add_argument(
        "--source-state",
        type=Path,
        default=REPO_ROOT / "targets" / "tlv_server" / "state",
    )
    ap.add_argument(
        "--cov-file",
        type=Path,
        default=REPO_ROOT / "targets" / "snapfuzz-gate7" / "coverage" / "tlv_server.cov",
    )
    ap.add_argument(
        "--module",
        default="snapfuzz",
        help="wtf --name for every arm. The arms hardcoded 'snapfuzz', the DEV target's "
             "module, so the comparison could only ever run against one target -- and "
             "CP10's claim is about the search, which one target cannot establish",
    )
    ap.add_argument(
        "--label-prefix",
        default="cmp",
        help="prefix for the per-arm target dir and run label. A second target must not "
             "reuse 'cmp-<arm>' or it destroys the first target's evidence (D-057)",
    )
    ap.add_argument(
        "--poor-seed",
        type=Path,
        help="the single deliberately poor seed every arm starts from. Required for a "
             "target whose wire format is not the development one: the built-in default "
             "is tlv_server's, and starting from a seed that fails the target's own magic "
             "check measures the seed instead of the search",
    )
    ap.add_argument("--arms", nargs="*", help="arm names; default all")
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "artifacts/runs/gate10")
    ap.add_argument(
        "--recompute",
        action="store_true",
        help="re-derive log metrics from archived logs; runs no fuzzing",
    )
    args = ap.parse_args(argv)

    if args.recompute:
        print(f"recomputing from archived master logs in {args.out}")
        results = recompute_from_logs(args.out)
        if not results:
            raise SystemExit(f"no arm results found in {args.out}")
        (args.out / "comparison.json").write_text(
            json.dumps(
                {
                    "budget_minutes": args.minutes,
                    "workers": results[0].workers,
                    "arms": [r.to_json() for r in results],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"wrote {args.out / 'comparison.json'}")
        return 0

    # The module is a property of the TARGET, not of the experimental condition, so it is
    # substituted into every arm rather than duplicated five times in ARMS.
    arms = tuple(dataclasses.replace(a, module=args.module) for a in ARMS)
    chosen = arms
    if args.arms:
        names = set(args.arms)
        unknown = names - {a.name for a in arms}
        if unknown:
            raise SystemExit(f"unknown arm(s): {sorted(unknown)}")
        chosen = tuple(a for a in arms if a.name in names)

    poor_seed = POOR_SEEDS.get(args.module, POOR_SEED)
    if args.poor_seed:
        poor_seed = args.poor_seed.read_bytes()
        print(f"poor seed  : {args.poor_seed} ({len(poor_seed)} bytes)")
    elif args.module not in POOR_SEEDS:
        raise SystemExit(
            f"no built-in poor seed for module {args.module!r} and --poor-seed was not "
            f"given. Starting from the development target's seed would fail this target's "
            f"own magic check, so every arm would explore nothing and the comparison "
            f"would measure the seed rather than the search."
        )

    args.out.mkdir(parents=True, exist_ok=True)
    results: list[ArmResult] = []

    absent: list[str] = []
    for arm in chosen:
        print(f"\n=== {arm.name}: {arm.description} ===", flush=True)
        try:
            result = run_arm(
                arm,
                minutes=args.minutes,
                workers=args.workers,
                a1=args.a1,
                cov_file=args.cov_file,
                source_state=args.source_state,
                plateau_execs=args.plateau_execs,
                seeds=args.seeds,
                samples=args.samples,
                label_prefix=args.label_prefix,
                seed_bytes=poor_seed,
            )
        except ArmDidNotRun as exc:
            # ONE ARM THAT CANNOT RUN MUST NOT TAKE THE OTHERS WITH IT. Raising was right --
            # an arm with no executions is not a result of zero -- but raising out of the
            # LOOP meant wtf's built-in-mutator crash (0xC0000409) killed the whole
            # comparison at arm 1, so the three LLM arms were never measured either. The arm
            # is recorded as absent, loudly, and the run continues.
            absent.append(arm.name)
            print(f"  ARM DID NOT RUN: {exc}", flush=True)
            stale = args.out / f"{arm.name}.json"
            if stale.is_file():
                # A previous run's numbers for an arm that just failed would be read as this
                # run's -- the same class of error as any other stale artifact.
                stale.unlink()
                print(f"  removed a previous {stale.name}; it is not this run's result")
            continue

        results.append(result)
        (args.out / f"{arm.name}.json").write_text(
            json.dumps(result.to_json(), indent=2), encoding="utf-8"
        )
        print(
            f"  execs {result.peak_executions:<9} corpus {result.corpus_size:<4} "
            f"buckets {result.distinct_buckets} "
            f"first crash {result.seconds_to_first_crash}s "
            f"exec/s {result.mean_exec_per_s}",
            flush=True,
        )

    # MERGE with the arms already on disk, rather than replace. A `--arms` subset is the
    # normal way to re-run one arm that flaked, and writing only that subset SHRANK
    # comparison.json from five arms to two -- silently deleting the record of three runs
    # that had completed. The per-arm JSONs survived, so nothing was lost permanently, but
    # the file everyone reads said the comparison was two arms wide.
    #
    # Same rule as the label prefix above and as D-057: a re-run must not destroy evidence
    # it did not produce.
    merged: dict[str, dict] = {}
    for path in sorted(args.out.glob("*.json")):
        if path.name == "comparison.json":
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict) and payload.get("arm"):
            merged[payload["arm"]] = payload
    for result in results:
        merged[result.arm] = result.to_json()
    ordered = [merged[a.name] for a in ARMS if a.name in merged]

    (args.out / "comparison.json").write_text(
        json.dumps(
            {
                "budget_minutes": args.minutes,
                "workers": args.workers,
                "arms": ordered,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    print("\n=== comparison ===")
    header = f"{'arm':<24}{'execs':>10}{'corpus':>8}{'buckets':>9}{'1st crash':>11}{'exec/s':>9}"
    print(header)
    for result in results:
        print(
            f"{result.arm:<24}{result.peak_executions:>10}{result.corpus_size:>8}"
            f"{str(result.distinct_buckets):>9}"
            f"{str(result.seconds_to_first_crash):>11}{result.mean_exec_per_s:>9.0f}"
        )
    if absent:
        print(f"\nARMS THAT DID NOT RUN: {', '.join(absent)}")
        print("  Absent from the comparison, not zero. See the log above for the cause.")
    print(f"\nwrote {args.out / 'comparison.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
