"""GATE 4b -- distributed bring-up (CLAUDE.md section 12.6).

Gate conditions (edges 19-26, 30, 31):
  * master starts and serves >= 2 workers simultaneously
  * each worker executes and reports
  * master aggregate coverage reflects all workers, not one
  * killing one worker does not stop the campaign, and it is restarted
  * the corpus ingest path is resolved and documented, with a test that injects
    a known seed by that mechanism and proves a worker executed it
  * crash records carry worker_id
  * no LLM call in master or worker paths

Two of these need comment, because the honest answer differs from the wording:

**"aggregate coverage strictly greater than any individual worker's."** Per-worker
coverage is never exposed -- workers report to the master and the master keeps
one set (``server.h:822-830``). What *is* observable, and is the substance of the
requirement, is that throughput scales with worker count: 360 exec/s with one
worker against ~1450 with four, and ``(4 nodes)`` in the master's own stat line.
A master tracking a single worker could not show either.

**"crash records carry worker_id."** It is not recoverable. Crashes are written
by the MASTER from a worker-reported result (``server.h:861-866``, D-018), into
one directory, with no worker tag; ``wtf fuzz`` has no ``--crashes`` flag to
separate them. The contract types the field ``str | None`` precisely because of
this, and it stays None rather than being invented. Recording it would require
patching upstream wtf.

The live orchestration is guarded by ``SNAPFUZZ_LIVE_CP4B=1`` because it runs a
multi-minute campaign.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from engine_bridge.coverage import iter_stat_lines, parse_stat_line
from fuzzer.corpus import SeedSpool

REPO_ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = REPO_ROOT / "artifacts"

# GATE 4b's own evidence directory -- see the note in test_cp4.py. Produce with:
#   python -m fuzzer.run --minutes 4 --workers 4 --label gate4b
EVIDENCE = ARTIFACTS / "runs" / "gate4b"

MASTER_LOG = EVIDENCE / "master.log"
RUN_METADATA = EVIDENCE / "run_metadata.json"
WORKER_LOGS = ARTIFACTS / "logs" / "workers"

live_only = pytest.mark.skipif(
    os.environ.get("SNAPFUZZ_LIVE_CP4B") != "1",
    reason="set SNAPFUZZ_LIVE_CP4B=1 to run the multi-minute campaign",
)

# A seed that deterministically CRASHES the target, so its execution leaves
# evidence. Modelled on the author's own interesting/big_overflow.json: the
# valid Command 0 / Command 1 sequence, with the second packet declaring
# BodySize 1024 against an 8-byte body.
#
# The shape matters. An earlier version used Command 7 with BodySize 0xffff on
# the theory that a bigger overflow is a better crash; the target rejected it
# after **22 instructions** because 7 is not a valid command, so it proved
# nothing. This one runs 44.6k instructions, reaches 9,387 coverage -- more than
# normal.json's 7,632 -- and reports crash: 1.
#
# Id 4242 is the marker that makes it recognisable byte-for-byte.
CRASHING_SEED = (
    b'{"Packets":[{"Id":4242,"Command":0,"BodySize":0,"Body":[]},'
    b'{"Id":4242,"Command":1,"BodySize":1024,'
    b'"Body":[222,173,190,239,222,173,190,239]}]}'
)


# --- the spool protocol (offline) -----------------------------------------


def test_spool_write_is_atomic(tmp_path: Path) -> None:
    """Temp-then-rename, so a half-written seed is never visible (R9).

    The consumer skips ``.tmp``; if the producer wrote in place, the mutator
    could read a truncated seed and feed the target garbage that looks like a
    legitimate testcase.
    """
    spool = SeedSpool(tmp_path / "spool")
    path = spool.write(CRASHING_SEED, name="known")

    assert path.name == "known.json"
    assert path.read_bytes() == CRASHING_SEED
    assert not list(spool.path.glob("*.tmp")), "a temp file was left behind"
    assert spool.depth() == 1


def test_spool_ignores_in_progress_writes(tmp_path: Path) -> None:
    spool = SeedSpool(tmp_path / "spool")
    spool.ensure()
    (spool.path / "half-written.tmp").write_bytes(b"{partial")
    assert spool.pending() == [], "a .tmp must not be offered to the consumer"
    assert spool.depth() == 0


def test_spool_refuses_an_empty_seed(tmp_path: Path) -> None:
    """The consumer skips empty files, so writing one is a silent no-op."""
    spool = SeedSpool(tmp_path / "spool")
    with pytest.raises(ValueError, match="empty seed"):
        spool.write(b"")


def test_spool_records_provenance_separately(tmp_path: Path) -> None:
    """Only bytes cross to the guest; the rationale goes to a log.

    GATE 7 needs coverage attributable to LLM seeds, and the seed file itself
    carries no metadata.
    """
    from arch.contracts import SeedRecord

    spool = SeedSpool(tmp_path / "spool")
    record = SeedRecord(
        seed_bytes=CRASHING_SEED,
        origin="llm_seed_gen",
        rationale="oversized BodySize to reach the memcpy at 0x140001150",
    )
    spooled = spool.write_record(record)
    log = tmp_path / "provenance.jsonl"
    spool.log_provenance(record, spooled, log)

    assert spooled.read_bytes() == CRASHING_SEED  # no metadata leaked in
    entry = json.loads(log.read_text(encoding="utf-8").strip())
    assert entry["origin"] == "llm_seed_gen"
    assert "0x140001150" in entry["rationale"]


# --- topology declarations ------------------------------------------------


def test_config_can_express_more_than_one_worker() -> None:
    """CP4 says not to hardcode single-worker assumptions."""
    import yaml

    cfg = yaml.safe_load(
        (REPO_ROOT / "config" / "fuzz.yaml").read_text(encoding="utf-8")
    )
    topology = cfg["topology"]
    assert "count" in topology["workers"]
    assert topology["corpus_ingest"] == "custom_mutator_spool"


def test_worker_pool_builds_one_command_per_worker(tmp_path: Path) -> None:
    from fuzzer.workers import WorkerPool

    pool = WorkerPool(
        wtf_exe=Path("wtf.exe"),
        target_dir=tmp_path,
        name="snapfuzz",
        backend="bochscpu",
        limit=10_000_000,
        env={},
        log_dir=tmp_path / "logs",
        count=4,
    )
    cmd = pool.command()
    assert "fuzz" in cmd and "--backend=bochscpu" in cmd
    assert pool.count == 4


def test_edges_flag_is_rejected_on_non_bochscpu(tmp_path: Path) -> None:
    """wtf raises a ParseError for --edges outside bochscpu (wtf.cc:334-338)."""
    from fuzzer.workers import WorkerPool

    pool = WorkerPool(
        wtf_exe=Path("wtf.exe"),
        target_dir=tmp_path,
        name="snapfuzz",
        backend="whv",
        limit=3,
        env={},
        log_dir=tmp_path / "logs",
        edges=True,
    )
    with pytest.raises(ValueError, match="bochscpu"):
        pool.command()


# --- evidence from a multi-worker run -------------------------------------


def _stat_lines() -> list:
    if not MASTER_LOG.exists():
        return []
    return list(iter_stat_lines(MASTER_LOG.read_text(encoding="utf-8", errors="replace")))


@pytest.mark.skipif(not RUN_METADATA.exists(), reason="no run metadata")
def test_master_served_at_least_two_workers() -> None:
    """GATE 4b: the master serves >= 2 workers simultaneously."""
    meta = json.loads(RUN_METADATA.read_text(encoding="utf-8"))
    if meta["worker_count"] < 2:
        pytest.skip(
            f"last run used {meta['worker_count']} worker(s); "
            f"run `python -m fuzzer.run --workers 4`"
        )

    stats = _stat_lines()
    if not stats:
        pytest.skip("master flushed no stat lines -- D-033")
    peak_nodes = max(s.nodes for s in stats)
    assert peak_nodes >= 2, (
        f"the master only ever saw {peak_nodes} node(s); the workers did not "
        f"connect, and it would have kept fuzzing with whatever did"
    )
    assert peak_nodes == meta["worker_count"]


@pytest.mark.skipif(not RUN_METADATA.exists(), reason="no run metadata")
def test_throughput_scales_with_worker_count() -> None:
    """GATE 4b: the aggregate reflects all workers, not one.

    Per-worker coverage is never exposed, so this is the observable form of the
    requirement -- and it is a strong one: a master tracking a single worker
    could not report 4x the throughput.
    """
    meta = json.loads(RUN_METADATA.read_text(encoding="utf-8"))
    workers = meta["worker_count"]
    if workers < 2:
        pytest.skip(f"last run used {workers} worker(s)")

    stats = _stat_lines()
    if not stats:
        pytest.skip("master flushed no stat lines -- D-033")

    peak_rate = max(s.execs_per_sec for s in stats)
    # One bochscpu worker measured ~360 exec/s. Require clearly more than a
    # single worker could produce, without demanding perfect linearity.
    assert peak_rate > 360 * 1.5, (
        f"peak throughput was {peak_rate:.0f} exec/s with {workers} workers; "
        f"one worker alone reaches ~360, so the master is not aggregating"
    )


@pytest.mark.skipif(not WORKER_LOGS.exists(), reason="no worker logs")
def test_no_worker_died_of_a_broken_harness() -> None:
    """A worker that cannot resolve its breakpoints dies in Init, silently.

    The master keeps waiting for work that never comes back, so the campaign
    looks merely slow rather than broken.
    """
    for log in WORKER_LOGS.glob("*.log"):
        text = log.read_text(encoding="utf-8", errors="replace")
        assert "Could not initialize target fuzzer" not in text, (
            f"{log.name} failed in Init:\n{text[-800:]}"
        )
        assert "Could not set a breakpoint" not in text, (
            f"{log.name} could not resolve a breakpoint symbol (D-023):\n"
            f"{text[-800:]}"
        )


@pytest.mark.skipif(not RUN_METADATA.exists(), reason="no run metadata")
def test_worker_id_is_absent_and_that_is_recorded() -> None:
    """GATE 4b asks for worker_id; wtf's architecture does not provide it.

    Asserted rather than quietly skipped, so if a future wtf version starts
    tagging crashes this test fails and the deviation gets revisited.
    """
    from arch.contracts import CrashRecord

    crashes = ARTIFACTS / "a5_crashes.jsonl"
    if not crashes.exists():
        pytest.skip("no crash records")

    records = [
        CrashRecord.model_validate_json(line)
        for line in crashes.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert records
    assert all(r.worker_id is None for r in records), (
        "a crash record carries a worker_id -- if wtf now tags crashes by "
        "client, D-018 and this test should be revisited"
    )


# --- the live orchestration ------------------------------------------------


@live_only
def test_injected_seed_reaches_a_worker() -> None:
    """GATE 4b: inject a known seed by the documented path, prove it executed.

    "Proved it executed" is taken literally. The seed is a packet whose declared
    BodySize is 0xffff against an 8-byte body, which reaches the overflow path.
    The master saves the crashing testcase verbatim (``server.h:861-866``), so
    finding a file whose bytes equal the seed is proof a WORKER ran it -- not
    merely that the master consumed it from the spool.
    """
    import dataclasses

    from arch.addr import AddressSpace
    from fuzzer.run import Campaign, CampaignConfig

    base = CampaignConfig.from_yaml(
        REPO_ROOT / "config" / "fuzz.yaml",
        REPO_ROOT / "config" / "target.yaml",
        worker_count=4,
    )

    # A dedicated target tree with an EMPTY outputs/ and crashes/.
    #
    # The main tree cannot prove this: coverage there is saturated at ~13,370
    # and every common fault address already has a file, and the master skips
    # saving anything it has seen (D-024). So an injected seed can execute
    # perfectly and leave no trace. Starting from an empty corpus makes any save
    # attributable, because early testcases all register new coverage.
    clean = REPO_ROOT / "targets" / "snapfuzz-cp4b"
    if not (clean / "state" / "mem.dmp").exists():
        pytest.skip(
            f"{clean} not prepared; it needs inputs/, empty outputs/ and "
            f"crashes/, a coverage/*.cov, and state/ (a junction is fine)"
        )
    config = dataclasses.replace(base, target_dir=clean)

    a1 = json.loads((ARTIFACTS / "a1_snapshot.json").read_text(encoding="utf-8"))
    campaign = Campaign(
        config=config,
        space=AddressSpace(
            "tlv_server", a1["module_base"], a1["ghidra_image_base"]
        ),
    )
    assert not campaign.preflight(), campaign.preflight()

    spool = SeedSpool(config.seed_spool)
    spool.ensure()
    for stale in spool.pending():
        stale.unlink()

    # Populate the spool BEFORE starting, so the seeds are served among the very
    # first testcases. Injecting 15 seconds in does not work: at ~1450 exec/s the
    # workers have already run ~20,000 testcases and saturated coverage, so a
    # seed that executes correctly produces neither new coverage nor an unseen
    # fault address -- and the master saves neither (D-024). It executed, and
    # left no evidence.
    for idx in range(10):
        spool.write(CRASHING_SEED, name=f"cp4b-known-{idx}")
    assert spool.depth() == 10

    campaign.start()
    try:
        deadline = time.time() + 120
        drained = False
        while time.time() < deadline:
            time.sleep(5)
            if spool.depth() == 0:
                drained = True
                break

        assert drained, (
            f"{spool.depth()} seeds still in the spool after 90s: the master's "
            f"CustomMutator_t is not draining it, so every LLM seed would be "
            f"silently ignored (edge 21a)"
        )

        # Now the stronger claim: a worker actually ran it.
        found = False
        for directory in (config.target_dir / "crashes", config.target_dir / "outputs"):
            for path in directory.iterdir():
                if path.is_file() and path.read_bytes() == CRASHING_SEED:
                    found = True
                    print(f"injected seed executed; landed at {path}")
                    break
            if found:
                break

        assert found, (
            "the spool drained but no saved testcase matches the seed bytes. "
            "The master consumed it; whether a worker executed it is unproven."
        )

        assert campaign.pool is not None
        assert len(campaign.pool.alive()) >= 2
    finally:
        campaign.stop()


@live_only
def test_killing_a_worker_does_not_stop_the_campaign() -> None:
    """GATE 4b: kill one worker; the campaign continues and it is restarted."""
    from arch.addr import AddressSpace
    from fuzzer.run import Campaign, CampaignConfig

    config = CampaignConfig.from_yaml(
        REPO_ROOT / "config" / "fuzz.yaml",
        REPO_ROOT / "config" / "target.yaml",
        worker_count=3,
    )
    a1 = json.loads((ARTIFACTS / "a1_snapshot.json").read_text(encoding="utf-8"))
    campaign = Campaign(
        config=config,
        space=AddressSpace("tlv_server", a1["module_base"], a1["ghidra_image_base"]),
    )

    campaign.start()
    try:
        time.sleep(15)
        assert campaign.pool is not None
        assert len(campaign.pool.alive()) == 3, "pool did not fully start"

        victim = campaign.pool.workers[1]
        victim.proc.kill()
        victim.proc.wait(timeout=10)
        assert not victim.is_running

        # The master must not care.
        assert campaign.master is not None and campaign.master.is_running
        assert len(campaign.pool.alive()) == 2

        died = campaign.pool.check(restart=True)
        assert died, "the dead worker was not detected"
        time.sleep(10)

        assert len(campaign.pool.alive()) == 3, "the worker was not restarted"
        assert max(w.restarts for w in campaign.pool.workers) == 1
        assert campaign.master.is_running, "the master died with its worker"
    finally:
        campaign.stop()
