"""GATE 4 -- fuzzer module + first real fuzzing run, NO LLM (CLAUDE.md CP4).

Gate conditions (edges 18-26, 30, 31; single worker):
  * a >=10-minute run on the real target produces nonzero and **growing** coverage
  * corpus grows via requeue
  * >=1 `CoverageSummary` tick written
  * any crash yields a well-formed `CrashRecord`
  * a symbolized `rip` trace proves execution reaches `FuzzEntry.static_addr`
  * **no LLM call exists in this path**

The long-run evidence is produced by `python -m fuzzer.run --minutes 12` and
lands in `artifacts/`; those tests skip if it has not been done. Everything that
can be checked without a 12-minute wait -- the parsers, the no-LLM assertion,
the module's registration -- runs unconditionally.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from arch.addr import AddressSpace
from arch.contracts import CoverageSummary, CrashRecord, TraceRef
from engine_bridge.coverage import CoverageTracker, iter_stat_lines, parse_stat_line
from engine_bridge.crash_watch import CrashWatcher, parse_crash_name

REPO_ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = REPO_ROOT / "artifacts"

COVERAGE_JSONL = ARTIFACTS / "coverage_summaries.jsonl"
CRASHES_JSONL = ARTIFACTS / "a5_crashes.jsonl"
RUN_METADATA = ARTIFACTS / "run_metadata.json"
MASTER_LOG = ARTIFACTS / "logs" / "master.log"
SYMBOLIZED = ARTIFACTS / "traces-symbolized" / "snapfuzz.rip.txt"

# From artifacts/a1_snapshot.json, verified in tests/test_addr.py.
MODULE_BASE = 0x7FF719E50000
GHIDRA_IMAGE_BASE = 0x140000000
ENTRY_STATIC = 0x140001150
ENTRY_SYMBOL = "ProcessPacket"

# Fast-path modules. Section 12.2: the master counts as fast clock too, so an
# LLM call in any of these stalls every worker.
FAST_PATH_MODULES = [
    REPO_ROOT / "fuzzer" / "run.py",
    REPO_ROOT / "fuzzer" / "master.py",
    REPO_ROOT / "fuzzer" / "workers.py",
    REPO_ROOT / "fuzzer" / "corpus.py",
    REPO_ROOT / "fuzzer" / "build.py",
    REPO_ROOT / "engine_bridge" / "coverage.py",
    REPO_ROOT / "engine_bridge" / "crash_watch.py",
]

requires_run = pytest.mark.skipif(
    not COVERAGE_JSONL.exists(),
    reason="no campaign artifacts; run `python -m fuzzer.run --minutes 12`",
)


# --- the no-LLM assertion (CP4 requires this explicitly) ------------------


@pytest.mark.parametrize("module", FAST_PATH_MODULES, ids=lambda p: p.name)
def test_no_llm_import_on_the_fast_path(module: Path) -> None:
    """Assert no LLM client is reachable from the fast loop or the master.

    Checked structurally with the AST rather than by grepping for a word, so a
    comment mentioning "llm" does not fail the gate and an aliased import does
    not pass it.
    """
    tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
    offenders: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in {"llm", "openai", "httpx", "anthropic", "dspy"}:
                    offenders.append(f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in {"llm", "openai", "httpx", "anthropic", "dspy"}:
                offenders.append(f"from {node.module} import ...")

    assert not offenders, (
        f"{module.name} reaches an LLM client on the fast path: {offenders}. "
        f"The slow clock is a separate process (section 12.2)."
    )


def test_fuzzer_module_does_not_call_out_to_the_network() -> None:
    """The C++ module runs on both master and worker; it must stay local.

    The seed spool is a directory read, which is the point -- section 12.1's
    ingest path deliberately avoids putting anything network-shaped on the
    master's hot path.
    """
    source = (REPO_ROOT / "fuzzer" / "module" / "fuzzer_snapfuzz.cc").read_text(
        encoding="utf-8"
    )
    for forbidden in ("curl", "socket(", "WSAStartup", "InternetOpen", "http://",
                      "https://"):
        assert forbidden not in source, (
            f"fuzzer module references {forbidden!r}; it runs per test-case on "
            f"the master and per iteration on the worker"
        )


def test_module_declares_the_nonblocking_spool_contract() -> None:
    """The spool read must be best-effort. A blocking read stalls every worker."""
    source = (REPO_ROOT / "fuzzer" / "module" / "fuzzer_snapfuzz.cc").read_text(
        encoding="utf-8"
    )
    # std::error_code overloads are the non-throwing filesystem API; using the
    # throwing ones inside GetNewTestcase would abort the master on a missing dir.
    assert "std::error_code" in source
    assert "SNAPFUZZ_SEED_SPOOL" in source


# --- stat line parsing (the aggregate coverage read path) -----------------


def test_parses_a_real_master_stat_line() -> None:
    line = (
        "#7158 cov: 12636 (+5) corp: 32 (28.6kb) exec/s: 357.0 (1 nodes) "
        "lastcov: 9.0s crash: 1113 timeout: 0 cr3: 0 uptime: 24.0s"
    )
    stats = parse_stat_line(line)
    assert stats is not None
    assert stats.execs == 7158
    assert stats.coverage == 12636
    assert stats.new_coverage == 5
    assert stats.corpus_size == 32
    assert stats.execs_per_sec == 357.0
    assert stats.nodes == 1
    assert stats.crash_events == 1113
    assert stats.uptime_s == 24.0
    assert not stats.is_multi_worker


def test_tolerates_the_first_line_sentinel_rate() -> None:
    """The master's very first line carries a garbage exec/s."""
    line = (
        "#0 cov: 0 (+0) corp: 0 (0.0b) exec/s: 9223372036854.8m (1 nodes) "
        "lastcov: 4.0s crash: 0 timeout: 0 cr3: 0 uptime: 4.0s"
    )
    stats = parse_stat_line(line)
    assert stats is not None
    assert stats.coverage == 0
    assert stats.execs_per_sec >= 0.0  # parsed, not crashed


def test_uptime_units_are_converted() -> None:
    """wtf switches to minutes after 60s; a raw number would read as 2 seconds."""
    base = (
        "#1 cov: 5 (+5) corp: 1 (1.0b) exec/s: 1.0 (1 nodes) lastcov: 0.0s "
        "crash: 0 timeout: 0 cr3: 0 uptime: "
    )
    assert parse_stat_line(base + "30.0s").uptime_s == 30.0
    assert parse_stat_line(base + "2.0min").uptime_s == 120.0


def test_non_stat_lines_are_ignored() -> None:
    for line in (
        "Saving output in .\\outputs\\975e0ce6",
        "Setting mxcsr_mask to 0xffbf.",
        "",
    ):
        assert parse_stat_line(line) is None


def test_tracker_detects_growth_and_plateau() -> None:
    lines = [
        "#0 cov: 0 (+0) corp: 0 (0.0b) exec/s: 1.0 (1 nodes) lastcov: 0.0s "
        "crash: 0 timeout: 0 cr3: 0 uptime: 1.0s",
        "#100 cov: 500 (+500) corp: 5 (1.0kb) exec/s: 1.0 (1 nodes) lastcov: 0.0s "
        "crash: 0 timeout: 0 cr3: 0 uptime: 2.0s",
        "#200 cov: 500 (+0) corp: 5 (1.0kb) exec/s: 1.0 (1 nodes) lastcov: 1.0s "
        "crash: 0 timeout: 0 cr3: 0 uptime: 3.0s",
        "#300 cov: 500 (+0) corp: 5 (1.0kb) exec/s: 1.0 (1 nodes) lastcov: 2.0s "
        "crash: 0 timeout: 0 cr3: 0 uptime: 4.0s",
    ]
    tracker = CoverageTracker()
    summaries = [tracker.observe(s) for s in iter_stat_lines("\n".join(lines))]

    assert len(summaries) == 4
    assert summaries[1].new_edges == 500
    assert tracker.is_growing
    # Two consecutive ticks without new coverage.
    assert summaries[-1].plateau_ticks == 2
    # And the plateau counter resets on new coverage.
    assert summaries[1].plateau_ticks == 0


# --- crash record derivation ----------------------------------------------


def test_parses_wtf_crash_filenames() -> None:
    parsed = parse_crash_name("crash-EXCEPTION_ACCESS_VIOLATION_READ-0x7ff8aa381423")
    assert parsed == ("access-violation-read", 0x7FF8AA381423)

    write = parse_crash_name("crash-EXCEPTION_ACCESS_VIOLATION_WRITE-0x7ff8aa381550")
    assert write == ("access-violation-write", 0x7FF8AA381550)

    # A module-specific name (hevd uses bugcheck codes) does not match, and the
    # caller must keep the file rather than discard it.
    assert parse_crash_name("crash-0xfffff764b91c0000-0x0-0x2") is None


def test_crash_records_carry_static_addresses(tmp_path: Path) -> None:
    """Section 10 forbids hashing runtime addresses -- they must be de-slid."""
    crashes = tmp_path / "crashes"
    crashes.mkdir()
    (crashes / "crash-EXCEPTION_ACCESS_VIOLATION_READ-0x7ff719e51160").write_bytes(
        b'{"Packets":[]}'
    )

    watcher = CrashWatcher(
        crashes_dir=crashes,
        space=AddressSpace("tlv_server", MODULE_BASE, GHIDRA_IMAGE_BASE),
        backend="bochscpu",
    )
    records = watcher.poll()
    assert len(records) == 1

    record = records[0]
    assert record.fault_runtime_addr == 0x7FF719E51160
    assert record.fault_static_addr == 0x140001160  # de-slid
    assert record.backend == "bochscpu"
    # Not invented: these need a replay (CP8).
    assert record.registers == {}
    assert record.backtrace == []
    assert record.worker_id is None
    # And it round-trips as a contract.
    assert CrashRecord.model_validate_json(record.model_dump_json()) == record


def test_watcher_does_not_re_report_or_double_count(tmp_path: Path) -> None:
    crashes = tmp_path / "crashes"
    crashes.mkdir()
    (crashes / "crash-EXCEPTION_ACCESS_VIOLATION_READ-0x1000").write_bytes(b"a")

    watcher = CrashWatcher(
        crashes_dir=crashes,
        space=AddressSpace("m", MODULE_BASE, GHIDRA_IMAGE_BASE),
        backend="bochscpu",
    )
    assert len(watcher.poll()) == 1
    assert watcher.poll() == []  # already seen

    (crashes / "crash-EXCEPTION_ACCESS_VIOLATION_WRITE-0x2000").write_bytes(b"b")
    assert len(watcher.poll()) == 1


def test_priming_excludes_pre_existing_crashes(tmp_path: Path) -> None:
    """A run must not be credited with crashes that were already on disk."""
    crashes = tmp_path / "crashes"
    crashes.mkdir()
    (crashes / "crash-EXCEPTION_ACCESS_VIOLATION_READ-0x1000").write_bytes(b"old")

    watcher = CrashWatcher(
        crashes_dir=crashes,
        space=AddressSpace("m", MODULE_BASE, GHIDRA_IMAGE_BASE),
        backend="bochscpu",
    )
    assert watcher.prime() == 1
    assert watcher.poll() == []


# --- evidence from the long run -------------------------------------------


@requires_run
def test_coverage_ticks_were_written() -> None:
    """GATE 4: >=1 CoverageSummary tick written."""
    summaries = [
        CoverageSummary.model_validate_json(line)
        for line in COVERAGE_JSONL.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert summaries, "no coverage ticks recorded"
    assert all(s.tick > 0 for s in summaries)


@requires_run
def test_coverage_is_nonzero_and_growing() -> None:
    """GATE 4: nonzero AND growing coverage."""
    summaries = [
        CoverageSummary.model_validate_json(line)
        for line in COVERAGE_JSONL.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert max(s.total_edges for s in summaries) > 0, "coverage never left zero"
    assert any(s.new_edges > 0 for s in summaries), (
        "coverage never grew: the harness may be running but not reaching new code"
    )


@requires_run
def test_corpus_grew_via_requeue() -> None:
    """GATE 4: corpus grows via requeue (edge 26, decided at the master)."""
    summaries = [
        CoverageSummary.model_validate_json(line)
        for line in COVERAGE_JSONL.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    sizes = [s.corpus_size for s in summaries]
    assert max(sizes) > min(sizes), f"corpus never grew: {sizes[:10]}"


@requires_run
def test_run_lasted_at_least_ten_minutes() -> None:
    """GATE 4 says >=10 minutes, measured by the runner.

    Deliberately NOT read from the master's ``uptime`` field: the master
    block-buffers stdout and terminating it never flushes the last buffer, so
    its final minutes of stat lines are lost. A duration proved from a number
    that can silently truncate would understate the run.
    """
    if not RUN_METADATA.exists():
        pytest.skip("no run metadata; re-run `python -m fuzzer.run`")
    meta = json.loads(RUN_METADATA.read_text(encoding="utf-8"))
    duration = meta.get("duration_s")
    assert duration is not None, "run metadata has no duration"
    assert duration >= 600, f"run lasted {duration:.0f}s, GATE 4 requires >=600s"


@requires_run
def test_run_metadata_records_a_single_worker_on_bochscpu() -> None:
    """CP4 is explicitly the single-worker bring-up; CP4b scales it."""
    if not RUN_METADATA.exists():
        pytest.skip("no run metadata")
    meta = json.loads(RUN_METADATA.read_text(encoding="utf-8"))
    assert meta["worker_count"] == 1, "CP4 uses ONE worker; N workers is GATE 4b"
    assert meta["backend"] == "bochscpu"
    assert meta["module"] == "snapfuzz", (
        f"the campaign ran module {meta['module']!r} -- if this is not ours, the "
        f"run proves nothing about our harness"
    )


@requires_run
def test_the_run_produced_corpus_and_crashes_on_disk() -> None:
    """Edges 30 and 31: A4 and A5 actually gained files during the run."""
    if not RUN_METADATA.exists():
        pytest.skip("no run metadata")
    meta = json.loads(RUN_METADATA.read_text(encoding="utf-8"))
    assert meta["outputs_after"] > meta["outputs_before"], (
        f"outputs/ did not grow ({meta['outputs_before']} -> "
        f"{meta['outputs_after']}): the master saves a testcase only when it "
        f"finds NEW coverage, so no growth means no new coverage"
    )
    assert meta["coverage_grew"] is True


@requires_run
def test_crashes_are_well_formed_records() -> None:
    """GATE 4: any crash yields a well-formed CrashRecord."""
    if not CRASHES_JSONL.exists():
        pytest.skip("no crashes recorded in this run")
    records = [
        CrashRecord.model_validate_json(line)
        for line in CRASHES_JSONL.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert records
    for record in records:
        assert record.fault_type
        assert record.backend in {"bochscpu", "whv", "kvm"}
        if record.fault_runtime_addr:
            # De-slid, per section 9.
            assert record.fault_static_addr != record.fault_runtime_addr


# --- harness validation (mandatory, CP4) ----------------------------------


@pytest.mark.skipif(
    not SYMBOLIZED.exists(),
    reason="no symbolized trace; run `python -m analysis.trace ...`",
)
def test_symbolized_trace_reaches_the_fuzz_entry() -> None:
    """GATE 4: a symbolized rip trace proves execution reaches FuzzEntry.

    CP4 calls this mandatory and names the failure it catches: a harness that
    runs and reports coverage but never enters the parser.
    """
    from analysis.trace import first_hit, module_histogram

    line = first_hit(SYMBOLIZED, ENTRY_SYMBOL)
    assert line is not None, (
        f"{ENTRY_SYMBOL} never appears in {SYMBOLIZED.name}. The harness is not "
        f"fuzzing the intended code. Modules seen: "
        f"{module_histogram(SYMBOLIZED, 5)}"
    )
    # The snapshot breaks AT the entry, so it should be the very first
    # instruction, not merely somewhere in the trace.
    assert line == 1, f"{ENTRY_SYMBOL} first appears at line {line}, expected 1"


@pytest.mark.skipif(
    not SYMBOLIZED.exists(), reason="no symbolized trace"
)
def test_trace_ref_validates_as_a_contract() -> None:
    from analysis.trace import first_hit

    ref = TraceRef(
        bucket_id="harness-validation",
        trace_type="rip",
        raw_path=str(ARTIFACTS / "traces" / "snapfuzz" / "normal.json.trace"),
        symbolized_path=str(SYMBOLIZED),
        reached_fuzz_entry=first_hit(SYMBOLIZED, ENTRY_SYMBOL) is not None,
    )
    assert ref.reached_fuzz_entry
    assert TraceRef.model_validate_json(ref.model_dump_json()) == ref


# --- the module is actually in the built binary ---------------------------


@pytest.mark.skipif(
    not (REPO_ROOT / "src" / "build" / "wtf.exe").exists(),
    reason="wtf.exe not built",
)
def test_snapfuzz_module_is_registered() -> None:
    """A stale wtf.exe runs the OLD module and looks completely healthy."""
    from fuzzer.build import registered_targets

    targets = registered_targets()
    assert "snapfuzz" in targets, f"registered: {targets}"


def test_a1_and_config_agree_on_the_entry() -> None:
    """A1, A3 and config/target.yaml must name the same address.

    If they drift, CP4 instruments one function and fuzzes another.
    """
    import yaml

    a1 = ARTIFACTS / "a1_snapshot.json"
    if not a1.exists():
        pytest.skip("A1 not generated")

    ref = json.loads(a1.read_text(encoding="utf-8"))
    space = AddressSpace("tlv_server", ref["module_base"], ref["ghidra_image_base"])
    assert space.to_static(ref["entry_runtime_addr"]) == ENTRY_STATIC

    cfg = yaml.safe_load(
        (REPO_ROOT / "config" / "target.yaml").read_text(encoding="utf-8")
    )
    assert cfg["entry"]["static_addr"] == ENTRY_STATIC
    assert cfg["entry"]["symbol"] == ENTRY_SYMBOL
