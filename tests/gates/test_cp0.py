"""GATE 0 -- scaffold, contracts, config, graph (CLAUDE.md CP0).

Gate conditions:
  * contracts import cleanly
  * graph YAML parses and every section-3.2 edge is present
  * the graph test passes            -> tests/gates/test_graph.py
  * docs/PROGRESS.md lists every edge as pending

The graph's own well-formedness lives in test_graph.py; this file covers the
rest and checks the two are consistent with each other.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
GRAPH_PATH = REPO_ROOT / "arch" / "graph.yaml"
PROGRESS_PATH = REPO_ROOT / "docs" / "PROGRESS.md"

CANONICAL_EDGE_IDS = frozenset(
    [str(i) for i in range(1, 21)]
    + ["21a", "21b"]
    + [str(i) for i in range(22, 44)]
    + ["23b", "32b", "32c", "36b", "37b", "41b"]
)

# CLAUDE.md section 5. Directories are required now; the .py files inside them
# arrive at the checkpoint that implements them.
EXPECTED_LAYOUT = [
    "arch/contracts.py",
    "arch/graph.yaml",
    "arch/addr.py",
    "config/llm.yaml",
    "config/fuzz.yaml",
    "config/target.yaml",
    "prep",
    "fuzzer/module",
    "engine_bridge",
    "llm/prompts",
    "analysis",
    "orchestrator",
    "eval/planted_bugs",
    "tests/gates",
    "docs/PROGRESS.md",
    "docs/DECISIONS.md",
    "docs/DEVIATIONS.md",
    "docs/ENVIRONMENT.md",
    "docs/RESULTS.md",
]


@pytest.fixture(scope="module")
def graph() -> dict:
    with GRAPH_PATH.open(encoding="utf-8") as fd:
        return yaml.safe_load(fd)


@pytest.mark.parametrize("relpath", EXPECTED_LAYOUT)
def test_layout_exists(relpath: str) -> None:
    assert (REPO_ROOT / relpath).exists(), f"missing from section 5 layout: {relpath}"


def test_graph_impl_paths_live_in_real_directories(graph: dict) -> None:
    """Every node names where it will be implemented, in a directory that exists.

    Catches a node pointing at a stage directory section 5 never declared.
    """
    for name, node in graph["nodes"].items():
        impl = node.get("impl")
        if not impl:
            continue
        parent = (REPO_ROOT / impl).parent
        assert parent.is_dir(), (
            f"node {name!r} declares impl {impl!r} but {parent} does not exist"
        )


# --- contracts ------------------------------------------------------------


def test_contracts_import_cleanly() -> None:
    from arch import contracts

    for name in contracts.__all__:
        assert hasattr(contracts, name), f"contracts.__all__ names missing {name}"


def test_contracts_round_trip_through_json() -> None:
    """Every stage boundary serialises to JSON on disk (section 6)."""
    from arch.contracts import CoverageSummary, FuzzEntry, SnapshotRef, TraceRef

    entry = FuzzEntry(
        module="tlv_server",
        symbol="ProcessPacket",
        static_addr=0x140001150,
        rationale="only parser reached from the socket read",
        input_param="rcx",
        size_param="rdx",
    )
    assert FuzzEntry.model_validate_json(entry.model_dump_json()) == entry

    ref = SnapshotRef(
        path="targets/tlv_server/state",
        os="windows",
        mem_dmp="targets/tlv_server/state/mem.dmp",
        regs_json="targets/tlv_server/state/regs.json",
        symbol_store_json="targets/tlv_server/state/symbol-store.json",
        module_base=0x7FF719E50000,
        ghidra_image_base=0x140000000,
        entry_runtime_addr=0x7FF719E51150,
        aslr_disabled=False,
    )
    assert SnapshotRef.model_validate_json(ref.model_dump_json()) == ref

    summary = CoverageSummary(
        tick=1,
        total_edges=128,
        new_edges=12,
        plateau_ticks=0,
        corpus_size=7,
        crash_bucket_count=0,
        frontier=[0x140001020],
    )
    assert CoverageSummary.model_validate_json(summary.model_dump_json()) == summary

    trace = TraceRef(
        bucket_id="b0",
        trace_type="rip",
        raw_path="traces/b0.rip.trace",
        symbolized_path="traces-sym/b0.rip.trace",
        reached_fuzz_entry=True,
    )
    assert TraceRef.model_validate_json(trace.model_dump_json()) == trace


def test_binary_contracts_survive_non_utf8_bytes() -> None:
    """Fuzz inputs are arbitrary bytes; JSON must not mangle or reject them.

    Pydantic's default UTF-8 handling for `bytes` raises on exactly the inputs
    fuzzing produces, so SeedRecord and CrashRecord opt into base64.
    """
    from arch.contracts import CrashRecord, SeedRecord

    payload = bytes(range(256))

    seed = SeedRecord(
        seed_bytes=payload,
        origin="llm_seed_gen",
        rationale="magic 'RIFF' header to pass the check at 0x1400010a4",
    )
    assert SeedRecord.model_validate_json(seed.model_dump_json()).seed_bytes == payload

    crash = CrashRecord(
        input_bytes=payload,
        fault_type="access-violation",
        fault_runtime_addr=0x7FF719E51150,
        fault_static_addr=0x140001150,
        registers={"rax": 0x41414141, "rip": 0x7FF719E51150},
        backtrace=[0x140001150, 0x140001000],
        coverage_delta=3,
        worker_id="worker-02",
        backend="bochscpu",
        timestamp=1753401600.0,
    )
    restored = CrashRecord.model_validate_json(crash.model_dump_json())
    assert restored.input_bytes == payload
    assert restored == crash


def test_contracts_reject_out_of_contract_values() -> None:
    """The Literal fields are real constraints, not documentation."""
    from pydantic import ValidationError

    from arch.contracts import CrashRecord, TriageVerdict

    with pytest.raises(ValidationError):
        CrashRecord(
            input_bytes=b"",
            fault_type="access-violation",
            fault_runtime_addr=0,
            fault_static_addr=0,
            backend="qemu",  # not one of wtf's three backends
            timestamp=0.0,
        )

    with pytest.raises(ValidationError):
        TriageVerdict(
            bucket_id="b0",
            verdict="verified",  # section 1: triage never says "verified"
            confidence=1.0,
            exploitability="dos",
            root_cause="",
            signals_used=[],
            reproducer_input_path="",
        )


def test_linux_snapshot_requires_aslr_off_and_a_symbol_store() -> None:
    """Section 6 / 13.1 state these as requirements; they are enforced.

    Both are silent failures on Linux: with ASLR on every address conversion is
    quietly wrong, and without symbol-store.json there are no coverage
    breakpoints at all because Linux has no dbgeng.
    """
    from pydantic import ValidationError

    from arch.contracts import SnapshotRef

    base = dict(
        path="targets/x/state",
        os="linux",
        mem_dmp="targets/x/state/mem.dmp",
        regs_json="targets/x/state/regs.json",
        symbol_store_json="targets/x/state/symbol-store.json",
        module_base=0x400000,
        ghidra_image_base=0x400000,
        entry_runtime_addr=0x401150,
        aslr_disabled=True,
    )

    SnapshotRef(**base)  # the valid case

    with pytest.raises(ValidationError, match="aslr_disabled"):
        SnapshotRef(**{**base, "aslr_disabled": False})

    with pytest.raises(ValidationError, match="symbol_store_json"):
        SnapshotRef(**{**base, "symbol_store_json": None})

    # Windows has dbgeng and regenerates the symbol store at runtime, so
    # neither constraint applies there.
    SnapshotRef(**{**base, "os": "windows", "symbol_store_json": None})


def test_replay_result_refuses_an_undefended_determinism_claim() -> None:
    """Section 13.5: only bochscpu is deterministic by default.

    Concluding "nondeterministic" from whv/kvm without re-checking on bochscpu
    is a listed anti-pattern, so the contract will not accept it silently.
    """
    from pydantic import ValidationError

    from arch.contracts import ReplayResult

    ReplayResult(
        bucket_id="b0", reproduced=True, deterministic=True, replays=5,
        backend="bochscpu",
    )

    with pytest.raises(ValidationError, match="bochscpu"):
        ReplayResult(
            bucket_id="b0", reproduced=False, deterministic=False, replays=5,
            backend="kvm",
        )

    # Allowed once the reasoning is recorded.
    ReplayResult(
        bucket_id="b0", reproduced=False, deterministic=False, replays=5,
        backend="kvm",
        notes="re-checked on bochscpu: reproduced there, so this is kvm "
        "nondeterminism rather than a state-dependent bug",
    )


def test_five_triage_signals_are_named(graph: dict) -> None:
    from arch.contracts import TRIAGE_SIGNALS

    assert len(TRIAGE_SIGNALS) == 5
    assert len(set(TRIAGE_SIGNALS)) == 5


# --- PROGRESS.md must not drift from the graph ---------------------------


def _progress_rows() -> dict[str, str]:
    text = PROGRESS_PATH.read_text(encoding="utf-8")
    return dict(
        re.findall(r"^\|\s*(\d+[a-z]?)\s*\|.*?\|\s*(pending|live)\s*\|", text, re.M)
    )


def test_progress_lists_every_edge() -> None:
    """GATE 0: docs/PROGRESS.md accounts for every section-3.2 edge.

    At CP0 every edge was `pending`; that was a snapshot of a moment, not an
    invariant. What must hold permanently is that no edge goes missing from the
    table, and that going `live` is earned -- see
    :func:`test_live_edges_have_a_passed_gate`.
    """
    rows = _progress_rows()
    for edge_id in sorted(CANONICAL_EDGE_IDS):
        assert edge_id in rows, f"edge {edge_id} is not listed in PROGRESS.md"


def test_live_edges_have_a_passed_gate(graph: dict) -> None:
    """RULE 3, enforced: an edge is `live` only once its gate has passed.

    Catches the failure RULE 3 exists to prevent -- marking an interface done
    because the code compiles, without the gate that proves it is wired.
    """
    text = PROGRESS_PATH.read_text(encoding="utf-8")
    # Gate-status table rows: | 2 | ... | **PASS** | ... |
    passed_gates = {
        gate
        for gate, status in re.findall(
            r"^\|\s*(\d+b?)\s*\|[^|]*\|\s*\*{0,2}(\w+)\*{0,2}\s*\|", text, re.M
        )
        if status.upper() == "PASS"
    }

    for edge in graph["edges"]:
        if edge["status"] != "live":
            continue
        gates = {str(g) for g in edge.get("gates", [])}
        assert gates, f"edge {edge['id']} is live but names no gate"
        assert gates & passed_gates, (
            f"edge {edge['id']} is marked live, but none of its gates "
            f"{sorted(gates)} is recorded as PASS in PROGRESS.md "
            f"(passed: {sorted(passed_gates)})"
        )


def test_progress_status_matches_graph(graph: dict) -> None:
    """PROGRESS.md and graph.yaml must not drift apart."""
    rows = _progress_rows()
    for edge in graph["edges"]:
        eid = edge["id"]
        assert eid in rows, f"edge {eid} is in graph.yaml but not PROGRESS.md"
        assert rows[eid] == edge["status"], (
            f"edge {eid}: PROGRESS.md says {rows[eid]}, "
            f"graph.yaml says {edge['status']}"
        )


# --- config ---------------------------------------------------------------


def test_configs_parse() -> None:
    for name in ("llm.yaml", "fuzz.yaml", "target.yaml"):
        path = REPO_ROOT / "config" / name
        with path.open(encoding="utf-8") as fd:
            assert yaml.safe_load(fd) is not None, f"{name} parsed as empty"


def test_fuzz_config_declares_the_distributed_topology() -> None:
    """Section 12.4: worker count and ingest path are config, not assumptions.

    CP4 explicitly says not to hardcode single-worker assumptions.
    """
    cfg = yaml.safe_load((REPO_ROOT / "config" / "fuzz.yaml").read_text("utf-8"))
    topology = cfg["topology"]
    assert topology["workers"]["count"] >= 1
    assert topology["workers"]["backend"] in {"bochscpu", "whv", "kvm"}
    assert "corpus_ingest" in topology, (
        "the corpus ingest path must be declared, even as `unresolved` "
        "(section 12.4) -- assuming it is the single worst silent failure here"
    )


def test_plateau_is_defined_in_executions_not_wall_clock() -> None:
    """Section 12.3: a wall-clock threshold tuned on 1 worker fires far too late.

    With N workers the execution budget burns ~N times faster.
    """
    cfg = yaml.safe_load((REPO_ROOT / "config" / "fuzz.yaml").read_text("utf-8"))
    plateau = cfg["plateau"]
    assert "plateau_execs_threshold" in plateau, (
        "plateau must be primarily defined in total executions without new "
        "coverage, not wall-clock time"
    )
    assert "wall_clock_bound_s" in plateau, "a wall-clock safety bound is required"


def test_limit_is_keyed_by_backend() -> None:
    """--limit is an instruction count on bochscpu and seconds on whv/kvm.

    Confirmed by wtf.cc:267-268. One shared value is a silent misconfiguration
    on whichever backend it does not match.
    """
    cfg = yaml.safe_load((REPO_ROOT / "config" / "fuzz.yaml").read_text("utf-8"))
    limit = cfg["wtf"]["limit"]
    assert isinstance(limit, dict), "`wtf.limit` must be keyed by backend"
    assert set(limit) == {"bochscpu", "whv", "kvm"}
    assert limit["bochscpu"] > limit["whv"] * 1000, (
        "bochscpu counts instructions and whv counts seconds; these values look "
        "like the same unit, which means one of them is wrong"
    )


def test_no_secrets_committed_in_config() -> None:
    """Section 10: never hardcode the LLM base URL or token outside config.

    And the token does not belong in config either -- it is read from the
    environment. This catches a pasted key before it reaches a commit.
    """
    text = (REPO_ROOT / "config" / "llm.yaml").read_text(encoding="utf-8")
    cfg = yaml.safe_load(text)
    # EVERY provider, not one `endpoint` block. This read `cfg["endpoint"]`, which
    # stopped existing when the config became multi-provider -- so it resolved to
    # None, compared None to (None, ""), and passed unconditionally. A test whose
    # whole job is to catch a pasted key had stopped being able to fail.
    providers = cfg.get("providers") or {}
    assert providers, "config/llm.yaml declares no providers"
    for name, provider in providers.items():
        assert (provider or {}).get("api_key") in (None, ""), (
            f"provider {name} carries an inline api_key; it must come from the "
            f"environment variable named by its api_key_env"
        )
    assert not re.search(r"\bsk-[A-Za-z0-9]{16,}", text), (
        "config/llm.yaml looks like it contains an API key"
    )
