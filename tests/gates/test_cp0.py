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

from tests.gates.conftest import read_internal_doc

REPO_ROOT = Path(__file__).resolve().parents[2]
GRAPH_PATH = REPO_ROOT / "arch" / "graph.yaml"
PROGRESS_PATH = REPO_ROOT / "docs" / "PROGRESS.md"
# Internal: the gate scorecard is not distributed. `read_internal_doc` skips
# rather than fails when it is absent -- see tests/gates/conftest.py.

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
]

# Section 5 also lists these five, and they exist on a working checkout -- but they
# are INTERNAL and gitignored: the spec, the gate scorecard, the decision and
# deviation logs, and the measured results are how this was built, not how it is
# used. A clone does not have them, so requiring them would fail every clone's
# suite. Checked separately, and skipped when absent.
INTERNAL_DOCS = [
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


@pytest.mark.parametrize("relpath", INTERNAL_DOCS)
def test_internal_docs_exist_on_a_working_checkout(relpath: str) -> None:
    """Section 5 lists these, and they must not silently disappear from a working
    tree -- but a clone does not have them, so this skips there rather than failing.

    Verified by hiding all five and re-running the suite: without this split, five
    tests failed on a simulated clone.
    """
    read_internal_doc(REPO_ROOT / relpath)


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
    text = read_internal_doc(PROGRESS_PATH)
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
    """RULE 3, enforced: an edge is `live` only once its gate has proven it.

    Catches the failure RULE 3 exists to prevent -- marking an interface done
    because the code compiles, without the gate that proves it is wired.

    PARTIAL counts, and that is a deliberate loosening rather than a leak. The
    rule used to be "at least one gate says PASS", which is too coarse in a way
    that pushes the wrong direction: GATE 6's single unproven condition is the
    live GhidraMCP call, and edges 3/4/9 are about entry selection feeding A2 --
    proven, and unrelated to MCP. Under the old rule, labelling GATE 6 honestly
    as PARTIAL would have forced three edges to be marked pending that are
    demonstrably wired, which trades one false statement for three.

    What keeps PARTIAL from becoming a loophole is the companion test below: a
    PARTIAL row must name the edges it does NOT prove, and this one checks the
    edge is not among them.
    """
    # ONLY the gate table. The EDGE table's rows also start `| <number> |`, and
    # collecting both into a dict let an edge row overwrite a gate's status --
    # `| 10 | ghidra.bb_enumerate | a3_bp_list |` became gate 10's "status".
    text = _gate_table(read_internal_doc(PROGRESS_PATH))
    rows = dict(
        re.findall(
            r"^\|\s*(\d+b?)\s*\|[^|]*\|\s*\*{0,2}(\w+)\*{0,2}\s*\|", text, re.M
        )
    )
    usable = {gate for gate, status in rows.items() if status.upper() in ("PASS", "PARTIAL")}

    # "Edges 1/6/6b/7/8 stay pending", "Edge 22 still pending", "edge 14 ..."
    row_text = dict(
        re.findall(r"^\|\s*(\d+b?)\s*\|[^|]*\|[^|]*\|[^|]*\|([^|]*)\|", text, re.M)
    )  # `text` is already the gate table only

    def excluded_by(gate: str, edge_id: str) -> bool:
        """Does this gate's note say it does NOT prove ``edge_id``?

        Read to the end of the CLAUSE, not a fixed window, and keyed on "pending"
        or "not wired" only. A first attempt also accepted "stay", which matched
        "Edges 3/4/9 stay live" -- inverting the meaning of the sentence it was
        reading.
        """
        note = row_text.get(gate, "")
        for match in re.finditer(r"[Ee]dges?\s+([0-9b/, and]+)", note):
            listed = re.split(r"[/,]|\s+and\s+", match.group(1))
            if edge_id not in {piece.strip() for piece in listed if piece.strip()}:
                continue
            clause = re.split(r"[;.]", note[match.end() :], maxsplit=1)[0].lower()
            if "pending" in clause or "not wired" in clause:
                return True
        return False

    for edge in graph["edges"]:
        if edge["status"] != "live":
            continue
        gates = {str(g) for g in edge.get("gates", [])}
        assert gates, f"edge {edge['id']} is live but names no gate"
        supporting = gates & usable
        assert supporting, (
            f"edge {edge['id']} is marked live, but none of its gates "
            f"{sorted(gates)} is recorded as PASS or PARTIAL in PROGRESS.md "
            f"(recorded: {rows})"
        )
        assert not all(excluded_by(g, str(edge["id"])) for g in supporting), (
            f"edge {edge['id']} is marked live, but every supporting gate's row "
            f"lists it as pending"
        )


def _gate_table(text: str) -> str:
    """The gate-status table only.

    The edge table below it has rows of the same shape, and mixing them lets an
    edge row masquerade as a gate's status.
    """
    head, _, _ = text.partition("## Edges")
    return head


def test_a_partial_gate_says_what_it_does_not_prove(graph: dict) -> None:
    """PARTIAL is only honest if the row is specific.

    Without this, PARTIAL becomes what "PASS (Scoped)" was: a label that admits
    something is missing without saying what, which reads as PASS to anyone
    skimming (D-070). Every PARTIAL row has to name the unproven condition or the
    variable that would prove it.
    """
    text = _gate_table(read_internal_doc(PROGRESS_PATH))
    rows = re.findall(
        r"^\|\s*(\d+b?)\s*\|([^|]*)\|\s*\*{0,2}(\w+)\*{0,2}\s*\|[^|]*\|([^|]*)\|",
        text,
        re.M,
    )
    partial = [(gate, note) for gate, _, status, note in rows if status.upper() == "PARTIAL"]
    assert partial, "no gate is PARTIAL -- has the table been flattened back to PASS?"

    for gate, note in partial:
        lowered = note.lower()
        assert any(
            marker in lowered
            for marker in ("unproven", "no gate file", "not a gate", "unmet", "pending")
        ), f"gate {gate} is PARTIAL but its note does not say what is unproven: {note[:120]}"


def test_no_gate_is_pass_with_a_scoped_style_caveat() -> None:
    """The specific dishonesty this vocabulary replaced.

    "**PASS** ... **Scoped.**" let a gate whose central condition was never
    exercised present as green. Any word that means "passed, except" belongs in a
    PARTIAL row, not next to PASS.
    """
    text = _gate_table(read_internal_doc(PROGRESS_PATH))
    for line in text.splitlines():
        if not re.match(r"^\|\s*\d+b?\s*\|", line):
            continue
        if "**PASS**" not in line:
            continue
        lowered = line.lower()
        for weasel in ("scoped", "except", "unproven", "not exercised", "never executed"):
            assert weasel not in lowered, (
                f"a PASS row carries {weasel!r}, which means it is not a PASS:\n{line[:160]}"
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


# --- the contract changes from the code review (D-068) --------------------


def test_coverage_summary_says_what_its_number_counts() -> None:
    """Section 13.5: the backends measure different events. bochscpu gets
    full-system coverage (edges with --edges), whv and kvm count breakpoints on
    A3's basic blocks. A field called `total_edges` claimed all of them were
    edges, while the comment beside it in the same line of the spec said "BPs
    hit". CP10 compares numbers across arms, so the kind has to travel with them.
    """
    from arch.contracts import CoverageSummary, coverage_kind_for

    summary = CoverageSummary(
        tick=1,
        coverage_units=128,
        new_units=12,
        coverage_kind="basic_block_breakpoint",
        backend="kvm",
        plateau_ticks=0,
        corpus_size=4,
        crash_bucket_count=0,
    )
    assert summary.coverage_units == 128
    assert summary.coverage_kind == "basic_block_breakpoint"
    assert summary.backend == "kvm"

    # Derived from the backend when nobody says otherwise, and NOT "edge" for
    # bochscpu: --edges is what turns edge coverage on and this project does not
    # pass it, so claiming edges would be the overclaim the rename removes.
    assert coverage_kind_for("kvm") == "basic_block_breakpoint"
    assert coverage_kind_for("whv") == "basic_block_breakpoint"
    assert coverage_kind_for("bochscpu") == "engine_native"
    assert coverage_kind_for(None) == "engine_native"


def test_a_pre_rename_coverage_record_still_loads() -> None:
    """An audit trail a field rename silently invalidates is not an audit trail.

    The evidence bundle's whole purpose is that recorded runs stay checkable, so
    `total_edges`/`new_edges` are accepted as input aliases.
    """
    from arch.contracts import CoverageSummary

    summary = CoverageSummary.model_validate(
        {
            "tick": 7,
            "total_edges": 9686,
            "new_edges": 3,
            "plateau_ticks": 0,
            "corpus_size": 28,
            "crash_bucket_count": 2,
        }
    )
    assert summary.coverage_units == 9686
    assert summary.new_units == 3
    # A record that could not say what it counted gets the honest answer.
    assert summary.coverage_kind == "engine_native"


def test_a_coverage_delta_larger_than_the_total_is_refused() -> None:
    """Not reachable through the tracker, which computes the delta -- but a
    hand-written or corrupted artifact can carry it, and "+500 of 12 covered" is
    the kind of number that gets quoted into a writeup."""
    from arch.contracts import CoverageSummary

    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="exceeds coverage_units"):
        CoverageSummary(
            tick=1,
            coverage_units=12,
            new_units=500,
            coverage_kind="engine_native",
            plateau_ticks=0,
            corpus_size=1,
            crash_bucket_count=0,
        )


def test_an_unattributable_fault_has_no_static_address_at_all() -> None:
    """None, not 0. 0 is a real address, so the sentinel made "not attributable"
    indistinguishable from "faulted at zero" -- and it silently invited three
    things: dedup keying every external fault together, a pseudo-C lookup at
    address zero, and a consumer that just forgot (D-068).
    """
    from arch.contracts import CrashRecord

    record = CrashRecord(
        input_bytes=b"x",
        fault_type="access-violation-read",
        fault_runtime_addr=0x7FF8AA3812DE,
        backend="bochscpu",
        timestamp=0.0,
    )
    assert record.fault_static_addr is None
    assert record.address_normalized is False

    # And the converted case says so, which is the distinction the flag exists for.
    attributed = CrashRecord(
        input_bytes=b"x",
        fault_type="access-violation-write",
        fault_runtime_addr=0x7FF719E51150,
        fault_static_addr=0x140001150,
        fault_module="tlv_server",
        address_normalized=True,
        backend="bochscpu",
        timestamp=0.0,
    )
    assert attributed.address_normalized is True
    assert attributed.fault_static_addr == 0x140001150


def test_a_missing_static_address_is_rendered_for_the_model_as_a_sentence() -> None:
    """`f"{None:#x}"` is a TypeError, and `0x0` would ask the model to decode a
    sentinel -- the same demand the type change removed from our own code."""
    from analysis.triage import format_static_addr

    assert format_static_addr(None) == "not attributable to the target module"
    assert format_static_addr(0x140001150) == "0x140001150"
