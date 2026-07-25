"""Structural checks on arch/graph.yaml (CLAUDE.md CP0).

These assert the architecture graph is well-formed. They say nothing about
whether an edge is implemented -- that is `status`, and flipping an edge to
`live` is the job of the checkpoint gate named in its `gates` list.

Several checks exist because the corresponding mistake fails *silently* at
runtime rather than erroring, which is the whole reason RULE 4 was added:

* `test_no_llm_call_on_master_or_worker` -- RULE 1 in the distributed case.
* `test_module_is_loaded_by_both_roles` -- if 21a dies the master falls back to
  a built-in mutator and every LLM seed is ignored, while coverage keeps
  climbing and the campaign looks healthy.
* `test_worker_facing_edges_declare_fanout` -- interfaces 2 and 3 go to *every*
  worker; wiring them once to a single engine is the classic bug.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
GRAPH_PATH = REPO_ROOT / "arch" / "graph.yaml"

# The authoritative edge list in CLAUDE.md section 3.2, including its lettered
# sub-edges. 50 edges. Must never be renumbered.
CANONICAL_EDGE_IDS = frozenset(
    [str(i) for i in range(1, 21)]  # 1..20
    + ["21a", "21b"]  # module loaded by master AND worker
    + [str(i) for i in range(22, 44)]  # 22..43
    + ["23b", "32b", "32c", "36b", "37b", "41b"]
)

VALID_STATUSES = frozenset({"pending", "live"})
VALID_KINDS = frozenset({"input", "process", "artifact"})
FAST_CLOCK_ROLES = frozenset({"master", "worker"})


@pytest.fixture(scope="module")
def graph() -> dict:
    with GRAPH_PATH.open(encoding="utf-8") as fd:
        return yaml.safe_load(fd)


@pytest.fixture(scope="module")
def nodes(graph: dict) -> dict:
    return graph["nodes"]


@pytest.fixture(scope="module")
def edges(graph: dict) -> list[dict]:
    return graph["edges"]


@pytest.fixture(scope="module")
def successors(edges: list[dict]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        out[edge["from"]].add(edge["to"])
    return out


def _reachable(start: set[str], successors: dict[str, set[str]]) -> set[str]:
    seen = set(start)
    stack = list(start)
    while stack:
        for nxt in successors.get(stack.pop(), ()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


# --- well-formedness -----------------------------------------------------


def test_graph_parses(graph: dict) -> None:
    assert graph["version"] == 2
    assert graph["nodes"], "graph declares no nodes"
    assert graph["edges"], "graph declares no edges"
    assert graph["roots"], "graph declares no roots"


def test_all_canonical_edges_present(edges: list[dict]) -> None:
    """GATE 0: every edge of CLAUDE.md section 3.2 is transcribed."""
    present = {e["id"] for e in edges}
    missing = sorted(CANONICAL_EDGE_IDS - present)
    assert not missing, f"section 3.2 edges missing from graph.yaml: {missing}"


def test_edge_ids_are_strings(edges: list[dict]) -> None:
    """Lettered ids exist, so ids are uniformly strings, never ints."""
    bad = [e["id"] for e in edges if not isinstance(e["id"], str)]
    assert not bad, f"edge ids must be quoted strings in YAML: {bad}"


def test_edge_ids_are_unique(edges: list[dict]) -> None:
    ids = [e["id"] for e in edges]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    assert not dupes, f"duplicate edge ids: {dupes}"


def test_non_canonical_edges_are_flagged_derived(edges: list[dict]) -> None:
    """Anything not in section 3.2 must announce itself as derived.

    This keeps the canonical list honest: an edge cannot be quietly invented to
    make a gate pass.
    """
    for edge in edges:
        if edge["id"] in CANONICAL_EDGE_IDS:
            continue
        assert edge.get("derived") is True, (
            f"edge {edge['id']} is not in section 3.2 and is not marked "
            f"`derived: true`"
        )
        assert edge.get("note"), f"derived edge {edge['id']} carries no rationale"


def test_edge_endpoints_are_declared_nodes(edges: list[dict], nodes: dict) -> None:
    for edge in edges:
        for side in ("from", "to"):
            assert edge[side] in nodes, (
                f"edge {edge['id']} references undeclared node "
                f"{edge[side]!r} on the {side!r} side"
            )


def test_edge_statuses_are_valid(edges: list[dict]) -> None:
    for edge in edges:
        assert edge["status"] in VALID_STATUSES, (
            f"edge {edge['id']} has status {edge['status']!r}, "
            f"expected one of {sorted(VALID_STATUSES)}"
        )


def test_node_kinds_are_valid(nodes: dict) -> None:
    for name, node in nodes.items():
        assert node["kind"] in VALID_KINDS, (
            f"node {name!r} has kind {node['kind']!r}, "
            f"expected one of {sorted(VALID_KINDS)}"
        )


def test_no_orphan_nodes(nodes: dict, edges: list[dict]) -> None:
    touched = {e["from"] for e in edges} | {e["to"] for e in edges}
    orphans = sorted(set(nodes) - touched)
    assert not orphans, f"nodes with no edges: {orphans}"


def test_roots_are_declared_inputs(graph: dict, nodes: dict) -> None:
    declared_roots = set(graph["roots"])
    input_nodes = {n for n, v in nodes.items() if v["kind"] == "input"}
    assert declared_roots == input_nodes, (
        f"roots and kind:input disagree -- "
        f"roots only: {sorted(declared_roots - input_nodes)}, "
        f"inputs only: {sorted(input_nodes - declared_roots)}"
    )


def test_only_inputs_lack_producers(nodes: dict, edges: list[dict]) -> None:
    consumed = {e["to"] for e in edges}
    unproduced = {
        n for n, v in nodes.items() if v["kind"] != "input" and n not in consumed
    }
    assert not unproduced, f"non-input nodes with no inbound edge: {sorted(unproduced)}"


def test_every_node_reachable_from_roots(
    graph: dict, nodes: dict, successors: dict[str, set[str]]
) -> None:
    reachable = _reachable(set(graph["roots"]), successors)
    unreachable = sorted(set(nodes) - reachable)
    assert not unreachable, f"nodes unreachable from roots: {unreachable}"


def test_every_derived_node_reachable_from_target_binary(
    nodes: dict, successors: dict[str, set[str]]
) -> None:
    """GATE 0's reachability check, scoped to what the binary can produce.

    The other four roots are external inputs (startup seeds, hand-written
    fuzzer-module code) that the binary does not produce; see
    docs/DEVIATIONS.md D-002. Everything else must trace back to the binary.
    """
    reachable = _reachable({"target_binary"}, successors)
    expected = {n for n, v in nodes.items() if v["kind"] != "input"}
    unreachable = sorted(expected - reachable)
    assert not unreachable, f"nodes unreachable from target_binary: {unreachable}"


def test_every_artifact_is_produced_and_consumed(
    nodes: dict, edges: list[dict]
) -> None:
    produced = {e["to"] for e in edges}
    consumed = {e["from"] for e in edges}
    artifacts = {n for n, v in nodes.items() if v["kind"] == "artifact"}
    assert artifacts, "graph declares no artifacts"
    for artifact in sorted(artifacts):
        assert artifact in produced, f"artifact {artifact!r} is never produced"
        assert artifact in consumed, f"artifact {artifact!r} is never consumed"


# --- RULE 1, in the distributed case (sections 10, 12.2) -----------------


def test_no_llm_call_on_master_or_worker(nodes: dict) -> None:
    """The master is fast clock too -- blocking it stalls every worker.

    Section 10 lists "any LLM call inside the master" as an anti-pattern
    separately from the fast loop, because the master *looks* like a control
    plane and is easy to mistake for a safe place to put one.
    """
    offenders = sorted(
        n
        for n, v in nodes.items()
        if v.get("role") in FAST_CLOCK_ROLES and v.get("calls_llm") is True
    )
    assert not offenders, (
        f"nodes on the fast path that call the LLM: {offenders}. "
        f"The slow clock is a separate process (section 12.2)."
    )


def test_llm_calls_only_happen_off_the_fast_path(nodes: dict) -> None:
    """Enumerate who may call the LLM, so a new caller is a deliberate act."""
    callers = {n for n, v in nodes.items() if v.get("calls_llm") is True}
    allowed = {
        "ghidra.fuzz_entry_selection",  # prep, runs once
        "fuzzer_module.llm_input_struct",  # build time, emits C++
        "slow_clock.llm_seed_gen",  # the sidecar -- a separate process
        "analysis.llm_triage",  # CP9, offline
    }
    assert callers == allowed, (
        f"unexpected LLM callers: {sorted(callers - allowed)}; "
        f"missing expected: {sorted(allowed - callers)}"
    )


def test_slow_clock_is_not_the_master_or_a_worker(nodes: dict) -> None:
    assert nodes["slow_clock.llm_seed_gen"]["role"] == "sidecar", (
        "the seed generator must be a separate process (section 12.2)"
    )


# --- distributed topology (section 3.2, section 12) ----------------------


def test_module_is_loaded_by_both_roles(edges: list[dict]) -> None:
    """Edges 21a and 21b: ONE module artifact, BOTH roles.

    Section 3.2 is explicit that test_graph.py must assert this. A build where
    only the worker loads the module means the master silently falls back to a
    built-in mutator and every LLM seed is ignored.
    """
    by_id = {e["id"]: e for e in edges}
    assert by_id["21a"]["to"] == "master.mutator"
    assert by_id["21b"]["to"] == "worker.execute"
    assert by_id["21a"]["from"] == by_id["21b"]["from"] == "fuzz_target.fuzzer_module"


def test_generation_happens_on_the_master(edges: list[dict], nodes: dict) -> None:
    """Edge 23: mutation/generation is a master activity, never a worker one."""
    by_id = {e["id"]: e for e in edges}
    assert by_id["23"]["from"] == "master.corpus"
    assert by_id["23"]["to"] == "master.mutator"
    assert nodes["master.mutator"]["role"] == "master"
    # And the generated testcase reaches the worker over the wire (23b),
    # not by the worker reading a local directory.
    assert by_id["23b"]["from"] == "master.mutator"
    assert by_id["23b"]["to"] == "worker.execute"


def test_worker_facing_edges_declare_fanout(edges: list[dict], nodes: dict) -> None:
    """Interfaces 2 and 3 are delivered to EVERY worker, not once to an engine."""
    per_worker_nodes = {n for n, v in nodes.items() if v.get("fanout") == "per_worker"}
    assert per_worker_nodes, "no node declares per-worker fan-out"
    for edge in edges:
        if edge["to"] in per_worker_nodes:
            assert edge.get("fanout") == "per_worker", (
                f"edge {edge['id']} targets per-worker node {edge['to']!r} "
                f"but does not declare `fanout: per_worker`"
            )


def test_interface_1_goes_to_the_master_only(edges: list[dict]) -> None:
    """Startup seeds go to the master; only interfaces 2 and 3 fan out."""
    if1 = [e for e in edges if e.get("interface") == 1]
    assert len(if1) == 1
    assert if1[0]["to"] == "master.corpus"
    assert if1[0].get("fanout") is None


def test_plateau_is_computed_on_aggregate_coverage(edges: list[dict]) -> None:
    """Section 12.3: never on one worker's coverage."""
    by_id = {e["id"]: e for e in edges}
    assert by_id["27"]["from"] == "master.aggregate_coverage"
    assert by_id["27"]["to"] == "slow_clock.llm_seed_gen"
    assert by_id["27"]["clock"] == "slow"


# --- multi-signal independence (section 3.2, edges 38-41b) ---------------


def test_triage_receives_five_independent_signals(edges: list[dict]) -> None:
    """Five signals now, not four -- 4 is dynamic, 5 is static.

    Collapsing them into one blob, or letting one decide, is an explicit
    anti-pattern (section 10).
    """
    signal_edges = [e for e in edges if e["to"] == "analysis.llm_triage"]
    assert len(signal_edges) == 5, (
        f"expected 5 signal edges into analysis.llm_triage, found "
        f"{len(signal_edges)}"
    )
    assert {e["signal"] for e in signal_edges} == {1, 2, 3, 4, 5}
    assert len({e["from"] for e in signal_edges}) == 5, (
        "the five triage signals must come from five distinct sources"
    )


def test_dynamic_and_static_signals_are_separate(edges: list[dict]) -> None:
    """Signals 4 and 5 must not share a source -- that is the whole design."""
    by_id = {e["id"]: e for e in edges}
    assert by_id["41"]["from"] == "analysis.symbolize_trace"  # dynamic
    assert by_id["41b"]["from"] == "analysis.reverse_engineer"  # static
    assert by_id["41"]["from"] != by_id["41b"]["from"]


def test_triage_signal_names_match_the_contracts(edges: list[dict]) -> None:
    """graph.yaml and TRIAGE_SIGNALS must not drift apart."""
    from arch.contracts import TRIAGE_SIGNALS

    signal_edges = sorted(
        (e for e in edges if e["to"] == "analysis.llm_triage"),
        key=lambda e: e["signal"],
    )
    assert tuple(e["signal_name"] for e in signal_edges) == TRIAGE_SIGNALS
