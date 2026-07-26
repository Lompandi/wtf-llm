"""GATE 7 -- slow clock: plateau detection + LLM seed generation (CLAUDE.md CP7).

Gate conditions (edges 27, 29; amended by section 12.6):
  * an induced plateau triggers **exactly one** seed-gen call -- not one per tick
    while the plateau persists
  * generated seeds land in the corpus and are demonstrably executed
  * coverage increases after injection, recorded before/after
  * the timing log shows the fast loop never stalled on the LLM
  * plateau is detected on **aggregate** coverage with **N > 1 workers** running

Nothing here calls the LLM or starts a campaign. The mechanisms -- the detector,
the frontier, the prompt, the spool bookkeeping -- are exercised as pure units;
the campaign claims are asserted against recorded evidence and skip when the
evidence has not been produced yet. Regenerate it with::

    python -m orchestrator.scheduler --label gate7 --workers 2 --minutes 9 \\
        --target-dir targets/snapfuzz-cp7b --plateau-execs 20000

which writes ``artifacts/runs/gate7/`` and appends to
``artifacts/sidecar_events.jsonl``.

Four findings from this checkpoint are pinned here so they cannot come back:

* **D-042** -- the sidecar launched ``wtf run --trace-type=cov`` with no
  ``_NT_SYMBOL_PATH``, so wtf died in ``Init`` and wrote zero traces, and
  ``measure_coverage`` returned an empty set. An empty set produces an empty
  frontier, which skips seed generation with "frontier is empty" -- a total
  failure that reads as "nothing left to explore".
* **D-043** -- ``seed_gen`` max_tokens must cover the model's reasoning, which is
  billed against it.
* **D-044** -- attempted-but-still-unreached branches are fed back into the
  prompt, and the counter survives a sidecar restart (section 12.2).
* **D-045** -- ``FrontierBlock`` states RVAs and static addresses in separately
  named fields, element-for-element, because mixing them in one prompt sentence
  made the model echo RVAs that no coverage check could ever match.
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
import time
from pathlib import Path

import pytest
import yaml

from arch.addr import AddressSpace
from arch.contracts import CoverageSummary
from engine_bridge.plateau import (
    BlockGraph,
    FrontierBlock,
    PlateauDetector,
    compute_frontier,
    is_input_reachable,
    parse_cov_traces,
    summarise,
)
from llm.seed_gen import (
    SeedGenRequest,
    _frontier_context,
    _prompt,
    format_target,
    parse_target,
)
from llm.sidecar import Sidecar, SidecarConfig
from prep.pseudoc_cache import PseudoCCache

REPO_ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = REPO_ROOT / "artifacts"

# GATE 7's own evidence directory -- one per gate, for the reason recorded in
# test_cp4.py: a later run under a shared label retroactively invalidates an
# earlier gate's metadata.
EVIDENCE = ARTIFACTS / "runs" / "gate7"
SCHEDULER_RESULT = EVIDENCE / "scheduler_result.json"
MASTER_LOG = EVIDENCE / "master.log"
SEED_DELTA = EVIDENCE / "seed_delta.json"
CONTROL_PROBE = EVIDENCE / "control_probe.json"
CAPACITY_PROBE = EVIDENCE / "capacity_probe.json"

# The sidecar's own log lives beside the other artifacts, not under runs/: it is
# append-only across runs by design, because the attempt counter is rebuilt from
# it after a restart (D-044).
SIDECAR_EVENTS = ARTIFACTS / "sidecar_events.jsonl"
SEED_PROVENANCE = ARTIFACTS / "seed_provenance.jsonl"

A1 = ARTIFACTS / "a1_snapshot.json"
A3_MODULE = ARTIFACTS / "a3_ghidra_blocks_module.json"
COV_TRACES = ARTIFACTS / "cov-traces"
CP7_TARGET = REPO_ROOT / "targets" / "snapfuzz-cp7b"

# Ground truth, established in tests/test_addr.py and reused by every gate.
MODULE_BASE = 0x7FF719E50000
IMAGE_BASE = 0x140000000

# Measured this session (artifacts/runs/gate7/control_probe.json): eight Allocate
# packets in ONE testcase reach 0x14000131c and four do not, so ChunkList's
# capacity is between 5 and 8 and that branch is the free-slot search running off
# the end of a fixed-size global table.
CAPACITY_BRANCH = 0x14000131C
# ChunkList holds four slots; the fifth Allocate writes out of bounds and the
# sixth reads that value back, which is the null test guarding CAPACITY_BRANCH.
# See docs/DEVIATIONS.md D-047.
EXPECTED_CAPACITY_THRESHOLD = 6

# Fast clock (section 12.2: the master counts as fast clock too). engine_bridge/
# plateau.py is on this list because it computes the trigger and must stay
# LLM-free -- the *sending* is llm/sidecar.py's job.
FAST_PATH_MODULES = [
    REPO_ROOT / "engine_bridge" / "plateau.py",
    REPO_ROOT / "engine_bridge" / "coverage.py",
    REPO_ROOT / "engine_bridge" / "crash_watch.py",
    REPO_ROOT / "orchestrator" / "scheduler.py",
    REPO_ROOT / "fuzzer" / "run.py",
    REPO_ROOT / "fuzzer" / "master.py",
    REPO_ROOT / "fuzzer" / "workers.py",
    REPO_ROOT / "fuzzer" / "corpus.py",
]

_LLM_ROOTS = {"llm", "openai", "httpx", "anthropic", "dspy"}

requires_campaign = pytest.mark.skipif(
    not SCHEDULER_RESULT.exists(),
    reason=f"no campaign evidence at {SCHEDULER_RESULT}; see this module's docstring",
)
requires_sidecar_log = pytest.mark.skipif(
    not SIDECAR_EVENTS.exists(),
    reason=f"no sidecar event log at {SIDECAR_EVENTS}",
)


# --- helpers --------------------------------------------------------------


def _graph_export(
    path: Path, blocks: list[tuple[int, str | None, list[int]]]
) -> Path:
    """Write a synthetic A3 export. ``blocks`` is [(rva, function, successors)]."""
    path.write_text(
        json.dumps(
            {
                "module": "synthetic",
                "image_base": IMAGE_BASE,
                "blocks": [
                    {
                        "rva": rva,
                        "static_addr": IMAGE_BASE + rva,
                        "function": function,
                        "successors": list(successors),
                    }
                    for rva, function, successors in blocks
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _sidecar(tmp_path: Path, blocks, **overrides) -> Sidecar:
    """A Sidecar over a synthetic graph. Touches nothing outside tmp_path."""
    for name in ("inputs", "outputs", "crashes", "coverage"):
        (tmp_path / "target" / name).mkdir(parents=True, exist_ok=True)
    config = SidecarConfig(
        target_dir=tmp_path / "target",
        wtf_exe=tmp_path / "wtf.exe",
        module="synthetic",
        a3_export=_graph_export(tmp_path / "a3.json", blocks),
        a2_cache=tmp_path / "a2.sqlite",
        spool_path=tmp_path / "spool",
        artifacts_dir=tmp_path / "artifacts",
        space=AddressSpace("synthetic", MODULE_BASE, IMAGE_BASE),
        **overrides,
    )
    config.artifacts_dir.mkdir(parents=True, exist_ok=True)
    return Sidecar(config)


def _campaign_window() -> tuple[float, float] | None:
    """(started_at, ended_at) of the recorded campaign, if the runner logged it.

    The sidecar log is append-only across runs by design -- the attempt counter is
    rebuilt from it after a restart (D-044) -- so a claim about *this* campaign
    has to be scoped to the campaign's own wall-clock window.
    """
    meta = EVIDENCE / "run_metadata.json"
    if not meta.exists():
        return None
    data = json.loads(meta.read_text(encoding="utf-8"))
    if "started_at" in data and "ended_at" in data:
        return float(data["started_at"]), float(data["ended_at"])
    return None


def _events(kinds: set[str] | None = None) -> list[dict]:
    if not SIDECAR_EVENTS.exists():
        return []
    out: list[dict] = []
    for line in SIDECAR_EVENTS.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if kinds is None or record.get("event") in kinds:
            out.append(record)
    return out


# One stat sample from the master log, parsed **independently** of
# engine_bridge.coverage.parse_stat_line. That regex requires ``lastcov: <n>s``
# and so silently drops every line the master prints more than a minute after the
# last new coverage -- which is exactly the plateau window this gate has to
# measure. In the recorded gate7 log, 42 lines are stat lines and only 9 of them
# parse. Throughput evidence must not depend on a parser that goes blind during a
# plateau, so this gate reads the raw numbers.
_RAW_STAT = re.compile(
    r"^#(?P<execs>\d+)\s+cov:\s*(?P<cov>\d+)\b.*?"
    r"\((?P<nodes>\d+)\s+nodes\).*?"
    r"uptime:\s*(?P<uptime>[\d.]+)(?P<unit>s|min|h)\b"
)
_UPTIME_SCALE = {"s": 1.0, "min": 60.0, "h": 3600.0}


def _master_samples(text: str) -> list[tuple[int, int, int, float]]:
    """(execs, coverage, nodes, uptime_s) for every complete stat line."""
    samples = []
    for line in text.splitlines():
        m = _RAW_STAT.match(line.strip())
        if m:
            samples.append(
                (
                    int(m.group("execs")),
                    int(m.group("cov")),
                    int(m.group("nodes")),
                    float(m.group("uptime")) * _UPTIME_SCALE[m.group("unit")],
                )
            )
    return samples


# --- PlateauDetector: exactly once per plateau (pure unit) ----------------


def test_plateau_fires_exactly_once_while_the_plateau_persists() -> None:
    """GATE 7: one seed-gen call per plateau, not one per tick.

    The detector stays *plateaued* for as long as no new coverage arrives -- that
    is the honest state -- so the "only once" property lives in ``should_fire``,
    which consumes the trigger. Firing per tick would spend the allocation on the
    same frontier every 30 seconds for the rest of the campaign.
    """
    detector = PlateauDetector(threshold_executions=1_000)
    now = 1_000.0

    first = detector.observe(0, 0, now)
    assert not first.plateaued
    assert not detector.should_fire(first)

    fired = 0
    for step in range(1, 6):  # 1000 .. 5000 executions, no new coverage
        state = detector.observe(step * 1_000, 0, now + step)
        assert state.plateaued, "the campaign is plateaued and must say so"
        if detector.should_fire(state):
            fired += 1

    assert fired == 1, f"seed generation would have been called {fired} times"


def test_new_coverage_rearms_the_detector() -> None:
    """A plateau that breaks and returns is a second plateau, not the same one.

    The re-arm is what makes the slow clock event-driven rather than one-shot: the
    next plateau after real progress deserves a fresh call.
    """
    detector = PlateauDetector(threshold_executions=1_000)
    now = 0.0

    detector.observe(0, 0, now)
    assert detector.should_fire(detector.observe(1_000, 0, now + 1))

    # New coverage: the counters rebase and the trigger re-arms.
    rearmed = detector.observe(1_500, 1, now + 2)
    assert not rearmed.plateaued
    assert rearmed.executions_since_new_coverage == 0
    assert not detector.fired

    assert not detector.should_fire(detector.observe(2_000, 1, now + 3))  # only 500
    assert detector.should_fire(detector.observe(2_500, 1, now + 4))  # 1000 again


def test_the_first_sample_does_not_count_as_a_plateau() -> None:
    """A sidecar attached mid-campaign must not fire on arrival.

    Without a baseline, an existing execution count reads as "N executions since
    new coverage" on the very first observation, and the first tick after startup
    would always generate seeds.
    """
    detector = PlateauDetector(threshold_executions=10_000)
    state = detector.observe(500_000, 12, time.time())
    assert not state.plateaued
    assert state.executions_since_new_coverage == 0


def test_plateau_is_measured_in_executions_with_wall_clock_as_a_safety_net() -> None:
    """Section 12.3: executions are primary; wall clock only catches a stall.

    A wall-clock threshold tuned on one worker fires far too late with sixteen,
    because the same execution budget burns ~16x faster. The safety net exists so
    a campaign whose throughput has collapsed still eventually asks for help --
    and it says so in the reason, since the two cases warrant different reactions.
    """
    by_execs = PlateauDetector(threshold_executions=1_000, wall_clock_bound_s=10_000)
    by_execs.observe(0, 0, 0.0)
    state = by_execs.observe(1_000, 0, 1.0)
    assert state.plateaued
    assert "executions without new coverage" in state.reason

    by_clock = PlateauDetector(threshold_executions=10**9, wall_clock_bound_s=10.0)
    by_clock.observe(0, 0, 0.0)
    stalled = by_clock.observe(5, 0, 11.0)
    assert stalled.plateaued
    assert "wall-clock safety net" in stalled.reason
    assert stalled.executions_since_new_coverage == 5


# --- the frontier ---------------------------------------------------------


def test_successor_that_is_not_a_known_block_is_excluded(tmp_path: Path) -> None:
    """A block absent from A3 cannot be instrumented, so it can never be observed.

    Offering it as a target asks the LLM for an input whose success is
    unmeasurable: it could be reached on the first try and the frontier would
    still report it unreached forever.
    """
    graph = BlockGraph.from_export(
        _graph_export(
            tmp_path / "a3.json",
            [
                (0x1000, "ProcessPacket", [0x2000, 0x9999]),  # 0x9999 not enumerated
                (0x2000, "ProcessPacket", []),
            ],
        )
    )
    frontier = compute_frontier({0x1000}, graph)

    assert len(frontier) == 1
    assert frontier[0].unreached_successor_rvas == (0x2000,)
    assert 0x9999 not in frontier[0].unreached_successor_rvas
    assert IMAGE_BASE + 0x9999 not in frontier[0].unreached_successor_statics


def test_input_opaque_successors_are_excluded_unless_asked_for(tmp_path: Path) -> None:
    """D-040: a branch input cannot steer wastes a whole generation round.

    CP7 watched this happen -- of five frontier branches offered, one was inside
    ``operator_new``'s allocation-failure path and one inside printf's internals.
    The filter is about reachability by input, not about the code being boring, so
    it is switchable rather than hardcoded.
    """
    graph = BlockGraph.from_export(
        _graph_export(
            tmp_path / "a3.json",
            [
                (0x1000, "ProcessPacket", [0x2000, 0x3000]),
                (0x2000, "operator_new", []),  # allocation failure path
                (0x3000, "ProcessPacket", []),
            ],
        )
    )

    filtered = compute_frontier({0x1000}, graph, input_reachable_only=True)
    assert filtered[0].unreached_successor_rvas == (0x3000,)

    unfiltered = compute_frontier({0x1000}, graph, input_reachable_only=False)
    assert set(unfiltered[0].unreached_successor_rvas) == {0x2000, 0x3000}

    # Conservative by design: an unknown function stays a candidate, because
    # dropping a real parser is worse than keeping an allocator.
    assert is_input_reachable(None) is True
    assert is_input_reachable("FUN_140001150") is True
    assert is_input_reachable("operator_new") is False


def test_frontier_address_lists_correspond_element_for_element(
    tmp_path: Path,
) -> None:
    """D-045: the two lists are parallel, and each is in a named address space.

    The bug this replaces: one unlabelled ``unreached_successors`` field holding
    RVAs next to a ``static_addr`` field holding a Ghidra address, so the prompt
    said "reached 0x1400012c9, but never took the branch to 0x12de". The model
    echoed the RVA form back, and no attempted branch could ever be matched
    against measured coverage.
    """
    graph = BlockGraph.from_export(
        _graph_export(
            tmp_path / "a3.json",
            [
                (0x12C9, "ProcessPacket", [0x12DE, 0x12ED]),
                (0x12DE, "ProcessPacket", []),
                (0x12ED, "ProcessPacket", []),
            ],
        )
    )
    block = compute_frontier({0x12C9}, graph)[0]

    assert block.rva == 0x12C9
    assert block.static_addr == IMAGE_BASE + 0x12C9
    assert block.degree == 2
    assert len(block.unreached_successor_rvas) == len(
        block.unreached_successor_statics
    )
    for rva, static in zip(
        block.unreached_successor_rvas, block.unreached_successor_statics
    ):
        assert static == IMAGE_BASE + rva, (
            "the static list must be the RVA list de-slid in the same order"
        )


def test_frontier_block_refuses_mismatched_address_lists() -> None:
    """The invariant is enforced at construction, not trusted.

    Both lists reach the prompt. A silent length mismatch would print one
    successor's address against another's, which is worse than an error.
    """
    with pytest.raises(ValueError, match="element-for-element"):
        FrontierBlock(
            rva=0x1000,
            static_addr=IMAGE_BASE + 0x1000,
            function="ProcessPacket",
            unreached_successor_rvas=(0x2000, 0x3000),
            unreached_successor_statics=(IMAGE_BASE + 0x2000,),
        )


def test_frontier_ranks_by_unreached_degree(tmp_path: Path) -> None:
    """Most unreached successors first -- that is where behaviour is concentrated."""
    graph = BlockGraph.from_export(
        _graph_export(
            tmp_path / "a3.json",
            [
                (0x1000, "P", [0x4000]),
                (0x2000, "P", [0x4000, 0x5000, 0x6000]),
                (0x4000, "P", []),
                (0x5000, "P", []),
                (0x6000, "P", []),
            ],
        )
    )
    frontier = compute_frontier({0x1000, 0x2000}, graph)
    assert [f.rva for f in frontier] == [0x2000, 0x1000]
    assert compute_frontier({0x1000, 0x2000}, graph, limit=1)[0].rva == 0x2000


def test_a_covered_block_with_nowhere_left_to_go_is_not_frontier(
    tmp_path: Path,
) -> None:
    graph = BlockGraph.from_export(
        _graph_export(
            tmp_path / "a3.json",
            [(0x1000, "P", [0x2000]), (0x2000, "P", [])],
        )
    )
    assert compute_frontier({0x1000, 0x2000}, graph) == []
    # And an address covered in another module is not a block of ours.
    assert compute_frontier({0x7FFF}, graph) == []


def test_a3_without_successor_edges_is_refused(tmp_path: Path) -> None:
    """An export with no edges yields an empty frontier, which reads as 'done'.

    The same silent-success shape as D-042: nothing errors, seed generation is
    skipped, and the campaign looks like it had nothing left to explore.
    """
    export = _graph_export(tmp_path / "a3.json", [(0x1000, "P", []), (0x2000, "P", [])])
    with pytest.raises(ValueError, match="no successor edges"):
        BlockGraph.from_export(export)


# --- RULE 1: no LLM on the fast path -------------------------------------


@pytest.mark.parametrize("module", FAST_PATH_MODULES, ids=lambda p: p.name)
def test_no_llm_import_on_the_fast_path(module: Path) -> None:
    """RULE 1, extended to the CP7 modules.

    Checked with the AST rather than by grepping for a word, so plateau.py's
    docstring reference to :mod:`llm.seed_gen` does not fail the gate and an
    aliased import does not pass it.
    """
    tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            offenders += [
                f"import {a.name}"
                for a in node.names
                if a.name.split(".")[0] in _LLM_ROOTS
            ]
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in _LLM_ROOTS:
                offenders.append(f"from {node.module} import ...")

    assert not offenders, (
        f"{module.name} reaches an LLM client on the fast path: {offenders}. "
        f"The slow clock is a separate process (section 12.2), and the master "
        f"counts as fast clock -- an LLM call there stalls every worker."
    )


def test_seed_generation_originates_only_in_the_sidecar() -> None:
    """llm/sidecar.py is the ONLY place a seed-gen call may come from.

    The scheduler supervises the sidecar as a *subprocess* and must never import
    it: an in-process call would put LLM latency back in the process that also
    owns the master.
    """
    callers: set[str] = set()
    for path in sorted(REPO_ROOT.glob("*/*.py")) + sorted(REPO_ROOT.glob("*/*/*.py")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel.startswith((".venv/", "tests/", "src/", "eval/planted_bugs/")):
            continue
        if rel == "llm/seed_gen.py":
            continue  # the implementation itself
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").endswith(
                "seed_gen"
            ):
                callers.add(rel)
            elif isinstance(node, ast.Import):
                if any(a.name.endswith("seed_gen") for a in node.names):
                    callers.add(rel)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "generate_seeds":
                    callers.add(rel)

    assert callers == {"llm/sidecar.py"}, (
        f"seed generation is reachable from {sorted(callers)}; only the sidecar "
        f"may call it (section 12.2)"
    )


def test_the_scheduler_runs_the_sidecar_as_a_separate_process() -> None:
    """Section 12.2 is about process boundaries, not just module boundaries."""
    source = (REPO_ROOT / "orchestrator" / "scheduler.py").read_text(encoding="utf-8")
    assert "subprocess.Popen" in source
    assert "llm.sidecar" in source, (
        "the scheduler does not launch the sidecar; the slow clock would never run"
    )


# --- the prompt: summaries only, full static addresses --------------------


def _prompt_fixture(tmp_path: Path, attempted: dict[int, int] | None = None):
    """A synthetic seed-gen request over a two-branch frontier."""
    graph = BlockGraph.from_export(
        _graph_export(
            tmp_path / "a3.json",
            [
                (0x12C9, "ProcessPacket", [0x12DE]),
                (0x12DE, "ProcessPacket", []),
                (0x131C, "ProcessPacket", []),
                (0x130C, "ProcessPacket", [0x131C]),
                (0xBEEF, "ProcessPacket", []),  # covered, no unreached successor
            ],
        )
    )
    covered = {0x12C9, 0x130C, 0xBEEF}
    frontier = compute_frontier(covered, graph)

    cache = PseudoCCache(tmp_path / "a2.sqlite")
    from arch.contracts import PseudoCEntry

    cache.put(
        PseudoCEntry(
            module="synthetic",
            static_addr=IMAGE_BASE + 0x1150,
            function="ProcessPacket",
            code="void ProcessPacket(char *param_1, ulonglong param_2) { /* body */ }",
        ),
        min_static=IMAGE_BASE + 0x1150,
        max_static=IMAGE_BASE + 0x1400,
    )

    request = SeedGenRequest(
        summary=summarise(
            tick=1,
            covered=covered,
            frontier=frontier,
            corpus_size=44,
            crash_buckets=0,
        ),
        frontier=frontier,
        example_seed=b'{"Packets":[{"Id":1,"Command":0,"BodySize":0,"Body":[]}]}',
        want=8,
        attempted=attempted or {},
    )
    context, functions = _frontier_context(request, cache)
    cache.close()
    assert functions == ["ProcessPacket"]
    return request, _prompt(request, context)


def test_prompt_carries_a_summary_not_the_corpus_or_a_bitmap(tmp_path: Path) -> None:
    """Section 7.3 and section 10: summaries and targeted pseudo-C only.

    Structural first: :class:`SeedGenRequest` has no field that could carry the
    corpus or a coverage bitmap, so sending one would require changing the
    contract rather than a careless line in the prompt. Then the prompt itself is
    checked -- one example seed, the frontier, and the numbers.
    """
    import dataclasses

    fields = {f.name: f for f in dataclasses.fields(SeedGenRequest)}
    assert fields["summary"].type in (CoverageSummary, "CoverageSummary"), (
        "the coverage input must be the bounded CoverageSummary, not a raw set"
    )
    smuggled = sorted(
        name
        for name in fields
        if re.search(r"corpus|bitmap|dump|covered|traces", name)
    )
    assert not smuggled, (
        f"SeedGenRequest gained field(s) {smuggled} that could carry the raw "
        f"corpus or a coverage bitmap into the prompt (section 7.3, section 10)"
    )

    request, prompt = _prompt_fixture(tmp_path)

    # Exactly one field carries seed bytes, and it is the single format example.
    byte_fields = [
        name for name in fields if isinstance(getattr(request, name), bytes)
    ]
    assert byte_fields == ["example_seed"]

    # The summary's integers, not the sets behind them.
    assert str(request.summary.coverage_units) in prompt
    assert str(request.summary.corpus_size) in prompt

    # Exactly one seed appears, as a format example.
    assert prompt.count(request.example_seed.decode()) == 1

    # A covered block that is NOT on the frontier must not be listed: that would
    # be a coverage dump in prose.
    assert f"{IMAGE_BASE + 0xBEEF:#x}" not in prompt

    # Bounded: 4 functions x 6000 chars of pseudo-C plus scaffolding.
    assert len(prompt) < 40_000, f"prompt is {len(prompt)} chars"


def test_prompt_states_frontier_branches_as_full_static_addresses(
    tmp_path: Path,
) -> None:
    """D-045: one address space per sentence, and it is the static one.

    ``targets_branch`` is matched against measured coverage keyed by static
    address, so a prompt that shows a 4-hex-digit RVA teaches the model to answer
    in a form that can never match.
    """
    request, prompt = _prompt_fixture(tmp_path)

    for block in request.frontier:
        assert f"{block.static_addr:#x}" in prompt
        for static in block.unreached_successor_statics:
            assert f"{static:#x}" in prompt, (
                f"unreached successor {static:#x} is missing from the prompt"
            )
        for rva in block.unreached_successor_rvas:
            assert f"{rva:#x}" not in prompt, (
                f"the prompt shows RVA {rva:#x}; the model will echo it back and "
                f"no attempt will ever match measured coverage (D-045)"
            )

    # And it is told the matching rule explicitly.
    assert "VERBATIM AND IN FULL" in prompt


def test_prompt_reports_branches_already_tried_and_still_unreached(
    tmp_path: Path,
) -> None:
    """D-044: without this the round is one-shot prompting repeated N times.

    Measured: three consecutive rounds spent 6 of 8 seeds on the same two
    branches, because nothing in the prompt could tell the model they had already
    been aimed at and never reached.
    """
    _, clean = _prompt_fixture(tmp_path)
    assert "ALREADY TRIED" not in clean, (
        "a first round has no feedback yet and must not claim to"
    )

    _, with_history = _prompt_fixture(
        tmp_path, attempted={IMAGE_BASE + 0x12DE: 3, IMAGE_BASE + 0x131C: 1}
    )
    assert "ALREADY TRIED AND STILL NOT REACHED" in with_history
    assert f"{IMAGE_BASE + 0x12DE:#x} (tried 3x)" in with_history
    assert f"{IMAGE_BASE + 0x131C:#x} (tried 1x)" in with_history
    # Most-tried first, so the worst offender is what the model reads first.
    assert with_history.index(f"{IMAGE_BASE + 0x12DE:#x} (tried") < with_history.index(
        f"{IMAGE_BASE + 0x131C:#x} (tried"
    )
    # And it is given permission to judge a branch unreachable rather than
    # producing a seed it does not believe in.
    assert "unreachable" in with_history


def test_only_one_content_field_is_offered_for_a_textual_target(
    tmp_path: Path,
) -> None:
    """D-041: a hex answer to a JSON target produces seeds the parser discards.

    Asking for the right field in prose did not work -- across three rounds the
    model kept answering in ``content_hex`` for a JSON target, and a hex string of
    arbitrary text unhexlifies into bytes ``InsertTestcase`` throws away. Eight
    seeds, zero usable, and it looks like the LLM having no ideas. The schema is
    the one instruction the model cannot ignore, so the wrong field is not in it.
    """
    from llm.seed_gen import _batch_model

    text_seed = _batch_model("json").model_fields["seeds"].annotation.__args__[0]
    assert "content" in text_seed.model_fields
    assert "content_hex" not in text_seed.model_fields

    binary_seed = _batch_model("raw").model_fields["seeds"].annotation.__args__[0]
    assert "content_hex" in binary_seed.model_fields
    assert "content" not in binary_seed.model_fields

    _, prompt = _prompt_fixture(tmp_path)
    assert "Each input goes in `content`" in prompt
    assert "content_hex" not in prompt, (
        "the prompt still mentions the field the schema does not offer"
    )


# --- the target round trip ------------------------------------------------


def test_format_and_parse_target_round_trip() -> None:
    """The aimed-at branch survives the trip through SeedRecord.rationale.

    ``rationale`` is free text that also has to be machine-readable, which is why
    the writer and the reader are a matched pair in one module: the attempt
    counter (D-044) and every retirement decision depend on recovering the exact
    address the round aimed at.
    """
    for addr in (0x1400012DE, 0x14000131C, 0x140001150):
        rationale = f"{format_target(f'{addr:#x}')}: repeat the Allocate packet 8x"
        assert parse_target(rationale) == addr

    # Bare hex is accepted too -- the model is asked for 0x form but not trusted.
    assert parse_target(format_target("1400012de")) == 0x1400012DE


def test_parse_target_rejects_a_non_address() -> None:
    """A free-text field is a free-text field; None means 'not countable'.

    Returning a wrong number here would credit an attempt to whichever branch the
    digits happened to resemble, and retire it as reached later.
    """
    assert parse_target("targets the free-slot loop in ProcessPacket") is None
    assert parse_target("targets : nothing") is None
    assert parse_target("no prefix at all 0x1400012de") is None
    assert parse_target("") is None


# --- the sidecar's measurement and bookkeeping ---------------------------


def test_measure_coverage_passes_the_symbol_path_to_wtf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D-042: every process that launches wtf needs _NT_SYMBOL_PATH.

    wtf resolves breakpoints by symbol name through dbgeng and sets no symbol
    path itself. fuzzer/run.py had this; the sidecar's copy did not, so it died in
    ``Init`` with "Could not set a breakpoint at tlv_server!ProcessPacket".
    """
    sidecar = _sidecar(
        tmp_path,
        [(0x1000, "P", [0x2000]), (0x2000, "P", [])],
        symbol_paths=["srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"],
    )
    (sidecar.config.target_dir / "inputs" / "seed.json").write_bytes(b"{}")
    captured: dict = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["env"] = kwargs["env"]
        # wtf writes one trace per input; emit a runtime address in our module.
        out = sidecar.config.artifacts_dir / "cov-traces" / "unit"
        (out / "seed.json.trace").write_text(
            f"{MODULE_BASE + 0x1000:#x}\n", encoding="utf-8"
        )
        return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    covered = sidecar.measure_coverage(label="unit")

    assert covered == {0x1000}, "the trace's runtime address must come back as an RVA"
    assert captured["env"]["_NT_SYMBOL_PATH"], (
        "wtf was launched with no _NT_SYMBOL_PATH; it would die in Init and write "
        "zero traces, and the frontier would come out empty (D-042)"
    )
    assert "--trace-type=cov" in captured["cmd"]


def test_measure_coverage_refuses_to_report_zero_traces_as_no_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D-042: the worst possible outcome is an empty set returned quietly.

    Empty coverage produces an empty frontier, which skips seed generation with
    "frontier is empty" -- a total failure that reads as "the campaign has
    explored everything". It must raise instead.
    """
    sidecar = _sidecar(tmp_path, [(0x1000, "P", [0x2000]), (0x2000, "P", [])])
    (sidecar.config.target_dir / "inputs" / "seed.json").write_bytes(b"{}")

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda cmd, **kw: subprocess.CompletedProcess(
            cmd, 1, stdout="Could not set a breakpoint at tlv_server!ProcessPacket", stderr=""
        ),
    )
    with pytest.raises(RuntimeError, match="produced no traces"):
        sidecar.measure_coverage(label="unit")


def test_attempts_are_retired_when_coverage_proves_the_branch_was_reached(
    tmp_path: Path,
) -> None:
    """D-044: the counter must be honest in both directions.

    A branch a seed genuinely reached has to stop being reported as a failure, or
    the next round is told to avoid the one thing that worked.
    """
    sidecar = _sidecar(
        tmp_path,
        [
            (0x12DE, "P", [0x131C]),
            (0x131C, "P", []),
        ],
    )
    sidecar.attempted = {IMAGE_BASE + 0x12DE: 2, IMAGE_BASE + 0x131C: 1}

    still_open = sidecar._retire_reached_attempts({0x131C})

    assert still_open == {IMAGE_BASE + 0x12DE: 2}
    assert IMAGE_BASE + 0x131C not in sidecar.attempted
    retired = [e for e in sidecar.events if e["event"] == "attempts_retired"]
    assert retired and retired[0]["reached"] == [hex(IMAGE_BASE + 0x131C)]


def test_attempt_counter_survives_a_sidecar_restart(tmp_path: Path) -> None:
    """Section 12.2: the sidecar is restartable without stopping the campaign.

    A counter that lived only in memory would make a restarted sidecar re-derive
    the same dead branches from scratch, so it is rebuilt from the durable event
    log -- including rounds logged before D-045, which recorded RVAs because that
    is what the prompt showed the model. Those are real evidence and are
    normalised rather than discarded.
    """
    blocks = [(0x12DE, "P", [0x131C]), (0x131C, "P", [])]
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    (artifacts / "sidecar_events.jsonl").write_text(
        "\n".join(
            [
                json.dumps(
                    {  # legacy form: an RVA, with the "targets " prefix
                        "event": "seeds_published",
                        "targets": ["targets 0x12de", "targets 0xdead"],
                    }
                ),
                json.dumps(
                    {  # current form: a bare static address
                        "event": "seeds_published",
                        "targets": [hex(IMAGE_BASE + 0x12DE)],
                    }
                ),
                json.dumps({"event": "frontier_computed", "frontier": 1}),
                "not json at all",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    sidecar = _sidecar(tmp_path, blocks)

    assert sidecar.attempted == {IMAGE_BASE + 0x12DE: 2}, (
        "the RVA and static forms of the same branch must collapse to one entry"
    )


def test_build_config_populates_the_symbol_path_from_shared_code() -> None:
    """D-042: one resolver, used by both the campaign and the sidecar.

    The bug was a duplicated concept, not a typo -- fuzzer/run.py computed symbol
    paths inside its own CampaignConfig and the sidecar simply had no equivalent.
    Asserting they share the function is what stops it recurring.
    """
    if not (A1.exists() and CP7_TARGET.is_dir()):
        pytest.skip("needs artifacts/a1_snapshot.json and targets/snapfuzz-cp7b")

    from llm.sidecar import build_config

    source = (REPO_ROOT / "llm" / "sidecar.py").read_text(encoding="utf-8")
    assert "from fuzzer.run import resolve_symbol_paths" in source, (
        "the sidecar computes symbol paths itself instead of sharing the resolver"
    )

    cfg = build_config(
        target_dir=CP7_TARGET, module="snapfuzz", a1=A1,
        # CP7_TARGET is targets/snapfuzz-gate7, a tlv_server snapshot whose A1
        # predates SnapshotRef.module -- so target.yaml does describe it, and
        # the directory name is NOT the module name (D-073).
        allow_config_fallback=True,
    )
    assert cfg.symbol_paths, "no symbol paths; the sidecar would measure no coverage"
    assert any("symbols" in p or Path(p).is_dir() for p in cfg.symbol_paths)
    # And the plateau parameters come from config, not from defaults in code.
    fuzz = yaml.safe_load((REPO_ROOT / "config" / "fuzz.yaml").read_text("utf-8"))
    assert cfg.plateau_execs_threshold == fuzz["plateau"]["plateau_execs_threshold"]
    assert cfg.wall_clock_bound_s == fuzz["plateau"]["wall_clock_bound_s"]


def test_seed_gen_token_budget_covers_the_models_reasoning() -> None:
    """D-043: reasoning is billed against max_tokens, and it is not small.

    Measured on the real seed-generation prompt: 28k-60k CHARS of reasoning before
    a single seed. At 4096, 8192 and 16384 the API returned HTTP 200 with
    ``finish_reason: "length"`` and ``content: null``; one round died as "role
    'seed_gen' failed after 3 attempts". Starting high makes attempt 1 succeed.
    """
    cfg = yaml.safe_load((REPO_ROOT / "config" / "llm.yaml").read_text("utf-8"))
    seed_gen = cfg["roles"]["seed_gen"]
    assert seed_gen["max_tokens"] >= 16_384, (
        f"seed_gen has {seed_gen['max_tokens']} max_tokens; measured need on the "
        f"real prompt is >= 16384 (D-043)"
    )
    assert cfg["response_handling"]["treat_length_finish_as_error"] is True


def test_plateau_config_is_declared_in_execution_terms() -> None:
    """Section 12.4: executions primary, wall clock a documented safety net."""
    fuzz = yaml.safe_load((REPO_ROOT / "config" / "fuzz.yaml").read_text("utf-8"))
    plateau = fuzz["plateau"]
    assert isinstance(plateau["plateau_execs_threshold"], int)
    assert plateau["plateau_execs_threshold"] > 0
    assert plateau["wall_clock_bound_s"] > 0
    assert plateau["tick_interval_s"] > 0
    assert plateau["max_seed_gen_calls_per_run"] > 0, (
        "an uncapped slow clock can drain the allocation on a stubborn plateau"
    )


def test_graph_declares_the_two_slow_clock_edges() -> None:
    """Edges 27 and 29 are what GATE 7 exists to make live."""
    graph = yaml.safe_load((REPO_ROOT / "arch" / "graph.yaml").read_text("utf-8"))
    by_id = {e["id"]: e for e in graph["edges"]}

    # 27: plateau is computed on the MASTER's aggregate, never one worker's.
    assert by_id["27"]["from"] == "master.aggregate_coverage"
    assert by_id["27"]["to"] == "slow_clock.llm_seed_gen"
    assert by_id["27"]["clock"] == "slow"

    # 29: seeds go back into the master's corpus, by the mechanism section 12.1
    # resolved -- the custom mutator's spool, not a drop into inputs/.
    assert by_id["29"]["from"] == "slow_clock.llm_seed_gen"
    assert by_id["29"]["to"] == "master.corpus"
    assert by_id["29"]["clock"] == "slow"
    assert 7 in by_id["27"]["gates"] and 7 in by_id["29"]["gates"]

    fuzz = yaml.safe_load((REPO_ROOT / "config" / "fuzz.yaml").read_text("utf-8"))
    assert fuzz["topology"]["corpus_ingest"] == "custom_mutator_spool"


# --- the frontier over real recorded traces ------------------------------


@pytest.mark.skipif(
    not (A1.exists() and A3_MODULE.exists() and COV_TRACES.is_dir()),
    reason="needs A1, the module-scope A3 export, and recorded cov traces",
)
def test_frontier_over_real_traces_is_well_formed() -> None:
    """The frontier on measured data, not a synthetic graph.

    Deliberately property-based rather than pinned to specific addresses: the
    frontier legitimately changes as the corpus grows (0x14000131c moved from
    unreached to covered during this checkpoint). What must hold for any corpus is
    that every offered branch is enumerable, uncovered, and input-steerable --
    otherwise seed generation is being asked for the impossible.
    """
    traces = [
        d
        for d in COV_TRACES.iterdir()
        if d.is_dir() and any(d.glob("*.trace"))
    ]
    if not traces:
        pytest.skip("no cov-trace directory has any *.trace files")
    newest = max(traces, key=lambda d: d.stat().st_mtime)

    ref = json.loads(A1.read_text(encoding="utf-8"))
    space = AddressSpace("tlv_server", ref["module_base"], ref["ghidra_image_base"])
    covered = parse_cov_traces(newest, space)
    graph = BlockGraph.from_export(A3_MODULE)

    in_module = covered & set(graph.blocks)
    assert in_module, f"{newest.name} covered no enumerated block of the target"

    frontier = compute_frontier(covered, graph, limit=12)
    assert frontier, (
        f"{len(in_module)} blocks covered from {newest.name} but no frontier: "
        f"seed generation would be skipped as 'frontier is empty'"
    )

    for block in frontier:
        assert block.rva in graph.blocks
        assert block.rva in covered, "a frontier block must itself be covered"
        assert block.static_addr == graph.blocks[block.rva]["static_addr"]
        assert len(block.unreached_successor_rvas) == len(
            block.unreached_successor_statics
        )
        for rva, static in zip(
            block.unreached_successor_rvas, block.unreached_successor_statics
        ):
            assert rva in graph.blocks, "an unreachable-to-observe target"
            assert rva not in covered, "successor is already covered"
            assert graph.blocks[rva]["static_addr"] == static
            assert is_input_reachable(graph.function_of(rva))


# --- evidence from the campaign ------------------------------------------


@requires_campaign
def test_plateau_was_watched_with_more_than_one_worker() -> None:
    """GATE 7 as amended by section 12.6: plateau detection with N > 1 workers.

    A single worker would make the whole aggregate question vacuous.
    """
    result = json.loads(SCHEDULER_RESULT.read_text(encoding="utf-8"))
    assert result["worker_count"] >= 2, (
        f"the campaign ran {result['worker_count']} worker(s); GATE 7's section "
        f"12.6 amendment requires N > 1. Re-run with --workers 2."
    )
    assert result["duration_s"] > 60


@requires_campaign
def test_the_master_served_both_workers_simultaneously() -> None:
    """The nodes count in the master's own stat line is the aggregate's witness.

    Per-worker coverage is never exposed (server.h:822-830, recorded at GATE 4b),
    so "aggregate" is proved the same way there: the master reporting more than
    one node, and throughput that one worker could not produce.
    """
    if not MASTER_LOG.exists():
        pytest.skip("no master log in the evidence directory")
    samples = _master_samples(MASTER_LOG.read_text(encoding="utf-8", errors="replace"))
    if not samples:
        pytest.skip("master flushed no stat lines -- D-033")

    peak_nodes = max(nodes for _, _, nodes, _ in samples)
    result = json.loads(SCHEDULER_RESULT.read_text(encoding="utf-8"))
    assert peak_nodes >= 2, (
        f"the master only ever saw {peak_nodes} node(s); it would have kept "
        f"fuzzing with whatever connected, and the plateau would have been "
        f"judged on a fraction of the campaign"
    )
    assert peak_nodes == result["worker_count"]


@requires_campaign
def test_the_plateau_signal_is_the_masters_aggregate_corpus() -> None:
    """Section 12.3: the sidecar's input is master-side, never a worker's.

    The scheduler writes ``{executions, new_coverage_events}`` and the sidecar
    polls it; ``new_coverage_events`` is a count of files in ``outputs/``, which
    the master owns and writes on behalf of every worker.
    """
    result = json.loads(SCHEDULER_RESULT.read_text(encoding="utf-8"))
    state_path = ARTIFACTS / f"campaign_state_{result['label']}.json"
    if not state_path.exists():
        pytest.skip(f"no campaign state file at {state_path}")

    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert set(state) >= {"executions", "new_coverage_events"}
    assert result["outputs_before"] <= state["new_coverage_events"] <= result[
        "outputs_after"
    ], (
        f"the state file's new_coverage_events ({state['new_coverage_events']}) is "
        f"outside the master's own corpus growth "
        f"({result['outputs_before']} -> {result['outputs_after']}), so the "
        f"plateau was judged on something other than the aggregate"
    )


@requires_sidecar_log
def test_a_plateau_produced_a_seed_generation_round() -> None:
    """GATE 7: the trigger reaches the LLM and the LLM answers.

    ``llm_seconds`` is asserted nonzero because it is the other half of the
    timing evidence: a round that cost real latency, in a process that is not the
    master.
    """
    rounds = _events({"seeds_published"})
    if not rounds:
        pytest.skip(
            "no seeds_published event recorded yet; run the scheduler with a "
            "sidecar (see this module's docstring)"
        )

    latest = rounds[-1]
    assert latest["seeds"] > 0
    assert latest["llm_seconds"] > 0
    assert latest["targets"], "the round recorded no aimed-at branch"
    assert all(e["clock"] == "slow" for e in _events()), (
        "a sidecar event is tagged as fast clock; the log is the evidence that "
        "every LLM call happened off the fast path"
    )


@requires_sidecar_log
def test_at_most_one_generation_round_per_plateau() -> None:
    """GATE 7: EXACTLY one call per plateau, measured on the real log.

    Hand-run rounds are excluded by their recorded ``trigger``, not by position.
    ``python -m llm.sidecar --once`` deliberately generates without a plateau in
    order to exercise the slow clock alone, and it appends to the same log; a
    positional rule ("ignore anything before the first plateau") got this wrong as
    soon as a --once round was run *after* a campaign, and reported the detector
    as re-firing when it had not. A false alarm on a real check is the worst
    outcome available, because the reflex is to loosen the check.
    """
    events = _events()
    plateaus = [i for i, e in enumerate(events) if e["event"] == "plateau"]
    if not plateaus:
        pytest.skip(
            "no plateau event recorded; the campaign never reported a plateau, so "
            "the once-per-plateau property has no evidence to check"
        )

    round_kinds = {"seeds_published", "seed_gen_failed", "spool_full", "skipped"}
    bounds = plateaus + [len(events)]
    for start, end in zip(bounds, bounds[1:]):
        window = [
            e
            for e in events[start + 1 : end]
            if e["event"] in round_kinds and e.get("trigger", "plateau") != "manual"
        ]
        assert len(window) <= 1, (
            f"{len(window)} plateau-triggered generation rounds between two "
            f"plateau events ({[e['event'] for e in window]}); the detector is "
            f"re-firing while the same plateau persists"
        )


@requires_campaign
def test_published_seeds_were_consumed_by_the_master() -> None:
    """GATE 7: generated seeds land in the corpus and are executed.

    "Consumed" is the observable form: the spool's only consumer is the master's
    ``CustomMutator_t::GetNewTestcase``, which reads a seed and deletes it
    (DECISIONS R9). A seed leaving the spool therefore means the master served it
    to a worker; a spool that only grows means every LLM seed was ignored while
    coverage kept climbing and the campaign looked healthy.
    """
    result = json.loads(SCHEDULER_RESULT.read_text(encoding="utf-8"))
    assert result["sidecar_rounds"] >= 1, (
        "the campaign recorded no generation round, so nothing was injected"
    )
    assert result["seeds_consumed"] > 0, (
        f"{result['sidecar_rounds']} round(s) published seeds and none were "
        f"consumed: the master's CustomMutator_t is not draining the spool "
        f"(check SNAPFUZZ_SEED_SPOOL), so edge 29 is not live"
    )


@pytest.mark.skipif(not SEED_PROVENANCE.exists(), reason="no seed provenance log")
def test_published_seeds_carry_provenance_naming_a_static_address() -> None:
    """Only bytes cross into the spool, so provenance lives in a side log.

    Without it the seeds are anonymous the moment they are written and no
    coverage can be attributed to them. The target must also be recoverable as a
    *static* address -- that is what makes attribution and retirement possible
    (D-045).
    """
    entries = [
        json.loads(line)
        for line in SEED_PROVENANCE.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert entries
    assert all(e["origin"] == "llm_seed_gen" for e in entries)
    assert all(e["bytes"] > 0 for e in entries)
    assert all(e["rationale"].startswith("targets ") for e in entries)

    if not A3_MODULE.exists():
        pytest.skip("no A3 export to resolve targets against")
    statics = {b["static_addr"] for b in json.loads(
        A3_MODULE.read_text(encoding="utf-8")
    )["blocks"]}
    resolved = [
        addr
        for addr in (parse_target(e["rationale"]) for e in entries[-8:])
        if addr in statics
    ]
    assert resolved, (
        "none of the last 8 published seeds names a known static address, so no "
        "attempt can be matched against measured coverage (D-045)"
    )


@requires_campaign
def test_the_fast_loop_never_stalled_on_the_llm() -> None:
    """GATE 7: the timing log shows the fast loop kept running through the round.

    Read from the master's own execution counter rather than from the scheduler's
    tick samples: the scheduler's first sample straddles bochscpu's dump load and
    is meaningless. What matters is that no interval between stat lines went
    quiet, and that the window observed is longer than the LLM round it has to
    cover -- a 60-90 s call inside a process that shares the master's thread
    would leave an unmistakable hole.
    """
    if not MASTER_LOG.exists():
        pytest.skip("no master log in the evidence directory")
    samples = _master_samples(MASTER_LOG.read_text(encoding="utf-8", errors="replace"))
    if len(samples) < 4:
        pytest.skip(f"only {len(samples)} master stat lines -- D-033")

    rates = []
    for (execs_a, _, _, up_a), (execs_b, _, _, up_b) in zip(samples, samples[1:]):
        if up_b > up_a:
            rates.append((execs_b - execs_a) / (up_b - up_a))
    assert rates, "no usable interval between stat lines"

    # Skip the first interval: it contains process start and snapshot load.
    steady = rates[1:] or rates
    assert min(steady) > 50, (
        f"throughput fell to {min(steady):.0f} exec/s between stat lines "
        f"(series: {[round(r) for r in steady]}); the fast loop stalled"
    )

    observed_s = samples[-1][3] - samples[0][3]
    window = _campaign_window()
    rounds = [
        e
        for e in _events({"seeds_published"})
        if window is None or window[0] <= e["ts"] <= window[1]
    ]
    longest_call = max((e["llm_seconds"] for e in rounds), default=0.0)
    if longest_call:
        assert observed_s >= longest_call, (
            f"the master log covers {observed_s:.0f}s but the longest LLM round "
            f"took {longest_call:.0f}s, so the evidence does not span the call"
        )


# --- before/after: did injection actually buy coverage? ------------------


@pytest.mark.skipif(not SEED_DELTA.exists(), reason="no seed_delta.json recorded")
def test_coverage_was_measured_before_and_after_injection() -> None:
    """GATE 7 requires the before/after to be RECORDED, not just claimed.

    Measured the only way it can be (D-021, D-033): cov traces regenerated over
    the corpus, and separately over the LLM seeds alone, so the delta is
    attributable rather than coincidental with whatever the mutator did.
    """
    delta = json.loads(SEED_DELTA.read_text(encoding="utf-8"))
    for key in (
        "covered_before",
        "covered_by_llm_seeds",
        "covered_union",
        "new_blocks",
        "frontier_before",
        "frontier_after",
    ):
        assert key in delta, f"seed_delta.json has no {key}"

    assert delta["llm_seed_files"] > 0, "no LLM seed was measured"
    assert delta["covered_before"] > 0, "the baseline measured no coverage at all"
    assert delta["covered_union"] >= delta["covered_before"], (
        "the union of before and the LLM seeds is smaller than before, which "
        "means the two measurements are not comparable"
    )
    assert len(delta["new_blocks"]) == delta["covered_union"] - delta[
        "covered_before"
    ], (
        f"new_blocks lists {len(delta['new_blocks'])} block(s) but the counts say "
        f"{delta['covered_union'] - delta['covered_before']}; one of the two is "
        f"measuring something else"
    )


@pytest.mark.skipif(not SEED_DELTA.exists(), reason="no seed_delta.json recorded")
def test_llm_seeds_increased_coverage() -> None:
    """GATE 7's headline result: coverage increases after injection.

    Not asserted-away when the recorded round added nothing: that is a real
    outcome of a real round, and it is the number the writeup has to report either
    way. What it is NOT is evidence for the gate -- so this reports differently
    depending on who is asking. In development it skips with the measurement
    printed; under SNAPFUZZ_STRICT_GATE=1 it FAILS, because a green suite must not
    be able to stand in for the one criterion GATE 7 exists to check (D-067).
    """
    from tests.gates.conftest import missing_gate_evidence

    delta = json.loads(SEED_DELTA.read_text(encoding="utf-8"))
    if not delta["new_blocks"]:
        missing_gate_evidence(
            f"the recorded round added no new blocks "
            f"({delta['covered_before']} covered before, "
            f"{delta['covered_by_llm_seeds']} by the seeds alone, union "
            f"{delta['covered_union']}). GATE 7's coverage-increase evidence has "
            f"not been produced yet -- re-measure after a round whose seeds aim "
            f"at a branch the control probe shows is input-reachable."
        )
    assert delta["covered_union"] > delta["covered_before"], (
        "new_blocks is non-empty but the union did not grow"
    )
    print(
        f"LLM seeds added {len(delta['new_blocks'])} block(s): "
        f"{delta['new_blocks']} in {delta.get('new_block_functions')}"
    )


@pytest.mark.skipif(not CONTROL_PROBE.exists(), reason="no control_probe.json")
def test_the_control_probe_shows_the_frontier_is_not_a_phantom() -> None:
    """A frontier branch nothing can reach would make the gate unfalsifiable.

    The probe is a hand-written input, not an LLM one, and the mechanism is now
    pinned exactly (capacity_probe.json; adversarially verified over 454 measured
    executions). ``ChunkList`` holds **four** slots, 0x140006a18..0x140006a38:

    * Allocates 1-4 fill the table.
    * Allocate 5 finds no free slot, runs off the end, and writes a ``Chunk_t*``
      out of bounds over the adjacent CRT function pointer
      ``__dyn_tls_dtor_callback`` -- which is NULL in this snapshot, so the null
      test still takes the null path and 0x14000131c is SKIPPED.
    * Allocate 6 reads that out-of-bounds slot back as a ``Chunk_t*`` and frees
      it. That is 0x14000131c.

    So the minimum is exactly six, with no intervening Delete (each Delete frees a
    slot and raises the count by one). Two things follow, and both are the reason
    this branch is the right test case for LLM seed generation: it is reachable
    only by REPEATING one command, which the pseudo-C tells you and random
    mutation finds only by luck; and the out-of-bounds write itself, at five,
    covers nothing new (see eval/coverage_gradient.py), so coverage guidance has
    no gradient pointing at it.
    """
    probe = json.loads(CONTROL_PROBE.read_text(encoding="utf-8"))
    by_count = {int(k): v for k, v in probe.items()}
    assert len(by_count) >= 2, "a control needs at least two packet counts"

    low, high = min(by_count), max(by_count)
    assert by_count[high]["blocks"] > by_count[low]["blocks"], (
        f"{high} packets covered no more blocks than {low}; the probe shows "
        f"nothing about sequence length"
    )
    gained = set(by_count[high]["reached"]) - set(by_count[low]["reached"])
    assert gained, (
        f"{high} packets reached no frontier branch that {low} did not, so the "
        f"frontier is not demonstrably input-reachable"
    )
    assert f"{CAPACITY_BRANCH:#x}" in gained, (
        f"expected {CAPACITY_BRANCH:#x} among the branches only the longer "
        f"sequence reaches; got {sorted(gained)}"
    )


@pytest.mark.skipif(not CAPACITY_PROBE.exists(), reason="no capacity_probe.json")
def test_the_reachability_threshold_is_pinned_not_bounded() -> None:
    """The bar the LLM has to clear is an exact number, not a range.

    It matters that this is exact. "Between 5 and 8 allocations" would let any
    long sequence look like success; six is a claim that can be wrong, and it is
    what the writeup states. It also has to be MONOTONIC -- once the out-of-bounds
    slot is populated it stays populated, so every count above the threshold must
    reach the branch too. A non-monotonic result would mean the probe measured
    something incidental.
    """
    probe = json.loads(CAPACITY_PROBE.read_text(encoding="utf-8"))
    hits = {int(k): bool(v) for k, v in probe["hits"].items()}
    minimum = probe["minimum_reaching"]

    assert minimum == EXPECTED_CAPACITY_THRESHOLD, (
        f"the threshold moved: capacity_probe says {minimum}, the writeup and "
        f"docs/DEVIATIONS.md D-047 say {EXPECTED_CAPACITY_THRESHOLD}"
    )
    below = [n for n, ok in sorted(hits.items()) if n < minimum]
    assert below and not any(hits[n] for n in below), (
        f"counts below {minimum} should all miss the branch; got "
        f"{ {n: hits[n] for n in below} }"
    )
    above = [n for n, ok in sorted(hits.items()) if n >= minimum]
    assert all(hits[n] for n in above), (
        f"reaching {CAPACITY_BRANCH:#x} must be monotonic in the allocation "
        f"count once the out-of-bounds slot is populated; got "
        f"{ {n: hits[n] for n in above} }"
    )
