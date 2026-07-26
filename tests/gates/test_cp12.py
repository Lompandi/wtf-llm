"""GATE 12 -- the pipeline driver (``orchestrator/pipeline.py``).

Before this driver the pipeline was thirteen commands run by hand. A driver that
merely runs them in sequence is worth nothing: the value is entirely in the
**negative** properties, because a pipeline runner is the easiest place in a
project to hide a failure. So this gate is almost all negative tests.

What it asserts, and why each one is a way a runner hides a failure:

* **Ordering.** A2 must be built before the entry is chosen, and every stage that
  needs the entry must come after it. The order is *derived* from the stage list
  here rather than pinned as a literal list of thirteen strings, so the test says
  WHY the order is what it is instead of merely freezing it.
* **The artifact is the evidence.** Every stage names something it must produce.
  A stage with no artifact would be marked done on exit code alone, and
  ``analyzeHeadless`` and ``wtf`` both exit 0 having produced nothing
  (D-026, D-042).
* **The late-bound entry never falls back to a guess.** ``resolve_entry`` returns
  an error string, never a plausible symbol: a wrong entry gives a harness that
  runs, reports coverage and never enters the parser -- the silent failure CP4's
  trace validation exists to catch.
* **The summary never prints unqualified success.** ``_summarise`` returns
  non-zero when anything failed, was blocked, or was never reached. This is the
  most important test in the file: it is what stops an exit code of 0 being
  printed next to "PIPELINE DID NOT COMPLETE".
* **Prerequisites are checked before any stage runs.** A missing
  ``GHIDRA_INSTALL_DIR`` discovered after a twenty-minute campaign wastes the
  campaign.
* **The honesty claims survive.** Snapshot ACQUISITION is not performed here
  (edges 1/6/7 pending) and the shipped module does not include the generated
  header (edge 14 pending, D-055). Both live in ``note`` fields; deleting one
  makes the README and the graph wrong silently.
* **RULE 1.** This module imports no LLM client. It launches two LLM-using
  stages as *subprocesses*, which is a different thing.

Everything here is checkable from the stage list, the module's own functions and
``tmp_path`` fixtures: no subprocesses, no Ghidra, no campaigns.
"""

from __future__ import annotations

import ast
import json
import shutil
from pathlib import Path

import pytest
import yaml

import orchestrator.pipeline as pipeline
from orchestrator.pipeline import (
    ENTRY_PLACEHOLDER,
    PipelineConfig,
    StageResult,
    _summarise,
    _up_to_date,
    build_stages,
    check_prerequisites,
    resolve_entry,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATH = REPO_ROOT / "orchestrator" / "pipeline.py"
SOURCE = SOURCE_PATH.read_text(encoding="utf-8")

# The name of the FuzzEntry artifact is not hardcoded here: it is read back out of
# run_pipeline (see test_the_late_bound_entry_is_read_from_the_stage_that_makes_it),
# because a driver resolving the placeholder from a file no stage produces would
# fail for every new target and the two facts live in different functions.
ENTRY_ARTIFACT_NAME = "fuzz_entry_llm.json"

# Substrings that mean a module talks to the model. Deliberately NOT the bare
# string "llm": `analysis/reverse.py` legitimately imports `llm.ghidra_mcp`, a
# decompiler client that sends no prompt (the same exception test_cp8.py carves
# out). `llm.sidecar` counts because a module that launches the sidecar is how
# the campaign stage reaches the model, per section 12.2.
LLM_MARKERS = ("LlmClient", "from llm.client", "llm.sidecar", "dspy")


# --- fixtures ------------------------------------------------------------


def _config(**overrides) -> PipelineConfig:
    """A config against the real repo, for tests that only read the stage list."""
    settings = dict(
        target_name="snapfuzz",
        binary=REPO_ROOT / "targets" / "tlv_server" / "target" / "tlv_server.exe",
        entry_symbol=None,
        state_dir=REPO_ROOT / "targets" / "tlv_server" / "state",
    )
    settings.update(overrides)
    return PipelineConfig(**settings)


def _stages(**overrides):
    return build_stages(_config(**overrides))


def _module_of(stage) -> str:
    """The module a stage runs: argv is [python, -u, -m, <module>, ...]."""
    return stage.argv[stage.argv.index("-m") + 1]


def _stage_running(stages, module: str):
    return next(s for s in stages if _module_of(s) == module)


def _stage_with_argv(stages, *needles: str):
    """The one stage whose argv contains all of ``needles``."""
    matches = [s for s in stages if all(n in s.argv for n in needles)]
    assert len(matches) == 1, f"{needles} matches {[s.key for s in matches]}"
    return matches[0]


def _index_producing(stages, name: str) -> int:
    """Index of the stage that produces the artifact called ``name``."""
    matches = [i for i, s in enumerate(stages) if any(p.name == name for p in s.produces)]
    assert len(matches) == 1, f"{name} is produced by {len(matches)} stage(s)"
    return matches[0]


def _api_key_env() -> str:
    """The DEFAULT provider's key variable -- the one the pre-flight will find first."""
    config = yaml.safe_load((REPO_ROOT / "config" / "llm.yaml").read_text(encoding="utf-8"))
    return next(iter(config["providers"].values()))["api_key_env"]


def _all_api_key_envs() -> list[str]:
    """Every provider's key variable. Any one of them satisfies the pre-flight, so
    a test that wants the no-key case has to clear them all."""
    config = yaml.safe_load((REPO_ROOT / "config" / "llm.yaml").read_text(encoding="utf-8"))
    return [p["api_key_env"] for p in config["providers"].values() if p.get("api_key_env")]


@pytest.fixture
def satisfied_env(monkeypatch, tmp_path):
    """Environment prerequisites met, so the target-tree tests report only the
    target tree.

    GHIDRA_INSTALL_DIR is pointed at a REAL install, not at tmp_path. This fixture
    used to set it to tmp_path and rely on the checker short-circuiting whenever the
    variable was merely present -- which was itself the bug (a variable left pointing
    at the wrong directory passed the check and failed twenty minutes later, D-057).
    Now the checker always validates, so the fixture has to supply something valid.
    """
    from prep.ghidra_headless import GhidraError, find_ghidra

    try:
        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(find_ghidra()))
    except GhidraError:
        pytest.skip("Ghidra is not installed; the prerequisite control needs one")
    monkeypatch.setenv(_api_key_env(), "sk-not-a-real-key")


def _fake_target(
    tmp_path: Path,
    *,
    dirs: tuple[str, ...] = ("inputs", "outputs", "coverage", "crashes", "state"),
    binary: bool = True,
    seed: bool = True,
) -> PipelineConfig:
    """A self-contained repo root under tmp_path, so prerequisite tests never
    depend on the state of the real targets/ tree.

    The three config files are copied rather than synthesised: check_prerequisites
    reads all of them, and a hand-written stub would test the stub.
    """
    root = tmp_path / "repo"
    (root / "config").mkdir(parents=True)
    for name in ("llm.yaml", "fuzz.yaml", "target.yaml"):
        shutil.copy(REPO_ROOT / "config" / name, root / "config" / name)

    target_dir = root / "targets" / "fake"
    target_dir.mkdir(parents=True)
    for sub in dirs:
        (target_dir / sub).mkdir()
    if seed and (target_dir / "inputs").is_dir():
        (target_dir / "inputs" / "seed.json").write_text("{}", encoding="utf-8")

    binary_path = root / "bin" / "fake.exe"
    binary_path.parent.mkdir(parents=True)
    if binary:
        binary_path.write_bytes(b"MZ")

    return PipelineConfig(
        target_name="fake",
        binary=binary_path,
        entry_symbol="FakeEntry",
        state_dir=target_dir / "state",
        repo_root=root,
    )


def _entry_json(path: Path, **overrides) -> Path:
    payload = {
        "module": "tlv_server",
        "symbol": "ProcessPacket",
        "static_addr": 0x140001150,
        "rationale": "hand-written for this test",
        "input_param": "rcx",
        "size_param": "rdx",
    }
    payload.update(overrides)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _result(key: str, status: str, detail: str = "") -> StageResult:
    return StageResult(key=key, title=f"the {key} stage", status=status, detail=detail)


# --- ordering: derived from the stage list, not pinned --------------------


def test_the_stage_list_is_the_fourteen_stage_pipeline() -> None:
    """A canary on the count only. The ORDER is derived by the tests below, so a
    reorder must fail for a reason that names the constraint it broke.

    Fourteen since `08b-harness`, which derives the HarnessSpec. `prep/harness_derive.py`
    existed from CP11 and no stage ran it, so the harness spec could only be produced
    by hand -- which is why the generated module in the tree was built once for
    tlv_server and never again (D-073)."""
    stages = _stages()
    assert len(stages) == 14
    keys = [s.key for s in stages]
    assert len(set(keys)) == len(keys), f"duplicate stage keys: {keys}"


def test_stage_keys_are_numbered_in_execution_order() -> None:
    """``--from`` and ``--only`` select by key PREFIX, so a key whose number
    disagrees with its position makes ``--from 09`` start somewhere else."""
    # A key may carry a LETTER suffix -- `07a-acquire`, `08b-harness` -- for a stage
    # inserted between two existing ones. `int()` on "08b" raises, and it already
    # would have for `07a` on any `--kd-pipe` run; the test simply never built that
    # stage list. Sorting on (number, suffix) keeps the property that matters, which
    # is that key order and execution order agree.
    def sort_key(key: str) -> tuple[int, str]:
        head = key.split("-", 1)[0]
        digits = "".join(c for c in head if c.isdigit())
        suffix = head[len(digits):]
        return int(digits), suffix

    keys = [s.key for s in _stages()]
    positions = [sort_key(k) for k in keys]
    assert positions == sorted(positions), (
        f"key order disagrees with execution order, so --from selects the wrong "
        f"stage: {keys}"
    )
    # And the numbers still start at 1 and never skip, letters aside.
    numbers = sorted({n for n, _ in positions})
    assert numbers == list(range(1, len(numbers) + 1)), numbers


def test_a2_is_built_before_the_entry_is_chosen() -> None:
    """The trap this module exists to encode.

    CLAUDE.md section 3.1 draws entry selection FEEDING decompilation (edges 4
    and 5), which reads as "entry first". It cannot be: the entry is chosen by a
    model reading pseudo-C, so the A2 cache has to exist first. Derived from the
    data -- the entry stage's own ``needs`` names the cache it reads -- rather
    than asserted as two literal keys, so the test states the dependency instead
    of freezing the numbering.
    """
    stages = _stages()
    entry_index = _index_producing(stages, ENTRY_ARTIFACT_NAME)

    caches = [p for p in stages[entry_index].needs if p.suffix == ".sqlite"]
    assert caches, (
        "the entry stage needs no pseudo-C cache; the model would be choosing an "
        "entry with no code in front of it"
    )
    for cache in caches:
        assert _index_producing(stages, cache.name) < entry_index, (
            f"{cache.name} is produced after the entry that reads it"
        )


def test_a2_is_decompiled_at_module_scope_because_there_is_no_entry_yet() -> None:
    """A closure scope needs a function to take the closure OF. At stage 01 there
    is none, so module scope is not a preference -- it is the only option."""
    stages = _stages()
    pseudoc = _stage_with_argv(stages, "--what", "pseudoc")
    assert pseudoc is stages[0], "decompilation must be the first thing that happens"
    assert pseudoc.argv[pseudoc.argv.index("--scope") + 1] == "module"
    assert ENTRY_PLACEHOLDER not in pseudoc.argv
    assert "--entry" not in pseudoc.argv


def test_every_stage_that_needs_the_entry_runs_after_it_is_chosen() -> None:
    """Both halves of the ordering argument, from the two ways a stage can depend
    on the entry: carrying the late-bound placeholder in its argv, or naming the
    FuzzEntry artifact in its needs."""
    stages = _stages()
    entry_index = _index_producing(stages, ENTRY_ARTIFACT_NAME)

    placeholder_stages = [i for i, s in enumerate(stages) if ENTRY_PLACEHOLDER in s.argv]
    assert len(placeholder_stages) >= 3, (
        "no stage carries the placeholder, so this test proves nothing -- late "
        "binding has been removed or renamed"
    )
    for index in placeholder_stages:
        assert index > entry_index, (
            f"{stages[index].key} is handed the entry symbol before "
            f"{stages[entry_index].key} has chosen one"
        )

    consumers = [
        i for i, s in enumerate(stages)
        if any(p.name == ENTRY_ARTIFACT_NAME for p in s.needs)
    ]
    assert consumers, "nothing consumes the FuzzEntry; stage 03's output is dead"
    for index in consumers:
        assert index > entry_index


def test_the_data_symbol_stage_comes_after_the_entry_and_says_why() -> None:
    """A6 is the reason the second half of the ordering matters, and the failure
    is silent: with no entry every symbol is marked unreferenced, load_globals
    returns nothing, and the seed prompt quietly loses the table capacities D-047
    exists to supply. Nothing errors."""
    stages = _stages()
    datasyms = _stage_with_argv(stages, "--what", "data-symbols")
    assert ENTRY_PLACEHOLDER in datasyms.argv
    assert stages.index(datasyms) > _index_producing(stages, ENTRY_ARTIFACT_NAME)
    assert "load_globals" in datasyms.note
    assert "D-047" in datasyms.note


def test_the_placeholder_disappears_when_an_entry_is_configured() -> None:
    """With ``--entry-symbol`` there is nothing to late-bind, and a leftover
    placeholder would be passed to Ghidra verbatim."""
    stages = _stages(entry_symbol="ProcessPacket")
    for stage in stages:
        assert ENTRY_PLACEHOLDER not in stage.argv, stage.key
    assert any("ProcessPacket" in s.argv for s in stages)


def test_no_stage_needs_an_artifact_that_a_later_stage_produces() -> None:
    """The general form of the ordering claim: a topological check over the whole
    list, so a reorder that breaks any dependency fails here even if it happens
    to keep A2 before the entry."""
    stages = _stages()
    produced_at = {p: i for i, s in enumerate(stages) for p in s.produces}
    for index, stage in enumerate(stages):
        for need in stage.needs:
            if need in produced_at:
                assert produced_at[need] < index, (
                    f"{stage.key} needs {need.name}, produced later by "
                    f"{stages[produced_at[need]].key}"
                )


# --- the artifact is the evidence, not the exit code ---------------------


def test_every_stage_names_at_least_one_artifact() -> None:
    """A stage with an empty ``produces`` cannot be verified, so it would be
    marked done because its command exited 0 -- and analyzeHeadless and wtf both
    exit 0 having produced nothing (D-026, D-042)."""
    for stage in _stages():
        assert stage.produces, f"{stage.key} names no artifact, so it cannot be checked"


def test_a_stage_with_no_artifact_can_never_look_up_to_date() -> None:
    """The other half of the same rule, on the function that implements it:
    ``all()`` over an empty list is True, so without the explicit guard a
    stage naming nothing would be skipped forever."""
    from orchestrator.pipeline import Stage

    empty = Stage(key="99-nothing", title="produces nothing", argv=[], produces=[])
    assert _up_to_date(empty)[0] is False


def test_up_to_date_needs_every_named_artifact_not_just_one(tmp_path: Path) -> None:
    from orchestrator.pipeline import Stage

    present, absent = tmp_path / "a.json", tmp_path / "b.json"
    present.write_text("{}", encoding="utf-8")
    partial = Stage(key="99", title="two artifacts", argv=[], produces=[present, absent])
    assert _up_to_date(partial)[0] is False
    complete = Stage(key="99", title="one artifact", argv=[], produces=[present])
    # Presence only -- no identity passed, so this is the "does the output exist"
    # question. Reusing it for THIS target additionally needs provenance; see
    # test_provenance.py.
    assert _up_to_date(complete)[0] is True


def test_no_two_stages_claim_the_same_artifact() -> None:
    """Shared evidence means the second stage looks up-to-date the moment the
    first has run, and is then skipped forever without ever having run."""
    seen: dict[Path, str] = {}
    for stage in _stages():
        for artifact in stage.produces:
            assert artifact not in seen, (
                f"{stage.key} and {seen[artifact]} both claim {artifact.name}"
            )
            seen[artifact] = stage.key


def test_artifact_paths_are_absolute_and_inside_the_repo() -> None:
    """Two separate silent failures. A relative path is checked against the
    process cwd, so the same stage is 'done' or not depending on where it was
    launched from; and the skip message computes ``relative_to(repo_root)``, which
    raises ValueError for anything outside the repo."""
    config = _config()
    for stage in _stages():
        for path in [*stage.produces, *stage.needs]:
            assert path.is_absolute(), f"{stage.key}: {path} is relative"
        for artifact in stage.produces:
            artifact.relative_to(config.repo_root)  # raises if outside


# --- the late-bound entry never falls back to a guess --------------------


def test_the_late_bound_entry_is_read_from_the_stage_that_makes_it() -> None:
    """``run_pipeline`` resolves the placeholder from a filename written in its own
    body, while a stage declares it as an artifact somewhere else in the file. If
    those two names drift apart the placeholder resolves from a file nothing
    produces -- and only for a NEW target, which is the case nobody tests by hand.
    """
    tree = ast.parse(SOURCE)
    function = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "run_pipeline"
    )
    literals = {
        node.value for node in ast.walk(function)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.endswith(".json")
    }
    assert literals == {ENTRY_ARTIFACT_NAME}, (
        f"run_pipeline resolves the entry from {literals}"
    )
    _index_producing(_stages(), ENTRY_ARTIFACT_NAME)  # asserts exactly one producer


def test_resolve_entry_substitutes_the_symbol_from_the_artifact(tmp_path: Path) -> None:
    entry = _entry_json(tmp_path / ENTRY_ARTIFACT_NAME, symbol="ProcessPacket")
    argv = ["py", "-u", "-m", "prep.ghidra_headless", "--entry", ENTRY_PLACEHOLDER]

    resolved = resolve_entry(argv, entry)

    assert resolved == ["py", "-u", "-m", "prep.ghidra_headless", "--entry", "ProcessPacket"]
    assert ENTRY_PLACEHOLDER not in resolved


def test_resolve_entry_substitutes_every_occurrence(tmp_path: Path) -> None:
    entry = _entry_json(tmp_path / ENTRY_ARTIFACT_NAME, symbol="ProcessPacket")
    argv = ["--entry", ENTRY_PLACEHOLDER, "--entry-symbol", ENTRY_PLACEHOLDER]
    assert resolve_entry(argv, entry) == [
        "--entry", "ProcessPacket", "--entry-symbol", "ProcessPacket",
    ]


def test_resolve_entry_passes_argv_through_when_there_is_no_placeholder(
    tmp_path: Path,
) -> None:
    """Stages 01/02/03 and everything after 08 have no placeholder, so a missing
    FuzzEntry must not stop them -- stage 03 is what creates it."""
    argv = ["py", "-u", "-m", "prep.pseudoc_cache", "build"]
    assert resolve_entry(argv, tmp_path / "does-not-exist.json") == argv


def test_resolve_entry_reports_a_missing_artifact_rather_than_guessing(
    tmp_path: Path,
) -> None:
    result = resolve_entry(["--entry", ENTRY_PLACEHOLDER], tmp_path / ENTRY_ARTIFACT_NAME)
    assert isinstance(result, str)
    assert ENTRY_ARTIFACT_NAME in result
    assert "03" in result, "the message must say which stage produces it"
    assert "--entry-symbol" in result, "the message must say how to supply one by hand"


def test_resolve_entry_reports_an_unreadable_artifact(tmp_path: Path) -> None:
    broken = tmp_path / ENTRY_ARTIFACT_NAME
    broken.write_text("{not json,", encoding="utf-8")
    result = resolve_entry(["--entry", ENTRY_PLACEHOLDER], broken)
    assert isinstance(result, str)
    assert "not a readable FuzzEntry" in result


def test_resolve_entry_reports_an_entry_that_names_no_symbol(tmp_path: Path) -> None:
    """A FuzzEntry carrying only an address is valid (``symbol`` is optional), and
    a stage that takes a symbol cannot use it. Substituting the empty string, or
    the address, would hand Ghidra a scope it silently fails to resolve."""
    entry = _entry_json(tmp_path / ENTRY_ARTIFACT_NAME, symbol=None)
    result = resolve_entry(["--entry", ENTRY_PLACEHOLDER], entry)
    assert isinstance(result, str)
    assert "names no symbol" in result
    assert "0x140001150" in result, "the message must say what it does have"


@pytest.mark.parametrize("flaw", ["missing", "unreadable", "no-symbol", "wrong-shape"])
def test_no_failure_of_resolve_entry_yields_a_runnable_command(
    tmp_path: Path, flaw: str
) -> None:
    """The headline negative. Every way of failing to know the entry returns an
    error STRING, never argv -- so the stage cannot run.

    A fallback symbol here is the worst outcome available: a plausible wrong entry
    gives a harness that runs, reports coverage and never enters the parser, which
    is exactly the silent failure CP4's trace validation exists to catch.
    """
    path = tmp_path / ENTRY_ARTIFACT_NAME
    if flaw == "unreadable":
        path.write_text("\x00\x01 not json", encoding="utf-8")
    elif flaw == "no-symbol":
        _entry_json(path, symbol=None)
    elif flaw == "wrong-shape":
        path.write_text(json.dumps({"symbol": "ProcessPacket"}), encoding="utf-8")

    result = resolve_entry(["--entry", ENTRY_PLACEHOLDER], path)

    assert isinstance(result, str), f"{flaw!r} produced a runnable argv: {result}"
    assert not isinstance(result, list)


# --- the summary never prints unqualified success -----------------------


def test_summarise_returns_zero_only_when_every_stage_is_accounted_for(capsys) -> None:
    results = [_result("01-a", "ran"), _result("02-b", "skipped-uptodate")]
    assert _summarise(results, 2) == 0
    assert "all stages accounted for" in capsys.readouterr().out


def test_summarise_returns_nonzero_when_a_stage_failed() -> None:
    results = [_result("01-a", "ran"), _result("02-b", "failed", "exit 0, no artifact")]
    assert _summarise(results, 2) != 0


def test_summarise_returns_nonzero_when_a_stage_was_blocked() -> None:
    """Blocked is not a benign skip: snapshot acquisition cannot be performed
    here, so a campaign built on a state/ that does not exist must not proceed."""
    results = [_result("01-a", "ran"), _result("07-snapshot", "blocked", "needs KD")]
    assert _summarise(results, 2) != 0


def test_summarise_returns_nonzero_when_stages_were_never_reached() -> None:
    """The quietest case: the loop broke, so there is no failed result for the
    stages after it -- only fewer results than stages. A runner that reported on
    what it did rather than on what it was asked to do would exit 0 here."""
    results = [_result("01-a", "ran"), _result("02-b", "ran")]
    assert _summarise(results, 13) != 0


@pytest.mark.parametrize(
    "results,total",
    [
        ([_result("01-a", "failed", "exit 1")], 1),
        ([_result("01-a", "blocked", "needs a VM")], 1),
        ([_result("01-a", "ran")], 13),
        ([_result("01-a", "ran"), _result("02-b", "failed")], 13),
    ],
    ids=["failed", "blocked", "never-reached", "failed-and-never-reached"],
)
def test_summarise_never_prints_success_next_to_a_failure(
    capsys, results, total
) -> None:
    """The most important test in this file.

    An exit code and a printed summary that disagree is how a broken campaign gets
    written up as a working one. So: non-zero, the words that say so, and NOT the
    words that say otherwise.
    """
    code = _summarise(results, total)
    out = capsys.readouterr().out

    assert code == 1
    assert "all stages accounted for" not in out
    assert ("PIPELINE DID NOT COMPLETE" in out) or ("INCOMPLETE" in out)


def test_summarise_reports_every_skipped_stage_and_its_reason(capsys) -> None:
    """A run that quietly did three of thirteen stages and printed "done" is worse
    than a crash, so a skip has to appear in the summary with its reason."""
    results = [
        _result("01-pseudoc", "skipped-uptodate"),
        _result("07-snapshot", "skipped-selected", "not selected by --only"),
    ]
    _summarise(results, 2)
    out = capsys.readouterr().out

    assert "01-pseudoc" in out and "07-snapshot" in out
    assert "skipped-uptodate" in out and "skipped-selected" in out
    assert "not selected by --only" in out, "a skip with no reason cannot be reviewed"
    assert "0 ran, 2 skipped" in out, "a skipped stage must not be counted as ran"


def test_a_summary_of_nothing_is_not_a_success(capsys) -> None:
    """``--only`` matching no stage, or a crash before the first stage, gives an
    empty result list. Zero of thirteen is the clearest possible failure."""
    assert _summarise([], 13) != 0
    assert "all stages accounted for" not in capsys.readouterr().out


# --- prerequisites, checked before anything runs ------------------------


def test_a_complete_target_tree_has_no_prerequisite_problems(
    tmp_path: Path, satisfied_env
) -> None:
    """The control. Without it every test below could pass because the checker
    always complains about something."""
    config = _fake_target(tmp_path)
    assert check_prerequisites(config, build_stages(config)) == []


def test_prerequisites_report_a_missing_binary(tmp_path: Path, satisfied_env) -> None:
    config = _fake_target(tmp_path, binary=False)
    problems = check_prerequisites(config, build_stages(config))
    assert any("fake.exe" in p and "does not exist" in p for p in problems), problems


def test_prerequisites_report_every_missing_per_target_directory(
    tmp_path: Path, satisfied_env
) -> None:
    """Section 13.1 requires all five, and wtf creates none of them.

    These four are now CREATED rather than reported: they are this tool's own layout
    inside `targets/<name>/`, they are empty, and making a first-time user mkdir four
    directories is friction with nothing behind it. What must not regress is that they
    END UP THERE -- a missing crashes/ is otherwise not noticed until a crash has been
    found and dropped on the floor.
    """
    config = _fake_target(tmp_path, dirs=())
    problems = check_prerequisites(config, build_stages(config))
    for sub in ("inputs", "outputs", "coverage", "crashes"):
        assert (config.target_dir / sub).is_dir(), (
            f"{sub}/ was neither created nor reported: {problems}"
        )
        assert not any(f"{sub} is missing" in p for p in problems), (
            f"{sub}/ was created, so it must not also be reported as a problem"
        )


def test_prerequisites_report_an_empty_inputs_directory(
    tmp_path: Path, satisfied_env
) -> None:
    """inputs/ is the startup seed directory: an empty one gives the mutator
    nothing to work from, and the campaign runs to completion finding nothing."""
    config = _fake_target(tmp_path, seed=False)
    problems = check_prerequisites(config, build_stages(config))
    assert any("holds no seeds" in p for p in problems), problems


def test_prerequisites_report_a_missing_state_directory_as_not_ours_to_make(
    tmp_path: Path, satisfied_env
) -> None:
    """The pending-by-design case. Acquisition needs a Hyper-V VM, WinDbg/KD and
    the 0vercl0k/snapshot extension, so the driver must say the snapshot has to be
    supplied -- not offer to produce one."""
    config = _fake_target(tmp_path, dirs=("inputs", "outputs", "coverage", "crashes"))
    problems = check_prerequisites(config, build_stages(config))
    matching = [p for p in problems if str(config.state_dir) in p]
    assert matching, problems
    assert any("NOT produced by this pipeline" in p for p in matching)
    assert any("1/6/7" in p for p in matching), "the pending edges must be named"
    # And it must not read as an offer. An intermediate version of this message said
    # "Pass --kd-pipe to acquire one from a running guest VM", which presents a path
    # that has never been executed end to end as the easy option.
    for text in matching:
        if "--kd-pipe" in text:
            assert "never been executed" in text or "untested" in text, (
                f"the message offers acquisition without saying it is unproven: {text}"
            )


def test_prerequisites_report_missing_ghidra_and_name_the_stages_that_need_it(
    tmp_path: Path, monkeypatch
) -> None:
    """Derived from the stage list inside check_prerequisites, so the message
    cannot come to name stages that no longer exist -- which it already did once."""
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.setenv(_api_key_env(), "sk-not-a-real-key")

    # find_ghidra is stubbed rather than relying on the env var being absent.
    # Unsetting the variable no longer means "not installed": find_ghidra also
    # consults PATH and then ghidra.install_dir in config/target.yaml, which is now
    # populated. So this test has to simulate a machine with no Ghidra at all,
    # otherwise it silently stops exercising the branch it is named after.
    import prep.ghidra_headless as ghidra_mod

    def no_ghidra(explicit=None):
        raise ghidra_mod.GhidraError(
            "Ghidra not found. Pass --ghidra, set GHIDRA_INSTALL_DIR, or set "
            "ghidra.install_dir in config/target.yaml."
        )

    monkeypatch.setattr(ghidra_mod, "find_ghidra", no_ghidra)

    config = _fake_target(tmp_path)
    stages = build_stages(config)

    problems = check_prerequisites(config, stages)
    ghidra = [p for p in problems if "GHIDRA_INSTALL_DIR" in p]
    assert ghidra, problems

    expected = {s.key for s in stages if "ghidra_headless" in " ".join(s.argv)}
    assert expected, "no stage runs Ghidra, so this check is dead"
    for key in expected:
        assert key in ghidra[0], f"{key} needs Ghidra but is not named: {ghidra[0]}"


def test_prerequisites_report_a_missing_llm_key_before_ghidra_runs(
    tmp_path: Path, monkeypatch
) -> None:
    """Four stages call the model. Discovering a missing key after Ghidra has run
    wastes the Ghidra time, which is the whole argument for checking up front."""
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path))
    for var in _all_api_key_envs():
        monkeypatch.delenv(var, raising=False)
    config = _fake_target(tmp_path)
    problems = check_prerequisites(config, build_stages(config))
    assert any("no LLM API key" in p and _api_key_env() in p for p in problems), problems


def test_main_runs_no_stage_when_prerequisites_are_not_met(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """The ordering claim itself: ``main`` must not reach ``run_pipeline`` at all.
    A missing prerequisite found halfway costs whatever already ran."""
    def refuse(*args, **kwargs):
        raise AssertionError("a stage was launched before prerequisites were checked")

    monkeypatch.setattr(pipeline, "run_pipeline", refuse)
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path))
    monkeypatch.setenv(_api_key_env(), "sk-not-a-real-key")

    code = pipeline.main(["--binary", str(tmp_path / "absent.exe"), "--dry-run"])

    out = capsys.readouterr().out
    assert code == 1
    assert "PREREQUISITES NOT MET -- nothing was run" in out
    assert "absent.exe" in out


# --- the honesty claims survive ----------------------------------------


def test_the_snapshot_stage_ingests_and_refuses_to_invent_a_snapshot() -> None:
    """Stage 07 INGESTS. Acquisition is a separate, opt-in stage (07a).

    This used to quote a sentence claiming acquisition was not implemented at all,
    which stopped being true once 07a existed -- pinning the wording would have
    blocked the correction. What still needs defending is the SPLIT: if 07 ever
    starts acquiring, a run with no guest VM fails at a mandatory stage instead of
    asking for a state/ directory it could have been handed.
    """
    stage = _stage_running(_stages(), "prep.snapshot_win")
    assert "ingest" in stage.argv
    assert "acquire" not in stage.argv

    assert "INGEST only" in stage.note
    assert "07a" in stage.note, "the note must say where acquisition lives"

    # Edges 1/6/7 moved with the code. The citation used to live here because this
    # was the only stage that mentioned acquisition; it now belongs on 07a, which is
    # the stage that would make those edges live.
    from orchestrator.pipeline import build_stages

    acquire = {s.key: s for s in build_stages(_config(kd_pipe="p"))}["07a-acquire"]
    assert "NEVER EXERCISED" in acquire.note, (
        "07a has never run: there is no guest VM on this host. Dropping that "
        "sentence makes the pipeline read as though snapshots are a solved step."
    )

    # Asserted on the SUBSTANCE, not on a list of tool names.
    #
    # This used to require "Hyper-V" and "WinDbg/KD" in the note, on the assumption
    # that they were the blockers. They are not: the hypervisor, kd.exe and
    # 0vercl0k/snapshot are all installed and recorded in config/fuzz.yaml, and
    # D-032 -- which recorded Hyper-V as unavailable on this host -- is stale. Pinning
    # tool names made the gate enforce a claim that had stopped being true, which is
    # worse than not checking: it would have blocked the correction (D-057).
    #
    # What must survive is now a DIFFERENT distinction. The commands are no longer
    # merely emitted -- 07a executes kd -- so the surviving claim is that stage 07
    # cannot produce a snapshot on its own and says what is missing.
    assert "guest" in stage.note, "the note must name what acquisition still needs"
    assert "VM" in stage.note

    # The refusal is structural too: it needs files it cannot create.
    assert {p.name for p in stage.needs} == {"mem.dmp", "regs.json"}


def test_codegen_is_wired_for_a_new_target_and_not_for_the_development_one() -> None:
    """EDGE 14, and the reason it resolves differently per target.

    For the development target the generated header is still produced and NOT
    compiled: adopting it renames the test-case JSON keys and invalidates the recorded
    corpus, the crash files and the eval cases (D-055). That is a real cost paid for
    nothing, since the hand-written module already parses that program correctly.

    For any OTHER binary the hand-written module is simply wrong -- it parses
    tlv_server's TLV format -- so leaving edge 14 unwired means the campaign delivers
    a structure the target does not accept, runs, reports coverage and finds nothing.
    "It ran and found nothing" is the worst available outcome because it looks like a
    result. So the generated module is the default there, and the note has to say
    which of the two is in force (D-073).
    """
    # The development target: header only, and the reader is told it is not compiled.
    dev = _stage_running(_stages(), "fuzzer.codegen")
    assert [p.name for p in dev.produces] == ["generated_input.h"]
    assert "NOT compiled" in dev.note
    assert "D-055" in dev.note
    assert "--generated-harness" in dev.note, "the override must be discoverable"

    # A different binary: the generated MODULE, which stage 10 compiles.
    other = _stage_running(_stages(generated_harness=True), "fuzzer.codegen")
    produced = {p.name for p in other.produces}
    assert produced == {"generated_input.h", "fuzzer_gen.cc"}, produced
    assert "--module-out" in other.argv and "--harness" in other.argv
    assert "EDGE 14" in other.note

    # And the module that gets built and run is the generated one, not the hand-written
    # one. This is the link that was missing: fuzzer_gen.cc is already in wtf.exe's
    # link line, so the only thing absent was ever selecting it.
    stages = _stages(generated_harness=True)
    build = _stage_running(stages, "fuzzer.build")
    campaign = _stage_running(stages, "orchestrator.scheduler")
    expected = build.argv[build.argv.index("--expect-target") + 1]
    assert expected.endswith("_gen"), expected
    assert campaign.argv[campaign.argv.index("--module") + 1] == expected, (
        "stage 10 builds one module and stage 11 runs another"
    )


def test_the_coverage_file_stage_admits_bochscpu_ignores_it() -> None:
    """Otherwise a green stage 05 reads as coverage instrumentation being live,
    when on bochscpu the .cov file is not even parsed (D-004/D-036)."""
    stage = _stage_running(_stages(), "prep.bb_to_wtf")
    assert "bochscpu ignores" in stage.note
    assert "pending" in stage.note


def test_the_campaign_stage_says_the_llm_lives_in_a_separate_process() -> None:
    """Section 12.2: the master is on the fast path, so an LLM call inside it
    stalls every worker. The note is where that claim is visible from here."""
    stage = _stage_running(_stages(), "orchestrator.scheduler")
    assert "separate process" in stage.note
    assert stage.calls_llm is True


# --- RULE 1 -------------------------------------------------------------


def test_the_driver_imports_no_llm_client() -> None:
    """RULE 1, and the subprocess argument for why this is not a loophole.

    The driver launches two build-time LLM stages, and a third that starts the
    slow-clock sidecar, with ``subprocess.run`` -- a separate process, its own
    interpreter, its own client, its own latency. Nothing in *this* module can
    block on a model: it holds no client, sends no prompt and reads no key. The
    check is on ``llm.client``/``LlmClient`` specifically rather than on the
    string "llm", following test_cp8.py, because a weakened check is worse than
    none.
    """
    tree = ast.parse(SOURCE)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert node.module != "llm.client", "the driver imports llm.client"
            assert not node.module.startswith("llm."), (
                f"the driver imports {node.module}"
            )
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("llm."), f"the driver imports {alias.name}"

    for forbidden in ("LlmClient", "complete_json(", "chat/completions", "dspy"):
        assert forbidden not in SOURCE, f"the driver references {forbidden!r}"


def test_the_llm_stages_are_launched_as_subprocesses() -> None:
    """The positive half of the argument above: the only way this module reaches
    a model is by starting another process."""
    assert "subprocess.run(resolved" in SOURCE
    for stage in _stages():
        if stage.calls_llm:
            assert stage.argv[0].endswith("python.exe"), stage.argv
            assert stage.argv[1:3] == ["-u", "-m"], (
                f"{stage.key} is not launched as a module in its own interpreter"
            )


def test_every_stage_runs_a_module_that_exists() -> None:
    """A typo'd module name passes every check here and fails at run time, after
    the earlier stages have already spent their Ghidra and campaign time."""
    for stage in _stages():
        module = _module_of(stage)
        path = REPO_ROOT.joinpath(*module.split(".")).with_suffix(".py")
        assert path.exists(), f"{stage.key} runs {module}, which is not a module"


def test_every_stage_marked_calls_llm_really_reaches_the_model() -> None:
    """A decorative flag is worse than none: the ``[LLM]`` marker and the API-key
    prerequisite both hang off it, so a stage wrongly marked makes the key look
    required when it is not."""
    for stage in _stages():
        if not stage.calls_llm:
            continue
        module = _module_of(stage)
        source = REPO_ROOT.joinpath(*module.split(".")).with_suffix(".py").read_text(
            encoding="utf-8"
        )
        assert any(marker in source for marker in LLM_MARKERS), (
            f"{stage.key} is marked calls_llm but {module} contains no LLM call"
        )


def test_no_stage_reaches_the_model_without_declaring_it() -> None:
    """The direction that actually protects the allocation and RULE 1: an
    undeclared LLM stage runs a model with no key check and no ``[LLM]`` label."""
    for stage in _stages():
        if stage.calls_llm:
            continue
        module = _module_of(stage)
        source = REPO_ROOT.joinpath(*module.split(".")).with_suffix(".py").read_text(
            encoding="utf-8"
        )
        found = [marker for marker in LLM_MARKERS if marker in source]
        assert not found, (
            f"{stage.key} runs {module}, which references {found}, but is not "
            f"marked calls_llm"
        )


def test_exactly_the_expected_stages_call_the_model() -> None:
    """Four, all of them either build-time-once-per-target or a supervisor that
    starts the sidecar. Anything else means the model moved into the fast loop."""
    llm_modules = {_module_of(s) for s in _stages() if s.calls_llm}
    assert llm_modules == {
        "prep.entry_select",      # once per target: choose the fuzz entry
        "prep.input_struct",      # once per target: derive the input structure
        "prep.harness_derive",    # once per target: breakpoints and input register
        "orchestrator.scheduler",  # starts the sidecar; the LLM is in that process
        "analysis.triage_run",    # after the campaign, on deduped buckets only
    }


# --- stage 07a: acquisition is opt-in ------------------------------------
#
# The stage needs a guest VM. Adding it unconditionally would fail every run that
# already has a state/ directory -- which is nearly all of them -- so its presence
# is keyed to --kd-pipe. These tests pin BOTH directions, because either mistake is
# quiet: absent when wanted means the pipeline demands a snapshot nobody is going to
# produce, present when unwanted means a mandatory stage that cannot pass.

def test_acquire_stage_absent_without_a_pipe():
    from orchestrator.pipeline import build_stages

    keys = [s.key for s in build_stages(_config())]
    assert "07a-acquire" not in keys
    assert "07-snapshot" in keys


def test_acquire_stage_present_with_a_pipe():
    from orchestrator.pipeline import build_stages

    stages = build_stages(_config(kd_pipe=r"\\.\pipe\snapfuzz"))
    keys = [s.key for s in stages]
    assert "07a-acquire" in keys
    # BEFORE ingest: ingest reads what acquisition writes.
    assert keys.index("07a-acquire") < keys.index("07-snapshot")


def test_acquire_stage_produces_what_ingest_needs():
    """The handoff is the two files. If these drift apart the pipeline reports
    acquisition succeeded and then ingest fails needing something else."""
    from orchestrator.pipeline import build_stages

    stages = {s.key: s for s in build_stages(_config(kd_pipe="p"))}
    assert set(stages["07-snapshot"].needs) <= set(stages["07a-acquire"].produces)


def test_acquire_stage_breaks_on_the_chosen_entry():
    """The breakpoint must carry the module, and must be the entry -- a snapshot
    taken somewhere else loads fine and fuzzes the wrong state (D-057)."""
    from orchestrator.pipeline import build_stages

    stage = {
        s.key: s
        for s in build_stages(_config(kd_pipe="p", entry_symbol="ProcessPacket"))
    }["07a-acquire"]
    argv = stage.argv
    assert argv[argv.index("--module") + 1] == "tlv_server"
    assert argv[argv.index("--break-at") + 1] == "ProcessPacket"


def test_acquire_stage_leaves_a_late_bound_entry_substitutable():
    """The placeholder must be its OWN argument.

    Built as f"{module}!{entry}" it survives resolve_entry untouched and kd gets
    `bp tlv_server!<ENTRY>` -- a breakpoint that never binds, indistinguishable from
    a stimulus that never arrived. This is why resolve_entry now refuses an embedded
    placeholder instead of passing it through.
    """
    stage = {
        s.key: s for s in build_stages(_config(kd_pipe="p", entry_symbol=None))
    }["07a-acquire"]
    assert ENTRY_PLACEHOLDER in stage.argv, stage.argv
    assert not any(
        ENTRY_PLACEHOLDER in part and part != ENTRY_PLACEHOLDER for part in stage.argv
    )


def test_resolve_entry_refuses_an_embedded_placeholder(tmp_path):
    entry = _entry_json(tmp_path / "e.json")
    resolved = resolve_entry(["--break-at", f"mod!{ENTRY_PLACEHOLDER}"], entry)
    assert isinstance(resolved, str), "an embedded placeholder must be an error"
    assert "whole arguments only" in resolved


def test_acquire_stage_waits_for_the_entry_artifact():
    """Acquisition cannot precede entry selection: the breakpoint address IS the
    definition of the state worth taking."""
    from orchestrator.pipeline import build_stages

    stage = {s.key: s for s in build_stages(_config(kd_pipe="p"))}["07a-acquire"]
    assert any("entry" in str(n) for n in stage.needs), stage.needs


def test_acquire_stage_forwards_stimulus_and_wow64():
    from orchestrator.pipeline import build_stages

    stage = {s.key: s for s in build_stages(
        _config(kd_pipe="p", kd_stimulus="python poke.py", wow64=True)
    )}["07a-acquire"]
    assert "--wow64" in stage.argv
    assert stage.argv[stage.argv.index("--stimulus") + 1] == "python poke.py"


def test_acquire_stage_calls_no_llm():
    """RULE 1 -- and the stage sits between two LLM stages, so this is exactly
    where a convenience call would get added."""
    from orchestrator.pipeline import build_stages

    stage = {s.key: s for s in build_stages(_config(kd_pipe="p"))}["07a-acquire"]
    assert stage.calls_llm is False


def test_an_unchanged_artifact_is_only_forgiven_where_a_verify_hook_replaces_it():
    """The byte-identical check is what catches a generator that did not run.

    Exempting a stage from it removes that protection, so an exempt stage must
    carry a `verify` hook checking the property the comparison stood in for.
    Without that rule the exemption is just a way to switch the check off.
    """
    for stage in _stages():
        if stage.output_may_be_unchanged:
            assert stage.verify is not None, (
                f"{stage.key} is exempt from the byte-identical check but has no "
                f"verify hook, so nothing checks its artifact at all"
            )


def test_only_the_incremental_build_is_exempt():
    """Pinned narrowly on purpose. The exemption exists for ONE reason -- Ninja
    relinks nothing when no source changed -- and every other stage here produces
    generated data, where identical output really does mean the tool did not run.

    This is the bug the flag was added for (D-065): stage 10 is deliberately never
    skipped as up-to-date, so it always invokes the build, and the byte comparison
    then failed it on every second run. Two anti-false-success rules cancelling out.
    """
    exempt = {s.key for s in _stages() if s.output_may_be_unchanged}
    assert exempt == {"10-build"}, exempt
