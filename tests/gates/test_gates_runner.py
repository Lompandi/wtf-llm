"""The gate runner, the evidence manifest, and the two places they can drift.

`tools/gates.py` now decides whether every checkpoint passed, and `tools/evidence.py`
decides whether the artifacts behind those decisions are still there. Both shipped
with no tests at all -- the thing that judges the gates was itself ungated, which is
the same substitution RULE 3 forbids one level up.

Two of the tests here are drift checks rather than unit tests, and they matter more:

* **PROGRESS.md's table was hand-copied from the runner's output.** That recreates
  exactly what the runner existed to remove -- two sources of truth for the same
  fact, one of which goes stale silently. It is the D-050 shape (a value recorded in
  a place no consumer reads) and the D-070 shape (a label that outlived what it
  described) at once.
* **CLAUDE.md section 6 and `arch/contracts.py` were hand-synced too.** The spec is
  where field names are specified; a rename in one and not the other is how
  `total_edges` came to disagree with its own comment.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from tests.gates.conftest import read_internal_doc
from tools.gates import GATE_ORDER, GATES, Condition, _evaluate, run_gates

REPO_ROOT = Path(__file__).resolve().parents[2]
PROGRESS = REPO_ROOT / "docs" / "PROGRESS.md"
CLAUDE_MD = REPO_ROOT / "CLAUDE.md"


# --- the runner's own judgement -------------------------------------------


def test_a_skipped_condition_is_incomplete_not_proven() -> None:
    """The whole reason this runner exists. GATE 7's coverage criterion was a
    `pytest.skip`, so `pytest tests/gates` exited 0 while the one thing that gate
    asks for was unmet (D-067)."""
    result = _evaluate(
        Condition("coverage increases after injection", ("test_it",)),
        {"tests/gates/test_cp7.py::test_it": "skipped"},
        {"tests/gates/test_cp7.py::test_it": "no evidence recorded"},
    )
    assert result["status"] == "incomplete"
    assert "skipped" in result["detail"]
    # And the reason travels with it, or the report says "incomplete" without
    # saying why -- which is what a bare skip count already did.
    assert "no evidence recorded" in result["detail"]


def test_a_condition_whose_test_vanished_is_incomplete() -> None:
    """A renamed or deleted test must not silently stop proving its clause while
    the gate stays green -- the D-057 shape."""
    result = _evaluate(
        Condition("something", ("test_that_no_longer_exists",)),
        {"tests/gates/test_cp4.py::test_something_else": "passed"},
        {},
    )
    assert result["status"] == "incomplete"
    assert "no test matched" in result["detail"]


def test_a_failing_test_beats_a_passing_one_in_the_same_condition() -> None:
    """Several tests can back one clause. One of them failing means the clause is
    not proven, however many others passed."""
    result = _evaluate(
        Condition("x", ("test_a", "test_b")),
        {"f.py::test_a": "passed", "f.py::test_b": "failed"},
        {},
    )
    assert result["status"] == "failed"
    assert "test_b" in result["detail"]


def test_a_condition_with_no_named_test_can_never_be_proven() -> None:
    """Conditions that cannot be shown on this host -- acquisition needs a guest
    VM, edge 14 needs the corpus migration -- stay visible and stay unproven.
    Being unprovable here is not the same as being proven."""
    result = _evaluate(
        Condition("acquisition runs", (), needs="a Hyper-V guest"),
        {"f.py::test_anything": "passed"},
        {},
    )
    assert result["status"] == "incomplete"
    assert "Hyper-V" in result["detail"]


def test_every_gate_declares_at_least_one_condition() -> None:
    """A gate with no conditions is reported incomplete rather than passed, but it
    should not exist in the first place: RULE 3 says a gate names the assertions
    that must pass, so a gate naming none is a spec hole, not a passing gate."""
    for spec in GATES:
        assert spec.conditions, f"gate {spec.checkpoint} declares no conditions"


def test_gate_conditions_name_tests_that_exist() -> None:
    """Every substring a condition names must match a real test somewhere.

    Without this the runner reports "no test matched" at run time and nobody sees
    it until they run the gates -- and the mapping was written by hand against the
    test files, so a typo is the expected failure. This caught six of mine.
    """
    all_tests = "\n".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in (REPO_ROOT / "tests" / "gates").glob("test_*.py")
    )
    for spec in GATES:
        for condition in spec.conditions:
            for needle in condition.tests:
                assert f"def {needle}" in all_tests, (
                    f"gate {spec.checkpoint} names {needle!r}, which is not a test "
                    f"function anywhere under tests/gates/"
                )


def test_blocked_at_is_the_earliest_gate_that_does_not_pass() -> None:
    """RULE 3: "do not start checkpoint N+1 until checkpoint N's gate passes."

    The release state is the FIRST failure, not the best row -- which is the
    property the old table lost by marking CP8..CP12 as PASS with CP7 partial.
    """
    report = run_gates(["cp0"])
    assert report["blocked_at"] in (None, "cp0")
    assert "provenance" in report
    # Tied to a tree state, or the result says conditions were proven but not of
    # what.
    assert "commit" in report["provenance"]


def test_gate_order_is_checkpoint_order() -> None:
    """`--through cp7` has to mean cp0..cp7. A misordered list would silently run
    a different set."""
    assert GATE_ORDER[0] == "cp0"
    assert GATE_ORDER.index("cp4") < GATE_ORDER.index("cp4b") < GATE_ORDER.index("cp5")
    assert GATE_ORDER.index("cp7") < GATE_ORDER.index("cp8")


# --- drift: PROGRESS.md vs the runner --------------------------------------


def _gate_rows() -> dict[str, tuple[str, str]]:
    """{gate: (status, note)} from PROGRESS.md's gate table only."""
    head, _, _ = read_internal_doc(PROGRESS).partition("## Edges")
    rows = re.findall(
        r"^\|\s*(\d+b?)\s*\|([^|]*)\|\s*\*{0,2}(\w+)\*{0,2}\s*\|[^|]*\|([^|]*)\|",
        head,
        re.M,
    )
    return {gate: (status.upper(), note) for gate, _, status, note in rows}


def test_every_gate_in_the_runner_has_a_progress_row() -> None:
    """The two lists have to describe the same set of gates.

    They were synced by hand, so a gate added to one and not the other is the
    expected drift -- and it fails toward silence: a gate with no row simply is
    not reported to anyone reading the table.
    """
    rows = _gate_rows()
    for spec in GATES:
        number = spec.checkpoint.removeprefix("cp")
        assert number in rows, (
            f"tools/gates.py declares {spec.checkpoint} but PROGRESS.md's gate "
            f"table has no row for it (rows: {sorted(rows)})"
        )


def test_every_progress_row_has_a_gate_in_the_runner() -> None:
    """And the other direction: a row for a gate the runner does not know about
    cannot be verified by anything."""
    known = {spec.checkpoint.removeprefix("cp") for spec in GATES}
    for gate in _gate_rows():
        assert gate in known, (
            f"PROGRESS.md has a row for gate {gate}, which tools/gates.py does not "
            f"declare -- nothing can verify it"
        )


def test_a_gate_with_a_known_unprovable_condition_is_not_marked_pass() -> None:
    """The drift check that matters.

    A condition carrying `needs` cannot be proven on this host by construction --
    acquisition needs a guest VM, edge 14 needs the corpus migration, the live
    tests need a key. A gate holding one of those can never legitimately be PASS,
    and this is what would catch the table sliding back to green without the work
    (D-070). It is static: no gates are run, so it holds even in CI with no
    artifacts.
    """
    rows = _gate_rows()
    for spec in GATES:
        unprovable = [c for c in spec.conditions if c.needs]
        if not unprovable:
            continue
        number = spec.checkpoint.removeprefix("cp")
        status, _ = rows[number]
        assert status != "PASS", (
            f"gate {spec.checkpoint} is PASS in PROGRESS.md, but it has "
            f"{len(unprovable)} condition(s) that cannot be proven on this host: "
            f"{[c.needs for c in unprovable]}"
        )


# --- drift: CLAUDE.md section 6 vs arch/contracts.py ----------------------


@pytest.mark.parametrize(
    "model_name",
    ["CoverageSummary", "CrashRecord", "SnapshotRef", "FuzzEntry", "TriageVerdict"],
)
def test_the_spec_and_the_contract_declare_the_same_fields(model_name: str) -> None:
    """Section 6 is where the field names are specified. A rename in the code and
    not the spec is how `total_edges: int  # BPs hit` came to disagree with itself
    inside one line (D-068).

    Compared by NAME only, not by type: section 6 writes types as prose in places
    (`Literal[...] | None`), and parsing those would test the parser.
    """
    import arch.contracts as contracts

    model = getattr(contracts, model_name)
    actual = set(model.model_fields)

    text = read_internal_doc(CLAUDE_MD)
    match = re.search(rf"^class {model_name}\(BaseModel\):\n(.*?)(?=\n\nclass |\n```)",
                      text, re.M | re.S)
    assert match, f"CLAUDE.md section 6 has no `class {model_name}(BaseModel)` block"

    # `name: type` at one indent level, skipping comments and continuations.
    specified = {
        m.group(1)
        for line in match.group(1).splitlines()
        if (m := re.match(r"^    ([a-z_][a-z0-9_]*)\s*:", line))
    }
    assert specified, f"no fields parsed out of section 6's {model_name}"

    missing = specified - actual
    assert not missing, (
        f"CLAUDE.md section 6 specifies {sorted(missing)} on {model_name}, but "
        f"arch/contracts.py does not declare them -- the spec and the code have "
        f"drifted"
    )


def test_the_spec_no_longer_names_the_renamed_coverage_fields() -> None:
    """The specific drift D-068 was: the spec kept `total_edges` after the code
    stopped using it. Aliases keep old ARTIFACTS loading, which is deliberate --
    but the spec must describe the current field."""
    text = read_internal_doc(CLAUDE_MD)
    section6 = text[text.index("## 6. Data contracts") : text.index("## 7.")]
    assert "coverage_units" in section6
    # `total_edges` may appear in prose explaining the rename, but not as a
    # declared field.
    assert not re.search(r"^    total_edges\s*:", section6, re.M), (
        "CLAUDE.md section 6 still declares `total_edges` as a field"
    )


# --- the evidence manifest ------------------------------------------------


def test_the_manifest_is_tracked_and_the_large_files_are_not() -> None:
    """The whole point of D-069's fix: hashes in git, 1.8 GB out of git."""
    import subprocess

    from tools.evidence import EVIDENCE, MANIFEST

    assert MANIFEST.exists(), "run `python -m tools.evidence record`"
    tracked = subprocess.run(
        ["git", "ls-files", str(MANIFEST.relative_to(REPO_ROOT)).replace("\\", "/")],
        cwd=REPO_ROOT, capture_output=True, text=True,
    ).stdout.strip()
    assert tracked, f"{MANIFEST} is not tracked, so the hashes ship with nothing"

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["entries"], "the manifest lists no artifacts"
    assert len(manifest["entries"]) == len(EVIDENCE)


def test_every_recorded_artifact_says_how_to_regenerate_it() -> None:
    """"Missing" and "missing, and here is what produces it" are different
    messages, and only the second one lets somebody else close the gap."""
    from tools.evidence import EVIDENCE

    for item in EVIDENCE:
        assert item.regenerate.strip(), f"{item.path} records no regeneration command"
        assert item.proves.strip(), f"{item.path} does not say what it proves"
        assert item.gate, f"{item.path} names no gate"


def test_a_changed_artifact_is_reported_as_drift(tmp_path: Path) -> None:
    """Drift is the case that matters: a file that still exists but hashes
    differently means a recorded result describes bytes that are gone."""
    from tools.evidence import verify_manifest

    artifact = tmp_path / "evidence.json"
    artifact.write_text("original", encoding="utf-8")
    manifest = {
        "entries": [
            {
                "path": "evidence.json",
                "present": True,
                "sha256": __import__("hashlib").sha256(b"original").hexdigest(),
            }
        ]
    }
    assert verify_manifest(manifest, tmp_path) == ([], [])

    artifact.write_text("tampered", encoding="utf-8")
    drifted, absent = verify_manifest(manifest, tmp_path)
    assert drifted == ["evidence.json"]
    assert absent == []


def test_an_artifact_that_was_present_and_vanished_says_so(tmp_path: Path) -> None:
    """Distinguished from never having been there: one means the evidence was
    deleted under a recorded result, the other is a fresh clone."""
    from tools.evidence import verify_manifest

    manifest = {"entries": [{"path": "gone.json", "present": True, "sha256": "x" * 64}]}
    _, absent = verify_manifest(manifest, tmp_path)
    assert absent == ["gone.json (was present when recorded)"]


def test_every_partial_gate_declares_what_it_needs() -> None:
    """The other half of the drift check above.

    That test says "a gate with a `needs` condition must not be PASS". This one
    says "a gate that is PARTIAL must have a `needs` condition" -- otherwise a
    gate could be PARTIAL for a reason the runner cannot see, and the static check
    would have nothing to hold it to. Together they tie the table to the runner in
    both directions.
    """
    rows = _gate_rows()
    for spec in GATES:
        number = spec.checkpoint.removeprefix("cp")
        status, note = rows[number]
        if status != "PARTIAL":
            continue
        assert any(c.needs for c in spec.conditions), (
            f"gate {spec.checkpoint} is PARTIAL in PROGRESS.md but every condition "
            f"in tools/gates.py claims to be provable here. Either the row is "
            f"stale or a condition is missing its `needs`. Row says: {note[:120]}"
        )
