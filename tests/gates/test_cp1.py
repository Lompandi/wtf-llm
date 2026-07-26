"""GATE 1 -- wtf builds and a bundled example fuzzes (CLAUDE.md CP1).

CLAUDE.md section 8 states it as:

    wtf builds; a bundled example fuzzes >=60s on `bochscpu` with nonzero coverage;
    corpus and crash output paths identified; `docs/DEVIATIONS.md` records the actual
    CLI, snapshot format, BP-file format, and output layout.

**This file did not exist, and its absence is the reason the project's release state
is CP1.** RULE 3 says "implement each gate as an executable check under
`tests/gates/`". The 150-second run happened and was written up, so the row said PASS
-- resting on a log entry rather than on an assertion, which is the exact substitution
RULE 3 forbids. `tools/gates.py` reported it on its first run, because it asks each
gate for its section 8 conditions instead of asking pytest for an exit code (D-070).

Three modes, because the conditions are not all the same kind of claim:

* **unit** -- the CLI surface and the output layout, checked against the built binary
  and against our own code. No campaign, no artifacts, runs anywhere.
* **evidence** -- a recorded campaign that satisfies ">=60s with nonzero coverage".
  Skips when the artifact is absent, since a clone has no `artifacts/`.
* **live** -- run the campaign now. Behind `SNAPFUZZ_LIVE_CP1=1`, because it takes
  minutes and needs the snapshot.

The write-up condition reads `docs/DEVIATIONS.md`, which is internal and gitignored,
so it goes through `read_internal_doc` and skips on a clone (D-072).
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from tests.gates.conftest import missing_gate_evidence, read_internal_doc

REPO_ROOT = Path(__file__).resolve().parents[2]
WTF_EXE = REPO_ROOT / "src" / "build" / "wtf.exe"
DEV_TARGET = REPO_ROOT / "targets" / "tlv_server"
GATE1 = REPO_ROOT / "artifacts" / "runs" / "gate1"
RESULT = GATE1 / "scheduler_result.json"

# Section 8's own number. Named rather than inlined so the assertion and the message
# cannot drift apart.
MIN_SECONDS = 60

# The three verbs CP1 requires be exercised (CLAUDE.md section 8, CP1 body).
VERBS = ("master", "fuzz", "run")


# --- unit: the CLI surface -------------------------------------------------


def test_wtf_is_built() -> None:
    if not WTF_EXE.exists():
        missing_gate_evidence(
            f"{WTF_EXE} does not exist -- run `python -m fuzzer.build`. GATE 1's first "
            f"clause is that wtf builds, and nothing here can stand in for it."
        )
    assert WTF_EXE.stat().st_size > 1_000_000, (
        "wtf.exe is implausibly small; a truncated link produces a binary that exists "
        "and does nothing"
    )


def test_wtf_offers_the_three_verbs_cp1_requires() -> None:
    """`master`, `fuzz` and `run`, read out of the binary rather than assumed.

    Everything downstream is built on these three and their flags. Asserted against
    `--help` because a wtf revision that renamed one would otherwise surface as a
    campaign that silently does nothing.
    """
    if not WTF_EXE.exists():
        missing_gate_evidence(f"{WTF_EXE} does not exist")
    proc = subprocess.run(
        [str(WTF_EXE), "--help"], capture_output=True, text=True, timeout=60
    )
    text = proc.stdout + proc.stderr
    for verb in VERBS:
        assert verb in text, f"wtf --help does not mention the {verb!r} subcommand"


def test_the_bundled_examples_are_registered_in_the_binary() -> None:
    """CP1 fuzzes a BUNDLED example, so the binary has to contain one.

    Asked of the binary via its own registry rather than inferred from the source
    tree: a stale wtf.exe runs the old module and looks completely healthy, which is
    the failure `fuzzer/build.py` documents.
    """
    if not WTF_EXE.exists() or not (DEV_TARGET / "state").is_dir():
        missing_gate_evidence("needs wtf.exe and a target tree to list the registry")
    from fuzzer.build import registered_targets

    targets = registered_targets(DEV_TARGET)
    assert targets, "wtf listed no registered targets at all"
    assert "tlv_server" in targets, (
        f"the CP1-mandated bundled example is not registered; have {sorted(targets)}"
    )


def test_the_output_layout_is_identified_in_code() -> None:
    """"corpus and crash output paths identified" -- as code, not as prose.

    A gate condition satisfied only by a sentence in a document is not re-checkable,
    which is this file's whole subject.
    """
    from fuzzer.run import Corpus

    corpus = Corpus(DEV_TARGET)
    assert corpus.inputs == DEV_TARGET / "inputs"
    assert corpus.outputs == DEV_TARGET / "outputs"
    assert corpus.crashes == DEV_TARGET / "crashes"
    # And the coverage directory, which is the fourth path wtf reads.
    assert corpus.coverage == DEV_TARGET / "coverage"


def test_the_bp_file_format_is_pinned_by_a_parser() -> None:
    """The .cov format, enforced rather than described.

    wtf iterates a directory and takes only files ending in `.cov`, reads `name`
    unguarded, and computes `GetModuleBase(name) + rva`. A file that is wrong in any
    of those ways is skipped or misplaced SILENTLY, so the parser refuses instead.
    """
    from prep.bb_to_wtf import CovFileError, validate_cov_file

    import tempfile

    tmp = Path(tempfile.mkdtemp())
    # An extension in `name` makes GetModuleBase return 0 -- the whole load fails.
    bad = tmp / "x.cov"
    bad.write_text(json.dumps({"name": "tlv_server.exe", "addresses": [1]}), "utf-8")
    with pytest.raises(CovFileError):
        validate_cov_file(bad)

    # A name wtf will never look at, because it does not end in .cov.
    wrong_suffix = tmp / "x.json"
    wrong_suffix.write_text(json.dumps({"name": "t", "addresses": [1]}), "utf-8")
    with pytest.raises(CovFileError):
        validate_cov_file(wrong_suffix)

    good = tmp / "tlv_server.cov"
    good.write_text(json.dumps({"name": "tlv_server", "addresses": [0x1150]}), "utf-8")
    parsed = validate_cov_file(good, expect_name="tlv_server")
    assert parsed.name == "tlv_server" and len(parsed) == 1


# --- evidence: the recorded campaign --------------------------------------


def _recorded() -> dict:
    if not RESULT.exists():
        missing_gate_evidence(
            f"{RESULT} does not exist. Produce it with "
            f"`python -m orchestrator.scheduler --label gate1 --workers 1 "
            f"--minutes 1.5 --target-dir targets/tlv_server "
            f"--a1 artifacts/tlv_server/a1_snapshot.json --module snapfuzz --no-sidecar`"
        )
    return json.loads(RESULT.read_text(encoding="utf-8"))


def test_the_recorded_campaign_ran_long_enough() -> None:
    recorded = _recorded()
    duration = recorded.get("duration_s", 0)
    assert duration >= MIN_SECONDS, (
        f"the recorded campaign ran {duration:.0f}s; section 8 requires >={MIN_SECONDS}s"
    )


def test_the_recorded_campaign_produced_nonzero_growing_coverage() -> None:
    """"nonzero coverage" -- and growth, which is the part that means it worked.

    Measured as new-coverage events rather than the master's `cov:` line, because wtf
    block-buffers stdout and does not flush, so a healthy run can leave a 0-byte log
    (D-033). The master writes a file into outputs/ exactly when a test-case produced
    new coverage, and a file appearing on disk is not buffered.
    """
    recorded = _recorded()
    events = recorded.get("new_coverage_events", 0)
    before = recorded.get("outputs_before", 0)
    after = recorded.get("outputs_after", 0)
    assert events > 0, (
        f"the recorded campaign produced no new coverage ({before} -> {after} "
        f"outputs). Zero here is what every worker dying in Init looks like "
        f"(D-023, D-042)"
    )
    assert after > before, f"outputs/ did not grow: {before} -> {after}"


def test_the_recorded_campaign_used_bochscpu() -> None:
    """Section 8 names the backend. bochscpu is the only fully deterministic one
    (section 13.5), which is why the de-risking run uses it."""
    metadata = GATE1 / "run_metadata.json"
    if not metadata.exists():
        missing_gate_evidence(f"{metadata} does not exist")
    payload = json.loads(metadata.read_text(encoding="utf-8"))
    backend = json.dumps(payload).lower()
    assert "bochscpu" in backend, f"{metadata.name} does not record a bochscpu run"


# --- the write-up condition ----------------------------------------------


def test_deviations_records_what_cp1_was_for() -> None:
    """Section 8's last clause: the CLI, snapshot format, BP-file format and output
    layout are written down.

    CP1's stated purpose is to learn those before any of our code exists, so the
    record IS the deliverable. Internal document, so this skips on a clone (D-072).
    """
    text = read_internal_doc(REPO_ROOT / "docs" / "DEVIATIONS.md")
    for subject, needle in (
        ("the CLI verbs", "master"),
        ("the snapshot layout", "mem.dmp"),
        ("the BP-file format", ".cov"),
        ("the output layout", "crashes/"),
    ):
        assert needle in text, f"DEVIATIONS.md does not record {subject}"


# --- live ---------------------------------------------------------------


@pytest.mark.live
@pytest.mark.campaign
def test_a_live_campaign_meets_the_gate(tmp_path: Path) -> None:
    """Run it now rather than trusting the recording. Minutes, so opt-in."""
    if os.environ.get("SNAPFUZZ_LIVE_CP1") != "1":
        pytest.skip("set SNAPFUZZ_LIVE_CP1=1 to run a live >=60s campaign")

    label = "gate1-live"
    proc = subprocess.run(
        [
            str(REPO_ROOT / ".venv" / "Scripts" / "python.exe"), "-u",
            "-m", "orchestrator.scheduler",
            "--label", label,
            "--workers", "1",
            "--minutes", "1.5",
            "--target-dir", str(DEV_TARGET),
            "--a1", str(REPO_ROOT / "artifacts" / "tlv_server" / "a1_snapshot.json"),
            "--module", "snapfuzz",
            "--no-sidecar",
        ],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=600,
    )
    assert proc.returncode == 0, proc.stdout[-3000:] + proc.stderr[-2000:]

    result = json.loads(
        (REPO_ROOT / "artifacts" / "runs" / label / "scheduler_result.json")
        .read_text(encoding="utf-8")
    )
    assert result["duration_s"] >= MIN_SECONDS
    assert result["new_coverage_events"] > 0
