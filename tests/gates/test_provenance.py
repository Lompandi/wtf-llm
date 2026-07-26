"""The up-to-date check must not reuse another target's artifacts (D-073).

Written against a reported failure, and the transcript is the specification:

    --binary .../fuzzing-base-test.exe --target-name fuzzing-snapshot-2
    [1/13] 01-pseudoc  SKIPPED, already produced: artifacts/a2_pseudoc_module.json
    [5/13] 05-covfile  cov file: .../tlv_server.cov  (613 RVAs, name='tlv_server')
                       FAILED: fuzzing-base-test.cov absent

Four stages of a *different program's* analysis were reported as this target's work.
The last two tests here are the ones that matter: the run above stopped only because
stage 05 derived the module name from a different source than the pipeline expected,
and had those two agreed, the campaign would have proceeded on the wrong basic blocks
without an error anywhere. So a test that only pins the filename would pass while the
real defect survived.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from orchestrator.pipeline import Stage, _up_to_date
from orchestrator.provenance import (
    STAMP_NAME,
    TargetIdentity,
    load_stamps,
    record,
    stale_reason,
)


@pytest.fixture
def two_targets(tmp_path: Path) -> tuple[Path, Path, Path]:
    """An artifacts dir plus two distinct target binaries."""
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    first = tmp_path / "tlv_server.exe"
    first.write_bytes(b"MZ first program")
    second = tmp_path / "fuzzing-base-test.exe"
    second.write_bytes(b"MZ a completely different program")
    return artifacts, first, second


def _identity(name: str, binary: Path, scope: str = "module") -> TargetIdentity:
    return TargetIdentity.of(target_name=name, binary=binary, scope=scope)


# --- the reported bug ------------------------------------------------------


def test_another_targets_artifact_is_never_reusable(two_targets) -> None:
    """THE BUG. An artifact stamped for target A must not satisfy target B."""
    artifacts, first, second = two_targets
    export = artifacts / "a3_ghidra_blocks_module.json"
    export.write_text(json.dumps({"module": "tlv_server"}), encoding="utf-8")

    a = _identity("tlv_server", first)
    record(artifacts, a, "04-blocks", [export])

    b = _identity("fuzzing-snapshot-2", second)
    reason = stale_reason(export, b, load_stamps(artifacts), artifacts)
    assert reason is not None, (
        "an artifact produced for tlv_server was accepted for another target -- this "
        "is the D-073 bug: four stages skipped and the wrong program's basic blocks "
        "used for the campaign"
    )
    assert "different binary" in reason and "tlv_server" in reason


def test_the_stage_that_produced_it_is_still_reusable_for_its_own_target(
    two_targets,
) -> None:
    """The fix must not defeat caching -- re-running Ghidra every time is not the goal."""
    artifacts, first, _ = two_targets
    export = artifacts / "a2_pseudoc_module.json"
    export.write_text("{}", encoding="utf-8")

    a = _identity("tlv_server", first)
    record(artifacts, a, "01-pseudoc", [export])
    assert stale_reason(export, a, load_stamps(artifacts), artifacts) is None


def test_an_unstamped_artifact_is_not_evidence(two_targets) -> None:
    """Absent provenance means re-run, never reuse.

    This is the case that actually bit: the artifacts existed from before provenance
    was recorded at all. "I cannot tell whose this is" has to behave like "not mine",
    because the alternative is what shipped.
    """
    artifacts, first, _ = two_targets
    export = artifacts / "fuzz_entry_llm.json"
    export.write_text("{}", encoding="utf-8")
    reason = stale_reason(export, _identity("t", first), {}, artifacts)
    assert reason is not None and "no provenance" in reason


def test_a_rebuilt_binary_invalidates_its_own_artifacts(two_targets) -> None:
    """Same target, same path, different bytes -- A3's offsets are now wrong.

    Not a hypothetical: the offsets move, so the breakpoints land in the wrong place,
    which D-027 describes as silent coverage loss rather than an error.
    """
    artifacts, first, _ = two_targets
    export = artifacts / "a3_ghidra_blocks_module.json"
    export.write_text("{}", encoding="utf-8")
    record(artifacts, _identity("tlv_server", first), "04-blocks", [export])

    first.write_bytes(b"MZ first program, recompiled with another block")
    reason = stale_reason(
        export, _identity("tlv_server", first), load_stamps(artifacts), artifacts
    )
    assert reason is not None and "rebuilt" in reason


def test_scope_still_matters(two_targets) -> None:
    """The scope axis was already guarded by the filename; keep it guarded here too."""
    artifacts, first, _ = two_targets
    export = artifacts / "a3_ghidra_blocks_module.json"
    export.write_text("{}", encoding="utf-8")
    record(artifacts, _identity("tlv_server", first, "module"), "04", [export])
    reason = stale_reason(
        export,
        _identity("tlv_server", first, "function-closure"),
        load_stamps(artifacts),
        artifacts,
    )
    assert reason is not None and "scope" in reason


def test_an_artifact_edited_after_stamping_is_not_covered_by_the_stamp(
    two_targets,
) -> None:
    artifacts, first, _ = two_targets
    export = artifacts / "a2_pseudoc_module.json"
    export.write_text("{}", encoding="utf-8")
    identity = _identity("tlv_server", first)
    record(artifacts, identity, "01", [export])

    import os

    stat = export.stat()
    export.write_text('{"changed": true}', encoding="utf-8")
    os.utime(export, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000))
    assert stale_reason(export, identity, load_stamps(artifacts), artifacts) is not None


def test_stamping_one_target_does_not_erase_the_other(two_targets) -> None:
    """Both targets share the directory, so the record has to accumulate."""
    artifacts, first, second = two_targets
    a_art = artifacts / "a_only.json"
    b_art = artifacts / "b_only.json"
    a_art.write_text("{}", encoding="utf-8")
    b_art.write_text("{}", encoding="utf-8")

    record(artifacts, _identity("tlv_server", first), "01", [a_art])
    record(artifacts, _identity("fuzzing-snapshot-2", second), "01", [b_art])

    stamps = load_stamps(artifacts)
    assert {"a_only.json", "b_only.json"} <= set(stamps)
    assert stamps["a_only.json"].identity.target_name == "tlv_server"
    assert stamps["b_only.json"].identity.target_name == "fuzzing-snapshot-2"


# --- the same question, through the pipeline's own check -------------------


def test_up_to_date_refuses_a_foreign_artifact_and_says_why(two_targets) -> None:
    """End to end on `_up_to_date`, which is what printed "SKIPPED, already produced"."""
    artifacts, first, second = two_targets
    export = artifacts / "a2_pseudoc_module.json"
    export.write_text("{}", encoding="utf-8")
    stage = Stage(key="01-pseudoc", title="A2", argv=[], produces=[export])

    a = _identity("tlv_server", first)
    record(artifacts, a, "01-pseudoc", [export])

    assert _up_to_date(stage, a, load_stamps(artifacts), artifacts)[0] is True

    b = _identity("fuzzing-snapshot-2", second)
    reusable, why_not = _up_to_date(stage, b, load_stamps(artifacts), artifacts)
    assert reusable is False
    assert why_not and "different binary" in why_not, (
        "the pipeline must print WHY it is re-running; 'SKIPPED, already produced' in "
        "front of a target the user has never run is the message that hid this"
    )


def test_a_corrupt_stamp_file_means_re_run_not_a_crash(two_targets) -> None:
    """The safe direction. A truncated cache annotation must not fail the run."""
    artifacts, first, _ = two_targets
    (artifacts / STAMP_NAME).write_text("{not json", encoding="utf-8")
    export = artifacts / "a2_pseudoc_module.json"
    export.write_text("{}", encoding="utf-8")
    assert load_stamps(artifacts) == {}
    stage = Stage(key="01", title="A2", argv=[], produces=[export])
    assert _up_to_date(stage, _identity("t", first), {}, artifacts)[0] is False


# --- why stage 05 was the only thing that noticed -------------------------


def test_the_cov_filename_has_one_source() -> None:
    """The accident that surfaced the bug, pinned so it cannot become a coincidence.

    `prep.bb_to_wtf` named the .cov from the export's own `module`; the pipeline
    expected `<binary stem>.cov`. Two derivations of one fact. They disagreed only
    because the export was stale, and the error blamed the filename.

    Now the pipeline passes `--module`, and bb_to_wtf compares it against the export.
    The point of this test is that the comparison EXISTS -- had the two agreed by
    luck, the wrong basic blocks would have gone to the campaign silently.
    """
    from orchestrator.pipeline import PipelineConfig, build_stages

    config = PipelineConfig(
        target_name="fuzzing-snapshot-2",
        binary=Path(__file__),  # any existing file; only its stem is read
        entry_symbol="Entry",
        state_dir=Path(__file__).parent,
    )
    stage = next(s for s in build_stages(config) if s.key == "05-covfile")
    assert "--module" in stage.argv, (
        "stage 05 does not tell bb_to_wtf which module it is for, so the .cov name is "
        "derived twice from two sources (D-073)"
    )
    expected = stage.argv[stage.argv.index("--module") + 1]
    assert expected == Path(__file__).stem
    cov = next(p for p in stage.produces if p.suffix == ".cov")
    assert cov.stem == expected, (
        f"stage 05 expects {cov.name} but tells bb_to_wtf {expected!r}; these must be "
        f"the same string or the disagreement returns"
    )


def test_bb_to_wtf_refuses_an_export_for_another_module(tmp_path: Path) -> None:
    """The message must name the cause, not the symptom.

    The reported failure said "fuzzing-base-test.cov absent", which sounds like a
    path problem and is actually "these are different programs".
    """
    from prep.bb_to_wtf import main

    export = tmp_path / "a3.json"
    export.write_text(
        json.dumps(
            {
                "module": "tlv_server",
                "image_base": 0x140000000,
                "blocks": [{"static_addr": 0x140001150, "function": "ProcessPacket"}],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "--export", str(export),
                "--coverage-dir", str(tmp_path / "coverage"),
                "--bp-list", str(tmp_path / "bp.json"),
                "--module", "fuzzing-base-test",
            ]
        )
    message = str(exc.value)
    assert "tlv_server" in message and "fuzzing-base-test" in message
    assert "different programs" in message
    assert not (tmp_path / "coverage" / "tlv_server.cov").exists(), (
        "it wrote the other program's .cov anyway"
    )
