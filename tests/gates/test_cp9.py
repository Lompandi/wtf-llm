"""GATE 9 -- DSPy multi-signal triage and the GHSA report (CP9, edges 38-43).

GATE 9 requires:

* triage consumes all five signals and ``signals_used`` reflects that;
* verdicts validate against ``TriageVerdict``;
* precision and recall reported on the **held-out** planted-bug split;
* the GHSA report renders with confirmed findings only;
* discards logged separately.

Live LLM tests are gated behind ``SNAPFUZZ_LIVE_LLM=1``; everything else runs
offline against recorded evidence, and skips with a message naming what is
missing.
"""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path

import pytest

from analysis.classify import Classification
from analysis.report import SEVERITY_ORDER, Finding, render_report, write_report
from analysis.reverse import CrashContext
from analysis.triage import (
    SignalBundle,
    TriageProgram,
    render_signals,
    triage_metric,
)
from arch.contracts import (
    TRIAGE_SIGNALS,
    CrashBucket,
    CrashRecord,
    ReplayResult,
    TraceRef,
    TriageVerdict,
)
from eval.cases import assigned_split, load_cases, split_cases

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE9 = REPO_ROOT / "artifacts" / "runs" / "gate9"
CASES_DIR = REPO_ROOT / "eval" / "planted_bugs"

live_llm = pytest.mark.skipif(
    os.environ.get("SNAPFUZZ_LIVE_LLM") != "1",
    reason="set SNAPFUZZ_LIVE_LLM=1 to spend allocation on live triage",
)


def _bundle(*, with_trace: bool = True, with_context: bool = True) -> SignalBundle:
    record = CrashRecord(
        input_bytes=b'{"Packets":[{"BodySize":8,"Body":[]}]}',
        fault_type="access-violation-read",
        fault_runtime_addr=0x7FF8_AA38_1378,
        fault_static_addr=0,
        registers={},
        backtrace=[],
        coverage_delta=0,
        backend="bochscpu",
        timestamp=1.0,
    )
    bucket = CrashBucket(
        bucket_id="b1",
        representative=record,
        hit_count=47,
        key_kind="fault_function",
        key_detail="access-violation-read|VCRUNTIME140.dll!memmove",
    )
    return SignalBundle(
        bucket=bucket,
        classification=Classification(
            bucket_id="b1", fault_type=record.fault_type, access="read"
        ),
        replay=ReplayResult(
            bucket_id="b1",
            reproduced=True,
            deterministic=True,
            replays=3,
            backend="bochscpu",
            notes="faulted at 0x7ff8aa381378 on 3/3 run(s)",
        ),
        trace=TraceRef(
            bucket_id="b1",
            trace_type="rip",
            raw_path="r",
            symbolized_path="s",
            reached_fuzz_entry=True,
        )
        if with_trace
        else None,
        context=CrashContext(bucket_id="b1", function="ProcessPacket", pseudo_c="void f(){}")
        if with_context
        else None,
        reproducer_path="crashes/x",
    )


def _verdict(**kw) -> TriageVerdict:
    base = dict(
        bucket_id="b1",
        verdict="confirmed",
        confidence=0.9,
        cwe_guess="CWE-125",
        exploitability="info_leak",
        root_cause="unvalidated length",
        signals_used=list(TRIAGE_SIGNALS),
        reproducer_input_path="crashes/x",
    )
    base.update(kw)
    return TriageVerdict(**base)


# --- the five signals stay five ------------------------------------------


def test_all_five_signals_are_rendered_as_separate_fields() -> None:
    """Section 10 forbids collapsing them into one blob.

    Signals 4 and 5 are dynamic and static respectively; their errors are
    uncorrelated, and that independence is the whole design (edges 41/41b).
    """
    rendered = render_signals(_bundle())
    assert set(rendered) == set(TRIAGE_SIGNALS)
    assert all(text.strip() for text in rendered.values())


def test_the_dspy_signature_takes_one_input_field_per_signal() -> None:
    """Guards against a refactor that merges the fields."""
    dspy = pytest.importorskip("dspy")
    from analysis.triage import _build_signature

    signature = _build_signature()
    inputs = {
        name
        for name, field in signature.model_fields.items()
        if field.json_schema_extra
        and field.json_schema_extra.get("__dspy_field_type") == "input"
    }
    assert inputs == set(TRIAGE_SIGNALS)


def test_a_missing_signal_is_stated_not_omitted() -> None:
    """A prompt that silently drops signal 4 invites reasoning as though the
    dynamic evidence agreed with the static evidence."""
    rendered = render_signals(_bundle(with_trace=False))
    assert "NOT AVAILABLE" in rendered["symbolize_trace"]
    assert "do not infer" in rendered["symbolize_trace"].lower()

    rendered = render_signals(_bundle(with_context=False))
    assert "NOT AVAILABLE" in rendered["reverse_engineer"]


def test_the_bundle_reports_which_signals_are_missing() -> None:
    bundle = _bundle(with_trace=False, with_context=False)
    assert bundle.missing == ["symbolize_trace", "reverse_engineer"]
    assert bundle.available == ["dedup", "classification", "replay"]


def test_the_prompt_states_that_the_dedup_rung_changes_what_hit_count_means() -> None:
    """A coarse bucket's hit count may aggregate unrelated bugs."""
    rendered = render_signals(_bundle())
    assert "fault_function" in rendered["dedup"]
    assert "merged unrelated bugs" in rendered["dedup"]


def test_the_prompt_says_pseudo_c_is_not_source() -> None:
    rendered = render_signals(_bundle())
    assert "not source" in rendered["reverse_engineer"].lower()


def test_the_prompt_qualifies_a_non_deterministic_backend() -> None:
    bundle = _bundle()
    bundle.replay = ReplayResult(
        bucket_id="b1",
        reproduced=True,
        deterministic=False,
        replays=3,
        backend="kvm",
        notes="re-check on bochscpu before drawing any conclusion",
    )
    assert "NOT deterministic by default" in render_signals(bundle)["replay"]


# --- verdict coercion -----------------------------------------------------


class _Prediction:
    def __init__(self, **kw):
        for key, value in kw.items():
            setattr(self, key, value)


def test_an_unparseable_verdict_becomes_a_false_positive() -> None:
    """Over-reporting wastes a human's time; a model that could not answer has
    not made a case."""
    verdict = TriageProgram.to_verdict(
        _Prediction(verdict="maybe?", confidence="high"), _bundle()
    )
    assert verdict.verdict == "false_positive"
    assert verdict.confidence == 0.0


def test_an_out_of_range_exploitability_becomes_unknown_not_a_severity() -> None:
    verdict = TriageProgram.to_verdict(
        _Prediction(verdict="confirmed", exploitability="catastrophic"), _bundle()
    )
    assert verdict.exploitability == "unknown"


def test_confidence_is_clamped_to_the_unit_interval() -> None:
    high = TriageProgram.to_verdict(
        _Prediction(verdict="confirmed", confidence=42.0), _bundle()
    )
    assert high.confidence == 1.0


def test_a_signal_the_model_did_not_have_is_not_credited() -> None:
    """Otherwise signals_used is unfalsifiable: a model could claim to have used
    the trace when no trace existed, and GATE 9 checks that field."""
    verdict = TriageProgram.to_verdict(
        _Prediction(
            verdict="confirmed",
            signals_used="dedup, classification, replay, symbolize_trace, reverse_engineer",
        ),
        _bundle(with_trace=False),
    )
    assert "symbolize_trace" not in verdict.signals_used
    assert "dedup" in verdict.signals_used


def test_the_metric_puts_the_verdict_first() -> None:
    """A correct verdict with a wrong CWE beats the reverse."""
    example = _Prediction(
        label="confirmed", expected_cwe="CWE-125", expected_exploitability="info_leak"
    )
    right_verdict_wrong_extras = triage_metric(
        example, _Prediction(verdict="confirmed", cwe_guess="CWE-999", exploitability="dos")
    )
    wrong_verdict = triage_metric(
        example,
        _Prediction(verdict="false_positive", cwe_guess="CWE-125", exploitability="info_leak"),
    )
    assert right_verdict_wrong_extras >= 0.7
    assert wrong_verdict == 0.0


# --- the labelled set and the split --------------------------------------


def test_the_case_set_exists_and_carries_ground_truth_rationales() -> None:
    cases = load_cases()
    assert cases, f"no cases in {CASES_DIR}; run python -m eval.build_cases"
    for case in cases:
        assert case.label_rationale.strip(), f"{case.case_id} has no rationale"
        assert len(case.label_rationale) > 80, (
            f"{case.case_id}'s rationale is too short to be checkable"
        )


def test_both_labels_are_present_in_both_splits() -> None:
    """A split with one label on either side makes precision or recall
    undefined, and a metric that cannot fail is not a metric."""
    train, heldout = split_cases(load_cases())
    assert train and heldout
    assert {c.label for c in train} == {"confirmed", "false_positive"}
    assert {c.label for c in heldout} == {"confirmed", "false_positive"}


def test_the_split_is_deterministic_and_independent_per_case() -> None:
    """A seeded shuffle depends on the SET, so adding a case would silently move
    others across the boundary between an optimisation run and a reporting run."""
    assert assigned_split("measured-01-read") == assigned_split("measured-01-read")
    before = {c.case_id: assigned_split(c.case_id) for c in load_cases()}
    after = {c.case_id: assigned_split(c.case_id) for c in load_cases()}
    assert before == after


def test_no_case_is_in_both_splits() -> None:
    train, heldout = split_cases(load_cases())
    assert not ({c.case_id for c in train} & {c.case_id for c in heldout})


def test_synthetic_cases_are_labelled_as_synthetic() -> None:
    """The weakness has to be visible in the data, not only in a docstring."""
    cases = load_cases()
    assert any(c.origin == "synthetic" for c in cases)
    assert any(c.origin == "measured" for c in cases)
    for case in cases:
        if case.origin == "synthetic":
            assert case.label == "false_positive"


def test_a_case_cannot_mix_signals_from_different_crashes() -> None:
    from eval.cases import TriageCase

    case = load_cases()[0]
    payload = json.loads(case.model_dump_json())
    payload["replay"]["bucket_id"] = "some-other-bucket"
    with pytest.raises(ValueError, match="signals must not be mixed"):
        TriageCase.model_validate(payload)


# --- the report -----------------------------------------------------------


def test_only_confirmed_findings_reach_the_report() -> None:
    """Edges 42/43: confirmed ships, false_positive is discarded."""
    finding = Finding(verdict=_verdict(verdict="false_positive"), bucket=_bundle().bucket)
    with pytest.raises(ValueError, match="only confirmed findings ship"):
        render_report([finding], target="t", module="m", entry="e")


def test_discards_are_logged_separately_and_kept(tmp_path: Path) -> None:
    """Section 9: kept for evaluation, not shipped. Deleting them would make a
    triage regression invisible."""
    bundle = _bundle()
    report_path, discard_path = write_report(
        [_verdict(), _verdict(bucket_id="b1", verdict="false_positive", confidence=0.1)],
        buckets={"b1": bundle.bucket},
        out_dir=tmp_path,
        target="tlv_server.exe",
        module="snapfuzz",
        entry="ProcessPacket",
    )
    assert report_path.exists() and discard_path.exists()
    lines = [l for l in discard_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 1
    assert json.loads(lines[0])["verdict"] == "false_positive"


def test_the_report_carries_the_oracle_limits() -> None:
    """A GHSA advisory implying more certainty than a binary-only oracle can
    provide is the kind of thing that gets a report dismissed wholesale."""
    bundle = _bundle()
    text = render_report(
        [Finding(verdict=_verdict(), bucket=bundle.bucket, replay=bundle.replay)],
        target="tlv_server.exe",
        module="snapfuzz",
        entry="ProcessPacket",
    )
    assert "no sanitizer" in text.lower()
    assert "not detected" in text.lower()
    assert "decompiler output, not source" in text.lower()
    assert "bochscpu" in text


def test_findings_are_ordered_worst_first() -> None:
    bundle = _bundle()
    text = render_report(
        [
            Finding(verdict=_verdict(bucket_id="b1", exploitability="dos"), bucket=bundle.bucket),
            Finding(
                verdict=_verdict(bucket_id="b1", exploitability="possible_rce"),
                bucket=bundle.bucket,
            ),
        ],
        target="t",
        module="m",
        entry="e",
    )
    assert text.index("possible_rce") < text.index("**dos**")
    assert SEVERITY_ORDER[0] == "possible_rce"


def test_a_pipe_in_a_dedup_key_does_not_break_the_table() -> None:
    """Dedup keys contain a literal `|`. Unescaped it splits the cell and shifts
    every column after it, misattributing a severity."""
    bundle = _bundle()
    text = render_report(
        [Finding(verdict=_verdict(), bucket=bundle.bucket)],
        target="t",
        module="m",
        entry="e",
    )
    rule_line = next(l for l in text.splitlines() if "Bucketing rule" in l)
    assert "\\|" in rule_line, "the dedup key's pipe was not escaped"
    # Count only STRUCTURAL pipes: an escaped one still contains the character,
    # so it has to be removed before counting or the check contradicts itself.
    structural = rule_line.replace("\\|", "")
    assert structural.count("|") == 3, (
        f"table cell split by an unescaped pipe: {rule_line}"
    )


def test_the_report_is_not_generated_by_an_llm() -> None:
    """Section 9: ordinary code assembles the report. An LLM here would add a
    second place for facts to drift from the evidence."""
    source = (REPO_ROOT / "analysis" / "report.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert not node.module.startswith("llm."), "report.py must not call the LLM"
    assert "LlmClient" not in source
    assert "dspy" not in source


# --- recorded evidence ----------------------------------------------------


def _recorded(name: str):
    path = GATE9 / name
    if not path.exists():
        pytest.skip(
            f"{path.relative_to(REPO_ROOT)} has not been produced. Run: "
            f"python -m analysis.triage_run --evidence artifacts/runs/gate8 "
            f"--label gate9"
        )
    return path


def test_recorded_verdicts_validate_against_the_contract() -> None:
    payload = json.loads(_recorded("verdicts.json").read_text(encoding="utf-8"))
    verdicts = [TriageVerdict.model_validate(v) for v in payload]
    assert verdicts
    for verdict in verdicts:
        assert 0.0 <= verdict.confidence <= 1.0
        assert verdict.root_cause.strip(), f"{verdict.bucket_id} has no root cause"


def test_recorded_verdicts_name_the_signals_they_used() -> None:
    """GATE 9: signals_used must reflect all five when available."""
    payload = json.loads(_recorded("verdicts.json").read_text(encoding="utf-8"))
    verdicts = [TriageVerdict.model_validate(v) for v in payload]
    for verdict in verdicts:
        assert set(verdict.signals_used) <= set(TRIAGE_SIGNALS)
    assert any(
        set(v.signals_used) == set(TRIAGE_SIGNALS) for v in verdicts
    ), "no verdict used all five signals, which is what the design is for"


def test_the_write_is_rated_more_severe_than_the_read() -> None:
    """An out-of-bounds write corrupts state; a read leaks it. Triage collapsing
    that distinction would make the report useless for prioritising."""
    payload = json.loads(_recorded("verdicts.json").read_text(encoding="utf-8"))
    verdicts = {v["bucket_id"]: v for v in payload}
    buckets = json.loads(
        (GATE9.parent / "gate8" / "buckets.json").read_text(encoding="utf-8")
    )
    for bucket in buckets:
        verdict = verdicts.get(bucket["bucket_id"])
        if verdict is None or verdict["verdict"] != "confirmed":
            continue
        rank = SEVERITY_ORDER.index(verdict["exploitability"])
        if "write" in bucket["key_detail"]:
            assert rank <= SEVERITY_ORDER.index("info_leak"), (
                f"a write bucket was rated {verdict['exploitability']}"
            )


def test_the_scorecard_reports_on_the_held_out_split_only() -> None:
    """Optimising and evaluating on the same split is invalid (section 10)."""
    path = GATE9 / "triage_scorecard.json"
    if not path.exists():
        pytest.skip("run python -m eval.triage_eval to produce the scorecard")
    card = json.loads(path.read_text(encoding="utf-8"))

    assert card["split"] == "heldout"
    assert not (set(card["train_case_ids"]) & set(card["heldout_case_ids"])), (
        "a case appears in both splits; the reported metric is invalid"
    )
    assert card["n"] == len(card["heldout_case_ids"])
    # The caveat is part of the result, not decoration.
    assert "not a claim about real-world precision" in card["caveat"]
    assert f"n={card['n']}" in card["caveat"]


def test_the_scorecard_does_not_report_precision_over_zero_findings() -> None:
    """Precision 1.0 over nothing confirmed is the most flattering possible lie."""
    path = GATE9 / "triage_scorecard.json"
    if not path.exists():
        pytest.skip("run python -m eval.triage_eval to produce the scorecard")
    card = json.loads(path.read_text(encoding="utf-8"))
    shipped = card["confusion"]["true_positive"] + card["confusion"]["false_positive"]
    if shipped == 0:
        assert card["precision"] is None


def test_the_advisory_renders_with_confirmed_findings_only() -> None:
    path = GATE9 / "advisory.md"
    if not path.exists():
        pytest.skip("run python -m analysis.triage_run to produce the advisory")
    text = path.read_text(encoding="utf-8")
    verdicts = json.loads((GATE9 / "verdicts.json").read_text(encoding="utf-8"))
    confirmed = [v for v in verdicts if v["verdict"] == "confirmed"]

    assert f"{len(confirmed)} confirmed finding" in text
    for verdict in verdicts:
        if verdict["verdict"] == "false_positive":
            assert verdict["root_cause"][:60] not in text, (
                "a discarded finding's text appears in the shipped advisory"
            )


@live_llm
def test_live_triage_produces_a_valid_verdict() -> None:
    from analysis.triage import configure_dspy

    configure_dspy(role="triage")
    verdict = TriageProgram(use_cot=True)(_bundle())
    assert verdict.verdict in {"confirmed", "false_positive"}
    assert verdict.signals_used
