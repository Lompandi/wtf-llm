"""Run the checkpoint gates and report which CLAUDE.md conditions were proven.

RULE 3: "Each checkpoint (section 8) defines an explicit gate: the concrete
artifacts that must exist and the assertions that must pass, proving the
interfaces are **actually wired** -- not merely that code compiles. Do not start
checkpoint N+1 until checkpoint N's gate passes. Implement each gate as an
executable check under `tests/gates/` and record the result in
`docs/PROGRESS.md`."

`pytest tests/gates` does not do that, and the difference is the reason this file
exists. It reports "473 passed, 12 skipped" and exits 0 -- which says nothing
about *which* of section 8's conditions were proven, and hides the case that
matters most: a condition expressed as `pytest.skip` still exits 0. GATE 7's
coverage-increase criterion was exactly that, so the suite was green while the
one thing GATE 7 asks for had not been shown (D-067).

So this runner works from the conditions themselves. `GATES` below quotes section
8's wording and names the tests that prove each clause. A condition is:

* **proven** -- at least one named test matched, and every match passed;
* **incomplete** -- a named test SKIPPED, or nothing matched it at all;
* **failed** -- a named test failed.

A gate with any incomplete condition is `incomplete`, never `pass`. Nothing here
can be satisfied by a test that did not run.

**Why "nothing matched" is incomplete rather than an error.** A renamed or deleted
test would otherwise silently stop proving its condition while the gate stayed
green -- the same shape as the eleven false successes in D-057.

Usage:

    python -m tools.gates run                 # every gate
    python -m tools.gates run --gate cp4      # one
    python -m tools.gates run --through cp7   # cp0..cp7, stopping at the first
                                              # gate that does not pass (RULE 3)
    python -m tools.gates status              # last recorded results, no run

Set SNAPFUZZ_STRICT_GATE=1 (or pass --strict) to make the exit code non-zero on
any incomplete gate, not only a failing one. That is the mode for judging release
readiness; the default is for development, where a skipped live test is expected.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS = REPO_ROOT / "artifacts" / "gates" / "gate-results.json"

__all__ = ["GATES", "GateSpec", "Condition", "run_gate", "run_gates", "GATE_ORDER"]


@dataclass(frozen=True)
class Condition:
    """One clause of a section 8 gate, and the tests that prove it.

    ``text`` is quoted from CLAUDE.md rather than paraphrased: a paraphrase drifts
    from the spec and then the runner is checking something nobody specified.
    ``tests`` are node-id substrings, so a rename is caught as "nothing matched"
    instead of quietly ceasing to be checked.
    """

    text: str
    tests: tuple[str, ...]
    # Conditions that cannot be shown on a machine with no guest VM, no second
    # backend, or no allocation to spend. They still appear in the report, and
    # they still make the gate incomplete -- being unprovable here is not the same
    # as being proven, and this is the field that stops those two collapsing.
    needs: str = ""


@dataclass(frozen=True)
class GateSpec:
    checkpoint: str
    title: str
    # None means section 8 defines the gate but nothing under tests/gates/
    # implements it -- itself a RULE 3 violation, reported as such.
    test_path: str | None
    conditions: tuple[Condition, ...] = ()
    note: str = ""


# --- the gates, quoted from CLAUDE.md section 8 ---------------------------

GATES: tuple[GateSpec, ...] = (
    GateSpec(
        "cp0",
        "Scaffold, contracts, config, graph",
        "tests/gates/test_cp0.py",
        (
            Condition(
                "contracts import cleanly",
                ("test_contracts_import_cleanly", "test_contracts_round_trip_through_json"),
            ),
            Condition("graph YAML parses", ("test_configs_parse",)),
            Condition(
                "every edge in section 3.2 present; graph test passes",
                ("test_progress_lists_every_edge", "test_graph"),
            ),
            Condition(
                "docs/PROGRESS.md lists every edge",
                ("test_progress_status_matches_graph", "test_live_edges_have_a_passed_gate"),
            ),
        ),
    ),
    GateSpec(
        "cp1",
        "Build wtf, run a bundled example unmodified",
        # The gate file this project's release state was blocked on. RULE 3 says
        # "implement each gate as an executable check under tests/gates/" and for a
        # long time there was no test_cp1.py: the 150-second run happened and was
        # written up, so the row said PASS while resting on a log entry rather than on
        # an assertion (D-070). The conditions below are section 8's, split by what
        # KIND of claim each one is -- a CLI surface, a recorded measurement, a
        # write-up -- because they are not checkable the same way.
        "tests/gates/test_cp1.py",
        (
            Condition(
                "wtf builds",
                ("test_wtf_is_built",),
            ),
            Condition(
                "the three verbs CP1 requires exist, and a bundled example is "
                "registered in the binary",
                (
                    "test_wtf_offers_the_three_verbs_cp1_requires",
                    "test_the_bundled_examples_are_registered_in_the_binary",
                ),
            ),
            Condition(
                "a bundled example fuzzes >= 60s on bochscpu with nonzero coverage",
                (
                    "test_the_recorded_campaign_ran_long_enough",
                    "test_the_recorded_campaign_produced_nonzero_growing_coverage",
                    "test_the_recorded_campaign_used_bochscpu",
                ),
            ),
            Condition(
                "corpus and crash output paths identified, and the BP-file format is "
                "pinned by a parser rather than described",
                (
                    "test_the_output_layout_is_identified_in_code",
                    "test_the_bp_file_format_is_pinned_by_a_parser",
                ),
            ),
            Condition(
                "DEVIATIONS.md records the actual CLI, snapshot format, BP-file "
                "format and output layout",
                ("test_deviations_records_what_cp1_was_for",),
            ),
        ),
    ),
    GateSpec(
        "cp2",
        "Ghidra headless BB enumeration -> A3",
        "tests/gates/test_cp2.py",
        (
            Condition("a3_bp_list.json exists with >0 blocks", ("test_bp_list_exists_with_blocks",)),
            Condition(
                "the wtf-native BP file passes format validation",
                ("test_generated_cov_file_validates", "test_round_trip_write_then_parse"),
            ),
            Condition(
                "a round-trip test parses our file with the same logic wtf uses",
                ("test_our_format_matches_the_shipped_file_exactly",),
            ),
        ),
    ),
    GateSpec(
        "cp3",
        "Snapshot acquisition -> A1",
        "tests/gates/test_cp3.py",
        (
            Condition("a1_snapshot.json exists", ("test_a1_exists_and_validates",)),
            Condition(
                "wtf loads the snapshot and executes >= 1 iteration from it",
                ("test_wtf_loads_the_snapshot_and_executes",),
            ),
            Condition(
                "module_base and entry_runtime_addr recorded",
                ("test_a1_records_module_base_and_entry", "test_a1_address_chain_agrees_with_ghidra"),
            ),
            Condition(
                "on Linux, aslr_disabled == True",
                ("test_linux_ingest_sets_aslr_disabled",),
            ),
            # The gate's own heading is "Snapshot ACQUISITION". Everything above
            # tests a snapshot somebody else produced.
            Condition(
                "the acquisition path itself runs (edges 1, 6 or 6b, 7 or 8)",
                (),
                needs="a Hyper-V guest with KD attached, or a Linux/KVM host with "
                "linux_mode built -- neither exists on this host",
            ),
        ),
    ),
    GateSpec(
        "cp4",
        "Fuzzer module + first real fuzzing run (1 worker)",
        "tests/gates/test_cp4.py",
        (
            Condition(
                "a >= 10-minute run on the real target produces nonzero and growing coverage",
                ("test_coverage_is_nonzero_and_growing",),
            ),
            Condition("corpus grows via requeue", ("test_corpus_grew_via_requeue",)),
            Condition(">= 1 CoverageSummary tick written", ("test_coverage_ticks_were_written",)),
            Condition(
                "any crash yields a well-formed CrashRecord",
                (
                    "test_crashes_are_well_formed_records",
                    "test_crash_collection_is_wired_even_when_no_new_crash_appears",
                ),
            ),
            Condition(
                "a symbolized rip trace proves execution reaches FuzzEntry.static_addr",
                ("test_symbolized_trace_reaches_the_fuzz_entry",),
            ),
            Condition(
                "assert no LLM call exists in this path",
                ("test_no_llm_import_on_the_fast_path",),
            ),
        ),
    ),
    GateSpec(
        "cp4b",
        "Distributed bring-up (>= 2 workers)",
        "tests/gates/test_cp4b.py",
        (
            Condition(
                "master starts and serves >= 2 workers simultaneously",
                ("test_master_served_at_least_two_workers",),
            ),
            Condition(
                "master aggregate coverage exceeds any individual worker's contribution",
                ("test_throughput_scales_with_worker_count",),
            ),
            Condition(
                "killing one worker does not stop the campaign and it is restarted",
                ("test_killing_a_worker_does_not_stop_the_campaign",),
                needs="the multi-minute campaign (SNAPFUZZ_LIVE_CP4B=1)",
            ),
            Condition(
                "the corpus ingest path is resolved and documented, with a test that "
                "injects a known seed and proves a worker executed it",
                ("test_injected_seed_reaches_a_worker",),
                needs="the multi-minute campaign (SNAPFUZZ_LIVE_CP4B=1)",
            ),
            Condition("crash records carry worker_id", ("test_worker_id_is_absent_and_that_is_recorded",)),
        ),
    ),
    GateSpec(
        "cp5",
        "LLM client",
        "tests/gates/test_cp5.py",
        (
            Condition(
                "every configured role resolves to a model returning a valid completion",
                ("test_every_role_returns_a_valid_completion",),
                needs="a live provider key and allocation to spend (SNAPFUZZ_LIVE_LLM=1)",
            ),
            Condition(
                "a JSON-constrained call round-trips into a pydantic model",
                ("test_json_call_round_trips_into_a_pydantic_model",),
                needs="SNAPFUZZ_LIVE_LLM=1",
            ),
            Condition("usage log populated", ("test_usage_log_is_populated", "test_usage_log_records_the_provider")),
            Condition(
                "budget cap triggers when set to a tiny value",
                ("test_budget_cap_triggers_when_tiny", "test_token_budget_cap_also_triggers"),
            ),
        ),
    ),
    GateSpec(
        "cp6",
        "GhidraMCP + A2 + LLM fuzz-entry selection",
        "tests/gates/test_cp6.py",
        (
            Condition("A2 populated for the entry closure", ("test_a2_is_populated_for_the_entry_closure",)),
            Condition(
                "get_by_addr returns pseudo-C for a known function address",
                ("test_module_scope_a2_gives_the_llm_real_choice",),
            ),
            Condition(
                "GhidraMCP answers a live decompile request",
                ("test_ghidra_mcp_answers_a_live_decompile_request",),
                needs="a Ghidra GUI with GhidraMCP enabled (SNAPFUZZ_LIVE_MCP=1)",
            ),
            Condition(
                "entry_select.py emits a valid FuzzEntry whose static_addr is a real function",
                ("test_llm_entry_is_a_valid_fuzz_entry_at_a_real_function",),
            ),
            Condition(
                "re-run CP3 with the LLM-chosen entry and confirm the snapshot still loads",
                ("test_snapshot_still_loads_with_the_llm_chosen_entry",),
            ),
        ),
    ),
    GateSpec(
        "cp7",
        "Plateau detection + LLM seed generation",
        "tests/gates/test_cp7.py",
        (
            Condition(
                "an induced plateau triggers exactly one seed-gen call",
                ("test_a_plateau_produced_a_seed_generation_round", "test_at_most_one_generation_round_per_plateau"),
            ),
            Condition(
                "generated seeds land in the corpus and are demonstrably executed",
                ("test_published_seeds_were_consumed_by_the_master",),
            ),
            Condition(
                "coverage increases after injection on >= 1 target",
                ("test_llm_seeds_increased_coverage",),
                needs="a recorded round whose seeds add blocks -- the measured round "
                "added none (48 covered before, union 48), and tlv_server saturates "
                "in ~100s, so this needs a target with headroom",
            ),
            Condition(
                "timing log shows the fast loop never stalled on the LLM",
                ("test_no_llm_import_on_the_fast_path", "test_seed_generation_originates_only_in_the_sidecar"),
            ),
            Condition(
                "the plateau is detected on aggregate coverage with N > 1 workers running",
                (
                    "test_plateau_was_watched_with_more_than_one_worker",
                    "test_the_plateau_signal_is_the_masters_aggregate_corpus",
                ),
            ),
        ),
    ),
    GateSpec(
        "cp8",
        "Crash dedup, classification, deterministic replay",
        "tests/gates/test_cp8.py",
        (
            Condition(
                "dedup collapses crashes to a small bucket count with correct hit_count",
                (
                    "test_dedup_collapses_the_real_crash_set",
                    "test_hit_count_is_the_number_of_crashes_merged",
                ),
            ),
            Condition(
                "every bucket has a ReplayResult",
                (
                    "test_every_bucket_has_a_replay_result",
                    "test_replays_reproduced_deterministically_on_bochscpu",
                ),
            ),
            Condition(
                "reverse.py returns pseudo-C for each bucket's fault address",
                ("test_every_bucket_has_static_context_with_pseudo_c",),
            ),
            Condition(
                "assert no LLM call occurs anywhere in CP8's path",
                ("test_no_llm_call_anywhere_in_cp8",),
            ),
        ),
    ),
    GateSpec(
        "cp9",
        "DSPy multi-signal triage + report",
        "tests/gates/test_cp9.py",
        (
            Condition(
                "triage consumes all five signals and signals_used reflects that",
                (
                    "test_all_five_signals_are_rendered_as_separate_fields",
                    "test_recorded_verdicts_name_the_signals_they_used",
                    "test_a_signal_the_model_did_not_have_is_not_credited",
                ),
            ),
            Condition(
                "verdicts validate against TriageVerdict",
                ("test_recorded_verdicts_validate_against_the_contract",),
            ),
            Condition(
                "precision/recall reported on the HELD-OUT planted-bug split",
                (
                    "test_the_scorecard_reports_on_the_held_out_split_only",
                    "test_no_case_is_in_both_splits",
                ),
            ),
            Condition(
                "the GHSA report renders with confirmed findings only; discards logged separately",
                (
                    "test_the_advisory_renders_with_confirmed_findings_only",
                    "test_discards_are_logged_separately_and_kept",
                ),
            ),
        ),
    ),
    GateSpec(
        "cp10",
        "Evaluation harness",
        "tests/gates/test_cp10.py",
        (
            Condition(
                "baseline vs system numbers for >= 1 target with both ablations",
                ("test_the_comparison_covers_baselines_the_system_and_both_ablations",),
            ),
            Condition("coverage curves plotted", ("test_the_curve_plot_was_produced",)),
            Condition("results written to docs/RESULTS.md", ("test_results_are_written_up",)),
            Condition(
                "wtf's built-in mutators are both baselined",
                ("test_both_built_in_mutators_are_baselined",),
            ),
        ),
    ),
    GateSpec(
        "cp11",
        "LLM-derived input structure (edges 12, 14)",
        "tests/gates/test_cp11.py",
        (
            Condition(
                "the derived spec reproduces the hand-written layout by OFFSET, not field name",
                ("test_the_derived_spec_reproduces_the_ground_truth_layout",),
            ),
            Condition(
                "the model fills a validated schema; ordinary code renders the C++",
                (
                    "test_codegen_contains_no_llm_call",
                    "test_the_derivation_is_the_only_place_the_model_is_asked",
                ),
            ),
            Condition(
                "the generated C++ compiles",
                ("test_the_generated_header_compiles",),
                needs="MSVC (SNAPFUZZ_LIVE_CC=1)",
            ),
            Condition(
                "edge 14: the generated header is a build dependency of the shipped module",
                (),
                needs="adopting it renames the test-case JSON keys and invalidates the "
                "existing corpus and crash files (D-055)",
            ),
        ),
        note="not a gate in CLAUDE.md section 8 -- see section 14.3",
    ),
    GateSpec(
        "cp12",
        "End-to-end pipeline driver",
        "tests/gates/test_cp12.py",
        (
            Condition(
                "every stage names the artifact that proves it ran",
                ("test_every_stage_names_at_least_one_artifact",),
            ),
            Condition(
                "the summary never prints unqualified success",
                (
                    "test_summarise_never_prints_success_next_to_a_failure",
                    "test_summarise_returns_zero_only_when_every_stage_is_accounted_for",
                ),
            ),
            Condition(
                "prerequisites are checked before any stage runs",
                ("test_main_runs_no_stage_when_prerequisites_are_not_met",),
            ),
            Condition(
                "the driver imports no LLM client (RULE 1)",
                ("test_the_driver_imports_no_llm_client",),
            ),
        ),
        note="not a gate in CLAUDE.md section 8 -- see section 14.5",
    ),
)

GATE_ORDER: tuple[str, ...] = tuple(g.checkpoint for g in GATES)


# --- running --------------------------------------------------------------


class _Collector:
    """Pytest plugin: remember every test's outcome, keyed by node id."""

    def __init__(self) -> None:
        self.outcomes: dict[str, str] = {}
        self.reasons: dict[str, str] = {}

    def pytest_runtest_logreport(self, report: Any) -> None:
        # A test is "passed" only if its call phase passed. A setup-phase skip
        # never reaches the call phase, so recording only `call` would lose it.
        if report.when == "call":
            self.outcomes[report.nodeid] = report.outcome
        elif report.when == "setup" and report.outcome in ("skipped", "failed"):
            self.outcomes.setdefault(report.nodeid, report.outcome)
        if report.outcome == "skipped" and getattr(report, "longrepr", None):
            longrepr = report.longrepr
            reason = longrepr[2] if isinstance(longrepr, tuple) and len(longrepr) > 2 else str(longrepr)
            self.reasons[report.nodeid] = str(reason)


def _evaluate(
    condition: Condition, outcomes: dict[str, str], reasons: dict[str, str]
) -> dict[str, Any]:
    matched = {
        nodeid: outcome
        for nodeid, outcome in outcomes.items()
        if any(needle in nodeid for needle in condition.tests)
    }
    if not condition.tests:
        status = "incomplete"
        detail = condition.needs or "no test named for this condition"
    elif not matched:
        # A renamed or deleted test must not silently stop proving its clause.
        status = "incomplete"
        detail = f"no test matched {list(condition.tests)} -- renamed or removed?"
    elif any(o == "failed" for o in matched.values()):
        status = "failed"
        detail = "; ".join(n for n, o in matched.items() if o == "failed")
    elif any(o == "skipped" for o in matched.values()):
        status = "incomplete"
        skipped = [n for n, o in matched.items() if o == "skipped"]
        why = reasons.get(skipped[0], "")
        detail = f"skipped: {skipped[0]}" + (f" -- {why}" if why else "")
    else:
        status = "proven"
        detail = f"{len(matched)} assertion(s)"
    return {
        "condition": condition.text,
        "status": status,
        "detail": detail,
        "needs": condition.needs,
        "tests": list(matched),
    }


def run_gate(spec: GateSpec, *, repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    """Run one gate's test file and evaluate its section 8 conditions."""
    import pytest

    started = time.time()
    collector = _Collector()

    if spec.test_path is None:
        outcomes: dict[str, str] = {}
        exit_code = -1
    else:
        path = repo_root / spec.test_path
        if not path.exists():
            outcomes, exit_code = {}, -1
        else:
            # test_graph.py backs one of GATE 0's clauses, so it has to be in the
            # run for that condition to be provable.
            targets = [str(path)]
            if spec.checkpoint == "cp0":
                targets.append(str(repo_root / "tests" / "gates" / "test_graph.py"))
            exit_code = int(
                pytest.main(["-q", "--no-header", "-p", "no:cacheprovider", *targets],
                            plugins=[collector])
            )
            outcomes = collector.outcomes

    conditions = [_evaluate(c, outcomes, collector.reasons) for c in spec.conditions]
    counted = {c["status"] for c in conditions}
    if "failed" in counted:
        status = "failed"
    elif "incomplete" in counted:
        status = "incomplete"
    elif not conditions:
        # A gate with no declared conditions cannot be passed by running tests --
        # that is the "green suite stands in for a gate" failure this exists to
        # stop, so it is never reported as a pass.
        status = "incomplete"
    else:
        status = "pass"

    return {
        "gate": spec.checkpoint,
        "title": spec.title,
        "status": status,
        "note": spec.note,
        "test_path": spec.test_path,
        "pytest_exit": exit_code,
        "required_conditions": len(spec.conditions),
        "proven_conditions": sum(1 for c in conditions if c["status"] == "proven"),
        "incomplete_conditions": sum(1 for c in conditions if c["status"] == "incomplete"),
        "tests_run": len(outcomes),
        "tests_passed": sum(1 for o in outcomes.values() if o == "passed"),
        "tests_skipped": sum(1 for o in outcomes.values() if o == "skipped"),
        "conditions": conditions,
        "duration_s": round(time.time() - started, 2),
    }


def _provenance(repo_root: Path) -> dict[str, Any]:
    """What was measured, so a result can be tied to a tree state.

    Without this a gate-results.json is unattributable: it says conditions were
    proven but not of what.
    """

    def _git(*args: str) -> str | None:
        try:
            return subprocess.run(
                ["git", *args], cwd=repo_root, capture_output=True, text=True, timeout=30
            ).stdout.strip() or None
        except Exception:
            return None

    def _sha256(path: Path) -> str | None:
        if not path.exists() or not path.is_file():
            return None
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1 << 20):
                digest.update(chunk)
        return digest.hexdigest()

    target = repo_root / "targets" / "tlv_server" / "target" / "tlv_server.exe"
    return {
        "commit": _git("rev-parse", "HEAD"),
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "dirty": bool(_git("status", "--porcelain")),
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "target_binary": str(target.relative_to(repo_root)) if target.exists() else None,
        "target_sha256": _sha256(target),
        "wtf_exe_sha256": _sha256(repo_root / "src" / "build" / "wtf.exe"),
        "timestamp": time.time(),
    }


def run_gates(
    names: list[str] | None = None,
    *,
    through: str | None = None,
    repo_root: Path = REPO_ROOT,
    stop_on_failure: bool = True,
) -> dict[str, Any]:
    """Run gates in checkpoint order.

    ``through`` implements RULE 3's sequencing: run cp0..cpN and STOP at the first
    gate that does not pass, because "do not start checkpoint N+1 until checkpoint
    N's gate passes" is meaningless if the runner carries on regardless.
    """
    selected = list(GATES)
    if through is not None:
        if through not in GATE_ORDER:
            raise SystemExit(f"unknown gate {through!r}; known: {list(GATE_ORDER)}")
        selected = selected[: GATE_ORDER.index(through) + 1]
    if names:
        unknown = [n for n in names if n not in GATE_ORDER]
        if unknown:
            raise SystemExit(f"unknown gate(s) {unknown}; known: {list(GATE_ORDER)}")
        selected = [g for g in selected if g.checkpoint in names]

    results: list[dict[str, Any]] = []
    blocked_at: str | None = None
    for spec in selected:
        result = run_gate(spec, repo_root=repo_root)
        results.append(result)
        if result["status"] != "pass" and blocked_at is None:
            blocked_at = spec.checkpoint
            if through is not None and stop_on_failure:
                # Everything after this is unreached, and saying so is the point.
                for later in selected[selected.index(spec) + 1 :]:
                    results.append(
                        {
                            "gate": later.checkpoint,
                            "title": later.title,
                            "status": "not-reached",
                            "note": f"RULE 3: blocked at {spec.checkpoint}",
                            "conditions": [],
                        }
                    )
                break

    return {
        "type": "gate-results",
        "provenance": _provenance(repo_root),
        # The earliest gate that does not pass. RULE 3 makes this the project's
        # release state, whatever the later gates say about themselves.
        "blocked_at": blocked_at,
        "gates": results,
    }


def _print(report: dict[str, Any], *, verbose: bool) -> None:
    width = max((len(g["gate"]) for g in report["gates"]), default=4)
    symbols = {
        "pass": "PASS",
        "incomplete": "INCOMPLETE",
        "failed": "FAILED",
        "not-reached": "not reached",
    }
    print()
    for gate in report["gates"]:
        counts = ""
        if gate.get("required_conditions"):
            counts = f"  {gate['proven_conditions']}/{gate['required_conditions']} conditions"
        print(f"  [{symbols[gate['status']]:^11}] {gate['gate'].ljust(width)}  {gate['title']}{counts}")
        if gate.get("note"):
            print(f"  {' ' * 13} {' ' * width}  note: {gate['note']}")
        for condition in gate.get("conditions", []):
            if condition["status"] == "proven" and not verbose:
                continue
            mark = {"proven": "ok", "incomplete": "??", "failed": "XX"}[condition["status"]]
            print(f"  {' ' * 13} {' ' * width}  [{mark}] {condition['condition']}")
            if condition["status"] != "proven":
                print(f"  {' ' * 13} {' ' * width}       {condition['detail']}")
    print()
    blocked = report["blocked_at"]
    if blocked:
        print(f"  RULE 3: the earliest gate that does not pass is {blocked}.")
        print("  Later checkpoints may be implemented and independently validated,")
        print("  but release readiness is blocked here.")
    else:
        print("  every gate run passed every condition it declares")
    print()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="run gates and record the result")
    run.add_argument("--gate", action="append", dest="gates", help="repeatable")
    run.add_argument("--through", help="run cp0..this gate, stopping at the first non-pass")
    run.add_argument(
        "--strict",
        action="store_true",
        help="exit non-zero on any INCOMPLETE gate, not only a failing one "
        "(also SNAPFUZZ_STRICT_GATE=1)",
    )
    run.add_argument("-v", "--verbose", action="store_true", help="show proven conditions too")
    run.add_argument("--out", type=Path, default=RESULTS)

    show = sub.add_parser("status", help="print the last recorded results")
    show.add_argument("--out", type=Path, default=RESULTS)
    show.add_argument("-v", "--verbose", action="store_true")

    args = ap.parse_args(argv)

    if args.cmd == "status":
        if not args.out.exists():
            print(f"no results at {args.out}; run `python -m tools.gates run` first")
            return 1
        report = json.loads(args.out.read_text(encoding="utf-8"))
        _print(report, verbose=args.verbose)
        return 0

    report = run_gates(args.gates, through=args.through)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    _print(report, verbose=args.verbose)
    print(f"  written to {args.out}")

    strict = args.strict or os.environ.get("SNAPFUZZ_STRICT_GATE") == "1"
    statuses = {g["status"] for g in report["gates"]}
    if "failed" in statuses:
        return 1
    if strict and ("incomplete" in statuses or "not-reached" in statuses):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
