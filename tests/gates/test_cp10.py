"""GATE 10 -- baseline vs LLM-guided evaluation harness (CP10).

GATE 10 requires:

* baseline vs system numbers for >= 1 target with **both** ablations;
* coverage curves plotted;
* results written to docs/RESULTS.md.

The tests that matter most here are not about the numbers -- they are about
whether the comparison is *capable of being lost*. An arm that silently ran our
own mutator while being labelled a baseline, or an ablation that quietly kept the
thing it claims to remove, would produce a favourable result with no content. So
the ablations are checked for actually ablating, and the arms for differing in
exactly one thing.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from arch.contracts import CoverageSummary
from engine_bridge.plateau import FrontierBlock
from eval.baseline import ARMS, POOR_SEED, Arm
from llm.seed_gen import SeedGenRequest, _prompt, _strip_pseudoc

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE10 = REPO_ROOT / "artifacts" / "runs" / "gate10"
MODULE_SOURCE = REPO_ROOT / "fuzzer" / "module" / "fuzzer_snapfuzz.cc"


def _comparison():
    path = GATE10 / "comparison.json"
    if not path.exists():
        pytest.skip(
            f"{path.relative_to(REPO_ROOT)} has not been produced. Run: "
            f"python -m eval.baseline --minutes 5 --workers 2"
        )
    return json.loads(path.read_text(encoding="utf-8"))


# --- the arms are what they claim to be ----------------------------------


def test_both_built_in_mutators_are_baselined() -> None:
    """Section 10 of CP10: run against BOTH so the baseline cannot be dismissed
    as a weak straw man."""
    baselines = {a.env.get("SNAPFUZZ_MUTATOR") for a in ARMS if not a.sidecar}
    assert "libfuzzer" in baselines
    assert "honggfuzz" in baselines


def test_both_required_ablations_exist() -> None:
    """(a) no LLM seed gen, (b) no pseudo-C in prompts."""
    names = {a.name for a in ARMS}
    assert "ablation-no-seedgen" in names
    assert "ablation-no-pseudoc" in names

    no_seedgen = next(a for a in ARMS if a.name == "ablation-no-seedgen")
    assert no_seedgen.sidecar is False, "ablation (a) must disable the sidecar"

    no_pseudoc = next(a for a in ARMS if a.name == "ablation-no-pseudoc")
    assert no_pseudoc.sidecar is True, (
        "ablation (b) must keep the sidecar -- it removes the pseudo-C, not the LLM"
    )
    assert no_pseudoc.env.get("SNAPFUZZ_NO_PSEUDOC") == "1"


def test_the_llm_guided_arm_uses_our_mutator_and_the_sidecar() -> None:
    arm = next(a for a in ARMS if a.name == "llm-guided")
    assert arm.sidecar is True
    assert "SNAPFUZZ_MUTATOR" not in arm.env, (
        "the treatment arm must not pin a built-in mutator"
    )


def test_arm_names_are_unique() -> None:
    names = [a.name for a in ARMS]
    assert len(set(names)) == len(names)


def test_every_arm_starts_from_the_same_single_poor_seed() -> None:
    """Different starting corpora would make the comparison meaningless."""
    assert POOR_SEED.startswith(b'{"Packets"')
    # One packet, one command, empty body: valid enough to be accepted, poor
    # enough to leave the search something to do.
    parsed = json.loads(POOR_SEED)
    assert len(parsed["Packets"]) == 1
    assert parsed["Packets"][0]["Body"] == []


# --- the ablations actually ablate ---------------------------------------


def test_the_pseudoc_ablation_removes_the_code_from_the_prompt() -> None:
    """The check that stops ablation (b) being decorative.

    The frontier ADDRESSES stay -- the model still knows which branches are
    unreached -- so what is isolated is reasoning over decompiled code, not
    knowing where to aim.
    """
    context = (
        "Function ProcessPacket:\n"
        "  reached 0x1400012c9, but never took the branch to 0x1400012de\n\n"
        "=== ProcessPacket ===\n"
        "void ProcessPacket(uchar *p, uint n) { UNIQUE_CODE_MARKER; }"
    )
    stripped = _strip_pseudoc(context)
    assert "UNIQUE_CODE_MARKER" not in stripped
    assert "0x1400012de" in stripped, "the frontier addresses must survive"
    assert "withheld" in stripped

    request = SeedGenRequest(
        summary=CoverageSummary(
            tick=1,
            total_edges=48,
            new_edges=0,
            plateau_ticks=1,
            corpus_size=39,
            crash_bucket_count=0,
            frontier=[0x1400012C9],
        ),
        frontier=[
            FrontierBlock(
                rva=0x12C9,
                static_addr=0x1400012C9,
                function="ProcessPacket",
                unreached_successor_rvas=(0x12DE,),
                unreached_successor_statics=(0x1400012DE,),
            )
        ],
        example_seed=b"{}",
        without_pseudoc=True,
    )
    prompt = _prompt(request, stripped)
    assert "UNIQUE_CODE_MARKER" not in prompt
    assert "0x1400012de" in prompt


def test_the_pseudoc_ablation_also_withholds_the_global_bounds() -> None:
    """A6 is the same kind of static fact read out of the binary (D-047), so
    leaving it in would leak most of what the ablation claims to remove."""
    source = (REPO_ROOT / "llm" / "sidecar.py").read_text(encoding="utf-8")
    assert 'globals_table="" if cfg.without_pseudoc' in source


def test_the_ablation_flag_is_settable_from_the_environment() -> None:
    """So an arm can turn it on without editing committed config."""
    source = (REPO_ROOT / "llm" / "sidecar.py").read_text(encoding="utf-8")
    assert 'SNAPFUZZ_NO_PSEUDOC' in source


def test_the_module_dispatches_to_the_built_in_mutators() -> None:
    """wtf has no --mutator flag: the module's factory is the only place the
    baseline arms can be selected, so it must actually do so."""
    source = MODULE_SOURCE.read_text(encoding="utf-8")
    assert "SNAPFUZZ_MUTATOR" in source
    assert "LibfuzzerMutator_t::Create" in source
    assert "HonggfuzzMutator_t::Create" in source


def test_an_unrecognised_mutator_name_aborts_rather_than_guessing() -> None:
    """A typo must not silently label our mutator's numbers as a baseline."""
    source = MODULE_SOURCE.read_text(encoding="utf-8")
    index = source.find("SNAPFUZZ_MUTATOR")
    region = source[index : index + 2000]
    assert "std::abort()" in region
    assert "refusing to guess" in region
    # abort() does not flush C stdio, so without this the refusal is invisible.
    assert "fflush(stdout)" in region


def test_the_comparison_holds_the_harness_fixed_and_says_so() -> None:
    """Honesty requirement: Init/InsertTestcase/Restore stay ours in every arm,
    so the comparison isolates generation and does not claim more."""
    source = MODULE_SOURCE.read_text(encoding="utf-8")
    # Asserted on the claim itself rather than a byte window around the factory:
    # a positional window silently drifts whenever the comment above it is edited,
    # which makes the test fail for a reason unrelated to what it checks.
    assert "stay OURS in every arm" in source
    assert "isolates" in source and "generation" in source
    assert "does not claim to" in source


# --- unique crashes mean the same thing in every arm ---------------------


def test_arms_are_compared_on_buckets_not_crash_files() -> None:
    """Counting crash FILES would compare wtf's filename collapsing, which is not
    a bug count: 53 files held 52 distinct fault addresses and 4 bugs (D-024)."""
    source = (REPO_ROOT / "eval" / "baseline.py").read_text(encoding="utf-8")
    assert "bucket_crashes" in source
    assert "distinct_buckets" in source


def test_minset_is_available_and_uses_the_documented_form() -> None:
    """Section 13.2, and section 10 lists skipping minset as an anti-pattern."""
    source = (REPO_ROOT / "eval" / "baseline.py").read_text(encoding="utf-8")
    assert "--runs=0" in source
    assert '"--inputs", "outputs"' in source
    assert '"--outputs", "minset"' in source


def test_no_llm_call_in_the_comparison_harness() -> None:
    """The harness launches arms; the LLM lives in the sidecar it starts."""
    source = (REPO_ROOT / "eval" / "baseline.py").read_text(encoding="utf-8")
    assert "LlmClient" not in source
    assert "from llm.client" not in source


# --- recorded results ----------------------------------------------------


def test_the_comparison_covers_baselines_the_system_and_both_ablations() -> None:
    data = _comparison()
    ran = {arm["arm"] for arm in data["arms"]}
    required = {
        "baseline-libfuzzer",
        "baseline-honggfuzz",
        "llm-guided",
        "ablation-no-seedgen",
        "ablation-no-pseudoc",
    }
    missing = required - ran
    assert not missing, f"arms not run: {sorted(missing)}"


def test_every_arm_got_the_same_budget_and_worker_count() -> None:
    """An arm with more time or more workers is not a comparison."""
    data = _comparison()
    workers = {arm["workers"] for arm in data["arms"]}
    assert len(workers) == 1, f"arms ran with different worker counts: {workers}"

    durations = [arm["duration_s"] for arm in data["arms"]]
    spread = max(durations) - min(durations)
    assert spread < 90, (
        f"arm durations differ by {spread:.0f}s, which is too much of the budget "
        f"to call this a fixed-budget comparison"
    )


def test_every_arm_actually_executed_testcases() -> None:
    """An arm that failed to start would otherwise read as 'found nothing'."""
    for arm in _comparison()["arms"]:
        assert arm["peak_executions"] > 1000, (
            f"{arm['arm']} executed only {arm['peak_executions']} testcases; it "
            f"probably failed to start rather than performing badly"
        )


def test_the_sidecar_arms_actually_consumed_seeds() -> None:
    """If the LLM-guided arm consumed no seeds it IS the ablation, and the
    comparison would be measuring nothing."""
    arms = {a["arm"]: a for a in _comparison()["arms"]}
    for name in ("llm-guided", "ablation-no-pseudoc"):
        arm = arms.get(name)
        if arm is None:
            continue
        if arm["sidecar_rounds"] == 0:
            pytest.skip(
                f"{name} never reached a plateau in its budget, so no seeds were "
                f"generated -- the arm ran but tests nothing about seed injection"
            )
        assert arm["seeds_consumed"] > 0, (
            f"{name} published seeds over {arm['sidecar_rounds']} round(s) but "
            f"consumed none; the injection path is broken in this arm"
        )


def test_the_ablation_arms_consumed_no_seeds_where_they_should_not() -> None:
    arms = {a["arm"]: a for a in _comparison()["arms"]}
    for name in ("baseline-libfuzzer", "baseline-honggfuzz", "ablation-no-seedgen"):
        arm = arms.get(name)
        if arm is None:
            continue
        assert arm["sidecar_rounds"] == 0, (
            f"{name} ran {arm['sidecar_rounds']} sidecar round(s) but is a "
            f"no-LLM arm"
        )


def test_coverage_curves_were_recorded_for_every_arm() -> None:
    """GATE 10 asks for curves, so the data behind them must exist per arm."""
    for arm in _comparison()["arms"]:
        curve = arm["coverage_curve"]
        assert len(curve) >= 3, (
            f"{arm['arm']} has {len(curve)} coverage sample(s); a curve needs more"
        )
        times = [point[0] for point in curve]
        assert times == sorted(times), f"{arm['arm']}'s curve is not monotonic in time"
        coverage = [point[1] for point in curve]
        assert coverage == sorted(coverage), (
            f"{arm['arm']}'s aggregate coverage decreases, which cannot happen -- "
            f"the parse is wrong"
        )


def test_the_curve_plot_was_produced() -> None:
    path = GATE10 / "coverage_curves.png"
    if not path.exists():
        pytest.skip("run python -m eval.plot_curves to render the coverage plot")
    assert path.stat().st_size > 5000, "the plot file is too small to be a real figure"


def test_results_are_written_up() -> None:
    """GATE 10: results in docs/RESULTS.md, not only in JSON."""
    text = (REPO_ROOT / "docs" / "RESULTS.md").read_text(encoding="utf-8")
    if "baseline-libfuzzer" not in text:
        pytest.skip("the CP10 comparison has not been written into docs/RESULTS.md yet")
    for arm in ("baseline-libfuzzer", "baseline-honggfuzz", "llm-guided"):
        assert arm in text
    assert "ablation" in text.lower()
