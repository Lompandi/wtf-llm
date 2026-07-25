"""Triage accuracy on the HELD-OUT split (CLAUDE.md CP9, GATE 9).

Section 9 and section 10: prompts are optimised on the train split and metrics are
reported on a **held-out** split. Optimising and evaluating on the same set is
invalid and would be caught. This module never scores a case it optimised on --
the split comes from :func:`eval.cases.assigned_split`, which hashes each case id
independently so a case cannot drift across the boundary between runs.

Read :mod:`eval.cases` for what the label set is worth. In short: the positives
are real buckets from a real campaign with ground truth from the target's own
source; the negatives are constructed, so these numbers are indicative of the
prompt's reasoning and are **not** a claim about real-world precision.

Run:
    python -m eval.triage_eval                 # score the held-out split
    python -m eval.triage_eval --optimise      # compile on train, then score
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path

from analysis.triage import (
    SignalBundle,
    TriageProgram,
    configure_dspy,
    render_signals,
    triage_metric,
)
from arch.contracts import TRIAGE_SIGNALS, TriageVerdict
from eval.cases import TriageCase, load_cases, split_cases

REPO_ROOT = Path(__file__).resolve().parents[1]

__all__ = ["Scorecard", "evaluate", "bundle_for"]


def bundle_for(case: TriageCase) -> SignalBundle:
    return SignalBundle(
        bucket=case.bucket,
        classification=case.classification,
        replay=case.replay,
        trace=case.trace,
        context=case.context,
        reproducer_path=f"eval/planted_bugs/{case.case_id}.json",
    )


@dataclass
class Scorecard:
    """Confusion matrix plus the derived rates, on ONE split."""

    split: str
    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0
    verdicts: list[TriageVerdict] = field(default_factory=list)
    wrong: list[str] = field(default_factory=list)
    signal_use: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return (
            self.true_positive
            + self.false_positive
            + self.true_negative
            + self.false_negative
        )

    @property
    def precision(self) -> float | None:
        """Of the findings we would SHIP, how many are real.

        None when nothing was confirmed: a precision of 1.0 over zero findings is
        not a result, and reporting it as one would be the most flattering
        possible lie.
        """
        shipped = self.true_positive + self.false_positive
        return self.true_positive / shipped if shipped else None

    @property
    def recall(self) -> float | None:
        real = self.true_positive + self.false_negative
        return self.true_positive / real if real else None

    @property
    def accuracy(self) -> float | None:
        return (
            (self.true_positive + self.true_negative) / self.total
            if self.total
            else None
        )

    def to_json(self) -> dict:
        return {
            "split": self.split,
            "n": self.total,
            "confusion": {
                "true_positive": self.true_positive,
                "false_positive": self.false_positive,
                "true_negative": self.true_negative,
                "false_negative": self.false_negative,
            },
            "precision": self.precision,
            "recall": self.recall,
            "accuracy": self.accuracy,
            "misclassified": self.wrong,
            "signal_use": self.signal_use,
            "caveat": (
                f"n={self.total}. The negatives are constructed (see "
                f"eval/cases.py), so these rates describe the prompt's reasoning "
                f"on this set and are not a claim about real-world precision."
            ),
        }


def evaluate(
    program: TriageProgram, cases: list[TriageCase], *, split: str
) -> Scorecard:
    """Score ``program`` over ``cases``. No optimisation happens here."""
    card = Scorecard(split=split)
    for case in cases:
        bundle = bundle_for(case)
        verdict = program(bundle)
        card.verdicts.append(verdict)

        for signal in verdict.signals_used:
            card.signal_use[signal] = card.signal_use.get(signal, 0) + 1

        truth_positive = case.label == "confirmed"
        said_positive = verdict.verdict == "confirmed"
        if truth_positive and said_positive:
            card.true_positive += 1
        elif not truth_positive and said_positive:
            card.false_positive += 1
            card.wrong.append(f"{case.case_id}: benign, called confirmed")
        elif truth_positive and not said_positive:
            card.false_negative += 1
            card.wrong.append(f"{case.case_id}: real bug, called false_positive")
        else:
            card.true_negative += 1
    return card


def _to_dspy_examples(cases: list[TriageCase]):
    """Cases -> dspy.Example, with the rendered signals as inputs."""
    import dspy

    examples = []
    for case in cases:
        rendered = render_signals(bundle_for(case))
        examples.append(
            dspy.Example(
                **rendered,
                label=case.label,
                expected_cwe=case.expected_cwe or "",
                expected_exploitability=case.expected_exploitability,
            ).with_inputs(*rendered.keys())
        )
    return examples


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--optimise",
        action="store_true",
        help="compile the prompt on the TRAIN split before scoring held-out",
    )
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "artifacts" / "runs" / "gate9")
    args = ap.parse_args(argv)

    cases = load_cases()
    train, heldout = split_cases(cases)
    if not heldout:
        raise SystemExit("the held-out split is empty; nothing can be reported")

    print(
        f"{len(cases)} case(s): train {len(train)}, heldout {len(heldout)}  "
        f"(confirmed {sum(1 for c in heldout if c.label == 'confirmed')} / "
        f"false_positive {sum(1 for c in heldout if c.label == 'false_positive')} "
        f"in heldout)"
    )
    configure_dspy(role="triage")
    program = TriageProgram(use_cot=True)

    optimised = False
    if args.optimise:
        import dspy

        # BootstrapFewShot with a cheap teacher: section 9 says use a cheap model
        # for demo generation and the 550B for the final reasoning. Demos are
        # drawn ONLY from train.
        print(f"compiling on {len(train)} train case(s)...")
        try:
            compiler = dspy.BootstrapFewShot(
                metric=triage_metric,
                max_bootstrapped_demos=min(2, len(train)),
                max_labeled_demos=min(2, len(train)),
            )
            program.module = compiler.compile(
                program.module, trainset=_to_dspy_examples(train)
            )
            optimised = True
            print("compiled")
        except Exception as exc:
            # An optimiser failure must not be mistaken for a scoring failure, and
            # must not silently fall back to reporting unoptimised numbers as
            # optimised ones.
            print(f"optimisation FAILED, scoring the unoptimised program: {exc}")

    card = evaluate(program, heldout, split="heldout")

    print()
    print(f"held-out n = {card.total}")
    print(
        f"  TP {card.true_positive}  FP {card.false_positive}  "
        f"TN {card.true_negative}  FN {card.false_negative}"
    )
    for name in ("precision", "recall", "accuracy"):
        value = getattr(card, name)
        print(f"  {name:<10} {'n/a' if value is None else f'{value:.2f}'}")
    if card.wrong:
        print("  misclassified:")
        for item in card.wrong:
            print(f"    - {item}")

    print(f"  signal use across {card.total} verdict(s):")
    for signal in TRIAGE_SIGNALS:
        print(f"    {signal:<18} {card.signal_use.get(signal, 0)}")

    args.out.mkdir(parents=True, exist_ok=True)
    payload = card.to_json()
    payload["optimised"] = optimised
    payload["train_case_ids"] = [c.case_id for c in train]
    payload["heldout_case_ids"] = [c.case_id for c in heldout]
    (args.out / "triage_scorecard.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8"
    )
    (args.out / "triage_verdicts.json").write_text(
        json.dumps(
            [json.loads(v.model_dump_json()) for v in card.verdicts], indent=2
        ),
        encoding="utf-8",
    )
    print(f"\nwrote {args.out / 'triage_scorecard.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
