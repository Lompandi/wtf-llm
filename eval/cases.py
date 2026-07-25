"""Labelled triage cases and the train / held-out split (CLAUDE.md CP9, CP10).

What this is, and what it is not
-------------------------------
CLAUDE.md asks for ``eval/planted_bugs/`` -- "targets with deliberately
introduced, documented bugs" -- serving two purposes: DSPy training and triage
accuracy measurement.

**This is the second purpose only, and it is not the same thing.** Building
planted-bug *targets* requires taking a snapshot of each new binary, and snapshot
acquisition is outside this checkpoint (edges 1/6/7 are still pending; the
snapshot in use was produced by someone else). So what exists here is a set of
labelled **triage cases**: the five signals plus a ground-truth verdict. That is
exactly what triage consumes -- it never sees a binary -- so the measurement is
sound for what it measures, and it is *not* an end-to-end claim about finding
planted bugs.

Where the labels come from
--------------------------
* ``origin="measured"`` -- real buckets from a real campaign on tlv_server. Their
  labels are ground truth because the target's own source is available (it ships
  as a wtf example) and states the bug: ``ProcessPacket`` trusts the packet's
  ``BodySize`` and ``memcpy``s that many bytes without checking it against what
  arrived or against the destination's size. The **pipeline** never sees that
  source; only the labeller did.
* ``origin="synthetic"`` -- hand-constructed signal combinations for benign
  patterns, each with a written rationale.

**The synthetic negatives are the weak point and must be stated as one.** They
were written by the same person who wrote the triage prompt, so a model can score
well by recognising the construction rather than the reasoning. Precision and
recall over a set containing them is therefore *not* a claim about real-world
performance. There is no honest way around this without either planted-bug
targets or a corpus of real triage false positives, and neither exists yet.

The split
---------
Section 8/CP9 and section 10: optimising prompts on the same split used for
reported metrics is invalid. The split is deterministic -- a sorted hash of the
case id, not a random seed -- so it cannot drift between a training run and a
reporting run, and it is recorded in DECISIONS.md.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from analysis.classify import Classification
from analysis.reverse import CrashContext
from arch.contracts import CrashBucket, ReplayResult, TraceRef

REPO_ROOT = Path(__file__).resolve().parents[1]
CASES_DIR = REPO_ROOT / "eval" / "planted_bugs"

__all__ = [
    "TriageCase",
    "CASES_DIR",
    "load_cases",
    "split_cases",
    "assigned_split",
]


class TriageCase(BaseModel):
    """One labelled triage case: the five signals plus ground truth."""

    case_id: str
    origin: Literal["measured", "synthetic"]

    label: Literal["confirmed", "false_positive"]
    label_rationale: str = Field(
        description="why this label is ground truth, in prose a reviewer can check"
    )
    expected_cwe: str | None = None
    expected_exploitability: Literal["dos", "info_leak", "possible_rce", "unknown"] = (
        "unknown"
    )

    # The five independent signals (section 3.2, edges 38-41b). Signals 4 and 5
    # stay separate: one dynamic, one static, uncorrelated errors.
    bucket: CrashBucket  # signal 1
    classification: Classification  # signal 2
    replay: ReplayResult  # signal 3
    trace: TraceRef | None = None  # signal 4
    context: CrashContext | None = None  # signal 5

    @model_validator(mode="after")
    def _ids_agree(self) -> "TriageCase":
        """Every signal must describe the SAME bucket.

        A case that mixes signals from different crashes would train and score a
        model on a contradiction while looking perfectly well-formed.
        """
        expected = self.bucket.bucket_id
        for name, signal in (
            ("classification", self.classification),
            ("replay", self.replay),
            ("trace", self.trace),
            ("context", self.context),
        ):
            if signal is None:
                continue
            actual = getattr(signal, "bucket_id", expected)
            if actual and actual != expected:
                raise ValueError(
                    f"{name} describes bucket {actual!r} but the case is for "
                    f"{expected!r}; signals must not be mixed across crashes"
                )
        return self

    @property
    def available_signals(self) -> list[str]:
        """Which of the five this case actually carries."""
        present = ["dedup", "classification", "replay"]
        if self.trace is not None:
            present.append("symbolize_trace")
        if self.context is not None:
            present.append("reverse_engineer")
        return present


def assigned_split(case_id: str, *, train_fraction: float = 0.5) -> str:
    """Deterministic train / heldout assignment from the case id.

    A hash, not ``random.seed``: a seeded shuffle depends on the *set* of cases,
    so adding one case would silently reshuffle the rest and move cases across the
    boundary between an optimisation run and a reporting run. Hashing each id
    independently means a case's side never changes once assigned.
    """
    digest = hashlib.sha256(case_id.encode()).digest()
    position = int.from_bytes(digest[:4], "big") / 0xFFFF_FFFF
    return "train" if position < train_fraction else "heldout"


def load_cases(directory: Path = CASES_DIR) -> list[TriageCase]:
    """Every ``*.json`` case in ``directory``, sorted by id."""
    cases = [
        TriageCase.model_validate_json(path.read_text(encoding="utf-8"))
        for path in sorted(directory.glob("*.json"))
    ]
    ids = [c.case_id for c in cases]
    if len(set(ids)) != len(ids):
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        raise ValueError(f"duplicate case ids: {duplicates}")
    return sorted(cases, key=lambda c: c.case_id)


def split_cases(
    cases: list[TriageCase], *, train_fraction: float = 0.5
) -> tuple[list[TriageCase], list[TriageCase]]:
    """(train, heldout). Optimise on train, report on heldout. Never both."""
    train = [c for c in cases if assigned_split(c.case_id, train_fraction=train_fraction) == "train"]
    heldout = [c for c in cases if c not in train]
    return train, heldout


def write_case(case: TriageCase, directory: Path = CASES_DIR) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{case.case_id}.json"
    path.write_text(
        json.dumps(json.loads(case.model_dump_json()), indent=2), encoding="utf-8"
    )
    return path
