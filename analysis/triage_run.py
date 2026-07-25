"""Run triage over a CP8 output directory and write the advisory (CP9).

Reads the five per-stage artifact files CP8 wrote, triages each bucket, and emits
the GHSA-format advisory plus the discard log.

**Dedup has already happened by the time this runs, and that is the point.**
Section 10 lists sending un-deduplicated crashes to the LLM as an anti-pattern,
and section 7.3 says the grant is wasted by thousands of duplicate crashes rather
than by a few extra tokens per prompt. On the measured set this is one call per
bucket -- 4 -- instead of one per crash -- 53.

Run:
    python -m analysis.triage_run --evidence artifacts/runs/gate8 --label gate9
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from analysis.classify import Classification
from analysis.report import write_report
from analysis.reverse import CrashContext
from analysis.triage import SignalBundle, TriageProgram, configure_dspy
from arch.contracts import CrashBucket, ReplayResult, TraceRef, TriageVerdict

REPO_ROOT = Path(__file__).resolve().parents[1]

__all__ = ["load_evidence", "triage_all"]


def load_evidence(evidence: Path) -> dict:
    """The five CP8 artifact files, keyed by bucket id."""

    def load(name: str, model):
        path = evidence / name
        if not path.exists():
            raise SystemExit(
                f"{path} is missing. Run: python -m analysis.pipeline "
                f"--target-dir <target> --label {evidence.name}"
            )
        return [
            model.model_validate(item)
            for item in json.loads(path.read_text(encoding="utf-8"))
        ]

    buckets = load("buckets.json", CrashBucket)
    return {
        "buckets": {b.bucket_id: b for b in buckets},
        "order": [b.bucket_id for b in buckets],
        "classifications": {
            c.bucket_id: c for c in load("classifications.json", Classification)
        },
        "replays": {r.bucket_id: r for r in load("replays.json", ReplayResult)},
        "traces": {t.bucket_id: t for t in load("traces.json", TraceRef)},
        "contexts": {c.bucket_id: c for c in load("contexts.json", CrashContext)},
        "summary": json.loads((evidence / "summary.json").read_text(encoding="utf-8")),
    }


def triage_all(
    evidence: dict,
    *,
    crashes_dir: Path | None = None,
    program: TriageProgram | None = None,
) -> list[TriageVerdict]:
    """One triage call per bucket, in the order dedup ranked them."""
    program = program or TriageProgram(use_cot=True)
    verdicts: list[TriageVerdict] = []

    for bucket_id in evidence["order"]:
        bucket = evidence["buckets"][bucket_id]
        reproducer = ""
        if crashes_dir is not None:
            needle = f"{bucket.representative.fault_runtime_addr:#x}"
            for candidate in sorted(crashes_dir.glob("*")):
                if candidate.is_file() and needle in candidate.name:
                    if candidate.read_bytes() == bucket.representative.input_bytes:
                        reproducer = str(candidate.relative_to(REPO_ROOT))
                        break

        bundle = SignalBundle(
            bucket=bucket,
            classification=evidence["classifications"][bucket_id],
            replay=evidence["replays"][bucket_id],
            trace=evidence["traces"].get(bucket_id),
            context=evidence["contexts"].get(bucket_id),
            reproducer_path=reproducer,
        )
        if bundle.missing:
            print(f"  {bucket_id}: MISSING signals {bundle.missing}")
        verdicts.append(program(bundle))
    return verdicts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--evidence", type=Path, default=REPO_ROOT / "artifacts/runs/gate8")
    ap.add_argument("--label", default="gate9")
    ap.add_argument("--target-dir", type=Path, default=REPO_ROOT / "targets/snapfuzz-gate7")
    ap.add_argument("--module", default="snapfuzz")
    args = ap.parse_args(argv)

    target_config = yaml.safe_load(
        (REPO_ROOT / "config" / "target.yaml").read_text(encoding="utf-8")
    )["target"]

    evidence = load_evidence(args.evidence)
    print(f"triaging {len(evidence['order'])} bucket(s) from {args.evidence}")

    configure_dspy(role="triage")
    verdicts = triage_all(
        evidence, crashes_dir=args.target_dir / "crashes"
    )

    out_dir = REPO_ROOT / "artifacts" / "runs" / args.label
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "verdicts.json").write_text(
        json.dumps([json.loads(v.model_dump_json()) for v in verdicts], indent=2),
        encoding="utf-8",
    )

    report_path, discard_path = write_report(
        verdicts,
        buckets=evidence["buckets"],
        classifications=evidence["classifications"],
        replays=evidence["replays"],
        traces=evidence["traces"],
        contexts=evidence["contexts"],
        out_dir=out_dir,
        target=Path(target_config.get("binary", "target")).name,
        module=args.module,
        entry=target_config.get("entry_symbol")
        or target_config.get("symbol")
        or "unknown",
        crashes=evidence["summary"]["crashes"],
    )

    for verdict in verdicts:
        print(
            f"  {verdict.bucket_id[:26]:<28} {verdict.verdict:<15} "
            f"conf={verdict.confidence:.2f} {verdict.exploitability:<13} "
            f"{verdict.cwe_guess or '-'}"
        )
    confirmed = sum(1 for v in verdicts if v.verdict == "confirmed")
    print(
        f"\nconfirmed {confirmed}, discarded {len(verdicts) - confirmed}\n"
        f"advisory: {report_path}\ndiscards: {discard_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
