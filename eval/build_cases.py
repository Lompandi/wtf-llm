"""Build the labelled triage case set (CLAUDE.md CP9).

Positives come from the CP8 pipeline's real output; negatives are constructed and
labelled as such. Read :mod:`eval.cases` for what this set does and does not
claim -- in particular, the synthetic negatives are a stated weakness, not a
detail.

Run: ``python -m eval.build_cases``
"""

from __future__ import annotations

import json
from pathlib import Path

from analysis.classify import Classification
from analysis.reverse import CrashContext
from arch.contracts import CrashBucket, CrashRecord, ReplayResult, TraceRef
from eval.cases import CASES_DIR, TriageCase, assigned_split, write_case

REPO_ROOT = Path(__file__).resolve().parents[1]
GATE8 = REPO_ROOT / "artifacts" / "runs" / "gate8"

# tlv_server's actual defect, from the target's own source. The pipeline never
# reads this; it is the labeller's justification.
BODYSIZE_BUG = (
    "ProcessPacket reads the packet's 16-bit BodySize field and memcpy's that "
    "many bytes without validating it against either how much data actually "
    "arrived or the size of the destination buffer. Confirmed against the "
    "target's own source, which ships as a wtf example; the pipeline itself only "
    "ever saw Ghidra pseudo-C."
)


def _measured_cases() -> list[TriageCase]:
    """One case per real bucket from the CP8 run."""
    if not (GATE8 / "buckets.json").exists():
        raise SystemExit(
            f"{GATE8} has no CP8 output. Run: python -m analysis.pipeline "
            f"--target-dir targets/snapfuzz-gate7 --label gate8"
        )

    def load(name: str, model):
        return [
            model.model_validate(item)
            for item in json.loads((GATE8 / name).read_text(encoding="utf-8"))
        ]

    buckets = load("buckets.json", CrashBucket)
    classifications = {c.bucket_id: c for c in load("classifications.json", Classification)}
    replays = {r.bucket_id: r for r in load("replays.json", ReplayResult)}
    traces = {t.bucket_id: t for t in load("traces.json", TraceRef)}
    contexts = {c.bucket_id: c for c in load("contexts.json", CrashContext)}

    cases: list[TriageCase] = []
    for index, bucket in enumerate(buckets, start=1):
        write = "write" in bucket.key_detail

        # A write past the end of a heap buffer is a different severity from a
        # read past the end of a packet, and the label set must not blur them.
        if write:
            cwe, exploitability = "CWE-787", "possible_rce"
            detail = (
                "Out-of-bounds WRITE: the Edit path copies BodySize bytes into a "
                "chunk buffer allocated for a size chosen by an earlier packet, so "
                "a later packet can specify more. Heap overflow."
            )
        else:
            cwe, exploitability = "CWE-125", "info_leak"
            detail = (
                "Out-of-bounds READ: BodySize exceeds the bytes actually delivered, "
                "so memcpy reads past the end of the packet buffer. The 70-byte "
                "reproducer declares BodySize 8 with an empty Body."
            )

        cases.append(
            TriageCase(
                case_id=f"measured-{index:02d}-{'write' if write else 'read'}",
                origin="measured",
                label="confirmed",
                label_rationale=f"{detail} {BODYSIZE_BUG}",
                expected_cwe=cwe,
                expected_exploitability=exploitability,
                bucket=bucket,
                classification=classifications[bucket.bucket_id],
                replay=replays[bucket.bucket_id],
                trace=traces.get(bucket.bucket_id),
                context=contexts.get(bucket.bucket_id),
            )
        )
    return cases


# A FIXED timestamp for synthetic records, not time.time().
#
# These cases are committed, so a wall-clock stamp makes every rebuild produce
# different bytes for semantically identical content: the files churn in git and a
# real edit becomes indistinguishable from a re-run. A synthetic crash has no
# meaningful time of occurrence anyway. 2026-01-01T00:00:00Z, chosen only for being
# obviously not a measurement.
SYNTHETIC_TIMESTAMP = 1767225600.0


def _record(**kw) -> CrashRecord:
    base = dict(
        input_bytes=b"{}",
        fault_type="access-violation-read",
        fault_runtime_addr=0,
        fault_static_addr=0,
        registers={},
        backtrace=[],
        coverage_delta=0,
        backend="bochscpu",
        timestamp=SYNTHETIC_TIMESTAMP,
    )
    base.update(kw)
    return CrashRecord(**base)


def _synthetic_cases() -> list[TriageCase]:
    """Benign patterns, each with the reason it is benign written down.

    These are the categories a binary-only fuzzer genuinely produces and that a
    human triager dismisses. They are still CONSTRUCTED, and eval/cases.py says
    what that costs.
    """
    cases: list[TriageCase] = []

    def add(
        case_id: str,
        *,
        rationale: str,
        record: CrashRecord,
        key_detail: str,
        classification_kw: dict,
        replay_kw: dict,
        context: CrashContext | None,
        exploitability: str = "unknown",
        trace: TraceRef | None = None,
    ) -> None:
        bucket_id = f"synthetic-{case_id}"
        bucket = CrashBucket(
            bucket_id=bucket_id,
            representative=record,
            hit_count=1,
            key_kind="fault_function",
            key_detail=key_detail,
        )
        classification = Classification(
            bucket_id=bucket_id,
            fault_type=record.fault_type,
            **classification_kw,
        )
        replay = ReplayResult(
            bucket_id=bucket_id, backend="bochscpu", **replay_kw
        )
        if context is not None:
            context = context.model_copy(update={"bucket_id": bucket_id})
        if trace is not None:
            trace = trace.model_copy(update={"bucket_id": bucket_id})
        cases.append(
            TriageCase(
                case_id=case_id,
                origin="synthetic",
                label="false_positive",
                label_rationale=rationale,
                expected_cwe=None,
                expected_exploitability=exploitability,
                bucket=bucket,
                classification=classification,
                replay=replay,
                trace=trace,
                context=context,
            )
        )

    # NOTE on a case that is deliberately NOT here. An earlier version of this set
    # included a fuzzer-induced out-of-memory null dereference inside
    # operator_new's bad_alloc path, labelled false_positive on the grounds that
    # it is not attacker-interesting. Triage called it `confirmed` with CWE-690
    # (unchecked return value to null dereference) and that reading is
    # defensible -- an unchecked allocation result IS a defect. The ground truth
    # was contestable, so the case was measuring the labeller's opinion rather
    # than the model's reasoning, and it was removed rather than kept as a case
    # the model "fails". See DECISIONS.md.
    add(
        "synthetic-01-never-entered-target",
        rationale=(
            "The trace shows execution never reached the fuzz entry, so whatever "
            "faulted, it was not the target's parser -- this crash is about the "
            "harness or the snapshot's surrounding state. TraceRef.reached_fuzz_"
            "entry exists precisely to make this checkable, and CP4 treats a "
            "harness that never enters the parser as the classic silent failure. "
            "Unambiguous: a finding about code that did not run cannot be a "
            "finding about the target."
        ),
        record=_record(fault_runtime_addr=0x7FF8_1111_2222, input_bytes=b"\xff\xfe not json"),
        key_detail="access-violation-read|ntdll.dll!RtlpAllocateHeapInternal",
        classification_kw=dict(
            access="read",
            fault_runtime_addr=0x7FF8_1111_2222,
            near_null=False,
            wild=True,
            attacker_influenced=False,
            registers_available=False,
            notes=[
                "the fault is not attributable to the target module",
                "no disassembly available",
            ],
        ),
        replay_kw=dict(
            reproduced=True,
            deterministic=True,
            replays=3,
            notes="faulted at 0x7ff811112222 on 3/3 run(s)",
        ),
        context=CrashContext(
            function=None,
            context_frame=None,
            faulting_frame="ntdll.dll!RtlpAllocateHeapInternal+0x40",
            pseudo_c_source="unavailable",
            in_module_call_path=[],
            notes=[
                "the trace's approach path contains no frame in 'tlv_server'. "
                "Either the harness never entered the target (check "
                "TraceRef.reached_fuzz_entry) or the module prefix is wrong."
            ],
        ),
        # The signal that makes this case unambiguous. Without it the case would
        # merely be "a fault in ntdll", which is not benign on its own.
        trace=TraceRef(
            bucket_id="placeholder",
            trace_type="rip",
            raw_path="artifacts/analysis/synthetic/never-entered.trace",
            symbolized_path="artifacts/runs/synthetic/never-entered.rip.txt",
            reached_fuzz_entry=False,
        ),
    )

    add(
        "synthetic-02-timeout-misfiled",
        rationale=(
            "A timeout, not a crash. DECISIONS R5 settles that a timeout is a "
            "fourth outcome alongside crash, end-of-testcase and CR3 change -- it "
            "means the input exhausted the instruction budget and tells us nothing "
            "about memory safety. There is no fault address at all, so every "
            "derived judgement is unknown, and treating it as a finding would be "
            "reporting the absence of evidence as evidence."
        ),
        record=_record(fault_type="timeout", fault_runtime_addr=0),
        key_detail="timeout",
        classification_kw=dict(
            access="unknown",
            near_null=None,
            wild=None,
            attacker_influenced=None,
            registers_available=False,
            notes=["no fault address is recorded", "fault type does not name read or write"],
        ),
        replay_kw=dict(
            reproduced=False,
            deterministic=False,
            replays=3,
            notes=(
                "ran 3 time(s) on bochscpu and never faulted -- it timed out. A "
                "non-reproducing crash is NOT automatically benign, but a timeout "
                "is a distinct outcome (R5)."
            ),
        ),
        context=None,
    )

    add(
        "synthetic-03-harness-frame",
        rationale=(
            "The fault is inside our own injected harness code, not the target: "
            "the faulting frame is the fuzzer module's packet-delivery breakpoint "
            "handler, reached with an empty packet queue. It is a bug in the "
            "harness if anything, and reporting it as a target finding would be "
            "reporting our own defect as the target's."
        ),
        record=_record(fault_runtime_addr=0x7FF7_1234_5678, input_bytes=b'{"Packets":[]}'),
        key_detail="access-violation-read|snapfuzz_harness!DeliverPacket",
        classification_kw=dict(
            access="read",
            fault_runtime_addr=0x7FF7_1234_5678,
            near_null=False,
            wild=True,
            attacker_influenced=False,
            registers_available=False,
            notes=["faulting module is the harness, not the target"],
        ),
        replay_kw=dict(reproduced=True, deterministic=True, replays=3, notes="faulted at 0x7ff712345678 on 3/3 run(s)"),
        context=CrashContext(
            function=None,
            context_frame=None,
            pseudo_c_source="unavailable",
            in_module_call_path=[],
            notes=["no target-module frame on the fault path"],
        ),
    )

    add(
        "synthetic-04-weak-influence-only",
        rationale=(
            "The only evidence of attacker influence is a 2-byte match, which "
            "occurs by chance in almost any binary input -- classify.py flags this "
            "explicitly as weak. Everything else points away from a bug: the fault "
            "is a near-null read on a path that does not consume packet data, and "
            "the input byte that 'matched' is a length field that is never used as "
            "a pointer. Accepting a 2-byte coincidence as influence is the mistake "
            "this case exists to catch."
        ),
        record=_record(fault_runtime_addr=0x1234, input_bytes=b"\x34\x12rest-of-input"),
        key_detail="access-violation-read|tlv_server.exe!printf",
        classification_kw=dict(
            access="read",
            fault_runtime_addr=0x1234,
            near_null=True,
            wild=False,
            attacker_influenced=True,
            influence_offsets=[0],
            influence_widths=[2],
            registers_available=False,
            notes=[
                "the only matches are 2 bytes wide, which occurs by chance in most "
                "binary inputs; treat this as weak evidence of influence"
            ],
        ),
        replay_kw=dict(reproduced=True, deterministic=True, replays=3, notes="faulted at 0x1234 on 3/3 run(s)"),
        context=CrashContext(
            function="printf",
            context_frame="tlv_server.exe!printf",
            pseudo_c_source="a2_cache",
            pseudo_c="void printf(char *fmt, ...) { /* CRT stdio */ }",
            in_module_call_path=["ProcessPacket", "printf"],
            notes=["fault is in stdio internals"],
        ),
    )

    return cases


def main() -> int:
    CASES_DIR.mkdir(parents=True, exist_ok=True)
    for stale in CASES_DIR.glob("*.json"):
        stale.unlink()

    cases = _measured_cases() + _synthetic_cases()
    for case in cases:
        write_case(case)

    train = [c for c in cases if assigned_split(c.case_id) == "train"]
    heldout = [c for c in cases if assigned_split(c.case_id) != "train"]

    print(f"wrote {len(cases)} case(s) to {CASES_DIR}")
    for case in cases:
        side = assigned_split(case.case_id)
        print(
            f"  [{side:<7}] {case.case_id:<30} {case.label:<15} "
            f"{case.origin:<9} signals={len(case.available_signals)}"
        )
    print(
        f"\ntrain {len(train)} / heldout {len(heldout)}   "
        f"confirmed {sum(1 for c in cases if c.label == 'confirmed')} / "
        f"false_positive {sum(1 for c in cases if c.label == 'false_positive')}"
    )
    if len(heldout) < 4:
        print(
            "\nWARNING: the held-out split is tiny. Precision and recall over it "
            "are indicative at best and must be reported with n."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
