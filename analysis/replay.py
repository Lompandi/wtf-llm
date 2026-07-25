"""Deterministic replay (CLAUDE.md CP8, edges 35-36, triage signal 3).

Re-runs a bucket representative N times and reports whether the crash reproduces
and whether it is deterministic.

**NO LLM IN THIS MODULE.**

Always bochscpu
---------------
Section 13.5: bochscpu is the only **fully deterministic** backend. ``whv`` and
``kvm`` are deterministic only if sources of nondeterminism have been handled by
hand -- the README's own example is patching a function that uses ``rdrand``. So a
crash found on ``kvm`` that will not reproduce may be *backend nondeterminism
rather than a property of the bug*, and section 10 lists concluding otherwise as
an anti-pattern. Non-reproducing cases are always re-checked here, on bochscpu,
before any conclusion is drawn, and **a non-reproducing crash is not
automatically benign**. ``ReplayResult`` enforces part of this itself: its
validator requires the word "bochscpu" in ``notes`` when the backend is whv or kvm.

How the fault address is recovered, and why it is not obvious
------------------------------------------------------------
`wtf run` reports a crash only as ``crash: 1`` in its final stat line. It does
**not** print the fault address, and it does not write a crash file -- the ``run``
verb has no ``--crashes`` option, and the crash directory is unchanged after a
crashing run (both measured). So determinism, which section 8 defines as "same
fault address across N replays", cannot be read off wtf's output at all.

It is recovered from a rip trace instead, by
:func:`analysis.trace.fault_address_from_trace`: the fault is the last user-mode
address before the final user->kernel transition, because control passes to the
kernel's exception dispatcher and the trace continues for thousands of
instructions past the fault. Verified against the address wtf itself put in the
crash filename, on three crashes with different addresses (D-051).

That also buys a **stronger** determinism check than the contract asks for. Since
bochscpu is deterministic, two runs of the same input should produce a
byte-identical trace -- measured, on three crashes, and they do. Identical traces
mean identical execution, not merely an identical endpoint, so both are reported:
``deterministic`` follows the contract's definition, and the notes say whether the
whole execution matched.

A timeout is neither a crash nor an end-of-testcase (DECISIONS R5). It is a
fourth outcome and is reported as one, never folded into "did not reproduce" --
an input that ran out of instruction budget has told us nothing about the crash.
"""

from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from arch.contracts import Backend, CrashBucket, ReplayResult
from analysis.trace import (
    TraceError,
    TraceTarget,
    fault_address_from_trace,
    generate_trace,
)

__all__ = ["ReplayError", "Attempt", "replay_input", "replay_bucket"]

DEFAULT_REPLAYS = 3


class ReplayError(RuntimeError):
    pass


@dataclass
class Attempt:
    """One replay. ``fault_addr`` is None when the run did not fault."""

    index: int
    fault_addr: int | None
    trace_digest: str
    trace_lines: int
    ran: bool = True
    note: str = ""


@dataclass
class ReplayPlan:
    """Everything a replay needs. Mirrors TraceTarget plus the knobs."""

    target: TraceTarget
    workdir: Path
    backend: Backend = "bochscpu"
    replays: int = DEFAULT_REPLAYS
    limit: int = 200_000_000
    keep_traces: bool = False
    _made: list[Path] = field(default_factory=list, init=False)


def replay_input(input_path: Path, plan: ReplayPlan) -> list[Attempt]:
    """Run one input ``plan.replays`` times, returning what each run did.

    Distinguishes "ran and did not fault" from "did not run". The second is the
    D-042 shape: wtf failing to start looks exactly like a clean run unless the
    two are separated, and a replay that silently reports "not reproduced"
    because the harness never initialised would send triage the opposite of the
    truth.
    """
    if not input_path.exists():
        raise ReplayError(
            f"{input_path} no longer exists, so this bucket cannot be replayed. "
            f"That is not the same as 'did not reproduce' and must not be "
            f"recorded as one."
        )

    attempts: list[Attempt] = []
    for index in range(1, plan.replays + 1):
        trace_dir = plan.workdir / f"replay{index:02d}"
        if trace_dir.exists():
            shutil.rmtree(trace_dir)
        trace_dir.mkdir(parents=True, exist_ok=True)

        try:
            trace = generate_trace(
                plan.target,
                input_path,
                trace_dir,
                trace_type="rip",
                backend=plan.backend,
                limit=plan.limit,
            )
        except TraceError as exc:
            # wtf did not produce a trace. Recording this as a non-reproduction
            # would be a lie; it is an absence of evidence.
            attempts.append(
                Attempt(
                    index=index,
                    fault_addr=None,
                    trace_digest="",
                    trace_lines=0,
                    ran=False,
                    note=f"wtf produced no trace: {exc}",
                )
            )
            continue

        data = trace.read_bytes()
        attempts.append(
            Attempt(
                index=index,
                fault_addr=fault_address_from_trace(trace),
                trace_digest=hashlib.sha256(data).hexdigest()[:16],
                trace_lines=data.count(b"\n"),
            )
        )
        if not plan.keep_traces:
            shutil.rmtree(trace_dir, ignore_errors=True)

    return attempts


def replay_bucket(
    bucket: CrashBucket,
    input_path: Path,
    plan: ReplayPlan,
) -> ReplayResult:
    """Replay a bucket's representative and build its ReplayResult."""
    attempts = replay_input(input_path, plan)

    ran = [a for a in attempts if a.ran]
    faulted = [a for a in ran if a.fault_addr is not None]
    addresses = {a.fault_addr for a in faulted}
    digests = {a.trace_digest for a in ran if a.trace_digest}

    reproduced = bool(faulted)
    # The contract's definition: the same fault address every time it faulted,
    # and it faulted on every run that actually ran. One run out of three is not
    # determinism, it is a coin landing the same way once.
    deterministic = bool(faulted) and len(addresses) == 1 and len(faulted) == len(ran)

    notes: list[str] = []
    if not ran:
        notes.append(
            "NO REPLAY RAN. wtf produced no trace on any attempt, so this is an "
            "absence of evidence, not a non-reproduction. First error: "
            + next((a.note for a in attempts if a.note), "unknown")
        )
    elif not reproduced:
        notes.append(
            f"ran {len(ran)} time(s) on {plan.backend} and never faulted. A "
            f"non-reproducing crash is NOT automatically benign (section 10): it "
            f"may depend on state this snapshot does not carry."
        )
    else:
        where = ", ".join(f"{a:#x}" for a in sorted(addresses))
        notes.append(f"faulted at {where} on {len(faulted)}/{len(ran)} run(s)")

    if len(ran) > 1:
        if len(digests) == 1:
            notes.append(
                "every replay produced a BYTE-IDENTICAL rip trace, so the whole "
                "execution matched, not just the fault address -- the strongest "
                "determinism evidence bochscpu can give"
            )
        else:
            notes.append(
                f"replays produced {len(digests)} distinct trace digests. On "
                f"bochscpu that should be impossible (section 13.5), so suspect "
                f"the harness or residual state rather than the target."
            )

    if len(ran) < len(attempts):
        notes.append(f"{len(attempts) - len(ran)} attempt(s) failed to run at all")

    if plan.backend != "bochscpu":
        # ReplayResult's own validator requires this word; say something true
        # rather than satisfying the validator with a token.
        notes.append(
            f"backend was {plan.backend}, which is not deterministic by default; "
            f"re-check on bochscpu before drawing any conclusion"
        )

    return ReplayResult(
        bucket_id=bucket.bucket_id,
        reproduced=reproduced,
        deterministic=deterministic,
        replays=len(attempts),
        backend=plan.backend,
        notes=" | ".join(notes),
    )
