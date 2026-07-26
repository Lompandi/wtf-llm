"""Shared helpers for the checkpoint gates.

One helper, and it exists because of a real failure. GATE 7's coverage-increase
criterion -- the one thing that gate asks for -- was expressed as `pytest.skip`.
That is right for development: the recorded round genuinely added no new blocks,
and pretending otherwise would be worse. But it means `pytest tests/gates` exits
0 while the criterion is unmet, and "473 passed" then reads as a passing gate
(D-067).

So the same call site has to behave differently depending on what is being asked:

* **development** -- skip, with the reason printed. A missing artifact or an
  unspent allocation is not a code defect.
* **strict gate** -- fail. RULE 3 says a gate proves the interfaces are actually
  wired, and an assertion that did not run proves nothing.

`SNAPFUZZ_STRICT_GATE=1` selects the second. `tools/gates.py` reads the same
variable and additionally reports which section 8 condition each skip belongs to,
so a gate is `incomplete` rather than `pass` either way -- this helper makes the
raw `pytest` invocation agree with the runner instead of contradicting it.
"""

from __future__ import annotations

import os

import pytest

__all__ = ["STRICT_GATE", "missing_gate_evidence"]

STRICT_GATE = os.environ.get("SNAPFUZZ_STRICT_GATE") == "1"


def missing_gate_evidence(reason: str) -> None:
    """Skip in development, fail under SNAPFUZZ_STRICT_GATE=1. Never returns.

    Call this instead of `pytest.skip` wherever the thing being skipped is a
    CLAUDE.md section 8 gate condition rather than an optional extra. The
    difference is whether a green suite is allowed to stand in for the gate.
    """
    if STRICT_GATE:
        pytest.fail(f"GATE EVIDENCE MISSING: {reason}", pytrace=False)
    pytest.skip(reason)
