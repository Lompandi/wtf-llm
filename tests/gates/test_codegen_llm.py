"""The model writes the module C++, and what catches a bad generation before MSVC does.

`fuzzer/codegen_llm.py` reverses the split `fuzzer/codegen.py` argues for: instead of the
model filling an InputSpec and deterministic code rendering C++, the model writes the
translation unit. That was the project owner's call after comparing both outputs.

The objection to it is real and unchanged -- a compile error from model-written C++ lands
far from the mistake, and free-form C++ cannot be schema-validated. What makes it workable
is that the check is not a schema:

* it must **compile**, under `/WX`, in the real wtf tree (stage 10);
* the campaign built from it must **produce coverage** (stage 11's verify hook);
* `--codegen template` is one flag away.

Those are stronger than schema-validity, which a harness that never delivers input can
satisfy. This file tests the cheap structural gate that runs BEFORE the compiler, so that
"the model returned prose" produces a message about prose rather than four hundred lines
of MSVC output.

**No network.** Every test here feeds `check_generated` text directly. Whether the live
550B produces something that compiles is not decidable offline, and at the time of
writing the endpoint was returning HTTP 500 for every role, so it is not decided here
either -- stated rather than implied by a green suite.
"""

from __future__ import annotations

import pytest

from arch.contracts import HarnessBreakpoint, HarnessSpec
from fuzzer.codegen_llm import _strip_fence, check_generated


def _harness(**overrides) -> HarnessSpec:
    settings = dict(
        module="tlv_server",
        target_name="snapfuzz_gen",
        entry_symbol="tlv_server!ProcessPacket",
        input_param="rcx",
        size_param="rdx",
        breakpoints=[
            HarnessBreakpoint(
                symbol="tlv_server!ProcessPacket",
                purpose="fuzz_entry",
                action="deliver_next_input",
                rva=0x1150,
            )
        ],
    )
    settings.update(overrides)
    return HarnessSpec(**settings)


GOOD = """
#include <cstdint>
#include "backend.h"

namespace Gen {
bool InsertTestcase(const uint8_t *Buffer, const size_t BufferSize) { return true; }
bool Restore() { return true; }
bool Init(const Options_t &Opts, const CpuState_t &) {
  SetupUsermodeCrashDetectionHooks();
  if (!g_Backend->SetBreakpoint(Gva_t(g_Dbg->GetModuleBase("tlv_server") + 0x1150),
                                [](Backend_t *B) { }))
    return false;
  return true;
}
}
Target_t GenTarget("snapfuzz_gen", Gen::Init, Gen::InsertTestcase, Gen::Restore,
                   CustomMutator_t::Create);
"""


def test_a_good_module_passes() -> None:
    """The control. Without it, every assertion below could be passing vacuously."""
    assert check_generated(GOOD, _harness()) == []


def test_an_empty_answer_is_reported_as_empty() -> None:
    problems = check_generated("", _harness())
    assert problems and "returned nothing" in problems[0]


def test_a_missing_registration_is_caught() -> None:
    """Without `Target_t`, wtf does not know the module exists and `--name` fails.

    Worth catching here because the failure otherwise arrives as `Existing targets:` and
    a list that does not include yours -- true, and unhelpful about why.
    """
    problems = check_generated(GOOD.replace('Target_t GenTarget("snapfuzz_gen"', 'Target_t GenTarget("something_else"'), _harness())
    assert any("Target_t registration" in p for p in problems)


def test_a_missing_entry_point_is_caught() -> None:
    for entry in ("Init", "InsertTestcase", "Restore"):
        broken = GOOD.replace(f"{entry}(", f"Renamed{entry}(")
        problems = check_generated(broken, _harness())
        assert any(entry in p for p in problems), f"{entry} removal not caught"


def test_a_missing_crash_oracle_is_caught() -> None:
    """No `SetupUsermodeCrashDetectionHooks` means crashes are not detected.

    The campaign then runs, reports coverage, and finds nothing -- which reads as "no
    bugs" rather than as "the oracle was never installed".
    """
    problems = check_generated(GOOD.replace("SetupUsermodeCrashDetectionHooks();", ""), _harness())
    assert any("CrashDetection" in p for p in problems)


def test_non_ascii_is_caught_because_msvc_rejects_it() -> None:
    """D-054, measured: a model wrote "4-byte" with U+2011 and the build failed C4819.

    Under `/WX` on a non-UTF-8 codepage that is an error, so model prose would decide
    whether the artifact compiles.
    """
    problems = check_generated(GOOD + "\n// a non‑breaking hyphen\n", _harness())
    assert any("non-ASCII" in p and "U+2011" in p for p in problems)


def test_a_markdown_fence_is_caught() -> None:
    problems = check_generated("```cpp\n" + GOOD + "\n```", _harness())
    assert any("markdown fence" in p for p in problems)


def test_symbol_resolved_breakpoints_are_caught_when_the_spec_has_rvas() -> None:
    """The bug that killed a whole campaign (D-075).

    A stripped target has no symbols for dbgeng, so `SetBreakpoint("mod!FUN_140001150")`
    fails, every worker dies in Init, and the campaign reports zero executions. When the
    spec carries RVAs the code has to use them.
    """
    by_name = GOOD.replace(
        'Gva_t(g_Dbg->GetModuleBase("tlv_server") + 0x1150)', '"tlv_server!ProcessPacket"'
    )
    problems = check_generated(by_name, _harness())
    assert any("GetModuleBase" in p for p in problems)

    # And it is not demanded when the spec has no RVA to use.
    no_rva = _harness(
        breakpoints=[
            HarnessBreakpoint(
                symbol="tlv_server!ProcessPacket",
                purpose="fuzz_entry",
                action="deliver_next_input",
            )
        ]
    )
    assert check_generated(by_name, no_rva) == []


@pytest.mark.parametrize(
    "wrapped",
    [
        "```cpp\nint main() {}\n```",
        "```c++\nint main() {}\n```",
        "```\nint main() {}\n```",
        "Here is the code:\n```cpp\nint main() {}\n```\nHope that helps.",
    ],
)
def test_a_fence_is_stripped_rather_than_compiled(wrapped: str) -> None:
    """Models fence code even when told not to.

    Not indulgence: the alternative is a file whose first line is ```cpp, which fails to
    compile for a reason that says nothing about the harness.
    """
    assert _strip_fence(wrapped).strip() == "int main() {}"


def test_unfenced_text_is_left_alone() -> None:
    assert _strip_fence(GOOD) == GOOD


def test_the_prompt_carries_the_rva_and_the_legacy_names() -> None:
    """Two things the model cannot infer and must be told.

    The RVA, because a stripped target has no symbol to resolve; and the legacy field
    names, because a recorded corpus was written with them and `from_json` has to accept
    them or 149 files stop parsing (edge 14).
    """
    from arch.contracts import InputField, InputSpec
    from fuzzer.codegen_llm import _prompt

    spec = InputSpec(
        module="tlv_server",
        entry_symbol="ProcessPacket",
        struct_name="Packet_t",
        fields=[
            InputField(
                name="Cmd", kind="scalar", ctype="uint32_t", legacy_names=["Command"]
            ),
            # A length field, because InputSpec refuses a variable-length field without
            # one: "either the spec is missing one, or the parser delimits them some
            # other way". That validator is right, and it rejected the first version of
            # this fixture.
            InputField(
                name="PayloadSize",
                kind="length",
                ctype="uint16_t",
                counts_field="Payload",
                unit="bytes",
                legacy_names=["BodySize"],
            ),
            InputField(name="Payload", kind="bytes", legacy_names=["Body"]),
        ],
    )
    prompt = _prompt(spec, _harness(), example="")
    assert "0x1150" in prompt, "the RVA is not in the prompt"
    assert "Command" in prompt, "the legacy name is not in the prompt"
    assert "snapfuzz_gen" in prompt, "the target name to register is not in the prompt"
