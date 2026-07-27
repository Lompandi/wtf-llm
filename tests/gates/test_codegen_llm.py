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
  if (!g_Backend->SetBreakpoint(Gva_t(snapfuzz::ResolveModuleBase("tlv_server") + 0x1150),
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
        'Gva_t(snapfuzz::ResolveModuleBase("tlv_server") + 0x1150)',
        '"tlv_server!ProcessPacket"',
    )
    problems = check_generated(by_name, _harness())
    assert any("ResolveModuleBase" in p for p in problems)

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


# --- the three rules added after the model's second generation ---------------
#
# Each of these is a mistake the 550B actually made, on a real target, in code that
# compiled cleanly. That is the common thread: none of them is a compile error, none
# moves a coverage number, and all three end in a campaign that runs at full speed and
# finds nothing.


def test_hand_rolled_page_tail_arithmetic_is_caught() -> None:
    """A register is a POINTER, not a page base.

    Written verbatim by the model, twice, on independent generations:

        const uint64_t PageBase = Backend->Rcx();
        uint64_t Address = PageBase + (kPageSize - Bytes);

    With rcx = 0xd3d77ff7a0 that is 0xd3d7800790 -- past the end of the page, inside the
    unmapped hole. It even named the variable PageBase, so the intent was right and only
    the mask was missing. The fix is to call ResolveInputAddress rather than to mask,
    because the helper also knows the VERIFIED boundary.
    """
    hand_rolled = GOOD.replace(
        "bool Restore() { return true; }",
        "bool Restore() {\n"
        "  const uint64_t PageBase = g_Backend->Rcx();\n"
        "  uint64_t Address = PageBase + (kPageSize - Bytes);\n"
        "  return true;\n"
        "}",
    )
    problems = check_generated(hand_rolled, _harness())
    assert any("ResolveInputAddress" in p for p in problems), problems


def test_a_raw_register_named_like_a_page_base_is_caught_on_its_own() -> None:
    """The second check, which fires even when the arithmetic is elsewhere.

    Two checks rather than one because the two halves can appear apart: the assignment in
    Init and the addition inside a lambda. Either alone is the same bug.
    """
    problems = check_generated(
        GOOD.replace(
            "  SetupUsermodeCrashDetectionHooks();",
            "  SetupUsermodeCrashDetectionHooks();\n"
            "  const uint64_t PageBase = g_Backend->Rcx();",
        ),
        _harness(),
    )
    assert any("masking off the low 12 bits" in p for p in problems), problems


def test_renamed_json_keys_are_caught() -> None:
    """The keys are the corpus's wire contract, not a naming preference.

    The model wrote `Json.at("Magic")` for a spec field named `magic`. nlohmann's `at`
    THROWS on a missing key, InsertTestcase catches it, and every recorded test-case is
    reported as "not valid JSON, skipping" -- silently, at full speed, while the campaign
    reports coverage. C++ members may be named anything; the keys may not.
    """
    from arch.contracts import InputField, InputSpec

    spec = InputSpec(
        module="t",
        entry_symbol="fuzzme",
        struct_name="Packet_t",
        header_bytes=5,
        fields=[
            InputField(name="magic", kind="scalar", ctype="uint32_t"),
            InputField(name="payload_len", kind="length", ctype="uint8_t",
                       counts_field="payload", unit="bytes"),
            InputField(name="payload", kind="bytes"),
        ],
        rationale="fixture",
        source_functions=["fuzzme"],
    )

    capitalised = GOOD.replace(
        "bool Restore() { return true; }",
        'bool Restore() { Json.at("Magic"); Json.at("PayloadLen"); '
        'Json.at("Payload"); return true; }',
    )
    problems = check_generated(capitalised, _harness(), spec)
    assert any("field names as JSON keys" in p for p in problems), problems
    named = next(p for p in problems if "field names as JSON keys" in p)
    assert "magic" in named and "payload_len" in named

    # The control: the same module with the spec's spellings passes.
    correct = GOOD.replace(
        "bool Restore() { return true; }",
        'bool Restore() { Json.at("magic"); Json.at("payload_len"); '
        'Json.at("payload"); return true; }',
    )
    assert check_generated(correct, _harness(), spec) == []


def test_the_spec_is_optional_so_older_callers_still_work() -> None:
    """`spec` defaults to None: the field-name check is skipped, not crashed."""
    assert check_generated(GOOD, _harness()) == []


def test_the_repair_prompt_quotes_the_line_the_compiler_named() -> None:
    """A diagnostic without its line throws away a third of what makes it useful.

    Measured over five generations of one prompt: four compiled with ZERO repairs, and the
    fifth reported

        fuzzer_gen.cc(124): error C2440: cannot convert from 'uint64_t' to 'Gva_t'

    three times -- the original answer and both repairs, identical. The loop was not
    converging on that one at all, and what it had been sending explains why: the
    diagnostic named line 124, the whole file was attached, and nothing indicated which
    line 124 was. The model had to count, and regenerated the same line instead.
    """
    from fuzzer.codegen_llm import _offending_lines

    lines = [f"filler {i}" for i in range(1, 20)]
    lines[11] = "  const Gva_t Addr = ResolveModuleBase(kMod) + kRva;"
    source = "\n".join(lines)

    quoted = _offending_lines(
        source, ["fuzzer_gen.cc(12): error C2440: cannot convert from uint64_t to Gva_t"]
    )
    assert "ResolveModuleBase(kMod) + kRva" in quoted, quoted
    assert ">   12 |" in quoted, "the named line must be marked, not merely included"
    # One line either side, because the error is often reported where an expression CLOSES
    # while the mistake is where it opens.
    assert "filler 11" in quoted and "filler 13" in quoted

    # Robustness: the loop must not crash on a diagnostic it cannot parse, or on a line
    # number past the end of a file the model truncated.
    assert _offending_lines(source, ["LINK : fatal error LNK1169"]) == ""
    assert _offending_lines(source, ["fuzzer_gen.cc(9999): error C2440: x"]) == ""
    # And the same line named twice is quoted once.
    twice = _offending_lines(
        source,
        [
            "fuzzer_gen.cc(12): error C2440: a",
            "fuzzer_gen.cc(12): error C2440: b",
        ],
    )
    assert twice.count("The line MSVC named") == 1
