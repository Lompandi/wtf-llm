"""GATE 11 -- the LLM-derived input structure (edges 12 and 14).

**This gate is not in CLAUDE.md, and that is the point.** Section 3.1 draws a box
called "LLM-generated input struct / reads pseudo-C (A2) `[LLM]`" and section 3.2
gives it edges 12 and 14, but no gate in section 8 lists either edge -- GATE 4
covers 18-26/30/31, GATE 6 covers 3/4/9/28/37. Under RULE 3, "the gate is the
definition of done", so this was the one component in the architecture that could
not fail, and it stayed a hand-written struct while looking finished on the
diagram. The gate is added here rather than left implicit (D-055).

What it asserts:

* the spec cannot express something that will not compile -- identifiers, units,
  layout coherence;
* generation is deterministic and produces ASCII regardless of what the model
  wrote;
* a spec derived from pseudo-C reproduces the hand-written ground truth's
  **layout** -- offsets, widths, and length semantics. Not its field NAMES:
  pseudo-C has none, so the model invents them and asserting on them would test
  its vocabulary rather than its understanding;
* no LLM in the codegen path (RULE 1 -- generation happens at build time).

The live-model derivation and the MSVC compile are opt-in
(``SNAPFUZZ_LIVE_LLM``, ``SNAPFUZZ_LIVE_CC``) because one spends allocation and
the other needs a C++ toolchain.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
from pathlib import Path

import pydantic
import pytest

from arch.contracts import FuzzEntry, InputField, InputSpec
from fuzzer.codegen import ascii_comment, generate_header, write_header

REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC_PATH = REPO_ROOT / "artifacts" / "tlv_server" / "input_spec.json"

live_llm = pytest.mark.skipif(
    os.environ.get("SNAPFUZZ_LIVE_LLM") != "1",
    reason="set SNAPFUZZ_LIVE_LLM=1 to derive an input spec from the live model",
)
live_cc = pytest.mark.skipif(
    os.environ.get("SNAPFUZZ_LIVE_CC") != "1",
    reason="set SNAPFUZZ_LIVE_CC=1 to compile generated C++ with MSVC",
)

# The hand-written Packet_t in fuzzer/module/fuzzer_snapfuzz.cc, which is the
# ground truth a derived spec is measured against. Names are deliberately absent:
# see the module docstring.
GROUND_TRUTH_LAYOUT = [
    ("scalar", "uint32_t", 0),
    ("scalar", "uint16_t", 4),
    ("length", "uint16_t", 6),
    ("bytes", None, 8),
]
GROUND_TRUTH_HEADER_BYTES = 8

_WIDTH = {"uint8_t": 1, "uint16_t": 2, "uint32_t": 4, "uint64_t": 8,
          "int8_t": 1, "int16_t": 2, "int32_t": 4, "int64_t": 8}


def _ground_truth_spec() -> InputSpec:
    return InputSpec(
        module="tlv_server",
        entry_symbol="ProcessPacket",
        struct_name="Packet_t",
        source_functions=["ProcessPacket"],
        rationale="4-byte command, 2-byte id, 2-byte length, then the payload.",
        fields=[
            InputField(name="Command", kind="scalar", ctype="uint32_t"),
            InputField(name="Id", kind="scalar", ctype="uint16_t"),
            InputField(
                name="BodySize", kind="length", ctype="uint16_t",
                counts_field="Body", unit="bytes", includes_header=False,
            ),
            InputField(name="Body", kind="bytes", max_length=4000),
        ],
    )


def _layout(spec: InputSpec) -> list[tuple[str, str | None, int]]:
    """(kind, ctype, offset) per field, in wire order."""
    out: list[tuple[str, str | None, int]] = []
    offset = 0
    for field in spec.fields:
        out.append((field.kind, field.ctype, offset))
        offset += _WIDTH[field.ctype] if field.ctype else 0
    return out


# --- the spec cannot express the ungeneratable ----------------------------


def test_a_field_name_that_is_not_an_identifier_is_refused() -> None:
    """Field names become C++ identifiers, so the contract must reject one that
    cannot be. Caught here rather than in the compiler, where the error would be
    thousands of tokens from the model's mistake."""
    for bad in ("my field", "2ndField", "field-name", "", "欄位"):
        with pytest.raises(pydantic.ValidationError):
            InputField(name=bad, kind="scalar", ctype="uint8_t")


def test_a_reserved_word_is_refused_as_a_field_name() -> None:
    for bad in ("class", "int", "operator", "template"):
        with pytest.raises(pydantic.ValidationError, match="reserved word"):
            InputField(name=bad, kind="scalar", ctype="uint8_t")


def test_a_length_field_must_say_what_it_counts() -> None:
    """RULE 4's table asks "bytes or element count?" -- an unattributed length is
    exactly the ambiguity it forbids."""
    with pytest.raises(pydantic.ValidationError, match="does not say which field"):
        InputField(name="Len", kind="length", ctype="uint16_t")


def test_a_length_field_records_its_unit_and_whether_it_covers_the_header() -> None:
    field = InputField(
        name="Len", kind="length", ctype="uint16_t", counts_field="Body",
        unit="elements", includes_header=True,
    )
    assert field.unit == "elements"
    assert field.includes_header is True


def test_a_variable_length_field_must_not_carry_a_fixed_ctype() -> None:
    with pytest.raises(pydantic.ValidationError, match="variable-length"):
        InputField(name="Body", kind="bytes", ctype="uint8_t")


def test_a_magic_field_without_a_value_is_refused() -> None:
    with pytest.raises(pydantic.ValidationError, match="no magic_value"):
        InputField(name="Magic", kind="magic", ctype="uint32_t")


def test_an_unbounded_variable_length_tail_is_refused() -> None:
    """A tail with NO way to end means the parser cannot know where it stops.

    Generating that struct would silently truncate every test-case. Counted or delimited
    both end it; neither does not.
    """
    with pytest.raises(pydantic.ValidationError, match="neither counted"):
        InputSpec(
            module="m", entry_symbol="e",
            fields=[InputField(name="Body", kind="bytes")],
        )


def test_a_delimited_tail_is_accepted_without_a_length_field() -> None:
    """A NUL-terminated string is the most ordinary shape in C, and it has no length.

    The contract required a length field for every `bytes` field, which is true of
    length-prefixed formats and false here. Handed a `char *` target, the model read it
    correctly -- "validates the input starts with \"test\", uses the fifth byte" -- and
    the spec was rejected for not inventing a length field the code does not have. The
    terminator IS the length (D-075).
    """
    spec = InputSpec(
        module="fuzzing-base-test",
        entry_symbol="fuzzme",
        fields=[
            InputField(name="magic", kind="magic", ctype="uint32_t", magic_value=0x74736574),
            InputField(name="payload", kind="bytes", terminator=0, max_length=256),
        ],
    )
    payload = next(f for f in spec.fields if f.kind == "bytes")
    assert payload.terminator == 0
    assert not any(f.kind == "length" for f in spec.fields)


def test_the_terminator_is_written_after_the_payload() -> None:
    """Omitting the sentinel leaves the parser reading past the payload.

    Checked on the generated C++, because "the spec allows it" and "the harness emits
    it" are different claims and only the second one reaches the guest.
    """
    from fuzzer.codegen import _serialise_field

    spec = InputSpec(
        module="m",
        entry_symbol="e",
        fields=[InputField(name="payload", kind="bytes", terminator=0, max_length=64)],
    )
    lines = "\n".join(_serialise_field(spec, spec.fields[0]))
    assert "push_back(uint8_t(0x00))" in lines, lines
    assert "delimited by" in lines


def test_two_variable_length_fields_are_refused() -> None:
    with pytest.raises(pydantic.ValidationError, match="unambiguously"):
        InputSpec(
            module="m", entry_symbol="e",
            fields=[
                InputField(name="A", kind="bytes"),
                InputField(name="B", kind="bytes"),
                InputField(name="LA", kind="length", ctype="uint16_t", counts_field="A"),
                InputField(name="LB", kind="length", ctype="uint16_t", counts_field="B"),
            ],
        )


def test_a_length_field_pointing_at_nothing_is_refused() -> None:
    with pytest.raises(pydantic.ValidationError, match="not a field of this struct"):
        InputSpec(
            module="m", entry_symbol="e",
            fields=[
                InputField(name="L", kind="length", ctype="uint16_t", counts_field="Ghost")
            ],
        )


def test_a_length_field_counting_itself_is_refused() -> None:
    with pytest.raises(pydantic.ValidationError, match="counts itself"):
        InputSpec(
            module="m", entry_symbol="e",
            fields=[
                InputField(name="L", kind="length", ctype="uint16_t", counts_field="L")
            ],
        )


def test_duplicate_field_names_are_refused() -> None:
    with pytest.raises(pydantic.ValidationError, match="duplicate field names"):
        InputSpec(
            module="m", entry_symbol="e",
            fields=[
                InputField(name="X", kind="scalar", ctype="uint8_t"),
                InputField(name="X", kind="scalar", ctype="uint8_t"),
            ],
        )


def test_the_struct_name_must_be_an_identifier() -> None:
    with pytest.raises(pydantic.ValidationError):
        InputSpec(
            module="m", entry_symbol="e", struct_name="not a name",
            fields=[InputField(name="X", kind="scalar", ctype="uint8_t")],
        )


def test_header_bytes_is_the_sum_of_the_fixed_fields() -> None:
    assert _ground_truth_spec().header_bytes == GROUND_TRUTH_HEADER_BYTES


def test_the_spec_round_trips_through_json() -> None:
    spec = _ground_truth_spec()
    assert InputSpec.model_validate_json(spec.model_dump_json()) == spec


# --- generation is safe and deterministic --------------------------------


def test_model_prose_cannot_break_the_generated_file() -> None:
    """Measured: the derived rationale contained U+2011 and MSVC refused the file
    under /WX with C4819. Model prose must never decide whether the artifact
    compiles (D-054)."""
    hostile = "4‑byte “value” → memcpy */ int x = 1; 中文"
    out = ascii_comment(hostile)
    assert all(ord(c) < 128 for c in out), out
    assert "*/" not in out, "comment injection would spill prose into code"
    assert "4-byte" in out and '"value"' in out and "-> memcpy" in out


def test_a_hostile_rationale_still_yields_an_ascii_header() -> None:
    spec = _ground_truth_spec()
    spec.rationale = "reads “param_1” → offset 8 */ break"
    spec.fields[0].rationale = "4‑byte command — see 中文"
    header = generate_header(spec)
    assert all(ord(c) < 128 for c in header)
    # The struct body must not have been terminated early by an injected `*/`.
    assert header.count("struct Packet_t {") == 1


def test_generation_is_deterministic() -> None:
    """The same spec must produce identical bytes, or a regenerated header shows
    up as a diff and nobody can tell a real change from a re-run."""
    spec = _ground_truth_spec()
    assert generate_header(spec) == generate_header(spec)


def test_the_generated_header_recomputes_length_fields() -> None:
    """CP4: a mutated length that disagrees with the payload is rejected at the
    parser's first check, and that is the difference between 5% and 50% coverage."""
    header = generate_header(_ground_truth_spec())
    assert "BodySizeValue" in header
    assert "static_cast<uint16_t>(Packet.Body.size())" in header
    # The struct's own field must NOT be what gets serialised.
    assert "Append(Out, Packet.BodySize)" not in header


def test_the_generated_header_carries_the_wire_size_override() -> None:
    """Without it a `size < header` guard is unreachable by construction, whatever
    the seed (D-040)."""
    header = generate_header(_ground_truth_spec())
    assert "uint32_t WireSize" in header
    assert "ReportedSize" in header


def test_the_wire_size_override_can_be_switched_off() -> None:
    spec = _ground_truth_spec()
    spec.wire_size_override = False
    header = generate_header(spec)
    assert "WireSize" not in header
    assert "ReportedSize" not in header


def test_big_endian_fields_get_a_byte_swapping_writer() -> None:
    spec = _ground_truth_spec()
    spec.fields[0].little_endian = False
    header = generate_header(spec)
    assert "AppendBigEndian(Out, Packet.Command)" in header


def test_a_magic_field_is_defaulted_to_its_constant() -> None:
    spec = InputSpec(
        module="m", entry_symbol="e",
        fields=[
            InputField(name="Magic", kind="magic", ctype="uint32_t", magic_value=0x41424344),
            InputField(name="Len", kind="length", ctype="uint16_t", counts_field="Body"),
            InputField(name="Body", kind="bytes"),
        ],
    )
    header = generate_header(spec)
    assert "uint32_t Magic = 0x41424344;" in header


def test_the_generated_file_says_it_is_generated_and_how_to_regenerate() -> None:
    header = generate_header(_ground_truth_spec(), spec_path="artifacts/tlv_server/input_spec.json")
    assert "GENERATED FILE" in header
    assert "do not edit by hand" in header
    assert "python -m fuzzer.codegen --spec artifacts/tlv_server/input_spec.json" in header


def test_the_generated_file_states_what_is_NOT_generated() -> None:
    """A reader must not assume the crash oracle or InsertTestcase came from a
    model -- they are the hand-written "Manual tweaks" box."""
    header = generate_header(_ground_truth_spec())
    for name in ("Init", "InsertTestcase", "Restore", "crash oracle", "mutator"):
        assert name in header


# --- RULE 1: no LLM in the generation path -------------------------------


def test_codegen_contains_no_llm_call() -> None:
    """Generation is ordinary code. The model's contribution is the spec; if a
    model also wrote the C++ the output could not be guaranteed to compile."""
    source = (REPO_ROOT / "fuzzer" / "codegen.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert not node.module.startswith("llm."), "codegen must not call the LLM"
    assert "LlmClient" not in source


def test_the_derivation_is_the_only_place_the_model_is_asked() -> None:
    source = (REPO_ROOT / "prep" / "input_struct.py").read_text(encoding="utf-8")
    assert "complete_json" in source, "the derivation must go through the JSON path"
    assert "input_struct" in source, "it must use its own configured role"


def test_the_input_struct_role_is_configured_at_temperature_zero() -> None:
    """One correct answer exists -- the target has one wire format -- so sampling
    diversity costs correctness. Contrast seed_gen, where diversity is the goal."""
    import yaml

    config = yaml.safe_load(
        (REPO_ROOT / "config" / "llm.yaml").read_text(encoding="utf-8")
    )
    role = config["roles"]["input_struct"]
    assert role["temperature"] == 0.0
    assert role["max_tokens"] >= 16384, "this reasoning model needs the budget (D-043)"


# --- the recorded derivation vs ground truth -----------------------------


def _recorded_spec() -> InputSpec:
    if not SPEC_PATH.exists():
        pytest.skip(
            f"{SPEC_PATH.relative_to(REPO_ROOT)} has not been produced. Run: "
            f"python -m prep.input_struct --entry artifacts/tlv_server/fuzz_entry_llm.json"
        )
    return InputSpec.model_validate_json(SPEC_PATH.read_text(encoding="utf-8"))


def test_the_derived_spec_reproduces_the_ground_truth_layout() -> None:
    """The headline claim of edge 12, and the reason names are excluded.

    Pseudo-C has no field names, so the model invents them -- it produced
    Cmd/HeaderInfo/PayloadSize/Payload where the hand-written struct says
    Command/Id/BodySize/Body. Asserting on names would test vocabulary. What must
    match is the LAYOUT: how many fields, at what widths, at what offsets, and
    which one is the length.
    """
    spec = _recorded_spec()
    assert _layout(spec) == GROUND_TRUTH_LAYOUT, (
        f"derived layout {_layout(spec)} does not match the hand-written struct "
        f"{GROUND_TRUTH_LAYOUT}"
    )
    assert spec.header_bytes == GROUND_TRUTH_HEADER_BYTES


def test_the_derived_length_field_has_the_right_semantics() -> None:
    """Bytes not elements, and excluding the header. Both are RULE 4 questions and
    both are wrong-able: the value is passed straight to memcpy."""
    spec = _recorded_spec()
    length = next(f for f in spec.fields if f.kind == "length")
    tail = next(f for f in spec.fields if f.kind == "bytes")
    assert length.counts_field == tail.name
    assert length.unit == "bytes"
    assert length.includes_header is False


def test_the_derived_spec_knows_the_parser_is_stateful() -> None:
    """supports_sequence decides whether a test-case can carry several structures,
    and whole branches are unreachable without it.

    This one was WRONG at first, and diagnosably so: the model was shown only
    ProcessPacket, whose `while` loop is the chunk-table search, not a receive
    loop. The `recv` loop and the repeated call live in `main`. Statefulness is a
    property of the CALLER, so callers are now included in the prompt.
    """
    spec = _recorded_spec()
    assert spec.supports_sequence is True


def test_the_derived_spec_records_where_it_came_from() -> None:
    spec = _recorded_spec()
    assert spec.module == "tlv_server"
    assert spec.entry_symbol == "ProcessPacket"
    assert spec.source_functions, "a spec with no cited source cannot be reviewed"
    assert spec.rationale.strip(), "a spec with no rationale cannot be checked"


def test_the_derived_spec_generates_an_ascii_header() -> None:
    header = generate_header(_recorded_spec())
    assert all(ord(c) < 128 for c in header)


# --- opt-in: live model, and a real compile ------------------------------


@live_llm
def test_live_derivation_from_pseudoc() -> None:
    from llm.client import LlmClient
    from prep.input_struct import derive_input_spec
    from prep.pseudoc_cache import PseudoCCache

    entry_path = REPO_ROOT / "artifacts" / "tlv_server" / "fuzz_entry_llm.json"
    if not entry_path.exists():
        pytest.skip("no FuzzEntry recorded; run prep.entry_select first")
    entry = FuzzEntry.model_validate_json(entry_path.read_text(encoding="utf-8"))

    cache_path = REPO_ROOT / "artifacts" / "tlv_server" / "a2_pseudoc_module.sqlite"
    with PseudoCCache(cache_path) as cache, LlmClient.from_config() as client:
        spec, warnings = derive_input_spec(entry, cache, client)

    assert _layout(spec) == GROUND_TRUTH_LAYOUT, f"warnings were: {warnings}"
    assert spec.supports_sequence is True


@live_cc
def test_the_generated_header_compiles(tmp_path: Path) -> None:
    """Valid C++ under the same toolchain wtf is built with, warnings as errors.

    /W4 /WX is deliberate: a generated file that merely parses is not good enough,
    because a warning in a generated header would be noise nobody can fix.
    """
    from fuzzer.build import find_vcvars

    spec = _recorded_spec()
    write_header(spec, tmp_path / "generated_input.h")
    (tmp_path / "main.cc").write_text(
        '#include "generated_input.h"\n'
        "int main() {\n"
        f"  snapfuzz_generated::{spec.struct_name} P;\n"
        "  const auto Wire = snapfuzz_generated::Serialize(P);\n"
        "  return Wire.empty() ? 0 : 0;\n"
        "}\n",
        encoding="utf-8",
    )

    env = dict(os.environ)
    parts = (p.strip().strip('"') for p in env.get("PATH", "").split(os.pathsep))
    env["PATH"] = os.pathsep.join(p for p in parts if p)

    bat = tmp_path / "build.bat"
    bat.write_text(
        f'@echo off\r\ncall "{find_vcvars()}" >nul\r\ncd /d "{tmp_path}"\r\n'
        f"cl /nologo /std:c++20 /EHsc /W4 /WX main.cc\r\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        ["cmd", "/c", str(bat)], env=env, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=900,
    )
    assert result.returncode == 0, result.stdout[-3000:]


def test_a_reversed_magic_constant_is_caught() -> None:
    """Measured on a real target: the model got the byte order backwards (D-075).

    Its own rationale said the magic is 0x74736574 and it filled `magic_value` with
    0x74657374 -- the same four characters in the opposite order. That writes `tset`, so
    every test-case failed the target's first comparison and no mutation could recover:
    the constant is checked before anything else runs.

    Nothing caught it. A schema cannot -- both are valid uint32_t -- and the campaign
    could not, because "coverage stopped growing" is indistinguishable from "this target
    is small". Converting the value back to bytes and comparing against the characters
    the code compares against does catch it.
    """
    from prep.input_struct import check_against_pseudoc

    # The shape Ghidra emits for an unrolled byte-wise compare, index 0 written as
    # `*param_1` rather than `param_1[0]` -- which the first version of the check missed,
    # on the exact case it was written for.
    code = (
        "void fuzzme(char *param_1) {\n"
        "  if (*param_1 == 't' && param_1[1] == 'e' && param_1[2] == 's' "
        "&& param_1[3] == 't') {\n"
        "    process(param_1 + 5, (ulonglong)(byte)param_1[4]);\n"
        "  }\n"
        "}\n"
    )

    def spec_with(magic: int) -> InputSpec:
        return InputSpec(
            module="fuzzing-base-test",
            entry_symbol="fuzzme",
            fields=[
                InputField(name="magic", kind="magic", ctype="uint32_t", magic_value=magic),
                InputField(
                    name="payload_len", kind="length", ctype="uint8_t",
                    counts_field="payload", unit="bytes",
                ),
                InputField(name="payload", kind="bytes", max_length=65),
            ],
        )

    reversed_warnings = check_against_pseudoc(spec_with(0x74657374), code)
    assert any("byte order is reversed" in w for w in reversed_warnings), reversed_warnings
    # And it says what the value should be, since a warning that only says "wrong" leaves
    # the reader to redo the arithmetic that produced the mistake.
    assert any(f"{int.from_bytes(b'test', 'little'):#x}" in w for w in reversed_warnings)

    # Silent when the spec agrees with the code -- otherwise the check is noise and gets
    # ignored, which is worse than not having it.
    assert not [
        w
        for w in check_against_pseudoc(spec_with(int.from_bytes(b"test", "little")), code)
        if "byte order" in w
    ]


def test_the_magic_check_reads_a_string_literal_too() -> None:
    """`strncmp(param_1, "test", 4)` is the other shape, when the compiler did not
    unroll the comparison. Both are read because which one appears depends on the
    compiler, and neither is more authoritative."""
    from prep.input_struct import _ascii_literals

    assert b"test" in _ascii_literals('strncmp(param_1, "test", 4);', 4)
    # Width-filtered: a longer literal is not a 4-byte magic.
    assert _ascii_literals('strcmp(param_1, "abcdefgh");', 4) == set()
