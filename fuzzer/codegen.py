"""InputSpec -> C++ for the fuzzer module (CLAUDE.md edge 14).

**NO LLM IN THIS MODULE.** The model produces an :class:`InputSpec`
(`prep/input_struct.py`, edge 12); this turns that spec into C++. Splitting it
that way is the whole design:

* a model asked for C++ directly fails in the C++ toolchain, thousands of tokens
  away from the mistake it made;
* free-form C++ cannot be validated, while an InputSpec is checked by pydantic and
  by the semantic rules in the contract;
* RULE 4's "units and encoding are stated" is enforceable in a schema and merely
  hoped for in prose.

So generation is deterministic and the output compiles by construction. What the
model contributes is the *understanding* of the format; what this contributes is
the guarantee that the understanding becomes valid code.

**Build time, never run time.** The artifact that reaches the fuzzer is C++ that
went through the compiler. Nothing here executes while the fast loop is running
(RULE 1).

What is generated, and what is not
----------------------------------
Generated: the struct, its JSON serialisers, the wire-format serialiser
`InsertTestcase` writes into guest memory, and the length/`WireSize` fixups.

**Not** generated: `Init`, `InsertTestcase`, `Restore`, the crash oracle, or the
mutator. Those are the "Manual tweaks" box in section 3.1 and they stay
hand-written -- they encode decisions about *this* target's residual state and
crash conditions that no input-format description implies. The generated header is
included by the hand-written module.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from arch.contracts import InputField, InputSpec

REPO_ROOT = Path(__file__).resolve().parents[1]

__all__ = ["generate_header", "write_header"]

_WIDTH = {
    "uint8_t": 1, "int8_t": 1, "uint16_t": 2, "int16_t": 2,
    "uint32_t": 4, "int32_t": 4, "uint64_t": 8, "int64_t": 8,
}

# Unicode punctuation a model reaches for that MSVC cannot read under a non-UTF-8
# codepage. Measured: the derived spec's rationale said "4-byte" with U+2011, a
# NON-BREAKING HYPHEN, and the generated header failed to compile with
#   warning C4819: The file contains a character that cannot be represented in
#   the current code page (950)
# under /WX. Model prose must never decide whether the artifact compiles, so it is
# transliterated rather than trusted (D-054).
_TRANSLITERATE = {
    "‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "--",
    "―": "--", "‘": "'", "’": "'", "‚": "'", "‛": "'",
    "“": '"', "”": '"', "„": '"', "…": "...", "→": "->",
    "←": "<-", "⇒": "=>", " ": " ", "×": "x", "≤": "<=",
    "≥": ">=", "≠": "!=", "·": "-", "•": "-",
}


def ascii_comment(text: str) -> str:
    """Model-supplied prose, made safe to embed in a C++ comment.

    Three hazards, all of which have to be closed for the output to compile
    regardless of what the model wrote:

    * **Non-ASCII** breaks MSVC under a non-UTF-8 codepage (see above). Known
      punctuation is transliterated; anything else is dropped rather than guessed
      at.
    * **``*/``** would close the comment early and spill prose into code. Neutered
      to ``* /``.
    * **Newlines** are the caller's business -- it prefixes each line with ``//``.

    A UTF-8 BOM would also have satisfied MSVC, and was rejected: it fixes only the
    encoding symptom, leaves comment injection open, and makes the generated file
    depend on every downstream tool tolerating a BOM.
    """
    out: list[str] = []
    for char in text:
        if char in _TRANSLITERATE:
            out.append(_TRANSLITERATE[char])
        elif char == "\n" or 0x20 <= ord(char) <= 0x7E:
            out.append(char)
        elif char == "\t":
            out.append(" ")
        # Anything else is dropped: an unrenderable character in a comment is
        # worth less than a file that compiles.
    return "".join(out).replace("*/", "* /")


def _cpp_field(field: InputField) -> str:
    if field.kind == "bytes":
        return f"  std::vector<uint8_t> {field.name};"
    default = ""
    if field.kind == "magic":
        default = f" = {field.magic_value:#x}"
    return f"  {field.ctype} {field.name}{default};"


def _field_comment(field: InputField) -> str:
    bits: list[str] = [field.kind]
    if field.kind == "length":
        bits.append(f"counts {field.counts_field} in {field.unit}")
        if field.includes_header:
            bits.append(f"INCLUDING the {field.ctype} header")
    if field.kind == "magic":
        bits.append(f"parser compares against {field.magic_value:#x}")
    if field.kind == "bytes" and field.max_length:
        bits.append(f"capped at {field.max_length} bytes")
    if not field.little_endian:
        bits.append("BIG-endian on the wire")
    line = "; ".join(bits)
    if field.rationale:
        line += f" -- {field.rationale}"
    return "  // " + ascii_comment(line).replace("\n", " ")


def _serialise_field(spec: InputSpec, field: InputField) -> list[str]:
    """Lines that append one field to the wire buffer."""
    if field.kind == "bytes":
        return [
            f"  // {field.name}: variable-length tail",
            f"  Out.insert(Out.end(), Packet.{field.name}.begin(),",
            f"             Packet.{field.name}.end());",
        ]

    width = _WIDTH[field.ctype]
    lines = [f"  // {field.name} ({field.ctype}, {width} byte(s))"]

    if field.kind == "length":
        counted = next(f for f in spec.fields if f.name == field.counts_field)
        expr = f"Packet.{counted.name}.size()"
        if field.unit == "elements":
            # Only meaningful for a byte vector today, where elements == bytes.
            # Stated rather than silently assumed.
            expr = f"Packet.{counted.name}.size()  /* elements == bytes here */"
        if field.includes_header:
            expr = f"{expr} + {spec.header_bytes}"
        lines.append(
            "  // Recomputed, NOT taken from the test-case: a mutated length that"
        )
        lines.append(
            "  // disagrees with the payload is rejected at the parser's first"
        )
        lines.append(
            "  // check, and that is the difference between 5% and 50% coverage"
        )
        lines.append("  // (CLAUDE.md CP4).")
        lines.append(f"  const {field.ctype} {field.name}Value =")
        lines.append(f"      static_cast<{field.ctype}>({expr});")
        source = f"{field.name}Value"
    else:
        source = f"Packet.{field.name}"

    if field.little_endian:
        lines.append(f"  Append(Out, {source});")
    else:
        lines.append(f"  AppendBigEndian(Out, {source});")
    return lines


_HEADER_TEMPLATE = '''// GENERATED FILE -- do not edit by hand.
//
// Produced by fuzzer/codegen.py from an InputSpec that
// prep/input_struct.py derived from Ghidra pseudo-C (CLAUDE.md edges 12 and 14).
// Regenerate with:
//
//     python -m fuzzer.codegen --spec {spec_path} --out <this file>
//
// Target : {module}!{entry_symbol}
// Source : {source_functions}
//
// Why the shape is this, per the model:
{rationale_block}
//
// Hand-written code -- Init, InsertTestcase, Restore, the crash oracle, the
// mutator -- lives in the module that includes this header. Those encode
// decisions about residual state and crash conditions that no description of an
// input format implies, and they are deliberately NOT generated (section 3.1's
// "Manual tweaks" box).
//
#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

namespace snapfuzz_generated {{

//
// Little-endian append. The guest is x86-64, so a plain memcpy of the host
// representation is already little-endian; this is written out rather than
// memcpy'd wholesale because a struct copy would also copy padding the target
// never sees.
//
template <typename T> inline void Append(std::vector<uint8_t> &Out, const T Value) {{
  const auto *Bytes = reinterpret_cast<const uint8_t *>(&Value);
  Out.insert(Out.end(), Bytes, Bytes + sizeof(T));
}}

template <typename T>
inline void AppendBigEndian(std::vector<uint8_t> &Out, const T Value) {{
  for (size_t Idx = sizeof(T); Idx-- > 0;) {{
    Out.push_back(static_cast<uint8_t>((Value >> (Idx * 8)) & 0xff));
  }}
}}

struct {struct_name} {{
{field_block}
{wire_size_block}}};

//
// Fixed-size prefix, in bytes. {header_bytes} = {header_sum}
//
constexpr size_t k{struct_name}HeaderBytes = {header_bytes};

//
// Serialise one {struct_name} to the bytes the target will parse.
//
// Length fields are RECOMPUTED here from the actual payload, which is the
// structural fixup CP4 requires: a mutator that flips a length byte would
// otherwise produce a test-case the parser discards at its first bounds check.
//
inline std::vector<uint8_t> Serialize(const {struct_name} &Packet) {{
  std::vector<uint8_t> Out;
  Out.reserve(k{struct_name}HeaderBytes + {tail_size_expr});

{serialise_block}
  return Out;
}}
{wire_size_helper}
}} // namespace snapfuzz_generated
'''

_WIRE_SIZE_FIELD = '''
  //
  // How many bytes the target is TOLD arrived, independent of how many were
  // written. 0 means the natural size.
  //
  // Without this a guard like `if (size < header) reject` is unreachable BY
  // CONSTRUCTION -- no seed can satisfy it, however well reasoned. CP7 measured
  // exactly that: the frontier offered the branch, the model aimed at it
  // correctly, and nothing could have worked (D-040). It is also realistic: a
  // peer on a socket can send fewer bytes than its header claims.
  //
  uint32_t WireSize = 0;
'''

_WIRE_SIZE_HELPER = '''
//
// The size to report to the target for this packet.
//
inline uint32_t ReportedSize(const {struct_name} &Packet,
                             const size_t ActualBytes) {{
  return Packet.WireSize ? Packet.WireSize
                         : static_cast<uint32_t>(ActualBytes);
}}
'''


def generate_header(spec: InputSpec, *, spec_path: str = "<spec>") -> str:
    """Render the C++ header for ``spec``."""
    field_lines: list[str] = []
    for field in spec.fields:
        field_lines.append(_field_comment(field))
        field_lines.append(_cpp_field(field))

    serialise_lines: list[str] = []
    for field in spec.fields:
        serialise_lines.extend(_serialise_field(spec, field))
        serialise_lines.append("")

    variable = [f for f in spec.fields if f.kind == "bytes"]
    tail = f"Packet.{variable[0].name}.size()" if variable else "0"

    widths = " + ".join(
        f"{_WIDTH[f.ctype]}" for f in spec.fields if f.kind != "bytes" and f.ctype
    )

    rationale = ascii_comment(spec.rationale.strip()) or "(none recorded)"
    rationale_block = "\n".join(f"//   {line}" for line in rationale.splitlines())

    return _HEADER_TEMPLATE.format(
        spec_path=spec_path,
        module=spec.module,
        entry_symbol=spec.entry_symbol,
        source_functions=ascii_comment(", ".join(spec.source_functions)) or "(unrecorded)",
        rationale_block=rationale_block,
        struct_name=spec.struct_name,
        field_block="\n".join(field_lines),
        wire_size_block=_WIRE_SIZE_FIELD if spec.wire_size_override else "",
        header_bytes=spec.header_bytes,
        header_sum=widths or "0",
        tail_size_expr=tail,
        serialise_block="\n".join(serialise_lines),
        wire_size_helper=(
            _WIRE_SIZE_HELPER.format(struct_name=spec.struct_name)
            if spec.wire_size_override
            else ""
        ),
    )


def write_header(spec: InputSpec, out_path: Path, *, spec_path: str = "<spec>") -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(generate_header(spec, spec_path=spec_path), encoding="utf-8")
    return out_path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--spec",
        type=Path,
        default=REPO_ROOT / "artifacts" / "input_spec.json",
        help="InputSpec JSON, from prep/input_struct.py",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "fuzzer" / "module" / "generated_input.h",
    )
    args = ap.parse_args(argv)

    spec = InputSpec.model_validate_json(args.spec.read_text(encoding="utf-8"))
    path = write_header(spec, args.out, spec_path=str(args.spec))

    print(f"{spec.module}!{spec.entry_symbol}: {len(spec.fields)} field(s)")
    for field in spec.fields:
        detail = field.ctype or "bytes"
        if field.kind == "length":
            detail += f" -> counts {field.counts_field} in {field.unit}"
        if field.kind == "magic":
            detail += f" == {field.magic_value:#x}"
        print(f"  {field.name:<16} {field.kind:<9} {detail}")
    print(f"header is {spec.header_bytes} bytes; wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
