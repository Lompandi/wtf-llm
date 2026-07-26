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

from arch.contracts import HarnessSpec, InputField, InputSpec

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


def _from_json_line(field: InputField) -> str:
    """One field's `from_json` read, accepting its legacy names as fallbacks.

    Emitted as nested `Json.contains` checks rather than a chain of `Json.value`
    defaults, because a default cannot distinguish "absent" from "present and zero" --
    and `0` is a perfectly ordinary value for a command byte. Getting that wrong would
    silently read 0 for every field whose canonical name is absent, which is the whole
    recorded corpus.
    """
    if field.kind == "bytes":
        cpp_type = "std::vector<uint8_t>"
        empty = "std::vector<uint8_t>{}"
    else:
        cpp_type = field.ctype
        empty = f"{field.ctype}(0)"

    names = [field.name, *field.legacy_names]
    if len(names) == 1:
        return f'  Value.{field.name} = Json.value("{field.name}", {empty});'

    # `Command` (hand-written) and `command` (derived) are the same field to a reader
    # and different keys to nlohmann::json, so every name is tried in order.
    conditions = " ".join(
        f'if (Json.contains("{name}")) Value.{field.name} = '
        f'Json.at("{name}").get<{cpp_type}>();\n  else '
        for name in names
    )
    return f"  {conditions}Value.{field.name} = {empty};"


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


# --- the whole module ----------------------------------------------------
#
# CP11 stopped at the struct and left ~550 lines hand-written. That contradicted
# contribution 1, which section 11 says is about removing "snapshot fuzzing's main
# usability barrier" -- and a hand-written harness per target IS that barrier. So
# the generator now emits the module, driven by an InputSpec plus a HarnessSpec.
#
# The model still writes no C++. It fills in two schemas; this renders them.

_REG_METHOD = {
    "rax": "Rax", "rbx": "Rbx", "rcx": "Rcx", "rdx": "Rdx",
    "rsi": "Rsi", "rdi": "Rdi", "rsp": "Rsp", "rbp": "Rbp",
    "r8": "R8", "r9": "R9", "r10": "R10", "r11": "R11",
    "r12": "R12", "r13": "R13", "r14": "R14", "r15": "R15",
}


def _register(name: str) -> str:
    """wtf's accessor for a register, e.g. 'rcx' -> 'Rcx'."""
    key = name.strip().lower().lstrip("@%$")
    if key not in _REG_METHOD:
        raise ValueError(
            f"{name!r} is not an x86-64 GPR this generator can address. wtf exposes "
            f"one accessor per register, so a stack slot or a memory operand needs "
            f"hand-written delivery."
        )
    return _REG_METHOD[key]


def _json_default(field: InputField) -> str:
    return "{}" if field.kind == "bytes" else "0"


def generate_module(
    spec: InputSpec,
    harness: HarnessSpec,
    *,
    spec_path: str = "<input_spec>",
    harness_path: str = "<harness_spec>",
    namespace: str | None = None,
) -> str:
    """Render a complete wtf fuzzer module from the two derived specs."""
    from fuzzer.module_template import MODULE_TEMPLATE

    namespace = namespace or f"Gen{spec.module.title().replace('_', '')}"
    target_var = f"{namespace}Target"
    tail = next((f for f in spec.fields if f.kind == "bytes"), None)

    # --- the struct, reusing the header renderer's field logic ------------
    struct_lines: list[str] = []
    for field in spec.fields:
        struct_lines.append(_field_comment(field))
        struct_lines.append(_cpp_field(field))
    if spec.wire_size_override:
        struct_lines.append(_WIRE_SIZE_FIELD.rstrip())
    struct = (
        f"struct {spec.struct_name} {{\n" + "\n".join(struct_lines) + "\n};"
    )

    names = [f.name for f in spec.fields] + (
        ["WireSize"] if spec.wire_size_override else []
    )
    to_json = ",\n".join(
        f'      {{"{n}", Value.{n}}}' for n in names
    )
    # Each field reads its canonical name and then its legacy ones, so a corpus written
    # against an older set of names keeps parsing (edge 14, D-075). `WireSize` is not a
    # spec field -- it is the generated override -- so it keeps the simple form.
    from_json = "\n".join(
        [_from_json_line(f) for f in spec.fields]
        + (
            [f'  Value.WireSize = Json.value("WireSize", {_json_default_by_name(spec, "WireSize")});']
            if spec.wire_size_override
            else []
        )
    )

    # --- sequence handling ------------------------------------------------
    if harness.deliver_sequence:
        wrapper = (
            f"//\n"
            f"// One test-case carries several structures, delivered in order to the\n"
            f"// SAME live process. State the target builds up persists between them,\n"
            f"// which is what makes a branch requiring an existing object reachable\n"
            f"// at all (section 13.7).\n"
            f"//\n"
            f"struct {spec.sequence_field_name}_t {{\n"
            f"  std::vector<{spec.struct_name}> {spec.sequence_field_name};\n"
            f"}};\n\n"
            f"inline void from_json(const json::json &Json,\n"
            f"                      {spec.sequence_field_name}_t &Value) {{\n"
            f'  Json.at("{spec.sequence_field_name}")'
            f".get_to(Value.{spec.sequence_field_name});\n"
            f"}}\n\n"
            f"inline void to_json(json::json &Json,\n"
            f"                    const {spec.sequence_field_name}_t &Value) {{\n"
            f'  Json = json::json{{{{"{spec.sequence_field_name}",'
            f" Value.{spec.sequence_field_name}}}}};\n"
            f"}}"
        )
        parse_body = (
            f"    const auto &Parsed = Root.get<{spec.sequence_field_name}_t>();\n"
            f"    for (auto Item : Parsed.{spec.sequence_field_name}) {{\n"
            f"      GlobalState.Inputs.emplace_back(std::move(Item));\n"
            f"    }}"
        )
        sequence_wording = "a *sequence* of structures"
    else:
        wrapper = ""
        parse_body = (
            f"    GlobalState.Inputs.emplace_back(Root.get<{spec.struct_name}>());"
        )
        sequence_wording = "a single structure"

    # --- wire size --------------------------------------------------------
    wire_size = f"{spec.header_bytes}"
    if tail is not None:
        wire_size += f" + Value.{tail.name}.size()"

    # --- the size register ------------------------------------------------
    if harness.size_param:
        reg = _register(harness.size_param)
        size_write = (
            f"        //\n"
            f"        // {harness.size_param} carries the length, in BYTES.\n"
            f"        //\n"
        )
        if spec.wire_size_override:
            size_write += (
                f"        // WireSize, when set, reports FEWER (or more) bytes than\n"
                f"        // were written -- modelling a short read on a socket. It is\n"
                f"        // what makes a `size < header` guard reachable at all\n"
                f"        // (D-040).\n"
                f"        //\n"
                f"        size_t Reported = Bytes;\n"
                f"        if (Input.WireSize != 0 && Input.WireSize < kPageSize) {{\n"
                f"          Reported = Input.WireSize;\n"
                f"        }}\n"
                f"        Backend->{reg}(Reported);\n"
            )
        else:
            size_write += f"        Backend->{reg}(Bytes);\n"
    else:
        size_write = (
            "        // No separate length parameter was identified, so the target\n"
            "        // must derive the length from the data itself.\n"
        )

    # --- field-by-field guest writes -------------------------------------
    #
    # Length fields are written VERBATIM from the test-case here, never recomputed.
    # The disagreement between a declared length and the real payload IS the bug on
    # this class of target, and recomputing it at delivery time would quietly neuter
    # every overflow test-case. Generate() is where they are made consistent.
    writes: list[str] = []
    for field in spec.fields:
        if field.kind == "bytes":
            writes.append(
                f"        if (!Input.{field.name}.empty() &&\n"
                f"            !Backend->VirtWriteDirty(Gva_t(Address),\n"
                f"                                     Input.{field.name}.data(),\n"
                f"                                     Input.{field.name}.size())) {{\n"
                f'          fmt::print("{namespace}: failed to write '
                f'{field.name}\\n");\n'
                f"          std::abort();\n"
                f"        }}"
            )
            continue
        note = ""
        if field.kind == "length":
            note = (
                f"        //\n"
                f"        // Written from the test-case, NOT recomputed from the\n"
                f"        // payload. The disagreement between them is the bug\n"
                f"        // trigger; recomputing here would neuter every overflow.\n"
                f"        //\n"
            )
        writes.append(
            note
            + f"        if (!Backend->VirtWriteStructDirty(Gva_t(Address),\n"
            f"                                           &Input.{field.name})) {{\n"
            f'          fmt::print("{namespace}: failed to write {field.name}\\n");\n'
            f"          std::abort();\n"
            f"        }}\n"
            f"        Address += sizeof(Input.{field.name});"
        )

    # --- symbol constants and simulated returns --------------------------
    entry_bp = next(b for b in harness.breakpoints if b.purpose == "fuzz_entry")
    constants = [f'constexpr const char *kFuzzEntry = "{entry_bp.symbol}";']

    # THE FUZZ ENTRY BREAKPOINT, by address when the spec carries an RVA. This is the
    # one that actually killed the campaign: with no PDB, Ghidra's invented
    # `FUN_140001150` resolves to nothing, wtf prints `Could not set a breakpoint at
    # mytarget!FUN_140001150`, and every worker dies in Init while the campaign reports
    # zero executions (D-075). `kFuzzEntry` stays as the string used in the log lines.
    if entry_bp.rva is not None:
        entry_module = entry_bp.symbol.split("!", 1)[0]
        fuzz_entry_target = (
            f'Gva_t(g_Dbg->GetModuleBase("{entry_module}") + {entry_bp.rva:#x})'
        )
    else:
        fuzz_entry_target = "kFuzzEntry"
    simulated: list[str] = []
    for index, bp in enumerate(harness.breakpoints):
        if bp.action != "simulate_return":
            continue
        name = f"kSkip{index:02d}"
        constants.append(
            f'constexpr const char *{name} = "{bp.symbol}";'
            f"  // {bp.purpose}: {ascii_comment(bp.rationale)[:90]}"
        )
        # BY ADDRESS when the spec carries an RVA. Resolving by symbol needs dbgeng to
        # know the name, which needs a PDB -- and a stripped binary has none, so Ghidra
        # invents `FUN_140001150`, wtf reports `Could not set a breakpoint at
        # mytarget!FUN_140001150`, and every worker dies in Init. The campaign then
        # reports zero executions, which is what "all workers dead" looks like from the
        # outside (D-075). `GetModuleBase(name) + rva` is what wtf's own .cov loader
        # does for the same reason (utils.cc:366).
        if bp.rva is not None:
            module = bp.symbol.split("!", 1)[0]
            target = f'Gva_t(g_Dbg->GetModuleBase("{module}") + {bp.rva:#x})'
        else:
            target = name
        simulated.append(
            f"  //\n"
            f"  // {bp.symbol}: {bp.purpose}.\n"
            f"  // {ascii_comment(bp.rationale)[:180]}\n"
            f"  //\n"
            f"  if (!g_Backend->SetBreakpoint({target}, [](Backend_t *Backend) {{\n"
            f"        Backend->SimulateReturnFromFunction({bp.return_value});\n"
            f"      }})) {{\n"
            f'    fmt::print("{namespace}: failed to SetBreakpoint on {{}}\\n",'
            f" {name});\n"
            f"    return false;\n"
            f"  }}\n"
        )

    return MODULE_TEMPLATE.format(
        fuzz_entry_target=fuzz_entry_target,
        spec_path=spec_path,
        harness_path=harness_path,
        entry_symbol=harness.entry_symbol,
        input_param=harness.input_param,
        size_note=(
            f", length in {harness.size_param}" if harness.size_param else ""
        ),
        source_functions=ascii_comment(
            ", ".join(sorted(set(spec.source_functions + harness.source_functions)))
        )
        or "(unrecorded)",
        input_rationale="\n".join(
            f"//   {line}" for line in ascii_comment(spec.rationale).splitlines()
        )
        or "//   (none)",
        harness_rationale="\n".join(
            f"//   {line}" for line in ascii_comment(harness.rationale).splitlines()
        )
        or "//   (none)",
        namespace_name=namespace,
        symbol_constants="\n".join(constants),
        max_input_bytes=harness.max_input_bytes,
        struct_definition=struct,
        struct_name=spec.struct_name,
        to_json_body=to_json,
        from_json_body=from_json,
        sequence_wrapper=wrapper,
        sequence_wording=sequence_wording,
        wire_size_expr=wire_size,
        parse_body=parse_body,
        size_param_write=size_write,
        pointer_wording=(
            "HOLDS the buffer address"
            if harness.input_is_pointer
            else "IS the buffer address"
        ),
        input_reg_getter=_register(harness.input_param),
        input_reg_setter=_register(harness.input_param),
        write_body="\n\n".join(writes),
        simulated_returns="\n".join(simulated),
        restore_wording=(
            "The snapshot restore handles guest memory and registers; the only "
            "residual state here is the input queue, which InsertTestcase clears "
            "before each test-case. Restoring twice would be as wrong as not "
            "restoring, so this is a no-op (DECISIONS R2)."
            if not harness.restore_globals
            else f"Resets {harness.restore_globals} in addition to the snapshot "
            f"restore -- see the harness rationale for why."
        ),
        generate_body=_generate_body(spec, harness),
        mutate_body=_mutate_body(spec, harness),
        target_var=target_var,
        target_name=harness.target_name,
    )


def _json_default_by_name(spec: InputSpec, name: str) -> str:
    if name == "WireSize":
        return "uint32_t(0)"
    field = next(f for f in spec.fields if f.name == name)
    if field.kind == "bytes":
        return f"std::vector<uint8_t>{{}}"
    if field.kind == "magic":
        return f"{field.ctype}({field.magic_value:#x})"
    return f"{field.ctype}(0)"


def _generate_body(spec: InputSpec, harness: HarnessSpec) -> str:
    """Build one structure (or a sequence) from scratch, per the spec."""
    tail = next((f for f in spec.fields if f.kind == "bytes"), None)
    lines: list[str] = []

    build: list[str] = [f"      {spec.struct_name} Item;"]
    for field in spec.fields:
        if field.kind == "bytes":
            cap = min(field.max_length or 256, harness.max_input_bytes - spec.header_bytes)
            build.append(f"      const uint32_t Len = GetUint32(0, {max(cap, 1)});")
            build.append(f"      Item.{field.name}.resize(Len);")
            build.append(f"      for (uint32_t I = 0; I < Len; I++) {{")
            build.append(f"        Item.{field.name}[I] = uint8_t(GetUint32(0, 255));")
            build.append(f"      }}")
        elif field.kind == "magic":
            build.append(
                f"      // The parser compares this against a constant, so a random\n"
                f"      // value is rejected immediately. Kept correct MOST of the\n"
                f"      // time so the corpus gets past the check at all.\n"
                f"      Item.{field.name} = GetUint32(1, 10) == 1\n"
                f"                              ? {field.ctype}(GetUint32(0, 0xffff))\n"
                f"                              : {field.ctype}({field.magic_value:#x});"
            )
        elif field.kind == "length":
            counted = next(f for f in spec.fields if f.name == field.counts_field)
            build.append(
                f"      // Consistent with the payload: an inconsistent length is\n"
                f"      // rejected at the parser's first check, and a corpus of\n"
                f"      // rejected inputs teaches the fuzzer nothing (CP4).\n"
                f"      Item.{field.name} = {field.ctype}(Item.{counted.name}.size());"
            )
        else:
            build.append(
                f"      Item.{field.name} = {field.ctype}(GetUint32(0, 16));"
            )
    if spec.wire_size_override:
        build.append(
            "      // Usually the natural size; occasionally a lie, which is the\n"
            "      // only way a `size < header` guard is reachable (D-040).\n"
            "      Item.WireSize = GetUint32(1, 8) == 1 ? GetUint32(0, 8) : 0;"
        )

    if harness.deliver_sequence:
        lines.append(f"    {spec.sequence_field_name}_t Root;")
        lines.append("    const uint32_t Count = GetUint32(1, 10);")
        lines.append("    for (uint32_t N = 0; N < Count; N++) {")
        lines.extend(build)
        lines.append(f"      Root.{spec.sequence_field_name}.emplace_back(Item);")
        lines.append("    }")
    else:
        lines.append(f"    {spec.struct_name} Root;")
        lines.extend(f"  {line}" for line in build)
        lines.append("    Root = Item;")

    lines.append("    json::json Serialized;")
    lines.append("    to_json(Serialized, Root);")
    lines.append("    return Serialized.dump();")
    return "\n".join(lines)


def _mutate_body(spec: InputSpec, harness: HarnessSpec) -> str:
    """Mutate an existing test-case structurally.

    Deliberately allows length fields to disagree with their payload -- that
    disagreement is the bug on this class of target, and Generate() is where
    consistency is kept.
    """
    tail = next((f for f in spec.fields if f.kind == "bytes"), None)
    scalar = [f for f in spec.fields if f.kind in {"scalar", "magic", "length"}]
    seq = harness.deliver_sequence
    root_type = (
        f"{spec.sequence_field_name}_t" if seq else spec.struct_name
    )
    items = f"Root.{spec.sequence_field_name}" if seq else "Items"

    lines = [
        f"    {root_type} Root;",
        "    try {",
        "      const auto &Parsed = json::json::parse(Data, Data + DataLen);",
        f"      Root = Parsed.get<{root_type}>();",
        "    } catch (const std::exception &) {",
        "      // Not our format -- start fresh rather than aborting the master.",
        "      return Generate();",
        "    }",
    ]
    if not seq:
        lines.append(f"    std::vector<{spec.struct_name}> Items{{Root}};")

    lines += [
        f"    if ({items}.empty()) {{",
        "      return Generate();",
        "    }",
        "",
        f"    const size_t Index = GetUint32(0, uint32_t({items}.size() - 1));",
        f"    auto &Item = {items}[Index];",
        "",
        "    switch (GetUint32(0, 5)) {",
        "    case 0:",
    ]
    if scalar:
        lines += [
            f"      // Flip a header field. Length fields included ON PURPOSE: a",
            f"      // length that disagrees with the payload is the bug.",
            f"      switch (GetUint32(0, {len(scalar) - 1})) {{",
        ]
        for index, field in enumerate(scalar):
            lines.append(f"      case {index}:")
            lines.append(
                f"        Item.{field.name} = {field.ctype}(GetUint32(0, 0xffff));"
            )
            lines.append("        break;")
        lines.append("      }")
    lines.append("      break;")

    if tail:
        lines += [
            "    case 1: {",
            "      // Grow the payload without touching the declared length.",
            f"      const uint32_t Extra = GetUint32(1, 64);",
            f"      for (uint32_t I = 0; I < Extra; I++) {{",
            f"        Item.{tail.name}.push_back(uint8_t(GetUint32(0, 255)));",
            "      }",
            "      break;",
            "    }",
            "    case 2:",
            f"      // Shrink it, likewise leaving the length alone.",
            f"      if (!Item.{tail.name}.empty()) {{",
            f"        Item.{tail.name}.resize(Item.{tail.name}.size() / 2);",
            "      }",
            "      break;",
            "    case 3:",
            f"      if (!Item.{tail.name}.empty()) {{",
            f"        Item.{tail.name}[GetUint32(0, uint32_t(Item.{tail.name}.size() - 1))] =",
            "            uint8_t(GetUint32(0, 255));",
            "      }",
            "      break;",
        ]
    if seq:
        lines += [
            "    case 4:",
            "      // Duplicate a structure. Repetition is how a fixed-size table",
            "      // gets exhausted, and coverage gives no gradient toward it",
            "      // (eval/coverage_gradient.py).",
            f"      if ({items}.size() < 64) {{",
            f"        {items}.push_back(Item);",
            "      }",
            "      break;",
            "    case 5:",
            f"      if ({items}.size() > 1) {{",
            f"        {items}.erase({items}.begin() + Index);",
            "      }",
            "      break;",
        ]
    if spec.wire_size_override:
        lines += [
            "    default:",
            "      Item.WireSize = GetUint32(0, 16);",
            "      break;",
            "    }",
        ]
    else:
        lines += ["    default:", "      break;", "    }"]

    if not seq:
        lines.append("    Root = Items[0];")
    lines += [
        "    json::json Serialized;",
        "    to_json(Serialized, Root);",
        "    std::string Out = Serialized.dump();",
        "    if (Out.size() > MaxSize) {",
        "      return Generate();",
        "    }",
        "    return Out;",
    ]
    return "\n".join(lines)


def write_module(
    spec: InputSpec,
    harness: HarnessSpec,
    out_path: Path,
    **kwargs,
) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(generate_module(spec, harness, **kwargs), encoding="utf-8")
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
        "--harness",
        type=Path,
        default=None,
        help="HarnessSpec JSON, from prep/harness_derive.py; enables --module-out",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "fuzzer" / "module" / "generated_input.h",
    )
    ap.add_argument(
        "--module-out",
        type=Path,
        default=None,
        help="write a COMPLETE fuzzer module here (needs --harness)",
    )
    ap.add_argument("--namespace", default=None)
    args = ap.parse_args(argv)

    spec = InputSpec.model_validate_json(args.spec.read_text(encoding="utf-8"))

    if args.module_out:
        harness_path = args.harness or REPO_ROOT / "artifacts" / "harness_spec.json"
        if not harness_path.exists():
            raise SystemExit(
                f"--module-out needs a HarnessSpec; {harness_path} does not exist. "
                f"Run: python -m prep.harness_derive"
            )
        harness = HarnessSpec.model_validate_json(
            harness_path.read_text(encoding="utf-8")
        )
        path = write_module(
            spec, harness, args.module_out,
            spec_path=str(args.spec), harness_path=str(harness_path),
            namespace=args.namespace,
        )
        text = path.read_text(encoding="utf-8")
        print(f"{harness.entry_symbol}: wtf target {harness.target_name!r}")
        print(f"  {len(spec.fields)} field(s), {spec.header_bytes}-byte header")
        print(f"  {len(harness.breakpoints)} derived breakpoint(s)")
        print(f"  sequence per test-case: {harness.deliver_sequence}")
        print(f"wrote {path} ({len(text.splitlines())} lines, "
              f"{'ASCII' if all(ord(c) < 128 for c in text) else 'NON-ASCII!'})")
        # AND the header, when one was asked for. This used to `return 0` here, so a
        # caller passing both --out and --module-out -- which the pipeline's stage 09
        # does -- got the module written and the header left exactly as it was. On a
        # tree that already had one from an earlier target, that meant a STALE header
        # sitting next to a fresh module, describing different fields under different
        # names, with nothing to say so (D-075).
        if args.out:
            header = write_header(spec, args.out, spec_path=str(args.spec))
            print(f"wrote {header}")
        return 0

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
