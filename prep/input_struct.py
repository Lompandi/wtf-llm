"""Derive a target's input structure from pseudo-C (CLAUDE.md edge 12).

Section 3.1 draws this as "LLM-generated input struct / reads pseudo-C (A2)
`[LLM]`", and section 3.1's ownership list names it one of the five things that are
*our* contribution rather than wtf features. It is the second half of contribution
1: the fuzz entry says *where* input arrives, and this says *what shape* it has.
Together they are the injection decision that otherwise requires a
reverse-engineering expert -- snapshot fuzzing's main usability barrier.

**Why it was the last thing built, recorded because it is a process lesson.** No
gate in section 8 lists edge 12 or 14 -- GATE 4 covers 18-26/30/31, GATE 6 covers
3/4/9/28/37 -- so under RULE 3 this was the only component in the architecture
with no definition of done. Everything around it was forced to completion by a
gate; this stayed hand-written while looking finished on the diagram. A box on an
architecture diagram is not a deliverable until something can fail.

**The model does not write C++.** It emits an :class:`InputSpec`, which
:mod:`fuzzer.codegen` turns into a header. Asking for C++ directly fails RULE 4
three ways: a compile error surfaces in the C++ toolchain far from the model's
mistake; free-form C++ cannot be schema-checked; and "units and encoding are
stated" is enforceable in a contract and merely hoped for in prose.

**RULE 1.** This runs at build time, once per target, never inside the fuzzing
loop.

Verification
------------
tlv_server has ground truth: the hand-written `Packet_t` is
`{uint32 Command, uint16 Id, uint16 BodySize, vector<uint8> Body}` with an 8-byte
header. A derived spec that reproduces it -- including that `BodySize` counts
`Body` in bytes and not elements, and excludes the header -- is evidence the
approach works. `tests/gates/test_cp11.py` asserts it.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from arch.contracts import FuzzEntry, InputSpec
from llm.client import LlmClient
from prep.pseudoc_cache import PseudoCCache

REPO_ROOT = Path(__file__).resolve().parents[1]

__all__ = ["InputStructError", "derive_input_spec", "check_against_pseudoc"]

# Enough pseudo-C to see the whole parse, not enough to bury it. The entry
# function is what matters; callees are included only if they are few.
_MAX_CHARS_PER_FUNCTION = 12_000
_MAX_EXTRA_FUNCTIONS = 3


class InputStructError(RuntimeError):
    pass


_SYSTEM = (
    "You derive the wire format of a binary's input from Ghidra decompiler "
    "output. The binary has NO source. Pseudo-C is lossy: names are invented, "
    "types are inferred, and inlining is flattened, so reason from what the code "
    "DOES with the bytes -- the offsets it reads, the widths it reads them at, "
    "and what it compares or passes them to -- rather than from any declared "
    "type. Report only structure you can point at a line for."
)


def _prompt(entry: FuzzEntry, code: str, extra: str) -> str:
    return (
        f"Function `{entry.symbol}` in module `{entry.module}` is the fuzz entry: "
        f"the fuzzer will place an attacker-controlled buffer where its input "
        f"arrives and let it parse.\n\n"
        f"The input buffer arrives via: {entry.input_param}\n"
        f"Its length arrives via: {entry.size_param or '(no separate length '
        'parameter was identified)'}\n\n"
        f"DECOMPILED CODE\n{code}\n\n"
        f"{extra}"
        f"Describe the structure this function expects, as fields in wire order "
        f"starting at offset 0 of the buffer.\n\n"
        f"For each field give:\n"
        f"  * name        -- a readable name; invent one if the code has none\n"
        f"  * kind        -- one of:\n"
        f"      scalar    a plain value the parser reads or compares\n"
        f"      length    a value used as a COUNT or SIZE for another field\n"
        f"      magic     a value compared against a constant to accept the input\n"
        f"      bytes     a variable-length payload (at most ONE of these)\n"
        f"      padding   a field the parser never reads\n"
        f"  * ctype       -- uint8_t/uint16_t/uint32_t/uint64_t or the signed "
        f"forms, chosen from the WIDTH the code reads at. REQUIRED for every "
        f"kind EXCEPT `bytes` -- including `magic`, where it is the width of "
        f"the constant being compared. Omit it only for `bytes`.\n"
        f"  * little_endian -- true unless the code byte-swaps\n"
        f"  * rationale   -- the expression in the code that implies this field, "
        f"quoted\n\n"
        f"For a `length` field you MUST also give:\n"
        f"  * counts_field    -- the name of the field it sizes\n"
        f"  * unit            -- \"bytes\" or \"elements\". Say which the code "
        f"actually uses; if it is passed straight to a memcpy length, it is bytes\n"
        f"  * includes_header -- true if the count covers the fixed header as "
        f"well as the payload, false if it covers only the payload\n\n"
        f"For a `magic` field give magic_value as an integer AND a ctype. A "
        f"magic field with no ctype is REJECTED by the contract -- the harness "
        f"cannot write a constant whose width it does not know -- and the "
        f"prompt used to ask only for the value, so a correct reading of the "
        f"code still failed validation (D-075).\n"
        f"For the `bytes` field give max_length, a sane upper bound, AND say how "
        f"it ends -- every variable-length field must end somehow:\n"
        f"  * if a `length` field counts it, name that field in counts_field;\n"
        f"  * if the parser instead reads until a sentinel byte -- a "
        f"NUL-terminated string is the common case -- give terminator as that "
        f"byte (0 for a C string) and do NOT invent a length field.\n"
        f"A field that is neither counted nor delimited is rejected, because the "
        f"harness would truncate every test-case.\n\n"
        f"Also decide:\n"
        f"  * struct_name       -- a C++ name for one of these structures\n"
        f"  * supports_sequence -- true if the parser is called repeatedly on a "
        f"stream and state persists between calls, so one test-case should carry "
        f"several structures in order\n"
        f"  * rationale         -- two or three sentences on how you read the "
        f"format, naming the offsets\n"
        f"  * source_functions  -- which functions you used\n\n"
        f"Offsets must be consistent: the fixed fields, in order, must account for "
        f"every byte before the variable-length payload. If the code reads offset "
        f"6 as a 16-bit value and offset 8 as the payload, then offsets 0-5 are "
        f"fields too, even if you have to name them from how they are used."
    )


def _find_callers(
    entry: FuzzEntry, cache: PseudoCCache, *, limit: int = _MAX_EXTRA_FUNCTIONS
) -> list[tuple[str, str]]:
    """Functions in A2 whose code calls the entry, shortest first.

    **Statefulness is a property of the CALLER, not of the parser.** Measured on
    tlv_server: asked whether one test-case should carry several structures, the
    model answered no -- correctly, from what it had been given. `ProcessPacket`'s
    own pseudo-C shows a `while` loop, but that is the chunk-table search, not a
    receive loop. The `recv` loop and the repeated `ProcessPacket(buf, len)` call
    are in `main`. So the question was unanswerable from the parser alone, and the
    fix is to supply who calls it rather than to reword the prompt.

    Matched textually on `<symbol>(`, because A2 stores decompiled text and no call
    graph. Cheap and good enough: a false positive costs a few thousand characters
    of prompt, a false negative loses information the model then has to guess at.
    """
    if not entry.symbol:
        return []

    needle = f"{entry.symbol}("
    found: list[tuple[str, str]] = []
    for name in cache.functions(module=entry.module):
        if name == entry.symbol:
            continue
        record = cache.get_by_function(name, module=entry.module)
        if record and needle in record.code:
            found.append((name, record.code))

    # Shortest first: a small caller is usually the immediate one, and a huge
    # function that merely mentions the symbol is the least informative.
    found.sort(key=lambda pair: len(pair[1]))
    return found[:limit]


def _gather_code(
    entry: FuzzEntry, cache: PseudoCCache
) -> tuple[str, str, list[str]]:
    """Pseudo-C for the entry plus its callers. Raises if the entry is absent."""
    if not entry.symbol:
        raise InputStructError(
            "the FuzzEntry has no symbol, so its pseudo-C cannot be looked up by "
            "name. Re-run entry selection, or look the address up in A2 first."
        )

    # module=entry.module, because A2 is ONE SQLite file shared by every target ever
    # built: `build` uses INSERT OR REPLACE and deletes nothing, so after a second
    # target's stage 02 the cache holds both programs' rows. Unqualified, this returned
    # whichever `main`/`printf`/`__scrt_*` row came first -- and those names collide
    # for any two statically linked MSVC binaries, so it is a certainty rather than a
    # coincidence. `_find_callers` below was already module-qualified, which made the
    # prompt a MIXTURE of two programs: this program's callers around another
    # program's body (D-073).
    primary = cache.get_by_function(entry.symbol, module=entry.module)
    if primary is None:
        primary = cache.get_by_addr(entry.static_addr, module=entry.module)
    if primary is None:
        raise InputStructError(
            f"A2 has no pseudo-C for {entry.symbol!r} ({entry.static_addr:#x}). "
            f"Build A2 over a scope that includes the fuzz entry -- deriving an "
            f"input structure without the parser's code is guesswork."
        )

    code = primary.code
    if len(code) > _MAX_CHARS_PER_FUNCTION:
        code = code[:_MAX_CHARS_PER_FUNCTION] + "\n/* ...truncated... */\n"

    used = [primary.function]
    callers = _find_callers(entry, cache)
    if not callers:
        extra = (
            "NO CALLER of this function was found in the decompiled cache, so "
            "there is no evidence either way about whether it is invoked "
            "repeatedly on a stream. Say supports_sequence=false unless the "
            "function's own code shows it consuming more than one structure.\n\n"
        )
        return code, extra, used

    blocks = []
    for name, caller_code in callers:
        used.append(name)
        trimmed = caller_code
        if len(trimmed) > _MAX_CHARS_PER_FUNCTION // 2:
            trimmed = trimmed[: _MAX_CHARS_PER_FUNCTION // 2] + "\n/* ...cut... */\n"
        blocks.append(f"=== caller: {name} ===\n{trimmed}")

    extra = (
        "CALLERS OF THE ENTRY FUNCTION. These decide `supports_sequence`, which "
        "the entry function's own code cannot answer. Look for a receive/read "
        "loop that calls the entry more than once against state that persists "
        "between calls -- a global table, a list, an allocation registry. If you "
        "see one, set supports_sequence=true, because a test-case then has to be "
        "able to carry a SEQUENCE of structures or whole branches stay "
        "unreachable.\n\n" + "\n\n".join(blocks) + "\n\n"
    )
    return code, extra, used


def check_against_pseudoc(spec: InputSpec, code: str) -> list[str]:
    """Cheap consistency checks between the spec and the code it came from.

    Warnings, not errors: pseudo-C is lossy enough that a mismatch is sometimes
    the decompiler's fault rather than the model's. They are returned so the
    caller records them next to the spec instead of discarding them -- a spec that
    disagrees with its own source is exactly what a reviewer needs to see.
    """
    warnings: list[str] = []
    header = spec.header_bytes

    # A size guard is the most common way a parser states its header length, and
    # it is a strong cross-check on the field layout.
    import re

    guards = [
        int(match.group(1))
        for match in re.finditer(r"(?:param_2|size|len\w*)\s*<\s*(\d+)", code)
    ]
    if guards and header and header not in guards:
        warnings.append(
            f"the code guards against sizes < {sorted(set(guards))} but the "
            f"derived fixed header is {header} bytes; one of the two is wrong"
        )

    for field in spec.fields:
        if field.kind != "length":
            continue
        counted = next(f for f in spec.fields if f.name == field.counts_field)
        if counted.kind != "bytes" and field.unit == "bytes":
            warnings.append(
                f"{field.name} counts {counted.name} in bytes, but "
                f"{counted.name} is a fixed-width {counted.ctype} -- a length "
                f"field over a fixed field is usually a misreading"
            )
        if "memcpy" in code and field.unit == "elements":
            warnings.append(
                f"{field.name} is declared in elements while the code calls "
                f"memcpy, whose third argument is bytes; check the unit"
            )

    if not any(f.kind == "bytes" for f in spec.fields):
        warnings.append(
            "no variable-length payload was identified. That is possible, but a "
            "fixed-size-only format means the fuzzer can only vary field values, "
            "never the length -- confirm the parser really has no tail"
        )
    return warnings


def derive_input_spec(
    entry: FuzzEntry,
    cache: PseudoCCache,
    client: LlmClient,
    *,
    role: str = "input_struct",
) -> tuple[InputSpec, list[str]]:
    """Derive an InputSpec for ``entry``. Returns the spec and any warnings.

    The spec is validated by :class:`InputSpec` itself -- duplicate names, a
    length field that names no target, more than one variable-length field, an
    uncounted tail -- so this only adds the checks that need the source code.
    """
    code, extra, used = _gather_code(entry, cache)

    spec = client.complete_json(
        role, _prompt(entry, code, extra), InputSpec, system=_SYSTEM
    )

    # The model is asked for these but must not be trusted to set them: the module
    # and entry are facts we already have, and letting a model restate them is how
    # a spec ends up describing the wrong function.
    spec.module = entry.module
    spec.entry_symbol = entry.symbol or spec.entry_symbol
    if not spec.source_functions:
        spec.source_functions = used

    return spec, check_against_pseudoc(spec, code)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--entry",
        type=Path,
        default=REPO_ROOT / "artifacts" / "fuzz_entry.json",
        help="FuzzEntry JSON from prep/entry_select.py",
    )
    ap.add_argument(
        "--cache",
        type=Path,
        default=REPO_ROOT / "artifacts" / "a2_pseudoc_module.sqlite",
    )
    ap.add_argument(
        "--out", type=Path, default=REPO_ROOT / "artifacts" / "input_spec.json"
    )
    args = ap.parse_args(argv)

    entry = FuzzEntry.model_validate_json(args.entry.read_text(encoding="utf-8"))
    print(f"deriving the input structure of {entry.module}!{entry.symbol}")

    with PseudoCCache(args.cache) as cache, LlmClient.from_config() as client:
        spec, warnings = derive_input_spec(entry, cache, client)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(spec.model_dump_json(indent=2), encoding="utf-8")

    print(f"\n{spec.struct_name}: {len(spec.fields)} field(s), "
          f"{spec.header_bytes}-byte fixed header")
    for field in spec.fields:
        detail = field.ctype or "bytes"
        if field.kind == "length":
            detail += (
                f" -> counts {field.counts_field} in {field.unit}"
                f"{' incl. header' if field.includes_header else ''}"
            )
        if field.kind == "magic":
            detail += f" == {field.magic_value:#x}"
        print(f"  {field.name:<16} {field.kind:<9} {detail}")
    print(f"sequence of packets per test-case: {spec.supports_sequence}")

    if warnings:
        print("\nconsistency warnings against the pseudo-C:")
        for warning in warnings:
            print(f"  ! {warning}")

    print(f"\nwrote {args.out}")
    print(f"next: python -m fuzzer.codegen --spec {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
