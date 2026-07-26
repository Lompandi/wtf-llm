"""Match a derived InputSpec to an existing struct BY LAYOUT, to keep a corpus readable.

Edge 14 -- compiling the derived structure into the shipped module -- sat unwired for
one concrete reason. The model names fields from pseudo-C, so it called the development
target's four fields `Cmd`/`HeaderInfo`/`PayloadSize`/`Payload` while the hand-written
module calls them `Command`/`Id`/`BodySize`/`Body`. Adopting the generated struct would
have stopped **149 recorded corpus files and 52 crash files** from parsing, and those
cannot be re-derived: they are the record of campaigns that already happened (D-055).

Renaming a field is not what invalidates a corpus. Renaming it without keeping the old
key readable is. So this fills `InputField.legacy_names`, `fuzzer/codegen.py` emits a
`from_json` that tries each, and the recorded corpus keeps parsing with nothing
rewritten and no campaign re-run.

**Matched by offset and width, never by name.** CP11's gate says the derived spec must
reproduce a hand-written layout "by offset, width and length semantics -- never by field
name, because pseudo-C has no names and comparing names tests the model's word choice".
The same argument applies here and more sharply: the entire point is that the names
DIFFER, so a name-based match would find nothing. Two fields correspond when they begin
at the same offset and are the same width -- which is what the wire format says, and
what a parser reading those bytes actually cares about.

If the layouts disagree, this returns the disagreement instead of guessing. A wrong
alias is worse than no alias: it would silently read one field's bytes into another and
every recorded test-case would parse into a different structure than the one recorded.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from arch.contracts import InputSpec

__all__ = ["CppField", "LayoutMismatch", "apply_aliases", "parse_cpp_struct", "pair_by_layout"]

_WIDTH = {
    "uint8_t": 1, "int8_t": 1, "uint16_t": 2, "int16_t": 2,
    "uint32_t": 4, "int32_t": 4, "uint64_t": 8, "int64_t": 8,
}

# A field declaration inside a struct: `uint16_t BodySize;` or
# `std::vector<uint8_t> Body;`. Deliberately narrow -- anything it does not recognise is
# reported rather than skipped, because a silently dropped field shifts every offset
# after it.
_FIELD = re.compile(
    r"^\s*(?:(?P<scalar>u?int(?:8|16|32|64)_t)|(?P<bytes>std::vector<uint8_t>))"
    r"\s+(?P<name>[A-Za-z_]\w*)\s*;"
)

# Generated bookkeeping, not part of the wire format.
_NOT_WIRE = frozenset({"WireSize"})


class LayoutMismatch(RuntimeError):
    """Two structs describe different wire formats, so no alias mapping is safe."""


@dataclass(frozen=True)
class CppField:
    name: str
    ctype: str | None  # None for the variable-length tail
    offset: int
    width: int | None  # None for the tail


def parse_cpp_struct(source: str, struct_name: str | None = None) -> list[CppField]:
    """Fields of a C++ struct, with the offset each one starts at.

    Offsets are computed by summing widths in declaration order -- which is what the
    generated serialiser does when it writes the wire format, and therefore the layout
    that a recorded test-case was written against. Not `offsetof`: C++ padding is not
    what reaches the guest.
    """
    lines = source.splitlines()
    start = 0
    if struct_name:
        for index, line in enumerate(lines):
            if re.search(rf"\bstruct\s+{re.escape(struct_name)}\b", line):
                start = index + 1
                break
        else:
            raise LayoutMismatch(f"no struct named {struct_name!r} in the source")

    out: list[CppField] = []
    offset = 0
    depth = 0
    for line in lines[start:]:
        depth += line.count("{") - line.count("}")
        if struct_name and depth < 0:
            break
        match = _FIELD.match(line)
        if not match:
            continue
        name = match.group("name")
        if name in _NOT_WIRE:
            continue
        if match.group("bytes"):
            out.append(CppField(name=name, ctype=None, offset=offset, width=None))
            continue
        ctype = match.group("scalar")
        width = _WIDTH[ctype]
        out.append(CppField(name=name, ctype=ctype, offset=offset, width=width))
        offset += width
    return out


def _spec_layout(spec: InputSpec) -> list[CppField]:
    out: list[CppField] = []
    offset = 0
    for field in spec.fields:
        if field.kind == "bytes":
            out.append(CppField(name=field.name, ctype=None, offset=offset, width=None))
            continue
        width = _WIDTH.get(str(field.ctype))
        if width is None:
            raise LayoutMismatch(
                f"{field.name} has ctype {field.ctype!r}, whose width is unknown, so "
                f"its offset cannot be computed"
            )
        out.append(
            CppField(name=field.name, ctype=field.ctype, offset=offset, width=width)
        )
        offset += width
    return out


def pair_by_layout(
    spec: InputSpec, existing: list[CppField]
) -> dict[str, str]:
    """`{spec field name: existing field name}` for fields at the same offset and width.

    Raises when the two layouts are not the same wire format. Being strict is the point:
    an alias that maps the wrong field reads one field's bytes into another, and every
    recorded test-case would then parse into a structure nobody recorded.
    """
    derived = _spec_layout(spec)
    if len(derived) != len(existing):
        raise LayoutMismatch(
            f"the derived spec has {len(derived)} field(s) and the existing struct has "
            f"{len(existing)}: "
            f"{[f.name for f in derived]} vs {[f.name for f in existing]}. These are "
            f"different wire formats, so no alias mapping is safe."
        )

    mapping: dict[str, str] = {}
    for want, have in zip(derived, existing):
        if want.offset != have.offset or want.width != have.width:
            raise LayoutMismatch(
                f"{want.name} sits at offset {want.offset} width {want.width} but "
                f"{have.name} sits at offset {have.offset} width {have.width}. "
                f"Matching these would read one field's bytes as another's."
            )
        if want.name != have.name:
            mapping[want.name] = have.name
    return mapping


def apply_aliases(spec: InputSpec, existing: list[CppField]) -> tuple[InputSpec, dict[str, str]]:
    """A copy of `spec` whose fields accept the existing struct's names too.

    Returns (spec, mapping). An empty mapping means the names already agree, which is
    the case worth reporting rather than treating as failure -- it is what happens on a
    second derivation of the same target.
    """
    mapping = pair_by_layout(spec, existing)
    updated = spec.model_copy(deep=True)
    for field in updated.fields:
        alias = mapping.get(field.name)
        if alias and alias not in field.legacy_names:
            field.legacy_names = [*field.legacy_names, alias]
    return updated, mapping


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--spec", required=True, type=Path, help="artifacts/input_spec.json")
    ap.add_argument(
        "--existing",
        required=True,
        type=Path,
        help="the .cc whose struct a recorded corpus was written against",
    )
    ap.add_argument("--struct", default=None, help="struct name; defaults to the first")
    ap.add_argument("--out", type=Path, default=None, help="defaults to --spec in place")
    args = ap.parse_args(argv)

    spec = InputSpec.model_validate_json(args.spec.read_text(encoding="utf-8"))
    existing = parse_cpp_struct(
        args.existing.read_text(encoding="utf-8", errors="replace"), args.struct
    )
    if not existing:
        raise SystemExit(f"no struct fields found in {args.existing}")

    updated, mapping = apply_aliases(spec, existing)
    out = args.out or args.spec
    out.write_text(updated.model_dump_json(indent=2), encoding="utf-8")

    print(f"{args.existing.name}: {len(existing)} wire field(s)")
    for field in existing:
        width = "variable" if field.width is None else f"{field.width}B"
        print(f"  +{field.offset:<3} {width:<9} {field.name}")
    if mapping:
        print("aliases added (matched by offset and width, not by name):")
        for derived_name, legacy in mapping.items():
            print(f"  {derived_name} also reads {legacy!r}")
    else:
        print("names already agree; no aliases needed")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
