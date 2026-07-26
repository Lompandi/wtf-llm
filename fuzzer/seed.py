"""A first test-case, synthesised from the derived InputSpec.

The pipeline refused to start without at least one file in `inputs/`, and the reason
was sound: the master starts from that directory, and an empty corpus gives the mutator
nothing to work from -- the campaign then runs to completion having explored nothing.

But it asked the user for something the pipeline already knows. By the time codegen
runs, an `InputSpec` describes every field of the structure the target parses: the
widths, which field is a length and what it counts, and any magic value the model found
in the pseudo-C. A structurally valid test-case follows from that with no guessing at
all, and a valid one is worth considerably more than the arbitrary bytes a user reaches
for when told "put a seed here" -- a seed that fails the parser's first length check
explores one branch (D-075).

**This is a starting point, not a substitute for a real sample.** A captured input from
the target's actual traffic carries information no spec does: which command values are
interesting, what a realistic body looks like, which optional fields appear together. A
seed written from the structure alone gets past the parser's validation and no further.
Anything already in `inputs/` is therefore left alone.
"""

from __future__ import annotations

import json
from pathlib import Path

__all__ = ["SeedError", "ensure_seed", "seed_from_spec"]

# Enough bytes to be a non-trivial body, small enough that the first mutations still
# reach every field. The exact number matters less than that it is not zero: a
# zero-length payload skips the copy loop entirely in most parsers.
_DEFAULT_PAYLOAD = 16


class SeedError(RuntimeError):
    pass


def _scalar_value(field: dict) -> int:
    """A value for one scalar field: its magic value where the parser demands one.

    A magic mismatch is normally the very first thing a parser rejects, so getting this
    wrong means every test-case dies at the first comparison and coverage never leaves
    the entry block. When the model recorded one, it is the single most valuable byte
    sequence available.
    """
    magic = field.get("magic_value")
    if magic in (None, ""):
        return 0
    if isinstance(magic, int):
        return magic
    text = str(magic).strip()
    try:
        return int(text, 0) if text.lower().startswith("0x") else int(text)
    except ValueError:
        # A magic recorded as characters, e.g. "MZ" or "RIFF".
        raw = text.encode("utf-8", "replace")[:8]
        return int.from_bytes(raw, "little") if raw else 0


def seed_from_spec(spec: dict, *, payload_bytes: int = _DEFAULT_PAYLOAD) -> dict:
    """One structurally valid test-case, in the JSON shape the generated module reads.

    The shape is set by `fuzzer/codegen.py`'s `from_json`: a flat object of field names,
    wrapped in `{"<sequence_field>": [...]}` when the spec says a test-case delivers
    several structures to the same live process.
    """
    fields = spec.get("fields") or []
    if not fields:
        raise SeedError(
            "the InputSpec describes no fields, so there is no structure to build a "
            "test-case from"
        )

    record: dict[str, object] = {}
    lengths: list[dict] = []
    for field in fields:
        name, kind = field.get("name"), field.get("kind")
        if not name:
            continue
        if kind == "bytes":
            cap = field.get("max_length") or payload_bytes
            size = max(1, min(int(cap), payload_bytes))
            # 'A' repeated: recognisable in a hex dump and in a crash's input, which
            # matters when the question is "did my seed reach this code".
            record[name] = [0x41] * size
        elif kind == "length":
            lengths.append(field)
            record[name] = 0  # filled in below, once the counted field exists
        else:
            record[name] = _scalar_value(field)

    # Length fields LAST, because a length that disagrees with what it counts is
    # rejected before anything interesting runs -- and it is the mutator's job to try
    # that case deliberately, not the seed's job to start there.
    for field in lengths:
        counted = field.get("counts_field")
        value = record.get(counted) if counted else None
        size = len(value) if isinstance(value, list) else 0
        if field.get("includes_header"):
            size += _header_bytes(fields)
        record[field["name"]] = size

    sequence_field = spec.get("sequence_field_name")
    if spec.get("supports_sequence") and sequence_field:
        return {sequence_field: [record]}
    return record


_WIDTHS = {
    "uint8_t": 1, "int8_t": 1, "uint16_t": 2, "int16_t": 2,
    "uint32_t": 4, "int32_t": 4, "uint64_t": 8, "int64_t": 8,
}


def _header_bytes(fields: list[dict]) -> int:
    """Total width of the fixed-size fields, i.e. everything before the body."""
    return sum(
        _WIDTHS.get(str(f.get("ctype")), 0)
        for f in fields
        if f.get("kind") != "bytes"
    )


def ensure_seed(spec_path: Path, inputs_dir: Path) -> Path | None:
    """Write a derived seed into `inputs/` if it is empty. Returns the path, or None.

    Never overwrites and never adds a second file: a user's own sample is better than
    anything derivable, so the presence of ANY file here means this does nothing.
    """
    inputs_dir = Path(inputs_dir)
    inputs_dir.mkdir(parents=True, exist_ok=True)
    existing = [p for p in inputs_dir.iterdir() if p.is_file()]
    if existing:
        return None

    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    seed = seed_from_spec(spec)
    out = inputs_dir / "derived_seed.json"
    out.write_text(json.dumps(seed, indent=2), encoding="utf-8")
    return out


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--spec", required=True, type=Path, help="artifacts/input_spec.json")
    ap.add_argument("--inputs", required=True, type=Path, help="targets/<name>/inputs")
    args = ap.parse_args(argv)

    written = ensure_seed(args.spec, args.inputs)
    if written is None:
        count = len([p for p in args.inputs.iterdir() if p.is_file()])
        print(f"{args.inputs} already holds {count} seed(s); left alone")
    else:
        print(f"wrote {written}")
        print(json.dumps(json.loads(written.read_text(encoding='utf-8')))[:200])
        print(
            "  a structurally valid starting point only -- a captured real input is "
            "worth more, and anything you put here is left alone"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
