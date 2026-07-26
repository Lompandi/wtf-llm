"""Everything about a snapshot's layout, from the three files a user actually has.

The premise this module exists to satisfy: **a memory dump, a register state, and the
original executable.** Nothing else. No `config/target.yaml`, no `symbol-store.json`, no
`--module-base`, no `--entry-symbol`, no editing anything.

That turns out to be enough, and the reason is arithmetic rather than clever. Windows
maps an image on a 64 KB boundary, so for a snapshot taken at a breakpoint on a
function:

    module_base = rip - (function_static_addr - image_base)

is a candidate base for *every* function Ghidra found, and almost all of those
candidates are not 64 KB aligned. Filtering on alignment collapses the set. Measured on
the development target's snapshot -- 176 functions, `rip = 0x7ff719e51150`,
`image_base = 0x140000000` -- exactly one candidate survives:

    module_base = 0x7ff719e50000   from 1 function: ProcessPacket

which matches `symbol-store.json` exactly. And because the surviving candidate names
the function, the same step yields **the fuzz entry**: the snapshot's `rip` is where
execution was stopped, so it is where fuzzing must resume. That is not a guess to be
checked later against a model's opinion -- it is the one fact the snapshot is a record
of.

This replaces three separate demands on the user with one derivation:

* `module_base` came from `symbol-store.json`, which `ingest_state_dir` hard-required
  and which a user who has only a dump does not have;
* `ghidra_image_base` came from `config/target.yaml`, which describes one target;
* `entry_symbol` came from `config/target.yaml`'s `entry:` block, i.e. from the
  development target, which is why every other target was scoped to `ProcessPacket`
  (D-073).

**When it cannot decide it says so and stops.** Ambiguity here would put every later
address conversion silently off by a constant, which is the failure mode that produces
coverage numbers for the wrong bytes rather than an error (D-027).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

__all__ = [
    "IMAGE_ALIGNMENT",
    "Layout",
    "LayoutError",
    "candidates_from_rip",
    "derive_layout",
    "read_rip",
]

# Windows maps images on a 64 KB boundary (SEC_IMAGE / the allocation granularity).
# This is the entire reason the derivation below is decidable: it throws away all but a
# 1-in-65536 slice of the candidate slides.
IMAGE_ALIGNMENT = 0x10000


class LayoutError(RuntimeError):
    """The layout could not be derived, or could not be derived unambiguously."""


@dataclass(frozen=True)
class Layout:
    """Where the target module sits in the snapshot, and where execution stopped."""

    module: str
    module_base: int
    image_base: int
    rip: int
    entry_symbol: str
    entry_static_addr: int
    # How this was decided, recorded because "derived" and "you told me" are different
    # levels of confidence and the next reader deserves to know which.
    source: str

    @property
    def slide(self) -> int:
        return self.module_base - self.image_base

    def to_json(self) -> str:
        payload = asdict(self)
        payload["slide"] = self.slide
        # Hex alongside the integers: every one of these is an address, and a decimal
        # address in a log is unreadable when the thing you need to do is compare it.
        payload["hex"] = {
            name: hex(payload[name])
            for name in ("module_base", "image_base", "rip", "entry_static_addr", "slide")
        }
        return json.dumps(payload, indent=2)

    @classmethod
    def load(cls, path: Path) -> Layout:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        fields = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in raw.items() if k in fields})


def read_rip(regs_json: Path) -> int:
    """`rip` from a wtf `regs.json`, whether it is a hex string or an integer."""
    raw = json.loads(Path(regs_json).read_text(encoding="utf-8"))
    if "rip" not in raw:
        raise LayoutError(
            f"{regs_json} has no `rip`. This is the register state of the snapshot; "
            f"without rip there is no way to know where execution stopped, and "
            f"therefore no way to know what to fuzz."
        )
    value = raw["rip"]
    if isinstance(value, str):
        return int(value, 16)
    return int(value)


def candidates_from_rip(
    rip: int,
    image_base: int,
    functions: dict[str, int],
    *,
    alignment: int = IMAGE_ALIGNMENT,
) -> dict[int, list[str]]:
    """Candidate module bases, each mapped to the functions that would put rip there.

    One entry per plausible base. A base is plausible when it is positive and aligned:
    an image is never mapped at a misaligned address, so a candidate that is misaligned
    is arithmetic that happens to work out rather than a real placement.
    """
    out: dict[int, list[str]] = {}
    for name, static in functions.items():
        base = rip - (int(static) - image_base)
        if base <= 0 or base % alignment:
            continue
        out.setdefault(base, []).append(name)
    for names in out.values():
        names.sort()
    return out


def read_cr3(regs_json: Path) -> int | None:
    raw = json.loads(Path(regs_json).read_text(encoding="utf-8"))
    value = raw.get("cr3")
    if value is None:
        return None
    base = int(value, 16) if isinstance(value, str) else int(value)
    # cr3's low 12 bits are flags (PCID/PWT/PCD), not part of the frame address.
    return base & ~0xFFF


def _mapped_image_bases(dump, cr3: int, limit: int = 4096) -> list[int]:
    """Every 64 KB-aligned USER virtual address in the snapshot that starts with 'MZ'.

    Found by walking the process's own page tables out of the dump, which is what makes
    this work at all: the user half is a 128 TB space, so probing it address by address
    is not an option, but the tables list exactly what is mapped and a small process
    maps a few thousand pages.

    Only 64 KB-aligned addresses are considered, because Windows maps images on the
    allocation granularity -- the same fact that makes the rip derivation decidable.
    """
    def entries(physical_page_addr: int) -> list[int]:
        raw = dump.read_physical_page(physical_page_addr)
        if not raw:
            return []
        return [
            int.from_bytes(raw[i : i + 8], "little") for i in range(0, len(raw), 8)
        ]

    PRESENT, LARGE = 1 << 0, 1 << 7
    FRAME = 0x000F_FFFF_FFFF_F000
    found: list[int] = []

    # PML4 entries 0..255 are the user half; 256.. is kernel space and cannot hold the
    # target's image.
    for pml4_i, pml4e in enumerate(entries(cr3)[:256]):
        if not pml4e & PRESENT:
            continue
        for pdpt_i, pdpte in enumerate(entries(pml4e & FRAME)):
            if not pdpte & PRESENT or pdpte & LARGE:
                continue  # a 1 GB page is never an image mapping
            for pd_i, pde in enumerate(entries(pdpte & FRAME)):
                if not pde & PRESENT or pde & LARGE:
                    continue
                for pt_i, pte in enumerate(entries(pde & FRAME)):
                    if not pte & PRESENT:
                        continue
                    va = (
                        (pml4_i << 39) | (pdpt_i << 30) | (pd_i << 21) | (pt_i << 12)
                    )
                    if va % IMAGE_ALIGNMENT:
                        continue
                    page = dump.read_physical_page(pte & FRAME)
                    if page and page[:2] == b"MZ":
                        found.append(va)
                        if len(found) >= limit:
                            return found
    return found


def _pe_identity(data: bytes) -> tuple[int, int, int] | None:
    """(TimeDateStamp, AddressOfEntryPoint, SizeOfImage) -- identical in file and image.

    Three fields rather than one because a single one collides: TimeDateStamp alone is
    shared by every binary from one build, and SizeOfImage alone by many.
    """
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe = int.from_bytes(data[0x3C:0x40], "little")
    if pe + 0x58 > len(data) or data[pe : pe + 4] != b"PE\0\0":
        return None
    return (
        int.from_bytes(data[pe + 0x08 : pe + 0x0C], "little"),  # TimeDateStamp
        int.from_bytes(data[pe + 0x28 : pe + 0x2C], "little"),  # AddressOfEntryPoint
        int.from_bytes(data[pe + 0x50 : pe + 0x54], "little"),  # SizeOfImage
    )


def module_base_from_dump(
    mem_dmp: Path, regs_json: Path, binary: Path
) -> tuple[int | None, str]:
    """Where the snapshot has this executable mapped. Returns (base, how_it_went).

    **This is the primary method**, and it is better than matching rip against function
    addresses for one specific reason: it does not care where the snapshot was taken. A
    dump captured mid-function, inside a callee, or in the middle of a memcpy still
    carries the module list, so the base is a fact to be read rather than a slide to be
    solved for.

    Identified by comparing the mapped image's PE header with the file's -- so it also
    answers a question nothing else here can: **is this dump even a dump of this
    executable.** A base found for a header that does not match is not returned.

    Never raises. A dump that cannot be parsed, a missing cr3, an unusual paging
    configuration: all of them return (None, reason) and let the caller fall back. The
    fallback is a derivation from rip that needs no dump at all, so failing here is
    inconvenient rather than fatal.
    """
    try:
        import kdmp_parser
    except ImportError:
        return None, (
            "kdmp-parser is not installed, so the dump's module list cannot be read "
            "(pip install -r requirements.txt)"
        )

    cr3 = read_cr3(regs_json)
    if cr3 is None:
        return None, f"{Path(regs_json).name} records no cr3, so the page tables of the snapshot's process cannot be walked"

    wanted = _pe_identity(Path(binary).read_bytes()[:0x1000])
    if wanted is None:
        return None, f"{Path(binary).name} has no readable PE header"

    try:
        dump = kdmp_parser.KernelDumpParser(str(mem_dmp))
    except Exception as exc:  # the parser raises a bare RuntimeError on a bad dump
        return None, f"{Path(mem_dmp).name} could not be parsed: {exc}"

    try:
        bases = _mapped_image_bases(dump, cr3)
    except Exception as exc:
        return None, f"walking the page tables of {Path(mem_dmp).name} failed: {exc}"

    for base in bases:
        page = dump.read_virtual_page(base, cr3)
        if page and _pe_identity(bytes(page)) == wanted:
            return base, f"read from the dump's mapped image list ({len(bases)} images mapped)"

    return None, (
        f"{Path(binary).name} is not among the {len(bases)} images mapped in "
        f"{Path(mem_dmp).name} -- either this dump is of a different program, or the "
        f"executable has been rebuilt since the snapshot was taken"
    )


def _functions_from_export(export: dict) -> dict[str, int]:
    """`{name: entry_static}` from a prep/ghidra_headless.py A2 or A3 export."""
    functions: dict[str, int] = {}
    for record in export.get("functions") or ():
        name = record.get("function") or record.get("name")
        addr = record.get("entry_static", record.get("static_addr"))
        if name and addr is not None:
            functions[name] = int(addr)
    if not functions:
        # A3 exports blocks rather than functions; its per-block `function` plus the
        # lowest address in each is the same information.
        lowest: dict[str, int] = {}
        for block in export.get("blocks") or ():
            name, addr = block.get("function"), block.get("static_addr")
            if name and addr is not None:
                lowest[name] = min(int(addr), lowest.get(name, 1 << 62))
        functions = lowest
    return functions


def derive_layout(
    *,
    binary: Path,
    regs_json: Path,
    export: Path,
    module: str | None = None,
    module_base: int | None = None,
    symbol_store: Path | None = None,
    mem_dmp: Path | None = None,
) -> Layout:
    """The whole derivation: dump + regs + exe -> module base and fuzz entry.

    `module_base` and `symbol_store` are escape hatches, not the path. They exist
    because a caller who already knows should not have to be re-convinced, and because
    a snapshot taken somewhere other than a function's first instruction cannot be
    resolved by the alignment argument alone -- see the error raised for that case.
    """
    from prep.snapshot_win import read_pe_image_base

    binary = Path(binary)
    module = module or binary.stem
    notes: list[str] = []
    image_base = read_pe_image_base(binary)
    rip = read_rip(regs_json)
    functions = _functions_from_export(
        json.loads(Path(export).read_text(encoding="utf-8"))
    )
    if not functions:
        raise LayoutError(
            f"{export} lists no functions, so there is nothing to match rip against. "
            f"Run the decompilation stage first."
        )

    # WHERE THE IMAGE IS, in order of authority. The first three are statements about
    # the snapshot; only the last is a derivation.
    #
    #   1. what the caller passed;
    #   2. THE DUMP ITSELF -- walk the snapshot's page tables, find the mapped images,
    #      identify ours by its PE header. This is the primary method because it does
    #      not care where the snapshot was taken, and because it is the only one that
    #      can tell you the dump is of a DIFFERENT program;
    #   3. symbol-store.json, when the snapshotter left one;
    #   4. matching rip against function addresses under the 64 KB alignment
    #      constraint, which needs no dump but only works for a snapshot taken at a
    #      function's first instruction.
    source = "module_base supplied"
    if module_base is None and mem_dmp and Path(mem_dmp).is_file():
        module_base, how = module_base_from_dump(Path(mem_dmp), regs_json, binary)
        if module_base is not None:
            source = how
        else:
            notes.append(how)

    if module_base is None and symbol_store and Path(symbol_store).is_file():
        from prep.snapshot_win import parse_symbol_store

        symbols = parse_symbol_store(Path(symbol_store))
        if module in symbols:
            module_base, source = symbols[module], "symbol-store.json"

    if module_base is not None:
        static = rip - module_base + image_base
        name = _function_at(functions, static)
        if name is None:
            # rip is not a function's first instruction. With the base known from the
            # dump this is still resolvable -- the containing function is what the
            # snapshot is inside of -- and it is a case the rip derivation cannot
            # handle at all, which is why reading the dump is the primary method.
            name = _function_containing(Path(export), static)
            if name is not None:
                notes.append(
                    f"rip is {static - functions.get(name, static):#x} bytes into "
                    f"{name}, not at its first instruction; the snapshot resumes at rip"
                )
        if name is None:
            raise LayoutError(
                f"with module_base {module_base:#x}, rip {rip:#x} maps to static "
                f"address {static:#x}, which lies in no function Ghidra found in "
                f"{binary.name}.\n"
                f"Most likely the snapshot was taken while executing somewhere else "
                f"entirely -- inside ntdll or the CRT rather than in your code -- so "
                f"there is nothing of yours to fuzz at that point. Re-take it with a "
                f"breakpoint on the function you want to fuzz."
            )
        return Layout(
            module=module,
            module_base=module_base,
            image_base=image_base,
            rip=rip,
            entry_symbol=name,
            entry_static_addr=functions.get(name, static),
            source="; ".join([source] + notes),
        )

    candidates = candidates_from_rip(rip, image_base, functions)
    if not candidates:
        raise LayoutError(
            f"no {IMAGE_ALIGNMENT // 1024} KB-aligned module base puts rip {rip:#x} at "
            f"the first instruction of any of the {len(functions)} functions in "
            f"{binary.name}.\n"
            f"The usual cause is that the snapshot was NOT taken at a function entry -- "
            f"it was taken mid-function, so rip is not a function's address and this "
            f"derivation has nothing to anchor on. Two ways forward: re-take the "
            f"snapshot with a breakpoint on the function you want to fuzz, or pass "
            f"--module-base if you know where the image is mapped.\n"
            f"The other possibility is that this dump is not a dump of {binary.name}."
        )
    if len(candidates) > 1:
        listing = "\n".join(
            f"  {base:#x}  ({', '.join(names[:3])})"
            for base, names in sorted(candidates.items())
        )
        raise LayoutError(
            f"rip {rip:#x} is consistent with {len(candidates)} different module "
            f"bases:\n{listing}\n"
            f"Guessing would put every later static/runtime conversion off by a "
            f"constant, which produces coverage for the wrong bytes rather than an "
            f"error (D-027). Pass --module-base, or supply state/symbol-store.json."
        )

    base, names = next(iter(candidates.items()))
    if len(names) > 1:
        raise LayoutError(
            f"module base {base:#x} is unambiguous, but rip {rip:#x} is the first "
            f"instruction of {len(names)} functions at the same address "
            f"({', '.join(names)}) -- identical thunks or aliases. Pass --entry-symbol "
            f"to say which one this snapshot is about."
        )
    return Layout(
        module=module,
        module_base=base,
        image_base=image_base,
        rip=rip,
        entry_symbol=names[0],
        entry_static_addr=functions[names[0]],
        source="; ".join(
            ["derived from rip and the 64 KB image alignment"] + notes
        ),
    )


def _function_containing(export_path: Path, static: int) -> str | None:
    """The function whose address RANGE covers `static`, tightest span first.

    A separate read of the export because the `{name: entry}` mapping used everywhere
    else deliberately throws the ranges away, and the tightest span is the informative
    one where bodies overlap (inlining).
    """
    export = json.loads(Path(export_path).read_text(encoding="utf-8"))
    best: tuple[int, str] | None = None
    for record in export.get("functions") or ():
        low = record.get("min_static", record.get("entry_static"))
        high = record.get("max_static")
        name = record.get("function") or record.get("name")
        if not name or low is None or high is None:
            continue
        if int(low) <= static <= int(high):
            span = int(high) - int(low)
            if best is None or span < best[0]:
                best = (span, name)
    return best[1] if best else None


def _function_at(functions: dict[str, int], static: int) -> str | None:
    for name, addr in functions.items():
        if int(addr) == static:
            return name
    return None


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--binary", required=True, type=Path)
    ap.add_argument("--regs", required=True, type=Path, help="the snapshot's regs.json")
    ap.add_argument(
        "--export", required=True, type=Path, help="prep/ghidra_headless.py A2 or A3"
    )
    ap.add_argument("--module", default=None, help="defaults to the binary's stem")
    ap.add_argument(
        "--module-base",
        default=None,
        help="escape hatch: where the image is mapped, if you already know",
    )
    ap.add_argument("--symbol-store", type=Path, default=None)
    ap.add_argument(
        "--mem-dmp",
        type=Path,
        default=None,
        help="the snapshot's mem.dmp -- read for its mapped image list, which is the "
             "primary way the module base is found",
    )
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args(argv)

    layout = derive_layout(
        binary=args.binary,
        regs_json=args.regs,
        export=args.export,
        module=args.module,
        module_base=int(str(args.module_base), 0) if args.module_base else None,
        symbol_store=args.symbol_store,
        mem_dmp=args.mem_dmp,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(layout.to_json(), encoding="utf-8")

    print(f"module      : {layout.module}")
    print(f"image base  : {layout.image_base:#x}   (from the PE header)")
    print(f"module base : {layout.module_base:#x}   ({layout.source})")
    print(f"slide       : {layout.slide:#x}")
    print(f"rip         : {layout.rip:#x}")
    print(f"fuzz entry  : {layout.entry_symbol} @ {layout.entry_static_addr:#x} static")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
