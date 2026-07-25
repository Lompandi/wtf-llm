"""Global data symbols as reasoning context (CLAUDE.md CP7, Contribution 2).

Decompiled pseudo-C states the bound of a loop over a global table as a
*symbol*::

    puVar11 = ChunkList;
    pp_Var9 = &__dyn_tls_dtor_callback;
    do { ... } while (puVar11 != pp_Var9);

A human reverse-engineer reads the capacity off Ghidra's listing in seconds: two
addresses, an element size, one division. An LLM handed only the pseudo-C cannot,
because the fact was destroyed in decompilation -- this is the concrete, measured
form of "pseudo-C is lossy" that section 2 warns about.

CP7 measured what it costs. Seed generation worked out, correctly and unprompted,
that a branch needed a global table exhausted. It then proposed sequences of 1, 2
and 5 allocations. The table holds four pointers, the fifth allocation writes one
past the end, and the sixth is the first to read that value back as non-null --
so six is the answer and five reaches nothing (D-047).

What this module supplies is the same table a human would look at: names,
addresses, sizes, and the span to the next symbol. It is not the answer to any
particular branch, and it is generated for every global in the program.

**NO LLM HERE.** This prepares context; :mod:`llm.seed_gen` sends it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

__all__ = ["GlobalSymbol", "load_globals", "format_globals"]

# Sections worth reasoning about. `.rdata` is excluded on purpose: in a C++ binary
# it is almost entirely string literals, vftables and `__imp_` import thunks, none
# of which bound a mutable table, and there are hundreds of them.
_DEFAULT_BLOCKS = (".data", ".bss")

# Compiler-generated names that carry no information for this purpose. Mangled
# duplicates are handled separately -- see `_prefer`.
_NOISE_PREFIXES = ("__imp_", "??_C@", "_TI", "_CT", ".xdata", ".rdata", "$")

# `Table[3]` / `Table[1]._Mypair._Myval2` -- a label on an element of a table
# that is itself reported. Its span is the distance to the table's end.
_ELEMENT_LABEL = re.compile(r"\[\d+\]")


@dataclass(frozen=True)
class GlobalSymbol:
    """One global, with both address spaces named (RULE 4)."""

    name: str
    static_addr: int
    rva: int
    size: int  # bytes, from Ghidra's applied data type; 0 when none was applied
    span_to_next: int  # bytes to the next data symbol; 0 for the last one
    block: str
    referenced_from_scope: bool

    @property
    def bound(self) -> int:
        """Best available byte extent: the applied size, else the span."""
        return self.size or self.span_to_next


def _prefer(a: str, b: str) -> str:
    """Pick the more readable of two names for the same address.

    Ghidra keeps both the mangled and demangled symbol, and often a
    `Table[1]._Mypair._Myval2` style member label too. The plain identifier is
    the one worth putting in a prompt.
    """
    for name in (a, b):
        other = b if name is a else a
        if "?" in other and "?" not in name:
            return name
    return a if len(a) <= len(b) else b


def load_globals(
    path: Path,
    *,
    referenced_only: bool = True,
    blocks: tuple[str, ...] = _DEFAULT_BLOCKS,
) -> list[GlobalSymbol]:
    """Read `ExportDataSymbols.java` output into a deduplicated, filtered list.

    ``referenced_only`` keeps just the globals the analysed closure actually
    touches, which is what belongs in a prompt -- 35 of 493 on tlv_server, and 4
    once ``blocks`` has dropped `.rdata`.
    """
    payload = json.loads(Path(path).read_text(encoding="utf-8"))

    best: dict[int, dict] = {}
    for record in payload.get("symbols", []):
        if referenced_only and not record.get("referenced_from_scope"):
            continue
        if blocks and record.get("block") not in blocks:
            continue
        name = record.get("name") or ""
        if any(name.startswith(prefix) for prefix in _NOISE_PREFIXES):
            continue
        # `ChunkList[1]._Mypair._Myval2` is a label on an element INSIDE a table
        # we are already reporting. Its span is the distance to the end of that
        # table, which read as a capacity is simply wrong.
        if _ELEMENT_LABEL.search(name):
            continue

        addr = int(record["static_addr"])
        existing = best.get(addr)
        if existing is None:
            best[addr] = dict(record)
            continue
        # Same address, two names. Keep the readable name but the most
        # informative size and span -- Ghidra splits those across the duplicates.
        existing["name"] = _prefer(existing["name"], name)
        existing["size"] = max(int(existing["size"]), int(record["size"]))
        existing["span_to_next"] = max(
            int(existing["span_to_next"]), int(record["span_to_next"])
        )

    return sorted(
        (
            GlobalSymbol(
                name=r["name"],
                static_addr=int(r["static_addr"]),
                rva=int(r["rva"]),
                size=int(r["size"]),
                span_to_next=int(r["span_to_next"]),
                block=r["block"],
                referenced_from_scope=bool(r["referenced_from_scope"]),
            )
            for r in best.values()
        ),
        key=lambda g: g.static_addr,
    )


def format_globals(globals_: list[GlobalSymbol], *, pointer_size: int = 8) -> str:
    """A compact table for a prompt, with the element count spelled out.

    The element count is the whole point: it is what the pseudo-C lost. It is
    reported as a division by ``pointer_size`` only when the extent divides
    evenly, because guessing an element size for a struct array would be worse
    than saying nothing.
    """
    if not globals_:
        return ""

    lines = []
    for symbol in globals_:
        extent = symbol.bound
        detail = f"{extent} bytes" if extent else "size unknown"
        if extent and extent % pointer_size == 0:
            slots = extent // pointer_size
            detail += f" = {slots} pointer-sized slot{'' if slots == 1 else 's'}"
        lines.append(f"  {symbol.static_addr:#x}  {symbol.name}  ({detail})")

    return (
        "GLOBAL VARIABLES THE CODE ABOVE TOUCHES, with the extents Ghidra knows "
        "and decompilation dropped. A loop written as `p = Table; q = &next_sym; "
        "do {...} while (p != q);` iterates over exactly the slots between those "
        "two addresses, so these numbers give the capacity the pseudo-C does "
        "not:\n" + "\n".join(lines) + "\n\n"
    )
