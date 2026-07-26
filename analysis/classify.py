"""Crash classification (CLAUDE.md CP8, edges 34-35, triage signal 2).

Turns a fault into a preliminary characterisation: what kind of fault, read or
write, near-null or wild, whether the faulting address looks attacker-influenced,
and the faulting instruction where it can be recovered.

**NO LLM IN THIS MODULE.** This is arithmetic and disassembly.

What "preliminary" means here
-----------------------------
There is no ASAN (section 2). The oracle sees observable faults only, so this
module's job is to describe a fault precisely, not to decide whether it is a bug.
Every field that cannot be established is reported as unknown rather than
defaulted, because a default reads as a finding: "not near null" and "we have no
address" must not look the same to triage.

The registers problem, stated plainly
-------------------------------------
A crash file is a name plus test-case bytes -- no registers, no backtrace. So on
the normal path ``registers`` is empty and every register-derived judgement is
unavailable. That is not a defect to be papered over: it is the access level, and
:class:`Classification` says so via ``registers_available``. Reconstructing
registers requires re-execution, which is CP8's replay stage, not this one.
"""

from __future__ import annotations

import struct
from pathlib import Path

# OPTIONAL. capstone is in requirements.txt and is genuinely needed to disassemble
# around a fault address -- but a hard import here made `pytest -q` fail at COLLECTION
# for the entire suite when it was absent, so an environment missing one optional
# dependency reported nothing about the twelve checkpoints that do not use it. A
# reviewer hit exactly that and could not run the suite at all.
#
# Absent, disassembly is skipped and says so. That is the same choice
# `read_module_bytes` already makes for a binary it cannot vouch for: report less
# rather than invent.
try:
    import capstone
except ModuleNotFoundError:  # pragma: no cover -- exercised by its absence
    capstone = None

from pydantic import BaseModel, Field

from arch.addr import AddressSpace
from arch.contracts import CrashRecord

__all__ = [
    "NEAR_NULL_LIMIT",
    "Classification",
    "classify",
    "read_module_bytes",
]

# Windows reserves the lowest 64 KB of the address space and never maps it, so a
# fault below this is a null-ish dereference: a null pointer plus a small struct
# offset or array index. Above it, an address can legitimately be mapped, so a
# fault there means a *wrong* pointer rather than a missing one -- and that
# distinction is the one that separates "crash on unchecked null" from
# "attacker-controlled pointer". Chosen as the OS's own reservation boundary
# rather than an arbitrary round number.
NEAR_NULL_LIMIT = 0x1_0000

# Enough context to see the faulting instruction and how it was reached, without
# turning a triage prompt into a disassembly listing.
_DISASM_BYTES_BEFORE = 32
_DISASM_BYTES_AFTER = 32


class Classification(BaseModel):
    """Triage signal 2. Every uncertainty is explicit."""

    bucket_id: str = ""
    fault_type: str

    # Access shape. `access` is derived from the fault type wtf reported, which
    # names read vs write for access violations and nothing for other faults.
    access: str = Field(
        default="unknown", description="read | write | execute | unknown"
    )
    fault_runtime_addr: int = 0
    # None when the address was not attributable to the target module, mirroring
    # CrashRecord (D-068). Renderers must handle it; `render_signals` does.
    fault_static_addr: int | None = None
    fault_module: str | None = None
    fault_symbol: str | None = None

    near_null: bool | None = Field(
        default=None,
        description=(
            f"fault address below {NEAR_NULL_LIMIT:#x}; None when no address is "
            f"known"
        ),
    )
    wild: bool | None = Field(
        default=None,
        description="fault address is neither near-null nor in a known module",
    )

    registers_available: bool = False
    faulting_instruction: str | None = None
    disasm_source: str = Field(
        default="unavailable",
        description="target_pe | unavailable -- where the decoded bytes came from",
    )

    attacker_influenced: bool | None = Field(
        default=None,
        description=(
            "the fault address, or a truncation of it, appears verbatim in the "
            "input; None when no address is known"
        ),
    )
    influence_offsets: list[int] = Field(
        default_factory=list, description="byte offsets in the input that matched"
    )
    influence_widths: list[int] = Field(
        default_factory=list, description="widths (bytes) at which a match was found"
    )

    notes: list[str] = Field(
        default_factory=list,
        description="what could not be determined, and why it matters",
    )


def _access_from_fault_type(fault_type: str) -> str:
    """wtf encodes read/write in the exception name; nothing else does."""
    lowered = fault_type.lower()
    if "write" in lowered:
        return "write"
    if "read" in lowered:
        return "read"
    if "execute" in lowered or "dep" in lowered:
        return "execute"
    return "unknown"


def _find_address_in_input(address: int, data: bytes) -> tuple[list[int], list[int]]:
    """Offsets where ``address`` appears in ``data``, and at which widths.

    Little-endian, at 8, 4 and 2 bytes. The narrower widths matter because a
    length or index copied out of the packet is what usually ends up in a
    pointer computation -- the full 64-bit fault address rarely appears verbatim,
    since it is base + attacker-controlled offset.

    **What a false positive looks like here, and it is common.** A 2-byte match on
    a small value like 0x0008 will hit almost any binary input by chance, so a
    match at width 2 is weak evidence and a match at width 8 is strong. The widths
    are returned rather than collapsed to a boolean so triage can weigh them
    instead of being handed a bare "attacker-influenced: true".
    """
    offsets: list[int] = []
    widths: list[int] = []
    for width, fmt in ((8, "<Q"), (4, "<I"), (2, "<H")):
        mask = (1 << (width * 8)) - 1
        needle = struct.pack(fmt, address & mask)
        start = 0
        found = False
        while True:
            index = data.find(needle, start)
            if index < 0:
                break
            offsets.append(index)
            start = index + 1
            found = True
        if found:
            widths.append(width)
    return sorted(set(offsets)), widths


def read_module_bytes(
    binary: Path, rva: int, *, before: int = _DISASM_BYTES_BEFORE, after: int = _DISASM_BYTES_AFTER
) -> tuple[bytes, int] | None:
    """Bytes around ``rva`` read from a PE on disk, plus the start RVA.

    Only sound for the *target* module: the file on disk is what Ghidra analysed
    and what the snapshot loaded. For a system DLL we have no such guarantee --
    the guest's copy may differ from anything on this host -- so callers must not
    use this for foreign modules. Disassembling the wrong bytes and presenting the
    result as the faulting instruction would be worse than presenting nothing.

    Uses the section table to map RVA -> file offset. Returns None when the RVA
    falls outside every section.
    """
    try:
        import pefile
    except ImportError:  # pragma: no cover - optional dependency
        return None

    pe = pefile.PE(str(binary), fast_load=True)
    try:
        for section in pe.sections:
            start = section.VirtualAddress
            end = start + max(section.Misc_VirtualSize, section.SizeOfRawData)
            if not (start <= rva < end):
                continue
            low = max(start, rva - before)
            offset = section.PointerToRawData + (low - start)
            length = (rva - low) + after
            with binary.open("rb") as fd:
                fd.seek(offset)
                return fd.read(length), low
        return None
    finally:
        pe.close()


def classify(
    record: CrashRecord,
    *,
    bucket_id: str = "",
    space: AddressSpace | None = None,
    target_binary: Path | None = None,
    fault_symbol: str | None = None,
    known_modules: dict[str, int] | None = None,
) -> Classification:
    """Characterise one crash. Never guesses; records what it could not tell."""
    notes: list[str] = []
    address = record.fault_runtime_addr

    result = Classification(
        bucket_id=bucket_id,
        fault_type=record.fault_type,
        access=_access_from_fault_type(record.fault_type),
        fault_runtime_addr=address,
        fault_static_addr=record.fault_static_addr,
        fault_module=record.fault_module,
        fault_symbol=fault_symbol,
        registers_available=bool(record.registers),
    )

    if result.access == "unknown":
        notes.append(
            f"fault type {record.fault_type!r} does not name read or write, so "
            f"the access direction is unknown -- do not read that as 'read'"
        )

    if not address:
        notes.append(
            "no fault address is recorded, so near-null, wildness and "
            "attacker-influence are all undeterminable"
        )
        result.notes = notes
        return result

    result.near_null = address < NEAR_NULL_LIMIT
    # "Wild" means we cannot place it: not near-null, and not inside any module we
    # know about. An address inside a known module is a *bad pointer into real
    # code or data*, which is a different story from a pointer into nowhere.
    if result.near_null:
        result.wild = False
    elif record.fault_module:
        result.wild = False
    elif known_modules:
        result.wild = not any(
            base <= address < base + 0x1000_0000 for base in known_modules.values()
        )
    else:
        result.wild = None
        notes.append(
            "no module map was supplied, so 'wild' cannot be decided -- an "
            "address inside an unlisted system DLL would look wild when it is not"
        )

    offsets, widths = _find_address_in_input(address, record.input_bytes)
    result.attacker_influenced = bool(offsets)
    result.influence_offsets = offsets[:16]
    result.influence_widths = widths
    if widths and max(widths) <= 2:
        notes.append(
            "the only matches are 2 bytes wide, which occurs by chance in most "
            "binary inputs; treat this as weak evidence of influence"
        )

    # Disassembly. Only attempted for the target module, per read_module_bytes.
    if record.fault_module and target_binary and space and record.fault_static_addr:
        rva = record.fault_static_addr - space.ghidra_image_base
        window = read_module_bytes(target_binary, rva)
        if window is None:
            notes.append(
                f"RVA {rva:#x} is outside every section of {target_binary.name}, "
                f"so no disassembly was produced"
            )
        else:
            code, low_rva = window
            if capstone is None:
                # `notes`, like the branch above: the same mechanism already carries
                # "why there is no disassembly", and `disasm_source` stays
                # "unavailable", which is exactly what happened.
                notes.append(
                    "capstone is not installed, so the faulting instruction was not "
                    "disassembled: pip install -r requirements.txt"
                )
                code = b""
            md = (
                capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                if capstone is not None
                else None
            )
            for insn in md.disasm(code, space.ghidra_image_base + low_rva) if md else ():
                if insn.address == record.fault_static_addr:
                    result.faulting_instruction = f"{insn.mnemonic} {insn.op_str}".strip()
                    result.disasm_source = "target_pe"
                    break
            if result.faulting_instruction is None:
                notes.append(
                    "the decoder never landed exactly on the fault address, which "
                    "means the window started mid-instruction; no instruction is "
                    "reported rather than a misaligned guess"
                )
    else:
        notes.append(
            "the fault is not attributable to the target module, so its bytes "
            "cannot be read from the binary on disk and no disassembly is "
            "available -- a system DLL in the guest may differ from any copy here"
        )

    if not record.registers:
        notes.append(
            "no registers: a crash file carries only its name and the test-case "
            "bytes, so register-derived judgements need CP8's replay stage"
        )

    result.notes = notes
    return result
