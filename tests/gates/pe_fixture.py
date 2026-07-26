"""Build a minimal PE64 in memory, so the layout derivation is testable anywhere.

`tests/gates/test_layout.py` reads the development target's executable and its 1.8 GB
`mem.dmp`. Neither ships, so on a clone every one of those tests SKIPPED -- which means
the derivation that the whole "a dump, a register state and an exe" premise rests on was
proven only on the one machine that has the recorded snapshot (D-075).

A skip is not a pass. `prep/layout.py` reads exactly four things out of an executable --
the PE ImageBase, the TimeDateStamp, the AddressOfEntryPoint and the SizeOfImage, plus
the CodeView PDB path when there is one -- and all five are constructible. So the parts
that need no dump are now tested against a PE built here, with known values, including
the cases a real binary cannot easily provide: no debug directory at all, a PDB path
that disagrees with the filename, a 32-bit image, a truncated header.

Deliberately NOT a general PE writer. It emits the smallest structure the readers under
test actually walk, and a field none of them look at is left zero.
"""

from __future__ import annotations

import struct

__all__ = ["build_pe"]

_DOS_STUB_SIZE = 0x40
_COFF_SIZE = 20
_SECTION_SIZE = 40


def build_pe(
    *,
    image_base: int = 0x140000000,
    timestamp: int = 0x66000000,
    entry_point: int = 0x1150,
    size_of_image: int = 0x8000,
    pdb_path: str | None = None,
    magic: int = 0x20B,
    truncate_to: int | None = None,
) -> bytes:
    """A PE64 carrying exactly the fields `prep/layout.py` and friends read.

    `pdb_path` adds a debug directory with a CodeView RSDS record, which is what
    `pe_module_name` reads -- the name a linker wrote, which survives renaming the file.
    `magic=0x10B` makes it PE32, which `read_pe_image_base` must refuse because wtf is
    x86-64 only. `truncate_to` cuts the result short, for the "not a PE at all" paths.
    """
    # One section, so an RVA can be mapped back to a file offset. Sized generously
    # enough to hold the debug records placed inside it.
    section_rva = 0x1000
    section_raw = 0x400
    section_size = 0x1000

    debug_dir_rva = 0
    debug_dir_size = 0
    debug_payload = b""
    if pdb_path is not None:
        # IMAGE_DEBUG_DIRECTORY (28 bytes) followed by the RSDS record it points at.
        # Both live inside the section, so PointerToRawData mapping is exercised too.
        cv_rva = section_rva + 0x100
        cv_offset = section_raw + 0x100
        rsds = (
            b"RSDS"
            + bytes(16)  # guid -- unread
            + struct.pack("<I", 1)  # age
            + pdb_path.encode("ascii") + b"\0"
        )
        debug_dir_rva = section_rva + 0x80
        debug_dir_size = 28
        entry = struct.pack(
            "<IIHHIIII",
            0,            # Characteristics
            timestamp,    # TimeDateStamp
            0, 0,         # MajorVersion, MinorVersion
            2,            # Type = IMAGE_DEBUG_TYPE_CODEVIEW
            len(rsds),    # SizeOfData
            cv_rva,       # AddressOfRawData
            cv_offset,    # PointerToRawData
        )
        debug_payload = (entry, rsds, debug_dir_rva - section_rva, cv_rva - section_rva)

    is_pe32_plus = magic == 0x20B
    # SizeOfOptionalHeader: the standard sizes, since the data directory count is 16.
    opt_size = 0xF0 if is_pe32_plus else 0xE0

    pe_offset = _DOS_STUB_SIZE
    out = bytearray()
    out += b"MZ" + bytes(0x3A)
    out += struct.pack("<I", pe_offset)  # e_lfanew at 0x3C
    assert len(out) == _DOS_STUB_SIZE, len(out)

    out += b"PE\0\0"
    out += struct.pack(
        "<HHIIIHH",
        0x8664 if is_pe32_plus else 0x14C,  # Machine
        1,                                   # NumberOfSections
        timestamp,
        0, 0,                                # symbol table -- unread
        opt_size,
        0x22,                                # Characteristics
    )

    # Written by explicit offset rather than by appending, because appending is how the
    # first version of this put SizeOfImage at 0x50 instead of 0x38 and ImageBase where
    # AddressOfEntryPoint goes. The readers under test caught both, which is the
    # argument for having them read a constructed file at all.
    #
    # PE32+ optional header, the fields anything here reads:
    #   0x00 Magic          0x10 AddressOfEntryPoint   0x18 ImageBase (8)
    #   0x38 SizeOfImage    0x70 DataDirectory[0]
    optional = bytearray(opt_size)
    struct.pack_into("<H", optional, 0x00, magic)
    struct.pack_into("<I", optional, 0x10, entry_point)
    if is_pe32_plus:
        struct.pack_into("<Q", optional, 0x18, image_base)
        size_of_image_at = 0x38
        directories_at = 0x70
    else:
        # PE32 shifts everything after ImageBase down by four bytes, since ImageBase is
        # 4 bytes there. Only needed so a PE32 file is well-formed enough that
        # `read_pe_image_base` refuses it for the RIGHT reason -- the magic -- rather
        # than by tripping over a short buffer.
        struct.pack_into("<I", optional, 0x18, image_base & 0xFFFFFFFF)
        size_of_image_at = 0x38 - 4
        directories_at = 0x60
    struct.pack_into("<I", optional, size_of_image_at, size_of_image)
    if debug_payload:
        struct.pack_into(
            "<II", optional, directories_at + 6 * 8, debug_dir_rva, debug_dir_size
        )
    out += bytes(optional)

    out += struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        section_size,   # VirtualSize
        section_rva,    # VirtualAddress
        section_size,   # SizeOfRawData
        section_raw,    # PointerToRawData
        0, 0, 0, 0,
        0x60000020,
    )

    out = out.ljust(section_raw, b"\0")
    body = bytearray(section_size)
    if debug_payload:
        entry, rsds, entry_at, cv_at = debug_payload
        body[entry_at : entry_at + len(entry)] = entry
        body[cv_at : cv_at + len(rsds)] = rsds
    out += body

    data = bytes(out)
    return data[:truncate_to] if truncate_to is not None else data
