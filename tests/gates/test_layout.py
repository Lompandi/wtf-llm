"""A memory dump, a register state, and the executable. Nothing else (D-075).

The premise: a user has three things and should not have to supply a fourth. What used
to be required on top of them was `module_base` (from `symbol-store.json`, which
`ingest_state_dir` hard-required), `ghidra_image_base` and `entry_symbol` (both from
`config/target.yaml`, which describes one target -- D-073), and a seed corpus.

Two derivations remove all of it, and this file pins both plus the order between them.

The values here are not invented. They are the development target's real snapshot:

    rip         0x7ff719e51150
    image base  0x140000000      (tlv_server.exe PE optional header)
    module base 0x7ff719e50000   (symbol-store.json, and both derivations agree)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from prep.layout import (
    IMAGE_ALIGNMENT,
    Layout,
    LayoutError,
    candidates_from_rip,
    derive_layout,
    module_base_from_dump,
    read_cr3,
    read_rip,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
STATE = REPO_ROOT / "targets" / "tlv_server" / "state"
BINARY = REPO_ROOT / "targets" / "tlv_server" / "target" / "tlv_server.exe"
A2 = REPO_ROOT / "artifacts" / "a2_pseudoc_module.json"

RIP = 0x7FF719E51150
IMAGE_BASE = 0x140000000
MODULE_BASE = 0x7FF719E50000
ENTRY_STATIC = 0x140001150


def _needs(*paths: Path) -> None:
    for path in paths:
        if not path.exists():
            pytest.skip(f"{path} is absent; this test reads the recorded snapshot")


# --- the arithmetic, with no files at all ---------------------------------


def test_alignment_collapses_the_candidate_set_to_one() -> None:
    """Why this is decidable rather than a guess.

    `module_base = rip - (static - image_base)` is a candidate for every function. What
    makes the answer unique is that Windows maps images on a 64 KB boundary, so all but
    a 1-in-65536 slice of the candidates are arithmetic that happens to work out.
    """
    functions = {
        "ProcessPacket": ENTRY_STATIC,
        "main": 0x140002000,
        "printf": 0x1400010F0,
        "helper": 0x140001151,  # one byte off: cannot be an aligned mapping
    }
    candidates = candidates_from_rip(RIP, IMAGE_BASE, functions)
    assert list(candidates) == [MODULE_BASE]
    assert candidates[MODULE_BASE] == ["ProcessPacket"]
    for base in candidates:
        assert base % IMAGE_ALIGNMENT == 0


def test_an_ambiguous_derivation_refuses_rather_than_picking() -> None:
    """Two aligned candidates means the slide is unknown, and a wrong slide is silent.

    Every later static/runtime conversion would be off by a constant, which produces
    coverage for the wrong bytes rather than an error (D-027). So this is the one place
    that must fail loudly.
    """
    functions = {
        "a": ENTRY_STATIC,
        "b": ENTRY_STATIC + IMAGE_ALIGNMENT,  # a second aligned candidate
    }
    candidates = candidates_from_rip(RIP, IMAGE_BASE, functions)
    assert len(candidates) == 2

    with pytest.raises(LayoutError) as exc:
        derive_layout(
            binary=BINARY,
            regs_json=STATE / "regs.json",
            export=_export_with(functions),
        )
    assert "different module bases" in str(exc.value)


def _export_with(functions: dict[str, int]) -> Path:
    import tempfile

    path = Path(tempfile.mkdtemp()) / "a2.json"
    path.write_text(
        json.dumps(
            {
                "module": "tlv_server",
                "image_base": IMAGE_BASE,
                "functions": [
                    {"function": name, "entry_static": addr, "min_static": addr,
                     "max_static": addr + 0x40}
                    for name, addr in functions.items()
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


# --- the snapshot's own answer, which outranks the derivation -------------


def test_the_module_base_is_read_out_of_the_dump() -> None:
    """THE PRIMARY METHOD, and better than the arithmetic for one reason: it does not
    care where the snapshot was taken.

    A dump captured mid-function, inside a callee, or in the middle of a memcpy still
    carries its mapped image list, so the base is a fact to read rather than a slide to
    solve for. Found by walking the snapshot's own page tables from cr3.
    """
    _needs(STATE / "mem.dmp", STATE / "regs.json", BINARY)
    base, how = module_base_from_dump(STATE / "mem.dmp", STATE / "regs.json", BINARY)
    assert base == MODULE_BASE, how
    assert "dump" in how


def test_the_dump_is_matched_by_pe_HEADER_not_by_filename() -> None:
    """The property that makes it trustworthy, and the reason it is not name matching.

    The executable is identified by TimeDateStamp, AddressOfEntryPoint and SizeOfImage,
    so a renamed copy still resolves -- verified for real by running the pipeline on
    `mytarget.exe`, a renamed tlv_server.exe, against a dump in which the image is
    mapped as `tlv_server.exe`. It found it.

    The same property answers a question nothing else here can: a dump of a DIFFERENT
    program does not match, and is reported rather than silently used.
    """
    _needs(STATE / "mem.dmp", STATE / "regs.json", BINARY)
    import shutil
    import tempfile

    renamed = Path(tempfile.mkdtemp()) / "totally-different-name.exe"
    shutil.copy(BINARY, renamed)
    base, how = module_base_from_dump(STATE / "mem.dmp", STATE / "regs.json", renamed)
    assert base == MODULE_BASE, how


def test_a_dump_of_another_program_is_reported_not_used() -> None:
    _needs(STATE / "mem.dmp", STATE / "regs.json")
    other = REPO_ROOT / "src" / "build" / "wtf.exe"
    if not other.exists():
        pytest.skip("no second PE to test against")
    base, how = module_base_from_dump(STATE / "mem.dmp", STATE / "regs.json", other)
    assert base is None
    assert "not among" in how or "rebuilt" in how


def test_cr3_low_bits_are_masked() -> None:
    """cr3's low 12 bits are PCID/PWT/PCD flags, not part of the frame address.

    Left in, every page-table read starts at the wrong physical page and the walk finds
    nothing -- which would look exactly like "this dump has no images mapped".
    """
    _needs(STATE / "regs.json")
    assert read_cr3(STATE / "regs.json") % 0x1000 == 0


# --- what the pipeline actually consumes ---------------------------------


def test_the_whole_layout_from_the_three_files() -> None:
    """The premise, end to end: dump + regs + exe -> base, entry, image base."""
    _needs(STATE / "mem.dmp", STATE / "regs.json", BINARY, A2)
    layout = derive_layout(
        binary=BINARY,
        regs_json=STATE / "regs.json",
        export=A2,
        mem_dmp=STATE / "mem.dmp",
    )
    assert layout.module == "tlv_server"
    assert layout.module_base == MODULE_BASE
    assert layout.image_base == IMAGE_BASE
    assert layout.rip == RIP
    assert layout.entry_static_addr == ENTRY_STATIC
    assert layout.slide == MODULE_BASE - IMAGE_BASE
    # The entry is where the snapshot stopped. On a binary with symbols that is
    # `ProcessPacket`; on one without it is `FUN_140001150`. The ADDRESS is the fact.
    assert layout.entry_symbol


def test_the_derivation_works_with_no_dump_at_all() -> None:
    """The fallback. Slower to trust, but it needs nothing but rip and the exe."""
    _needs(STATE / "regs.json", BINARY, A2)
    layout = derive_layout(binary=BINARY, regs_json=STATE / "regs.json", export=A2)
    assert layout.module_base == MODULE_BASE
    assert "rip" in layout.source


def test_the_dump_outranks_the_symbol_store_and_both_outrank_the_arithmetic() -> None:
    """Order of authority, asserted because it is a decision and not an accident.

    A statement about the snapshot beats a derivation from it. The arithmetic is last
    because it is the only one that can be defeated by where the snapshot was taken.
    """
    _needs(STATE / "mem.dmp", STATE / "regs.json", BINARY, A2)
    with_dump = derive_layout(
        binary=BINARY, regs_json=STATE / "regs.json", export=A2,
        mem_dmp=STATE / "mem.dmp", symbol_store=STATE / "symbol-store.json",
    )
    assert "dump" in with_dump.source

    without_dump = derive_layout(
        binary=BINARY, regs_json=STATE / "regs.json", export=A2,
        symbol_store=STATE / "symbol-store.json",
    )
    assert "symbol-store" in without_dump.source

    assert with_dump.module_base == without_dump.module_base == MODULE_BASE


def test_layout_round_trips_through_json() -> None:
    _needs(STATE / "regs.json", BINARY, A2)
    import tempfile

    layout = derive_layout(binary=BINARY, regs_json=STATE / "regs.json", export=A2)
    path = Path(tempfile.mkdtemp()) / "a0_layout.json"
    path.write_text(layout.to_json(), encoding="utf-8")
    assert Layout.load(path) == layout
    # Hex alongside the integers: a decimal address in a log is unreadable exactly when
    # what you need to do is compare it.
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw["hex"]["module_base"] == hex(MODULE_BASE)


def test_rip_is_required() -> None:
    import tempfile

    path = Path(tempfile.mkdtemp()) / "regs.json"
    path.write_text(json.dumps({"cr3": "0x1000"}), encoding="utf-8")
    with pytest.raises(LayoutError) as exc:
        read_rip(path)
    assert "where execution stopped" in str(exc.value)
