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

    # Built here rather than read from the recorded target, so this runs on a clone and
    # inside a release archive. It used to read the dev target's exe and regs.json and
    # therefore skipped in both -- proving the refusal only where the 1.8 GB recording
    # lives (D-075).
    import tempfile

    from tests.gates.pe_fixture import build_pe

    tmp = Path(tempfile.mkdtemp())
    binary = tmp / "ambiguous.exe"
    binary.write_bytes(build_pe(image_base=IMAGE_BASE))
    (tmp / "regs.json").write_text(json.dumps({"rip": hex(RIP)}), encoding="utf-8")

    with pytest.raises(LayoutError) as exc:
        derive_layout(
            binary=binary,
            regs_json=tmp / "regs.json",
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


# --- the derivation, with NO recorded target at all -----------------------
#
# Everything above that touches STATE or BINARY skips on a clone, which meant the
# premise this project now rests on -- a dump, a register state and an exe -- was
# proven only on the machine holding the 1.8 GB recording. A skip is not a pass
# (D-075). These use a PE built in-process, so they run anywhere and cover cases a
# real binary cannot easily provide.


def test_the_image_base_is_read_from_a_constructed_pe(tmp_path) -> None:
    from prep.snapshot_win import read_pe_image_base
    from tests.gates.pe_fixture import build_pe

    for base in (0x140000000, 0x180000000, 0x10000):
        path = tmp_path / f"b{base:x}.exe"
        path.write_bytes(build_pe(image_base=base))
        assert read_pe_image_base(path) == base


def test_a_32_bit_image_is_refused(tmp_path) -> None:
    """wtf is x86-64 only, so PE32 has to fail here rather than three stages later."""
    from prep.snapshot_win import SnapshotError, read_pe_image_base
    from tests.gates.pe_fixture import build_pe

    path = tmp_path / "x86.exe"
    path.write_bytes(build_pe(magic=0x10B, image_base=0x400000))
    with pytest.raises(SnapshotError):
        read_pe_image_base(path)


def test_the_recorded_name_beats_the_filename(tmp_path) -> None:
    """The bug this exists for: a renamed executable.

    wtf resolves breakpoints and .cov files through `GetModuleBase(name)`. Given the
    filename of a renamed copy it returns 0, the breakpoint lands at `0 + rva`, and the
    campaign completes with zero coverage and no error. The CodeView record is written
    at link time and survives the rename.
    """
    from prep.layout import pe_module_name
    from tests.gates.pe_fixture import build_pe

    path = tmp_path / "renamed-by-somebody.exe"
    path.write_bytes(build_pe(pdb_path=r"C:\obj\the_real_name.pdb"))
    assert pe_module_name(path) == "the_real_name"


def test_a_stripped_binary_falls_back_to_the_filename(tmp_path) -> None:
    """No debug directory is the normal case for a release build.

    None here, so the caller uses the filename -- the best available answer, and right
    whenever nobody renamed anything.
    """
    from prep.layout import pe_module_name
    from tests.gates.pe_fixture import build_pe

    path = tmp_path / "stripped.exe"
    path.write_bytes(build_pe(pdb_path=None))
    assert pe_module_name(path) is None


def test_a_truncated_or_non_pe_file_returns_none_rather_than_raising(tmp_path) -> None:
    """These run while the caller is deciding what to fuzz, so they must not explode."""
    from prep.layout import pe_module_name
    from tests.gates.pe_fixture import build_pe

    for name, data in (
        ("truncated.exe", build_pe(pdb_path="x.pdb", truncate_to=0x30)),
        ("empty.exe", b""),
        ("text.exe", b"this is not a PE at all"),
        ("mz-only.exe", b"MZ" + bytes(0x100)),
    ):
        path = tmp_path / name
        path.write_bytes(data)
        assert pe_module_name(path) is None, name


def test_pe_identity_distinguishes_two_builds_of_the_same_program(tmp_path) -> None:
    """What makes the dump match trustworthy.

    The module base is accepted only when the mapped image's TimeDateStamp,
    AddressOfEntryPoint and SizeOfImage all match the file's. Three fields because one
    collides: every binary from one build shares a timestamp, and many share a size.
    """
    from prep.layout import _pe_identity
    from tests.gates.pe_fixture import build_pe

    first = _pe_identity(build_pe(timestamp=0x1111, entry_point=0x1000, size_of_image=0x8000))
    same = _pe_identity(build_pe(timestamp=0x1111, entry_point=0x1000, size_of_image=0x8000))
    rebuilt = _pe_identity(build_pe(timestamp=0x2222, entry_point=0x1000, size_of_image=0x8000))
    moved_entry = _pe_identity(build_pe(timestamp=0x1111, entry_point=0x1400, size_of_image=0x8000))
    grew = _pe_identity(build_pe(timestamp=0x1111, entry_point=0x1000, size_of_image=0x9000))

    assert first == same
    assert first != rebuilt, "a rebuild is not detected"
    assert first != moved_entry, "a moved entry point is not detected"
    assert first != grew, "a size change is not detected"


def test_the_whole_derivation_with_a_constructed_pe_and_no_dump(tmp_path) -> None:
    """End to end on the fallback path, with nothing recorded.

    Constructs an export whose one function sits at a known static address, picks a
    module base, computes the rip that base implies, and checks the derivation recovers
    the base and names the function. This is the arithmetic the premise rests on, run
    where the recorded snapshot does not exist.
    """
    from prep.layout import derive_layout
    from tests.gates.pe_fixture import build_pe

    image_base = 0x140000000
    entry_static = image_base + 0x2150
    module_base = 0x7FF800000000  # 64 KB aligned, as any real mapping is
    rip = module_base + (entry_static - image_base)

    binary = tmp_path / "synthetic.exe"
    binary.write_bytes(build_pe(image_base=image_base, pdb_path=r"C:\o\synthetic.pdb"))
    (tmp_path / "regs.json").write_text(json.dumps({"rip": hex(rip)}), encoding="utf-8")
    (tmp_path / "a2.json").write_text(
        json.dumps(
            {
                "module": "synthetic",
                "image_base": image_base,
                "functions": [
                    {"function": "ParsePacket", "entry_static": entry_static,
                     "min_static": entry_static, "max_static": entry_static + 0x80},
                    # A decoy that cannot produce an aligned base.
                    {"function": "Decoy", "entry_static": entry_static + 1,
                     "min_static": entry_static + 1, "max_static": entry_static + 2},
                ],
            }
        ),
        encoding="utf-8",
    )

    layout = derive_layout(
        binary=binary,
        regs_json=tmp_path / "regs.json",
        export=tmp_path / "a2.json",
    )
    assert layout.module_base == module_base
    assert layout.image_base == image_base
    assert layout.entry_symbol == "ParsePacket"
    assert layout.entry_static_addr == entry_static
    assert layout.slide == module_base - image_base
    assert layout.module == "synthetic"


def test_a_snapshot_taken_outside_any_known_function_is_refused(tmp_path) -> None:
    """The honest failure. rip in nothing Ghidra found means there is nothing of yours
    to fuzz at that point, and the message has to say so rather than pick a function."""
    from prep.layout import LayoutError, derive_layout
    from tests.gates.pe_fixture import build_pe

    image_base = 0x140000000
    binary = tmp_path / "s.exe"
    binary.write_bytes(build_pe(image_base=image_base))
    # An rip that no aligned base can reconcile with the single function below.
    (tmp_path / "regs.json").write_text(
        json.dumps({"rip": hex(0x7FF800000000 + 0x2151)}), encoding="utf-8"
    )
    (tmp_path / "a2.json").write_text(
        json.dumps(
            {
                "module": "s",
                "image_base": image_base,
                "functions": [
                    {"function": "Only", "entry_static": image_base + 0x2150,
                     "min_static": image_base + 0x2150, "max_static": image_base + 0x2200}
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(LayoutError) as exc:
        derive_layout(
            binary=binary,
            regs_json=tmp_path / "regs.json",
            export=tmp_path / "a2.json",
        )
    message = str(exc.value)
    assert "not taken at a function entry" in message or "no 64 KB-aligned" in message
