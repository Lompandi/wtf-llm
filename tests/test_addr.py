"""Address normalisation round-trips (CLAUDE.md section 9).

Section 9 calls this "a bug you will hit". The round trip is the cheap guard:
if it holds, coverage breakpoints land on the right instructions and identical
bugs hash to the same bucket across runs.

The fixture is not invented. Every constant below was read out of wtf's own
`target-tlv_server` release archive, and the chain closes on itself:

    PE ImageBase (tlv_server.exe headers)      0x140000000
    module_base  (state/symbol-store.json)     0x7ff719e50000
    ProcessPacket runtime address              0x7ff719e51150
      - equals `rip` in state/regs.json, i.e. the snapshot's break location
    => RVA                                     0x1150
      - which is present in coverage/tlv_server.cov
    => Ghidra static address                   0x140001150

`test_chain_against_shipped_target_files` re-derives that from the files on
disk, so if wtf's format ever moves, this fails rather than the CP2 gate
passing over a wrong conversion.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from arch.addr import AddressSpace, from_rva, to_rva, to_runtime, to_static

REPO_ROOT = Path(__file__).resolve().parents[1]
TLV = REPO_ROOT / "targets" / "tlv_server"

# Verified constants -- see the module docstring.
GHIDRA_IMAGE_BASE = 0x140000000
MODULE_BASE = 0x7FF719E50000
RUNTIME_ADDR = 0x7FF719E51150  # tlv_server!ProcessPacket
STATIC_ADDR = 0x140001150
RVA = 0x1150

# targets/ is gitignored (it holds multi-GB memory dumps), so the archive is
# not present on a fresh clone.
requires_target = pytest.mark.skipif(
    not TLV.exists(),
    reason="targets/tlv_server not extracted; see docs/ENVIRONMENT.md",
)


def test_runtime_to_static_matches_section_9_formula() -> None:
    assert to_static(RUNTIME_ADDR, MODULE_BASE, GHIDRA_IMAGE_BASE) == STATIC_ADDR


def test_static_to_runtime_matches_section_9_formula() -> None:
    assert to_runtime(STATIC_ADDR, MODULE_BASE, GHIDRA_IMAGE_BASE) == RUNTIME_ADDR


def test_round_trip_static_runtime_static() -> None:
    there = to_runtime(STATIC_ADDR, MODULE_BASE, GHIDRA_IMAGE_BASE)
    assert to_static(there, MODULE_BASE, GHIDRA_IMAGE_BASE) == STATIC_ADDR


def test_round_trip_runtime_static_runtime() -> None:
    there = to_static(RUNTIME_ADDR, MODULE_BASE, GHIDRA_IMAGE_BASE)
    assert to_runtime(there, MODULE_BASE, GHIDRA_IMAGE_BASE) == RUNTIME_ADDR


def test_rva_round_trip() -> None:
    """wtf's .cov files store RVAs -- ParseCovFiles in src/wtf/utils.cc."""
    assert to_rva(STATIC_ADDR, GHIDRA_IMAGE_BASE) == RVA
    assert from_rva(RVA, GHIDRA_IMAGE_BASE) == STATIC_ADDR


def test_cov_rva_is_independent_of_the_runtime_base() -> None:
    """The .cov RVA must not change when the module is rebased.

    This is why coverage generation never needs module_base: wtf adds
    GetModuleBase() itself at load time.
    """
    space_a = AddressSpace("tlv_server", MODULE_BASE, GHIDRA_IMAGE_BASE)
    space_b = AddressSpace("tlv_server", 0x7FF000000000, GHIDRA_IMAGE_BASE)
    assert space_a.to_rva(STATIC_ADDR) == space_b.to_rva(STATIC_ADDR) == RVA


@pytest.mark.parametrize("static_addr", [0x140001000, 0x140001150, 0x140002E00])
def test_address_space_helpers_agree_with_free_functions(static_addr: int) -> None:
    space = AddressSpace("tlv_server", MODULE_BASE, GHIDRA_IMAGE_BASE)
    runtime = space.to_runtime(static_addr)
    assert runtime == to_runtime(static_addr, MODULE_BASE, GHIDRA_IMAGE_BASE)
    assert space.to_static(runtime) == static_addr


def test_slide_is_the_difference_between_the_two_spaces() -> None:
    space = AddressSpace("tlv_server", MODULE_BASE, GHIDRA_IMAGE_BASE)
    assert space.slide == MODULE_BASE - GHIDRA_IMAGE_BASE
    assert space.to_runtime(STATIC_ADDR) - STATIC_ADDR == space.slide


def test_no_slide_is_the_identity() -> None:
    """ASLR disabled (the Linux requirement) means static == runtime."""
    space = AddressSpace("t.elf", GHIDRA_IMAGE_BASE, GHIDRA_IMAGE_BASE)
    assert space.slide == 0
    assert space.to_runtime(STATIC_ADDR) == STATIC_ADDR
    assert space.to_static(STATIC_ADDR) == STATIC_ADDR


# --- cross-validation against wtf's own shipped target -------------------


def _pe_image_base(path: Path) -> int:
    """Read ImageBase out of a PE32+ optional header."""
    data = path.read_bytes()
    pe = int.from_bytes(data[0x3C:0x40], "little")
    magic = int.from_bytes(data[pe + 0x18 : pe + 0x1A], "little")
    assert magic == 0x20B, f"{path.name} is not PE32+ (magic {magic:#x})"
    off = pe + 0x18 + 0x18
    return int.from_bytes(data[off : off + 8], "little")


@requires_target
def test_chain_against_shipped_target_files() -> None:
    """Re-derive the whole conversion chain from wtf's own release files.

    Guards two independent things at once: that section 9's formulae are right,
    and that the file formats they read have not moved under us.
    """
    image_base = _pe_image_base(TLV / "target" / "tlv_server.exe")
    assert image_base == GHIDRA_IMAGE_BASE

    symbols = json.loads((TLV / "state" / "symbol-store.json").read_text())
    module_base = int(symbols["tlv_server"], 16)
    entry_runtime = int(symbols["tlv_server!ProcessPacket"], 16)
    assert module_base == MODULE_BASE
    assert entry_runtime == RUNTIME_ADDR

    space = AddressSpace("tlv_server", module_base, image_base)
    entry_static = space.to_static(entry_runtime)
    assert entry_static == STATIC_ADDR
    assert space.to_rva(entry_static) == RVA

    # The snapshot's rip is the fuzz entry: that is what "break at the fuzz
    # entry" means, and it is the fact edge 1 -> 6 -> 7 rests on.
    regs = json.loads((TLV / "state" / "regs.json").read_text())
    assert int(regs["rip"], 16) == entry_runtime

    # And the entry's RVA really is in the coverage file, in wtf's own format.
    cov = json.loads((TLV / "coverage" / "tlv_server.cov").read_text())
    assert cov["name"] == "tlv_server", "cov `name` must match the symbol-store key"
    assert space.to_rva(entry_static) in cov["addresses"]


@requires_target
def test_shipped_cov_addresses_are_rvas_not_absolute() -> None:
    """The single most likely CP2 mistake, asserted against a real file.

    Emitting absolute or runtime addresses here would make every breakpoint
    fail to translate, and wtf only *warns* on that (see DEVIATIONS D-005),
    so the fuzzer would run with almost no coverage instead of erroring.
    """
    cov = json.loads((TLV / "coverage" / "tlv_server.cov").read_text())
    addresses = cov["addresses"]
    assert addresses, "shipped .cov is empty"
    assert all(isinstance(a, int) for a in addresses)
    # A 21 KB image: every RVA must be far below any plausible load address.
    assert max(addresses) < 0x1000000, "these look like absolute addresses"
    assert min(addresses) >= 0x1000, "RVAs below the first section are suspect"
