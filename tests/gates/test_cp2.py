"""GATE 2 -- Ghidra headless BB enumeration -> wtf coverage BP list (A3).

CLAUDE.md gate conditions (edges 2, 5, 10):
  * `a3_bp_list.json` exists with >0 blocks
  * the wtf-native BP file passes format validation
  * a round-trip test parses our file with the same logic wtf uses

The format checks run everywhere. The artifact and reference-comparison checks
need `artifacts/` (gitignored) and the extracted target, so they skip cleanly on
a fresh clone -- regenerate with:

    python -m prep.ghidra_headless --binary targets/tlv_server/target/tlv_server.exe \
        --scope function-closure --entry ProcessPacket --out artifacts/a3_ghidra_blocks.json
    python -m prep.bb_to_wtf --export artifacts/a3_ghidra_blocks.json \
        --coverage-dir artifacts/coverage

The reference comparison is stronger than the gate asks for and is the reason to
trust the enumeration at all: wtf's `target-tlv_server` archive ships a `.cov`
produced by the author's own tooling, so we can diff against a real answer
rather than only checking our file is well-shaped.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from arch.addr import to_rva
from arch.contracts import BasicBlock
from prep.bb_to_wtf import (
    CovFileError,
    blocks_to_records,
    validate_cov_file,
    write_cov_file,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = REPO_ROOT / "artifacts"

BP_LIST = ARTIFACTS / "a3_bp_list.json"
COV_FILE = ARTIFACTS / "coverage" / "tlv_server.cov"
EXPORT_CLOSURE = ARTIFACTS / "a3_ghidra_blocks.json"
EXPORT_MODULE = ARTIFACTS / "a3_ghidra_blocks_module.json"
SHIPPED_COV = REPO_ROOT / "targets" / "tlv_server" / "coverage" / "tlv_server.cov"

TLV_IMAGE_BASE = 0x140000000

requires_a3 = pytest.mark.skipif(
    not (BP_LIST.exists() and COV_FILE.exists()),
    reason="A3 not generated; see this module's docstring",
)
requires_reference = pytest.mark.skipif(
    not SHIPPED_COV.exists(),
    reason="targets/tlv_server not extracted; see docs/ENVIRONMENT.md",
)


# --- format validation: the logic wtf will apply to our file --------------


def test_round_trip_write_then_parse(tmp_path: Path) -> None:
    """GATE 2: parse our own file with the same logic wtf uses."""
    records = [
        BasicBlock(module="demo", static_addr=TLV_IMAGE_BASE + rva, function="f")
        for rva in (0x1000, 0x1010, 0x1150)
    ]
    path = write_cov_file(records, TLV_IMAGE_BASE, tmp_path)

    assert path.name == "demo.cov"
    cov = validate_cov_file(path, expect_name="demo")
    assert cov.addresses == [0x1000, 0x1010, 0x1150]

    # And what wtf computes at load time: Gva = GetModuleBase(name) + Rva.
    module_base = 0x7FF719E50000
    assert cov.to_runtime(module_base) == [
        module_base + 0x1000,
        module_base + 0x1010,
        module_base + 0x1150,
    ]
    assert cov.to_static(TLV_IMAGE_BASE) == [r.static_addr for r in records]


def test_cov_file_must_end_in_dot_cov(tmp_path: Path) -> None:
    """utils.cc:352 skips anything else -- silently, which looks like no coverage."""
    bad = tmp_path / "blocks.json"
    bad.write_text(json.dumps({"name": "demo", "addresses": [1]}), encoding="utf-8")
    with pytest.raises(CovFileError, match=r"\.cov"):
        validate_cov_file(bad)


def test_module_name_must_not_carry_an_extension(tmp_path: Path) -> None:
    """GetModuleBase('tlv_server.exe') returns 0 and fails the WHOLE load."""
    bad = tmp_path / "x.cov"
    bad.write_text(
        json.dumps({"name": "tlv_server.exe", "addresses": [0x1000]}), encoding="utf-8"
    )
    with pytest.raises(CovFileError, match="extension"):
        validate_cov_file(bad)

    records = [BasicBlock(module="tlv_server.exe", static_addr=TLV_IMAGE_BASE)]
    with pytest.raises(CovFileError, match="GetModuleBase"):
        write_cov_file(records, TLV_IMAGE_BASE, tmp_path)


def test_addresses_must_be_integers(tmp_path: Path) -> None:
    """utils.cc:373 reads uint64_t; a hex string is a parse failure, not a skip."""
    bad = tmp_path / "x.cov"
    bad.write_text(
        json.dumps({"name": "demo", "addresses": ["0x1000"]}), encoding="utf-8"
    )
    with pytest.raises(CovFileError, match="integer"):
        validate_cov_file(bad)


def test_empty_coverage_is_rejected(tmp_path: Path) -> None:
    """wtf only warns, so the fuzzer would run with no coverage at all."""
    empty = tmp_path / "x.cov"
    empty.write_text(json.dumps({"name": "demo", "addresses": []}), encoding="utf-8")
    with pytest.raises(CovFileError, match="no addresses"):
        validate_cov_file(empty)

    with pytest.raises(CovFileError, match="empty"):
        write_cov_file([], TLV_IMAGE_BASE, tmp_path)


def test_missing_keys_are_rejected(tmp_path: Path) -> None:
    for payload in ({"addresses": [1]}, {"name": "demo"}):
        bad = tmp_path / "x.cov"
        bad.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(CovFileError):
            validate_cov_file(bad)


def test_blocks_below_the_image_base_are_rejected(tmp_path: Path) -> None:
    """A negative RVA means the wrong image base was used somewhere."""
    records = [BasicBlock(module="demo", static_addr=TLV_IMAGE_BASE - 0x10)]
    with pytest.raises(CovFileError, match="below the image base"):
        write_cov_file(records, TLV_IMAGE_BASE, tmp_path)


def test_duplicate_blocks_collapse(tmp_path: Path) -> None:
    """Coverage is set membership, not a hit count (DECISIONS R6)."""
    records = [
        BasicBlock(module="demo", static_addr=TLV_IMAGE_BASE + 0x1000) for _ in range(3)
    ]
    cov = validate_cov_file(write_cov_file(records, TLV_IMAGE_BASE, tmp_path))
    assert cov.addresses == [0x1000]


# --- the generated A3 artifacts -------------------------------------------


@requires_a3
def test_bp_list_exists_with_blocks() -> None:
    """GATE 2: a3_bp_list.json exists with >0 blocks."""
    records = [BasicBlock(**r) for r in json.loads(BP_LIST.read_text("utf-8"))]
    assert len(records) > 0
    assert all(r.module == "tlv_server" for r in records)
    # Static address space: every block sits at or above the image base.
    assert all(r.static_addr >= TLV_IMAGE_BASE for r in records)


@requires_a3
def test_generated_cov_file_validates() -> None:
    """GATE 2: the wtf-native BP file passes format validation."""
    cov = validate_cov_file(COV_FILE, expect_name="tlv_server")
    assert len(cov) > 0


@requires_a3
def test_bp_list_and_cov_file_describe_the_same_blocks() -> None:
    """The two A3 outputs must not drift: one is static, one is RVA."""
    records = [BasicBlock(**r) for r in json.loads(BP_LIST.read_text("utf-8"))]
    cov = validate_cov_file(COV_FILE)
    expected = sorted({to_rva(r.static_addr, TLV_IMAGE_BASE) for r in records})
    assert cov.addresses == expected


@requires_a3
def test_export_records_survive_the_contract() -> None:
    export = json.loads(EXPORT_CLOSURE.read_text("utf-8"))
    records = blocks_to_records(export)
    assert len(records) == len(export["blocks"])
    assert export["image_base"] == TLV_IMAGE_BASE


@requires_a3
def test_closure_scope_is_much_smaller_than_module_scope() -> None:
    """Scoping is the point of CP2: whole-module enumeration can be enormous."""
    if not EXPORT_MODULE.exists():
        pytest.skip("module-scope export not generated")
    closure = json.loads(EXPORT_CLOSURE.read_text("utf-8"))
    module = json.loads(EXPORT_MODULE.read_text("utf-8"))

    assert closure["scope"] == "function-closure"
    assert module["scope"] == "module"
    assert closure["entry"] is not None
    assert len(closure["blocks"]) < len(module["blocks"])

    # The closure must be a strict subset of the module -- if a closure block is
    # absent module-wide, the scoping logic invented an address.
    closure_rvas = {b["rva"] for b in closure["blocks"]}
    module_rvas = {b["rva"] for b in module["blocks"]}
    assert closure_rvas <= module_rvas


@requires_a3
def test_closure_entry_matches_the_known_fuzz_entry() -> None:
    """ProcessPacket's static address, cross-checked against the snapshot chain.

    0x7ff719e51150 (symbol-store.json) - 0x7ff719e50000 + 0x140000000.
    """
    closure = json.loads(EXPORT_CLOSURE.read_text("utf-8"))
    assert closure["entry"] == "ProcessPacket@140001150"
    assert 0x1150 in {b["rva"] for b in closure["blocks"]}


# --- comparison against wtf's own shipped coverage file -------------------


@requires_a3
@requires_reference
def test_our_format_matches_the_shipped_file_exactly() -> None:
    """Both files must parse identically under the same logic."""
    ours = validate_cov_file(COV_FILE)
    theirs = validate_cov_file(SHIPPED_COV)
    assert ours.name == theirs.name == "tlv_server"
    assert all(isinstance(a, int) for a in ours.addresses + theirs.addresses)


@requires_a3
@requires_reference
def test_closure_blocks_all_appear_in_the_reference() -> None:
    """Every block we would instrument is one wtf's own tooling also found.

    A false positive here would be an address that is not a real basic-block
    start -- wtf skips those with a warning, so they would quietly erode the
    breakpoint set rather than error.
    """
    ours = validate_cov_file(COV_FILE)
    reference = set(validate_cov_file(SHIPPED_COV).addresses)
    unknown = sorted(set(ours.addresses) - reference)
    assert not unknown, (
        f"{len(unknown)} closure blocks are absent from the reference .cov: "
        f"{[hex(a) for a in unknown[:10]]}"
    )


@requires_a3
@requires_reference
def test_module_scope_recall_against_the_reference() -> None:
    """We must find substantially all of what the author's tooling found.

    Extra blocks are cheap -- an untranslatable one is skipped with a warning.
    MISSING blocks are the real cost: they are coverage that is never counted,
    silently, so recall is the number worth gating on.
    """
    if not EXPORT_MODULE.exists():
        pytest.skip("module-scope export not generated")
    module = json.loads(EXPORT_MODULE.read_text("utf-8"))
    ours = {b["rva"] for b in module["blocks"]}
    reference = set(validate_cov_file(SHIPPED_COV).addresses)

    recall = len(ours & reference) / len(reference)
    assert recall >= 0.95, (
        f"recall against wtf's own .cov is {recall:.1%} "
        f"({len(reference - ours)} of {len(reference)} blocks missed)"
    )
