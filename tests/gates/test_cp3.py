"""GATE 3 -- snapshot acquisition -> A1 (CLAUDE.md CP3).

Gate conditions (edges 1, 6, 7 or 8, 11):
  * `a1_snapshot.json` exists
  * wtf loads the snapshot and executes >= 1 iteration from it
  * `module_base` and `entry_runtime_addr` recorded
  * on Linux, `aslr_disabled == True`

Scope note, stated plainly: GATE 3 asks that a snapshot **loads and runs**, not
that we took it ourselves. It is satisfied here against wtf's shipped
`tlv_server` snapshot. The *acquisition* half of `prep/snapshot_win.py`
(`build_kd_commands`) needs a Hyper-V VM and the `0vercl0k/snapshot` extension,
neither of which exists on this host, so it is unit-tested but has never driven
a real KD session. See docs/PROGRESS.md for what that leaves unproven.

Regenerate A1 with:

    python -m prep.snapshot_win ingest --state targets/tlv_server/state \
        --module tlv_server --entry-symbol ProcessPacket \
        --binary targets/tlv_server/target/tlv_server.exe
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from arch.addr import AddressSpace
from arch.contracts import SnapshotRef
from prep.snapshot_linux import (
    AslrEnabledError,
    LinuxSnapshotError,
    assert_aslr_disabled,
)
from prep.snapshot_linux import ingest_state_dir as linux_ingest
from prep.snapshot_win import (
    SnapshotError,
    ingest_state_dir,
    parse_symbol_store,
    read_pe_image_base,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
A1 = REPO_ROOT / "artifacts" / "a1_snapshot.json"
TLV = REPO_ROOT / "targets" / "tlv_server"
TLV_STATE = TLV / "state"
TLV_BINARY = TLV / "target" / "tlv_server.exe"
WTF_EXE = REPO_ROOT / "src" / "build" / "wtf.exe"

# Verified independently in tests/test_addr.py.
MODULE_BASE = 0x7FF719E50000
GHIDRA_IMAGE_BASE = 0x140000000
ENTRY_RUNTIME = 0x7FF719E51150
ENTRY_STATIC = 0x140001150

requires_a1 = pytest.mark.skipif(
    not A1.exists(), reason="A1 not generated; see this module's docstring"
)
requires_target = pytest.mark.skipif(
    not TLV_STATE.exists(), reason="targets/tlv_server not extracted"
)
requires_wtf = pytest.mark.skipif(
    not WTF_EXE.exists(), reason="wtf.exe not built; see docs/ENVIRONMENT.md"
)


def _write_state(tmp_path: Path, *, rip: int, symbols: dict[str, str]) -> Path:
    state = tmp_path / "state"
    state.mkdir()
    (state / "mem.dmp").write_bytes(b"")
    (state / "regs.json").write_text(json.dumps({"rip": hex(rip)}), encoding="utf-8")
    (state / "symbol-store.json").write_text(json.dumps(symbols), encoding="utf-8")
    return state


# --- PE image base --------------------------------------------------------


@requires_target
def test_reads_the_pe_image_base() -> None:
    assert read_pe_image_base(TLV_BINARY) == GHIDRA_IMAGE_BASE


def test_rejects_a_non_pe(tmp_path: Path) -> None:
    junk = tmp_path / "x.exe"
    junk.write_bytes(b"\x7fELF" + b"\0" * 128)
    with pytest.raises(SnapshotError, match="not a PE"):
        read_pe_image_base(junk)


# --- ingest: the checks that prevent silent wrongness ---------------------


def test_module_name_must_not_carry_an_extension(tmp_path: Path) -> None:
    state = _write_state(tmp_path, rip=0x1000, symbols={"m": "0x1000"})
    with pytest.raises(SnapshotError, match="extension"):
        ingest_state_dir(
            state, "tlv_server.exe", ghidra_image_base=GHIDRA_IMAGE_BASE
        )


def test_missing_state_files_are_caught(tmp_path: Path) -> None:
    empty = tmp_path / "state"
    empty.mkdir()
    with pytest.raises(SnapshotError, match="mem.dmp"):
        ingest_state_dir(empty, "m", ghidra_image_base=GHIDRA_IMAGE_BASE)


def test_unknown_module_lists_what_is_available(tmp_path: Path) -> None:
    state = _write_state(tmp_path, rip=0x1000, symbols={"other": "0x1000"})
    with pytest.raises(SnapshotError, match="known modules"):
        ingest_state_dir(state, "missing", ghidra_image_base=GHIDRA_IMAGE_BASE)


def test_snapshot_not_taken_at_the_entry_is_rejected(tmp_path: Path) -> None:
    """The failure this catches still fuzzes -- it just fuzzes the wrong thing.

    A snapshot taken somewhere other than the fuzz entry loads fine and reports
    healthy coverage, so nothing downstream would notice.
    """
    state = _write_state(
        tmp_path,
        rip=0x7FF719E50000,  # module base, not the entry
        symbols={"m": "0x7ff719e50000", "m!Parse": "0x7ff719e51150"},
    )
    with pytest.raises(SnapshotError, match="not taken at the entry"):
        ingest_state_dir(
            state, "m", entry_symbol="Parse", ghidra_image_base=GHIDRA_IMAGE_BASE
        )

    # ...but a harness that deliberately starts earlier can opt out.
    ref = ingest_state_dir(
        state,
        "m",
        entry_symbol="Parse",
        ghidra_image_base=GHIDRA_IMAGE_BASE,
        require_rip_at_entry=False,
    )
    assert ref.entry_runtime_addr == 0x7FF719E51150


def test_entry_defaults_to_the_snapshot_rip(tmp_path: Path) -> None:
    """No symbol given: rip IS the entry -- that is what breaking there means."""
    state = _write_state(tmp_path, rip=0x7FF719E51150, symbols={"m": "0x7ff719e50000"})
    ref = ingest_state_dir(state, "m", ghidra_image_base=GHIDRA_IMAGE_BASE)
    assert ref.entry_runtime_addr == 0x7FF719E51150


def test_image_base_must_come_from_somewhere(tmp_path: Path) -> None:
    state = _write_state(tmp_path, rip=0x1000, symbols={"m": "0x1000"})
    with pytest.raises(SnapshotError, match="ghidra-image-base"):
        ingest_state_dir(state, "m")


@requires_target
def test_symbol_store_parses() -> None:
    symbols = parse_symbol_store(TLV_STATE / "symbol-store.json")
    assert symbols["tlv_server"] == MODULE_BASE
    assert symbols["tlv_server!ProcessPacket"] == ENTRY_RUNTIME


# --- Linux path: ASLR is asserted loudly ---------------------------------


def test_aslr_must_be_disabled() -> None:
    assert_aslr_disabled(0)  # the only acceptable value
    for value in (1, 2):
        with pytest.raises(AslrEnabledError, match="randomize_va_space"):
            assert_aslr_disabled(value)


def test_linux_ingest_refuses_with_aslr_on(tmp_path: Path) -> None:
    state = _write_state(tmp_path, rip=0x401150, symbols={"m": "0x400000"})
    with pytest.raises(AslrEnabledError):
        linux_ingest(
            state,
            "m",
            module_base=0x400000,
            ghidra_image_base=0x400000,
            entry_runtime_addr=0x401150,
            randomize_va_space=2,
        )


def test_linux_ingest_sets_aslr_disabled(tmp_path: Path) -> None:
    """GATE 3: on Linux, aslr_disabled == True."""
    state = _write_state(tmp_path, rip=0x401150, symbols={"m": "0x400000"})
    ref = linux_ingest(
        state,
        "m",
        module_base=0x400000,
        ghidra_image_base=0x400000,
        entry_runtime_addr=0x401150,
        randomize_va_space=0,
    )
    assert ref.os == "linux"
    assert ref.aslr_disabled is True
    assert ref.symbol_store_json is not None


def test_linux_requires_a_symbol_store(tmp_path: Path) -> None:
    """No dbgeng on Linux: without this file there are no breakpoints at all."""
    state = _write_state(tmp_path, rip=0x401150, symbols={"m": "0x400000"})
    (state / "symbol-store.json").unlink()
    with pytest.raises(LinuxSnapshotError, match="REQUIRED on Linux"):
        linux_ingest(
            state,
            "m",
            module_base=0x400000,
            ghidra_image_base=0x400000,
            entry_runtime_addr=0x401150,
            randomize_va_space=0,
        )


def test_contract_rejects_a_linux_snapshot_with_aslr_on() -> None:
    """Belt and braces: the contract itself refuses it too."""
    with pytest.raises(ValidationError, match="aslr_disabled"):
        SnapshotRef(
            path="s", os="linux", mem_dmp="m", regs_json="r",
            symbol_store_json="ss", module_base=0x400000,
            ghidra_image_base=0x400000, entry_runtime_addr=0x401150,
            aslr_disabled=False,
        )


# --- the A1 artifact ------------------------------------------------------


@requires_a1
def test_a1_exists_and_validates() -> None:
    """GATE 3: a1_snapshot.json exists."""
    ref = SnapshotRef.model_validate_json(A1.read_text(encoding="utf-8"))
    assert ref.os == "windows"


@requires_a1
def test_a1_records_module_base_and_entry() -> None:
    """GATE 3: module_base and entry_runtime_addr recorded."""
    ref = SnapshotRef.model_validate_json(A1.read_text(encoding="utf-8"))
    assert ref.module_base == MODULE_BASE
    assert ref.entry_runtime_addr == ENTRY_RUNTIME
    assert ref.ghidra_image_base == GHIDRA_IMAGE_BASE


@requires_a1
def test_a1_address_chain_agrees_with_ghidra() -> None:
    """A1 and A3 must describe the same entry, or CP4 instruments the wrong code."""
    ref = SnapshotRef.model_validate_json(A1.read_text(encoding="utf-8"))
    space = AddressSpace("tlv_server", ref.module_base, ref.ghidra_image_base)
    assert space.to_static(ref.entry_runtime_addr) == ENTRY_STATIC

    export = REPO_ROOT / "artifacts" / "a3_ghidra_blocks.json"
    if export.exists():
        closure = json.loads(export.read_text(encoding="utf-8"))
        assert closure["entry"] == f"ProcessPacket@{ENTRY_STATIC:x}"


@requires_a1
def test_a1_paths_point_at_real_files() -> None:
    ref = SnapshotRef.model_validate_json(A1.read_text(encoding="utf-8"))
    for path in (ref.mem_dmp, ref.regs_json, ref.symbol_store_json):
        assert path and Path(path).exists(), f"A1 references missing {path}"


# --- edge 11: wtf actually loads it and runs ------------------------------


@requires_a1
@requires_wtf
@requires_target
def test_wtf_loads_the_snapshot_and_executes() -> None:
    """GATE 3, edge 11: A1 -> fuzz_target.snapshot, proven by running it.

    Needs _NT_SYMBOL_PATH (D-023) -- without it the module's Init fails to
    resolve its breakpoints and the run aborts before executing anything.
    """
    ref = SnapshotRef.model_validate_json(A1.read_text(encoding="utf-8"))

    env = dict(os.environ)
    env["_NT_SYMBOL_PATH"] = (
        "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols;"
        + str(TLV / "target")
    )
    env["PATH"] = os.pathsep.join(
        p for p in (q.strip().strip('"') for q in env.get("PATH", "").split(os.pathsep)) if p
    )

    proc = subprocess.run(
        [
            str(WTF_EXE), "run",
            "--name", "tlv_server",
            # A1 stores repo-root-relative paths; wtf resolves --state against
            # its own cwd, which is the target directory. Resolve explicitly.
            "--state", str((REPO_ROOT / ref.path).resolve()),
            "--backend=bochscpu",
            "--input", str(TLV / "inputs" / "normal.json"),
            "--limit", "10000000",
        ],
        cwd=TLV,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=900,
    )

    assert proc.returncode == 0, (
        f"wtf run failed ({proc.returncode}):\n{proc.stdout[-2000:]}"
    )
    assert "Run stats:" in proc.stdout, f"no run stats:\n{proc.stdout[-2000:]}"

    # >= 1 iteration executed, with real coverage rather than an empty run.
    assert "Instructions executed:" in proc.stdout
    cov_line = next(
        (ln for ln in proc.stdout.splitlines() if ln.startswith("#1 cov:")), None
    )
    assert cov_line, f"no coverage line:\n{proc.stdout[-2000:]}"
    coverage = int(cov_line.split("cov:")[1].split()[0])
    assert coverage > 0, f"snapshot loaded but covered nothing: {cov_line}"
