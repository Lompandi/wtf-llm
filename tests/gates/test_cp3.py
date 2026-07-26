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
import pathlib
import os
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from arch.addr import AddressSpace
# missing_gate_evidence: skip in development, fail under SNAPFUZZ_STRICT_GATE=1.
from tests.gates.conftest import missing_gate_evidence
from arch.contracts import SnapshotRef
from prep.snapshot_linux import (
    AslrEnabledError,
    LinuxSnapshotError,
    assert_aslr_disabled,
)
from prep.snapshot_linux import ingest_state_dir as linux_ingest
from prep.snapshot_linux import (
    COMM_MAX,
    DEFAULT_TARGET_BASE,
    LinuxAcquireError,
    build_plan,
    check_linux_prerequisites,
    comm_name,
    remaining_steps,
    render_bkpt,
)
from prep.snapshot_win import (
    AcquireError,
    acquire_snapshot,
    build_acquire_argv,
    split_windows_command,
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
    """No dbgeng: without this file there are no breakpoints at all.

    Pinned on "REQUIRED", not on the old "REQUIRED on Linux" phrasing. The
    condition is `#ifdef LINUX` -- a property of the host wtf was built for,
    not of the target's OS -- and the wording was corrected with D-062.
    """
    state = _write_state(tmp_path, rip=0x401150, symbols={"m": "0x400000"})
    (state / "symbol-store.json").unlink()
    with pytest.raises(LinuxSnapshotError, match="is REQUIRED"):
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
    """A1's three paths resolve -- where the snapshot is present.

    `mem.dmp` is 1.8 GB and is deliberately recorded by hash rather than shipped
    (D-069), so inside a release archive this asserts about a file that was never meant
    to be there. It skips instead: the claim is "A1 does not reference nonsense", and a
    file that is absent by policy is not nonsense (D-075).
    """
    ref = SnapshotRef.model_validate_json(A1.read_text(encoding="utf-8"))
    paths = [ref.mem_dmp, ref.regs_json, ref.symbol_store_json]
    for path in paths:
        assert path, f"A1 has an empty path among {paths}"
    absent = [p for p in paths if not Path(p).exists()]
    if absent:
        missing_gate_evidence(
            f"the recorded snapshot is not present here ({absent}); it is large and "
            f"travels by hash. This checks A1's paths resolve, which needs the files."
        )


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


# --- snapshot ACQUISITION: driving KD rather than printing its commands ----
#
# None of this can run end to end here: there is no guest VM on this host, so the
# only checkable surface is the command line that WOULD be issued, plus the refusals
# that happen before kd is ever launched. That is stated rather than papered over --
# these tests pin the argv, not the acquisition.

KD = Path("C:/kits/kd.exe")
DLL = Path("C:/tools/snapshot.dll")


def _argv(**kwargs):
    defaults = dict(
        kd_exe=KD,
        snapshot_dll=DLL,
        break_at="tlv_server!ProcessPacket",
        pipe=r"\\.\pipe\snapfuzz",
    )
    defaults.update(kwargs)
    return build_acquire_argv(Path("targets/t/state"), **defaults)


def test_acquire_argv_hangs_the_work_off_the_breakpoint():
    """The command list belongs to `bp`, not to the -c sequence after `g`.

    Sequencing `!snapshot` after `g` in the -c string assumes KD resumes executing
    that string once the break fires, which it does not promise. If this regresses
    the session runs `g` and hangs, having taken no snapshot -- and the failure
    looks exactly like "nothing drove the target", so it would be misdiagnosed.
    """
    argv = _argv()
    command = argv[argv.index("-c") + 1]
    assert 'bp tlv_server!ProcessPacket "!snapshot' in command
    assert command.rstrip().endswith("; g"), command
    # `g` is LAST. Nothing may follow it, because nothing after it is guaranteed.
    assert command.index("!snapshot") < command.index("; g")


def test_acquire_argv_quits_after_snapshotting():
    """`qq` inside the breakpoint command, or kd waits forever with the snapshot
    already on disk and the caller times out on a run that actually succeeded."""
    command = _argv()[_argv().index("-c") + 1]
    assert "; qq" in command


def test_acquire_argv_uses_a_reconnecting_pipe_transport():
    argv = _argv()
    transport = argv[argv.index("-k") + 1]
    assert transport.startswith("com:pipe,port=")
    # The guest rebooting mid-session must not end the session.
    assert "resets=0" in transport and "reconnect" in transport


def test_acquire_argv_switches_context_before_snapshotting_wow64():
    """`!wow64exts.sw` must precede `bp`/`!snapshot` (section 13.6).

    After the fact the captured state is the 32-bit view, which wtf cannot use --
    and the snapshot still exists, so this fails as a puzzling wtf error much later
    rather than at acquisition.
    """
    command = _argv(wow64=True)[_argv(wow64=True).index("-c") + 1]
    assert command.index("!wow64exts.sw") < command.index("bp ")
    assert command.index("!wow64exts.sw") < command.index("!snapshot")


def test_acquire_argv_omits_wow64_by_default():
    assert "!wow64exts" not in _argv()[_argv().index("-c") + 1]


def test_acquire_argv_rejects_a_bare_symbol_name():
    """`bp ProcessPacket` binds to whatever module KD's context happens to be in.

    Usually that is the kernel, so the breakpoint never fires and this looks like
    a stimulus problem.
    """
    with pytest.raises(ValueError, match="module!Function"):
        _argv(break_at="ProcessPacket")


def test_acquire_argv_accepts_a_raw_address():
    argv = _argv(break_at="0x7ff612340000")
    assert "bp 0x7ff612340000" in argv[argv.index("-c") + 1]


def test_acquire_argv_rejects_an_unknown_dump_kind():
    with pytest.raises(ValueError, match="full"):
        _argv(kind="everything")


def test_acquire_argv_passes_symbol_paths_and_log():
    argv = _argv(
        symbol_paths=["srv*C:/sym*https://msdl.microsoft.com/download/symbols", "C:/pdbs"],
        log_path=Path("logs/kd.log"),
    )
    assert argv[argv.index("-y") + 1].count(";") == 1, "symbol paths join with ;"
    assert Path(argv[argv.index("-logo") + 1]) == Path("logs/kd.log")


def test_split_windows_command_keeps_path_separators():
    """POSIX shlex ate the backslash the first time a stimulus was written.

    `python tools\\poke.py 1337` became `python toolspoke.py 1337`, which fails as
    file-not-found -- a quoting bug wearing a missing-file costume.
    """
    assert split_windows_command(r"python tools\poke.py 1337") == [
        "python",
        r"tools\poke.py",
        "1337",
    ]


def test_split_windows_command_strips_quotes_it_used_for_grouping():
    assert split_windows_command(r'"C:\Program Files\p.exe" "a b"') == [
        r"C:\Program Files\p.exe",
        "a b",
    ]


def test_acquire_refuses_to_overwrite_an_existing_snapshot(tmp_path):
    """Two campaigns against the same state/ must not silently share a file.

    Overwriting in place makes it impossible to say afterwards which state a
    finished campaign actually fuzzed.
    """
    state = tmp_path / "state"
    state.mkdir()
    (state / "mem.dmp").write_bytes(b"old")
    kd = tmp_path / "kd.exe"
    kd.write_bytes(b"")
    dll = tmp_path / "snapshot.dll"
    dll.write_bytes(b"")
    with pytest.raises(AcquireError, match="already holds"):
        acquire_snapshot(
            state,
            break_at="m!f",
            pipe="p",
            kd_exe=kd,
            snapshot_dll=dll,
        )


def test_acquire_refuses_a_missing_kd(tmp_path):
    with pytest.raises(AcquireError, match="does not exist"):
        acquire_snapshot(
            tmp_path / "state",
            break_at="m!f",
            pipe="p",
            kd_exe=tmp_path / "nope" / "kd.exe",
            snapshot_dll=DLL,
        )


# --- Linux acquisition: driving linux_mode --------------------------------
#
# Same situation as the Windows path: no guest exists here, so what is checkable
# is the plan, the generated `bkpt.py`, and the refusals. That is where both bugs
# in the Windows version were caught before any VM existed (D-058, D-059), so it
# is worth pinning here too.

WTF_ROOT = Path(__file__).resolve().parents[2]


def _plan(**overrides):
    settings = dict(
        repo_root=WTF_ROOT,
        target_name="mytarget",
        binary=Path("build/a.out"),
        break_at="do_crash_test",
    )
    settings.update(overrides)
    return build_plan(**settings)


def test_generated_bkpt_matches_the_shape_gdb_sources():
    """`bkpt.py` is executed as Python inside gdb, from gdb_client.sh's `-x`.

    The four names below are what wtf's own linux_mode/README.md tells a human to
    fill in, so they are the contract -- renaming one silently produces a file gdb
    runs to no effect.
    """
    source = render_bkpt(
        target_dir="mytarget", break_address="parse", file_name="a.out", sym_path="a.out"
    )
    assert "from gdb_fuzzbkpt import *" in source
    for name in ("target_dir", "break_address", "file_name"):
        assert f"{name} = " in source, name
    assert "FuzzBkpt(" in source
    # Compiles as Python: a syntax error here surfaces inside gdb, a long way from
    # the command that produced it.
    compile(source, "bkpt.py", "exec")


def test_generated_bkpt_quotes_its_values():
    """Values go through repr. A symbol carrying a quote would otherwise be a
    syntax error inside gdb rather than a rejected argument here."""
    source = render_bkpt(
        target_dir="t", break_address="odd'name", file_name="a b.out", sym_path=None
    )
    compile(source, "bkpt.py", "exec")
    assert "sym_path=None" in source


def test_generated_bkpt_carries_the_target_base_forward():
    """FuzzBkpt's `target_base` IS the module_base A1 needs. If the generated file
    and the reported number could differ, every address conversion built on A1
    would be quietly wrong."""
    plan = _plan(target_base=0x600000000000)
    assert "target_base=0x600000000000" in plan["bkpt_source"]
    assert plan["module_base"] == 0x600000000000


def test_default_target_base_matches_fuzzbkpt_itself():
    """Read off gdb_fuzzbkpt.py rather than remembered, so the two cannot drift.

    If wtf changes its default and this constant does not, A1 records a module
    base the snapshot was not taken at -- which is silent, not an error.
    """
    import re

    source = (WTF_ROOT / "linux_mode" / "qemu_snapshot" / "gdb_fuzzbkpt.py").read_text(
        encoding="utf-8", errors="replace"
    )
    match = re.search(r"target_base\s*=\s*(0[xX][0-9a-fA-F]+)", source)
    assert match, "FuzzBkpt no longer has a target_base default"
    assert int(match.group(1), 16) == DEFAULT_TARGET_BASE


def test_bare_decimal_break_address_is_rejected():
    """`break *1234` is a location gdb accepts and nobody meant -- a silently
    wrong breakpoint rather than an error."""
    with pytest.raises(ValueError, match="decimal"):
        render_bkpt(
            target_dir="t", break_address="1234", file_name="a.out", sym_path=None
        )


def test_hex_break_address_is_accepted():
    source = render_bkpt(
        target_dir="t", break_address="0x401000", file_name="a.out", sym_path=None
    )
    assert "break_address = '0x401000'" in source


def test_target_dir_is_a_name_not_a_path():
    """FuzzBkpt resolves it against $WTF/targets, so passing a path would nest
    targets/ inside targets/ and the snapshot would land somewhere nobody looks."""
    plan = _plan(target_name="mytarget")
    assert "target_dir = 'mytarget'" in plan["bkpt_source"]
    assert plan["state_dir"] == WTF_ROOT / "targets" / "mytarget" / "state"


def test_scripts_run_from_the_snapshot_subdirectory():
    """gdb_server.sh and gdb_client.sh both use `../` paths, and gdb_client.sh
    sources `./bkpt.py`. Invoked from anywhere else they resolve to nothing."""
    plan = _plan()
    assert plan["work_dir"] == WTF_ROOT / "linux_mode" / "mytarget"
    assert plan["bkpt_path"].parent == plan["work_dir"]
    for label in ("server_cmd", "client_cmd"):
        assert any("../qemu_snapshot/" in str(c) for c in plan[label]), label


def test_scp_runs_from_target_vm_where_its_key_lives():
    """scp.sh references ./image/bookworm.id_rsa relatively."""
    plan = _plan()
    assert plan["scp_cwd"].name == "target_vm"
    assert "scp.sh" in " ".join(str(c) for c in plan["scp_cmd"])


def test_stimulus_runs_inside_the_guest_not_on_the_host():
    """The process whose parser we break on lives in the VM. A host-side stimulus
    would connect to nothing -- and this is the one step that cannot be derived."""
    steps = "\n".join(remaining_steps(_plan(stimulus="/root/a.out")))
    assert "root@localhost" in steps
    assert "bookworm.id_rsa" in steps
    assert "/root/a.out" in steps


def test_no_stimulus_means_no_ssh_step():
    assert "root@localhost" not in "\n".join(remaining_steps(_plan()))


def test_prerequisites_refuse_a_windows_host():
    """linux_mode is bash + KVM. Reporting this up front beats failing inside a
    shell script."""
    problems = check_linux_prerequisites(WTF_ROOT)
    if sys.platform.startswith("win"):
        assert any("Windows host" in p for p in problems), problems


def test_prerequisites_name_setup_sh_when_the_vm_was_never_built(tmp_path):
    """The image is what setup.sh produces, and it takes a long time -- so the
    complaint has to name it rather than reporting a missing file."""
    fake = tmp_path / "repo"
    (fake / "linux_mode" / "qemu_snapshot").mkdir(parents=True)
    problems = check_linux_prerequisites(fake)
    assert any("setup.sh" in p for p in problems), problems


def test_prepare_refuses_to_overwrite_an_existing_snapshot(tmp_path, monkeypatch):
    """Same rule as the Windows path: overwriting in place makes it impossible to
    say afterwards which state a finished campaign fuzzed."""
    from prep import snapshot_linux

    state = tmp_path / "targets" / "mytarget" / "state"
    state.mkdir(parents=True)
    (state / "mem.dmp").write_bytes(b"old")
    # Prerequisites pass, so the overwrite check is what fires rather than the
    # host check masking it.
    monkeypatch.setattr(snapshot_linux, "check_linux_prerequisites", lambda root: [])

    binary = tmp_path / "a.out"
    binary.write_bytes(b"\x7fELF")
    with pytest.raises(LinuxAcquireError, match="already holds"):
        snapshot_linux.prepare(
            repo_root=tmp_path,
            target_name="mytarget",
            binary=binary,
            break_at="parse",
        )


def test_prepare_refuses_a_missing_binary(tmp_path, monkeypatch):
    from prep import snapshot_linux

    monkeypatch.setattr(snapshot_linux, "check_linux_prerequisites", lambda root: [])
    with pytest.raises(LinuxAcquireError, match="does not exist"):
        snapshot_linux.prepare(
            repo_root=tmp_path,
            target_name="mytarget",
            binary=tmp_path / "nope.out",
            break_at="parse",
        )


def test_prepare_puts_the_elf_where_nm_and_readelf_will_look(tmp_path, monkeypatch):
    """sym_path is read HOST-side: FuzzBkpt shells out to `nm` and `readelf -S` on
    it relative to gdb's cwd. An earlier version passed the bare filename without
    copying the ELF there, so bkpt.py would have raised inside gdb and left gdb
    running with no breakpoint installed."""
    from prep import snapshot_linux

    monkeypatch.setattr(snapshot_linux, "check_linux_prerequisites", lambda root: [])
    binary = tmp_path / "a.out"
    binary.write_bytes(b"\x7fELFdata")

    plan = snapshot_linux.prepare(
        repo_root=tmp_path, target_name="mytarget", binary=binary, break_at="parse"
    )
    assert plan["host_copy"].parent == plan["work_dir"]
    assert plan["host_copy"].read_bytes() == b"\x7fELFdata"
    assert f"sym_path='{binary.name}'" in plan["bkpt_source"]


def test_prepare_clears_the_symbol_store_it_would_otherwise_merge_into(
    tmp_path, monkeypatch
):
    """gdb_utils.write_to_store does `data.update(content)` and never truncates
    (gdb_utils.py:12-23), and FuzzBkpt unlinks only regs.json. A second run in the
    same work directory would ship the previous binary's symbols with the new ones
    -- wrong addresses, no error."""
    from prep import snapshot_linux

    monkeypatch.setattr(snapshot_linux, "check_linux_prerequisites", lambda root: [])
    binary = tmp_path / "a.out"
    binary.write_bytes(b"\x7fELF")

    work = tmp_path / "linux_mode" / "mytarget"
    work.mkdir(parents=True)
    (work / "symbol-store.json").write_text('{"stale": "0xdead"}', encoding="utf-8")
    (work / "regs.json").write_text("{}", encoding="utf-8")

    snapshot_linux.prepare(
        repo_root=tmp_path, target_name="mytarget", binary=binary, break_at="parse"
    )
    assert not (work / "symbol-store.json").exists()
    assert not (work / "regs.json").exists()


def test_program_name_is_truncated_to_the_kernel_comm_length():
    """task->comm is char[16]. FuzzBkpt tests `program_name in comm`, so a longer
    name never matches: the breakpoint fires, declines to stop, and the snapshot
    never happens -- with no error, because a failed name check is legitimate."""
    assert comm_name("a.out") == "a.out"
    long_name = "a-very-long-binary-name"
    assert len(comm_name(long_name)) == COMM_MAX
    assert comm_name(long_name) == long_name[:COMM_MAX]

    plan = _plan(binary=Path("build") / long_name)
    assert f"file_name = '{long_name[:COMM_MAX]}'" in plan["bkpt_source"]
    # sym_path keeps the FULL name -- it is a host-side path, not a comm value.
    assert f"sym_path='{long_name}'" in plan["bkpt_source"]


def test_the_cpu_step_is_automated_and_its_fallback_is_documented():
    """The step that used to need a human, and the honest description of it now.

    `wait_for_cpu_regs_dump` spins in an unbounded loop until regs.json appears, and
    only the `cpu` command in the SERVER gdb writes it -- so if nothing runs `cpu`, the
    snapshot HANGS rather than failing. That is why the instructions have to be right
    about who runs it.

    This test used to require the words "CANNOT BE AUTOMATED", which was the claim in
    the module and was wrong: Ctrl+C is SIGINT and `cpu` is a line on stdin, so a FIFO
    for stdin plus a recorded pid is all it took (D-062's mistake repeated -- an
    accurate reading of the code, and a conclusion about the world the code did not
    support).

    What must survive is that a reader is told BOTH things: it is automatic, and what
    to do when the trigger cannot find the server gdb -- because in that case the old
    prompt appears and the snapshot waits forever for someone who is not watching.
    """
    steps = "\n".join(remaining_steps(_plan()))
    assert "cpu" in steps
    assert "done for you" in steps, "the reader is not told it is automatic"
    # The fallback, which is the case that hangs if it is not documented.
    assert "Ctrl+C" in steps
    assert "gdb_server.pid" in steps and "gdb_server.fifo" in steps, (
        "the fallback must name what the trigger looks for, or a reader cannot tell "
        "why it did not fire"
    )
    assert "CANNOT BE AUTOMATED" not in steps, (
        "this claim was false and is what stopped it being automated"
    )
    # Still discussed after the client is attached: the dump is meaningless before the
    # breakpoint has been hit.
    assert steps.rindex("cpu") > steps.rindex("gdb_client.sh")


def test_the_server_gdb_launcher_exposes_stdin_and_its_pid():
    """The two things the trigger needs, in the script that has to provide them.

    Without either, `snapshot_trigger.request_cpu_dump` falls back to printing the
    manual instructions -- correct, but silently manual again. This is the pair that
    keeps the automation from rotting: someone editing gdb_server.sh has to keep them.
    """
    script = (
        pathlib.Path(__file__).resolve().parents[2]
        / "linux_mode" / "qemu_snapshot" / "gdb_server.sh"
    ).read_text(encoding="utf-8")
    assert "mkfifo" in script, "gdb has no FIFO on stdin, so `cpu` cannot be sent"
    assert "< ${FIFO}" in script, "the FIFO is created but not used as stdin"
    assert "gdb_server.pid" in script, "gdb's pid is not recorded, so it cannot be signalled"
    # A pipeline would make $! the last stage's pid, not gdb's -- the reason this
    # script writes to vm.log and tails it instead of piping through tee.
    assert "| tee vm.log" not in script, (
        "piping gdb through tee makes $! the pid of tee, so gdb_server.pid would name "
        "the wrong process and SIGINT would go to it"
    )


def test_the_trigger_falls_back_rather_than_signalling_a_guess(tmp_path):
    """Never signal a pid it cannot verify.

    Sending SIGINT to the wrong process is not recoverable, so every uncertain case
    returns the manual instructions instead. Checked here because the failure mode is
    invisible in the happy path.
    """
    import sys

    sys.path.insert(
        0,
        str(
            pathlib.Path(__file__).resolve().parents[2]
            / "linux_mode" / "qemu_snapshot"
        ),
    )
    import snapshot_trigger

    # No pid file at all.
    assert snapshot_trigger.server_pid(tmp_path) is None
    assert not snapshot_trigger.can_trigger(tmp_path)
    message = snapshot_trigger.request_cpu_dump(tmp_path, delay_s=0)
    assert snapshot_trigger.MANUAL_INSTRUCTIONS in message

    # A pid file that is not a number.
    (tmp_path / snapshot_trigger.PID_FILENAME).write_text("not a pid")
    assert snapshot_trigger.server_pid(tmp_path) is None
    assert snapshot_trigger.MANUAL_INSTRUCTIONS in snapshot_trigger.request_cpu_dump(
        tmp_path, delay_s=0
    )

    # A dead pid -- reused numbers are exactly why liveness is checked separately.
    (tmp_path / snapshot_trigger.PID_FILENAME).write_text("999999999")
    assert snapshot_trigger.server_pid(tmp_path) == 999999999
    assert not snapshot_trigger.is_alive(999999999)
    assert not snapshot_trigger.can_trigger(tmp_path)

    # A live pid but no FIFO: nothing to send the command through, so still manual.
    # This process is alive by definition, which makes it the honest way to test it.
    import os

    (tmp_path / snapshot_trigger.PID_FILENAME).write_text(str(os.getpid()))
    assert snapshot_trigger.is_alive(os.getpid())
    assert not snapshot_trigger.can_trigger(tmp_path)
    message = snapshot_trigger.request_cpu_dump(tmp_path, delay_s=0)
    assert snapshot_trigger.MANUAL_INSTRUCTIONS in message
    assert "fifo" in message.lower()


def test_the_stimulus_step_comes_after_the_breakpoint_is_installed():
    """The breakpoint does not exist until gdb_client.sh sources bkpt.py. Running
    the target first can miss the only hit."""
    steps = remaining_steps(_plan(stimulus="/root/a.out"))
    joined = "\n".join(steps)
    assert joined.index("gdb_client.sh") < joined.index("root@localhost")
    assert "AFTER tab 3" in joined


def test_prerequisites_do_not_mistake_a_tracked_directory_for_a_built_vm():
    """`target_vm/image/` is tracked in git (it holds .gitignore and
    create-image.sh), so testing `is_dir()` reported "host can acquire" on a fresh
    clone where setup.sh had never run. Existence is not evidence (D-057)."""
    problems = check_linux_prerequisites(WTF_ROOT)
    assert any("no disk image" in p for p in problems), problems


def test_ingest_says_acquire_writes_the_symbol_store(tmp_path):
    """The message used to say "generate it from Windows first", full stop.

    That was wrong -- linux_mode writes symbol-store.json itself
    (gdb_fuzzbkpt.py:377-380), and the Windows detour is only needed for a
    hand-assembled state/ (D-062). Believing wtf's error text over its code is
    what produced the wrong claim, so the corrected text is pinned here.
    """
    state = tmp_path / "state"
    state.mkdir()
    (state / "mem.dmp").write_bytes(b"d")
    (state / "regs.json").write_text("{}", encoding="utf-8")

    with pytest.raises(Exception) as excinfo:
        linux_ingest(
            state,
            "mytarget",
            module_base=DEFAULT_TARGET_BASE,
            ghidra_image_base=0x100000,
            entry_runtime_addr=DEFAULT_TARGET_BASE + 0x1000,
            randomize_va_space=0,
        )
    message = str(excinfo.value)
    assert "linux_mode WRITES this file" in message
    assert "acquire" in message
