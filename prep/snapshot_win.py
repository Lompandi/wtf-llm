"""Windows snapshot acquisition and ingest -> A1 (CLAUDE.md CP3).

Two jobs, deliberately separate:

* :func:`ingest_state_dir` turns an **existing** ``state/`` directory into a
  :class:`arch.contracts.SnapshotRef`. This is what CP4 consumes, and it works
  today against wtf's shipped targets.
* :func:`build_kd_commands` emits the kernel-debugger script that **takes** a new
  snapshot. Running it needs a Windows VM and the ``0vercl0k/snapshot``
  extension, neither of which exists on this host yet, so that path is
  generated and documented but **not** exercised. See docs/PROGRESS.md.

Snapshots are **not** taken by wtf (DEVIATIONS D-007). ``!snapshot`` comes from
a separate project loaded into KD with ``.load``.

Address handling here is the reason CP3 exists at all: `module_base` and
`entry_runtime_addr` are what every later static<->runtime conversion hangs off
(section 9), and both come out of ``symbol-store.json`` rather than needing a
live debugger (D-014).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from arch.addr import AddressSpace
from arch.contracts import SnapshotRef

__all__ = [
    "SnapshotError",
    "read_pe_image_base",
    "parse_symbol_store",
    "ingest_state_dir",
    "write_snapshot_ref",
    "build_kd_commands",
]

MEM_DMP = "mem.dmp"
REGS_JSON = "regs.json"
SYMBOL_STORE_JSON = "symbol-store.json"


class SnapshotError(RuntimeError):
    pass


def read_pe_image_base(binary: Path) -> int:
    """ImageBase from a PE32+ optional header -- Ghidra's static base.

    Read from the file rather than taken on trust, because it is one half of
    every address conversion and a wrong value silently shifts every coverage
    breakpoint and every crash bucket.
    """
    data = binary.read_bytes()
    if data[:2] != b"MZ":
        raise SnapshotError(f"{binary} is not a PE (no MZ signature)")

    pe = int.from_bytes(data[0x3C:0x40], "little")
    if data[pe : pe + 4] != b"PE\0\0":
        raise SnapshotError(f"{binary} has no PE header at {pe:#x}")

    magic = int.from_bytes(data[pe + 0x18 : pe + 0x1A], "little")
    if magic != 0x20B:
        raise SnapshotError(
            f"{binary} is not PE32+ (magic {magic:#x}); wtf is x86-64 only"
        )

    off = pe + 0x18 + 0x18
    return int.from_bytes(data[off : off + 8], "little")


def parse_symbol_store(path: Path) -> dict[str, int]:
    """``symbol-store.json`` -> {name: address}.

    A bare module name maps to its base; ``module!symbol`` maps to a symbol
    address (D-014).
    """
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {name: int(addr, 16) for name, addr in raw.items()}


def _read_rip(regs_json: Path) -> int:
    regs = json.loads(regs_json.read_text(encoding="utf-8"))
    if "rip" not in regs:
        raise SnapshotError(f"{regs_json} has no 'rip'")
    return int(regs["rip"], 16)


def ingest_state_dir(
    state_dir: Path,
    module: str,
    *,
    entry_symbol: str | None = None,
    binary: Path | None = None,
    ghidra_image_base: int | None = None,
    require_rip_at_entry: bool = True,
) -> SnapshotRef:
    """Build A1 from an existing ``state/`` directory.

    ``module`` is the name **as the debugger knows it** -- no file extension,
    the same string a ``.cov`` file must carry (D-005).

    ``ghidra_image_base`` is read from ``binary`` when not given explicitly; one
    of the two is required, since :class:`SnapshotRef` cannot be built without
    it and guessing would corrupt every later address conversion.

    **Path convention.** The paths recorded in A1 are stored exactly as passed,
    so pass **repo-root-relative** ones for portability. A consumer must resolve
    them against the repo root, *not* against its own working directory --
    ``wtf --state`` resolves relative to wherever wtf was launched, and the
    runner launches it from inside ``targets/<name>/``. Getting this wrong looks
    like ``--state: Directory does not exist``, which at least fails loudly.
    """
    state_dir = Path(state_dir)
    mem_dmp = state_dir / MEM_DMP
    regs_json = state_dir / REGS_JSON
    symbol_store = state_dir / SYMBOL_STORE_JSON

    for required in (mem_dmp, regs_json):
        if not required.exists():
            raise SnapshotError(
                f"{required} is missing; wtf derives it from --state "
                f"(wtf.cc:312-314) and fails late and unhelpfully without it"
            )

    if "." in module:
        raise SnapshotError(
            f"module {module!r} carries an extension; use the debugger's name "
            f"(e.g. 'tlv_server'), which is also what a .cov file must contain"
        )

    if ghidra_image_base is None:
        if binary is None:
            raise SnapshotError("pass either --binary or --ghidra-image-base")
        ghidra_image_base = read_pe_image_base(Path(binary))

    if not symbol_store.exists():
        raise SnapshotError(
            f"{symbol_store} is missing. On Windows wtf regenerates it at "
            f"runtime, so run the target once first; on Linux it is required "
            f"up front because there is no dbgeng (section 13.1)."
        )

    symbols = parse_symbol_store(symbol_store)
    if module not in symbols:
        raise SnapshotError(
            f"{module!r} is not in {symbol_store.name}; known modules: "
            f"{sorted(k for k in symbols if '!' not in k)}"
        )
    module_base = symbols[module]

    rip = _read_rip(regs_json)
    if entry_symbol:
        key = f"{module}!{entry_symbol}"
        if key not in symbols:
            raise SnapshotError(
                f"{key!r} is not in {symbol_store.name}; known symbols for "
                f"{module}: "
                f"{sorted(k for k in symbols if k.startswith(module + '!'))}"
            )
        entry_runtime_addr = symbols[key]
    else:
        # No symbol given: the snapshot's rip *is* the entry, which is what
        # "break at the fuzz entry" means.
        entry_runtime_addr = rip

    # A snapshot taken somewhere other than the fuzz entry still loads and still
    # fuzzes -- it just fuzzes the wrong thing. Catch it here rather than at
    # CP4 when the coverage numbers look inexplicable.
    if require_rip_at_entry and rip != entry_runtime_addr:
        raise SnapshotError(
            f"snapshot rip is {rip:#x} but the fuzz entry is "
            f"{entry_runtime_addr:#x}. The snapshot was not taken at the entry. "
            f"Re-take it with the breakpoint at {entry_symbol or 'the entry'}, "
            f"or pass require_rip_at_entry=False if the harness deliberately "
            f"starts earlier and drives execution to the entry itself."
        )

    return SnapshotRef(
        path=str(state_dir),
        os="windows",
        mem_dmp=str(mem_dmp),
        regs_json=str(regs_json),
        symbol_store_json=str(symbol_store),
        module_base=module_base,
        ghidra_image_base=ghidra_image_base,
        entry_runtime_addr=entry_runtime_addr,
        # The guest had ASLR on -- module_base differs from the image base. That
        # is fine on Windows: the snapshot pins one layout for every iteration.
        # Only Linux requires it off (section 6).
        aslr_disabled=(module_base == ghidra_image_base),
    )


def write_snapshot_ref(ref: SnapshotRef, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(ref.model_dump_json(indent=2), encoding="utf-8")
    return path


def _snapshot_dll_from_config(repo_root: Path | None = None) -> Path | None:
    """``tools.snapshot_dll`` from config/fuzz.yaml, or None."""
    repo_root = repo_root or Path(__file__).resolve().parents[1]
    config = repo_root / "config" / "fuzz.yaml"
    if not config.exists():
        return None
    try:
        import yaml

        data = yaml.safe_load(config.read_text(encoding="utf-8")) or {}
    except Exception:
        return None
    configured = (data.get("tools") or {}).get("snapshot_dll")
    return Path(configured) if configured else None


def build_kd_commands(
    state_dir: Path,
    *,
    snapshot_dll: Path,
    break_at: str,
    kind: str = "full",
    wow64: bool = False,
) -> list[str]:
    """The KD command sequence that takes a snapshot (section 13.6).

    ``break_at`` is the break location, parameterised as CP3 requires: a symbol
    (``tlv_server!ProcessPacket``) or an address.

    Emitted rather than executed -- this needs a Hyper-V VM with one virtual CPU
    and 4 GB of RAM, KD attached, and the target already at the right state.
    """
    if kind not in {"full", "active-kernel"}:
        raise ValueError(f"kind must be 'full' or 'active-kernel', got {kind!r}")

    commands: list[str] = []
    if wow64:
        # Switch to the 64-bit context BEFORE snapshotting, or the captured
        # state is the 32-bit view and wtf cannot use it (section 13.6).
        commands.append("!wow64exts.sw")

    commands += [
        f".load {snapshot_dll}",
        f"bp {break_at}",
        "g",
        f"!snapshot -k {kind} {state_dir}",
    ]
    return commands


# --- acquisition: driving KD instead of printing its commands -------------
#
# `build_kd_commands` EMITS a command list for a human to paste, and for a long
# while that was the whole acquisition story -- edges 1/6/7 pending because the
# step needed hands. It does not, once the pieces are in place: `kd -k <transport>
# -c "<commands>"` runs a kernel-debugging session non-interactively (verified
# against `kd -?`: `-c` executes a command at the first debugger prompt, `-k` gives
# the transport, `-logo` takes a transcript).
#
# THE ORDERING TRICK, because the obvious form is unreliable. Writing
#   -c ".load dll; bp mod!Func; g; !snapshot ...; qq"
# assumes the commands after `g` run once the breakpoint fires, which is not a
# guarantee KD makes. The reliable idiom attaches the work to the breakpoint
# itself:
#   bp mod!Func "!snapshot -k full <state>; qq"
# The breakpoint IS the definition of "the state worth snapshotting", so nothing
# has to judge when to act -- hitting it is the judgement.
#
# WHAT STILL IS NOT AUTOMATIC, stated plainly because it is the real remaining
# gap: something must make the target REACH the parser. For a network service that
# means a client connecting and sending a packet; until then `g` never returns and
# this times out. `stimulus` runs a command for that purpose, but what the command
# should be is target-specific and cannot be derived from the binary.

# Hyper-V exposes a guest COM port as a host named pipe. `resets=0,reconnect` is
# the standard form: it survives the guest rebooting mid-session.
DEFAULT_PIPE_TRANSPORT = "com:pipe,port={pipe},resets=0,reconnect"


class AcquireError(RuntimeError):
    pass


def split_windows_command(command: str) -> list[str]:
    """Split a command string into argv without eating Windows path separators.

    ``shlex.split`` defaults to POSIX rules, where ``\\`` is an escape: the first
    stimulus command written by hand, ``python tools\\poke.py 1337``, came out as
    ``python toolspoke.py 1337`` and would have failed with a confusing
    file-not-found rather than a quoting error. ``posix=False`` keeps the
    separators but leaves the quote characters inside the token, so they are
    stripped here.
    """
    import shlex

    tokens = []
    for token in shlex.split(command, posix=False):
        if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
            token = token[1:-1]
        tokens.append(token)
    return tokens


def subprocess_list2cmdline(argv: list[str]) -> str:
    """Quote an argv for display. Windows quoting, because that is the host."""
    import subprocess

    return subprocess.list2cmdline(argv)


def _kd_from_config(repo_root: Path | None = None) -> Path | None:
    """``tools.kd_exe`` from config/fuzz.yaml, or None."""
    repo_root = repo_root or Path(__file__).resolve().parents[1]
    config = repo_root / "config" / "fuzz.yaml"
    if not config.exists():
        return None
    try:
        import yaml

        data = yaml.safe_load(config.read_text(encoding="utf-8")) or {}
    except Exception:
        return None
    configured = (data.get("tools") or {}).get("kd_exe")
    return Path(configured) if configured else None


def build_acquire_argv(
    state_dir: Path,
    *,
    kd_exe: Path,
    snapshot_dll: Path,
    break_at: str,
    pipe: str,
    module: str | None = None,
    kind: str = "full",
    wow64: bool = False,
    symbol_paths: list[str] | None = None,
    log_path: Path | None = None,
) -> list[str]:
    """The full ``kd`` command line for an unattended snapshot.

    Separated from running it so the command can be inspected, tested and printed
    without a VM -- which is the only way any of this is checkable on a host with
    no guest.
    """
    if kind not in {"full", "active-kernel"}:
        raise ValueError(f"kind must be 'full' or 'active-kernel', got {kind!r}")
    if module and "!" not in break_at and not break_at.startswith("0x"):
        # Composed HERE rather than by the caller so the symbol can stay a whole
        # command-line argument. The pipeline substitutes its late-bound entry by
        # exact argument match, so f"{module}!{symbol}" would have reached kd with
        # the placeholder still in it -- an unbindable breakpoint whose symptom is
        # identical to a stimulus that never arrived.
        break_at = f"{module}!{break_at}"
    if "!" not in break_at and not break_at.startswith("0x"):
        raise ValueError(
            f"break_at {break_at!r} must be 'module!Function' or a 0x address -- "
            f"KD resolves it by name and a bare name will not bind. Pass --module, "
            f"or qualify it yourself."
        )

    # Escaped for nesting inside the -c string.
    inner = f'!snapshot -k {kind} {state_dir}; qq'
    setup = [f".load {snapshot_dll}"]
    if wow64:
        # Switch to the 64-bit context BEFORE snapshotting, or the captured state
        # is the 32-bit view and wtf cannot use it (section 13.6).
        setup.append("!wow64exts.sw")
    setup.append(f'bp {break_at} "{inner}"')
    setup.append("g")

    argv = [
        str(kd_exe),
        "-k", DEFAULT_PIPE_TRANSPORT.format(pipe=pipe),
    ]
    if symbol_paths:
        argv += ["-y", ";".join(symbol_paths)]
    if log_path is not None:
        argv += ["-logo", str(log_path)]
    argv += ["-c", "; ".join(setup)]
    return argv


def acquire_snapshot(
    state_dir: Path,
    *,
    break_at: str,
    pipe: str,
    module: str | None = None,
    kd_exe: Path | None = None,
    snapshot_dll: Path | None = None,
    kind: str = "full",
    wow64: bool = False,
    symbol_paths: list[str] | None = None,
    stimulus: list[str] | None = None,
    timeout_s: int = 900,
    log_path: Path | None = None,
) -> Path:
    """Take a snapshot by driving KD. Returns ``state_dir``.

    **NEVER EXERCISED ON THIS HOST.** There is no guest VM here (`Get-VM` is
    empty), so this has been written against `kd -?` and section 13.6 and has not
    run end to end. That is recorded rather than glossed: the argv builder is
    unit-tested, the orchestration is not.
    """
    import subprocess

    kd_exe = kd_exe or _kd_from_config()
    if kd_exe is None:
        raise AcquireError(
            "no kd.exe: set tools.kd_exe in config/fuzz.yaml, or pass kd_exe. "
            "Debugging Tools for Windows is a COMPANION TOOL, not part of wtf."
        )
    if not Path(kd_exe).exists():
        raise AcquireError(f"the configured kd.exe {kd_exe} does not exist")

    snapshot_dll = snapshot_dll or _snapshot_dll_from_config()
    if snapshot_dll is None or not Path(snapshot_dll).exists():
        raise AcquireError(
            f"no usable snapshot extension ({snapshot_dll}); set "
            f"tools.snapshot_dll in config/fuzz.yaml"
        )

    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    # Refuse to write into a directory that already holds a snapshot. Overwriting
    # one silently is how a campaign ends up fuzzing a state nobody meant to take.
    existing = [p.name for p in state_dir.glob("*") if p.name in {"mem.dmp", "regs.json"}]
    if existing:
        raise AcquireError(
            f"{state_dir} already holds {existing}. Move it aside first -- "
            f"overwriting a snapshot in place makes it impossible to say which "
            f"state a later campaign actually fuzzed."
        )

    argv = build_acquire_argv(
        state_dir,
        kd_exe=Path(kd_exe),
        snapshot_dll=Path(snapshot_dll),
        break_at=break_at,
        pipe=pipe,
        module=module,
        kind=kind,
        wow64=wow64,
        symbol_paths=symbol_paths,
        log_path=log_path,
    )

    stimulus_proc = None
    if stimulus:
        # Started BEFORE kd waits, because `g` does not return until the parser is
        # reached and nothing reaches it on its own.
        stimulus_proc = subprocess.Popen(stimulus)

    try:
        completed = subprocess.run(
            argv, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout_s,
        )
    except subprocess.TimeoutExpired as exc:
        raise AcquireError(
            f"kd did not reach {break_at} within {timeout_s}s. The usual cause is "
            f"that nothing drove the target to its parser -- `g` waits forever if "
            f"no input arrives. Supply a stimulus, or drive the target by hand."
        ) from exc
    finally:
        if stimulus_proc is not None and stimulus_proc.poll() is None:
            stimulus_proc.terminate()

    # The artifact is the evidence. kd exiting 0 says the session ended, not that
    # `!snapshot` wrote anything -- the same rule the rest of this project runs on.
    produced = {p.name for p in state_dir.glob("*")}
    missing = {"mem.dmp", "regs.json"} - produced
    if missing:
        tail = (completed.stdout or completed.stderr or "").strip()[-1200:]
        raise AcquireError(
            f"kd exited {completed.returncode} but {sorted(missing)} were not "
            f"written into {state_dir}. kd said:\n{tail}"
        )
    return state_dir


GUEST_PREP_NOTES = """\
Guest VM preparation, before any of the KD commands (section 13.6):

  1. Hyper-V VM, **one virtual CPU**, 4 GB RAM. More than one vCPU changes the
     CPU state layout the snapshot captures.
  2. Run scripts/disable-kva.cmd INSIDE THE GUEST and reboot. It sets
     FeatureSettingsOverride=3 / FeatureSettingsOverrideMask=3, disabling the
     Spectre v2 and Meltdown mitigations. KVA shadow splits page tables per
     process, which interferes with snapshot-based execution. The repo ships
     this script but references it nowhere -- see docs/DEVIATIONS.md D-028.
  3. Attach KD to the VM and drive the target to the desired state, close to
     the code to be fuzzed.
  4. Consider enabling Application Verifier on the target: wtf's own
     tlv_server snapshot was taken with it on, which materially widens the set
     of faults the crash oracle can observe (D-014).
"""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    ing = sub.add_parser("ingest", help="existing state/ dir -> A1")
    ing.add_argument("--state", required=True, type=Path)
    ing.add_argument("--module", required=True, help="debugger name, no extension")
    ing.add_argument("--entry-symbol")
    ing.add_argument("--binary", type=Path, help="to read the PE ImageBase")
    ing.add_argument("--ghidra-image-base", type=lambda s: int(s, 0))
    ing.add_argument("--out", type=Path, default=Path("artifacts/a1_snapshot.json"))
    ing.add_argument(
        "--allow-rip-mismatch",
        action="store_true",
        help="accept a snapshot not taken at the fuzz entry",
    )

    acq = sub.add_parser(
        "acquire",
        help="TAKE a snapshot by driving KD unattended (needs a guest VM)",
    )
    acq.add_argument("--state", required=True, type=Path)
    acq.add_argument(
        "--pipe",
        required=True,
        help=r"host named pipe for the guest COM port, e.g. \\.\pipe\snapfuzz",
    )
    acq.add_argument(
        "--break-at",
        required=True,
        help="module!Function, 0xADDR, or a bare symbol when --module is given",
    )
    acq.add_argument(
        "--module",
        default=None,
        help="debugger module name, no extension; qualifies a bare --break-at",
    )
    acq.add_argument("--kd", type=Path, default=None, help="default: tools.kd_exe")
    acq.add_argument("--snapshot-dll", type=Path, default=None)
    acq.add_argument("--kind", default="full", choices=["full", "active-kernel"])
    acq.add_argument("--wow64", action="store_true")
    acq.add_argument("--symbol-path", action="append", default=None, dest="symbol_paths")
    acq.add_argument("--log", type=Path, default=None, help="kd -logo transcript")
    acq.add_argument(
        "--timeout",
        type=int,
        default=900,
        help="seconds to wait for the breakpoint; nothing reaches a parser on its own",
    )
    acq.add_argument(
        "--stimulus",
        default=None,
        help="command to run that drives the target to its parser (shell-split)",
    )
    acq.add_argument(
        "--dry-run",
        action="store_true",
        help="print the kd command line and exit -- the only checkable path with no VM",
    )

    kd = sub.add_parser("kd-script", help="emit the KD commands to take one")
    kd.add_argument("--state", required=True, type=Path)
    # Defaults from config/fuzz.yaml's tools.snapshot_dll. Optional rather than
    # required because the extension's path is machine-specific and belongs in
    # config, and requiring it on the command line meant the tool reported itself
    # unusable while the DLL was already installed -- the same shape as D-050.
    kd.add_argument("--snapshot-dll", type=Path, default=None)
    kd.add_argument("--break-at", required=True)
    kd.add_argument("--kind", default="full", choices=["full", "active-kernel"])
    kd.add_argument("--wow64", action="store_true")

    args = ap.parse_args(argv)

    if args.cmd == "ingest":
        ref = ingest_state_dir(
            args.state,
            args.module,
            entry_symbol=args.entry_symbol,
            binary=args.binary,
            ghidra_image_base=args.ghidra_image_base,
            require_rip_at_entry=not args.allow_rip_mismatch,
        )
        path = write_snapshot_ref(ref, args.out)
        space = AddressSpace(args.module, ref.module_base, ref.ghidra_image_base)
        print(f"A1: {path}")
        print(f"  module_base        = {ref.module_base:#x}")
        print(f"  ghidra_image_base  = {ref.ghidra_image_base:#x}")
        print(f"  slide              = {space.slide:#x}")
        print(f"  entry_runtime_addr = {ref.entry_runtime_addr:#x}")
        print(f"  entry_static_addr  = {space.to_static(ref.entry_runtime_addr):#x}")
        return 0

    if args.cmd == "acquire":
        stimulus = split_windows_command(args.stimulus) if args.stimulus else None
        if args.dry_run:
            kd_exe = args.kd or _kd_from_config() or Path("kd.exe")
            dll = args.snapshot_dll or _snapshot_dll_from_config() or Path("snapshot.dll")
            try:
                argv_out = build_acquire_argv(
                    args.state,
                    kd_exe=Path(kd_exe),
                    snapshot_dll=Path(dll),
                    break_at=args.break_at,
                    pipe=args.pipe,
                    module=args.module,
                    kind=args.kind,
                    wow64=args.wow64,
                    symbol_paths=args.symbol_paths,
                    log_path=args.log,
                )
            except ValueError as exc:
                print(f"cannot build the kd command line: {exc}")
                return 1
            print(subprocess_list2cmdline(argv_out))
            if stimulus:
                print(f"stimulus: {subprocess_list2cmdline(stimulus)}")
            return 0
        try:
            state = acquire_snapshot(
                args.state,
                break_at=args.break_at,
                pipe=args.pipe,
                module=args.module,
                kd_exe=args.kd,
                snapshot_dll=args.snapshot_dll,
                kind=args.kind,
                wow64=args.wow64,
                symbol_paths=args.symbol_paths,
                stimulus=stimulus,
                timeout_s=args.timeout,
                log_path=args.log,
            )
        except (AcquireError, ValueError) as exc:
            print(f"acquisition failed: {exc}")
            return 1
        print(f"snapshot written to {state}")
        print("next: prep/snapshot_win.py ingest --state ... --module ...")
        return 0

    snapshot_dll = args.snapshot_dll or _snapshot_dll_from_config()
    if snapshot_dll is None:
        print(
            "no snapshot extension: pass --snapshot-dll, or set "
            "tools.snapshot_dll in config/fuzz.yaml. It is 0vercl0k/snapshot, a "
            "KD extension DLL -- a COMPANION TOOL, not part of wtf (section 3.1)."
        )
        return 1
    if not snapshot_dll.exists():
        print(f"the configured snapshot extension {snapshot_dll} does not exist")
        return 1

    print(GUEST_PREP_NOTES)
    print("KD commands:\n")
    for line in build_kd_commands(
        args.state,
        snapshot_dll=snapshot_dll,
        break_at=args.break_at,
        kind=args.kind,
        wow64=args.wow64,
    ):
        print(f"  kd> {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
