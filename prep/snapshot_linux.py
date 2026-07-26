"""Linux snapshot acquisition -> A1. **EXPERIMENTAL** (CLAUDE.md CP3).

Windows is first (section 2). This path exists so the requirement is captured
and asserted, not because it is on the critical path. Nothing here has been run
against a real guest.

Two honest caveats, both recorded in docs/DEVIATIONS.md:

* **D-010** -- CLAUDE.md describes this as "GDB-based ELF snapshot" of a
  user-mode process. That is right about *what* is captured and wrong about the
  *cost*: ``linux_mode/README.md`` calls it "experimental user-mode Linux mode"
  and "Linux ELF userland snapshotting", so the snapshot is indeed of a
  user-mode process -- but getting it requires building a whole target VM and
  kernel (``qemu_snapshot/setup.sh``), running QEMU under KVM
  (``gdb_server.sh``), scp'ing the target into the guest, and attaching GDB
  (``gdb_client.sh``). The full-system VM is the vehicle, not the subject.

  An earlier version of this docstring said "not a user-mode process", which
  contradicted wtf's own README and propagated into README.md.
* CLAUDE.md states "ASLR must be disabled". A grep of ``linux_mode/`` for
  ``aslr`` / ``randomize_va_space`` finds **nothing**, so that requirement is
  not corroborated by the repo. It is asserted here anyway, because it is
  cheap and because the failure it prevents is silent: with ASLR on, the
  snapshot's ``module_base`` is one sample of a value that moves, and every
  static<->runtime conversion built on it is quietly wrong.

``symbol-store.json`` is **required**, and an earlier version of this docstring
said it "cannot be produced on Linux -- generate it from Windows first". That is
wrong, and it came from believing wtf's own error message over its own code
(D-062). ``wtf.cc:195-201`` does say "You need to generate it from Windows", but
that fires only when the file is ABSENT; ``linux_mode`` writes it as part of
taking the snapshot -- ``FuzzBkpt.__init__`` builds the symbol dict from ``nm``
output and ``gdb_utils.write_to_store`` writes it, and
``gdb_fuzzbkpt.py:377-380`` moves it into ``state/`` beside ``mem.dmp``. So a
snapshot taken the supported way already has one; only a hand-assembled
``state/`` directory needs the Windows detour.

Two things around it are still true. The condition is ``#ifdef LINUX``, which is
about the **host wtf was built for** rather than the target's OS -- a Linux host
needs the file whatever it is fuzzing. And the same DebuggerLess path gives up on
the reverse direction: ``GetName`` prints "GetName does not work on Linux", so
address-to-symbol resolution is unavailable there, which matters for stack-hash
dedup and for ``analysis/reverse.py``.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any

from arch.contracts import SnapshotRef

__all__ = [
    "AslrEnabledError",
    "LinuxAcquireError",
    "LinuxSnapshotError",
    "COMM_MAX",
    "DEFAULT_TARGET_BASE",
    "comm_name",
    "render_bkpt",
    "check_linux_prerequisites",
    "build_plan",
    "prepare",
    "remaining_steps",
    "verify_snapshot",
    "read_randomize_va_space",
    "assert_aslr_disabled",
    "ingest_state_dir",
]

RANDOMIZE_VA_SPACE = Path("/proc/sys/kernel/randomize_va_space")

MEM_DMP = "mem.dmp"
REGS_JSON = "regs.json"
SYMBOL_STORE_JSON = "symbol-store.json"

_ASLR_MEANING = {
    0: "disabled",
    1: "conservative (mmap, stack, vdso randomised)",
    2: "full (also the heap)",
}


class LinuxSnapshotError(RuntimeError):
    pass


class AslrEnabledError(LinuxSnapshotError):
    """Raised loudly, as CP3 requires, rather than degrading quietly."""


def read_randomize_va_space(path: Path = RANDOMIZE_VA_SPACE) -> int:
    """Read the guest's ASLR setting.

    Must be read **in the guest being snapshotted**. Reading it on the host
    proves nothing, which is why the value can also be supplied explicitly.
    """
    if not path.exists():
        raise LinuxSnapshotError(
            f"{path} does not exist. Read it inside the guest and pass the "
            f"value explicitly -- the host's setting says nothing about the "
            f"process being snapshotted."
        )
    return int(path.read_text(encoding="utf-8").strip())


def assert_aslr_disabled(value: int) -> None:
    """Fail loudly unless ASLR is fully off."""
    if value != 0:
        raise AslrEnabledError(
            f"randomize_va_space = {value} ({_ASLR_MEANING.get(value, 'unknown')}). "
            f"ASLR must be disabled before snapshotting: otherwise module_base "
            f"is one sample of a moving value and every static<->runtime "
            f"conversion built on this snapshot is silently wrong. "
            f"Disable with: sysctl -w kernel.randomize_va_space=0 (in the GUEST), "
            f"or run the target under `setarch -R`."
        )


def ingest_state_dir(
    state_dir: Path,
    module: str,
    *,
    module_base: int,
    ghidra_image_base: int,
    entry_runtime_addr: int,
    randomize_va_space: int,
) -> SnapshotRef:
    """Build A1 from a Linux ``state/`` directory.

    Unlike the Windows path this takes the addresses explicitly: there is no
    dbgeng to resolve them, and the symbol store is an input rather than
    something wtf regenerates.
    """
    state_dir = Path(state_dir)
    assert_aslr_disabled(randomize_va_space)

    mem_dmp = state_dir / MEM_DMP
    regs_json = state_dir / REGS_JSON
    symbol_store = state_dir / SYMBOL_STORE_JSON

    for required in (mem_dmp, regs_json):
        if not required.exists():
            raise LinuxSnapshotError(f"{required} is missing")

    if not symbol_store.exists():
        raise LinuxSnapshotError(
            f"{symbol_store} is missing and is REQUIRED: there is no dbgeng, so "
            f"wtf places coverage breakpoints from this file (debugger.h:30-60) "
            f"and refuses to start without it (wtf.cc:195-201). linux_mode WRITES "
            f"this file when it takes the snapshot (gdb_fuzzbkpt.py:377-380), so "
            f"its absence means this state/ was assembled by hand -- take the "
            f"snapshot with `acquire`, or generate the file from Windows (D-062)."
        )

    # A no-op given assert_aslr_disabled above, but it states the invariant the
    # contract's own validator will re-check.
    return SnapshotRef(
        path=str(state_dir),
        os="linux",
        mem_dmp=str(mem_dmp),
        regs_json=str(regs_json),
        symbol_store_json=str(symbol_store),
        module_base=module_base,
        ghidra_image_base=ghidra_image_base,
        entry_runtime_addr=entry_runtime_addr,
        aslr_disabled=True,
    )


# --- preparation: every mechanical step, and the one that cannot be done ---
#
# `PROCEDURE_NOTES` below prints six steps for a human. This does the mechanical
# ones and prints the rest, because ONE OF THEM CANNOT BE AUTOMATED and an earlier
# version of this module pretended otherwise.
#
# THE STEP THAT BLOCKS FULL AUTOMATION. Mid-snapshot, `FuzzBkpt.stop()` calls
# `wait_for_cpu_regs_dump()` (gdb_fuzzbkpt.py:352-369), which prints
#
#     In the QEMU tab, press Ctrl+C, run the `cpu` command
#
# and then spins in `while not REGS_JSON_FILENAME.exists(): time.sleep(1)` -- an
# unbounded loop. `regs.json` is written only by the `cpu` command, `cpu` is
# registered by gdb_qemu.py in the **server** gdb rather than the client one, and
# nothing in gdb_qemu.py stops that gdb on its own. Reaching its prompt means
# interrupting it from a terminal.
#
# This is the opposite of the Windows path, where hanging the work off the
# breakpoint (section 14.2) removed the need for anyone to decide when to act.
# Here the interactive step is real, so this module does the mechanical work and
# states exactly what is left. The earlier version drove gdb anyway: it would have
# hung in that loop until the timeout and then reported a stimulus problem -- the
# one explanation guaranteed to be believed and wrong.

LINUX_MODE = "linux_mode"
QEMU_SNAPSHOT = "qemu_snapshot"
# FuzzBkpt's own default. Read off gdb_fuzzbkpt.py rather than remembered, so the
# two cannot drift; a test asserts they agree.
DEFAULT_TARGET_BASE = 0x555555554000
# task->comm is char[16]. FuzzBkpt's is_my_program() tests `program_name in comm`,
# so a longer name never matches: the breakpoint fires, declines to stop, and the
# snapshot never happens -- with no error, because a failed name check is a
# legitimate outcome.
COMM_MAX = 15

_BKPT_TEMPLATE = """\
# GENERATED by prep/snapshot_linux.py -- edit the command line, not this file.
#
# These are the values wtf's linux_mode/README.md asks a human to fill in. gdb
# sources this file from gdb_client.sh with the CWD set to this directory, which
# is why the scripts must be invoked from here.
import sys, os

from gdb_fuzzbkpt import *

target_dir = {target_dir!r}
break_address = {break_address!r}
file_name = {file_name!r}

FuzzBkpt(
    target_dir,
    break_address,
    file_name,
    sym_path={sym_path!r},
    checkname={checkname!r},
    bp_hits_required={bp_hits!r},
    target_base={target_base:#x},
)
"""


class LinuxAcquireError(LinuxSnapshotError):
    pass


def comm_name(binary_name: str) -> str:
    """What the kernel will actually report in task->comm.

    Truncated to 15 characters. Passing the full name makes `is_my_program()`
    false forever, and the failure is silent.
    """
    return binary_name[:COMM_MAX]


def render_bkpt(
    *,
    target_dir: str,
    break_address: str,
    file_name: str,
    sym_path: str | None = None,
    checkname: bool = True,
    bp_hits: int = 1,
    target_base: int = DEFAULT_TARGET_BASE,
) -> str:
    """The `bkpt.py` gdb sources. Values go through ``repr``, deliberately.

    The file is executed as Python inside gdb, so a symbol name carrying a quote
    would be a syntax error there rather than a rejected argument here.
    """
    if not break_address:
        raise ValueError("break_address is required")
    # A bare integer is read by gdb as a literal address: `break *1234` is a
    # silently wrong location rather than an error.
    if break_address.isdigit():
        raise ValueError(
            f"break_address {break_address!r} is a bare decimal number. Use a "
            f"symbol name, or an explicit 0x-prefixed address."
        )
    if bp_hits < 1:
        raise ValueError(f"bp_hits must be >= 1, got {bp_hits}")
    return _BKPT_TEMPLATE.format(
        target_dir=target_dir,
        break_address=break_address,
        file_name=file_name,
        sym_path=sym_path,
        checkname=checkname,
        bp_hits=bp_hits,
        target_base=target_base,
    )


def check_linux_prerequisites(repo_root: Path) -> list[str]:
    """Everything that would fail mid-run, checked first. Returns complaints.

    Reported all at once: `setup.sh` builds QEMU, a kernel and a disk image, and
    learning about the second missing thing after that finishes is the waste this
    exists to avoid.
    """
    import shutil
    import sys

    problems: list[str] = []

    if sys.platform.startswith("win"):
        problems.append(
            "linux_mode is bash + KVM and cannot run on a Windows host. Use a "
            "Linux machine or WSL2 with nested virtualisation, or hand a finished "
            "state/ directory to `ingest` instead."
        )

    base = repo_root / LINUX_MODE / QEMU_SNAPSHOT
    if not base.is_dir():
        problems.append(f"{base} is missing -- is this a full wtf checkout?")
        return problems

    target_vm = base / "target_vm"
    image_dir = target_vm / "image"
    # The IMAGE FILE, not the image/ DIRECTORY. That directory is tracked in git
    # -- it holds .gitignore and create-image.sh -- so testing `is_dir()` reported
    # "host can acquire" on a fresh clone where setup.sh had never run. Same class
    # of false success as D-057: existence is not evidence.
    images = sorted(image_dir.glob("*.img")) if image_dir.is_dir() else []
    if not images:
        problems.append(
            f"no disk image (*.img) under {image_dir}: "
            f"linux_mode/qemu_snapshot/setup.sh has never completed. It builds "
            f"QEMU, a kernel and a disk image, needs sudo, and takes a long time "
            f"-- run it once by hand."
        )
    if not (target_vm / "linux" / "vmlinux").exists():
        problems.append(
            f"{target_vm / 'linux' / 'vmlinux'} is missing: gdb_client.sh loads it "
            f"as the kernel symbol file, and setup.sh is what builds it."
        )
    for script in ("gdb_server.sh", "gdb_client.sh"):
        if not (base / script).exists():
            problems.append(f"{base / script} is missing")
    if not (target_vm / "scp.sh").exists():
        problems.append(f"{target_vm / 'scp.sh'} is missing (setup.sh writes it)")

    if not sys.platform.startswith("win"):
        if not Path("/dev/kvm").exists():
            problems.append(
                "/dev/kvm is absent: gdb_server.sh starts QEMU with accel=kvm. "
                "Enable virtualisation, or add yourself to the kvm group and "
                "re-open the shell."
            )
        # nm and readelf are used HOST-side by FuzzBkpt to read the target's
        # symbols and .text offset -- not inside the guest.
        for tool in ("gdb", "nm", "readelf", "scp"):
            if shutil.which(tool) is None:
                problems.append(f"{tool} is not on PATH")

    return problems


def build_plan(
    *,
    repo_root: Path,
    target_name: str,
    binary: Path,
    break_at: str,
    work_name: str | None = None,
    checkname: bool = True,
    bp_hits: int = 1,
    target_base: int = DEFAULT_TARGET_BASE,
    stimulus: str | None = None,
) -> dict[str, Any]:
    """Everything preparation does and everything left over, as data.

    Inspectable without a guest, which on a host that cannot run any of this is
    the only checkable surface -- and it is where the Windows path's two bugs were
    caught before a VM existed (D-058, D-059).
    """
    work = work_name or target_name
    work_dir = repo_root / LINUX_MODE / work
    # sym_path is used HOST-side: FuzzBkpt shells out to `nm` and `readelf -S` on
    # it and hands it to gdb's add-symbol-file, all relative to gdb's cwd
    # (= work_dir). So the ELF must exist THERE, not only inside the guest. An
    # earlier version passed the bare name without copying it, so bkpt.py would
    # have raised inside gdb -- leaving gdb running with no breakpoint installed
    # and the snapshot silently impossible.
    host_copy = work_dir / binary.name

    return {
        "work_dir": work_dir,
        "bkpt_path": work_dir / "bkpt.py",
        "host_copy": host_copy,
        "bkpt_source": render_bkpt(
            # Resolved by FuzzBkpt against $WTF/targets, so a NAME not a path --
            # a path would nest targets/ inside targets/.
            target_dir=target_name,
            break_address=break_at,
            file_name=comm_name(binary.name),
            sym_path=binary.name,
            checkname=checkname,
            bp_hits=bp_hits,
            target_base=target_base,
        ),
        "state_dir": repo_root / "targets" / target_name / "state",
        # Both scripts use ../ paths and gdb_client.sh sources ./bkpt.py, so the
        # CWD is load-bearing.
        "script_cwd": work_dir,
        "server_cmd": ["bash", f"../{QEMU_SNAPSHOT}/gdb_server.sh"],
        "client_cmd": ["bash", f"../{QEMU_SNAPSHOT}/gdb_client.sh"],
        "scp_cmd": ["bash", "./scp.sh", str(binary.resolve())],
        "scp_cwd": repo_root / LINUX_MODE / QEMU_SNAPSHOT / "target_vm",
        "stimulus": stimulus,
        "module_base": target_base,
        "guest_path": f"/root/{binary.name}",
        "comm": comm_name(binary.name),
    }


def prepare(
    *,
    repo_root: Path,
    target_name: str,
    binary: Path,
    break_at: str,
    work_name: str | None = None,
    checkname: bool = True,
    bp_hits: int = 1,
    target_base: int = DEFAULT_TARGET_BASE,
    stimulus: str | None = None,
) -> dict[str, Any]:
    """Do the mechanical steps; return the plan for the caller to print.

    Does: validate the host, refuse to overwrite an existing snapshot, create the
    work directory, copy the ELF there for host-side symbol reading, clear the
    stale files that would otherwise be merged into, and write `bkpt.py`.

    Does NOT: start the VM or perform the interactive `cpu` step. See the comment
    at the top of this section for why the second one cannot be done from here.
    """
    import shutil

    problems = check_linux_prerequisites(repo_root)
    if problems:
        raise LinuxAcquireError(
            "cannot prepare on this host:\n  - " + "\n  - ".join(problems)
        )
    if not binary.exists():
        raise LinuxAcquireError(f"target binary {binary} does not exist")

    plan = build_plan(
        repo_root=repo_root,
        target_name=target_name,
        binary=binary,
        break_at=break_at,
        work_name=work_name,
        checkname=checkname,
        bp_hits=bp_hits,
        target_base=target_base,
        stimulus=stimulus,
    )

    state_dir: Path = plan["state_dir"]
    existing = [
        name
        for name in (MEM_DMP, REGS_JSON, SYMBOL_STORE_JSON)
        if (state_dir / name).exists()
    ]
    if existing:
        raise LinuxAcquireError(
            f"{state_dir} already holds {existing}. Move it aside first -- "
            f"overwriting a snapshot in place makes it impossible to say which "
            f"state a later campaign actually fuzzed."
        )

    work_dir: Path = plan["work_dir"]
    work_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(binary, plan["host_copy"])

    # gdb_utils.write_to_store MERGES into an existing file rather than truncating
    # it (gdb_utils.py:12-23), and FuzzBkpt unlinks only regs.json. A second run in
    # the same work directory would therefore ship the previous binary's symbols
    # alongside the new ones: wrong addresses, no error.
    for stale in (SYMBOL_STORE_JSON, REGS_JSON):
        (work_dir / stale).unlink(missing_ok=True)

    plan["bkpt_path"].write_text(plan["bkpt_source"], encoding="utf-8")
    return plan


def remaining_steps(plan: dict[str, Any]) -> list[str]:
    """The steps preparation cannot do, in order, with the reasons.

    Returned as data rather than printed so a test can assert the interactive
    `cpu` step is named. Omitting it from the instructions is the failure this
    module is organised around: without it the snapshot hangs in
    `wait_for_cpu_regs_dump` rather than failing.
    """
    cwd = plan["work_dir"]
    scp = " ".join(str(c) for c in plan["scp_cmd"])
    steps = [
        "# tab 1 -- starts QEMU under gdb and stays running",
        f"cd {cwd} && bash ../{QEMU_SNAPSHOT}/gdb_server.sh",
        "",
        "# tab 2 -- once the guest has booted, copy the target in",
        f"cd {plan['scp_cwd']} && {scp}",
        "",
        "# tab 3 -- installs the breakpoint from bkpt.py, then continues",
        f"cd {cwd} && bash ../{QEMU_SNAPSHOT}/gdb_client.sh",
    ]
    if plan["stimulus"]:
        steps += [
            "",
            "# tab 2 again -- AFTER tab 3 reports the breakpoint is set, run the",
            "# target in the guest. Nothing reaches the parser on its own, and this",
            "# is the one thing that cannot be derived from the binary.",
            "ssh -i ./image/bookworm.id_rsa -p 10021 "
            f"-o 'StrictHostKeyChecking no' root@localhost {plan['stimulus']!r}",
        ]
    steps += [
        "",
        "# tab 1 again -- THE STEP THAT CANNOT BE AUTOMATED. When tab 3 prints",
        '#     "In the QEMU tab, press Ctrl+C, run the `cpu` command"',
        "#   press Ctrl+C in tab 1 and type:  cpu",
        "#",
        "# `cpu` is registered in the SERVER gdb (gdb_qemu.py) and is the only thing",
        "# that writes regs.json. FuzzBkpt waits for that file in an unbounded loop,",
        "# so skipping this hangs the snapshot instead of failing it.",
    ]
    return steps


def verify_snapshot(plan: dict[str, Any]) -> list[str]:
    """Which of the three artifacts are missing. Empty means the snapshot is there.

    The artifact is the evidence, as everywhere else here: gdb exits 0 having done
    nothing at all if the breakpoint was never hit.
    """
    state_dir: Path = plan["state_dir"]
    return [
        name
        for name in (MEM_DMP, REGS_JSON, SYMBOL_STORE_JSON)
        if not (state_dir / name).exists()
    ]


PROCEDURE_NOTES = """\
EXPERIMENTAL. wtf snapshots a user-mode ELF process, but does it from inside a
purpose-built QEMU VM driven by GDB (docs/DEVIATIONS.md D-010). From
linux_mode/README.md:

  1. linux_mode/qemu_snapshot/setup.sh          -- build the target VM + kernel
  2. a bkpt.py deriving from gdb_fuzzbkpt.py    -- name the break symbol + file
  3. ../qemu_snapshot/gdb_server.sh             -- start QEMU (one tab)
  4. target_vm/scp.sh <your binary>             -- copy the target into the guest
  5. ../qemu_snapshot/gdb_client.sh             -- attach GDB (another tab)
  6. (gdb) cpu                                  -- dump the CPU state

Before any of it, IN THE GUEST:

    sysctl -w kernel.randomize_va_space=0

and carry state/symbol-store.json over from a Windows run -- wtf cannot produce
it on a Linux host.
"""


def _ingest_hint(plan: dict[str, Any], args: Any) -> str:
    """The ingest command, pre-filled with what acquisition already knows.

    ``module_base`` comes from the ``target_base`` we passed to FuzzBkpt, and
    ``randomize_va_space`` from the guest -- the two values a reader would
    otherwise have to hunt for. ``ghidra_image_base`` and ``entry_runtime_addr``
    are deliberately left as placeholders: the first is a property of the Ghidra
    project and the second of the chosen entry, and guessing either would put a
    wrong number into A1, where every address conversion is built on it.
    """
    return (
        f"  python -m prep.snapshot_linux ingest \\\n"
        f"      --state {plan['state_dir']} \\\n"
        f"      --module {Path(args.binary).stem} \\\n"
        f"      --module-base {plan['module_base']:#x} \\\n"
        f"      --ghidra-image-base <from the Ghidra project> \\\n"
        f"      --entry-runtime-addr <module_base + entry RVA> \\\n"
        f"      --randomize-va-space 0"
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Linux snapshot ingest (EXPERIMENTAL)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("notes", help="print the procedure")

    chk = sub.add_parser("check-aslr", help="assert ASLR is off")
    chk.add_argument(
        "--value",
        type=int,
        help="randomize_va_space read IN THE GUEST; omit to read locally",
    )

    acq = sub.add_parser(
        "prepare",
        help="do the mechanical snapshot steps and print the interactive ones",
    )
    acq.add_argument("--target-name", required=True, help="targets/<name>/state")
    acq.add_argument("--binary", required=True, type=Path, help="the ELF to snapshot")
    acq.add_argument("--break-at", required=True, help="symbol name, or 0xADDR")
    acq.add_argument(
        "--work-name",
        default=None,
        help="subdirectory under linux_mode/ for bkpt.py; defaults to --target-name",
    )
    acq.add_argument(
        "--bp-hits",
        type=int,
        default=1,
        help="snapshot on the Nth hit, for a parser reached during startup first",
    )
    acq.add_argument(
        "--no-checkname",
        action="store_true",
        help="do not verify the breaking process is the target (FuzzBkpt checkname)",
    )
    acq.add_argument(
        "--target-base",
        type=lambda s: int(s, 0),
        default=DEFAULT_TARGET_BASE,
        help="load base given to FuzzBkpt; this becomes A1's module_base",
    )
    acq.add_argument(
        "--stimulus",
        default=None,
        help="command run INSIDE the guest over ssh to reach the breakpoint",
    )
    acq.add_argument("--timeout", type=int, default=900)
    acq.add_argument(
        "--dry-run",
        action="store_true",
        help="print the plan without writing bkpt.py or touching the work directory",
    )

    ver = sub.add_parser(
        "verify", help="did the snapshot actually land? checks the three artifacts"
    )
    ver.add_argument("--target-name", required=True)

    check = sub.add_parser(
        "check-host", help="report what is missing for acquisition on this host"
    )
    check.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])

    ing = sub.add_parser("ingest", help="state/ dir -> A1")
    ing.add_argument("--state", required=True, type=Path)
    ing.add_argument("--module", required=True)
    ing.add_argument("--module-base", required=True, type=lambda s: int(s, 0))
    ing.add_argument("--ghidra-image-base", required=True, type=lambda s: int(s, 0))
    ing.add_argument("--entry-runtime-addr", required=True, type=lambda s: int(s, 0))
    ing.add_argument("--randomize-va-space", required=True, type=int)
    ing.add_argument("--out", type=Path, default=Path("artifacts/a1_snapshot.json"))

    args = ap.parse_args(argv)

    if args.cmd == "notes":
        print(PROCEDURE_NOTES)
        return 0

    if args.cmd == "check-host":
        problems = check_linux_prerequisites(args.repo_root)
        if not problems:
            print("host can acquire: linux_mode prerequisites are all present")
            return 0
        print("acquisition is not possible on this host:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    if args.cmd == "verify":
        repo_root = Path(__file__).resolve().parents[1]
        state_dir = repo_root / "targets" / args.target_name / "state"
        missing = [
            name
            for name in (MEM_DMP, REGS_JSON, SYMBOL_STORE_JSON)
            if not (state_dir / name).exists()
        ]
        if missing:
            print(f"{state_dir} is missing {missing}")
            print("the snapshot did not complete -- was the `cpu` step performed?")
            return 1
        print(f"{state_dir} holds all three artifacts")
        return 0

    if args.cmd == "prepare":
        repo_root = Path(__file__).resolve().parents[1]
        if args.dry_run:
            plan = build_plan(
                repo_root=repo_root,
                target_name=args.target_name,
                binary=args.binary,
                break_at=args.break_at,
                work_name=args.work_name,
                checkname=not args.no_checkname,
                bp_hits=args.bp_hits,
                target_base=args.target_base,
                stimulus=args.stimulus,
            )
            print(f"# would write {plan['bkpt_path']}")
            print(plan["bkpt_source"])
            print(f"# would copy the ELF to {plan['host_copy']} (nm/readelf read it there)")
        else:
            try:
                plan = prepare(
                    repo_root=repo_root,
                    target_name=args.target_name,
                    binary=args.binary,
                    break_at=args.break_at,
                    work_name=args.work_name,
                    checkname=not args.no_checkname,
                    bp_hits=args.bp_hits,
                    target_base=args.target_base,
                    stimulus=args.stimulus,
                )
            except (LinuxAcquireError, ValueError) as exc:
                print(f"prepare failed: {exc}")
                return 1
            print(f"wrote {plan['bkpt_path']}")
            print(f"copied the ELF to {plan['host_copy']}")

        print(f"# guest path : {plan['guest_path']}")
        print(f"# comm       : {plan['comm']} (kernel truncates to {COMM_MAX} chars)")
        print(f"# module_base: {plan['module_base']:#x}")
        print()
        for line in remaining_steps(plan):
            print(line)
        print()
        print("# when all three artifacts exist:")
        print(f"#   python -m prep.snapshot_linux verify --target-name {args.target_name}")
        print(_ingest_hint(plan, args))

        if args.dry_run:
            problems = check_linux_prerequisites(repo_root)
            if problems:
                print("\n# this host cannot run it:")
                for problem in problems:
                    print(f"#   - {problem}")
        return 0

    if args.cmd == "check-aslr":
        value = args.value if args.value is not None else read_randomize_va_space()
        assert_aslr_disabled(value)
        print(f"randomize_va_space = {value} (disabled) -- ok")
        return 0

    ref = ingest_state_dir(
        args.state,
        args.module,
        module_base=args.module_base,
        ghidra_image_base=args.ghidra_image_base,
        entry_runtime_addr=args.entry_runtime_addr,
        randomize_va_space=args.randomize_va_space,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(ref.model_dump_json(indent=2), encoding="utf-8")
    print(f"A1 (linux, EXPERIMENTAL): {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
