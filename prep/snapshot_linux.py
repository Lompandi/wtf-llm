"""Linux snapshot acquisition -> A1. **EXPERIMENTAL** (CLAUDE.md CP3).

Windows is first (section 2). This path exists so the requirement is captured
and asserted, not because it is on the critical path. Nothing here has been run
against a real guest.

Two honest caveats, both recorded in docs/DEVIATIONS.md:

* **D-010** -- CLAUDE.md describes this as "GDB-based ELF snapshot" of a
  user-mode process. wtf's ``linux_mode/`` is GDB driving a **full-system QEMU
  VM with a kernel build** (``qemu_snapshot/gdb_server.sh`` +
  ``gdb_client.sh``), which is a substantially larger setup.
* CLAUDE.md states "ASLR must be disabled". A grep of ``linux_mode/`` for
  ``aslr`` / ``randomize_va_space`` finds **nothing**, so that requirement is
  not corroborated by the repo. It is asserted here anyway, because it is
  cheap and because the failure it prevents is silent: with ASLR on, the
  snapshot's ``module_base`` is one sample of a value that moves, and every
  static<->runtime conversion built on it is quietly wrong.

``symbol-store.json`` is **required** on Linux and cannot be produced there:
there is no dbgeng, so wtf reads the file instead of resolving symbols
(``debugger.h:30-60``), and ``wtf.cc:195-201`` refuses to start without it. It
has to be generated from Windows first.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from arch.contracts import SnapshotRef

__all__ = [
    "AslrEnabledError",
    "LinuxSnapshotError",
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
            f"{symbol_store} is missing and is REQUIRED on Linux: there is no "
            f"dbgeng, so wtf places coverage breakpoints from this file "
            f"(debugger.h:30-60) and refuses to start without it "
            f"(wtf.cc:195-201). Generate it from Windows first."
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


PROCEDURE_NOTES = """\
EXPERIMENTAL. wtf's Linux mode is GDB against a full-system QEMU VM, not a
user-mode process (docs/DEVIATIONS.md D-010). From linux_mode/README.md:

  1. linux_mode/qemu_snapshot/setup.sh          -- build the target VM + kernel
  2. ../qemu_snapshot/gdb_server.sh             -- start QEMU (one tab)
  3. ../qemu_snapshot/gdb_client.sh             -- attach GDB (another tab)
  4. a bkpt.py deriving from gdb_fuzzbkpt.py    -- set the break address
  5. (gdb) cpu                                  -- dump the CPU state

Before any of it, IN THE GUEST:

    sysctl -w kernel.randomize_va_space=0

and carry state/symbol-store.json over from a Windows run -- it cannot be
produced on Linux.
"""


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
