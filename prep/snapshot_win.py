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

    kd = sub.add_parser("kd-script", help="emit the KD commands to take one")
    kd.add_argument("--state", required=True, type=Path)
    kd.add_argument("--snapshot-dll", required=True, type=Path)
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

    print(GUEST_PREP_NOTES)
    print("KD commands:\n")
    for line in build_kd_commands(
        args.state,
        snapshot_dll=args.snapshot_dll,
        break_at=args.break_at,
        kind=args.kind,
        wow64=args.wow64,
    ):
        print(f"  kd> {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
