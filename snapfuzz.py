"""snapfuzz -- fuzz an executable from a memory dump, a register state, and the exe.

    python -m snapfuzz mytarget.exe path/to/state

That is the whole interface. `path/to/state` is a directory holding `mem.dmp` and
`regs.json`; `mytarget.exe` is the binary the dump is of. Nothing else is required and
nothing has to be edited -- no config file, no module name, no entry symbol, no
`symbol-store.json`, no seed corpus.

Everything else is read out of what you supplied:

* **where the module is mapped** -- from the dump's own page tables, by finding the
  mapped images and identifying yours by its PE header. This also catches the case
  where the dump is of a different program, which nothing else can;
* **the fuzz entry** -- from `rip`. The snapshot stopped somewhere; that is where
  fuzzing resumes. It is a fact to read, not a decision to make;
* **the image base** -- from the PE optional header;
* **the target's module name** -- the executable's filename;
* **the input structure and the harness** -- Ghidra's pseudo-C, read by the model, then
  rendered to C++ and compiled;
* **a first test-case** -- from the derived input structure, only if you did not supply
  one. Anything you put in `inputs/` is left alone, and a captured real input is worth
  more than a derived one.

This module exists because `orchestrator.pipeline` grew fourteen flags, and every one
of them was a decision the tool could make itself from the three files a person
actually has. It takes no options that change behaviour -- only how long to run --
because an option here would be a decision handed back (D-075).

Run `python -m orchestrator.pipeline --help` for the full driver when you need to
override something: a specific entry symbol, a hand-written harness, one stage on its
own.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

MEM_DMP = "mem.dmp"
REGS_JSON = "regs.json"


def _problems(binary: Path, state: Path) -> list[str]:
    """Everything wrong with the two arguments, checked before anything runs.

    All of them at once rather than the first: someone who pointed at the wrong
    directory usually has more than one thing to fix, and finding out one at a time is
    how a five-second mistake becomes five minutes.
    """
    found: list[str] = []
    if not binary.is_file():
        found.append(f"{binary} does not exist")
    elif binary.read_bytes()[:2] != b"MZ":
        found.append(
            f"{binary} is not a Windows executable (no MZ signature). For a Linux ELF "
            f"see the Linux section of the README -- its snapshots are taken a "
            f"different way"
        )
    if not state.is_dir():
        found.append(
            f"{state} is not a directory. It should be the snapshot directory holding "
            f"{MEM_DMP} and {REGS_JSON}"
        )
        return found
    for name in (MEM_DMP, REGS_JSON):
        if not (state / name).is_file():
            found.append(f"{state / name} is missing")
    return found


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(
        prog="python -m snapfuzz",
        description=__doc__.splitlines()[0],
        epilog=(
            "example:  python -m snapfuzz targets/tlv_server/target/tlv_server.exe "
            "targets/tlv_server/state"
        ),
    )
    ap.add_argument("binary", type=Path, help="the executable the dump is of")
    ap.add_argument(
        "state", type=Path, help=f"directory holding {MEM_DMP} and {REGS_JSON}"
    )
    ap.add_argument("--minutes", type=float, default=15.0, help="campaign length")
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument(
        "--name",
        default=None,
        help="output directory under targets/; defaults to the executable's name",
    )
    ap.add_argument(
        "--dry-run", action="store_true", help="print the plan and run nothing"
    )
    args = ap.parse_args(argv)

    binary = args.binary.resolve()
    state = args.state.resolve()
    problems = _problems(binary, state)
    if problems:
        print("cannot start:")
        for problem in problems:
            print(f"  ! {problem}")
        print()
        print("snapfuzz needs exactly three things:")
        print("  1. the memory dump          <state>/mem.dmp")
        print("  2. the register state       <state>/regs.json")
        print("  3. the executable itself    the first argument")
        return 1

    from orchestrator.pipeline import main as pipeline_main

    forwarded = [
        "--binary", str(binary),
        "--state-dir", str(state),
        "--target-name", args.name or binary.stem,
        "--workers", str(args.workers),
        "--minutes", str(args.minutes),
    ]
    if args.dry_run:
        forwarded.append("--dry-run")
    return pipeline_main(forwarded)


if __name__ == "__main__":
    sys.exit(main())
