"""Reproducible build of wtf + our fuzzer module (CLAUDE.md CP4).

Our module's tracked home is ``fuzzer/module/``. It is **copied** into
``src/wtf/`` before building because:

* ``src/CMakeLists.txt:19-23`` globs ``wtf/*.cc``, so a module is only compiled
  into ``wtf.exe`` if it sits there (DECISIONS DEC-002);
* ``.gitignore:35`` ignores ``src/wtf/fuzzer_*``, so a module living there
  permanently would be silently untracked (D-012). The copy is a build
  artifact, and being ignored is correct for it.

Two host quirks are handled here rather than left for the caller:

* the machine ``PATH`` on this host contains an entry with a stray double quote
  which makes ``vcvars64.bat`` abort (D-020);
* the CMake component installed into a *second* Visual Studio instance, so the
  toolchain is discovered rather than assumed.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_DIR = REPO_ROOT / "fuzzer" / "module"
WTF_SRC = REPO_ROOT / "src" / "wtf"
BUILD_DIR = REPO_ROOT / "src" / "build"
WTF_EXE = BUILD_DIR / "wtf.exe"

VSWHERE = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / (
    "Microsoft Visual Studio/Installer/vswhere.exe"
)


class BuildError(RuntimeError):
    """A failed build, carrying the compiler output.

    `output` exists because the diagnostics are the only useful product of a failed
    build, and they used to be printed to stderr and dropped. fuzzer/codegen_llm.py feeds
    them back to the model that wrote the offending file, which is a better prompt than
    any prose about the same rule -- it names the line, the types and the operation.
    """

    def __init__(self, message: str, output: str = "") -> None:
        super().__init__(message)
        self.output = output


def sanitised_env() -> dict[str, str]:
    """Strip stray quotes from PATH entries -- D-020.

    One unbalanced quote makes batch treat the rest of PATH as a quoted string,
    and vcvars64.bat dies with `\\VMware\\VMware was unexpected at this time.`
    """
    env = dict(os.environ)
    parts = (p.strip().strip('"') for p in env.get("PATH", "").split(os.pathsep))
    env["PATH"] = os.pathsep.join(p for p in parts if p)
    return env


def find_vcvars() -> Path:
    """Locate a vcvars64.bat belonging to an install that also has CMake.

    Both matter: this host has two VS instances and only one carries the
    "C++ CMake tools for Windows" component.
    """
    candidates: list[Path] = []

    if VSWHERE.exists():
        proc = subprocess.run(
            [
                str(VSWHERE), "-all", "-products", "*",
                "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                "-property", "installationPath",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        candidates += [Path(p) for p in proc.stdout.split("\n") if p.strip()]

    for root in candidates:
        vcvars = root / "VC" / "Auxiliary" / "Build" / "vcvars64.bat"
        cmake = (
            root / "Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe"
        )
        if vcvars.exists() and cmake.exists():
            return vcvars

    # Fall back to any install with vcvars, in case cmake is on PATH already.
    for root in candidates:
        vcvars = root / "VC" / "Auxiliary" / "Build" / "vcvars64.bat"
        if vcvars.exists():
            return vcvars

    raise BuildError(
        "No Visual Studio install with vcvars64.bat found. See "
        "docs/ENVIRONMENT.md -- the C++ CMake tools component is required."
    )


def stage_modules() -> list[Path]:
    """Copy fuzzer/module/*.cc and *.h into src/wtf/ so CMake's glob picks them up.

    HEADERS TOO, which was not obvious until a module included one. CMake globs `*.cc`,
    so only sources need to arrive for the module to be COMPILED -- but the compiler
    resolves `#include "snapfuzz_resolve.h"` relative to the staged .cc, which lives in
    `src/wtf/`, not next to its original. Staging only sources gives C1083 naming a
    header that plainly exists, two directories away.
    """
    sources = sorted(MODULE_DIR.glob("*.cc")) + sorted(MODULE_DIR.glob("*.h"))
    if not any(p.suffix == ".cc" for p in sources):
        raise BuildError(f"no .cc files in {MODULE_DIR}")

    staged = []
    for src in sources:
        dst = WTF_SRC / src.name
        # Only rewrite when the content differs, so ninja does not rebuild the
        # world on every invocation.
        if not dst.exists() or dst.read_bytes() != src.read_bytes():
            shutil.copy2(src, dst)
        staged.append(dst)
    return staged


def build(*, clean: bool = False, verbose: bool = False) -> Path:
    staged = stage_modules()
    for path in staged:
        print(f"staged {path.relative_to(REPO_ROOT)}")

    vcvars = find_vcvars()
    BUILD_DIR.mkdir(parents=True, exist_ok=True)

    if clean:
        for junk in ("CMakeCache.txt", "build.ninja"):
            (BUILD_DIR / junk).unlink(missing_ok=True)

    script = "\r\n".join(
        [
            "@echo off",
            f'call "{vcvars}" >nul',
            "if errorlevel 1 (echo VCVARS FAILED & exit /b 1)",
            f'cd /d "{BUILD_DIR}"',
            "cmake .. -GNinja -DCMAKE_BUILD_TYPE=RelWithDebInfo",
            "if errorlevel 1 (echo CONFIGURE FAILED & exit /b 1)",
            "cmake --build .",
            "if errorlevel 1 (echo BUILD FAILED & exit /b 1)",
            "",
        ]
    )

    bat = BUILD_DIR / "_snapfuzz_build.bat"
    bat.write_text(script, encoding="utf-8")
    try:
        proc = subprocess.run(
            ["cmd", "/c", str(bat)],
            env=sanitised_env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=3600,
        )
    finally:
        bat.unlink(missing_ok=True)

    out = proc.stdout + proc.stderr
    if verbose or proc.returncode != 0:
        print(out[-8000:], file=sys.stderr)

    if proc.returncode != 0:
        raise BuildError(f"build failed ({proc.returncode})", out)
    if not WTF_EXE.exists():
        raise BuildError(f"build reported success but {WTF_EXE} is missing", out)

    return WTF_EXE


def registered_targets(target_dir: Path | None = None) -> list[str]:
    """Ask the built binary which modules it has.

    Asking an unknown target name makes wtf print its registry
    (``Targets_t::DisplayRegisteredTargets``, ``src/wtf/targets.cc:31-36``)::

        Existing targets:
          - Name: snapfuzz

    Must run from a directory with a valid target tree: wtf validates
    ``state/`` and ``inputs/``/``outputs/``/``crashes/`` *before* it looks the
    name up, so from anywhere else it errors on directories and never lists.

    This guards a genuinely silent failure -- a stale ``wtf.exe`` runs the OLD
    module and looks completely healthy.
    """
    target_dir = target_dir or (REPO_ROOT / "targets" / "tlv_server")
    if not (target_dir / "state").is_dir():
        raise BuildError(
            f"{target_dir} is not a wtf target tree, so the registry cannot be "
            f"listed. Pass --target-dir at a directory with state/, inputs/, "
            f"outputs/ and crashes/."
        )

    proc = subprocess.run(
        [str(WTF_EXE), "fuzz", "--name", "__does_not_exist__", "--backend=bochscpu"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=sanitised_env(),
        cwd=target_dir,
        timeout=120,
    )

    names: list[str] = []
    for line in (proc.stdout + proc.stderr).splitlines():
        stripped = line.strip()
        if stripped.startswith("- Name:"):
            names.append(stripped.removeprefix("- Name:").strip())
    return names


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--clean", action="store_true", help="force a reconfigure")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument(
        "--expect-target",
        default="snapfuzz",
        help="fail unless this module registered in the built binary",
    )
    ap.add_argument(
        "--target-dir",
        type=Path,
        help="a wtf target tree, needed to list the registry (default tlv_server)",
    )
    args = ap.parse_args(argv)

    exe = build(clean=args.clean, verbose=args.verbose)
    size_mb = exe.stat().st_size / (1024 * 1024)
    print(f"built {exe.relative_to(REPO_ROOT)} ({size_mb:.1f} MB)")

    if args.expect_target:
        targets = registered_targets(args.target_dir)
        print(f"registered targets: {', '.join(targets) or '(could not parse)'}")
        if args.expect_target not in targets:
            print(
                f"ERROR: {args.expect_target!r} did not register. The module "
                f"either failed to compile in, or wtf.exe is stale.",
                file=sys.stderr,
            )
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
