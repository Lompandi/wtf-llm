"""Drive Ghidra's analyzeHeadless to enumerate basic blocks (CLAUDE.md CP2).

Produces the raw export that :mod:`prep.bb_to_wtf` turns into A3.

Two host details this has to handle, both learned the hard way and recorded in
docs/DEVIATIONS.md:

* **D-025** -- the post-script is Java, not Python. Ghidra 12 ships Jython only
  as an optional extension and routes ``.py`` scripts to PyGhidra, which
  ``analyzeHeadless`` cannot start.
* **D-020** -- ``analyzeHeadless.bat`` is a batch file, and this host's machine
  ``PATH`` contains an entry with a stray double quote that makes batch parsing
  abort. The environment is sanitised before launching.

Usage::

    python -m prep.ghidra_headless \
        --binary targets/tlv_server/target/tlv_server.exe \
        --scope function-closure --entry ProcessPacket \
        --out artifacts/a3_ghidra_blocks.json
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
POST_SCRIPT = "ExportBasicBlocks.java"
DATA_SCRIPT = "ExportDataSymbols.java"
SCRIPT_DIR = REPO_ROOT / "prep" / "ghidra_scripts"

SCOPE_MODULE = "module"
SCOPE_CLOSURE = "function-closure"
SCOPES = (SCOPE_CLOSURE, SCOPE_MODULE)


class GhidraError(RuntimeError):
    pass


@dataclass(frozen=True)
class GhidraExport:
    """The post-script's output, one entry per basic block."""

    module: str
    program: str
    image_base: int
    scope: str
    entry: str | None
    blocks: list[dict]
    skipped_out_of_scope: int
    skipped_below_image_base: int

    @classmethod
    def from_json(cls, path: Path) -> GhidraExport:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            module=raw["module"],
            program=raw["program"],
            image_base=raw["image_base"],
            scope=raw["scope"],
            entry=raw.get("entry"),
            blocks=raw["blocks"],
            skipped_out_of_scope=raw.get("skipped_out_of_scope", 0),
            skipped_below_image_base=raw.get("skipped_below_image_base", 0),
        )


def find_ghidra(explicit: str | None = None) -> Path:
    """Locate a Ghidra install, preferring an explicit path then the env var.

    ``GHIDRA_INSTALL_DIR`` is Ghidra's own convention, so honour it rather than
    inventing a snapfuzz-specific variable.
    """
    candidates = [explicit, os.environ.get("GHIDRA_INSTALL_DIR")]
    for candidate in candidates:
        if not candidate:
            continue
        root = Path(candidate)
        if (root / "support" / "analyzeHeadless.bat").exists() or (
            root / "support" / "analyzeHeadless"
        ).exists():
            return root
        raise GhidraError(f"no analyzeHeadless under {root}")

    raise GhidraError(
        "Ghidra not found. Pass --ghidra or set GHIDRA_INSTALL_DIR. "
        "See docs/ENVIRONMENT.md."
    )


def _analyze_headless(ghidra_root: Path) -> Path:
    name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    return ghidra_root / "support" / name


def _sanitised_env() -> dict[str, str]:
    """Strip stray quotes from PATH entries -- see DEVIATIONS D-020.

    A single unbalanced quote anywhere in PATH makes batch treat the remainder
    as one quoted string, and analyzeHeadless.bat dies parsing it.
    """
    env = dict(os.environ)
    path = env.get("PATH", "")
    cleaned = [p.strip().strip('"') for p in path.split(os.pathsep)]
    env["PATH"] = os.pathsep.join(p for p in cleaned if p)
    return env


def _run_post_script(
    post_script: str,
    binary: Path,
    out_json: Path,
    *,
    script_args: list[str],
    ghidra_root: Path | None = None,
    project_dir: Path | None = None,
    project_name: str = "snapfuzz",
    timeout_s: int = 3600,
) -> None:
    """Import ``binary``, analyse it, and run one post-script over it.

    Shared by every export so the two host workarounds (D-020's PATH sanitising
    and D-025's Java scripts) exist once. ``script_args`` follow the output path,
    which is always the post-script's first argument.
    """
    ghidra_root = ghidra_root or find_ghidra()
    headless = _analyze_headless(ghidra_root)
    out_json.parent.mkdir(parents=True, exist_ok=True)

    # A throwaway project unless the caller wants one kept: re-importing into an
    # existing project errors out, and these exports are meant to be re-runnable.
    with tempfile.TemporaryDirectory(prefix="snapfuzz-ghidra-") as tmp:
        proj_dir = project_dir or Path(tmp)
        proj_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            str(headless),
            str(proj_dir),
            project_name,
            "-import",
            str(binary),
            "-scriptPath",
            str(SCRIPT_DIR),
            "-postScript",
            post_script,
            str(out_json),
            *script_args,
            "-deleteProject",
        ]

        proc = subprocess.run(
            cmd,
            env=_sanitised_env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
        )

    combined = proc.stdout + proc.stderr
    for line in combined.splitlines():
        if "[snapfuzz]" in line or "ERROR" in line:
            print(line.strip(), file=sys.stderr)

    if proc.returncode != 0:
        raise GhidraError(f"analyzeHeadless exited {proc.returncode}")

    # analyzeHeadless exits 0 even when the post-script throws, so the artifact
    # is the only trustworthy success signal.
    if not out_json.exists():
        raise GhidraError(
            f"analyzeHeadless produced no output at {out_json}. "
            f"analyzeHeadless returns 0 even when a script fails, so check the "
            f"log above for a SCRIPT ERROR."
        )


def export_data_symbols(
    binary: Path,
    out_json: Path,
    *,
    scope: str = SCOPE_MODULE,
    entry: str | None = None,
    ghidra_root: Path | None = None,
    project_dir: Path | None = None,
    project_name: str = "snapfuzz",
    timeout_s: int = 3600,
) -> dict:
    """Export global data symbols with sizes and inter-symbol spans (CP7).

    The fact this recovers is the one decompilation loses: a loop bounded by
    ``&some_adjacent_symbol`` says nothing about how many elements the table
    holds, but the addresses do. Measured on tlv_server: ``ChunkList`` is 32
    bytes at 0x140006a18, i.e. **four** pointer slots, and the next symbol sits
    0x20 later. Seed generation had reasoned correctly that the branch needed
    that table exhausted, but with no capacity to work from it guessed low
    (D-047).
    """
    if scope not in SCOPES:
        raise ValueError(f"scope must be one of {SCOPES}, got {scope!r}")
    if scope == SCOPE_CLOSURE and not entry:
        raise ValueError("function-closure scope needs an entry")
    if not binary.exists():
        raise FileNotFoundError(binary)

    _run_post_script(
        DATA_SCRIPT,
        binary,
        out_json,
        script_args=[scope] + ([entry] if entry else []),
        ghidra_root=ghidra_root,
        project_dir=project_dir,
        project_name=project_name,
        timeout_s=timeout_s,
    )

    payload = json.loads(out_json.read_text(encoding="utf-8"))
    if not payload.get("symbols"):
        raise GhidraError(
            f"exported 0 data symbols (scope={scope}, entry={entry!r}). An empty "
            f"table silently removes the only static fact about global bounds "
            f"from the prompt, so this is an error rather than a warning."
        )
    return payload


def export_basic_blocks(
    binary: Path,
    out_json: Path,
    *,
    scope: str = SCOPE_CLOSURE,
    entry: str | None = None,
    ghidra_root: Path | None = None,
    project_dir: Path | None = None,
    project_name: str = "snapfuzz",
    timeout_s: int = 3600,
) -> GhidraExport:
    """Import ``binary`` into Ghidra, analyse it, and export basic blocks."""
    if scope not in SCOPES:
        raise ValueError(f"scope must be one of {SCOPES}, got {scope!r}")
    if scope == SCOPE_CLOSURE and not entry:
        raise ValueError(
            "function-closure scope needs --entry; use --scope=module to "
            "enumerate the whole binary"
        )
    if not binary.exists():
        raise FileNotFoundError(binary)

    _run_post_script(
        POST_SCRIPT,
        binary,
        out_json,
        script_args=[scope] + ([entry] if entry else []),
        ghidra_root=ghidra_root,
        project_dir=project_dir,
        project_name=project_name,
        timeout_s=timeout_s,
    )

    export = GhidraExport.from_json(out_json)
    if not export.blocks:
        raise GhidraError(
            f"exported 0 basic blocks (scope={scope}, entry={entry!r}). "
            f"An empty coverage file makes wtf run with no coverage at all "
            f"rather than failing, so this is treated as an error here."
        )
    return export


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--binary", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--scope", choices=SCOPES, default=SCOPE_CLOSURE)
    ap.add_argument(
        "--entry",
        help="symbol name or 0x-prefixed address; required for function-closure",
    )
    ap.add_argument("--ghidra", help="Ghidra install dir (else GHIDRA_INSTALL_DIR)")
    ap.add_argument("--project-name", default="snapfuzz")
    ap.add_argument(
        "--what",
        choices=("blocks", "data-symbols"),
        default="blocks",
        help="blocks -> A3 basic blocks; data-symbols -> global bounds (CP7)",
    )
    args = ap.parse_args(argv)

    if args.what == "data-symbols":
        payload = export_data_symbols(
            args.binary,
            args.out,
            scope=args.scope,
            entry=args.entry,
            ghidra_root=find_ghidra(args.ghidra),
            project_name=args.project_name,
        )
        sized = [s for s in payload["symbols"] if s["span_to_next"]]
        print(
            f"{payload['module']}: {len(payload['symbols'])} data symbols "
            f"({len(sized)} with a measurable span), scope={payload['scope']}"
        )
        return 0

    export = export_basic_blocks(
        args.binary,
        args.out,
        scope=args.scope,
        entry=args.entry,
        ghidra_root=find_ghidra(args.ghidra),
        project_name=args.project_name,
    )
    print(
        f"{export.module}: {len(export.blocks)} blocks "
        f"(scope={export.scope}, image_base={export.image_base:#x})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
