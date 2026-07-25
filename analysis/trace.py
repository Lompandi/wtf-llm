"""Execution traces: generation and symbolization (CLAUDE.md CP4, CP8).

Two uses, and section 13.3 is explicit that both are required:

1. **Harness validation (CP4, mandatory).** The execution backends are a black
   box. A harness that runs and reports coverage but never reaches the parser is
   the classic silent failure here, and the only way to rule it out is to look
   at a trace. :func:`validate_harness` does exactly that.
2. **Triage signal 4 (CP8).** A *dynamic* signal, independent of the static
   pseudo-C of signal 5, and per section 13.3 the main compensation for having
   no ASAN: it lets the analysis walk backwards from a fault to where a bad
   pointer or length came from.

``symbolizer-rs`` is a **companion tool, not wtf** (section 3.1). Raw traces load
into neither lighthouse nor Tenet.

**NO LLM ANYWHERE IN THIS MODULE.** CP8's gate asserts that for this whole path.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from arch.contracts import TraceRef

REPO_ROOT = Path(__file__).resolve().parents[1]

__all__ = [
    "TraceError",
    "find_symbolizer",
    "generate_trace",
    "symbolize",
    "validate_harness",
]

# `tenet` traces are bochscpu-only: exiting VMX is too expensive elsewhere
# (section 13.3).
BOCHSCPU_ONLY_TRACE_TYPES = frozenset({"tenet"})


class TraceError(RuntimeError):
    pass


def find_symbolizer(explicit: str | Path | None = None) -> Path:
    """Locate symbolizer-rs: explicit arg, then ``SYMBOLIZER_RS``, then PATH.

    Not read from config/fuzz.yaml by default -- an absolute path to a tool
    outside the repo is machine-specific and does not belong in a committed
    file. See docs/ENVIRONMENT.md.
    """
    for candidate in (explicit, os.environ.get("SYMBOLIZER_RS")):
        if candidate:
            path = Path(candidate)
            if path.is_dir():
                path = path / "symbolizer-rs.exe"
            if path.exists():
                return path
            raise TraceError(f"symbolizer-rs not found at {candidate}")

    found = shutil.which("symbolizer-rs") or shutil.which("symbolizer-rs.exe")
    if found:
        return Path(found)

    raise TraceError(
        "symbolizer-rs not found. Set SYMBOLIZER_RS or put it on PATH. "
        "Without it, CP4's harness validation cannot be performed and CP8 has "
        "no signal 4. See docs/ENVIRONMENT.md."
    )


def _sanitised_env(symbol_paths: list[str] | None = None) -> dict[str, str]:
    env = dict(os.environ)
    parts = (p.strip().strip('"') for p in env.get("PATH", "").split(os.pathsep))
    env["PATH"] = os.pathsep.join(p for p in parts if p)
    if symbol_paths:
        env["_NT_SYMBOL_PATH"] = ";".join(symbol_paths)
    return env


@dataclass(frozen=True)
class TraceTarget:
    """Where a trace comes from, and what it needs to be readable."""

    wtf_exe: Path
    target_dir: Path
    name: str
    state_dir: Path
    binary_dir: Path | None = None  # holds the target's own PDB
    symbol_paths: list[str] | None = None


def generate_trace(
    target: TraceTarget,
    input_path: Path,
    trace_dir: Path,
    *,
    trace_type: str = "rip",
    backend: str = "bochscpu",
    limit: int = 10_000_000,
    timeout_s: int = 1800,
) -> Path:
    """``wtf run --trace-type=<t>`` for one input. Returns the trace file."""
    if trace_type in BOCHSCPU_ONLY_TRACE_TYPES and backend != "bochscpu":
        raise TraceError(
            f"--trace-type={trace_type} is bochscpu-only (section 13.3), got "
            f"{backend!r}"
        )

    trace_dir.mkdir(parents=True, exist_ok=True)

    # wtf REFUSES to overwrite an existing trace -- it prints "Skipping <path>
    # as it already exists" and exits 0. A stale trace is genuinely dangerous
    # here: validating a harness against a trace produced by a DIFFERENT module
    # is a silent false pass, which is exactly the failure CP4's validation
    # exists to catch. So clear any trace for this input first.
    stale = sorted(trace_dir.glob(f"{input_path.name}*"))
    for path in stale:
        path.unlink()

    before = {p.name for p in trace_dir.iterdir() if p.is_file()}

    proc = subprocess.run(
        [
            str(target.wtf_exe), "run",
            "--name", target.name,
            "--state", str(target.state_dir.resolve()),
            f"--backend={backend}",
            "--input", str(input_path.resolve()),
            "--limit", str(limit),
            f"--trace-type={trace_type}",
            f"--trace-path={trace_dir.resolve()}",
        ],
        cwd=target.target_dir,
        env=_sanitised_env(target.symbol_paths),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_s,
    )
    if proc.returncode != 0:
        raise TraceError(
            f"wtf run failed ({proc.returncode}):\n{proc.stdout[-2000:]}\n"
            f"{proc.stderr[-2000:]}"
        )

    after = {p.name for p in trace_dir.iterdir() if p.is_file()}
    fresh = sorted(after - before)
    if not fresh:
        # wtf can exit 0 having produced nothing useful, so the artifact is the
        # only trustworthy signal -- same lesson as D-026.
        hint = ""
        if "as it already exists" in proc.stdout:
            hint = (
                "\nwtf skipped writing because a trace for this input already "
                "existed. That should have been cleared above -- check for a "
                "trace whose name does not start with the input filename."
            )
        raise TraceError(
            f"wtf run exited 0 but wrote no trace into {trace_dir}. "
            f"Output:\n{proc.stdout[-2000:]}{hint}"
        )
    return trace_dir / fresh[0]


def symbolize(
    trace_path: Path,
    output_path: Path,
    *,
    crash_dump: Path,
    symbolizer: Path | None = None,
    import_pdbs: Path | None = None,
    symbol_paths: list[str] | None = None,
    symcache: Path | None = None,
    style: str = "full",
    timeout_s: int = 1800,
) -> Path:
    """Symbolize a trace with symbolizer-rs.

    ``style`` defaults to ``full`` (``mod!func+offset``), which is what harness
    validation needs -- you have to see the function NAME to confirm the parser
    was reached. Section 13.3's ``--style modoff`` is for the coverage ->
    lighthouse path, where lighthouse wants module+offset.

    A symbol cache is **mandatory**: symbolizer-rs fails with ``Error: no
    sympath`` unless it gets ``--symcache`` or can parse ``_NT_SYMBOL_PATH``. So
    ``symbol_paths`` is forwarded into the child environment rather than relying
    on whatever the calling shell happens to have set.
    """
    if style not in {"full", "modoff"}:
        raise ValueError(f"style must be 'full' or 'modoff', got {style!r}")

    exe = symbolizer or find_symbolizer()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(exe),
        "--trace", str(trace_path.resolve()),
        "--output", str(output_path.resolve()),
        "--crash-dump", str(crash_dump.resolve()),
        "--style", style,
        "--overwrite",
    ]
    if import_pdbs is not None:
        cmd += ["--import-pdbs", str(import_pdbs.resolve())]
    if symcache is not None:
        cmd += ["--symcache", str(symcache.resolve())]

    env = _sanitised_env(symbol_paths)
    if symcache is None and not env.get("_NT_SYMBOL_PATH"):
        raise TraceError(
            "symbolizer-rs needs a symbol cache: pass symcache= or symbol_paths=, "
            "or set _NT_SYMBOL_PATH. Otherwise it exits with 'Error: no sympath'."
        )

    proc = subprocess.run(
        cmd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_s,
    )
    if proc.returncode != 0:
        raise TraceError(
            f"symbolizer-rs failed ({proc.returncode}):\n{proc.stdout[-2000:]}\n"
            f"{proc.stderr[-2000:]}"
        )
    if not output_path.exists():
        raise TraceError(f"symbolizer-rs reported success but {output_path} is absent")
    return output_path


_SYMBOL_LINE_RE = re.compile(r"^(?P<module>[^!+\s]+)(?:!(?P<symbol>[^+\s]+))?")


def first_hit(symbolized: Path, symbol: str) -> int | None:
    """1-based line number of the first occurrence of ``symbol``, or None."""
    with symbolized.open("r", encoding="utf-8", errors="replace") as fd:
        for lineno, line in enumerate(fd, start=1):
            if symbol in line:
                return lineno
    return None


def module_histogram(symbolized: Path, limit: int = 10) -> list[tuple[str, int]]:
    """Which modules the trace spent its instructions in.

    Useful context for triage: a fault deep in ntdll's allocator reads very
    differently from one inside the parser itself.
    """
    counts: dict[str, int] = {}
    with symbolized.open("r", encoding="utf-8", errors="replace") as fd:
        for line in fd:
            m = _SYMBOL_LINE_RE.match(line.strip())
            if m:
                counts[m.group("module")] = counts.get(m.group("module"), 0) + 1
    return sorted(counts.items(), key=lambda kv: -kv[1])[:limit]


def validate_harness(
    target: TraceTarget,
    input_path: Path,
    entry_symbol: str,
    *,
    trace_dir: Path,
    symbolized_path: Path,
    symbolizer: Path | None = None,
    bucket_id: str = "harness-validation",
) -> TraceRef:
    """CP4's mandatory check: prove execution reaches the chosen fuzz entry.

    Returns a :class:`TraceRef` whose ``reached_fuzz_entry`` is the answer.
    Deliberately returns rather than asserts, so a caller can report the
    module histogram of a failing trace instead of just a bare failure.
    """
    raw = generate_trace(target, input_path, trace_dir, trace_type="rip")
    symbolized = symbolize(
        raw,
        symbolized_path,
        crash_dump=target.state_dir / "mem.dmp",
        symbolizer=symbolizer,
        import_pdbs=target.binary_dir,
        symbol_paths=target.symbol_paths,
        style="full",
    )
    return TraceRef(
        bucket_id=bucket_id,
        trace_type="rip",
        raw_path=str(raw),
        symbolized_path=str(symbolized),
        reached_fuzz_entry=first_hit(symbolized, entry_symbol) is not None,
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Harness validation via a rip trace")
    ap.add_argument("--wtf", type=Path, default=REPO_ROOT / "src/build/wtf.exe")
    ap.add_argument("--target-dir", type=Path, required=True)
    ap.add_argument("--name", required=True, help="wtf --name (the module)")
    ap.add_argument("--input", type=Path, required=True)
    ap.add_argument("--entry-symbol", required=True, help="e.g. ProcessPacket")
    ap.add_argument("--binary-dir", type=Path, help="directory holding the PDB")
    ap.add_argument("--symbolizer", type=Path)
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "artifacts")
    args = ap.parse_args(argv)

    state = args.target_dir / "state"
    symbol_paths = ["srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"]
    if args.binary_dir:
        symbol_paths.append(str(args.binary_dir.resolve()))

    target = TraceTarget(
        wtf_exe=args.wtf,
        target_dir=args.target_dir,
        name=args.name,
        state_dir=state,
        binary_dir=args.binary_dir,
        symbol_paths=symbol_paths,
    )

    ref = validate_harness(
        target,
        args.input,
        args.entry_symbol,
        # Per-module trace directory: two modules validated against the same
        # snapshot would otherwise write the same filename.
        trace_dir=args.out / "traces" / args.name,
        symbolized_path=args.out / "traces-symbolized" / f"{args.name}.rip.txt",
        symbolizer=args.symbolizer,
    )

    sym = Path(ref.symbolized_path)
    line = first_hit(sym, args.entry_symbol)
    print(f"trace       : {ref.raw_path}")
    print(f"symbolized  : {ref.symbolized_path}")
    print(f"entry symbol: {args.entry_symbol}")
    print(f"first hit   : line {line}" if line else "first hit   : NOT FOUND")
    print("modules     :")
    for module, count in module_histogram(sym):
        print(f"  {count:>7}  {module}")

    if not ref.reached_fuzz_entry:
        print(
            "\nHARNESS VALIDATION FAILED: the trace never enters "
            f"{args.entry_symbol}. The harness runs and will report coverage, "
            "but it is not fuzzing the intended code."
        )
        return 1
    print("\nHARNESS VALIDATION PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
