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
    "SymbolRef",
    "KERNEL_BASE",
    "find_symbolizer",
    "generate_trace",
    "symbolize",
    "symbolize_addresses",
    "fault_address_from_trace",
    "fault_index_from_trace",
    "frames_before_fault",
    "validate_harness",
]

# `tenet` traces are bochscpu-only: exiting VMX is too expensive elsewhere
# (section 13.3).
BOCHSCPU_ONLY_TRACE_TYPES = frozenset({"tenet"})

# x64 canonical-address split. Everything at or above this is kernel space on
# Windows x64; below it is user space. Used to find where a fault handed control
# to the kernel -- see :func:`fault_address_from_trace`.
KERNEL_BASE = 0xFFFF_8000_0000_0000


class TraceError(RuntimeError):
    pass


def _symbolizer_from_config(repo_root: Path = REPO_ROOT) -> str | None:
    """``tools.symbolizer_rs`` from config/fuzz.yaml, or None."""
    config = repo_root / "config" / "fuzz.yaml"
    if not config.exists():
        return None
    try:
        import yaml

        data = yaml.safe_load(config.read_text(encoding="utf-8")) or {}
    except Exception:
        return None
    return (data.get("tools") or {}).get("symbolizer_rs")


def find_symbolizer(explicit: str | Path | None = None) -> Path:
    """Locate symbolizer-rs: explicit arg, ``SYMBOLIZER_RS``, PATH, then config.

    CP4 deliberately did *not* consult config/fuzz.yaml, on the grounds that an
    absolute path to a tool outside the repo is machine-specific and does not
    belong in a committed file. CP8 reversed that, because the premise was already
    false: the same file carries ``symbols.nt_symbol_path`` with ``C:\\symbols``
    and an MS symbol-server URL, so it is not machine-portable and pretending
    otherwise only meant the tool sat on disk while the pipeline reported it
    missing (D-050). Config is consulted **last**, so an env var still wins on a
    machine where the committed path is wrong.
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

    configured = _symbolizer_from_config()
    if configured:
        path = Path(configured)
        if path.is_dir():
            path = path / "symbolizer-rs.exe"
        if path.exists():
            return path
        raise TraceError(
            f"config/fuzz.yaml names symbolizer-rs at {configured}, which does "
            f"not exist. Fix the config or set SYMBOLIZER_RS."
        )

    raise TraceError(
        "symbolizer-rs not found. Set SYMBOLIZER_RS, put it on PATH, or set "
        "tools.symbolizer_rs in config/fuzz.yaml. Without it, CP4's harness "
        "validation cannot be performed and CP8 has no signal 4. See "
        "docs/ENVIRONMENT.md."
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


def fault_index_from_trace(trace_path: Path) -> int | None:
    """Line index (0-based) of the faulting instruction in a raw rip trace.

    Returned as an index, not just an address, because the symbolized trace has
    **one line per raw line in the same order** -- so this index locates the fault
    in the symbolized file too. That matters: the boundary cannot be found in the
    symbolized file directly, because after the fault the kernel returns to
    user-mode ``ntdll!RtlDispatchException`` and re-enters the kernel, so the
    *last* user->kernel transition is inside the post-fault dispatch path, not the
    fault. Locating it in the raw trace and carrying the index across avoids the
    guesswork entirely.
    """
    addresses: list[int] = []
    with Path(trace_path).open("r", encoding="utf-8", errors="replace") as fd:
        for line in fd:
            line = line.strip()
            if not line:
                continue
            try:
                addresses.append(int(line, 16))
            except ValueError:
                continue

    for index in range(len(addresses) - 1, 0, -1):
        if addresses[index] >= KERNEL_BASE and addresses[index - 1] < KERNEL_BASE:
            return index - 1
    return None


def fault_address_from_trace(trace_path: Path) -> int | None:
    """The faulting instruction's runtime address, recovered from a rip trace.

    **Why this is not simply the last line.** `wtf run` prints ``crash: 1`` in its
    stat line and *never prints the address* -- it also writes no crash file (the
    ``run`` verb has no ``--crashes`` option; measured, and the crash directory is
    unchanged after a crashing run). Meanwhile the rip trace does not stop at the
    fault: control passes to the kernel's exception dispatcher and the trace runs
    on for thousands more instructions. Measured on one crash: 43,305 lines, the
    fault at index 38,752, and 4,552 lines after it.

    So the rule is structural rather than symbolic: the fault is the last
    **user-mode** address before the final user->kernel transition. Earlier
    transitions exist -- ordinary syscalls -- so it must be the last one. This
    needs no symbols, which matters because the fault is usually in a system DLL.

    Verified against the address wtf itself put in the crash filename, on three
    crashes with different fault addresses: exact match each time (D-051).

    Returns None when the trace never enters the kernel, i.e. the input did not
    fault. That is a real answer, not a failure.
    """
    addresses: list[int] = []
    with Path(trace_path).open("r", encoding="utf-8", errors="replace") as fd:
        for line in fd:
            line = line.strip()
            if not line:
                continue
            try:
                addresses.append(int(line, 16))
            except ValueError:
                continue  # symbolized lines are not addresses; skip them

    for index in range(len(addresses) - 1, 0, -1):
        if addresses[index] >= KERNEL_BASE and addresses[index - 1] < KERNEL_BASE:
            return addresses[index - 1]
    return None


@dataclass(frozen=True)
class SymbolRef:
    """One symbolized address, split into its parts.

    ``function`` is None when symbols resolved the module but not a name. That
    distinction is load-bearing for dedup: bucketing by function is only sound
    when there *is* a function, and silently substituting the module would merge
    unrelated bugs.
    """

    raw: str
    module: str
    function: str | None
    offset: int | None

    @property
    def function_key(self) -> str | None:
        """``module!function``, or None if no name resolved."""
        return f"{self.module}!{self.function}" if self.function else None


def symbolize_addresses(
    addresses: list[int],
    *,
    crash_dump: Path,
    workdir: Path,
    symbolizer: Path | None = None,
    symbol_paths: list[str] | None = None,
    symcache: Path | None = None,
    timeout_s: int = 1800,
) -> dict[int, SymbolRef]:
    """Resolve arbitrary runtime addresses to ``module!function+offset``.

    symbolizer-rs only consumes *traces*, so a one-address-per-line file is
    written and symbolized -- a trace of length N is exactly what its input
    format is. This is the cheap path that makes dedup possible without
    generating an execution trace per crash: measured, 52 addresses resolved in
    0.0 s, against roughly a second of emulation per rip trace.

    Ordering is relied upon: symbolizer-rs emits one output line per input line,
    in order, so the mapping back to addresses is positional. Duplicate addresses
    are collapsed before the call, and the returned dict is keyed by address.
    """
    unique = sorted(set(addresses))
    if not unique:
        return {}

    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    listing = workdir / "addresses.trace"
    listing.write_text("\n".join(f"{a:#x}" for a in unique) + "\n", encoding="utf-8")

    resolved_path = symbolize(
        listing,
        workdir / "addresses.sym",
        crash_dump=crash_dump,
        symbolizer=symbolizer,
        symbol_paths=symbol_paths,
        symcache=symcache,
        style="full",
        timeout_s=timeout_s,
    )

    lines = resolved_path.read_text(encoding="utf-8", errors="replace").splitlines()
    if len(lines) != len(unique):
        raise TraceError(
            f"symbolizer-rs returned {len(lines)} lines for {len(unique)} "
            f"addresses. The mapping back to addresses is positional, so a count "
            f"mismatch would silently attribute faults to the wrong functions."
        )

    return {
        address: parse_symbol_line(line)
        for address, line in zip(unique, lines)
    }


_SYMBOL_LINE_RE = re.compile(r"^(?P<module>[^!+\s]+)(?:!(?P<symbol>[^+\s]+))?")

# `mod.dll!func+0x1e [source @ 12]` -- the offset and source are both optional.
_FULL_SYMBOL_RE = re.compile(
    r"^(?P<module>[^!+\s]+)"
    r"(?:!(?P<function>[^+\s\[]+))?"
    r"(?:\+(?P<offset>0x[0-9a-fA-F]+|\d+))?"
)


def parse_symbol_line(line: str) -> SymbolRef:
    """Split one symbolizer-rs ``--style full`` line into its parts."""
    text = line.strip()
    match = _FULL_SYMBOL_RE.match(text)
    if not match:
        return SymbolRef(raw=text, module=text or "<unknown>", function=None, offset=None)

    raw_offset = match.group("offset")
    offset = int(raw_offset, 0) if raw_offset else None
    return SymbolRef(
        raw=text,
        module=match.group("module"),
        function=match.group("function"),
        offset=offset,
    )


def frames_before_fault(
    symbolized: Path,
    *,
    count: int = 20,
    module: str | None = None,
    fault_index: int | None = None,
) -> list[str]:
    """The last ``count`` symbolized frames at or before the fault.

    Everything from the exception dispatch onward is dropped: those thousands of
    kernel frames are the *consequence* of the fault, not its cause, and triage
    walking backwards wants the approach path.

    ``fault_index`` comes from :func:`fault_index_from_trace` over the RAW trace
    and is the reliable way to find the boundary -- symbolizer-rs emits one line
    per input line in order, so the index transfers. Without it the boundary is
    guessed from where kernel frames begin, which is wrong for a symbolized trace:
    after the fault the kernel returns to user-mode ``ntdll!RtlDispatchException``
    and re-enters, so the last user->kernel transition sits in the post-fault path.

    ``module`` filters to one module, and for this target that is not a nicety. A
    tlv_server trace is dominated by system code -- measured 19,681 ntdll lines
    against 130 in the target itself -- so the unfiltered tail is entirely memcpy
    internals and says nothing about which parser branch set up the bad length.
    Filtering is applied BEFORE taking the last ``count``, so a caller asking for
    12 target frames gets 12 target frames rather than 12 lines that happen to
    contain none.
    """
    lines = [
        line.strip()
        for line in Path(symbolized)
        .read_text(encoding="utf-8", errors="replace")
        .splitlines()
        if line.strip()
    ]

    if fault_index is not None and 0 <= fault_index < len(lines):
        approach = lines[: fault_index + 1]
    else:
        # Fallback: first entry into kernel code. Less precise than the raw-trace
        # index but never includes the post-fault dispatch path.
        boundary = len(lines)
        for index, line in enumerate(lines):
            if line.startswith(("nt!", "hal!")):
                boundary = index
                break
        approach = lines[:boundary]

    if module:
        approach = [line for line in approach if line.startswith(module)]
    return approach[-count:]


def first_hit(symbolized: Path, symbol: str, rva: int | None = None) -> int | None:
    """1-based line number where the entry is first seen, by SYMBOL or by ADDRESS.

    The address form is not a convenience. symbolizer-rs resolves against the PDB and the
    export table, so a function with neither -- which is every internal function of a
    stripped binary -- never appears by name. Ghidra names it `FUN_1400447c0`; the trace
    says `fuzzing-test-cmp.exe+0x447c0`. Searching for the name then fails on a harness
    that is working perfectly, and on the third real target it did: delivery measured
    13,731 instructions against 1 for an empty test-case, the trace's FIRST line was the
    entry, and the gate still reported "the trace never enters FUN_1400447c0" (D-092).

    A check that cannot pass is worse than no check, because its failure gets believed. So
    the RVA is accepted too, matched as `+0x<rva>` -- the form symbolizer-rs prints when it
    has no symbol to offer.
    """
    needles = [symbol]
    if rva is not None:
        needles.append(f"+{rva:#x}")
    with symbolized.open("r", encoding="utf-8", errors="replace") as fd:
        for lineno, line in enumerate(fd, start=1):
            if any(needle in line for needle in needles):
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


def validate_delivery(
    target: TraceTarget,
    input_path: Path,
    *,
    trace_dir: Path,
    symbolizer: Path | None = None,
) -> tuple[bool, str]:
    """Does the input CHANGE anything? Returns (delivered, explanation).

    THE CHECK CP4 ASKS FOR IS VACUOUS ON THESE SNAPSHOTS, and that was measured rather
    than reasoned: with `InsertTestcase` deliberately altered to queue nothing, the rip
    trace still reported `first hit: line 1` and HARNESS VALIDATION PASSED. The reason is
    structural -- a snapshot is taken AT the fuzz entry, so `rip` is already inside it and
    the trace's first instruction hits the entry symbol whether or not a test-case was
    ever written. "Execution reaches the parser" is true of the untouched snapshot.

    So compare against a BASELINE: the same harness run on an empty input. An empty
    test-case is universally constructible, needs no knowledge of the target, and takes
    the same path through `InsertTestcase` that a rejected one does -- it queues nothing.
    If a real seed traces identically to that, the seed is not reaching the guest.

    This is what would have caught all three of the harness failures recorded here, none
    of which the entry-symbol check can see:

      * a wire format that did not match the corpus, so every case was skipped (D-082);
      * a breakpoint at 0 + rva because GetModuleBase returned 0 (D-075);
      * a module registered for a different target (D-085).

    A false NEGATIVE is possible and worth naming: a target that genuinely ignores its
    input would also produce identical traces. That is not a harness fault, and the
    message says so rather than asserting a cause it cannot distinguish.
    """
    empty = trace_dir / "_baseline_empty.bin"
    empty.parent.mkdir(parents=True, exist_ok=True)
    empty.write_bytes(b"")

    seed_trace = generate_trace(target, input_path, trace_dir / "seed", trace_type="rip")
    base_trace = generate_trace(target, empty, trace_dir / "baseline", trace_type="rip")

    seed_lines = seed_trace.read_text(encoding="utf-8", errors="replace").splitlines()
    base_lines = base_trace.read_text(encoding="utf-8", errors="replace").splitlines()
    if seed_lines != base_lines:
        return True, (
            f"the input changes execution: {len(seed_lines)} instruction(s) with the seed "
            f"against {len(base_lines)} with an empty test-case"
        )
    return False, (
        f"the seed and an EMPTY test-case trace identically ({len(seed_lines)} "
        f"instruction(s)), so nothing is reaching the guest. The entry-symbol check cannot "
        f"see this: the snapshot's rip is already inside the fuzz entry, so the trace hits "
        f"it whether or not a test-case was delivered. Either InsertTestcase is queueing "
        f"nothing, the breakpoint is not firing, or the target ignores this input."
    )


def validate_harness(
    target: TraceTarget,
    input_path: Path,
    entry_symbol: str,
    *,
    entry_rva: int | None = None,
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
        reached_fuzz_entry=first_hit(symbolized, entry_symbol, entry_rva) is not None,
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Harness validation via a rip trace")
    ap.add_argument("--wtf", type=Path, default=REPO_ROOT / "src/build/wtf.exe")
    ap.add_argument("--target-dir", type=Path, required=True)
    ap.add_argument("--name", required=True, help="wtf --name (the module)")
    ap.add_argument(
        "--input",
        type=Path,
        required=True,
        help="a test-case, or a DIRECTORY of them -- the first is used. The directory "
             "form exists because the pipeline builds this stage's argv before the seed "
             "stage has run, so no filename is known yet",
    )
    ap.add_argument("--entry-symbol", required=True, help="e.g. ProcessPacket")
    ap.add_argument(
        "--a1",
        type=Path,
        help="A1 snapshot JSON. The entry's RVA is derived from it as "
             "entry_runtime_addr - module_base, which is how a stripped entry with no "
             "symbol can still be found in a trace (D-092)",
    )
    ap.add_argument(
        "--entry-rva",
        type=lambda s: int(s, 0),
        help="the entry's RVA. Needed when the entry has no PDB or export symbol -- every "
             "internal function of a stripped binary -- because symbolizer-rs then prints "
             "module+0xrva and a name search can never match (D-092)",
    )
    ap.add_argument("--binary-dir", type=Path, help="directory holding the PDB")
    ap.add_argument("--symbolizer", type=Path)
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "artifacts")
    args = ap.parse_args(argv)

    chosen = args.input
    if chosen.is_dir():
        candidates = sorted(p for p in chosen.iterdir() if p.is_file())
        if not candidates:
            raise SystemExit(
                f"{chosen} holds no test-case to validate the harness with. Harness "
                f"validation needs one input; the seed stage should have written it."
            )
        chosen = candidates[0]
        print(f"input       : {chosen} (first of {len(candidates)} in {args.input})")

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

    entry_rva = args.entry_rva
    if entry_rva is None and args.a1 and args.a1.is_file():
        import json as _json

        a1 = _json.loads(args.a1.read_text(encoding="utf-8"))
        base, runtime = a1.get("module_base"), a1.get("entry_runtime_addr")
        if base and runtime:
            entry_rva = int(runtime) - int(base)
            print(f"entry rva    : {entry_rva:#x} (from A1)")

    ref = validate_harness(
        target,
        chosen,
        args.entry_symbol,
        entry_rva=entry_rva,
        # Per-module trace directory: two modules validated against the same
        # snapshot would otherwise write the same filename.
        trace_dir=args.out / "traces" / args.name,
        symbolized_path=args.out / "traces-symbolized" / f"{args.name}.rip.txt",
        symbolizer=args.symbolizer,
    )

    sym = Path(ref.symbolized_path)
    line = first_hit(sym, args.entry_symbol, entry_rva)
    print(f"trace       : {ref.raw_path}")
    print(f"symbolized  : {ref.symbolized_path}")
    print(f"entry symbol: {args.entry_symbol}")
    print(f"first hit   : line {line}" if line else "first hit   : NOT FOUND")
    print("modules     :")
    for module, count in module_histogram(sym):
        print(f"  {count:>7}  {module}")

    delivered, why = validate_delivery(
        target,
        chosen,
        trace_dir=args.out / "delivery" / args.name,
        symbolizer=args.symbolizer,
    )
    print(f"delivery    : {'YES' if delivered else 'NO'} -- {why}")
    if not delivered:
        print(
            "\nHARNESS VALIDATION FAILED: the harness does not deliver the test-case. "
            "It will run at full speed and report coverage while fuzzing nothing."
        )
        return 1

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
