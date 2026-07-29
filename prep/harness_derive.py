"""Derive the harness itself from Ghidra, not just the input format.

CP11 generated the input struct and left the harness hand-written, filed under
section 3.1's "Manual tweaks". That was half a real boundary and half an excuse.
Recounting the module showed most of those lines are derivable, and some are not
even target-specific:

* the **crash oracle is one line** -- ``SetupUsermodeCrashDetectionHooks()``, wtf's
  own helper. The fault sites it hooks (``nt!KeBugCheck2``,
  ``ntdll!RtlDispatchException``, ``verifier!VerifierStopMessage``) are
  Windows-generic;
* **Restore is a no-op**, and that is the general case -- wtf's snapshot restore
  already covers guest memory and registers (DECISIONS R2);
* the **mutator is field-driven**, so an InputSpec already determines it;
* the entry and the functions worth silencing come from **FuzzEntry plus Ghidra's
  call references**.

What remains is small enough to declare, and leaving it hand-written contradicts
contribution 1 -- which section 11 states is about removing "snapshot fuzzing's
main usability barrier". Five hundred hand-written lines per target *is* that
barrier.

**The model still does not write C++.** It fills in a :class:`HarnessSpec`;
:mod:`fuzzer.codegen` renders it. Same reasoning as CP11: a compile error from
generated C++ surfaces in the toolchain far from the model's mistake, free-form C++
cannot be schema-checked, and RULE 4's "units and encoding are stated" is
enforceable in a contract and merely hoped for in prose.

**Routed to the 550B**, unlike input-structure derivation. Deciding what is I/O
noise, when a test-case has ended, and what is non-deterministic is judgement over
lossy decompiler output, and section 7.2 reserves that model for where judgement
matters. It runs once per target.

**RULE 1**: build time, once per target, never inside the fuzzing loop.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from arch.contracts import FuzzEntry, HarnessSpec, InputSpec
from llm.client import LlmClient
from prep.pseudoc_cache import PseudoCCache

REPO_ROOT = Path(__file__).resolve().parents[1]

__all__ = [
    "HarnessDeriveError",
    "derive_harness",
    "check_harness",
    "candidate_calls",
]

_MAX_CHARS_PER_FUNCTION = 10_000
_MAX_CALLEES = 12

# Functions whose names imply console or file output. Offered to the model as
# CANDIDATES, never applied silently: a target that writes its parse result to a
# socket must not have that call skipped, and only reading the code can tell the
# difference between logging and protocol.
_IO_HINT = re.compile(
    r"^_?(v?f?printf|v?sn?printf|puts|fputs|fwrite|putchar|"
    r"Write(File|Console)\w*|OutputDebugString\w*)",
    re.IGNORECASE,
)

# Sources of non-determinism. wtf's README's own example of a patch is a function
# using rdrand; without pinning these, a crash will not reproduce on whv/kvm and
# the non-reproduction gets blamed on the bug (section 13.5, section 10).
_NONDET_HINT = re.compile(
    r"(rand|rdtsc|QueryPerformanceCounter|GetTickCount\w*|GetSystemTime\w*|"
    r"time64?|GetLocalTime|UuidCreate|BCryptGenRandom)",
    re.IGNORECASE,
)


class HarnessDeriveError(RuntimeError):
    pass


def candidate_calls(code: str, module: str) -> dict[str, list[str]]:
    """Functions called by ``code``, bucketed into hint categories.

    Extracted mechanically and offered to the model as candidates. The mechanical
    pass finds *what is called*; deciding whether silencing a call is safe needs
    the code, which is the model's job.
    """
    called = sorted(set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_:<>]*)\s*\(", code)))
    keywords = {"if", "while", "for", "switch", "return", "sizeof", "do"}
    called = [c for c in called if c not in keywords]

    return {
        "io": [c for c in called if _IO_HINT.match(c)],
        "nondeterministic": [c for c in called if _NONDET_HINT.search(c)],
        "other": [
            c for c in called
            if not _IO_HINT.match(c) and not _NONDET_HINT.search(c)
        ][:_MAX_CALLEES],
    }


_SYSTEM = (
    "You configure a snapshot fuzzer's harness for a binary with no source, from "
    "Ghidra decompiler output. Pseudo-C is lossy: names are invented and types are "
    "inferred. The harness runs INSIDE a restored snapshot: at a breakpoint on the "
    "parser you write a test-case into guest memory and let it run; when the "
    "test-case is consumed you stop the iteration. Getting this wrong produces a "
    "harness that executes and reports coverage while never delivering input, so "
    "prefer saying you are unsure in the rationale over inventing a breakpoint."
)


def _prompt(
    entry: FuzzEntry,
    input_spec: InputSpec,
    code: str,
    calls: dict[str, list[str]],
    caller_code: str,
) -> str:
    sequence = (
        "one test-case carries a SEQUENCE of structures, delivered one per hit of "
        "the entry breakpoint"
        if input_spec.supports_sequence
        else "one test-case carries a SINGLE structure"
    )
    return (
        f"TARGET: {entry.module}!{entry.symbol}\n"
        f"The fuzz input arrives in {entry.input_param}"
        f"{f' with its length in {entry.size_param}' if entry.size_param else ''}.\n"
        f"The input format has already been derived: {len(input_spec.fields)} "
        f"field(s), a {input_spec.header_bytes}-byte fixed header, and "
        f"{sequence}.\n\n"
        f"DECOMPILED CODE OF THE ENTRY\n{code}\n\n"
        f"{caller_code}"
        f"FUNCTIONS THIS CODE CALLS, pre-bucketed by name. These are CANDIDATES "
        f"from a regex, not conclusions -- check each against the code:\n"
        f"  output-looking : {calls['io'] or '(none)'}\n"
        f"  nondeterministic-looking: {calls['nondeterministic'] or '(none)'}\n"
        f"  others         : {calls['other'] or '(none)'}\n\n"
        f"Decide the harness configuration.\n\n"
        f"1. breakpoints. Give a list. Every symbol must be written "
        f"\"module!Function\".\n"
        f"   * EXACTLY ONE with purpose=fuzz_entry and action=deliver_next_input, "
        f"on {entry.module}!{entry.symbol}. This is where a structure is written "
        f"into guest memory.\n"
        f"   * purpose=silence_io, action=simulate_return, with a return_value, for "
        f"each call that only produces console or file output. Silencing costs "
        f"nothing and console I/O is slow enough to dominate a fuzzing loop. But do "
        f"NOT silence a call that transmits the parse RESULT -- that is protocol, "
        f"not logging, and skipping it removes behaviour you want tested. If the "
        f"code does not let you tell, leave it alone and say so.\n"
        f"   * purpose=nondeterminism, action=simulate_return, for anything whose "
        f"value differs run to run. Unpinned, a crash will not reproduce and the "
        f"non-reproduction gets blamed on the bug rather than on the clock.\n"
        f"   * purpose=end_of_testcase, action=stop_ok, ONLY if there is a distinct "
        f"function that runs once the input has been fully consumed. If the natural "
        f"end is simply returning from the entry, omit this -- the generated harness "
        f"handles that case itself.\n"
        f"2a. input_buffer_bytes -- how many bytes of room the target provides at "
        f"{entry.input_param}, if the code says. Look at the CALLER: a stack buffer "
        f"declared as `char buf[32]` means 32. This decides WHERE the test-case is "
        f"written -- a page-sized scratch area is filled from its end so an over-read "
        f"faults, and a small fixed buffer is written at the pointer itself. Getting it "
        f"wrong means the parser reads untouched memory and rejects every test-case. "
        f"Omit it only if the code genuinely does not say.\n"
        f"    THE SIZE PARAMETER'S CURRENT VALUE IS NOT THE CAPACITY. "
        f"{entry.size_param or 'The size register'} holds how many bytes the caller "
        f"passed in the ONE snapshot that was taken; the buffer behind the pointer is "
        f"usually far larger, and on a heap allocation its size is not in the code at "
        f"all. Answering with that register's value is the specific mistake to avoid: "
        f"the generated harness drops every test-case LARGER than this number, so a "
        f"value of 8 read off rdx made a 21-byte seed vanish -- zero instructions "
        f"executed, no crash, no error, and a campaign that looks like a clean run "
        f"(D-090). A pointer into the heap or a page-aligned address is evidence you "
        f"CANNOT tell: answer null, which selects the page-end placement. "
        f"Null is the safe answer and a guess is not.\n"
        f"2. input_is_pointer -- is {entry.input_param} a POINTER TO the buffer, or "
        f"the buffer's address used directly? RULE 4 asks this explicitly; look at "
        f"how the code dereferences it.\n"
        f"3. restore_globals -- globals the parser mutates that would need resetting "
        f"between test-cases. Almost always EMPTY: the snapshot restore already "
        f"returns guest memory to its captured state, and resetting again is as "
        f"wrong as not resetting. Name one only if you can argue it, in the "
        f"rationale.\n"
        f"4. max_input_bytes -- an upper bound on one structure. The delivery buffer "
        f"is page-backed, so keep it under 4096 unless the code demands more.\n"
        f"5. rationale -- three or four sentences: how input arrives, what you chose "
        f"to silence and why it is safe, and what you were unsure about.\n"
        f"6. source_functions -- which functions you read.\n\n"
        f"Do not include a breakpoint for crash detection. The fuzzer installs the "
        f"platform's fault hooks itself; they are the same for every Windows target."
    )


def calls_taking_the_input(code: str, input_param_name: str = "param_1") -> set[str]:
    """Functions in ``code`` called with the input buffer among their arguments.

    A `silence_io` stub on one of these does not quieten the harness -- it DELETES the
    thing being tested. The third real target made this concrete: its parser ends with

        thunk_FUN_1400c08f0(local_100, param_1, (ulonglong)*(byte *)(param_1 + 4));

    which is the memcpy that overflows a 224-byte stack buffer -- the entire bug. The model
    marked it `silence_io / simulate_return` and explained: "Appears to be a
    logging/printing routine called after successful parse; silencing avoids console I/O
    overhead without affecting parse logic." A reasonable guess from a name like
    `thunk_FUN_1400c08f0`, and it would have stubbed out the vulnerability. The campaign
    would have run at full speed, reported coverage, and found nothing -- because the
    harness skipped the call that crashes.

    It survived only by luck: A2 had no address for that thunk, so the breakpoint stayed
    name-resolved and Init failed loudly on a stripped target (D-091). Luck is not a check.

    Mechanical and conservative: it looks for the input parameter's name in the argument
    list. `param_1` is what Ghidra names a first parameter, and the name is passed in for
    the cases where it is not.
    """
    hits: set[str] = set()
    for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_:<>]*)\s*\(([^;]{0,400}?)\)\s*;", code):
        name, args = match.group(1), match.group(2)
        if name in {"if", "while", "for", "switch", "return", "sizeof", "do"}:
            continue
        if re.search(rf"\b{re.escape(input_param_name)}\b", args):
            hits.add(name)
    return hits


def check_harness(
    spec: HarnessSpec, input_spec: InputSpec, code: str
) -> list[str]:
    """Consistency warnings between the harness, the input spec, and the code.

    Warnings rather than errors: pseudo-C is lossy enough that a mismatch is
    sometimes the decompiler's fault. Returned so the caller records them beside
    the spec -- a harness that disagrees with its own source is what a reviewer
    most needs to see.
    """
    warnings: list[str] = []

    # A STUB ON A CALL THAT RECEIVES THE INPUT REMOVES THE BUG. Checked before anything
    # else because it is the one inconsistency here that silently invalidates a whole
    # campaign rather than merely making it noisier (D-091).
    takes_input = calls_taking_the_input(code)
    for breakpoint in spec.breakpoints:
        name = breakpoint.symbol.split("!", 1)[-1]
        if breakpoint.action != "simulate_return" or name not in takes_input:
            continue
        warnings.append(
            f"REFUSED: {breakpoint.symbol} is stubbed with simulate_return, but the entry "
            f"passes the INPUT BUFFER to it. Silencing it does not quieten the harness, it "
            f"deletes the code under test -- on the third target this exact call was the "
            f"memcpy that overflows. The breakpoint has been dropped; if it really is "
            f"logging, say so in the rationale and name a call that does not take the "
            f"input."
        )
    spec.breakpoints = [
        b for b in spec.breakpoints
        if not (b.action == "simulate_return"
                and b.symbol.split("!", 1)[-1] in takes_input)
    ]

    if spec.deliver_sequence != input_spec.supports_sequence:
        warnings.append(
            f"the harness delivers "
            f"{'a sequence' if spec.deliver_sequence else 'a single structure'} but "
            f"the input spec says supports_sequence="
            f"{input_spec.supports_sequence}. One of them is wrong, and if the "
            f"parser is stateful the single-structure choice makes whole branches "
            f"unreachable."
        )

    if spec.max_input_bytes > 4096:
        warnings.append(
            f"max_input_bytes is {spec.max_input_bytes}, over one page. The delivery "
            f"buffer is page-backed, so anything larger is dropped at run time"
        )

    silenced = [b.symbol.split("!", 1)[-1] for b in spec.breakpoints
                if b.purpose == "silence_io"]
    for name in silenced:
        if not _IO_HINT.match(name):
            warnings.append(
                f"{name} is silenced as output but its name does not look like an "
                f"output function -- confirm it is not carrying the parse result"
            )

    nondet = candidate_calls(code, spec.module)["nondeterministic"]
    pinned = {b.symbol.split("!", 1)[-1] for b in spec.breakpoints
              if b.purpose == "nondeterminism"}
    unpinned = [c for c in nondet if c not in pinned]
    if unpinned:
        warnings.append(
            f"possible non-determinism left unpinned: {unpinned}. A crash that will "
            f"not reproduce may be the clock rather than the bug (section 13.5)"
        )

    if not spec.rationale.strip():
        warnings.append("no rationale: the harness cannot be reviewed without one")
    return warnings


def derive_harness(
    entry: FuzzEntry,
    input_spec: InputSpec,
    cache: PseudoCCache,
    client: LlmClient,
    *,
    target_name: str = "snapfuzz",
    role: str = "harness_derive",
    # For turning A2's static addresses into RVAs. Defaults to the usual PE64 base so
    # an existing caller keeps working; the pipeline passes the real one from A2.
    ghidra_image_base: int = 0x140000000,
) -> tuple[HarnessSpec, list[str]]:
    """Derive a HarnessSpec. Returns the spec and any consistency warnings."""
    if not entry.symbol:
        raise HarnessDeriveError(
            "the FuzzEntry names no symbol, so no breakpoint can be placed on it. "
            "wtf resolves breakpoints by name through dbgeng."
        )

    # module=entry.module -- A2 is shared across targets; see prep/input_struct.py
    # for why an unqualified lookup returns another program's body (D-073).
    record = cache.get_by_function(
        entry.symbol, module=entry.module
    ) or cache.get_by_addr(entry.static_addr, module=entry.module)
    if record is None:
        raise HarnessDeriveError(
            f"A2 has no pseudo-C for {entry.symbol!r}. Deriving how to drive a "
            f"parser without its code is guesswork."
        )

    code = record.code
    if len(code) > _MAX_CHARS_PER_FUNCTION:
        code = code[:_MAX_CHARS_PER_FUNCTION] + "\n/* ...truncated... */\n"
    calls = candidate_calls(code, entry.module)

    # The caller shows how the parser is invoked -- the same information that fixed
    # supports_sequence at CP11, and it is what says whether returning from the
    # entry is the natural end of a test-case.
    from prep.input_struct import _find_callers

    callers = _find_callers(entry, cache, limit=1)
    caller_code = ""
    if callers:
        name, text = callers[0]
        trimmed = text[: _MAX_CHARS_PER_FUNCTION // 2]
        caller_code = (
            f"HOW THE ENTRY IS CALLED (function {name}). This says whether the entry "
            f"returns once per structure, and whether state persists between "
            f"calls:\n{trimmed}\n\n"
        )

    spec = client.complete_json(
        role,
        _prompt(entry, input_spec, code, calls, caller_code),
        HarnessSpec,
        system=_SYSTEM,
    )

    # Facts we already hold are not the model's to restate. Letting it do so is how
    # a spec ends up describing the wrong module.
    spec.module = entry.module
    spec.target_name = target_name
    spec.entry_symbol = f"{entry.module}!{entry.symbol}"
    spec.input_param = entry.input_param
    spec.size_param = entry.size_param
    spec.deliver_sequence = input_spec.supports_sequence
    if not spec.source_functions:
        spec.source_functions = [record.function]

    # WHERE EACH BREAKPOINT GOES, as an offset from the module base.
    #
    # wtf resolves a breakpoint symbol through dbgeng, which needs the target to have a
    # PDB. Stripped binaries are the normal case here, and Ghidra names their functions
    # `FUN_140001150` -- a label it invented, in no symbol table. wtf then reports
    # `Could not set a breakpoint at mytarget!FUN_140001150`, every worker dies in Init,
    # and the campaign records zero executions (D-075).
    #
    # A2 already holds the static address of every function, so the RVA is subtraction.
    # Filled in here rather than asked of the model: it is arithmetic over recorded
    # facts, and a model has nothing to add to it.
    resolved, unresolved = 0, []
    for bp in spec.breakpoints:
        name = bp.symbol.split("!", 1)[-1]
        target = cache.get_by_function(name, module=entry.module)
        if target is None:
            unresolved.append(name)
            continue
        bp.rva = target.static_addr - ghidra_image_base
        resolved += 1
    if unresolved:
        # Not fatal: a breakpoint on something outside A2 -- a CRT import thunk, say --
        # can still resolve by name if the target does have symbols for it. Said out
        # loud because if it does not, the failure is every worker dying in Init.
        print(
            f"  [warn] no address in A2 for {unresolved}; those breakpoints stay "
            f"name-resolved and will fail on a target without symbols for them"
        )

    return spec, check_harness(spec, input_spec, code)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--entry", type=Path, default=REPO_ROOT / "artifacts" / "fuzz_entry_llm.json"
    )
    ap.add_argument(
        "--input-spec", type=Path, default=REPO_ROOT / "artifacts" / "input_spec.json"
    )
    ap.add_argument(
        "--cache", type=Path,
        default=REPO_ROOT / "artifacts" / "a2_pseudoc_module.sqlite",
    )
    ap.add_argument(
        "--out", type=Path, default=REPO_ROOT / "artifacts" / "harness_spec.json"
    )
    ap.add_argument("--target-name", default="snapfuzz")
    ap.add_argument(
        "--ghidra-image-base",
        type=lambda s: int(s, 0),
        default=None,
        help="for converting A2 static addresses to RVAs; read from --export "
             "or defaults to 0x140000000",
    )
    ap.add_argument(
        "--export",
        type=Path,
        default=None,
        help="the A2 json, read only for its image_base",
    )
    args = ap.parse_args(argv)

    entry = FuzzEntry.model_validate_json(args.entry.read_text(encoding="utf-8"))
    input_spec = InputSpec.model_validate_json(
        args.input_spec.read_text(encoding="utf-8")
    )
    print(f"deriving the harness for {entry.module}!{entry.symbol}")

    with PseudoCCache(args.cache) as cache, LlmClient.from_config() as client:
        image_base = args.ghidra_image_base
        if image_base is None and args.export and args.export.is_file():
            image_base = json.loads(args.export.read_text(encoding="utf-8"))["image_base"]
        spec, warnings = derive_harness(
            entry, input_spec, cache, client,
            target_name=args.target_name,
            **({"ghidra_image_base": image_base} if image_base is not None else {}),
        )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(spec.model_dump_json(indent=2), encoding="utf-8")

    print(f"\n{len(spec.breakpoints)} breakpoint(s):")
    for bp in spec.breakpoints:
        detail = bp.action
        if bp.return_value is not None:
            detail += f" -> {bp.return_value}"
        print(f"  {bp.symbol:<34} {bp.purpose:<16} {detail}")
    print(f"input via {spec.input_param}"
          f"{f' (pointer)' if spec.input_is_pointer else ' (direct address)'}"
          f"{f', size in {spec.size_param}' if spec.size_param else ''}")
    print(f"sequence per test-case : {spec.deliver_sequence}")
    print(f"globals to restore     : {spec.restore_globals or '(none -- the usual case)'}")
    print(f"max bytes per structure: {spec.max_input_bytes}")

    if warnings:
        print("\nconsistency warnings:")
        for warning in warnings:
            print(f"  ! {warning}")

    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
