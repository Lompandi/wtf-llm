"""The model writes the wtf module C++ itself, and the compiler is the check.

`fuzzer/codegen.py` renders C++ from an InputSpec with deterministic templates, and
argues for that split: a compile error from model-written C++ surfaces in the toolchain
far from the mistake, and free-form C++ cannot be schema-validated. Both points are
true.

This module does it the other way, on the project owner's instruction after comparing
the two outputs. The argument that makes it defensible is not that the objection was
wrong -- it is that **the objection assumes the only available check is a schema**, and
here it is not:

* the result has to **compile**, under `/WX`, inside the real wtf tree;
* the campaign built from it has to **produce coverage**, which a harness that never
  delivers input does not;
* and `--codegen template` is one flag away when a generation is bad.

Those are stronger checks than schema-validity, not weaker ones. A schema-valid
InputSpec can still render a harness that runs, reports coverage and never injects a
test-case -- the exact failure CP4's trace validation exists to catch. A module that
compiles and moves the coverage counter has demonstrably done the thing.

**Build time, once per target, never in the fast loop.** RULE 1 is untouched, the same
way stages 03, 08 and 08b are: this runs as a subprocess before the campaign starts.

What the model is given
-----------------------
The InputSpec and HarnessSpec it is being asked to implement, the exact wtf interface it
must satisfy (`Init`/`InsertTestcase`/`Restore` and the `Target_t` registration), and
**the hand-written module as a worked example** -- because the interface is not
guessable from its signatures alone and an example is the cheapest way to convey it.

What is checked before the file is written
------------------------------------------
Cheap structural checks, so an obviously unusable answer fails here rather than in the
compiler with a less useful message: the registration is present with the right target
name, the three entry points exist, `#include` lines are plausible, and the text is
ASCII (MSVC under a non-UTF-8 codepage rejects a stray en dash under `/WX`, which is
D-054 and cost a build once already).
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from arch.contracts import HarnessSpec, InputSpec

REPO_ROOT = Path(__file__).resolve().parents[1]

__all__ = ["CodegenLlmError", "generate_module", "check_generated"]

# The module the model is shown as an example of the interface. Not a template it is
# asked to fill -- a worked example of a different target's answer.
EXAMPLE = REPO_ROOT / "fuzzer" / "module" / "fuzzer_snapfuzz.cc"

MAX_EXAMPLE_CHARS = 24_000


class CodegenLlmError(RuntimeError):
    pass


_SYSTEM = (
    "You write a single C++ translation unit implementing a fuzzing harness module for "
    "wtf, a snapshot fuzzer. You are given the input format and the harness "
    "configuration, both already derived, plus a working module for a different target "
    "as an example of the interface. Output ONLY C++ source -- no prose, no markdown "
    "fence. It is compiled with MSVC under /WX, so it must be ASCII and warning-clean. "
    "The harness runs inside a restored snapshot: at a breakpoint on the parser you "
    "write a test-case into guest memory and let it run. A harness that executes "
    "without delivering input reports coverage and finds nothing, so correctness of "
    "InsertTestcase matters more than anything else in the file."
)


def required_namespace(spec: InputSpec) -> str:
    """The namespace the generated module must use.

    Every fuzzer module in `fuzzer/module/` is compiled into ONE wtf.exe, so two modules
    sharing a namespace is a link error, not a style question. The first generation
    copied the example's `namespace Snapfuzz` -- which is what "copy the shape" invited --
    and the build failed with four LNK2005s and LNK1169: `Snapfuzz::Init`,
    `Snapfuzz::Restore`, `Snapfuzz::InsertTestcase` and the `Target_t` object all already
    defined in fuzzer_snapfuzz.cc.obj.

    The model's C++ was fine; the prompt had not said this. Same convention
    `fuzzer/codegen.py` uses, so both generators produce the same name (D-075).
    """
    from fuzzer.codegen import cpp_namespace

    # The same function the deterministic renderer uses. Two derivations of one name is
    # how the two generators end up disagreeing about which namespace is "already used".
    return cpp_namespace(spec.module)


def existing_namespaces(module_dir: Path, exclude: Path | None = None) -> set[str]:
    """Namespaces already used by modules that link into the same binary."""
    found: set[str] = set()
    for source in sorted(module_dir.glob("*.cc")):
        if exclude and source.resolve() == exclude.resolve():
            continue
        try:
            text = source.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        found.update(re.findall(r"^namespace\s+(\w+)\s*\{", text, re.M))
    return found


def guest_address_type(source: Path | None = None) -> str:
    """`Gva_t`'s declaration, quoted from wtf's own header.

    The model writes against this type in every guest-memory call and had never been shown
    it, so it guessed: `PacketAddress + sizeof(...)` (C2678 -- operator+ takes another
    Gva_t, and the constructor is explicit), then `.Get()` (C2039 -- the accessor is
    `U64`). Two repair rounds spent inventing an API is not a reasoning failure; it is a
    missing input.

    Quoted rather than described, per RULE 2: the source wins, and a paraphrase of an
    interface is exactly the thing RULE 4 says is not specified until you can write it
    without guessing.
    """
    source = source or REPO_ROOT / "src" / "wtf" / "gxa.h"
    try:
        text = source.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    match = re.search(r"^class Gva_t \{.*?^\};", text, re.S | re.M)
    return match.group(0) if match else ""


def _prompt(spec: InputSpec, harness: HarnessSpec, example: str) -> str:
    fields = "\n".join(
        f"  {i}. {f.name}: kind={f.kind} ctype={f.ctype or 'bytes'} "
        f"little_endian={f.little_endian}"
        + (f" counts={f.counts_field} in {f.unit}" if f.kind == "length" else "")
        + (f" includes_header={f.includes_header}" if f.kind == "length" else "")
        + (f" magic={f.magic_value:#x}" if f.magic_value is not None else "")
        + (f" max_length={f.max_length}" if f.max_length else "")
        + (
            f" TERMINATED BY {f.terminator:#04x} -- write this byte after the field"
            if f.terminator is not None
            else ""
        )
        + (f" also_reads={f.legacy_names}" if f.legacy_names else "")
        for i, f in enumerate(spec.fields, 1)
    )
    breakpoints = "\n".join(
        f"  - {b.symbol} purpose={b.purpose} action={b.action}"
        + (f" return_value={b.return_value}" if b.return_value is not None else "")
        + (f" rva={b.rva:#x}" if b.rva is not None else "")
        for b in harness.breakpoints
    )
    return (
        f"TARGET: {harness.entry_symbol}\n"
        f"wtf target name to register: {harness.target_name!r}\n"
        f"Input arrives in {harness.input_param}"
        f"{f', length in {harness.size_param}' if harness.size_param else ''}; "
        f"input_is_pointer={harness.input_is_pointer}.\n"
        f"One test-case carries "
        f"{'a SEQUENCE of structures, one delivered per breakpoint hit'
           if harness.deliver_sequence else 'a SINGLE structure'}.\n"
        f"max_input_bytes={harness.max_input_bytes}\n\n"
        f"STRUCT `{spec.struct_name}` -- {spec.header_bytes}-byte fixed header, "
        f"fields in wire order:\n{fields}\n\n"
        f"THE ON-DISK TEST-CASE FORMAT, which is fixed and not yours to choose. The JSON "
        f"root of one test-case is "
        f"{'an object with ONE key holding an ARRAY of these structures'
           if harness.deliver_sequence
           else f'THE {spec.struct_name} ITSELF: a plain object whose keys are the field '
                f'names above, with NO wrapper struct and NO array'}. "
        f"Existing corpus files are written that way. The keys are those exact spellings "
        f"-- lowercase and underscores included -- plus any also_reads aliases; C++ "
        f"members may be named however you like. Parsing the root as any other shape, or "
        f"reading a differently-spelled key, THROWS: InsertTestcase catches it, reports "
        f"'not valid JSON, skipping', and every corpus file is discarded silently while "
        f"the campaign reports coverage.\n\n"
        f"BREAKPOINTS to install in Init:\n{breakpoints or '  (none beyond the entry)'}\n\n"
        f"REQUIREMENTS\n"
        f"1. Put EVERYTHING in `namespace {required_namespace(spec)} {{ ... }}` and "
        f"name the registration object `{required_namespace(spec)}Target`. Every module "
        f"in this project links into ONE wtf.exe, so reusing the example's namespace or "
        f"its object name is a link error (LNK2005 on Init, Restore, InsertTestcase and "
        f"the Target_t object). Do not copy the example's namespace.\n"
        f"2. Register with: Target_t {required_namespace(spec)}Target"
        f"(\"{harness.target_name}\", Init, InsertTestcase, Restore, "
        f"CustomMutator_t::Create);\n"
        f"3. TWO HELPERS ARE PROVIDED, in \"snapfuzz_resolve.h\" -- include it and "
        f"call them; do NOT reimplement either. snapfuzz::ResolveModuleBase(name) "
        f"returns where the module is mapped, and snapfuzz::ResolveInputAddress("
        f"pointer, bytes) returns where to write the input. Both encode a decision "
        f"whose failure is SILENT rather than a compile error, which is why they are "
        f"ordinary code and not yours to write. EXACT SIGNATURES, because guessing them "
        f"is a compile error: `uint64_t ResolveModuleBase(const char *)` and "
        f"`Gva_t ResolveInputAddress(P, size_t Bytes)`, where P is a uint64_t or a Gva_t. "
        f"It RETURNS Gva_t, which Backend->{harness.input_param}(...), VirtWriteDirty and "
        f"SetBreakpoint all take directly; use .U64() if you need the integer. Gva_t's "
        f"constructor is EXPLICIT, so wrap with Gva_t(...), add with "
        f"`Addr + Gva_t(sizeof(x))`, and never compare a Gva_t against 0.\n"
        f"4. A breakpoint whose spec carries an `rva` MUST be placed BY ADDRESS: "
        f"Gva_t(ResolveModuleBase(\"<module>\") + rva). Use ResolveModuleBase, NOT "
        f"g_Dbg->GetModuleBase directly: on a real snapshot GetModuleBase returned 0 "
        f"because symbol-store.json named a different program, so the breakpoint went to "
        f"0+rva, never fired, and the campaign reported coverage while delivering "
        f"nothing. ResolveModuleBase falls back to SNAPFUZZ_MODULE_BASE and returns 0 "
        f"only when it genuinely cannot tell, which Init must treat as a refusal. A "
        f"stripped target has no symbols for dbgeng, so a name-resolved breakpoint fails "
        f"outright and every worker dies in Init.\n"
        f"5. LENGTH FIELDS. In the mutator's Generate(), recompute a length from what it "
        f"counts, so most inputs survive the parser's first check. When WRITING INTO "
        f"GUEST MEMORY, write the test-case's bytes VERBATIM -- never recompute there. A "
        f"length that disagrees with its payload IS the bug class being hunted, and a "
        f"harness that repairs it on the way in cannot find it.\n"
        f"6. WHERE THE INPUT GOES: call ResolveInputAddress(Pointer, Bytes), where "
        f"Pointer is the register value the target uses as the buffer and Bytes is the "
        f"number of bytes ACTUALLY WRITTEN. It returns an address whose end sits against "
        f"an unmapped page, so an overflow faults and becomes a detectable access "
        f"violation. Do NOT do this arithmetic yourself: a register holds a POINTER, not "
        f"a page base, and adding (kPageSize - Bytes) to an unmasked pointer lands past "
        f"the page end. Align on the bytes written, never on a reported size, or an "
        f"over-reported length reads our own bytes instead of faulting.\n"
        f"7. Where a field lists also_reads, from_json must accept those keys too -- a "
        f"recorded corpus was written with them.\n"
        f"8. Call SetupUsermodeCrashDetectionHooks() in Init.\n"
        f"9. ASCII only. No en dashes, no smart quotes: MSVC rejects them under /WX.\n\n"
        f"THE GUEST ADDRESS TYPE, quoted from wtf's own header. Every guest-memory call "
        f"takes it. Note there is NO implicit conversion either way, operator+ takes "
        f"another Gva_t (so `Addr + Gva_t(sizeof(x))`, never `Addr + sizeof(x)`), and the "
        f"accessor is U64():\n"
        f"```cpp\n{guest_address_type()}\n```\n\n"
        f"EXAMPLE -- a working module for a DIFFERENT target, showing the interface. Do "
        f"not copy its struct or its addresses; copy the shape.\n"
        f"```cpp\n{example}\n```\n"
    )


def check_generated(
    text: str, harness: HarnessSpec, spec: InputSpec | None = None
) -> list[str]:
    """Structural problems, so an unusable answer fails before the compiler does.

    Cheap checks only. The compiler is the real gate and this is not trying to be one --
    it exists so that "the model returned prose" produces a message about prose rather
    than four hundred lines of MSVC output.
    """
    problems: list[str] = []
    if not text.strip():
        problems.append("the model returned nothing")
        return problems

    if "```" in text:
        problems.append("the answer still contains a markdown fence")

    non_ascii = {ch for ch in text if ord(ch) > 127}
    if non_ascii:
        shown = ", ".join(f"U+{ord(c):04X}" for c in sorted(non_ascii)[:8])
        problems.append(
            f"non-ASCII characters ({shown}); MSVC rejects these under /WX with C4819 "
            f"on a non-UTF-8 codepage (D-054)"
        )

    # A NAMESPACE COLLISION is a link error four hundred lines later, and the linker's
    # message names mangled symbols rather than the mistake. Caught here instead.
    used = re.findall(r"^namespace\s+(\w+)\s*\{", text, re.M)
    clash = set(used) & existing_namespaces(
        REPO_ROOT / "fuzzer" / "module", exclude=REPO_ROOT / "fuzzer" / "module" / "fuzzer_gen.cc"
    )
    if clash:
        problems.append(
            f"namespace {sorted(clash)} is already used by another module in this "
            f"binary; every module links into one wtf.exe, so this is LNK2005 on Init, "
            f"Restore, InsertTestcase and the Target_t object"
        )

    if not re.search(r"\bTarget_t\s+\w+\s*\(\s*\"" + re.escape(harness.target_name), text):
        problems.append(
            f"no Target_t registration for {harness.target_name!r}; wtf would not know "
            f"the module exists and --name would fail"
        )
    for entry in ("Init", "InsertTestcase", "Restore"):
        if not re.search(rf"\b{entry}\s*\(", text):
            problems.append(f"no {entry} -- the Target_t constructor needs it")

    if "SetupUsermodeCrashDetectionHooks" not in text:
        problems.append(
            "Init does not call SetupUsermodeCrashDetectionHooks(), so crashes would "
            "not be detected and the campaign would report none"
        )

    # A breakpoint carrying an rva must be placed by address; see the prompt.
    if any(b.rva is not None for b in harness.breakpoints):
        if "ResolveModuleBase" not in text:
            problems.append(
                "the harness spec carries RVAs but the code never calls "
                "ResolveModuleBase, so breakpoints resolve by symbol -- which fails on a "
                "stripped target and kills every worker in Init (D-075)"
            )

    # THE PLACEMENT ARITHMETIC, which the model got wrong in a way nothing caught.
    #
    # Its module wrote `const uint64_t PageBase = Backend->Rcx();` and then added
    # `kPageSize - Bytes` to it. Rcx is a POINTER, not a page base: 0xd3d77ff7a0 + 0xff0
    # is 0xd3d7800790, past the end of the page and inside the unmapped hole. The
    # variable was even named PageBase, so the intent was right and only the mask was
    # missing -- which is exactly the kind of error a compiler cannot see and a coverage
    # number does not move for.
    #
    # Checked as a STRING because the fix is to call a helper rather than to do the
    # arithmetic: ResolveInputAddress owns the masking and the verified guard boundary,
    # so there is one right answer and the model's job is to call it.
    if re.search(r"kPageSize\s*-\s*\w*[Bb]ytes", text) and "ResolveInputAddress" not in text:
        problems.append(
            "the code computes a page-tail placement by hand instead of calling "
            "ResolveInputAddress(Pointer, Bytes). A raw register is a pointer, not a "
            "page base -- adding (kPageSize - Bytes) to it lands past the page end, "
            "where the write either fails or silently misses the guard page"
        )
    if re.search(r"(?:PageBase|Page)\s*=\s*\w+->R[a-z0-9]{2}\(\)\s*;", text):
        problems.append(
            "a raw register is assigned to something named like a page base without "
            "masking off the low 12 bits; use ResolveInputAddress instead"
        )

    # THE MODULE MUST NOT CALL GetModuleBase DIRECTLY. On a real snapshot it returned 0,
    # the breakpoint went to 0 + rva, and the campaign ran to completion reporting
    # coverage while delivering nothing (D-075). ResolveModuleBase falls back to
    # SNAPFUZZ_MODULE_BASE and REFUSES at zero. The check above only asked that
    # GetModuleBase appear at all, which the model satisfied by calling it raw.
    if re.search(r"g_Dbg->GetModuleBase", text) and "ResolveModuleBase" not in text:
        problems.append(
            "the code calls g_Dbg->GetModuleBase directly; use ResolveModuleBase, which "
            "falls back to SNAPFUZZ_MODULE_BASE and refuses at zero. GetModuleBase "
            "returned 0 on a real snapshot whose symbol-store.json named a different "
            "program, and a breakpoint at 0+rva never fires (D-075)"
        )

    # THE JSON KEYS ARE THE CORPUS'S KEYS, not a naming preference. `Json.at("Magic")`
    # throws on a recorded test-case written with "magic", the catch turns that into
    # "testcase is not valid JSON, skipping", and every input is skipped -- at full
    # speed, reporting coverage. The model picked C++-style capitals on its own, which is
    # reasonable style and the wrong contract.
    # THE TOP-LEVEL SHAPE IS THE SPEC'S TO DECIDE, NOT THE MODEL'S. With
    # deliver_sequence False a test-case is a single JSON object whose keys are the field
    # names; the model wrapped it in a `Packets_t` holding a vector anyway, so
    # `Root.get<Packets_t>()` threw on every file in the corpus, InsertTestcase caught it,
    # and each one was skipped as "not valid JSON". The campaign then ran with an empty
    # queue: the entry breakpoint fired, found nothing to deliver, and stopped -- 0
    # instructions executed and cov 1, reported as a clean run.
    if spec is not None and not harness.deliver_sequence:
        wrapper = re.search(
            rf"std::vector<\s*{re.escape(spec.struct_name)}\s*>", text
        )
        if wrapper:
            problems.append(
                f"deliver_sequence is False, so one test-case is a SINGLE "
                f"{spec.struct_name} and the JSON root is that object -- but the code "
                f"defines a sequence wrapper (std::vector<{spec.struct_name}>). Parsing "
                f"the root as a wrapper throws on every existing corpus file, and "
                f"InsertTestcase reports those as 'not valid JSON, skipping'"
            )

    # A DECLARED TERMINATOR MUST BE WRITTEN, and with a guard page behind the input the
    # cost of forgetting is total rather than partial. `fuzzme` opens with
    # `while (param_1[i] != '\0') i++`, so an unterminated input makes that scan walk off
    # the end -- into the unmapped page -- and EVERY input faults identically. Both probes
    # crashed at 3.3k instructions with cov 3089, which reads exactly like a found bug and
    # is the harness reading its own out-of-bounds.
    #
    # A weak check, deliberately: it only asks that the byte literal appear somewhere,
    # because "is this byte written after that field" is not decidable by grep. It catches
    # the case that happened -- no terminator anywhere in the file -- and nothing subtler.
    if spec is not None:
        for field in spec.fields:
            if field.terminator is None:
                continue
            literal = f"{field.terminator:#04x}"
            if literal not in text and f"'\\{field.terminator}'" not in text:
                problems.append(
                    f"field {field.name!r} is terminated by {literal} and that byte does "
                    f"not appear in the module. An unterminated input makes the target's "
                    f"scan read past the end; with a guard page behind the data every "
                    f"input then faults identically, which looks like a found bug"
                )

    if spec is not None:
        missing = [f.name for f in spec.fields if f'"{f.name}"' not in text]
        if missing:
            problems.append(
                f"from_json does not read the spec's field names as JSON keys: "
                f"{missing}. Those are the keys the recorded corpus and the seed "
                f"generator write; a renamed key means every test-case fails to parse "
                f"and is skipped silently"
            )
    return problems


def generate_module(
    spec: InputSpec,
    harness: HarnessSpec,
    *,
    client=None,
    role: str = "codegen",
    example_path: Path = EXAMPLE,
) -> tuple[str, list[str]]:
    """Ask the model for the module. Returns (source, structural warnings)."""
    from llm.client import LlmClient

    example = ""
    if example_path.is_file():
        example = example_path.read_text(encoding="utf-8", errors="replace")
        if len(example) > MAX_EXAMPLE_CHARS:
            example = example[:MAX_EXAMPLE_CHARS] + "\n// ...truncated...\n"

    own_client = client is None
    client = client or LlmClient.from_config()
    prompt = _prompt(spec, harness, example)
    try:
        completion = client.complete(role, prompt, system=_SYSTEM)
        text, problems = _finish(completion, harness, spec)

        # RETRY ONCE, WITH THE PROBLEMS. CP5 mandates this shape for structured output
        # and it applies here for the same reason: the checks already know the fix, so
        # refusing without saying so wastes a generation and leaves the user to re-run
        # and hope. Measured need, not caution -- the model wrote the unmasked
        # `PageBase = Backend->Rcx()` on the first attempt AND again on a fresh
        # generation, so "re-run and hope" is not a strategy.
        if problems:
            retry = (
                f"{prompt}\n\n"
                f"YOUR PREVIOUS ANSWER WAS REJECTED. Fix exactly these and return the "
                f"whole file again:\n"
                + "".join(f"  - {p}\n" for p in problems)
            )
            second = client.complete(role, retry, system=_SYSTEM)
            second_text, second_problems = _finish(second, harness, spec)
            # Keep the retry only if it is actually better. A second answer that trades
            # one problem for another is not progress, and silently preferring the later
            # one would hide that.
            if len(second_problems) < len(problems):
                return second_text, second_problems
    finally:
        if own_client:
            client.close()

    return text, problems


def compile_errors(module_out: Path) -> list[str]:
    """Build, and return the compiler's complaints about the generated module only.

    Filtered to the generated file because the build compiles every module in
    `fuzzer/module/`; an unrelated pre-existing error would otherwise be fed back to the
    model as though it were its own, and it would dutifully try to fix code it never
    wrote.
    """
    from fuzzer.build import BuildError, build

    try:
        build()
    except BuildError as exc:
        output = f"{exc}\n{getattr(exc, 'output', '')}"
        # `error C####:` is the MSVC diagnostic form; matching on " error " alone also
        # catches ninja's own "FAILED:" preamble and CMake chatter, which tells the model
        # nothing and crowds out the lines that do.
        mine = [
            line.strip()
            for line in output.splitlines()
            if module_out.name in line and re.search(r"\b(?:fatal )?error [A-Z]\d+:", line)
        ]
        if mine:
            return mine
        # Nothing named the generated file: the build broke somewhere else, and handing
        # the model someone else's error would have it edit code it never wrote.
        return [
            f"the build failed but no diagnostic named {module_out.name}; "
            f"the failure is elsewhere in the tree"
        ]
    return []


def repair_by_compiling(
    text: str,
    spec: InputSpec,
    harness: HarnessSpec,
    module_out: Path,
    *,
    attempts: int = 2,
    client=None,
    role: str = "codegen",
    example: str = "",
) -> tuple[str, list[str]]:
    """Write, compile, feed the errors back, repeat. Returns (text, remaining errors).

    THIS IS THE CHECK THIS MODULE CLAIMS. Its docstring argues that model-written C++ is
    defensible because "the result has to compile, under /WX, inside the real wtf tree" --
    but nothing was closing that loop, so a compile error ended the stage and left a human
    to paraphrase MSVC into the prompt. Which is what happened, three times, at eleven
    minutes a round: `Gva_t`'s constructor is explicit, so the model's `const Gva_t A =
    ResolveInputAddress(...)` is C2440, and prose about it did not stick.

    A compiler diagnostic is a better prompt than any description of the same rule: it
    names the line, the types and the operation. Feeding it back is not a workaround for a
    weak model, it is the loop a human uses.

    Bounded at `attempts` because a model that cannot fix its own compile error in two
    tries is not converging, and `--codegen template` exists for that.
    """
    from llm.client import LlmClient

    own_client = client is None
    client = client or LlmClient.from_config()
    base = _prompt(spec, harness, example)
    try:
        for attempt in range(attempts + 1):
            module_out.write_text(text, encoding="utf-8")
            errors = compile_errors(module_out)
            if not errors:
                if attempt:
                    print(f"  compiles after {attempt} repair attempt(s)")
                return text, []
            if attempt == attempts:
                return text, errors
            print(f"  compile attempt {attempt + 1} failed:")
            for line in errors[:6]:
                print(f"    {line}")
            repair = (
                f"{base}\n\n"
                f"YOUR PREVIOUS ANSWER DID NOT COMPILE. MSVC reported, against the file "
                f"you produced:\n"
                + "".join(f"  {e}\n" for e in errors[:12])
                + "\nReturn the WHOLE corrected file. Fix the reported lines; do not "
                "restructure what compiled.\n\nYour previous answer was:\n"
                f"{text}\n"
            )
            completion = client.complete(role, repair, system=_SYSTEM)
            text, _ = _finish(completion, harness, spec)
    finally:
        if own_client:
            client.close()
    return text, compile_errors(module_out)


def normalize_json_keys(text: str, spec: InputSpec) -> tuple[str, list[str]]:
    """Rewrite JSON key literals to the spec's exact spellings. Returns (text, changes).

    The model wrote `Json.at("Magic")` for a field named `magic`, and kept doing it after
    being told twice -- explicitly in the prompt, then again in a retry naming the three
    keys. Which is fair enough: `Magic` is better C++ style, and the instruction fights
    the habit of every codebase it has read.

    So stop asking. Member name to JSON key is a MECHANICAL mapping, and the same
    reasoning that moved the placement arithmetic into snapfuzz_resolve.h applies here:
    when there is exactly one right answer, ordinary code should produce it. The model
    still decides the struct, the parsing, the delivery and the oracle -- it just no
    longer decides the spelling of a wire contract.

    Only literals in a JSON accessor are touched (`Json.at`, `.value`, `Json[...]`), so
    the target name and other strings are left alone. Every change is returned, because a
    silent rewrite of model output is how you stop being able to read a generation.
    """
    changes: list[str] = []
    for field in spec.fields:
        wanted = field.name
        variants = {
            wanted.replace("_", ""),
            "".join(p.title() for p in wanted.split("_")),          # payload_len -> PayloadLen
            wanted.split("_")[0]
            + "".join(p.title() for p in wanted.split("_")[1:]),    # -> payloadLen
            wanted.title(),
            wanted.upper(),
        }
        variants.discard(wanted)
        for variant in sorted(variants, key=len, reverse=True):
            pattern = re.compile(
                r'((?:Json|json|Root|J)\s*(?:\.at|\.value|\[)\s*\(?\s*)"'
                + re.escape(variant)
                + r'"'
            )
            text, count = pattern.subn(lambda m: f'{m.group(1)}"{wanted}"', text)
            if count:
                changes.append(f'{variant!r} -> {wanted!r} ({count}x)')
    return text, changes


def _finish(
    completion, harness: HarnessSpec, spec: InputSpec | None = None
) -> tuple[str, list[str]]:

    # `completion.content`, NOT `completion.text`. The first version used a hasattr
    # fallback and therefore wrote the dataclass REPR to the file -- the whole module on
    # one line, with the C++ escaped inside it. A hasattr guard on an attribute name that
    # does not exist silently produces the wrong thing instead of an AttributeError,
    # which is why the field is named outright here.
    text = completion.content
    # Models fence code even when told not to. Stripping it is not indulgence: the
    # alternative is a file whose first line is ```cpp, which fails to compile for a
    # reason that says nothing about the harness.
    text = _strip_fence(text)
    if spec is not None:
        text, renamed = normalize_json_keys(text, spec)
        for change in renamed:
            print(f"  [json key] {change}")
    return text, check_generated(text, harness, spec)


def _strip_fence(text: str) -> str:
    match = re.search(r"```(?:cpp|c\+\+|c)?\s*\n(.*?)```", text, re.S)
    if match:
        return match.group(1)
    return text


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--spec", required=True, type=Path)
    ap.add_argument("--harness", required=True, type=Path)
    ap.add_argument("--module-out", required=True, type=Path)
    ap.add_argument(
        "--allow-warnings",
        action="store_true",
        help="write the file even if the structural checks complain. The compiler is "
             "still the gate; this is for inspecting a bad generation",
    )
    ap.add_argument(
        "--compile-retries",
        type=int,
        default=2,
        metavar="N",
        help="build the generated module and feed MSVC's errors back for up to N "
             "repairs (default 2). 0 leaves the build to stage 10. This is the check "
             "this generator claims: a diagnostic naming the line and the types is a "
             "better prompt than prose about the same rule",
    )
    args = ap.parse_args(argv)

    spec = InputSpec.model_validate_json(args.spec.read_text(encoding="utf-8"))
    harness = HarnessSpec.model_validate_json(args.harness.read_text(encoding="utf-8"))

    source, problems = generate_module(spec, harness)
    for problem in problems:
        print(f"  [warn] {problem}")
    if problems and not args.allow_warnings:
        raise SystemExit(
            f"{len(problems)} structural problem(s) in the generated module; refusing "
            f"to write it. Re-run, pass --allow-warnings to inspect it, or use "
            f"`python -m fuzzer.codegen` for the deterministic renderer."
        )

    args.module_out.parent.mkdir(parents=True, exist_ok=True)
    args.module_out.write_text(source, encoding="utf-8")
    print(f"{harness.entry_symbol}: wtf target {harness.target_name!r}")
    print(f"wrote {args.module_out} ({len(source.splitlines())} lines)")

    if args.compile_retries > 0:
        source, errors = repair_by_compiling(
            source, spec, harness, args.module_out, attempts=args.compile_retries
        )
        if errors:
            # The file is left on disk deliberately: `--compile-retries 0` plus an editor
            # is the next step, and deleting the evidence would make that harder.
            raise SystemExit(
                f"the generated module still does not compile after "
                f"{args.compile_retries} repair attempt(s):\n"
                + "".join(f"  {e}\n" for e in errors[:8])
                + f"It is left at {args.module_out} to inspect. Use "
                f"`python -m fuzzer.codegen` for the deterministic renderer."
            )
        print("  compiles clean under /WX")
    else:
        print("  the compiler is the check -- stage 10 builds it next")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
