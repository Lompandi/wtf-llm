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


def _prompt(spec: InputSpec, harness: HarnessSpec, example: str) -> str:
    fields = "\n".join(
        f"  {i}. {f.name}: kind={f.kind} ctype={f.ctype or 'bytes'} "
        f"little_endian={f.little_endian}"
        + (f" counts={f.counts_field} in {f.unit}" if f.kind == "length" else "")
        + (f" includes_header={f.includes_header}" if f.kind == "length" else "")
        + (f" magic={f.magic_value:#x}" if f.magic_value is not None else "")
        + (f" max_length={f.max_length}" if f.max_length else "")
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
        f"BREAKPOINTS to install in Init:\n{breakpoints or '  (none beyond the entry)'}\n\n"
        f"REQUIREMENTS\n"
        f"1. Put EVERYTHING in `namespace {required_namespace(spec)} {{ ... }}` and "
        f"name the registration object `{required_namespace(spec)}Target`. Every module "
        f"in this project links into ONE wtf.exe, so reusing the example's namespace or "
        f"its object name is a link error (LNK2005 on Init, Restore, InsertTestcase and "
        f"the Target_t object). Do not copy the example's namespace.\n"
        f"7. Register with: Target_t {required_namespace(spec)}Target"
        f"(\"{harness.target_name}\", Init, InsertTestcase, Restore, "
        f"CustomMutator_t::Create);\n"
        f"2. A breakpoint whose spec carries an `rva` MUST be placed BY ADDRESS: "
        f"Gva_t(g_Dbg->GetModuleBase(\"<module>\") + rva). A stripped target has no "
        f"symbols for dbgeng, so a name-resolved breakpoint fails and every worker dies "
        f"in Init.\n"
        f"3. A length field is RECOMPUTED from what it counts when serialising, never "
        f"taken from the test-case: a mutated length that disagrees with the payload is "
        f"rejected at the parser's first check.\n"
        f"4. Where a field lists also_reads, from_json must accept those keys too -- a "
        f"recorded corpus was written with them.\n"
        f"5. Call SetupUsermodeCrashDetectionHooks() in Init.\n"
        f"6. ASCII only. No en dashes, no smart quotes: MSVC rejects them under /WX.\n\n"
        f"EXAMPLE -- a working module for a DIFFERENT target, showing the interface. Do "
        f"not copy its struct or its addresses; copy the shape.\n"
        f"```cpp\n{example}\n```\n"
    )


def check_generated(text: str, harness: HarnessSpec) -> list[str]:
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
        if "GetModuleBase" not in text:
            problems.append(
                "the harness spec carries RVAs but the code never calls GetModuleBase, "
                "so breakpoints resolve by symbol -- which fails on a stripped target "
                "and kills every worker in Init (D-075)"
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
    try:
        completion = client.complete(
            role, _prompt(spec, harness, example), system=_SYSTEM
        )
    finally:
        if own_client:
            client.close()

    # , not . The first version used a hasattr fallback to
    #  and therefore wrote the dataclass REPR to the file -- one line,
    # with the C++ escaped inside it. A hasattr guard on an attribute name that does not
    # exist silently produces the wrong thing instead of an AttributeError, which is why
    # the field is now named outright.
    text = completion.content
    # Models fence code even when told not to. Stripping it is not indulgence: the
    # alternative is a file whose first line is ```cpp, which fails to compile for a
    # reason that says nothing about the harness.
    text = _strip_fence(text)
    return text, check_generated(text, harness)


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
    print("  the compiler is the check -- stage 10 builds it next")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
