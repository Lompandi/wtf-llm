"""LLM fuzz-entry selection (CLAUDE.md CP6) -- contribution 1.

Automates the decision that normally requires a reverse-engineering expert and
is snapshot fuzzing's main usability barrier: *which function do I snapshot at,
and how does its input arrive?*

Two-stage, because a real module has hundreds of functions and their combined
pseudo-C does not fit in a prompt (and section 7.3 forbids raw dumps anyway):

1. **Shortlist.** Every candidate's *signature* plus its size, which is cheap.
   The model names up to N plausible parsers.
2. **Choose.** Full pseudo-C for the shortlist only, and the model picks one and
   describes how input arrives.

**The model never supplies an address.** It returns a function *name*, and the
static address is looked up in A2. An LLM that hallucinates a plausible-looking
hex address would produce a `FuzzEntry` that validates, snapshots somewhere
arbitrary, fuzzes happily and reports coverage -- the exact silent failure RULE 4
exists to prevent. Names are checkable; addresses are not.

**Slow clock.** Runs once per target, off the fast path (RULE 1).
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, Field

from arch.addr import AddressSpace
from arch.contracts import FuzzEntry
from llm.client import LlmClient
from prep.pseudoc_cache import PseudoCCache

REPO_ROOT = Path(__file__).resolve().parents[1]

__all__ = ["EntrySelectionError", "Candidate", "select_entry"]

# Names that are never the parser: CRT scaffolding, allocator plumbing, thunks.
# A cheap filter, not a judgement -- it removes noise the model would have to
# read past, and every exclusion is a name pattern rather than a guess about
# behaviour.
_NOISE = re.compile(
    r"^(_+|\$|\?)|"
    r"(^|_)(printf|puts|malloc|free|memcpy|memset|strlen|strcpy)$|"
    r"operator_(new|delete)|"
    r"^std::|"
    r"bad_alloc|bad_array_new_length|"
    r"dynamic_(initializer|atexit)|"
    r"scrt_|security_(check|init)|"
    r"^_?guard_",
    re.IGNORECASE,
)


class EntrySelectionError(RuntimeError):
    pass


@dataclass(frozen=True)
class Candidate:
    function: str
    static_addr: int
    signature: str
    code_chars: int


class _Shortlist(BaseModel):
    """Stage 1 output."""

    functions: list[str] = Field(
        description="function names, most likely parser first"
    )
    reasoning: str = Field(description="one or two sentences")


class _Choice(BaseModel):
    """Stage 2 output. Deliberately has no address field."""

    function: str = Field(description="the chosen function's exact name")
    input_param: str = Field(
        description=(
            "where the input buffer arrives: a register name like 'rcx' when the "
            "register HOLDS the buffer's address, '&rcx' when the register IS the "
            "buffer, or 'arg:N' for the Nth stack argument"
        )
    )
    size_param: str | None = Field(
        default=None,
        description=(
            "register or slot carrying the input LENGTH IN BYTES, e.g. 'rdx'; "
            "null if the input is self-delimiting"
        )
    )
    rationale: str = Field(
        description="why this function is the right place to inject fuzz input"
    )
    confidence: float = Field(description="0.0 to 1.0")


def _signature_of(code: str) -> str:
    """First non-empty, non-comment line of pseudo-C -- the declaration."""
    for line in code.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith(("/*", "//", "*")):
            return stripped
    return "<no signature>"


def candidates(
    cache: PseudoCCache, *, module: str | None = None, drop_noise: bool = True
) -> list[Candidate]:
    out: list[Candidate] = []
    for name in cache.functions(module):
        if drop_noise and _NOISE.search(name):
            continue
        entry = cache.get_by_function(name, module=module)
        if entry is None:
            continue
        out.append(
            Candidate(
                function=name,
                static_addr=entry.static_addr,
                signature=_signature_of(entry.code),
                code_chars=len(entry.code),
            )
        )
    return out


_SYSTEM = (
    "You are a reverse engineer choosing where to place a snapshot for a "
    "coverage-guided snapshot fuzzer. You are given Ghidra decompiler output "
    "from a binary with NO source. Decompiled pseudo-C is lossy: names may be "
    "invented, types are inferred, and inlining is flattened. Reason from "
    "structure and behaviour, not from names you cannot verify."
)


def _shortlist_prompt(cands: list[Candidate], want: int) -> str:
    lines = [
        f"{c.function}  ::  {c.signature}  [{c.code_chars} chars]" for c in cands
    ]
    return (
        f"Here are {len(cands)} functions from one module, as "
        f"`name :: signature [size]`.\n\n"
        + "\n".join(lines)
        + f"\n\nPick at most {want} that are most likely to be a PARSER of "
        f"attacker-controlled input -- a function that takes a buffer and a "
        f"length and interprets the bytes. Prefer functions that look like they "
        f"validate a header, branch on a command or type field, or copy into "
        f"allocated memory. Ignore CRT and allocator plumbing."
    )


def _resolve_name(reported: str, known: dict[str, Candidate]) -> str | None:
    """Map a model-reported name onto a real one, or None.

    Deliberately narrow. Models echo whatever decoration the prompt used -- this
    one returned "ProcessPacket @ 0x140001150" because an earlier header format
    included the address -- and that is a formatting artefact, not a wrong
    answer. But the check must still reject an invented name, because the whole
    point of not letting the model supply addresses is that names are checkable.
    """
    name = reported.strip()
    if name in known:
        return name

    # Strip a trailing " @ 0x..." or "@0x...", which is header echo.
    stripped = re.sub(r"\s*@\s*0x[0-9a-fA-F]+\s*$", "", name).strip()
    if stripped in known:
        return stripped

    # Strip surrounding punctuation a model might add.
    bare = stripped.strip("`'\"()[]<>= ")
    if bare in known:
        return bare

    lowered = {k.lower(): k for k in known}
    return lowered.get(bare.lower())


def _choose_prompt(
    cache: PseudoCCache, shortlist: list[Candidate], module: str | None = None
) -> str:
    """The final prompt: each shortlisted function's full body.

    ``module`` is not optional in spirit. The shortlist in stage 1 is built by
    ``candidates(module=...)`` and is therefore correct; this lookup was unqualified,
    so on a shared A2 the model read ANOTHER binary's function under the right name.
    It then chose ``input_param`` and ``size_param`` from that body, and those two
    fields are copied into the FuzzEntry, carried into the HarnessSpec, and compiled
    into the harness's register writes -- so the harness would write fuzz bytes into a
    register chosen by reading a different program, execute millions of cases, report
    coverage, and never actually inject a test-case. The printed shortlist looks
    right, because the shortlist WAS right (D-073).
    """
    blocks = []
    for c in shortlist:
        entry = cache.get_by_function(c.function, module=module)
        code = entry.code if entry else "<unavailable>"
        # No address in the header: the model must not supply one, and including
        # it only invites the name being echoed back with it attached.
        blocks.append(f"=== FUNCTION: {c.function} ===\n{code}")

    return (
        "Full decompiler output for the shortlisted functions:\n\n"
        + "\n\n".join(blocks)
        + "\n\nChoose the ONE function to snapshot at, and describe how its input "
        "arrives.\n\n"
        "This is an x86-64 Windows binary, so the calling convention puts the "
        "first four integer/pointer arguments in rcx, rdx, r8, r9 and the rest "
        "on the stack.\n\n"
        "For input_param, use the bare register name (e.g. 'rcx') when that "
        "register HOLDS THE ADDRESS of the buffer, and '&rcx' when the register "
        "IS the buffer value itself. For size_param, give the register carrying "
        "the length IN BYTES, or null if the input is self-delimiting.\n\n"
        "Use the exact function name as given above."
    )


def select_entry(
    cache: PseudoCCache,
    client: LlmClient,
    *,
    module: str | None = None,
    shortlist_size: int = 5,
    ghidra_image_base: int | None = None,
) -> tuple[FuzzEntry, _Choice, list[str]]:
    """Pick the fuzz entry. Returns (FuzzEntry, raw choice, shortlist names)."""
    cands = candidates(cache, module=module)
    if not cands:
        raise EntrySelectionError(
            "no candidate functions in A2 after filtering. Build A2 with "
            "--scope=module so there is something to choose between."
        )

    by_name = {c.function: c for c in cands}

    # Stage 1 -- shortlist from signatures.
    if len(cands) <= shortlist_size:
        shortlist = list(cands)
        shortlist_names = [c.function for c in shortlist]
    else:
        picked = client.complete_json(
            "entry_select",
            _shortlist_prompt(cands, shortlist_size),
            _Shortlist,
            system=_SYSTEM,
        )
        shortlist_names = [n for n in picked.functions if n in by_name]
        unknown = [n for n in picked.functions if n not in by_name]
        if unknown:
            # Do not silently drop: a model inventing names is a signal about
            # how much to trust the rest of its answer.
            print(f"  [warn] shortlist named {len(unknown)} unknown function(s): {unknown}")
        if not shortlist_names:
            raise EntrySelectionError(
                f"the shortlist named no known function; it returned "
                f"{picked.functions}"
            )
        shortlist = [by_name[n] for n in shortlist_names[:shortlist_size]]

    # Stage 2 -- choose, with full pseudo-C.
    choice = client.complete_json(
        "entry_select",
        _choose_prompt(cache, shortlist, module),
        _Choice,
        system=_SYSTEM,
    )

    resolved = _resolve_name(choice.function, by_name)
    if resolved is None:
        raise EntrySelectionError(
            f"the model chose {choice.function!r}, which is not a function in A2. "
            f"Candidates were: {shortlist_names}. An unrecognised name is why the "
            f"model is not trusted with addresses -- names can be checked."
        )
    if resolved != choice.function.strip():
        print(f"  [note] normalised chosen name {choice.function!r} -> {resolved!r}")

    chosen = by_name[resolved]
    entry_cache = cache.get_by_function(chosen.function, module=module)
    assert entry_cache is not None

    fuzz_entry = FuzzEntry(
        module=entry_cache.module,
        symbol=chosen.function,
        # Ours, from A2 -- never the model's.
        static_addr=chosen.static_addr,
        rationale=(
            f"{choice.rationale} "
            f"[LLM-selected, confidence {choice.confidence:.2f}; "
            f"shortlisted from {len(cands)} candidates]"
        ),
        input_param=choice.input_param,
        size_param=choice.size_param,
    )
    return fuzz_entry, choice, shortlist_names


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--cache", type=Path, default=REPO_ROOT / "artifacts" / "a2_pseudoc.sqlite"
    )
    ap.add_argument("--module")
    ap.add_argument("--shortlist-size", type=int, default=5)
    ap.add_argument(
        "--out", type=Path, default=REPO_ROOT / "artifacts" / "fuzz_entry_llm.json"
    )
    ap.add_argument("--module-base", type=lambda s: int(s, 0))
    ap.add_argument("--ghidra-image-base", type=lambda s: int(s, 0))
    args = ap.parse_args(argv)

    with PseudoCCache(args.cache) as cache, LlmClient.from_config() as client:
        cands = candidates(cache, module=args.module)
        print(f"candidates after filtering: {len(cands)}")

        entry, choice, shortlist = select_entry(
            cache,
            client,
            module=args.module,
            shortlist_size=args.shortlist_size,
        )

        print(f"shortlist   : {shortlist}")
        print()
        print(f"CHOSEN      : {entry.symbol}")
        print(f"  static    : {entry.static_addr:#x}")
        if args.module_base and args.ghidra_image_base:
            space = AddressSpace(entry.module, args.module_base, args.ghidra_image_base)
            print(f"  runtime   : {space.to_runtime(entry.static_addr):#x}")
        print(f"  input     : {entry.input_param}")
        print(f"  size      : {entry.size_param}")
        print(f"  confidence: {choice.confidence:.2f}")
        print(f"  rationale : {choice.rationale}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(entry.model_dump_json(indent=2), encoding="utf-8")
    print()
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
