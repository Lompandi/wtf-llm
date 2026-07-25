"""Slow-clock seed generation (CLAUDE.md CP7).

On plateau, ask the LLM for concrete inputs that reach branches the fuzzer has
arrived at but never taken.

**What is sent, and what is not.** Section 7.3 and section 10 forbid sending the
raw corpus or a full coverage bitmap. What goes out is:

* the `CoverageSummary` numbers -- a handful of integers;
* the **frontier**: covered blocks with unreached successors, which is the
  actionable part of coverage rather than all of it;
* pseudo-C of only the functions *containing* frontier blocks, from A2;
* one existing seed, as a format example.

That last item matters more than it looks. Without it the model has to guess the
wire format, and a syntactically wrong seed is rejected by `InsertTestcase`
before it reaches any branch -- it would execute, produce nothing, and look like
the LLM having no useful ideas.

**RULE 1.** This module runs in the sidecar, a separate process (section 12.2).
It never runs inside the master or a worker: `GetNewTestcase()` is called per
test-case with every worker waiting, and an LLM round trip there would stall the
whole campaign.
"""

from __future__ import annotations

import binascii
import json
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel, Field, model_validator

from arch.contracts import CoverageSummary, SeedRecord
from engine_bridge.plateau import FrontierBlock
from llm.client import LlmClient
from prep.pseudoc_cache import PseudoCCache

__all__ = [
    "SeedGenError",
    "SeedGenRequest",
    "generate_seeds",
    "format_target",
    "parse_target",
]

# Enough pseudo-C to reason about a branch, not enough to blow the budget. A
# reasoning model spends its max_tokens on thinking (D-030), so the prompt has
# to leave room for that.
_MAX_PSEUDOC_CHARS_PER_FUNCTION = 6000
_MAX_FUNCTIONS = 4


class SeedGenError(RuntimeError):
    pass


class _SeedBase(BaseModel):
    """Fields every proposed seed carries, whatever the wire format."""

    targets_branch: str = Field(
        description=(
            "the unreached branch address this aims at, copied verbatim and in "
            "full from the list given in the prompt, e.g. 0x1400012de"
        )
    )
    rationale: str = Field(
        description="why this input should reach that branch, in one sentence"
    )

    def to_bytes(self) -> bytes:  # pragma: no cover - overridden
        raise NotImplementedError


class _TextSeed(_SeedBase):
    """A seed for a textual wire format."""

    content: str = Field(
        description=(
            "the seed as text, in exactly the same format as the example in the "
            "prompt"
        )
    )

    def to_bytes(self) -> bytes:
        return self.content.encode("utf-8")


class _BinarySeed(_SeedBase):
    """A seed for a binary wire format."""

    content_hex: str = Field(
        description="the seed as hex bytes; no 0x prefix, no spaces"
    )

    def to_bytes(self) -> bytes:
        cleaned = "".join(self.content_hex.split()).removeprefix("0x")
        try:
            return binascii.unhexlify(cleaned)
        except binascii.Error as exc:
            raise SeedGenError(f"content_hex is not valid hex: {exc}") from exc


class _TextBatch(BaseModel):
    seeds: list[_TextSeed] = Field(description="the proposed inputs")
    analysis: str = Field(description="one or two sentences on the approach")


class _BinaryBatch(BaseModel):
    seeds: list[_BinarySeed] = Field(description="the proposed inputs")
    analysis: str = Field(description="one or two sentences on the approach")


def _batch_model(wire_format: str) -> type[BaseModel]:
    """The schema to constrain the model with, chosen by wire format.

    **One content field, never two.** Offering both `content` and `content_hex`
    and asking for the right one in prose does not work: measured across three
    rounds the model repeatedly answered in `content_hex` for a JSON target, and
    a hex string of arbitrary text unhexlifies into bytes the parser discards --
    so the round produced eight seeds and zero usable ones (D-041, D-046). The
    schema is the only instruction the model cannot ignore, so the field it must
    not use is removed from it.
    """
    return _TextBatch if wire_format == "json" else _BinaryBatch


_TARGET_PREFIX = "targets "


def format_target(addr: str) -> str:
    """The `targets <addr>: ` prefix stored in `SeedRecord.rationale`."""
    return f"{_TARGET_PREFIX}{addr}"


def parse_target(rationale: str) -> int | None:
    """Recover the aimed-at address from a `SeedRecord.rationale`.

    Paired with :func:`format_target` so the two never drift. Returns None when
    the model named something that is not an address -- it is asked for one, but
    a free-text field is a free-text field.
    """
    if not rationale.startswith(_TARGET_PREFIX):
        return None
    token = rationale[len(_TARGET_PREFIX) :].split(":", 1)[0].strip()
    try:
        return int(token, 16) if token.lower().startswith("0x") else int(token, 16)
    except ValueError:
        return None


def _matches_wire_format(data: bytes, wire_format: str) -> bool:
    """Would the target's InsertTestcase accept this at all?

    Cheap structural check, not semantic validation. The point is to catch a seed
    in the wrong *encoding* -- hex bytes where the target wants JSON text -- which
    is otherwise indistinguishable from the LLM having nothing useful to say.
    """
    if wire_format != "json":
        return True  # binary formats: anything non-empty is plausible
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(parsed, (dict, list))


@dataclass
class SeedGenRequest:
    """Everything the prompt needs, assembled by the sidecar."""

    summary: CoverageSummary
    frontier: list[FrontierBlock]
    example_seed: bytes
    wire_format: str = "json"
    want: int = 8
    # Harness capabilities the example seed does not show. Without this the model
    # cannot know a field exists, so a branch guarded by it stays unreachable no
    # matter how well the model reasons (D-040).
    format_notes: str = ""
    # {static_addr: times already aimed at without ever becoming covered}.
    # Measured feedback from the fuzzer, not a hint from us. Without it every
    # round re-derives the same wrong idea: CP7 watched three consecutive rounds
    # spend 6 of 8 seeds on two branches that are unreachable by any input, and
    # nothing in the prompt could tell the model they had already been tried
    # (D-044).
    attempted: dict[int, int] = field(default_factory=dict)
    # Pre-rendered table of the globals the frontier functions touch, from
    # `prep.data_symbols.format_globals`. Empty string when unavailable, which
    # only costs reasoning quality -- never correctness (D-047).
    globals_table: str = ""
    # CP10 ablation (b). When True the prompt states that the code was withheld
    # rather than quietly omitting it, so a transcript cannot be mistaken for a
    # normal round.
    without_pseudoc: bool = False


def _frontier_context(
    request: SeedGenRequest, cache: PseudoCCache
) -> tuple[str, list[str]]:
    """Frontier description plus pseudo-C, deduplicated by function."""
    by_function: dict[str, list[FrontierBlock]] = {}
    for block in request.frontier:
        by_function.setdefault(block.function or "<unknown>", []).append(block)

    # Functions with the most unreached branches first -- that is where the
    # unexplored behaviour is concentrated.
    ranked = sorted(
        by_function.items(),
        key=lambda kv: -sum(b.degree for b in kv[1]),
    )[:_MAX_FUNCTIONS]

    lines: list[str] = []
    code_blocks: list[str] = []
    used: list[str] = []

    for function, blocks in ranked:
        used.append(function)
        lines.append(f"Function {function}:")
        for block in blocks:
            # Static addresses, matching how the reached block is stated. Mixing
            # in RVAs here is what made the model report an RVA as the branch it
            # aimed at, which no coverage check could ever match (D-045).
            targets = ", ".join(
                f"{s:#x}" for s in block.unreached_successor_statics
            )
            lines.append(
                f"  reached {block.static_addr:#x}, but never took the branch to "
                f"{targets}"
            )

        entry = cache.get_by_function(function)
        if entry is None:
            continue
        code = entry.code
        if len(code) > _MAX_PSEUDOC_CHARS_PER_FUNCTION:
            code = (
                code[:_MAX_PSEUDOC_CHARS_PER_FUNCTION]
                + "\n/* ...truncated... */\n"
            )
        code_blocks.append(f"=== {function} ===\n{code}")

    return "\n".join(lines) + "\n\n" + "\n\n".join(code_blocks), used


def _strip_pseudoc(context: str) -> str:
    """Keep the frontier description, drop the code blocks.

    The ``=== function ===`` blocks appended by :func:`_frontier_context` are the
    pseudo-C; everything before the first one is the branch listing.
    """
    marker = context.find("\n=== ")
    listing = context if marker < 0 else context[:marker]
    return (
        listing.rstrip()
        + "\n\n(The decompiled code of these functions is deliberately withheld "
        "in this run. Reason from the branch addresses and the input format "
        "alone.)\n"
    )


_SYSTEM = (
    "You generate fuzzing inputs for a coverage-guided snapshot fuzzer. You are "
    "shown Ghidra decompiler output from a binary with NO source, plus the "
    "branches the fuzzer has reached but never taken. Decompiled pseudo-C is "
    "lossy: names may be invented and types are inferred. Produce inputs that "
    "satisfy the concrete conditions guarding those branches -- magic values, "
    "length fields consistent or deliberately inconsistent, required orderings."
)


def _prompt(request: SeedGenRequest, context: str) -> str:
    summary = request.summary
    example = request.example_seed.decode("utf-8", errors="replace")

    notes = (
        f"ADDITIONAL FIELDS THE EXAMPLE DOES NOT SHOW:\n{request.format_notes}\n\n"
        if request.format_notes
        else ""
    )

    # Feedback from the previous rounds. This is the only thing in the prompt
    # that is *measured* rather than static, and it is what stops the round from
    # being one-shot prompting repeated N times.
    stale = ""
    if request.attempted:
        listed = ", ".join(
            f"{addr:#x} (tried {n}x)"
            for addr, n in sorted(
                request.attempted.items(), key=lambda kv: (-kv[1], kv[0])
            )
        )
        stale = (
            f"ALREADY TRIED AND STILL NOT REACHED: {listed}\n"
            f"Earlier rounds aimed at these and the fuzzer confirms they are "
            f"still uncovered, so whatever was tried did not work. For each one, "
            f"either name a CONCRETELY DIFFERENT mechanism than 'set the right "
            f"field value' -- a longer sequence, a different command order, an "
            f"earlier packet that changes state -- or judge it unreachable and "
            f"spend the seed elsewhere.\n"
            f"Some branches genuinely cannot be reached by any input. A null "
            f"check on a pointer that the lines just above it set to null, or a "
            f"C++ smart-pointer cleanup path on an object that was just "
            f"constructed empty, is dead code the decompiler still shows as a "
            f"branch. Say so in `analysis` and move on rather than producing a "
            f"seed you do not believe in.\n\n"
        )

    # The schema already admits only the right field (see _batch_model), so this
    # is a reminder of the FORMAT, not of which field to use.
    channel = (
        "Each input goes in `content`, as text in exactly the same format as the "
        "example above -- same field names, same nesting.\n\n"
        if request.wire_format == "json"
        else "Each input goes in `content_hex`, as hex bytes.\n\n"
    )

    return (
        f"The fuzzer has plateaued.\n\n"
        f"Coverage: {summary.total_edges} blocks covered, corpus "
        f"{summary.corpus_size} inputs, {len(request.frontier)} frontier blocks "
        f"(covered blocks with an unreached successor).\n\n"
        f"UNREACHED BRANCHES AND THE CODE AROUND THEM\n"
        f"{context}\n\n"
        f"{request.globals_table}"
        f"AN INPUT THAT THE TARGET ACCEPTS TODAY, as a format example "
        f"({request.wire_format}):\n{example}\n\n"
        f"{notes}"
        f"{stale}"
        f"Produce {request.want} NEW inputs, each aimed at a specific unreached "
        f"branch listed above. Set targets_branch to that branch's address "
        f"copied VERBATIM AND IN FULL from the list above -- do not shorten it "
        f"or drop leading digits, because it is matched against measured "
        f"coverage. Explain in one sentence why the input should get there.\n\n"
        f"{channel}"
        f"Vary the inputs: identical or near-identical seeds waste the round. "
        f"Prefer values the code visibly compares against -- constants, length "
        f"fields, command or type discriminants."
    )


def generate_seeds(
    request: SeedGenRequest,
    client: LlmClient,
    cache: PseudoCCache,
) -> list[SeedRecord]:
    """One seed-generation round. Returns validated `SeedRecord`s."""
    if not request.frontier:
        raise SeedGenError(
            "the frontier is empty, so there is nothing to aim at. Either "
            "coverage is complete or the frontier was not computed -- check that "
            "A3 has successor edges and that cov traces were parsed."
        )

    context, functions = _frontier_context(request, cache)
    if not functions:
        raise SeedGenError(
            "no frontier function has pseudo-C in A2. Build A2 over a scope that "
            "includes the frontier, or seed generation is reasoning blind."
        )

    # CP10 ablation (b): no pseudo-C in the prompt. The frontier addresses stay,
    # so the model still knows WHICH branches are unreached -- it just cannot read
    # the code guarding them. That isolates "reasoning over decompiled code" from
    # "an LLM producing structurally valid inputs", which is the distinction the
    # project's second contribution rests on.
    if request.without_pseudoc:
        context = _strip_pseudoc(context)

    batch = client.complete_json(
        "seed_gen",
        _prompt(request, context),
        _batch_model(request.wire_format),
        system=_SYSTEM,
    )

    records: list[SeedRecord] = []
    seen: set[bytes] = set()
    rejected_format = 0
    rejected_sample = b""

    for seed in batch.seeds:
        try:
            data = seed.to_bytes()
        except SeedGenError:
            continue  # a malformed seed is not worth failing the round over
        if not data or data in seen:
            continue

        # Reject seeds the target cannot even parse, BEFORE spending a worker on
        # them. Measured: with temperature 0.9 the model sometimes answers in
        # `content_hex` for a textual format, and a short hex string unhexlifies
        # into a handful of raw bytes -- 5-byte "seeds" that InsertTestcase
        # discards. They consume a slot, produce nothing, and make the round look
        # like the LLM had no useful ideas (D-041).
        if not _matches_wire_format(data, request.wire_format):
            rejected_format += 1
            rejected_sample = rejected_sample or data[:120]
            continue

        seen.add(data)
        records.append(
            SeedRecord(
                seed_bytes=data,
                origin="llm_seed_gen",
                rationale=f"{format_target(seed.targets_branch)}: {seed.rationale}",
            )
        )

    if not records:
        raise SeedGenError(
            f"the model returned {len(batch.seeds)} seeds and none survived "
            f"validation ({rejected_format} rejected as not valid "
            f"{request.wire_format}; first one began {rejected_sample!r}). "
            f"Analysis was: {batch.analysis!r}"
        )
    if rejected_format:
        print(
            f"  [warn] dropped {rejected_format} seed(s) that were not valid "
            f"{request.wire_format}"
        )
    return records
