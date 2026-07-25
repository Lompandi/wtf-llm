"""Crash-site static context (CLAUDE.md CP8, edges 37/37b, triage signal 5).

Assembles what the *code* says about a crash: pseudo-C of the relevant function,
the globals it touches, and the approach path through our own module.

**NO LLM IN THIS MODULE.** It imports :mod:`llm.ghidra_mcp`, which despite its
location is a **decompiler** client -- it asks a Ghidra plugin over HTTP to
decompile an address. No model is invoked, no prompt is sent, and GATE 8's no-LLM
assertion is about :mod:`llm.client`. The gate test checks for that specifically.

Signal 5 is deliberately kept separate from signal 4
----------------------------------------------------
Signal 4 is dynamic (what executed), signal 5 is static (what the code says).
Their errors are uncorrelated, which is the entire point of the multi-signal
design (section 3.2, edges 41/41b), so section 10 forbids collapsing them into
one blob. This module produces only the static half and takes the dynamic half as
an *input* rather than recomputing it.

The problem this module exists to solve
---------------------------------------
Section 8 says reverse.py returns pseudo-C "of the faulting function". On the
measured crash set that returns **nothing**, and would keep returning nothing
forever: every fault is in ``VCRUNTIME140.dll!memmove``, and A2 covers
tlv_server. We will never have pseudo-C for the CRT's memcpy, and if we did it
would explain nothing -- memcpy is not where the bug is.

What *does* have pseudo-C is the code in our module that called into it with a
bad length. So the context is anchored on the **deepest frame that is inside the
target module**, and every returned object says which frame it describes.
Labelling matters more than usual here: a reader handed pseudo-C without being
told it is the *caller* would reasonably assume they are looking at the faulting
instruction's own source, and reason about the wrong function.

Finding that frame needs the execution trace, so ``trace_ref`` is an input. With
no trace, this returns a context that says so rather than a context that looks
complete.

Pseudo-C is lossy
-----------------
Names are invented, types are inferred, inlining is flattened (section 2, and the
CP6 note in DECISIONS.md). It moves us from grey-box toward white-box but it is
**not source**, and triage prompts are written on that assumption.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from arch.addr import AddressSpace
from arch.contracts import CrashRecord, TraceRef
from analysis.trace import (
    fault_index_from_trace,
    frames_before_fault,
    parse_symbol_line,
)
from prep.data_symbols import GlobalSymbol, format_globals, load_globals
from prep.pseudoc_cache import PseudoCCache

__all__ = ["CrashContext", "assemble_context"]


class CrashContext(BaseModel):
    """Triage signal 5. Says what it is describing, and what is missing."""

    bucket_id: str = ""

    # WHICH frame the pseudo-C belongs to. `is_faulting_frame` False means this is
    # a caller, not the instruction that faulted -- the common case, and the one
    # that must never be misread.
    context_frame: str | None = Field(
        default=None, description="symbolized frame the pseudo-C describes"
    )
    context_static_addr: int = 0
    is_faulting_frame: bool = False

    faulting_frame: str | None = Field(
        default=None, description="symbolized frame where the fault occurred"
    )

    function: str | None = None
    pseudo_c: str | None = None
    pseudo_c_source: str = Field(
        default="unavailable", description="a2_cache | ghidra_mcp | unavailable"
    )

    approach_path: list[str] = Field(
        default_factory=list,
        description="last frames inside the target module before the fault",
    )
    in_module_call_path: list[str] = Field(
        default_factory=list,
        description=(
            "TAIL of the chronological sequence of target-module functions "
            "executed before the fault. NOT a call stack: a rip trace records "
            "which instruction ran, not the frames live at the time, and "
            "recovering a stack would need unwind information we do not have. So "
            "['ProcessPacket', 'memcpy'] means the parser ran and then memcpy ran, "
            "which is consistent with a call but does not prove one."
        ),
    )
    globals_touched: str = Field(
        default="", description="pre-rendered global bounds table, or empty"
    )
    notes: list[str] = Field(default_factory=list)


def _in_module_call_path(
    symbolized: Path,
    module_prefix: str,
    *,
    fault_index: int | None = None,
    tail: int = 8,
) -> list[str]:
    """Functions of ``module_prefix`` executed before the fault, in order.

    Collapses the per-instruction frames a rip trace produces -- 130 lines of
    ``ProcessPacket+0x5``, ``+0x6``, ... become one entry -- so the result reads as
    a sequence of functions rather than an instruction dump.

    Only the last ``tail`` transitions are returned. The full sequence is the whole
    execution history and on a multi-packet test-case it repeats the same handful
    of functions dozens of times: measured 62 entries for one crash, cycling
    ProcessPacket / printf / make_unique / malloc. The tail is the part that
    describes the fault.

    **This is a chronological sequence, not a call stack.** See
    :class:`CrashContext`.

    Filtering happens inside :func:`frames_before_fault`, which is the fix for a
    bug worth recording: taking an unfiltered window of the last N frames and then
    searching it for our module found nothing, because on this target the final
    thousands of frames are all memcpy internals and the parser's frames sit
    further back.
    """
    frames = frames_before_fault(
        symbolized,
        count=1_000_000,
        module=module_prefix,
        fault_index=fault_index,
    )

    path: list[str] = []
    for frame in frames:
        function = parse_symbol_line(frame).function
        name = function or frame
        if not path or path[-1] != name:
            path.append(name)
    return path[-tail:] if tail else path


def _deepest_documented_frame(
    call_path: list[str], cache: PseudoCCache | None
) -> tuple[str | None, list[str]]:
    """Deepest function on the path that A2 actually has pseudo-C for.

    Not simply the deepest in-module frame, which on this target is
    ``tlv_server.exe!memcpy`` -- the CRT import thunk. It is inside our module and
    it is genuinely the last thing our code executed, but A2 has no pseudo-C for a
    thunk and a thunk explains nothing. The frame worth showing triage is the
    deepest one we can actually *describe*, and the frames skipped on the way are
    reported so the path is not silently shortened.
    """
    if cache is None:
        return None, []

    skipped: list[str] = []
    for name in reversed(call_path):
        if cache.get_by_function(name) is not None:
            return name, skipped
        skipped.append(name)
    return None, skipped


def assemble_context(
    record: CrashRecord,
    *,
    bucket_id: str = "",
    cache: PseudoCCache | None = None,
    trace_ref: TraceRef | None = None,
    space: AddressSpace | None = None,
    module_prefix: str = "tlv_server",
    data_symbols: Path | None = None,
    mcp_client=None,
    approach_frames: int = 12,
) -> CrashContext:
    """Build the static context for one bucket.

    ``mcp_client`` is an optional :class:`llm.ghidra_mcp.GhidraMcpClient` used only
    when A2 has no entry for the address -- a decompiler call, not a model call.
    """
    notes: list[str] = []
    context = CrashContext(bucket_id=bucket_id)

    if trace_ref is None or not trace_ref.symbolized_path:
        notes.append(
            "no symbolized trace was supplied, so the frame that called into the "
            "faulting code is unknown. Static context is limited to whatever the "
            "fault address itself resolves to, which for a fault outside the "
            "target module is nothing."
        )
    else:
        symbolized = Path(trace_ref.symbolized_path)
        if not symbolized.exists():
            notes.append(f"symbolized trace {symbolized} is missing")
        else:
            # The fault's position comes from the RAW trace: symbolizer-rs emits
            # one line per input line in order, so the index transfers, and the
            # symbolized file cannot be used to find it (analysis/trace.py
            # fault_index_from_trace explains why).
            fault_index = None
            raw = Path(trace_ref.raw_path) if trace_ref.raw_path else None
            if raw is not None and raw.exists():
                fault_index = fault_index_from_trace(raw)
            else:
                notes.append(
                    "the raw trace is unavailable, so the fault's position was "
                    "approximated from where kernel frames begin; the reported "
                    "faulting frame may be earlier than the true fault"
                )

            context.approach_path = frames_before_fault(
                symbolized,
                count=approach_frames,
                module=module_prefix,
                fault_index=fault_index,
            )

            full = frames_before_fault(symbolized, count=1, fault_index=fault_index)
            context.faulting_frame = full[-1] if full else None

            # The FULL sequence is searched for a documented frame; only its tail
            # is reported. Searching the tail would miss ProcessPacket whenever
            # the last few transitions are all CRT helpers.
            call_path = _in_module_call_path(
                symbolized, module_prefix, fault_index=fault_index, tail=0
            )
            context.in_module_call_path = call_path[-8:]
            if not call_path:
                notes.append(
                    f"the trace's approach path contains no frame in "
                    f"{module_prefix!r}. Either the harness never entered the "
                    f"target (check TraceRef.reached_fuzz_entry) or the module "
                    f"prefix is wrong."
                )
            else:
                chosen, skipped = _deepest_documented_frame(call_path, cache)
                if chosen is None:
                    notes.append(
                        f"none of the {len(call_path)} in-module function(s) on the "
                        f"fault path has pseudo-C in A2: {call_path}. Build A2 over "
                        f"a scope that includes them."
                    )
                else:
                    context.function = chosen
                    context.context_frame = f"{module_prefix}!{chosen}"
                    context.is_faulting_frame = False
                    if skipped:
                        notes.append(
                            f"skipped {skipped} between this function and the "
                            f"fault -- no pseudo-C in A2 for them (a CRT thunk has "
                            f"none and would explain nothing)"
                        )
                    notes.append(
                        f"the pseudo-C below is a CALLER on the fault path, not the "
                        f"faulting instruction. The fault is in "
                        f"{context.faulting_frame}, for which no pseudo-C exists or "
                        f"ever will -- it is outside the analysed module."
                    )

    # Pseudo-C for whichever function we settled on.
    if context.function and cache is not None:
        entry = cache.get_by_function(context.function)
        if entry is not None:
            context.pseudo_c = entry.code
            context.pseudo_c_source = "a2_cache"
            context.context_static_addr = entry.static_addr

    if context.pseudo_c is None and context.function and mcp_client is not None:
        try:
            decompiled = mcp_client.decompile(context.function)
        except Exception as exc:  # a decompiler being down must not lose the record
            notes.append(f"GhidraMCP decompile failed: {exc}")
        else:
            if decompiled:
                context.pseudo_c = decompiled
                context.pseudo_c_source = "ghidra_mcp"

    if context.pseudo_c is None:
        notes.append(
            "no pseudo-C available. Triage receives the dynamic path and the "
            "fault characterisation only, and must not be told otherwise."
        )

    # Globals the code touches: CP7 showed this recovers facts decompilation drops
    # (D-047), and a length or table bound is exactly what explains this class of
    # fault.
    if data_symbols is not None and Path(data_symbols).exists():
        try:
            symbols: list[GlobalSymbol] = load_globals(Path(data_symbols))
            context.globals_touched = format_globals(symbols)
        except Exception as exc:
            notes.append(f"global symbol table unavailable: {exc}")

    context.notes = notes
    return context
