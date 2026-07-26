"""Data contracts for snapfuzz (CLAUDE.md section 6).

Every stage boundary passes one of these models. They serialise to JSON on disk
so that each stage is independently runnable and testable.

Three engineering notes that are not in section 6 but are forced by the data:

* ``SeedRecord.seed_bytes`` and ``CrashRecord.input_bytes`` hold arbitrary
  binary. Pydantic v2 defaults to UTF-8 for ``bytes`` in JSON, which throws on
  non-UTF-8 fuzz inputs -- exactly the inputs we care about. Both models
  therefore opt into base64 for JSON in *both* directions so a dump/load round
  trip is lossless.
* Addresses are plain ``int``. Which address space an ``int`` lives in is
  carried by the field name (``static_addr`` / ``fault_runtime_addr``) and
  converted only through :mod:`arch.addr` (CLAUDE.md section 9).
* Section 6 states two rules about Linux snapshots in prose -- ASLR must be
  disabled, and ``symbol-store.json`` is required because there is no dbgeng to
  place breakpoints with (section 13.1). They are enforced as validators rather
  than left as comments: on Linux both are silent-failure conditions, which is
  precisely what RULE 4 exists to prevent.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, model_validator

# Models holding raw fuzzer bytes need base64 in JSON; UTF-8 (the pydantic
# default) raises on the non-UTF-8 payloads that fuzzing produces constantly.
BINARY_JSON = ConfigDict(ser_json_bytes="base64", val_json_bytes="base64")

# wtf's three execution backends (src/wtf/globals.h BackendType_t). Which one
# produced a result changes how it must be read: only bochscpu is fully
# deterministic (CLAUDE.md section 13.5).
Backend = Literal["bochscpu", "whv", "kvm"]


class FuzzEntry(BaseModel):
    """The function the snapshot breaks at and where its input arrives."""

    module: str
    symbol: str | None = None
    static_addr: int  # Ghidra static address space
    rationale: str  # why the LLM chose it
    input_param: str  # register/stack slot/pointer carrying the input
    size_param: str | None = None  # register/slot carrying the length, if any


class BasicBlock(BaseModel):
    module: str
    static_addr: int
    function: str | None = None


class PseudoCEntry(BaseModel):
    module: str
    static_addr: int
    function: str
    code: str


class SnapshotRef(BaseModel):
    """A1 -- the state/ directory wtf restores from.

    The three file paths are named explicitly because wtf derives them from
    ``--state`` rather than taking them individually
    (``src/wtf/wtf.cc:312``: ``Opts.DumpPath = Opts.StatePath / "mem.dmp"``),
    so a missing one surfaces late and unhelpfully.
    """

    path: str  # the state/ directory wtf consumes
    os: Literal["windows", "linux"]
    mem_dmp: str  # state/mem.dmp
    regs_json: str  # state/regs.json
    symbol_store_json: str | None = None  # REQUIRED on linux
    module_base: int  # runtime base of the target module in the snapshot
    ghidra_image_base: int  # static base, for addr conversion (section 9)
    entry_runtime_addr: int
    aslr_disabled: bool  # must be True for linux

    @model_validator(mode="after")
    def _linux_requirements(self) -> SnapshotRef:
        if self.os != "linux":
            return self
        if not self.aslr_disabled:
            raise ValueError(
                "aslr_disabled must be True for a linux snapshot: with ASLR on, "
                "module_base differs from the base the snapshot was taken at and "
                "every static<->runtime conversion is silently wrong"
            )
        if not self.symbol_store_json:
            raise ValueError(
                "symbol_store_json is required for a linux snapshot: linux has no "
                "dbgeng, so wtf places coverage breakpoints from symbol-store.json "
                "and without it there is no coverage at all"
            )
        return self


class SeedRecord(BaseModel):
    model_config = BINARY_JSON

    seed_bytes: bytes
    origin: Literal["initial", "mutation", "llm_seed_gen"]
    rationale: str | None = None  # for llm_seed_gen: which branch it targets


# What a coverage number counts. Not decoration: section 13.5 says the backends
# measure DIFFERENT THINGS -- bochscpu gets full-system coverage for free and edge
# coverage with `--edges`, while whv and kvm count software breakpoints on basic
# blocks from the A3 list. A single field called `total_edges` claimed all three
# were edges, and the comment beside it said "BPs hit", so the name and the
# comment disagreed in one line of the spec (D-068).
#
# It matters for CP10: a cross-backend comparison of two numbers that count
# different events is not a comparison.
CoverageKind = Literal[
    "edge",  # bochscpu with --edges: real edge coverage
    "basic_block_breakpoint",  # whv/kvm: one hit per A3 breakpoint
    "engine_native",  # whatever the master's `cov:` field reports
]


class CoverageSummary(BaseModel):
    """Aggregate coverage as seen by the MASTER, never one worker (section 12.3)."""

    # Recorded summaries written BEFORE the rename must keep loading. An audit
    # trail that a field rename silently invalidates is not an audit trail, and
    # the whole point of the evidence bundle is that old runs stay checkable --
    # so the pre-D-068 names are accepted as aliases on input.
    model_config = ConfigDict(populate_by_name=True)

    tick: int
    # Renamed from `total_edges`/`new_edges` (section 6, D-068). "Units" because
    # what a unit IS depends on the backend, and `coverage_kind` says which.
    coverage_units: int = Field(validation_alias=AliasChoices("coverage_units", "total_edges"))
    new_units: int = Field(validation_alias=AliasChoices("new_units", "new_edges"))
    # Defaulted, because a pre-rename record cannot say what it counted. The
    # default is the honest answer for those: the master's own number.
    coverage_kind: CoverageKind = "engine_native"
    # Which backend produced the number. Required for the same reason: a summary
    # without it cannot be compared with another one safely.
    backend: Backend | None = None
    plateau_ticks: int
    corpus_size: int
    crash_bucket_count: int
    frontier: list[int] = Field(
        default_factory=list
    )  # covered BBs whose successors are still unreached

    @model_validator(mode="after")
    def _new_cannot_exceed_total(self) -> "CoverageSummary":
        if self.new_units > self.coverage_units:
            raise ValueError(
                f"new_units {self.new_units} exceeds coverage_units "
                f"{self.coverage_units}: the delta cannot be larger than the total"
            )
        return self


def coverage_kind_for(backend: str | None) -> CoverageKind:
    """The kind a backend's own coverage number is, absent an explicit override.

    bochscpu is `engine_native` rather than `edge`: `--edges` turns edge coverage
    on, and this project does not pass it, so calling the master's number "edge"
    would be the same overclaim the rename exists to remove (D-004: bochscpu
    ignores the `.cov` file entirely).
    """
    if backend in ("whv", "kvm"):
        return "basic_block_breakpoint"
    return "engine_native"


class CrashRecord(BaseModel):
    model_config = BINARY_JSON

    input_bytes: bytes
    fault_type: str  # access-violation / abort / illegal-insn / timeout
    fault_runtime_addr: int
    # De-slid (section 9), and **None when the fault is not attributable to the
    # target module** -- which is the common case: Application Verifier raises
    # from verifier.dll when it catches a heap overflow, and applying our slide to
    # that address yields garbage.
    #
    # None rather than 0 (D-068). 0 is a real address, so a sentinel made three
    # things indistinguishable from a fact: dedup keying every external fault
    # together, a pseudo-C lookup at address zero, and a consumer that simply
    # forgot. `int | None` makes the type system ask.
    fault_static_addr: int | None = None
    # Which module the fault address belongs to, when it can be determined.
    # Distinguishes "faulted in the parser" from "the heap manager noticed".
    fault_module: str | None = None
    # Whether the runtime -> static conversion was actually applied. Separates
    # "we converted it and got this" from "we could not, so there is nothing to
    # report" -- two states a bare address cannot tell apart.
    address_normalized: bool = False
    registers: dict[str, int] = Field(default_factory=dict)
    backtrace: list[int] = Field(default_factory=list)  # static addrs where recoverable
    coverage_delta: int = 0
    worker_id: str | None = None  # which worker found it (section 12.5)
    backend: Backend  # matters for determinism (section 13.5)
    timestamp: float


class CrashBucket(BaseModel):
    bucket_id: str  # stack hash
    representative: CrashRecord
    hit_count: int
    # WHICH dedup key produced this bucket, and its value. Not decoration: the
    # keys form a ladder that degrades when a backtrace or symbols are missing
    # (analysis/dedup.py KEY_KINDS), and a bucket keyed on `fault_type` alone
    # merges far more aggressively than one keyed on a stack hash. Without the
    # rung recorded, a coarse bucket is indistinguishable from a precise one and
    # "same bucket" gets read as "same bug" when it does not mean that.
    key_kind: str = "stack_hash"
    key_detail: str = ""


class ReplayResult(BaseModel):
    bucket_id: str
    reproduced: bool
    deterministic: bool  # same fault addr across N replays
    replays: int
    backend: Backend  # only bochscpu is fully deterministic
    notes: str = ""

    @model_validator(mode="after")
    def _determinism_needs_bochscpu(self) -> ReplayResult:
        """A determinism claim from whv/kvm is not evidence about the bug.

        Section 13.5: those backends are deterministic only if every source of
        nondeterminism was handled by hand. Concluding "nondeterministic" from
        them, without re-checking on bochscpu, is a listed anti-pattern.
        """
        if self.backend != "bochscpu" and "bochscpu" not in self.notes.lower():
            raise ValueError(
                f"replay ran on {self.backend!r}, which is not deterministic by "
                "default; re-check on bochscpu before judging, and record that "
                "reasoning in `notes`"
            )
        return self


class TraceRef(BaseModel):
    """Signal 4 -- what actually executed, as opposed to what the code says.

    Produced by ``wtf run --trace-type=...`` then symbolized with
    ``symbolizer-rs``. ``tenet`` traces are bochscpu-only (section 13.3).
    """

    bucket_id: str
    trace_type: Literal["rip", "tenet"]
    raw_path: str  # wtf output
    symbolized_path: str  # symbolizer-rs output
    reached_fuzz_entry: bool  # sanity: did it even enter the target parser?


class TriageVerdict(BaseModel):
    bucket_id: str
    verdict: Literal["confirmed", "false_positive"]
    confidence: float
    cwe_guess: str | None = None
    exploitability: Literal["dos", "info_leak", "possible_rce", "unknown"]
    root_cause: str
    signals_used: list[str]  # must name all five when available -- see below
    reproducer_input_path: str


# --- edge 12/14: the LLM-derived input structure ------------------------
#
# NOT IN CLAUDE.md section 6, and its absence is the reason this component was
# the last one built. Section 3.1 draws a box called "LLM-generated input struct
# / reads pseudo-C (A2) [LLM]" and section 3.2 gives it edges 12 and 14, but no
# gate in section 8 lists either edge -- so under RULE 3 it was the one piece of
# the architecture with no definition of done. Everything around it was forced to
# completion by a gate; this was not, and it stayed a hand-written struct while
# looking finished on the diagram.
#
# The contract exists so the LLM's output can be VALIDATED. Asking a model for C++
# directly fails RULE 4 three ways: a compile error surfaces in the C++ toolchain,
# far from the model's mistake; free-form C++ cannot be checked against a schema;
# and "units and encoding are stated" cannot be enforced in prose. So the model
# emits this declarative spec, and ordinary code (fuzzer/codegen.py) turns it into
# C++ -- which keeps generation deterministic and the output compilable.

CIntType = Literal[
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "int8_t", "int16_t", "int32_t", "int64_t",
]
FieldKind = Literal["scalar", "length", "magic", "bytes", "padding"]


# Names from the spec become C++ identifiers, so the spec must be unable to
# express one that cannot be generated. Enforced here rather than in codegen: a
# spec that cannot produce compilable code is invalid at the point it is created,
# not at the point someone tries to use it.
_C_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Not exhaustive -- just the keywords a plausible field name could collide with.
_CPP_RESERVED = frozenset(
    """
    alignas alignof and asm auto bool break case catch char class const consteval
    constexpr continue decltype default delete do double else enum explicit export
    extern false float for friend goto if inline int long mutable namespace new
    noexcept not nullptr operator or private protected public register return short
    signed sizeof static struct switch template this throw true try typedef typeid
    typename union unsigned using virtual void volatile wchar_t while xor
    """.split()
)


def _check_identifier(value: str, what: str) -> str:
    if not _C_IDENTIFIER.match(value):
        raise ValueError(
            f"{what} {value!r} is not a valid C identifier, so it cannot become a "
            f"struct field or type name"
        )
    if value in _CPP_RESERVED:
        raise ValueError(f"{what} {value!r} is a C++ reserved word")
    return value


class InputField(BaseModel):
    """One field of the target's input structure.

    Every RULE 4 question is a required or explicitly-defaulted field here, which
    is the point: a spec that cannot express "bytes or elements?" would let the
    same ambiguity back in through the model's output.
    """

    name: str
    kind: FieldKind
    ctype: CIntType | None = None  # None only for `bytes`, which is variable-length
    little_endian: bool = True

    # `length` fields only: which field's size this one carries, and in what unit.
    # CLAUDE.md's RULE 4 table asks "bytes or element count?" and "does the target
    # expect it to include a header or terminator?" -- both are answered here or
    # the spec is rejected.
    counts_field: str | None = None
    unit: Literal["bytes", "elements"] = "bytes"
    includes_header: bool = False

    # `magic` fields only: the constant the parser compares against.
    magic_value: int | None = None

    # `bytes` fields only: an upper bound the harness will not exceed.
    max_length: int | None = None

    rationale: str = ""  # which line of pseudo-C implied this field

    @model_validator(mode="after")
    def _kind_requirements(self) -> InputField:
        _check_identifier(self.name, "field name")
        if self.kind in {"scalar", "length", "magic", "padding"} and not self.ctype:
            raise ValueError(f"field {self.name!r} of kind {self.kind} needs a ctype")
        if self.kind == "bytes" and self.ctype:
            raise ValueError(
                f"field {self.name!r} is variable-length bytes and must not have a "
                f"fixed ctype"
            )
        if self.kind == "length" and not self.counts_field:
            raise ValueError(
                f"length field {self.name!r} does not say which field it counts; "
                f"an unattributed length is exactly the ambiguity RULE 4 forbids"
            )
        if self.kind == "magic" and self.magic_value is None:
            raise ValueError(f"magic field {self.name!r} has no magic_value")
        return self


class InputSpec(BaseModel):
    """The input structure a target's parser expects, derived from pseudo-C.

    Consumed by `fuzzer/codegen.py` at **build time**, never at run time -- RULE 1
    applies, and the artifact that reaches the fuzzer is generated C++.
    """

    module: str
    entry_symbol: str
    struct_name: str = "Packet_t"
    fields: list[InputField]

    # Can one test-case carry several structures delivered in sequence to the same
    # live process? On a stateful parser this is the difference between reaching a
    # branch and not: CLAUDE.md section 13.7 points at fuzzer_tlv_server.cc for it.
    supports_sequence: bool = True
    sequence_field_name: str = "Packets"

    # Let a test-case lie about how many bytes arrived. Without it a guard like
    # `if (size < 8) reject` is unreachable BY CONSTRUCTION, whatever the seed --
    # measured at CP7 (D-040).
    wire_size_override: bool = True

    rationale: str = ""  # why this shape, from the pseudo-C
    source_functions: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _spec_is_coherent(self) -> InputSpec:
        _check_identifier(self.struct_name, "struct name")
        _check_identifier(self.sequence_field_name, "sequence field name")
        if not self.fields:
            raise ValueError("an input spec with no fields describes nothing")

        names = [f.name for f in self.fields]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            raise ValueError(f"duplicate field names: {duplicates}")

        known = set(names)
        for field in self.fields:
            if field.counts_field and field.counts_field not in known:
                raise ValueError(
                    f"length field {field.name!r} counts {field.counts_field!r}, "
                    f"which is not a field of this struct"
                )
            if field.counts_field == field.name:
                raise ValueError(f"length field {field.name!r} counts itself")

        # A variable-length tail with no length field means the parser cannot know
        # where the data ends, so either the model missed the length field or the
        # shape is wrong. Refusing beats generating a struct that silently
        # truncates every test-case.
        variable = [f for f in self.fields if f.kind == "bytes"]
        if variable:
            counted = {f.counts_field for f in self.fields if f.kind == "length"}
            uncounted = [f.name for f in variable if f.name not in counted]
            if uncounted:
                raise ValueError(
                    f"variable-length field(s) {uncounted} have no length field. "
                    f"Either the spec is missing one, or the parser delimits them "
                    f"some other way -- say which in the rationale and model it."
                )
        if len(variable) > 1:
            raise ValueError(
                f"more than one variable-length field ({[f.name for f in variable]}) "
                f"cannot be laid out unambiguously"
            )
        return self

    @property
    def header_bytes(self) -> int:
        """Fixed-size prefix, in bytes. 0 if any fixed field lacks a ctype."""
        widths = {
            "uint8_t": 1, "int8_t": 1, "uint16_t": 2, "int16_t": 2,
            "uint32_t": 4, "int32_t": 4, "uint64_t": 8, "int64_t": 8,
        }
        return sum(
            widths[f.ctype] for f in self.fields if f.kind != "bytes" and f.ctype
        )


# --- the harness itself, derived rather than hand-written ----------------
#
# CP11 generated the input STRUCT and left ~550 lines of harness logic
# hand-written, filed under section 3.1's "Manual tweaks" box. That framing was
# half true and half an excuse: recounting the module showed most of those lines
# ARE derivable, and some are not even target-specific.
#
#   crash oracle          ONE line -- SetupUsermodeCrashDetectionHooks(), wtf's own
#                         helper. The fault sites it hooks (nt!KeBugCheck2,
#                         ntdll!RtlDispatchException, verifier!VerifierStopMessage)
#                         are Windows-generic, not target-generic.
#   Restore               a no-op, and that is the GENERAL case: wtf's snapshot
#                         restore already covers guest memory and registers.
#   mutator Generate/Mutate  entirely field-driven -- derivable from an InputSpec.
#   entry / I/O silencing dervivable from FuzzEntry plus Ghidra's call references.
#
# What is left is small enough to declare. Leaving it hand-written contradicts
# contribution 1, which is explicitly about removing "snapshot fuzzing's main
# usability barrier" -- and 550 hand-written lines per target is that barrier.
#
# The model still does NOT write C++ (see InputSpec's note). It fills this in, and
# fuzzer/codegen.py renders it.

BreakpointPurpose = Literal[
    "fuzz_entry",        # where a test-case is delivered
    "end_of_testcase",   # reaching here means the input was consumed cleanly
    "silence_io",        # console/file output: pure noise, and slow
    "nondeterminism",    # rdrand/rdtsc/GetTickCount -- must be pinned for replay
]
BreakpointAction = Literal[
    "deliver_next_input",  # write the next structure into guest memory
    "restore_context",     # reset GPRs so the next structure starts clean
    "stop_ok",             # Backend->Stop(Ok_t()) -- end of test-case, NOT a crash
    "simulate_return",     # skip the function, returning a fixed value
]


class HarnessBreakpoint(BaseModel):
    """One breakpoint the generated Init installs."""

    symbol: str  # "module!Function", resolved by wtf through dbgeng
    purpose: BreakpointPurpose
    action: BreakpointAction
    # `simulate_return` only: what the skipped function should appear to return.
    return_value: int | None = None
    rationale: str = ""

    @model_validator(mode="after")
    def _action_suits_purpose(self) -> HarnessBreakpoint:
        if not self.symbol or "!" not in self.symbol:
            raise ValueError(
                f"breakpoint symbol {self.symbol!r} must be 'module!Function' -- wtf "
                f"resolves it by name through dbgeng and a bare name will not bind"
            )
        if self.action == "simulate_return" and self.return_value is None:
            raise ValueError(
                f"{self.symbol}: simulate_return needs a return_value; skipping a "
                f"function while leaving its result undefined corrupts the caller"
            )
        if self.purpose == "silence_io" and self.action != "simulate_return":
            raise ValueError(
                f"{self.symbol}: silencing output means returning from it, not "
                f"{self.action!r}"
            )
        return self


class HarnessSpec(BaseModel):
    """Everything the generated fuzzer module needs that is not the input format.

    Deliberately declarative. Each field answers a question that would otherwise
    be answered by a human reading the binary, and every one of them is a question
    Ghidra plus the snapshot can answer.
    """

    module: str  # the binary, e.g. "tlv_server"
    target_name: str  # wtf's --name for this module
    entry_symbol: str  # "module!Function"

    # From FuzzEntry, and RULE 4's first two table rows: is the register a pointer
    # to the buffer or the buffer itself, and is the size in bytes?
    input_param: str
    size_param: str | None = None
    input_is_pointer: bool = True

    breakpoints: list[HarnessBreakpoint] = Field(default_factory=list)

    # Deliver several structures per test-case to the same live process. Comes from
    # InputSpec.supports_sequence -- kept here too because the harness is what
    # implements it, and a mismatch between the two is a bug worth catching.
    deliver_sequence: bool = True

    # Globals the parser mutates that survive wtf's snapshot restore. Normally
    # EMPTY: restoring guest memory covers them, and restoring twice is as wrong as
    # not restoring (DECISIONS R2). Non-empty is a claim that needs its rationale.
    restore_globals: list[str] = Field(default_factory=list)

    # A structure larger than this is dropped rather than delivered. Bounded
    # because the delivery buffer is page-backed.
    max_input_bytes: int = 4096

    rationale: str = ""
    source_functions: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _harness_is_coherent(self) -> HarnessSpec:
        if "!" not in self.entry_symbol:
            raise ValueError(
                f"entry_symbol {self.entry_symbol!r} must be 'module!Function'"
            )

        entries = [b for b in self.breakpoints if b.purpose == "fuzz_entry"]
        if len(entries) != 1:
            raise ValueError(
                f"exactly one fuzz_entry breakpoint is required, got {len(entries)}. "
                f"Without it nothing is ever delivered and the campaign runs happily "
                f"executing the snapshot untouched -- which reports coverage and "
                f"finds nothing."
            )
        if entries[0].symbol != self.entry_symbol:
            raise ValueError(
                f"the fuzz_entry breakpoint is on {entries[0].symbol!r} but the "
                f"entry is {self.entry_symbol!r}"
            )
        if entries[0].action != "deliver_next_input":
            raise ValueError(
                f"the fuzz_entry breakpoint must deliver input, not "
                f"{entries[0].action!r}"
            )

        symbols = [b.symbol for b in self.breakpoints]
        duplicates = sorted({s for s in symbols if symbols.count(s) > 1})
        if duplicates:
            raise ValueError(f"duplicate breakpoint symbols: {duplicates}")

        if self.max_input_bytes <= 0:
            raise ValueError("max_input_bytes must be positive")

        # A `restore_globals` entry without a reason is usually a guess, and a
        # spurious reset can mask the very state a stateful bug depends on.
        if self.restore_globals and not self.rationale.strip():
            raise ValueError(
                "restore_globals is non-empty but no rationale is given. wtf's "
                "snapshot restore already covers guest memory, so claiming extra "
                "state needs an argument (DECISIONS R2)."
            )
        return self


# The five independent triage signals (CLAUDE.md section 3.2, edges 38-41b).
# Signals 4 and 5 are deliberately separate: one is dynamic (what executed),
# one is static (what the code says). Collapsing them is an anti-pattern.
TRIAGE_SIGNALS = (
    "dedup",  # 1
    "classification",  # 2
    "replay",  # 3
    "symbolize_trace",  # 4 -- dynamic
    "reverse_engineer",  # 5 -- static
)


__all__ = [
    "Backend",
    "TRIAGE_SIGNALS",
    "FuzzEntry",
    "CIntType",
    "FieldKind",
    "InputField",
    "InputSpec",
    "BasicBlock",
    "PseudoCEntry",
    "SnapshotRef",
    "SeedRecord",
    "CoverageSummary",
    "CrashRecord",
    "CrashBucket",
    "ReplayResult",
    "TraceRef",
    "TriageVerdict",
]
