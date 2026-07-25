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

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

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


class CoverageSummary(BaseModel):
    """Aggregate coverage as seen by the MASTER, never one worker (section 12.3)."""

    tick: int
    total_edges: int  # BPs hit
    new_edges: int  # since last tick
    plateau_ticks: int
    corpus_size: int
    crash_bucket_count: int
    frontier: list[int] = Field(
        default_factory=list
    )  # covered BBs whose successors are still unreached


class CrashRecord(BaseModel):
    model_config = BINARY_JSON

    input_bytes: bytes
    fault_type: str  # access-violation / abort / illegal-insn / timeout
    fault_runtime_addr: int
    # De-slid (section 9) -- but ONLY when the fault lands inside the target
    # module. 0 means "not attributable to our module", which is the common case:
    # Application Verifier raises from verifier.dll when it catches a heap
    # overflow, and applying our slide to that address yields garbage.
    fault_static_addr: int
    # Which module the fault address belongs to, when it can be determined.
    # Distinguishes "faulted in the parser" from "the heap manager noticed".
    fault_module: str | None = None
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
