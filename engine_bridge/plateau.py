"""Plateau detection and the coverage frontier (CLAUDE.md CP7).

Two jobs, and the second is the interesting one.

**Plateau** is measured in **total executions without new coverage**, not wall
clock (section 12.3). With 16 workers the same execution budget burns roughly 16x
faster, so a time-based threshold tuned on one worker fires far too late. A
wall-clock bound exists only as a safety net for a stalled campaign.

It is computed on the **master's aggregate**, never one worker's. In practice
that means counting new-coverage events from ``outputs/``, because the master's
stdout is unusable (D-033) and no aggregated ``coverage.cov`` is written (D-021).
``outputs/`` is still genuinely aggregate: the master owns it and writes there on
behalf of every worker.

**The frontier** is the actionable signal: *covered basic blocks that still have
an unreached successor*. Those are the branches the fuzzer has arrived at but
never taken, so they are exactly what seed generation should target. Computing it
needs two things that arrive from different places:

* which blocks are covered -- from ``wtf run --trace-type=cov`` (D-033 again: the
  live master will not tell us, so coverage is measured from traces);
* the successor graph -- from Ghidra, via ``ExportBasicBlocks.java``.

**NO LLM IN THIS MODULE.** It produces the summary the slow clock sends; the
sending is :mod:`llm.seed_gen`'s job.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from arch.addr import AddressSpace, to_rva
from arch.contracts import CoverageSummary

__all__ = [
    "BlockGraph",
    "FrontierBlock",
    "PlateauState",
    "PlateauDetector",
    "parse_cov_trace",
    "compute_frontier",
]


# --- coverage traces ------------------------------------------------------


def parse_cov_trace(
    path: Path, space: AddressSpace, *, in_module_only: bool = True
) -> set[int]:
    """A ``--trace-type=cov`` file -> covered **RVAs**.

    The trace holds one *runtime* address per line. RVAs are the common currency
    with A3 (which stores RVAs, D-005), and they are slide-independent.

    ``in_module_only`` drops addresses outside the target, which is most of them:
    a trace is dominated by ntdll and the kernel (measured: 19,681 ntdll lines
    against 130 in the target itself). Keeping them would make the frontier
    meaningless and the arithmetic wrong, since another module's slide is not
    ours.
    """
    covered: set[int] = set()
    low = space.module_base
    high = space.module_base + 0x1000_0000  # sanity bound, not a real image size

    with path.open("r", encoding="utf-8", errors="replace") as fd:
        for line in fd:
            line = line.strip()
            if not line:
                continue
            try:
                runtime = int(line, 16) if line.startswith("0x") else int(line, 16)
            except ValueError:
                continue
            if in_module_only and not (low <= runtime < high):
                continue
            covered.add(to_rva(space.to_static(runtime), space.ghidra_image_base))
    return covered


def parse_cov_traces(
    directory: Path, space: AddressSpace, *, pattern: str = "*.trace"
) -> set[int]:
    """Union the coverage of every trace in a directory."""
    covered: set[int] = set()
    if not directory.is_dir():
        return covered
    for path in sorted(directory.glob(pattern)):
        covered |= parse_cov_trace(path, space)
    return covered


# --- the block graph ------------------------------------------------------


@dataclass(frozen=True)
class FrontierBlock:
    """A covered block with at least one successor never reached.

    **Both address spaces are named explicitly.** ``rva`` and
    ``unreached_successor_rvas`` are module-relative, which is what indexes
    :class:`BlockGraph` and A3; ``static_addr`` and
    ``unreached_successor_statics`` are Ghidra static addresses, which is what
    goes in front of a human or an LLM. Carrying an unlabelled ``successors``
    field made the seed-generation prompt state the reached block as a static
    address and its successors as RVAs in the same sentence, so the model echoed
    RVAs back as the branch it had aimed at and no attempt could ever be matched
    against measured coverage (D-045).
    """

    rva: int
    static_addr: int
    function: str | None
    unreached_successor_rvas: tuple[int, ...]
    unreached_successor_statics: tuple[int, ...]

    def __post_init__(self) -> None:
        if len(self.unreached_successor_rvas) != len(
            self.unreached_successor_statics
        ):
            raise ValueError(
                "unreached successor RVA and static lists must correspond "
                "element-for-element"
            )

    @property
    def degree(self) -> int:
        return len(self.unreached_successor_rvas)


@dataclass
class BlockGraph:
    """A3 plus its successor edges."""

    module: str
    image_base: int
    blocks: dict[int, dict] = field(default_factory=dict)  # rva -> record

    @classmethod
    def from_export(cls, path: Path) -> BlockGraph:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        blocks = {b["rva"]: b for b in raw["blocks"]}

        if not any(b.get("successors") for b in blocks.values()):
            raise ValueError(
                f"{path} has no successor edges, so the frontier cannot be "
                f"computed. Regenerate A3 with a build of ExportBasicBlocks.java "
                f"that emits `successors` (CP7)."
            )

        return cls(module=raw["module"], image_base=raw["image_base"], blocks=blocks)

    def successors(self, rva: int) -> list[int]:
        record = self.blocks.get(rva)
        return list(record.get("successors", [])) if record else []

    def function_of(self, rva: int) -> str | None:
        record = self.blocks.get(rva)
        return record.get("function") if record else None

    def __len__(self) -> int:
        return len(self.blocks)

    @property
    def edge_count(self) -> int:
        return sum(len(b.get("successors", [])) for b in self.blocks.values())


# Functions whose branches input cannot steer. Putting these in front of the LLM
# wastes a whole generation round on something no seed can do, which CP7 observed
# directly: of five frontier branches offered, one was inside `operator_new`'s
# allocation-failure path and one inside printf's internals (D-040).
#
# This is about REACHABILITY BY INPUT, not about the code being uninteresting.
_INPUT_OPAQUE = re.compile(
    r"operator_(new|delete)|"
    r"^_?(malloc|free|realloc|calloc)$|"
    r"printf|vfprintf|stdio|"
    r"^std::|"
    r"bad_alloc|bad_array_new_length|"
    r"_scrt_|__scrt|"
    r"dynamic_(initializer|atexit)|"
    r"^_?guard_|security_(check|cookie)",
    re.IGNORECASE,
)


def is_input_reachable(function: str | None) -> bool:
    """Can varying the input plausibly steer a branch in this function?

    Conservative: unknown functions count as reachable, because dropping a real
    parser would be worse than including an allocator.
    """
    if not function:
        return True
    return not _INPUT_OPAQUE.search(function)


def compute_frontier(
    covered: set[int],
    graph: BlockGraph,
    *,
    limit: int | None = None,
    input_reachable_only: bool = True,
) -> list[FrontierBlock]:
    """Covered blocks with unreached successors, most unreached first.

    Two filters, both of which exist to stop the LLM being asked the impossible:

    * a successor must be a **known block** -- one Ghidra mentioned but that is
      not in A3 cannot be instrumented, so it would never be observed as covered
      no matter what;
    * with ``input_reachable_only``, the successor must be in a function whose
      branches input can steer. An allocation-failure path is not reachable by
      sending different bytes.

    CP7 learned this by watching a round fail: the LLM aimed correctly at all
    five frontier branches and hit none, because they included an OOM path,
    printf internals, and a "packet too small" guard the *harness* could not
    express (D-040).
    """
    frontier: list[FrontierBlock] = []

    for rva in covered:
        record = graph.blocks.get(rva)
        if record is None:
            continue  # covered, but not a block start we enumerated
        unreached = tuple(
            s
            for s in record.get("successors", [])
            if s not in covered
            and s in graph.blocks
            and (
                not input_reachable_only
                or is_input_reachable(graph.function_of(s))
            )
        )
        if not unreached:
            continue
        frontier.append(
            FrontierBlock(
                rva=rva,
                static_addr=record["static_addr"],
                function=record.get("function"),
                unreached_successor_rvas=unreached,
                unreached_successor_statics=tuple(
                    graph.blocks[s]["static_addr"] for s in unreached
                ),
            )
        )

    # Most unreached successors first, then by address for a stable order.
    frontier.sort(key=lambda f: (-f.degree, f.rva))
    return frontier[:limit] if limit else frontier


# --- plateau --------------------------------------------------------------


@dataclass(frozen=True)
class PlateauState:
    plateaued: bool
    executions_since_new_coverage: int
    seconds_since_new_coverage: float
    threshold_executions: int
    reason: str


@dataclass
class PlateauDetector:
    """Execution-based plateau detection on aggregate coverage.

    ``observe`` is fed (executions, new-coverage-event count) samples. The event
    count is monotonic -- it is a file count in ``outputs/`` -- so any increase
    means the campaign is still finding new code.
    """

    threshold_executions: int
    wall_clock_bound_s: float | None = None

    last_event_count: int = field(default=0, init=False)
    executions_at_last_event: int = field(default=0, init=False)
    time_at_last_event: float = field(default=0.0, init=False)
    latest_executions: int = field(default=0, init=False)
    latest_time: float = field(default=0.0, init=False)
    started: bool = field(default=False, init=False)
    fired: bool = field(default=False, init=False)

    def observe(
        self, executions: int, new_coverage_events: int, now: float
    ) -> PlateauState:
        if not self.started:
            self.started = True
            self.last_event_count = new_coverage_events
            self.executions_at_last_event = executions
            self.time_at_last_event = now

        if new_coverage_events > self.last_event_count:
            self.last_event_count = new_coverage_events
            self.executions_at_last_event = executions
            self.time_at_last_event = now
            # New coverage re-arms the detector: GATE 7 wants ONE seed-gen call
            # per plateau, not one per tick while a plateau persists.
            self.fired = False

        self.latest_executions = executions
        self.latest_time = now

        execs_since = max(0, executions - self.executions_at_last_event)
        secs_since = max(0.0, now - self.time_at_last_event)

        by_execs = execs_since >= self.threshold_executions
        by_clock = (
            self.wall_clock_bound_s is not None
            and secs_since >= self.wall_clock_bound_s
        )

        if by_execs:
            reason = f"{execs_since} executions without new coverage"
        elif by_clock:
            reason = (
                f"{secs_since:.0f}s without new coverage (wall-clock safety net; "
                f"only {execs_since} executions, so throughput may be low)"
            )
        else:
            reason = (
                f"{execs_since}/{self.threshold_executions} executions since new "
                f"coverage"
            )

        return PlateauState(
            plateaued=bool(by_execs or by_clock),
            executions_since_new_coverage=execs_since,
            seconds_since_new_coverage=secs_since,
            threshold_executions=self.threshold_executions,
            reason=reason,
        )

    def should_fire(self, state: PlateauState) -> bool:
        """True at most once per plateau. Consumes the trigger."""
        if state.plateaued and not self.fired:
            self.fired = True
            return True
        return False


def summarise(
    *,
    tick: int,
    covered: set[int],
    frontier: list[FrontierBlock],
    corpus_size: int,
    crash_buckets: int,
    previous_covered: int = 0,
) -> CoverageSummary:
    """Build the compact summary the slow clock is allowed to send.

    Section 7.3 and section 10: never the raw corpus, never a full coverage
    bitmap. ``frontier`` carries the static addresses of the covered blocks that
    still have somewhere to go.
    """
    return CoverageSummary(
        tick=tick,
        total_edges=len(covered),
        new_edges=max(0, len(covered) - previous_covered),
        plateau_ticks=0,
        corpus_size=corpus_size,
        crash_bucket_count=crash_buckets,
        frontier=[f.static_addr for f in frontier],
    )
