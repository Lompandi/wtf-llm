"""Crash bucketing (CLAUDE.md CP8, edges 33-34, triage signal 1).

**This runs before triage, always.** Raw crash volume scales with worker count
while the number of distinct bugs does not (section 12.5), so dedup is what
protects the NCHC allocation from being spent re-explaining the same bug. Section
10 lists sending un-deduplicated crashes to the LLM as an anti-pattern.

**NO LLM IN THIS MODULE.** Bucketing is mechanical. Deciding whether two buckets
are really the same bug is a judgement, and that belongs to triage (CP9).

Why this is not just "hash the backtrace"
-----------------------------------------
Section 8 asks for a stack hash over the top N frames normalised to static
addresses, with ``(fault_static_addr, fault_type)`` as the fallback where
backtrace recovery is unreliable. On this target **neither is available**:

* A crash file is a name plus the test-case bytes. There are no registers and no
  backtrace in it -- to get either you must re-execute the input.
* Every fault lands *outside* the target module, in a system DLL. So
  ``fault_static_addr`` is meaningless and ``crash_watch.py`` deliberately leaves
  it 0 (D-035) -- de-sliding a foreign module's address with our module base
  produces a fictitious number that would look authoritative.

Measured on the CP7 campaign's output: 53 crash files, **52 distinct fault
addresses**, all inside a 0x39e span. Bucketing by fault address yields 52 buckets
for what is one bug. That is not dedup.

What does work is bucketing by the **function** containing the fault, which is a
statement about *where the code went wrong* rather than which byte of an unrolled
loop happened to touch the bad page. Symbolizing the 52 addresses collapses them
to two: ``VCRUNTIME140.dll!memmove`` (51) and
``VCRUNTIME140.dll!memcpy_repmovs`` (1). Both are the same memcpy family, but
noticing *that* is a judgement, so dedup reports two buckets and lets triage
argue they are one bug.

The key ladder
--------------
Keys degrade explicitly, best first, and every bucket records which rung produced
it. That labelling is the point: a coarse bucket that is indistinguishable from a
precise one invites treating "same fault type" as "same bug".

1. ``stack_hash``    -- top N static addresses of the backtrace. Requires a
                        backtrace. Section 8's preferred key.
2. ``fault_function``-- ``(fault_type, module!function)`` from symbolization.
                        Requires symbols to resolve a name.
3. ``fault_module``  -- ``(fault_type, module, offset)`` when the module resolves
                        but no function does. Does NOT collapse within a function,
                        so it is a genuine downgrade.
4. ``fault_type``    -- last resort, and marked as such. Merges aggressively and
                        will merge unrelated bugs; present so that a crash is
                        never dropped for want of a key.

Addresses are always normalised before hashing. Hashing runtime addresses would
make identical bugs hash differently across runs, because the module base moves
(section 9).
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from arch.addr import AddressSpace
from arch.contracts import CrashBucket, CrashRecord
from analysis.trace import SymbolRef, symbolize_addresses

__all__ = [
    "KEY_KINDS",
    "BucketKey",
    "FaultResolver",
    "SymbolizingResolver",
    "bucket_key",
    "bucket_crashes",
]

# Most precise first. The order is the ladder.
KEY_KINDS = ("stack_hash", "fault_function", "fault_module", "fault_type")

# Section 8: "hash the top N frames of the crashing backtrace (N configurable,
# start at 5)".
DEFAULT_TOP_FRAMES = 5


@dataclass(frozen=True)
class BucketKey:
    """A bucket identity plus which rung of the ladder produced it."""

    kind: str
    detail: str

    def __post_init__(self) -> None:
        if self.kind not in KEY_KINDS:
            raise ValueError(f"kind must be one of {KEY_KINDS}, got {self.kind!r}")

    @property
    def bucket_id(self) -> str:
        """Stable, short, and self-describing.

        The kind is part of the id on purpose: two buckets keyed at different
        rungs are not comparable, and an id that hides the rung invites comparing
        them anyway.
        """
        digest = hashlib.sha256(f"{self.kind}:{self.detail}".encode()).hexdigest()
        return f"{self.kind}-{digest[:12]}"

    @property
    def precision_rank(self) -> int:
        """0 is the most precise rung."""
        return KEY_KINDS.index(self.kind)


class FaultResolver:
    """Maps a runtime fault address to a symbol. Default resolves nothing.

    Split out so bucketing is testable without symbolizer-rs, a memory dump or
    any subprocess: the ladder's behaviour when symbols are unavailable is
    exactly what needs testing, and it is the common case on a machine that has
    not downloaded PDBs.
    """

    def resolve(self, addresses: list[int]) -> dict[int, SymbolRef]:
        return {}


@dataclass
class SymbolizingResolver(FaultResolver):
    """Resolves fault addresses through symbolizer-rs.

    One batched call for every address, not one per crash: symbolizer-rs takes a
    trace, and a list of addresses *is* a trace of length N. Measured at 52
    addresses in 0.0 s, so there is no reason to be clever about caching here.
    """

    crash_dump: Path
    workdir: Path
    symbolizer: Path | None = None
    symbol_paths: list[str] | None = None
    symcache: Path | None = None

    def resolve(self, addresses: list[int]) -> dict[int, SymbolRef]:
        return symbolize_addresses(
            addresses,
            crash_dump=self.crash_dump,
            workdir=self.workdir,
            symbolizer=self.symbolizer,
            symbol_paths=self.symbol_paths,
            symcache=self.symcache,
        )


def _stack_hash(backtrace: list[int], top_frames: int) -> str:
    """Hash of the top N frames. Caller guarantees STATIC addresses."""
    frames = backtrace[:top_frames]
    joined = ",".join(f"{frame:#x}" for frame in frames)
    return hashlib.sha256(joined.encode()).hexdigest()[:16]


def bucket_key(
    record: CrashRecord,
    *,
    symbol: SymbolRef | None = None,
    top_frames: int = DEFAULT_TOP_FRAMES,
    space: AddressSpace | None = None,
) -> BucketKey:
    """Pick the most precise key this crash supports.

    ``space`` is only needed when the backtrace holds runtime addresses; pass it
    and they are converted, because section 9 requires static addresses for
    hashing and a mixed-space backtrace would hash differently run to run. A
    backtrace already in static form needs no space.
    """
    if record.backtrace:
        frames = record.backtrace
        if space is not None:
            frames = [space.to_static(frame) for frame in frames]
        return BucketKey(
            kind="stack_hash",
            detail=f"{record.fault_type}|{_stack_hash(frames, top_frames)}",
        )

    if symbol is not None and symbol.function_key:
        return BucketKey(
            kind="fault_function",
            detail=f"{record.fault_type}|{symbol.function_key}",
        )

    if symbol is not None and symbol.module and symbol.offset is not None:
        # No function name, so this cannot collapse within a function. Keeping
        # the offset is deliberate: merging every unnamed address in a module
        # would be a bigger lie than not merging them.
        return BucketKey(
            kind="fault_module",
            detail=f"{record.fault_type}|{symbol.module}+{symbol.offset:#x}",
        )

    return BucketKey(kind="fault_type", detail=record.fault_type)


def bucket_crashes(
    records: list[CrashRecord],
    *,
    resolver: FaultResolver | None = None,
    top_frames: int = DEFAULT_TOP_FRAMES,
    space: AddressSpace | None = None,
) -> list[CrashBucket]:
    """Collapse crashes into buckets, most-hit first.

    The representative is the crash with the **smallest input**, not the first
    seen. A smaller reproducer is easier for a human to read and cheaper to
    replay, and on the measured set the smallest is 70 bytes against a 1,258-byte
    alternative for the same bug. Ties break on timestamp so the choice is
    deterministic -- an unstable representative would make bucket ids stable
    while the evidence behind them drifted.
    """
    if not records:
        return []

    resolver = resolver or FaultResolver()
    symbols = resolver.resolve([r.fault_runtime_addr for r in records])

    grouped: dict[str, list[CrashRecord]] = defaultdict(list)
    keys: dict[str, BucketKey] = {}

    for record in records:
        key = bucket_key(
            record,
            symbol=symbols.get(record.fault_runtime_addr),
            top_frames=top_frames,
            space=space,
        )
        grouped[key.bucket_id].append(record)
        keys[key.bucket_id] = key

    buckets: list[CrashBucket] = []
    for bucket_id, members in grouped.items():
        representative = min(
            members, key=lambda r: (len(r.input_bytes), r.timestamp)
        )
        key = keys[bucket_id]
        buckets.append(
            CrashBucket(
                bucket_id=bucket_id,
                representative=representative,
                hit_count=len(members),
                key_kind=key.kind,
                key_detail=key.detail,
            )
        )

    # Most-hit first, then by precision so a coarse bucket never outranks a
    # precise one at equal counts.
    buckets.sort(key=lambda b: (-b.hit_count, KEY_KINDS.index(b.key_kind)))
    return buckets
