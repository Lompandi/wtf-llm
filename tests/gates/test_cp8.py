"""GATE 8 -- crash dedup, classification, deterministic replay, traces (CP8).

GATE 8 (edges 33-37) requires:

* given a set of raw crashes, dedup collapses them to a small bucket count with
  correct ``hit_count``;
* every bucket has a ``ReplayResult``;
* ``reverse.py`` returns pseudo-C for each bucket;
* **no LLM call occurs anywhere in CP8's path.**

Unit tests run everywhere. Tests that need wtf or symbolizer-rs read the recorded
evidence under ``artifacts/runs/gate8/``, produced by
``python -m analysis.pipeline --target-dir targets/snapfuzz-gate7 --label gate8``,
and skip with a message naming what is missing rather than asserting something
vacuous.
"""

from __future__ import annotations

import ast
import json
import time
from pathlib import Path

import pytest

from analysis.classify import NEAR_NULL_LIMIT, Classification, classify
from analysis.dedup import (
    DEFAULT_TOP_FRAMES,
    KEY_KINDS,
    BucketKey,
    FaultResolver,
    bucket_crashes,
    bucket_key,
)
from analysis.reverse import CrashContext
from analysis.trace import (
    KERNEL_BASE,
    SymbolRef,
    fault_address_from_trace,
    fault_index_from_trace,
    frames_before_fault,
    parse_symbol_line,
)
from arch.addr import AddressSpace
from arch.contracts import CrashBucket, CrashRecord, ReplayResult, TraceRef

REPO_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = REPO_ROOT / "artifacts" / "runs" / "gate8"
CRASHES = REPO_ROOT / "targets" / "snapfuzz-gate7" / "crashes"

# CP8's own modules. analysis/reverse.py is listed even though it imports
# llm/ghidra_mcp -- see test_no_llm_call_anywhere_in_cp8 for why that is sound.
CP8_MODULES = (
    "analysis/dedup.py",
    "analysis/classify.py",
    "analysis/replay.py",
    "analysis/trace.py",
    "analysis/reverse.py",
    "analysis/coverage_report.py",
    "analysis/pipeline.py",
)

READ = "access-violation-read"
WRITE = "access-violation-write"


def _record(
    addr: int,
    *,
    size: int = 32,
    fault_type: str = READ,
    backtrace: list[int] | None = None,
    stamp: float | None = None,
    static: int = 0,
    module: str | None = None,
    registers: dict[str, int] | None = None,
    payload: bytes | None = None,
) -> CrashRecord:
    return CrashRecord(
        input_bytes=payload if payload is not None else b"A" * size,
        fault_type=fault_type,
        fault_runtime_addr=addr,
        fault_static_addr=static,
        fault_module=module,
        registers=registers or {},
        backtrace=backtrace or [],
        coverage_delta=0,
        backend="bochscpu",
        timestamp=stamp if stamp is not None else time.time(),
    )


def _evidence(name: str):
    path = EVIDENCE / name
    if not path.exists():
        pytest.skip(
            f"{path.relative_to(REPO_ROOT)} has not been produced. Run: "
            f"python -m analysis.pipeline --target-dir targets/snapfuzz-gate7 "
            f"--label gate8"
        )
    return json.loads(path.read_text(encoding="utf-8"))


# --- the key ladder -------------------------------------------------------


def test_key_ladder_is_ordered_most_precise_first() -> None:
    """The ladder's order IS its meaning, so it is asserted, not assumed."""
    assert KEY_KINDS == ("stack_hash", "fault_function", "fault_module", "fault_type")
    ranks = [BucketKey(kind=k, detail="x").precision_rank for k in KEY_KINDS]
    assert ranks == sorted(ranks) == [0, 1, 2, 3]


def test_a_backtrace_wins_over_a_symbol() -> None:
    """Section 8 prefers a stack hash; a symbol must not outrank one."""
    symbol = SymbolRef(
        raw="m!f+0x1", module="VCRUNTIME140.dll", function="memmove", offset=1
    )
    key = bucket_key(_record(0x7FF8_0000_1000, backtrace=[0x1400_1111]), symbol=symbol)
    assert key.kind == "stack_hash"


def test_a_symbol_is_used_when_there_is_no_backtrace() -> None:
    """The measured case: crash files carry no backtrace at all."""
    symbol = SymbolRef(
        raw="m!f+0x1", module="VCRUNTIME140.dll", function="memmove", offset=1
    )
    key = bucket_key(_record(0x7FF8_0000_1000), symbol=symbol)
    assert key.kind == "fault_function"
    assert "VCRUNTIME140.dll!memmove" in key.detail


def test_an_unnamed_address_degrades_to_module_and_offset() -> None:
    """Symbols resolved the module but no function: a genuine downgrade.

    Merging every unnamed address in a module would be a bigger lie than not
    merging them, so the offset stays in the key.
    """
    symbol = SymbolRef(raw="ntdll.dll+0x1234", module="ntdll.dll", function=None, offset=0x1234)
    key = bucket_key(_record(0x7FF8_0000_1000), symbol=symbol)
    assert key.kind == "fault_module"
    assert "ntdll.dll+0x1234" in key.detail


def test_with_nothing_at_all_the_weakest_rung_is_used_and_marked() -> None:
    """A crash is never dropped for want of a key, but the rung is recorded.

    This rung merges aggressively and will merge unrelated bugs. That is
    acceptable only because it is labelled -- an unlabelled coarse bucket reads
    exactly like a precise one.
    """
    key = bucket_key(_record(0x7FF8_0000_1000))
    assert key.kind == "fault_type"
    assert key.bucket_id.startswith("fault_type-")


def test_the_bucket_id_names_its_own_rung() -> None:
    """Two buckets keyed at different rungs are not comparable."""
    for kind in KEY_KINDS:
        assert BucketKey(kind=kind, detail="d").bucket_id.startswith(f"{kind}-")


def test_an_unknown_rung_is_refused() -> None:
    with pytest.raises(ValueError, match="kind must be one of"):
        BucketKey(kind="vibes", detail="d")


# --- section 9: static addresses, never runtime ---------------------------


def test_the_same_bug_at_a_different_module_base_lands_in_one_bucket() -> None:
    """Section 9's actual requirement, and the one that breaks silently.

    A backtrace is hashed after conversion to static addresses. Hashing runtime
    addresses would give the same bug a different id on every run, because the
    module base moves -- and nothing would look wrong.
    """
    static_frames = [0x1400_1111, 0x1400_2222, 0x1400_3333]
    early = AddressSpace("t", 0x7FF7_0000_0000, 0x1_4000_0000)
    later = AddressSpace("t", 0x7FF8_9AB0_0000, 0x1_4000_0000)

    first = bucket_key(
        _record(0, backtrace=[early.to_runtime(a) for a in static_frames]),
        space=early,
    )
    second = bucket_key(
        _record(0, backtrace=[later.to_runtime(a) for a in static_frames]),
        space=later,
    )
    assert first.kind == second.kind == "stack_hash"
    assert first.bucket_id == second.bucket_id


def test_only_the_top_frames_take_part_in_the_hash() -> None:
    """Section 8: top N frames, N configurable, default 5.

    Deeper frames differing must not split a bucket -- that is the entire reason
    for truncating rather than hashing the whole stack.
    """
    shared = list(range(0x1400_0000, 0x1400_0000 + DEFAULT_TOP_FRAMES))
    a = bucket_key(_record(0, backtrace=shared + [0xAAAA]))
    b = bucket_key(_record(0, backtrace=shared + [0xBBBB]))
    assert a.bucket_id == b.bucket_id

    deeper = bucket_key(_record(0, backtrace=shared + [0xAAAA]), top_frames=6)
    assert deeper.bucket_id != a.bucket_id


# --- bucketing behaviour --------------------------------------------------


def test_fault_type_splits_buckets_even_within_one_function() -> None:
    """A read and a write in the same function are not the same finding.

    On the real set this is what separates the out-of-bounds READ from the
    out-of-bounds WRITE, and the write is the more serious of the two.
    """
    symbol = SymbolRef(raw="m!memmove", module="VCRUNTIME140.dll", function="memmove", offset=0)

    class OneFunction(FaultResolver):
        def resolve(self, addresses):
            return {a: symbol for a in addresses}

    records = [_record(0x1000, fault_type=READ), _record(0x1004, fault_type=WRITE)]
    buckets = bucket_crashes(records, resolver=OneFunction())
    assert len(buckets) == 2


def test_hit_count_is_the_number_of_crashes_merged() -> None:
    records = [_record(0x1000 + i) for i in range(7)]
    buckets = bucket_crashes(records)
    assert len(buckets) == 1
    assert buckets[0].hit_count == 7
    assert sum(b.hit_count for b in buckets) == len(records)


def test_the_representative_is_the_smallest_reproducer() -> None:
    """Smaller inputs are easier to read and cheaper to replay.

    On the real set the smallest is 70 bytes against a 1,258-byte alternative for
    the same bug.
    """
    records = [_record(0x1000, size=900), _record(0x1004, size=70), _record(0x1008, size=300)]
    buckets = bucket_crashes(records)
    assert len(buckets[0].representative.input_bytes) == 70


def test_the_representative_choice_is_deterministic() -> None:
    """An unstable representative would leave bucket ids stable while the
    evidence behind them drifted, which is worse than either being unstable."""
    records = [
        _record(0x1000, size=70, stamp=100.0),
        _record(0x1004, size=70, stamp=50.0),
    ]
    first = bucket_crashes(list(records))[0]
    second = bucket_crashes(list(reversed(records)))[0]
    assert first.representative.timestamp == second.representative.timestamp == 50.0


def test_buckets_are_ordered_most_hit_first() -> None:
    records = [_record(0x1000, fault_type=READ) for _ in range(5)]
    records += [_record(0x2000, fault_type=WRITE)]
    buckets = bucket_crashes(records)
    assert [b.hit_count for b in buckets] == sorted(
        [b.hit_count for b in buckets], reverse=True
    )


def test_no_crashes_gives_no_buckets_rather_than_an_error() -> None:
    assert bucket_crashes([]) == []


def test_the_bucket_records_which_rung_produced_it() -> None:
    """Without this a coarse bucket is indistinguishable from a precise one."""
    bucket = bucket_crashes([_record(0x1000)])[0]
    assert bucket.key_kind in KEY_KINDS
    assert bucket.key_detail


# --- classification -------------------------------------------------------


def test_near_null_uses_the_os_reserved_region() -> None:
    """The boundary is Windows' own 64 KB reservation, not a round number."""
    assert NEAR_NULL_LIMIT == 0x1_0000
    assert classify(_record(0x120)).near_null is True
    assert classify(_record(0x7FF8_0000_0000)).near_null is False


def test_no_fault_address_leaves_every_derived_field_unknown() -> None:
    """None, not False. "not near null" and "we have no address" must not look
    the same to triage."""
    result = classify(_record(0))
    assert result.near_null is None
    assert result.wild is None
    assert result.attacker_influenced is None
    assert any("no fault address" in n for n in result.notes)


def test_the_access_direction_comes_from_the_fault_type() -> None:
    assert classify(_record(0x1000, fault_type=READ)).access == "read"
    assert classify(_record(0x1000, fault_type=WRITE)).access == "write"


def test_an_unnamed_fault_type_does_not_default_to_read() -> None:
    result = classify(_record(0x1000, fault_type="timeout"))
    assert result.access == "unknown"
    assert any("does not name read or write" in n for n in result.notes)


def test_attacker_influence_reports_the_widths_it_matched() -> None:
    """A 2-byte match hits by chance in most binary inputs, so the width is
    reported rather than collapsed into a bare boolean."""
    payload = (0x4142434445464748).to_bytes(8, "little")
    strong = classify(_record(0x4142434445464748, payload=payload))
    assert strong.attacker_influenced is True
    assert 8 in strong.influence_widths

    weak = classify(_record(0x1234, payload=b"\x34\x12"))
    assert weak.attacker_influenced is True
    assert weak.influence_widths == [2]
    assert any("weak evidence" in n for n in weak.notes)


def test_missing_registers_are_admitted_not_invented() -> None:
    result = classify(_record(0x1000))
    assert result.registers_available is False
    assert any("no registers" in n for n in result.notes)


def test_no_disassembly_is_reported_when_the_fault_is_outside_our_module() -> None:
    """The measured case. Disassembling a system DLL from a copy on THIS host
    could decode different bytes than the guest ran, and presenting that as the
    faulting instruction would be worse than presenting nothing."""
    result = classify(_record(0x7FF8_AA38_1378))
    assert result.faulting_instruction is None
    assert result.disasm_source == "unavailable"


# --- trace primitives -----------------------------------------------------


def test_the_fault_is_the_last_user_address_before_the_kernel(tmp_path: Path) -> None:
    """Not the last line: the trace runs on into the exception dispatcher.

    Measured on a real crash: 43,305 lines, fault at index 38,752, and 4,552
    lines after it.
    """
    trace = tmp_path / "t.trace"
    trace.write_text(
        "\n".join(
            [
                "0x140001000",
                f"{KERNEL_BASE + 0x10:#x}",  # an earlier syscall
                "0x140001010",
                "0x140001020",  # <- the fault
                f"{KERNEL_BASE + 0x2000:#x}",
                f"{KERNEL_BASE + 0x2004:#x}",
            ]
        ),
        encoding="utf-8",
    )
    assert fault_address_from_trace(trace) == 0x140001020
    assert fault_index_from_trace(trace) == 3


def test_a_trace_that_never_faults_returns_none_not_zero(tmp_path: Path) -> None:
    trace = tmp_path / "t.trace"
    trace.write_text("0x140001000\n0x140001004\n", encoding="utf-8")
    assert fault_address_from_trace(trace) is None
    assert fault_index_from_trace(trace) is None


def test_symbol_lines_split_into_module_function_and_offset() -> None:
    parsed = parse_symbol_line("VCRUNTIME140.dll!memmove+0x40")
    assert (parsed.module, parsed.function, parsed.offset) == (
        "VCRUNTIME140.dll",
        "memmove",
        0x40,
    )
    assert parsed.function_key == "VCRUNTIME140.dll!memmove"


def test_a_module_without_a_function_has_no_function_key() -> None:
    """Load-bearing for dedup: substituting the module for a missing function
    name would merge unrelated bugs."""
    parsed = parse_symbol_line("ntdll.dll+0x1234")
    assert parsed.function is None
    assert parsed.function_key is None


def test_frames_are_filtered_before_the_tail_is_taken(tmp_path: Path) -> None:
    """Asking for 3 target frames must give 3 target frames.

    Taking the tail first and filtering after is the bug this prevents: on a real
    trace the final thousands of frames are all memcpy internals, so the filter
    found nothing and static context came back empty.
    """
    symbolized = tmp_path / "s.txt"
    lines = ["tlv_server.exe!ProcessPacket+0x%x" % i for i in range(5)]
    lines += ["VCRUNTIME140.dll!memmove+0x%x" % i for i in range(50)]
    lines += ["nt!KiPageFault+0x0"]
    symbolized.write_text("\n".join(lines), encoding="utf-8")

    frames = frames_before_fault(
        symbolized, count=3, module="tlv_server", fault_index=len(lines) - 2
    )
    assert len(frames) == 3
    assert all(f.startswith("tlv_server") for f in frames)


def test_the_post_fault_dispatch_path_is_excluded(tmp_path: Path) -> None:
    """After the fault the kernel returns to user-mode ntdll and re-enters, so
    the LAST user->kernel transition is not the fault."""
    symbolized = tmp_path / "s.txt"
    lines = [
        "tlv_server.exe!ProcessPacket+0x1",
        "VCRUNTIME140.dll!memmove+0x2",  # index 1 -- the fault
        "nt!KiPageFault+0x0",
        "ntdll.dll!RtlDispatchException+0x0",  # user mode again
        "nt!KiExceptionDispatch+0x0",
    ]
    symbolized.write_text("\n".join(lines), encoding="utf-8")
    assert frames_before_fault(symbolized, count=1, fault_index=1) == [
        "VCRUNTIME140.dll!memmove+0x2"
    ]


# --- RULE 1 / GATE 8: no LLM anywhere ------------------------------------


@pytest.mark.parametrize("module", CP8_MODULES)
def test_no_llm_call_anywhere_in_cp8(module: str) -> None:
    """GATE 8 asserts CP8's whole path is LLM-free.

    The check is on :mod:`llm.client` and ``LlmClient`` specifically, not on the
    string "llm", because ``analysis/reverse.py`` legitimately imports
    ``llm.ghidra_mcp`` -- a **decompiler** client that asks a Ghidra plugin over
    HTTP to decompile an address. No model is invoked and no prompt is sent. A
    check that merely looked for "llm" would have to be weakened to accommodate
    that, and a weakened check is worse than none.
    """
    source = (REPO_ROOT / module).read_text(encoding="utf-8")
    tree = ast.parse(source)

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert node.module != "llm.client", f"{module} imports llm.client"
            assert not node.module.startswith("llm.seed_gen"), (
                f"{module} imports seed generation"
            )
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name != "llm.client", f"{module} imports llm.client"

    for forbidden in ("LlmClient", "complete_json(", "chat/completions"):
        assert forbidden not in source, (
            f"{module} references {forbidden!r}; CP8 must contain no LLM call"
        )


def test_the_decompiler_exception_is_real_and_narrow() -> None:
    """Guards the exception above: ghidra_mcp must stay LLM-free itself.

    If someone later adds a model call to llm/ghidra_mcp.py, the reasoning that
    lets analysis/reverse.py import it collapses -- and silently, because the
    import in reverse.py would not change.
    """
    source = (REPO_ROOT / "llm" / "ghidra_mcp.py").read_text(encoding="utf-8")
    assert "LlmClient" not in source
    assert "from llm.client" not in source


# --- recorded evidence from the live pipeline ----------------------------


def test_dedup_collapses_the_real_crash_set() -> None:
    """52 distinct fault addresses must not become 52 buckets.

    This is the property that fails if dedup keys on the fault address, and the
    reason section 8's documented fallback is unusable on this target: every fault
    lands outside the target module, so fault_static_addr is 0 for all of them.
    """
    buckets = [CrashBucket.model_validate(b) for b in _evidence("buckets.json")]
    summary = _evidence("summary.json")

    assert summary["crashes"] >= 50, "too few crashes for this to mean anything"
    assert len(buckets) == summary["buckets"]
    assert len(buckets) <= 8, (
        f"{summary['crashes']} crashes collapsed to only {len(buckets)} buckets; "
        f"more than 8 means bucketing is tracking the fault address"
    )
    assert sum(b.hit_count for b in buckets) == summary["crashes"], (
        "hit counts must account for every crash, or some were silently dropped"
    )
    # And it must be doing so for the stated reason.
    assert all(b.key_kind == "fault_function" for b in buckets)


def test_the_real_buckets_separate_reads_from_writes() -> None:
    """The write is the more serious finding and must not be merged into the read."""
    buckets = [CrashBucket.model_validate(b) for b in _evidence("buckets.json")]
    kinds = {b.key_detail.split("|")[0] for b in buckets}
    assert READ in kinds
    assert WRITE in kinds, (
        "no out-of-bounds WRITE bucket: either none was found or reads and writes "
        "were merged, and those are very different findings"
    )


def test_every_bucket_has_a_replay_result() -> None:
    buckets = [CrashBucket.model_validate(b) for b in _evidence("buckets.json")]
    replays = [ReplayResult.model_validate(r) for r in _evidence("replays.json")]
    assert {r.bucket_id for r in replays} == {b.bucket_id for b in buckets}


def test_replays_reproduced_deterministically_on_bochscpu() -> None:
    """bochscpu is the only fully deterministic backend (section 13.5), so a
    non-deterministic result here would point at our harness, not the target."""
    replays = [ReplayResult.model_validate(r) for r in _evidence("replays.json")]
    assert all(r.backend == "bochscpu" for r in replays)
    assert all(r.replays >= 2 for r in replays), "one replay proves no determinism"
    reproduced = [r for r in replays if r.reproduced]
    assert reproduced, "no bucket reproduced at all"
    assert all(r.deterministic for r in reproduced)


def test_a_non_reproduction_would_say_it_is_not_evidence_of_benignness() -> None:
    """Section 10: a non-reproducing crash is NOT automatically benign."""
    replays = [ReplayResult.model_validate(r) for r in _evidence("replays.json")]
    for replay in replays:
        if not replay.reproduced:
            assert "not automatically benign" in replay.notes.lower() or (
                "absence of evidence" in replay.notes.lower()
            )


def test_every_trace_reached_the_fuzz_entry() -> None:
    """reached_fuzz_entry is a sanity check, never a default: a crash whose trace
    never enters the parser says nothing about the target."""
    traces = [TraceRef.model_validate(t) for t in _evidence("traces.json")]
    assert traces, "no traces recorded"
    assert all(t.reached_fuzz_entry for t in traces)
    assert all(Path(t.symbolized_path).exists() for t in traces)


def test_every_bucket_has_static_context_with_pseudo_c() -> None:
    """GATE 8 asks for pseudo-C per bucket -- with the honest complication.

    Every fault is in ``VCRUNTIME140.dll!memmove``, so there is no pseudo-C for
    the faulting instruction and there never will be: A2 covers tlv_server, not
    the CRT. What is asserted is what the implementation actually promises -- the
    deepest function on the fault path that A2 can describe -- and that it is
    LABELLED as a caller, so nobody reads it as the faulting instruction's source.
    """
    contexts = [CrashContext.model_validate(c) for c in _evidence("contexts.json")]
    assert contexts, "no contexts recorded"

    for context in contexts:
        assert context.pseudo_c, f"{context.bucket_id} has no pseudo-C"
        assert context.pseudo_c_source in {"a2_cache", "ghidra_mcp"}
        assert context.function
        assert context.is_faulting_frame is False
        assert any("CALLER" in n for n in context.notes), (
            "the context must state that this is a caller, not the fault site"
        )
        assert context.faulting_frame and "!" in context.faulting_frame


def test_the_static_context_names_the_path_into_the_faulting_library() -> None:
    """The sequence is what distinguishes the two bug variants: the READ arrives
    via make_unique/memset (Allocate) and the WRITE via the chunk search (Edit).
    """
    contexts = [CrashContext.model_validate(c) for c in _evidence("contexts.json")]
    for context in contexts:
        assert context.in_module_call_path, f"{context.bucket_id} has no path"
        assert len(context.in_module_call_path) <= 8, "the tail must stay bounded"


def test_contract_round_trip_for_the_new_models() -> None:
    """Every stage boundary serialises to JSON and back (section 6)."""
    bucket = bucket_crashes([_record(0x1000)])[0]
    assert CrashBucket.model_validate_json(bucket.model_dump_json()) == bucket

    classification = classify(_record(0x1000))
    assert (
        Classification.model_validate_json(classification.model_dump_json())
        == classification
    )

    context = CrashContext(bucket_id="b", notes=["n"])
    assert CrashContext.model_validate_json(context.model_dump_json()) == context
