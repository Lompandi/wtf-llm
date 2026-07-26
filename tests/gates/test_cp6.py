"""GATE 6 -- GhidraMCP + pseudo-C cache (A2) + LLM fuzz-entry selection.

Gate conditions (edges 3, 4, 9, 28, 37):
  * A2 populated for the entry closure
  * `get_by_addr` returns pseudo-C for a known function address
  * GhidraMCP answers a live decompile request
  * `entry_select.py` emits a valid `FuzzEntry` whose `static_addr` is a real
    function
  * re-run CP3 with the LLM-chosen entry and confirm the snapshot still loads

Live tests are split by what they cost and what they need:

* ``SNAPFUZZ_LIVE_MCP=1`` -- needs a Ghidra **GUI** open with the plugin enabled,
  so it can never run unattended (D-039).
* ``SNAPFUZZ_LIVE_LLM=1`` -- spends allocation.

Regenerate the artifacts with::

    analyzeHeadless ... -postScript ExportPseudoC.java <out> function-closure ProcessPacket
    python -m prep.pseudoc_cache build --export artifacts/tlv_server/a2_pseudoc_export.json
    python -m prep.entry_select --cache artifacts/tlv_server/a2_pseudoc_module.sqlite
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from arch.addr import AddressSpace
from arch.contracts import FuzzEntry, PseudoCEntry, SnapshotRef
from prep.entry_select import _resolve_name, candidates
from prep.pseudoc_cache import PseudoCCache, build_from_export

REPO_ROOT = Path(__file__).resolve().parents[2]
# Repo-level artifacts: campaign runs, gate results, logs. NOT per target.
ARTIFACTS = REPO_ROOT / "artifacts"
# The DEVELOPMENT TARGET's derived artifacts. Per target since D-075: a second
# target used to overwrite these, and destroying them makes unrelated tests fail.
TARGET_ARTIFACTS = ARTIFACTS / "tlv_server"

A2_CLOSURE = TARGET_ARTIFACTS / "a2_pseudoc.sqlite"
A2_MODULE = TARGET_ARTIFACTS / "a2_pseudoc_module.sqlite"
A2_EXPORT = TARGET_ARTIFACTS / "a2_pseudoc_export.json"
FUZZ_ENTRY_LLM = TARGET_ARTIFACTS / "fuzz_entry_llm.json"
A1_LLM = TARGET_ARTIFACTS / "a1_snapshot_llm.json"

# Ground truth, established independently in tests/test_addr.py and by reading
# src/wtf/fuzzer_tlv_server.cc:113-124.
ENTRY_SYMBOL = "ProcessPacket"
ENTRY_STATIC = 0x140001150
ENTRY_RUNTIME = 0x7FF719E51150
MODULE_BASE = 0x7FF719E50000
GHIDRA_IMAGE_BASE = 0x140000000

live_mcp = pytest.mark.skipif(
    os.environ.get("SNAPFUZZ_LIVE_MCP") != "1",
    reason="needs a Ghidra GUI with GhidraMCP enabled; set SNAPFUZZ_LIVE_MCP=1",
)
live_llm = pytest.mark.skipif(
    os.environ.get("SNAPFUZZ_LIVE_LLM") != "1",
    reason="set SNAPFUZZ_LIVE_LLM=1 to spend allocation",
)
requires_a2 = pytest.mark.skipif(
    not A2_CLOSURE.exists(), reason="A2 not built; see this module's docstring"
)


# --- the cache, offline ---------------------------------------------------


def test_range_lookup_finds_the_containing_function(tmp_path: Path) -> None:
    """A fault address is almost never a function's entry point.

    This is the whole reason A2 is a database rather than files keyed by entry
    address: triage arrives with an address in the middle of a body.
    """
    cache = PseudoCCache(tmp_path / "a2.sqlite")
    cache.put(
        PseudoCEntry(
            module="m", static_addr=0x1000, function="parse", code="void parse(){}"
        ),
        min_static=0x1000,
        max_static=0x10FF,
    )

    assert cache.get_by_addr(0x1000).function == "parse"  # entry
    assert cache.get_by_addr(0x1080).function == "parse"  # middle
    assert cache.get_by_addr(0x10FF).function == "parse"  # last byte
    assert cache.get_by_addr(0x1100) is None  # past the end
    assert cache.get_by_addr(0x0FFF) is None  # before the start
    cache.close()


def test_tightest_enclosing_function_wins(tmp_path: Path) -> None:
    """Overlapping bodies happen; the innermost function is the informative one."""
    cache = PseudoCCache(tmp_path / "a2.sqlite")
    cache.put(
        PseudoCEntry(module="m", static_addr=0x1000, function="outer", code="o"),
        min_static=0x1000,
        max_static=0x2000,
    )
    cache.put(
        PseudoCEntry(module="m", static_addr=0x1500, function="inner", code="i"),
        min_static=0x1500,
        max_static=0x1600,
    )
    assert cache.get_by_addr(0x1550).function == "inner"
    assert cache.get_by_addr(0x1050).function == "outer"
    cache.close()


def test_mcp_sourced_rows_are_not_range_findable(tmp_path: Path) -> None:
    """An on-demand lookup knows only the entry address, not the body bounds.

    Recorded honestly: the row is findable by exact address and by name, but a
    range query will not match it, because inventing a span would make later
    range lookups confidently wrong.
    """
    cache = PseudoCCache(tmp_path / "a2.sqlite")
    cache.put(
        PseudoCEntry(module="m", static_addr=0x4000, function="late", code="l"),
        source="ghidra_mcp",
    )
    assert cache.get_by_addr(0x4000).function == "late"
    assert cache.get_by_addr(0x4008) is None
    assert cache.get_by_function("late").function == "late"
    cache.close()


def test_context_for_addr_marks_truncation(tmp_path: Path) -> None:
    """Section 7.3: summaries, not dumps -- and never a silent half-function."""
    cache = PseudoCCache(tmp_path / "a2.sqlite")
    cache.put(
        PseudoCEntry(module="m", static_addr=0x1000, function="big", code="x" * 5000),
        min_static=0x1000,
        max_static=0x2000,
    )
    ctx = cache.context_for_addr(0x1500, max_chars=500)
    assert "truncated" in ctx
    assert "m!big @ 0x1000" in ctx
    assert cache.context_for_addr(0x9999) is None
    cache.close()


def test_empty_export_is_rejected(tmp_path: Path) -> None:
    """An empty A2 makes seed-gen and triage context-free rather than failing."""
    export = tmp_path / "e.json"
    export.write_text(
        json.dumps({"module": "m", "image_base": 0, "functions": []}), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="no decompiled functions"):
        build_from_export(export, tmp_path / "a2.sqlite")


def test_backwards_bounds_are_rejected(tmp_path: Path) -> None:
    cache = PseudoCCache(tmp_path / "a2.sqlite")
    with pytest.raises(ValueError, match="below min_static"):
        cache.put(
            PseudoCEntry(module="m", static_addr=0x1000, function="f", code="c"),
            min_static=0x2000,
            max_static=0x1000,
        )
    cache.close()


# --- name resolution, which is what lets us refuse model addresses --------


def test_resolves_header_echo_but_refuses_invention() -> None:
    """The model echoed "ProcessPacket @ 0x140001150" from a prompt header.

    That is decoration, not a wrong answer, so it normalises. An invented name
    must still be refused -- names being checkable is exactly why the model is
    never trusted with an address.
    """
    from prep.entry_select import Candidate

    known = {
        "ProcessPacket": Candidate("ProcessPacket", ENTRY_STATIC, "sig", 100),
        "find_pe_section": Candidate("find_pe_section", 0x140002000, "sig", 50),
    }

    assert _resolve_name("ProcessPacket", known) == "ProcessPacket"
    assert _resolve_name("ProcessPacket @ 0x140001150", known) == "ProcessPacket"
    assert _resolve_name("  `ProcessPacket`  ", known) == "ProcessPacket"
    assert _resolve_name("processpacket", known) == "ProcessPacket"

    assert _resolve_name("ParsePacketHeader", known) is None
    assert _resolve_name("FUN_140009999", known) is None


def test_noise_filter_drops_crt_but_keeps_the_parser() -> None:
    """The filter must never remove a plausible parser."""
    from prep.entry_select import _NOISE

    for junk in (
        "__local_stdio_printf_options", "operator_new", "operator_delete[]",
        "bad_alloc", "__scrt_throw_std_bad_alloc", "printf",
        "`dynamic_initializer_for_'WsaData''",
    ):
        assert _NOISE.search(junk), f"{junk} should be filtered as noise"

    for keep in ("ProcessPacket", "find_pe_section", "parse_frame", "FUN_140001150"):
        assert not _NOISE.search(keep), f"{keep} must NOT be filtered"


# --- A2 as actually built -------------------------------------------------


@requires_a2
def test_a2_is_populated_for_the_entry_closure() -> None:
    """GATE 6: A2 populated for the entry closure."""
    with PseudoCCache(A2_CLOSURE) as cache:
        stats = cache.stats()
        assert stats is not None
        assert stats.functions > 0
        assert stats.module == "tlv_server"
        assert ENTRY_SYMBOL in cache.functions()


@requires_a2
def test_get_by_addr_returns_pseudoc_for_a_known_function() -> None:
    """GATE 6: get_by_addr returns pseudo-C for a known function address."""
    with PseudoCCache(A2_CLOSURE) as cache:
        entry = cache.get_by_addr(ENTRY_STATIC)
        assert entry is not None
        assert entry.function == ENTRY_SYMBOL
        assert entry.static_addr == ENTRY_STATIC
        # Real decompiler output, and specifically the parser's shape.
        assert "param_1" in entry.code or "ProcessPacket" in entry.code
        assert len(entry.code) > 100


@requires_a2
def test_get_by_addr_works_mid_function_on_real_data() -> None:
    """The triage case: an address inside the body, not at the entry."""
    with PseudoCCache(A2_CLOSURE) as cache:
        entry = cache.get_by_addr(ENTRY_STATIC + 0xB0)
        assert entry is not None
        assert entry.function == ENTRY_SYMBOL


@pytest.mark.skipif(not A2_MODULE.exists(), reason="module-scope A2 not built")
def test_module_scope_a2_gives_the_llm_real_choice() -> None:
    """Entry selection is only meaningful over candidates that do not presuppose
    the answer. The closure starts AT ProcessPacket, so it cannot test selection.
    """
    with PseudoCCache(A2_MODULE) as cache:
        all_functions = cache.functions()
        assert len(all_functions) > 100, "module scope should have many functions"
        surviving = candidates(cache)
        assert len(surviving) > 10
        assert any(c.function == ENTRY_SYMBOL for c in surviving), (
            "the noise filter removed the correct answer"
        )


# --- the LLM's choice -----------------------------------------------------


@pytest.mark.skipif(not FUZZ_ENTRY_LLM.exists(), reason="entry_select not run")
def test_llm_entry_is_a_valid_fuzz_entry_at_a_real_function() -> None:
    """GATE 6: a valid FuzzEntry whose static_addr is a REAL function."""
    entry = FuzzEntry.model_validate_json(
        FUZZ_ENTRY_LLM.read_text(encoding="utf-8")
    )
    assert entry.module == "tlv_server"
    assert entry.rationale.strip()

    # "A real function" is checked against A2, not taken on trust -- the model
    # supplies a name and we resolve the address ourselves.
    if A2_MODULE.exists():
        with PseudoCCache(A2_MODULE) as cache:
            found = cache.get_by_function(entry.symbol or "")
            assert found is not None, f"{entry.symbol!r} is not a function in A2"
            assert found.static_addr == entry.static_addr, (
                "the FuzzEntry address disagrees with A2 -- the address must "
                "come from the cache, never from the model"
            )


@pytest.mark.skipif(not FUZZ_ENTRY_LLM.exists(), reason="entry_select not run")
def test_llm_agrees_with_the_manual_choice() -> None:
    """Not a gate condition, but the headline result for contribution 1.

    Given 193 functions with no hint which is the parser, the LLM's answer is
    compared against the entry wtf's own author chose.
    """
    entry = FuzzEntry.model_validate_json(
        FUZZ_ENTRY_LLM.read_text(encoding="utf-8")
    )
    assert entry.symbol == ENTRY_SYMBOL, (
        f"LLM chose {entry.symbol!r}; ground truth is {ENTRY_SYMBOL!r}"
    )
    assert entry.static_addr == ENTRY_STATIC
    # And the injection spec, per the DECISIONS R7/R8 convention.
    assert entry.input_param == "rcx"
    assert entry.size_param == "rdx"


@pytest.mark.skipif(not A1_LLM.exists(), reason="CP3 not re-run with the LLM entry")
def test_snapshot_still_loads_with_the_llm_chosen_entry() -> None:
    """GATE 6: re-run CP3 with the LLM-chosen entry; the snapshot still loads.

    `ingest_state_dir` refuses a snapshot whose rip is not the entry, so a
    successfully written A1 IS the assertion that the two agree.
    """
    ref = SnapshotRef.model_validate_json(A1_LLM.read_text(encoding="utf-8"))
    assert ref.module_base == MODULE_BASE
    assert ref.entry_runtime_addr == ENTRY_RUNTIME

    space = AddressSpace("tlv_server", ref.module_base, ref.ghidra_image_base)
    assert space.to_static(ref.entry_runtime_addr) == ENTRY_STATIC

    entry = FuzzEntry.model_validate_json(FUZZ_ENTRY_LLM.read_text(encoding="utf-8"))
    assert space.to_runtime(entry.static_addr) == ref.entry_runtime_addr, (
        "the LLM-chosen entry and the snapshot disagree; the snapshot would be "
        "fuzzing different code than was selected"
    )


# --- GhidraMCP, live ------------------------------------------------------


@live_mcp
def test_ghidra_mcp_answers_a_live_decompile_request() -> None:
    """GATE 6: GhidraMCP answers a live decompile request."""
    from llm.ghidra_mcp import GhidraMcpClient

    client = GhidraMcpClient(module="tlv_server")
    assert client.available, "GhidraMCP is not reachable"

    methods = client.list_methods(limit=500)
    assert ENTRY_SYMBOL in methods

    code = client.decompile(ENTRY_SYMBOL)
    assert len(code) > 200
    assert "param_1" in code  # the buffer argument


@live_mcp
def test_mcp_fills_a_cache_miss(tmp_path: Path) -> None:
    """The on-demand path: an address A2 does not have."""
    from llm.ghidra_mcp import GhidraMcpClient

    cache = PseudoCCache(tmp_path / "a2.sqlite")
    assert cache.get_by_function(ENTRY_SYMBOL) is None

    client = GhidraMcpClient(module="tlv_server")
    if not client.available:
        pytest.skip("GhidraMCP not reachable")

    entry = client.fill_cache_miss(cache, ENTRY_SYMBOL, ENTRY_STATIC)
    assert entry.function == ENTRY_SYMBOL
    assert cache.get_by_function(ENTRY_SYMBOL) is not None
    cache.close()


def test_mcp_unavailability_is_not_a_crash() -> None:
    """Ghidra's GUI is usually closed. That must degrade, not fail."""
    from llm.ghidra_mcp import GhidraMcpClient, GhidraMcpUnavailable

    assert GhidraMcpClient(base_url="http://127.0.0.1:9", timeout_s=2.0).available is False

    # A FRESH client, so this exercises the first-failure path and its
    # explanatory message rather than the cached-down shortcut below.
    fresh = GhidraMcpClient(base_url="http://127.0.0.1:9", timeout_s=2.0)
    with pytest.raises(GhidraMcpUnavailable, match="only runs while a Ghidra GUI"):
        fresh.decompile(ENTRY_SYMBOL)


def test_mcp_caches_unavailability_to_avoid_repeated_timeouts() -> None:
    """A triage loop over 40 buckets must not spend 40 timeouts on a closed GUI."""
    from llm.ghidra_mcp import GhidraMcpClient, GhidraMcpUnavailable

    client = GhidraMcpClient(base_url="http://127.0.0.1:9", timeout_s=2.0)
    assert client.available is False  # trips the cache

    with pytest.raises(GhidraMcpUnavailable, match="already unreachable"):
        client.decompile(ENTRY_SYMBOL)


@live_llm
@pytest.mark.skipif(not A2_MODULE.exists(), reason="module-scope A2 not built")
def test_entry_selection_end_to_end() -> None:
    """Run selection live and check it lands on a real function."""
    from llm.client import LlmClient
    from prep.entry_select import select_entry

    with PseudoCCache(A2_MODULE) as cache, LlmClient.from_config() as client:
        entry, choice, shortlist = select_entry(cache, client, shortlist_size=5)

    assert shortlist
    assert 0.0 <= choice.confidence <= 1.0
    with PseudoCCache(A2_MODULE) as cache:
        assert cache.get_by_function(entry.symbol or "") is not None
