"""A guard page must be USABLE, and must not corrupt the guest to get there (D-077).

`prep/guard_page.py` turns an overflow of the buffer the harness supplies into an
observable access violation, which CLAUDE.md section 2 lists as the mitigation the project
defaulted to skipping. The tests that matter here are the refusals: a guard page placed
over live guest state produces crashes that are artefacts of the harness, and a fabricated
crash is worse than the missed bug it was added to find.

No dump file and no kdmp-parser: `find_guard_page` opens the dump, so the ranking logic is
exercised through a fake with the same two methods the walk uses. That is a deliberate
seam, not a convenience -- the alternative is a test that skips on every machine without a
recorded snapshot, and CLAUDE.md's gate runner counts a skipped condition as `incomplete`
rather than `pass`.
"""

from __future__ import annotations

import json

import pytest

from pathlib import Path

from prep.guard_page import (
    KUSER_SHARED_DATA,
    PAGE,
    GuardPage,
    GuardPageError,
    _trailing_free,
    find_guard_page,
)


class FakeDump:
    """The two members the walk touches: `directory_table_base` and physical page reads.

    Pages are described as {virtual address: bytes}; this builds the four levels of page
    table that make them reachable, so the code under test does a real walk.
    """

    def __init__(self, pages: dict[int, bytes]) -> None:
        self.directory_table_base = 0x1000
        # bytearray, not bytes: a table's entries are filled in AFTER its frame is
        # allocated, because a parent has to know the child's address. The first version
        # stored immutable bytes and every parent kept pointing at a stale frame, so the
        # walk reported pages at addresses nothing had put there.
        self._frames: dict[int, bytearray] = {0x1000: bytearray(PAGE)}
        self._next = 0x100000

        for va, content in pages.items():
            indices = (
                (va >> 39) & 0x1FF,
                (va >> 30) & 0x1FF,
                (va >> 21) & 0x1FF,
                (va >> 12) & 0x1FF,
            )
            table = 0x1000
            for level, index in enumerate(indices):
                if level == 3:
                    self._set(table, index, self._alloc(content) | 1)
                    break
                existing = self._get(table, index)
                if existing & 1:
                    table = existing & 0x000F_FFFF_FFFF_F000
                else:
                    child = self._alloc(b"")
                    self._set(table, index, child | 1)
                    table = child

    def _alloc(self, content: bytes) -> int:
        frame = self._next
        self._next += PAGE
        self._frames[frame] = bytearray(content.ljust(PAGE, b"\0"))
        return frame

    def _get(self, frame: int, index: int) -> int:
        raw = self._frames[frame]
        return int.from_bytes(raw[index * 8 : index * 8 + 8], "little")

    def _set(self, frame: int, index: int, value: int) -> None:
        self._frames[frame][index * 8 : index * 8 + 8] = value.to_bytes(8, "little")

    def read_physical_page(self, addr: int) -> bytes:
        return bytes(self._frames.get(addr, bytearray(PAGE)))


def _patch(monkeypatch, dump) -> None:
    """Make find_guard_page use `dump` instead of opening a file."""
    import sys
    import types

    fake = types.ModuleType("kdmp_parser")
    fake.KernelDumpParser = lambda _path: dump
    monkeypatch.setitem(sys.modules, "kdmp_parser", fake)
    monkeypatch.setattr("prep.guard_page._image_ranges", lambda *_: [])


# --- the trailing-run measurement, which is the whole selection criterion ----


def test_trailing_free_counts_only_the_tail() -> None:
    """The check that made the module work at all.

    Requiring the WHOLE page to be zero found nothing on a real dump -- all nine
    candidates held data. The bytes that get overwritten are only the last `size`.
    """
    assert _trailing_free(b"\xff" * 10 + b"\0" * 90) == 90
    assert _trailing_free(b"\0" * 100) == 100
    assert _trailing_free(b"\0" * 99 + b"\x01") == 0


def test_a_page_with_data_in_front_is_still_usable() -> None:
    """The real winner looked like this: 27 non-zero bytes at the front, 1951 free."""
    page = GuardPage(boundary=0x2000, page_base=0x1000, hole_pages=99, trailing_free=1951)
    assert page.placement_for(200) == 0x2000 - 200
    with pytest.raises(GuardPageError) as exc:
        page.placement_for(2000)
    assert "overwrite live guest state" in str(exc.value)


# --- selection ---------------------------------------------------------------


def test_the_largest_hole_wins(monkeypatch) -> None:
    """Among usable candidates, prefer the most certainly uncommitted neighbour.

    Two boundaries, both able to hold the input. The one with more unmapped space after it
    is the safer bet that the fault is a clean AV rather than a demand-paging request the
    snapshot cannot service.
    """
    small_hole = 0x10_000
    big_hole = 0x40_000
    dump = FakeDump(
        {
            small_hole: b"\0" * PAGE,
            small_hole + 0x2000: b"\0" * PAGE,      # 1-page hole after small_hole
            big_hole: b"\0" * PAGE,                  # nothing after it at all
        }
    )
    _patch(monkeypatch, dump)
    guard = find_guard_page(Path("dump.dmp"), size=64, min_hole_pages=1)
    assert guard.boundary == big_hole + PAGE


def test_kuser_shared_data_is_never_chosen(monkeypatch) -> None:
    """It scores second on a real dump and the kernel reads it.

    2271 trailing zero bytes and a 221-million-page hole above it. Excluded by address,
    which is what identifies it.
    """
    dump = FakeDump({KUSER_SHARED_DATA: b"\0" * PAGE})
    _patch(monkeypatch, dump)
    with pytest.raises(GuardPageError) as exc:
        find_guard_page(Path("dump.dmp"), size=64, min_hole_pages=1)
    assert "KUSER_SHARED_DATA" in str(exc.value)


def test_a_page_without_enough_trailing_room_is_refused_and_says_how_much(
    monkeypatch,
) -> None:
    dump = FakeDump({0x10_000: b"\xaa" * PAGE})
    _patch(monkeypatch, dump)
    with pytest.raises(GuardPageError) as exc:
        find_guard_page(Path("dump.dmp"), size=64, min_hole_pages=1)
    message = str(exc.value)
    assert "can hold 64 bytes" in message and "0 free trailing bytes" in message


def test_a_hole_smaller_than_the_threshold_does_not_qualify(monkeypatch) -> None:
    """One absent PTE is not evidence of an uncommitted region.

    It could be a page that is committed but not resident, and touching that asks the
    kernel to fetch it from a paging device the snapshot does not have.
    """
    # The top page is excluded on trailing room rather than on its hole, because the
    # HIGHEST mapped page has unbounded space above it and should qualify -- that is the
    # other fix this file pins. Filling it isolates the threshold under test.
    dump = FakeDump(
        {
            0x10_000: b"\0" * PAGE,
            0x12_000: b"\0" * PAGE,
            0x100_000: b"\xaa" * PAGE,
        }
    )
    _patch(monkeypatch, dump)
    with pytest.raises(GuardPageError):
        find_guard_page(Path("dump.dmp"), size=64, min_hole_pages=512)


def test_size_must_be_sane() -> None:
    for bad in (0, -1, PAGE + 1):
        with pytest.raises(GuardPageError) as exc:
            find_guard_page(Path("dump.dmp"), size=bad)
        assert "size must be in" in str(exc.value)


def test_an_image_page_is_excluded(monkeypatch) -> None:
    """A section's trailing slack is zero and followed by a hole, so it ranks well.

    It is also the program under test, and writing the input there writes into the binary
    being fuzzed.
    """
    import sys
    import types

    base = 0x7FF6_0000_0000
    dump = FakeDump({base: b"\0" * PAGE})
    fake = types.ModuleType("kdmp_parser")
    fake.KernelDumpParser = lambda _path: dump
    monkeypatch.setitem(sys.modules, "kdmp_parser", fake)
    monkeypatch.setattr(
        "prep.guard_page._image_ranges", lambda *_: [(base, base + 0x10_000)]
    )
    with pytest.raises(GuardPageError) as exc:
        find_guard_page(Path("dump.dmp"), size=64, min_hole_pages=1)
    assert "inside a mapped image" in str(exc.value)


def test_an_empty_dump_says_so_rather_than_returning_something(monkeypatch) -> None:
    _patch(monkeypatch, FakeDump({}))
    with pytest.raises(GuardPageError) as exc:
        find_guard_page(Path("dump.dmp"), size=64, min_hole_pages=1)
    assert "no user pages" in str(exc.value)


# --- the live thread stack, which is the exclusion that matters most ---------


def test_the_live_thread_stack_is_excluded(monkeypatch, tmp_path) -> None:
    """The best-SCORING candidate in a real snapshot, and the worst one (D-083).

    The top page of a thread stack has zero trailing bytes and hundreds of millions of
    unmapped pages above it, so it wins every ranking. It is also live memory: the stack
    grows down, so above rsp are the caller frames -- including the one holding
    `__security_cookie ^ frame`.

    Measured before this exclusion existed: the chosen page sat 754 KB above rsp, writing
    the input there corrupted an outer frame, and `__security_check_cookie` failed on EVERY
    input. Good input and overflowing input both gave 3.3k instructions, cov 3089,
    `crash: 1` -- a convincing stack-overflow signature produced entirely by the harness.
    A fabricated crash is worse than the missed bug, because it consumes triage and reaches
    a report.
    """
    rsp = 0xD3D77FF778
    stack_top = 0xD3D78BC000  # 772 KB above rsp, and a separate mapped run
    dump = FakeDump({rsp & ~(PAGE - 1): b"\xcc" * PAGE, stack_top: b"\0" * PAGE})
    _patch(monkeypatch, dump)
    regs = tmp_path / "regs.json"
    regs.write_text(json.dumps({"rsp": rsp}), encoding="utf-8")

    with pytest.raises(GuardPageError) as exc:
        find_guard_page(
            Path("dump.dmp"), size=64, regs_json=regs, min_hole_pages=1
        )
    assert "live thread stack" in str(exc.value)


def test_a_window_not_a_contiguous_run(monkeypatch, tmp_path) -> None:
    """Why `_stack_run` is a window: a Windows stack's mapped pages are NOT contiguous.

    The reserve is 1 MB and commitment is lazy, so rsp's committed pages and the stack top
    are separate runs with uncommitted reserved pages between. Walking outward from rsp
    stopped at the first hole and never reached the page 772 KB higher -- the exclusion ran,
    found a short run, and let the stack top through anyway.
    """
    from prep.guard_page import _stack_run

    rsp_page = 0xD3D77FF000
    stack_top = 0xD3D78BC000
    pages = {rsp_page: 0, stack_top: 0}  # deliberately NOT adjacent
    lo, hi = _stack_run(pages, rsp_page + 0x778)
    assert lo <= stack_top < hi, (
        "the stack top is 772 KB above rsp with a hole between; a contiguous-run walk "
        "misses it and the guard page lands on live frames"
    )


def test_without_regs_the_stack_is_not_excluded_which_is_why_run_py_passes_them(
    monkeypatch,
) -> None:
    """The unsafe default, pinned so it cannot be reintroduced silently.

    `regs_json` defaults to None because the module is usable without it, but the caller
    that matters -- fuzzer/run.py -- must pass it. This test documents what happens when it
    does not, so that the default is a known risk rather than a surprise.
    """
    rsp_page = 0xD3D77FF000
    stack_top = 0xD3D78BC000
    dump = FakeDump({rsp_page: b"\xcc" * PAGE, stack_top: b"\0" * PAGE})
    _patch(monkeypatch, dump)
    guard = find_guard_page(Path("dump.dmp"), size=64, min_hole_pages=1)
    assert guard.page_base == stack_top, (
        "without regs.json the stack top is still selected; if this changes, revisit "
        "whether fuzzer/run.py still needs to pass regs_json"
    )


def test_run_py_passes_regs_json() -> None:
    """The consumer, checked against its source, because the default is the unsafe one."""
    import inspect

    from fuzzer.run import Campaign

    source = inspect.getsource(Campaign._guard_boundary)
    assert "regs_json=" in source, (
        "fuzzer/run.py calls find_guard_page without regs_json, so the live thread stack "
        "is not excluded and every crash it reports may be the harness's (D-083)"
    )


# --- the CONSUMER, whose refusal path had never been executed ----------------


def test_the_refusal_path_actually_runs(tmp_path, capsys) -> None:
    """`_guard_boundary` must survive not finding one. It did not.

    Every test above exercises `find_guard_page`; none exercised the caller. So a
    `log.warning` in the refusal branch -- referring to a `log` that fuzzer/run.py does not
    define, since it prints rather than logs -- raised NameError and killed the campaign
    three seconds in. On the snapshot in hand the refusal branch is the ONLY branch, so the
    feature worked in isolation and broke the thing it was added to.

    Testing the unhappy path of a best-effort helper is the whole point: the happy path was
    covered nine times over, and the branch that runs on real data was covered zero times.
    """
    from arch.addr import AddressSpace
    from fuzzer.run import Campaign, CampaignConfig

    target = tmp_path / "targets" / "t"
    (target / "state").mkdir(parents=True)
    # A dump that cannot yield a boundary. find_guard_page opens it for real, so any
    # unreadable file exercises the same branch -- GuardPageError either way.
    (target / "state" / "mem.dmp").write_bytes(b"not a dump")

    config = CampaignConfig(
        wtf_exe=tmp_path / "wtf.exe",
        target_dir=target,
        name="t",
        backend="bochscpu",
        limit=1,
        max_len=4096,
        runs=0,
        worker_count=1,
        symbol_paths=[],
        seed_spool=tmp_path / "spool",
        artifacts_dir=tmp_path / "artifacts",
    )
    campaign = Campaign(
        config,
        AddressSpace(module="t", module_base=0x140000000, ghidra_image_base=0x140000000),
    )

    assert campaign._guard_boundary() is None
    out = capsys.readouterr().out
    assert "GUARD PAGE: none available" in out, (
        "the refusal must be reported: an unverified guard page fails open, and silence "
        "turns 'no crashes' into 'no crashes were observable'"
    )
