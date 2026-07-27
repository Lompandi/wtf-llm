"""A guard page built out of the snapshot's own page tables — CLAUDE.md §2 option (a).

§2 says there is no ASAN, lists the classes that go undetected, and offers two ways out:
"(a) investigate a binary-only sanitization approach and accept the slowdown, or (b)
accept the limitation and state it explicitly". It defaults to (b). This module is (a),
for one class, at no runtime cost — and the reason it is cheap is specific to snapshot
fuzzing rather than clever.

THE OBSERVATION. In a snapshot fuzzer the harness supplies the input buffer, so the
buffer's *address* is ours to choose. A target that overflows the buffer it was handed
therefore overflows into memory we selected. Choose an address whose page is mapped and
whose next page is not, place the input so it ENDS at that boundary, and an overflowing
write leaves mapped memory on its first byte past the end:

        ... mapped page ......|  unmapped
        [ slack ][ input     ]|
                              ^ the write past `len` faults here

A page fault on an uncommitted user address becomes an access violation, and wtf's
oracle already breakpoints `ntdll!RtlDispatchException` and calls `SaveCrash` on it
(`src/wtf/crash_detection_umode.cc:38-110`). So the fault is reported through the
existing path — nothing in the fast loop changes, and RULE 1 is untouched because this
is a placement decision made once, before the campaign starts.

WHY THIS WAS NEEDED. The second real target's planted bug is

    memset(param_1, 'A', (byte)param_1[4])          // fuzzme, RVA 0x10d0

whose destination is the *input buffer*, not a local — `fuzzme` has no locals and no
stack cookie. So there is nothing in the target to notice the overflow: no cookie, and
no guard page unless we place one. With the input written into a comfortable scratch
region, a 200-byte memset is simply an in-bounds write and the campaign is correct to
report no crash. The bug is real; the oracle could not see it.

WHAT THIS DOES NOT COVER. Overflows of buffers the *target* allocates — a local array,
a heap chunk — are unaffected, because we do not choose those addresses. For heap
buffers on Windows the answer is Application Verifier's page heap, enabled in the guest
before the snapshot is taken; wtf hooks `verifier!VerifierStopMessage` for exactly that
(same file), which is evidence the approach is sanctioned rather than invented here.
Both remain limitations to state plainly, per §11 — this narrows the gap, it does not
close it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "DEFAULT_STACK_WINDOW",
    "GuardPage",
    "GuardPageError",
    "find_guard_page",
    "mapped_user_pages",
]

PAGE = 0x1000
PRESENT, LARGE = 1 << 0, 1 << 7
FRAME = 0x000F_FFFF_FFFF_F000

# A hole this wide after the page is what makes "the next page is unmapped" trustworthy.
# One absent PTE could be a page that is committed but not resident, and touching that
# asks the kernel to fetch it from a paging device the snapshot does not have. A hole of
# several megabytes is a gap between regions, where the fault is a clean AV.
DEFAULT_MIN_HOLE_PAGES = 512  # 2 MB

# How far either side of `rsp` counts as the live thread stack. The default Windows thread
# stack RESERVE is 1 MB and it is committed lazily, so mapped pages belonging to one stack
# are not contiguous and cannot be found by walking outward from rsp.
DEFAULT_STACK_WINDOW = 1 << 20


class GuardPageError(RuntimeError):
    """No usable guard page — say so rather than placing the buffer somewhere unchecked."""


@dataclass(frozen=True)
class GuardPage:
    """A boundary to place an input against.

    `boundary` is the first UNMAPPED address: the input is written ending exactly there,
    so an input of `n` bytes goes at `boundary - n` and byte `n` is the first to fault.
    """

    boundary: int
    page_base: int
    hole_pages: int
    trailing_free: int

    def placement_for(self, size: int) -> int:
        """Where an input of `size` bytes goes so that byte `size` is the first to fault."""
        if size > self.trailing_free:
            raise GuardPageError(
                f"an input of {size} bytes does not fit in the {self.trailing_free} "
                f"unused trailing bytes before {self.boundary:#x}; writing it would "
                f"overwrite live guest state"
            )
        return self.boundary - size

    def to_json(self) -> str:
        return json.dumps(
            {
                "boundary": self.boundary,
                "page_base": self.page_base,
                "hole_pages": self.hole_pages,
                "trailing_free": self.trailing_free,
            },
            indent=2,
        )


def mapped_user_pages(dump) -> dict[int, int]:
    """{virtual page base: physical frame} for every present 4 KB page in the user half.

    The user half is 128 TB, so this is derived from the page tables rather than probed.
    PML4 entries 0..255 are user space; 256.. is the kernel, which is not ours to write
    into. Large pages are expanded, because for this question "is it mapped" is all that
    matters and a 2 MB page maps its 512 constituent pages.
    """
    cr3 = dump.directory_table_base & ~0xFFF

    def entries(physical_page_addr: int) -> list[int]:
        raw = dump.read_physical_page(physical_page_addr)
        if not raw:
            return []
        return [int.from_bytes(raw[i : i + 8], "little") for i in range(0, len(raw), 8)]

    pages: dict[int, int] = {}
    for pml4_i, pml4e in enumerate(entries(cr3)[:256]):
        if not pml4e & PRESENT:
            continue
        for pdpt_i, pdpte in enumerate(entries(pml4e & FRAME)):
            if not pdpte & PRESENT:
                continue
            base_1g = (pml4_i << 39) | (pdpt_i << 30)
            if pdpte & LARGE:  # 1 GB
                for i in range(0x40000):
                    pages[base_1g + i * PAGE] = (pdpte & FRAME) + i * PAGE
                continue
            for pd_i, pde in enumerate(entries(pdpte & FRAME)):
                if not pde & PRESENT:
                    continue
                base_2m = base_1g | (pd_i << 21)
                if pde & LARGE:  # 2 MB
                    for i in range(0x200):
                        pages[base_2m + i * PAGE] = (pde & FRAME) + i * PAGE
                    continue
                for pt_i, pte in enumerate(entries(pde & FRAME)):
                    if pte & PRESENT:
                        pages[base_2m | (pt_i << 12)] = pte & FRAME
    return pages


def _trailing_free(raw: bytes) -> int:
    """How many bytes at the END of the page are zero.

    The right question, and not the one asked first. Requiring the WHOLE page to be zero
    found nothing in a real snapshot -- all nine boundaries had some data -- while the
    bytes that actually get overwritten are only the last `size` of them. The best
    candidate on that snapshot is the top page of a thread stack: 27 non-zero bytes near
    the front, 1951 zero bytes of never-touched slack at the back, and 456 million
    unmapped pages above it.
    """
    n = 0
    for byte in reversed(raw):
        if byte:
            break
        n += 1
    return n


def _image_ranges(dump, pages: dict[int, int]) -> list[tuple[int, int]]:
    """[base, base+SizeOfImage) for every PE mapped in the user half.

    Used to keep the input out of a loaded image. The trailing slack of a section is
    zero and followed by a hole, so it looks like an ideal candidate and is not: it is
    the target's own image, and a write there is a write into the program under test.
    """
    from prep.layout import IMAGE_ALIGNMENT, _pe_identity

    ranges: list[tuple[int, int]] = []
    for va, frame in pages.items():
        if va % IMAGE_ALIGNMENT:
            continue
        head = dump.read_physical_page(frame) or b""
        identity = _pe_identity(head)
        if identity:
            ranges.append((va, va + identity[2]))  # identity[2] is SizeOfImage
    return ranges


# KUSER_SHARED_DATA. A fixed, documented address that is readable in every process and
# read by the kernel; the walk finds it with a 221-million-page hole above it and 2271
# trailing zero bytes, which makes it the second-best-looking candidate and a terrible
# one. Excluded by address because that is what it is identified by.
KUSER_SHARED_DATA = 0x7FFE0000


def _stack_run(
    pages: dict[int, int], rsp: int, window: int = DEFAULT_STACK_WINDOW
) -> tuple[int, int] | None:
    """The contiguous mapped run containing `rsp` — the live thread stack. [lo, hi).

    THE EXCLUSION THAT MATTERS MOST, because without it the module manufactures crashes
    that look exactly like the bug it is hunting.

    The top page of a thread stack is the best-looking candidate in a real snapshot: its
    trailing bytes are zero, and above it the stack's reserved region ends, giving a hole
    of hundreds of millions of pages. It is also **live memory**. The stack grows DOWN, so
    everything above `rsp` is the frames of the callers -- including the one holding the
    `__security_cookie ^ frame` value that `__security_check_cookie` verifies on the way
    out.

    Measured: the chosen page sat 754 KB above `rsp`. Writing the input there corrupted an
    outer frame, so `__security_check_cookie` (rva 0x1210) failed and jumped to the
    security-failure path on EVERY input, good and overflowing alike -- 3.3k instructions,
    cov 3089, `crash: 1`, identical for both. A convincing stack-overflow signature
    produced entirely by the harness.

    The whole run is excluded, not just the part above `rsp`: below it is where the target
    is about to build its frames.
    """
    # A WINDOW, NOT A CONTIGUOUS RUN, and the difference is the whole bug. Windows
    # RESERVES a thread stack (1 MB by default) and COMMITS it lazily, so the mapped pages
    # around `rsp` and the mapped page at the stack top are separate runs with uncommitted
    # reserved pages between them. Walking the contiguous run from `rsp` stopped at
    # 0xd3d7800000 and never reached 0xd3d78bc000 -- 772 KB higher, still the same stack,
    # and still the page this function exists to exclude.
    #
    # There is no VAD to read from a dump without much more machinery, so the reservation
    # is approximated by a window either side of `rsp`. Erring wide is the safe direction:
    # a rejected candidate costs one bug class on one snapshot, an accepted stack page
    # costs every crash the campaign reports.
    page = rsp & ~(PAGE - 1)
    if page not in pages:
        return None
    return page - window, page + window + PAGE


def find_guard_page(
    mem_dmp: Path,
    *,
    size: int,
    regs_json: Path | None = None,
    min_hole_pages: int = DEFAULT_MIN_HOLE_PAGES,
    stack_window: int = DEFAULT_STACK_WINDOW,
) -> GuardPage:
    """The mapped page with the largest unmapped run after it that can hold `size` bytes.

    `size` is required rather than defaulted because the answer depends on it: the page
    must have at least that many unused trailing bytes. A default would silently return
    a boundary that cannot hold the caller's input.

    Two exclusions, both for the same reason -- a guard page that corrupts live guest
    state produces crashes that are artefacts of the harness, and a fabricated crash is
    worse than the missed bug this was added to find:

    * anything inside a mapped image, which is the program under test;
    * `KUSER_SHARED_DATA`, which the kernel reads.
    """
    if size <= 0 or size > PAGE:
        raise GuardPageError(f"size must be in 1..{PAGE}, got {size}")
    try:
        import kdmp_parser
    except ImportError as exc:  # pragma: no cover - environment
        raise GuardPageError(
            "kdmp-parser is not installed, so the snapshot's page tables cannot be "
            "walked; install it or pass an explicit placement"
        ) from exc

    dump = kdmp_parser.KernelDumpParser(str(mem_dmp))
    pages = mapped_user_pages(dump)
    if not pages:
        raise GuardPageError(f"{mem_dmp} maps no user pages at all")

    images = _image_ranges(dump, pages)

    # The live thread stack, from regs.json. Without it the best-scoring candidate on a
    # real snapshot is the stack top, and using it fabricates a cookie failure on every
    # input. Passing regs_json is therefore strongly advised, and its absence is reported
    # rather than assumed harmless.
    stack: tuple[int, int] | None = None
    if regs_json is not None and regs_json.is_file():
        regs = json.loads(regs_json.read_text(encoding="utf-8"))
        raw = regs.get("rsp")
        rsp = raw if isinstance(raw, int) else int(str(raw), 16)
        stack = _stack_run(pages, rsp, stack_window)

    ordered = sorted(pages)
    candidates: list[GuardPage] = []
    rejected: list[str] = []
    # The HIGHEST mapped page has nothing above it at all, which is the largest hole
    # available, not the smallest acceptable one. Scoring it as exactly `min_hole_pages`
    # made it lose the ranking to any interior gap wider than the threshold -- so the
    # best boundary in the snapshot was systematically passed over whenever a mediocre
    # one existed.
    UNBOUNDED = 1 << 40

    for i, va in enumerate(ordered):
        nxt = ordered[i + 1] if i + 1 < len(ordered) else None
        hole = (nxt - (va + PAGE)) // PAGE if nxt else UNBOUNDED
        if hole < min_hole_pages:
            continue
        if va == KUSER_SHARED_DATA:
            rejected.append(f"{va:#x} is KUSER_SHARED_DATA")
            continue
        if any(lo <= va < hi for lo, hi in images):
            rejected.append(f"{va:#x} is inside a mapped image")
            continue
        if stack and stack[0] <= va < stack[1]:
            rejected.append(f"{va:#x} is in the live thread stack")
            continue
        raw = dump.read_physical_page(pages[va]) or b""
        free = _trailing_free(raw)
        if free < size:
            rejected.append(f"{va:#x} has only {free} free trailing bytes")
            continue
        candidates.append(
            GuardPage(
                boundary=va + PAGE,
                page_base=va,
                hole_pages=hole,
                trailing_free=free,
            )
        )

    if not candidates:
        detail = "; ".join(rejected[:6]) or "no page is followed by a large enough hole"
        raise GuardPageError(
            f"no guard boundary in {mem_dmp.name} can hold {size} bytes: {detail}"
        )

    # The largest hole is the most certainly uncommitted, so the fault above it is most
    # certainly a clean access violation rather than a demand-paging request the
    # snapshot cannot service.
    return max(candidates, key=lambda c: c.hole_pages)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mem-dmp", type=Path, required=True)
    parser.add_argument(
        "--regs-json",
        type=Path,
        help="state/regs.json. Strongly advised: without rsp the live thread stack cannot "
             "be excluded, and its top page is the best-SCORING and worst candidate",
    )
    parser.add_argument("--min-hole-pages", type=int, default=DEFAULT_MIN_HOLE_PAGES)
    parser.add_argument(
        "--size", type=int, required=True,
        help="max input size in BYTES; the page must have this much unused trailing space",
    )
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)

    try:
        guard = find_guard_page(
            args.mem_dmp,
            size=args.size,
            regs_json=args.regs_json,
            min_hole_pages=args.min_hole_pages,
        )
        if args.regs_json is None:
            print(
                "WARNING: no --regs-json, so the live thread stack was NOT excluded. Its "
                "top page scores best and corrupts an outer frame, which fails the stack "
                "cookie on every input."
            )
    except GuardPageError as exc:
        raise SystemExit(f"guard page: {exc}")

    print(
        f"guard boundary {guard.boundary:#x}  "
        f"(page {guard.page_base:#x}, {guard.hole_pages} unmapped pages after, "
        f"{guard.trailing_free} unused trailing bytes)"
    )
    print(
        f"an input of {args.size} bytes goes at "
        f"{guard.placement_for(args.size):#x}; byte {args.size} faults"
    )
    if args.out:
        args.out.write_text(guard.to_json(), encoding="utf-8")
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
