"""Watch wtf's crash output -> CrashRecord (CLAUDE.md CP4).

Crashes are written by the **master**, not by workers: a worker reports a
``Crash_t`` back over the wire and the master writes
``crashes/<Crash_t::CrashName>`` (``server.h:861-866``, D-018). So there is one
directory to watch, not N.

The filename is the only metadata on disk::

    crash-EXCEPTION_ACCESS_VIOLATION_READ-0x7ff8aa381423
          ^ fault type                    ^ fault address (RUNTIME)

Two consequences that this module handles rather than papers over:

* **The address is a runtime address.** Section 10 forbids hashing those --
  identical bugs would bucket differently across runs. Every record is de-slid
  to a static address through :mod:`arch.addr` before anything downstream sees
  it.
* **Registers and backtrace are not available here.** ``CrashRecord`` has fields
  for both, and they are left empty rather than invented; recovering them needs
  a replay, which is CP8's job. A partial record that is honest about being
  partial beats a complete-looking one with fabricated registers.

Also note ``worker_id`` stays ``None``. Section 12.5 asks for it, but the master
writes every crash into one directory with no worker tag, so it cannot be
recovered from the filesystem (D-018). Resolved at CP4b.

**NO LLM ANYWHERE IN THIS MODULE.** Dedup and triage come later, and dedup
always runs before any LLM sees a crash.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from arch.addr import AddressSpace
from arch.contracts import Backend, CrashRecord

__all__ = ["CRASH_NAME_RE", "parse_crash_name", "CrashWatcher"]

# crash-EXCEPTION_ACCESS_VIOLATION_READ-0x7ff8aa381423
CRASH_NAME_RE = re.compile(
    r"^crash-(?P<fault_type>[A-Za-z0-9_]+)-(?P<addr>0x[0-9a-fA-F]+)$"
)

# wtf's own names, mapped to the vocabulary CLAUDE.md section 6 uses for
# CrashRecord.fault_type. Anything unrecognised is passed through verbatim
# rather than coerced -- a fault class we have not seen before is information,
# not noise.
_FAULT_TYPE_MAP = {
    "EXCEPTION_ACCESS_VIOLATION_READ": "access-violation-read",
    "EXCEPTION_ACCESS_VIOLATION_WRITE": "access-violation-write",
    "EXCEPTION_ACCESS_VIOLATION_EXEC": "access-violation-exec",
    "EXCEPTION_ILLEGAL_INSTRUCTION": "illegal-insn",
    "EXCEPTION_INT_DIVIDE_BY_ZERO": "divide-by-zero",
    "EXCEPTION_STACK_OVERFLOW": "stack-overflow",
    "EXCEPTION_BREAKPOINT": "breakpoint",
}


def parse_crash_name(name: str) -> tuple[str, int] | None:
    """``crash-<TYPE>-<0xaddr>`` -> (normalised fault type, runtime address).

    Returns None for a filename that does not match, which happens for crash
    names a fuzzer module chose itself -- hevd, for instance, names them by
    bugcheck code. Callers should keep such files rather than discard them.
    """
    m = CRASH_NAME_RE.match(name)
    if not m:
        return None
    raw = m.group("fault_type")
    return _FAULT_TYPE_MAP.get(raw, raw), int(m.group("addr"), 16)


@dataclass
class CrashWatcher:
    """Poll a crashes directory and emit a CrashRecord per new file.

    Polling rather than a filesystem watcher: the master writes at most a
    handful of files per second (it deduplicates by name), and a poll cannot
    miss an event or need a platform-specific API.

    ``module_ranges`` maps module name -> runtime base, straight out of
    ``state/symbol-store.json``. It exists because **most faults do not land in
    the target module.** Measured on tlv_server: 48 of 55 crashes faulted in
    0x7ff8aa3812de-0x7ff8aa38167c, which is not the target and is not any module
    the 12-entry symbol store lists.

    CP8 settled what that range actually is, and it was not the guess recorded
    here first: symbolizing the addresses through symbolizer-rs against the
    memory dump resolves all 52 of them to **VCRUNTIME140.dll!memmove** and
    ``memcpy_repmovs`` -- the CRT's memcpy implementation, reached from the
    parser's unvalidated length copy. The earlier note speculated Application
    Verifier because the range sits ~192 KB below verifier.dll; proximity is not
    attribution, and symbols were available the whole time.

    Applying the target's slide to such an address produces a garbage "static"
    address (0x7ff8aa3812de became 0x2d05312de), and hashing that would corrupt
    every bucket while looking perfectly normal.

    So a fault is de-slid **only** when it falls inside the target module, and
    attributed only when it falls inside a declared range. Otherwise
    ``fault_static_addr`` is **None** and ``address_normalized`` is False --
    admitting we do not know beats guessing, and CP8's replay can recover the real
    answer.

    None rather than 0, since D-068: 0 is a real address, so the sentinel made
    "outside our module" indistinguishable from "faulted at zero" -- and every
    consumer had to remember a convention instead of being asked by the type.
    """

    crashes_dir: Path
    space: AddressSpace
    backend: Backend
    module_ranges: dict[str, int] = field(default_factory=dict)
    max_image_size: int = 0x1000_0000  # 256 MB; a sanity bound, not a real size
    seen: set[str] = field(default_factory=set)

    def attribute(self, runtime_addr: int) -> str | None:
        """Which module a runtime address most likely belongs to.

        Nearest declared base at or below the address. Returns None when there
        is nothing plausible, rather than guessing.
        """
        if not runtime_addr:
            return None
        best: tuple[int, str] | None = None
        for name, base in self.module_ranges.items():
            if "!" in name:  # symbol entry, not a module base
                continue
            if base <= runtime_addr and (best is None or base > best[0]):
                best = (base, name)
        if best is None:
            return None
        return best[1] if runtime_addr - best[0] <= self.max_image_size else None

    def _to_static(self, runtime_addr: int) -> tuple[int | None, str | None]:
        """De-slide only if the fault is inside OUR module.

        Returns None for the address whenever it was not converted, so the caller
        cannot mistake "not attributable" for an address (D-068).
        """
        module = self.attribute(runtime_addr)
        if not runtime_addr:
            return None, None
        in_our_module = (
            self.space.module_base
            <= runtime_addr
            < self.space.module_base + self.max_image_size
        )
        if not in_our_module:
            return None, module
        return self.space.to_static(runtime_addr), module or self.space.module

    def prime(self) -> int:
        """Mark everything already present as seen. Returns how many.

        Call this before a run so pre-existing crashes are not attributed to it.
        """
        existing = {p.name for p in self._files()}
        self.seen |= existing
        return len(existing)

    def _files(self) -> list[Path]:
        if not self.crashes_dir.is_dir():
            return []
        return [p for p in self.crashes_dir.iterdir() if p.is_file()]

    def poll(self) -> list[CrashRecord]:
        """Return a CrashRecord for every crash file not yet seen."""
        records: list[CrashRecord] = []
        for path in sorted(self._files()):
            if path.name in self.seen:
                continue
            self.seen.add(path.name)
            record = self.to_record(path)
            if record is not None:
                records.append(record)
        return records

    def to_record(self, path: Path) -> CrashRecord | None:
        parsed = parse_crash_name(path.name)
        if parsed is None:
            # A module-specific crash name. Keep it, but we cannot derive a
            # fault address from it; CP8's replay will have to.
            fault_type, runtime_addr = "unknown", 0
        else:
            fault_type, runtime_addr = parsed

        try:
            input_bytes = path.read_bytes()
        except OSError:
            return None

        # Static addresses only for faults inside our module -- section 10
        # forbids hashing runtime addresses, and cross-module de-sliding is
        # worse than not de-sliding at all.
        static_addr, fault_module = self._to_static(runtime_addr)

        return CrashRecord(
            input_bytes=input_bytes,
            fault_type=fault_type,
            fault_runtime_addr=runtime_addr,
            fault_static_addr=static_addr,
            # True exactly when the conversion ran. Separates "converted, and this
            # is the answer" from "could not convert" -- which a bare address,
            # sentinel or not, cannot express.
            address_normalized=static_addr is not None,
            registers={},  # needs a replay -- CP8
            backtrace=[],  # needs a replay -- CP8
            coverage_delta=0,
            worker_id=None,  # not recoverable from disk -- D-018
            backend=self.backend,
            timestamp=path.stat().st_mtime,
            # Which module the fault landed in. Usually NOT ours: Application
            # Verifier raises from verifier.dll when it catches a heap overflow.
            fault_module=fault_module,
        )

    def collect_all(self) -> list[CrashRecord]:
        """Every crash currently on disk, regardless of `seen`."""
        out = []
        for path in sorted(self._files()):
            record = self.to_record(path)
            if record is not None:
                out.append(record)
        return out

    def write_jsonl(self, records: list[CrashRecord], path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fd:
            for record in records:
                fd.write(record.model_dump_json() + "\n")
        return path
