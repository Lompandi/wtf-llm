"""Static <-> runtime address conversion (CLAUDE.md section 9).

Ghidra works in a *static* address space anchored at the image base recorded in
the file headers. The running process -- and therefore the snapshot -- uses a
*runtime* base that differs by the ASLR/PIE slide::

    static_addr  = runtime_addr - module_base + ghidra_image_base
    runtime_addr = static_addr  - ghidra_image_base + module_base

This module is the single implementation. Every crossing between the two spaces
goes through it, in particular:

* crash records: runtime -> static *before* stack hashing or pseudo-C lookup,
  because hashing runtime addresses makes identical bugs bucket differently
  across runs;
* pseudo-C lookup: always keyed on static addresses.

Coverage breakpoints are the exception, and it is worth being precise about
why. wtf's ``.cov`` files store **RVAs**, not addresses in either space: see
``ParseCovFiles`` in ``src/wtf/utils.cc``, which reads ``Json["addresses"]`` as
an RVA and adds ``g_Dbg->GetModuleBase(name)`` at load time. So generating a
coverage file needs :func:`to_rva` (static -> RVA) and never needs
``module_base`` at all -- wtf applies the slide itself. Use :func:`to_runtime`
for breakpoints only if you are placing them yourself outside the ``.cov``
mechanism.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["AddressSpace", "to_static", "to_runtime", "to_rva", "from_rva"]


def to_static(runtime_addr: int, module_base: int, ghidra_image_base: int) -> int:
    """Convert a runtime (snapshot/process) address to Ghidra's static space."""
    return runtime_addr - module_base + ghidra_image_base


def to_runtime(static_addr: int, module_base: int, ghidra_image_base: int) -> int:
    """Convert a Ghidra static address to the runtime (snapshot/process) space."""
    return static_addr - ghidra_image_base + module_base


def to_rva(static_addr: int, ghidra_image_base: int) -> int:
    """Convert a Ghidra static address to a module-relative RVA.

    This is the form wtf's ``.cov`` coverage-breakpoint files use.
    """
    return static_addr - ghidra_image_base


def from_rva(rva: int, ghidra_image_base: int) -> int:
    """Convert a module-relative RVA back to a Ghidra static address."""
    return rva + ghidra_image_base


@dataclass(frozen=True)
class AddressSpace:
    """Binds a module's two bases so conversions cannot silently mismatch.

    ``module_base`` comes from :attr:`arch.contracts.SnapshotRef.module_base`;
    ``ghidra_image_base`` comes from the Ghidra program's image base. Passing
    them positionally to the free functions is easy to get backwards, so
    prefer this when both are in hand.
    """

    module: str
    module_base: int
    ghidra_image_base: int

    def to_static(self, runtime_addr: int) -> int:
        return to_static(runtime_addr, self.module_base, self.ghidra_image_base)

    def to_runtime(self, static_addr: int) -> int:
        return to_runtime(static_addr, self.module_base, self.ghidra_image_base)

    def to_rva(self, static_addr: int) -> int:
        return to_rva(static_addr, self.ghidra_image_base)

    def from_rva(self, rva: int) -> int:
        return from_rva(rva, self.ghidra_image_base)

    @property
    def slide(self) -> int:
        """The ASLR/PIE slide: runtime_addr - static_addr."""
        return self.module_base - self.ghidra_image_base
