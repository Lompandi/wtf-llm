"""Turn a Ghidra block export into A3 (CLAUDE.md CP2).

Emits two things from one input:

* ``artifacts/a3_bp_list.json`` -- :class:`arch.contracts.BasicBlock` records,
  keyed on **static** addresses, which is what everything downstream reasons in.
* the **wtf-native** ``<module>.cov`` -- ``{"name": ..., "addresses": [rva, ...]}``,
  which is what wtf actually loads.

The two address spaces are not interchangeable and the conversion goes through
:mod:`arch.addr` (section 9). See docs/DEVIATIONS.md D-005 for the format, which
was confirmed against ``ParseCovFiles`` in ``src/wtf/utils.cc:342-408`` and
against wtf's own shipped ``tlv_server.cov``.

Three properties of that format are load-bearing and easy to get wrong, so they
are enforced here rather than discovered at run time:

* addresses are **RVAs**, not absolute -- wtf adds ``GetModuleBase()`` itself;
* ``name`` carries **no file extension** -- it must match the debugger's module
  name or ``GetModuleBase`` returns 0 and the entire load fails;
* an address wtf cannot translate is **skipped with a warning**, not an error,
  so a wrong base yields a near-empty breakpoint set and a fuzzer that reports
  almost no coverage while looking healthy.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from arch.addr import from_rva, to_rva
from arch.contracts import BasicBlock

__all__ = [
    "CovFile",
    "blocks_to_records",
    "write_bp_list",
    "write_cov_file",
    "parse_cov_file",
    "validate_cov_file",
]


class CovFileError(ValueError):
    pass


class CovFile:
    """A parsed wtf coverage file.

    :meth:`parse` mirrors ``ParseCovFiles`` (``src/wtf/utils.cc:342-408``) so a
    file we write can be checked with the same logic wtf will apply to it.
    """

    def __init__(self, name: str, addresses: list[int]) -> None:
        self.name = name
        self.addresses = addresses

    def __len__(self) -> int:
        return len(self.addresses)

    def to_runtime(self, module_base: int) -> list[int]:
        """What wtf computes: ``Gva = GetModuleBase(name) + Rva``."""
        return [module_base + rva for rva in self.addresses]

    def to_static(self, ghidra_image_base: int) -> list[int]:
        return [from_rva(rva, ghidra_image_base) for rva in self.addresses]

    @classmethod
    def parse(cls, path: Path) -> CovFile:
        # wtf iterates a DIRECTORY and takes only files ending in .cov
        # (utils.cc:352). A file named anything else is silently ignored, which
        # would look exactly like "no coverage instrumentation happened".
        if not path.name.endswith(".cov"):
            raise CovFileError(
                f"{path.name} does not end in .cov; wtf skips it silently"
            )

        raw = json.loads(path.read_text(encoding="utf-8"))

        if "name" not in raw:
            raise CovFileError("missing 'name'; wtf reads Json[\"name\"] unguarded")
        if "addresses" not in raw:
            raise CovFileError("missing 'addresses'")

        name = raw["name"]
        if not isinstance(name, str) or not name:
            raise CovFileError(f"'name' must be a non-empty string, got {name!r}")

        addresses = raw["addresses"]
        if not isinstance(addresses, list):
            raise CovFileError("'addresses' must be a list")

        for addr in addresses:
            # utils.cc:373 does Item.get<uint64_t>(); a string or float there is
            # a parse error inside wtf, not a skipped entry.
            if not isinstance(addr, int) or isinstance(addr, bool):
                raise CovFileError(
                    f"address {addr!r} is not an integer; wtf reads these as "
                    f"uint64_t and will fail to parse the file"
                )
            if addr < 0:
                raise CovFileError(f"negative RVA {addr}")

        return cls(name=name, addresses=addresses)


def validate_cov_file(path: Path, *, expect_name: str | None = None) -> CovFile:
    """Parse and apply the checks that only fail at wtf run time otherwise."""
    cov = CovFile.parse(path)

    if "." in cov.name:
        raise CovFileError(
            f"'name' is {cov.name!r}; it must be the debugger's module name with "
            f"no extension (e.g. 'tlv_server', not 'tlv_server.exe'), or "
            f"GetModuleBase returns 0 and the whole load fails"
        )
    if expect_name is not None and cov.name != expect_name:
        raise CovFileError(f"'name' is {cov.name!r}, expected {expect_name!r}")
    if not cov.addresses:
        raise CovFileError(
            "no addresses; wtf warns but continues, so the fuzzer would run "
            "with no coverage instead of failing"
        )
    if len(set(cov.addresses)) != len(cov.addresses):
        raise CovFileError("duplicate RVAs")

    return cov


def blocks_to_records(export: dict, module: str | None = None) -> list[BasicBlock]:
    """Ghidra export -> BasicBlock records, in the static address space."""
    module = module or export["module"]
    return [
        BasicBlock(
            module=module,
            static_addr=block["static_addr"],
            function=block.get("function"),
        )
        for block in export["blocks"]
    ]


def write_bp_list(records: list[BasicBlock], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [r.model_dump() for r in records]
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def write_cov_file(
    records: list[BasicBlock],
    ghidra_image_base: int,
    out_dir: Path,
    *,
    module: str | None = None,
) -> Path:
    """Write the wtf-native ``<module>.cov`` into a coverage directory.

    ``out_dir`` is a *directory* because that is what wtf scans -- it reads
    every ``*.cov`` inside it (``utils.cc:350-354``).
    """
    if not records:
        raise CovFileError("refusing to write an empty coverage file")

    module = module or records[0].module
    if "." in module:
        raise CovFileError(
            f"module name {module!r} contains a '.'; strip the extension or "
            f"GetModuleBase will return 0"
        )

    # A set: coverage is boolean membership, never a hit count (DECISIONS R6),
    # and duplicate RVAs would just be redundant breakpoints.
    rvas = sorted({to_rva(r.static_addr, ghidra_image_base) for r in records})
    if rvas and rvas[0] < 0:
        raise CovFileError("negative RVA: a block lies below the image base")

    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{module}.cov"
    path.write_text(
        json.dumps({"name": module, "addresses": rvas}), encoding="utf-8"
    )
    return path


def parse_cov_file(path: Path) -> CovFile:
    return CovFile.parse(path)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--export", required=True, type=Path, help="prep/ghidra_headless.py output"
    )
    ap.add_argument(
        "--bp-list", type=Path, default=Path("artifacts/a3_bp_list.json")
    )
    ap.add_argument(
        "--coverage-dir",
        type=Path,
        required=True,
        help="the target's coverage/ directory -- wtf scans it for *.cov",
    )
    args = ap.parse_args(argv)

    export = json.loads(args.export.read_text(encoding="utf-8"))
    records = blocks_to_records(export)

    bp_list = write_bp_list(records, args.bp_list)
    cov = write_cov_file(records, export["image_base"], args.coverage_dir)

    parsed = validate_cov_file(cov, expect_name=export["module"])
    print(f"A3: {len(records)} blocks")
    print(f"  bp list : {bp_list}")
    print(f"  cov file: {cov}  ({len(parsed)} RVAs, name={parsed.name!r})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
