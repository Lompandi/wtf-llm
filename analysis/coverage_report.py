"""Corpus coverage -> lighthouse-loadable files (CLAUDE.md CP8, edges 32/32b/32c).

The chain section 13.3 specifies:

    minset -> wtf run --trace-type=cov -> symbolizer-rs --style modoff -> lighthouse

**Where this module stops, stated plainly.** lighthouse is an IDA / Binary Ninja
plugin, and neither is installed here. So this produces the *symbolized
module+offset files lighthouse consumes* and goes no further -- it does not render
a report, and claiming otherwise would misrepresent what exists. What it does give
without lighthouse is the per-module and per-function breakdown below, which is
the same information in text form.

``--style modoff`` rather than ``full``: lighthouse wants ``module+offset``, and it
resolves names itself from the binary it has open. Harness validation (CP4) uses
``full`` instead, because there you need to *see* a function name.

**NO LLM IN THIS MODULE.**
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from arch.addr import AddressSpace
from analysis.trace import TraceError, TraceTarget, generate_trace, symbolize
from engine_bridge.plateau import BlockGraph, parse_cov_traces

__all__ = ["CoverageReport", "build_coverage_report"]


@dataclass
class CoverageReport:
    """Where the files landed, plus the text breakdown."""

    trace_dir: Path
    symbolized_dir: Path
    inputs: int
    covered_blocks: int
    known_blocks: int
    per_function: list[tuple[str, int]]
    per_module: list[tuple[str, int]]
    lighthouse_ready: list[Path]

    @property
    def block_coverage_ratio(self) -> float:
        return self.covered_blocks / self.known_blocks if self.known_blocks else 0.0

    def to_json(self) -> dict:
        return {
            "inputs": self.inputs,
            "covered_blocks": self.covered_blocks,
            "known_blocks": self.known_blocks,
            "block_coverage_ratio": round(self.block_coverage_ratio, 4),
            "per_function": self.per_function,
            "per_module": self.per_module,
            "lighthouse_files": [str(p) for p in self.lighthouse_ready],
            "note": (
                "lighthouse is an IDA/Binary Ninja plugin and is not installed "
                "here; these files are in the form it consumes"
            ),
        }


def build_coverage_report(
    target: TraceTarget,
    *,
    corpus_dir: Path,
    out_dir: Path,
    space: AddressSpace,
    block_graph: BlockGraph,
    crash_dump: Path,
    symbol_paths: list[str] | None = None,
    backend: str = "bochscpu",
    limit: int = 200_000_000,
) -> CoverageReport:
    """Generate cov traces over a corpus and symbolize them for lighthouse.

    One ``wtf run`` over the whole directory, not one per input: for coverage the
    union is what is wanted, and per-input attribution is what
    ``eval/coverage_gradient.py`` exists for.
    """
    inputs = sorted(p for p in corpus_dir.glob("*") if p.is_file())
    if not inputs:
        raise TraceError(
            f"{corpus_dir} holds no inputs, so there is no coverage to report. An "
            f"empty report would read as 'nothing covered'."
        )

    trace_dir = out_dir / "cov-traces"
    symbolized_dir = out_dir / "cov-symbolized"
    trace_dir.mkdir(parents=True, exist_ok=True)
    symbolized_dir.mkdir(parents=True, exist_ok=True)
    for stale in trace_dir.glob("*.trace"):
        stale.unlink()  # wtf skips writing when a trace already exists

    generate_trace(
        target,
        corpus_dir,
        trace_dir,
        trace_type="cov",
        backend=backend,
        limit=limit,
    )

    produced = sorted(trace_dir.glob("*.trace"))
    if not produced:
        raise TraceError(
            f"wtf wrote no cov traces into {trace_dir}. Returning an empty report "
            f"here would be indistinguishable from a target that covers nothing."
        )

    lighthouse_ready: list[Path] = []
    for trace in produced:
        lighthouse_ready.append(
            symbolize(
                trace,
                symbolized_dir / f"{trace.stem}.modoff.txt",
                crash_dump=crash_dump,
                symbol_paths=symbol_paths,
                style="modoff",
            )
        )

    covered = parse_cov_traces(trace_dir, space) & set(block_graph.blocks)
    functions = Counter(
        block_graph.function_of(rva) or "<unknown>" for rva in covered
    )

    # Module breakdown comes from the modoff files, which is the only place the
    # non-target modules survive: parse_cov_traces deliberately drops them,
    # because another module's slide is not ours.
    modules: Counter[str] = Counter()
    for path in lighthouse_ready:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            name = line.strip().split("+", 1)[0]
            if name:
                modules[name] += 1

    report = CoverageReport(
        trace_dir=trace_dir,
        symbolized_dir=symbolized_dir,
        inputs=len(inputs),
        covered_blocks=len(covered),
        known_blocks=len(block_graph.blocks),
        per_function=functions.most_common(),
        per_module=modules.most_common(10),
        lighthouse_ready=lighthouse_ready,
    )
    (out_dir / "coverage_report.json").write_text(
        json.dumps(report.to_json(), indent=2), encoding="utf-8"
    )
    return report
