"""Read the master's aggregate coverage -> CoverageSummary (CLAUDE.md CP4).

Section 12.3 is emphatic that plateau is computed on the **master's aggregate**
coverage, never one worker's. This module is therefore built around the master's
own stat line, which is exactly that aggregate.

Observed format (GATE 1, `wtf master` stdout)::

    #3745 cov: 12631 (+12631) corp: 31 (27.3kb) exec/s: 374.0 (1 nodes) \
        lastcov: 3.0s crash: 630 timeout: 0 cr3: 0 uptime: 14.0s

Note what the fields actually mean, because two are easy to misread:

* ``cov`` is a **cardinality**, not a hit count. The master keeps coverage in a
  set (``server.h:822-830``), so there is no notion of how often a block was
  hit (DECISIONS R6).
* ``crash`` is a count of crash **events**, not of distinct crashes or of files
  written. GATE 1 measured 1113 events against 38 files, because the master
  names crash files by fault address and skips ones that already exist
  (D-024). Do not report it as a bug count.

CLAUDE.md section 13.4 suggests watching an aggregated ``coverage.cov`` file
instead. No writer for that file exists in this revision of the source (D-021),
so this parser is the read path until that is resolved.

**NO LLM ANYWHERE IN THIS MODULE.** It is on the fast path.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from arch.contracts import CoverageSummary

__all__ = ["MasterStats", "parse_stat_line", "iter_stat_lines", "CoverageTracker"]

# #3745 cov: 12631 (+12631) corp: 31 (27.3kb) exec/s: 374.0 (1 nodes)
#   lastcov: 3.0s crash: 630 timeout: 0 cr3: 0 uptime: 14.0s
_STAT_RE = re.compile(
    r"^#(?P<execs>\d+)\s+"
    r"cov:\s*(?P<cov>\d+)\s*\(\+(?P<new_cov>\d+)\)\s+"
    r"corp:\s*(?P<corpus>\d+)\s*\((?P<corpus_size>[^)]*)\)\s+"
    r"exec/s:\s*(?P<execs_per_sec>[\d.]+\S*)\s*\((?P<nodes>\d+)\s+nodes\)\s+"
    r"lastcov:\s*(?P<lastcov>[\d.]+)s\s+"
    r"crash:\s*(?P<crashes>\d+)\s+"
    r"timeout:\s*(?P<timeouts>\d+)\s+"
    r"cr3:\s*(?P<cr3>\d+)\s+"
    r"uptime:\s*(?P<uptime>[\d.]+)(?P<uptime_unit>s|min|h)"
)

_UPTIME_SCALE = {"s": 1.0, "min": 60.0, "h": 3600.0}


@dataclass(frozen=True)
class MasterStats:
    """One aggregate sample from the master."""

    execs: int
    coverage: int  # cardinality of the aggregate coverage set
    new_coverage: int  # delta reported by the master for this line
    corpus_size: int
    execs_per_sec: float
    nodes: int  # how many workers are reporting
    seconds_since_last_coverage: float
    crash_events: int  # EVENTS, not distinct bugs -- see module docstring
    timeouts: int
    cr3_changes: int
    uptime_s: float

    @property
    def is_multi_worker(self) -> bool:
        return self.nodes > 1


def parse_stat_line(line: str) -> MasterStats | None:
    """Parse one master stat line, or return None if it is not one."""
    m = _STAT_RE.match(line.strip())
    if not m:
        return None

    # exec/s can be a garbage sentinel on the very first line
    # ("9223372036854.8m") before any testcase has completed.
    raw_rate = m.group("execs_per_sec")
    try:
        execs_per_sec = float(re.sub(r"[^\d.]", "", raw_rate) or 0.0)
    except ValueError:
        execs_per_sec = 0.0

    return MasterStats(
        execs=int(m.group("execs")),
        coverage=int(m.group("cov")),
        new_coverage=int(m.group("new_cov")),
        corpus_size=int(m.group("corpus")),
        execs_per_sec=execs_per_sec,
        nodes=int(m.group("nodes")),
        seconds_since_last_coverage=float(m.group("lastcov")),
        crash_events=int(m.group("crashes")),
        timeouts=int(m.group("timeouts")),
        cr3_changes=int(m.group("cr3")),
        uptime_s=float(m.group("uptime")) * _UPTIME_SCALE[m.group("uptime_unit")],
    )


def iter_stat_lines(text: str):
    """Yield every MasterStats in a master log, in order."""
    for line in text.splitlines():
        stats = parse_stat_line(line)
        if stats is not None:
            yield stats


@dataclass
class CoverageTracker:
    """Turn a stream of master stat lines into CoverageSummary ticks.

    ``new_edges`` is computed against the previous tick rather than trusted from
    the master's own ``(+n)``: the master reports its delta per stat line, which
    is not the same interval as our tick if lines are missed or batched.
    """

    tick: int = 0
    last_coverage: int = 0
    plateau_ticks: int = 0
    crash_bucket_count: int = 0
    history: list[CoverageSummary] = field(default_factory=list)

    def observe(self, stats: MasterStats, *, frontier: list[int] | None = None):
        """Record one sample and return the resulting CoverageSummary."""
        new_edges = max(0, stats.coverage - self.last_coverage)

        # A plateau is consecutive ticks with no NEW coverage. Section 12.3 wants
        # the primary threshold expressed in executions, not wall clock; that
        # decision belongs to plateau.py (CP7), which consumes these summaries.
        if new_edges == 0:
            self.plateau_ticks += 1
        else:
            self.plateau_ticks = 0

        self.tick += 1
        self.last_coverage = stats.coverage

        summary = CoverageSummary(
            tick=self.tick,
            total_edges=stats.coverage,
            new_edges=new_edges,
            plateau_ticks=self.plateau_ticks,
            corpus_size=stats.corpus_size,
            crash_bucket_count=self.crash_bucket_count,
            frontier=frontier or [],
        )
        self.history.append(summary)
        return summary

    @property
    def is_growing(self) -> bool:
        """Did coverage increase at any point? GATE 4 requires growth."""
        return any(s.new_edges > 0 for s in self.history[1:]) or (
            len(self.history) == 1 and self.history[0].total_edges > 0
        )

    def write_jsonl(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fd:
            for summary in self.history:
                fd.write(summary.model_dump_json() + "\n")
        return path
