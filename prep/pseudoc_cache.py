"""A2 -- the pseudo-C cache (CLAUDE.md CP6).

Batch-decompiles the fuzz entry's call closure with **headless** Ghidra and
stores `PseudoCEntry` rows in SQLite, keyed by `(module, static_addr)`.

SQLite rather than a pile of files because the query that matters is a **range**
query: at triage time a fault lands at some address and we need the function
containing it, which is almost never a function's entry point. `get_by_addr`
therefore matches `min_static <= addr <= max_static`.

Headless, not GhidraMCP: the MCP server is a GUI plugin and only exists while
Ghidra is open (D-039), so it cannot build A2. It serves the interactive
on-demand lookup for an address this cache does not have -- see
:mod:`llm.ghidra_mcp`.

**Pseudo-C is lossy and is not source** (DECISIONS DEC-007). Names are invented
where the binary has no symbols, types are inferred, inlining is flattened.
Everything downstream must treat it as evidence, not ground truth.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from arch.contracts import PseudoCEntry

REPO_ROOT = Path(__file__).resolve().parents[1]

__all__ = ["PseudoCCache", "CacheStats", "build_from_export"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS pseudoc (
    module        TEXT NOT NULL,
    function      TEXT NOT NULL,
    static_addr   INTEGER NOT NULL,   -- the function's entry point
    min_static    INTEGER NOT NULL,   -- inclusive body bounds, for range lookup
    max_static    INTEGER NOT NULL,
    code          TEXT NOT NULL,
    source        TEXT NOT NULL,      -- 'headless' | 'ghidra_mcp'
    PRIMARY KEY (module, static_addr)
);
CREATE INDEX IF NOT EXISTS idx_pseudoc_range ON pseudoc (module, min_static, max_static);
CREATE INDEX IF NOT EXISTS idx_pseudoc_function ON pseudoc (module, function);
"""


@dataclass(frozen=True)
class CacheStats:
    module: str
    functions: int
    total_code_bytes: int
    min_static: int
    max_static: int


class PseudoCCache:
    """Read/write access to A2."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def __enter__(self) -> PseudoCCache:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    # --- writing ---------------------------------------------------------

    def put(
        self,
        entry: PseudoCEntry,
        *,
        min_static: int | None = None,
        max_static: int | None = None,
        source: str = "headless",
    ) -> None:
        """Insert or replace one function's pseudo-C.

        ``min_static``/``max_static`` default to the entry address, which makes
        the row findable by exact address but **not** by a range query. Callers
        with real bounds should pass them -- an on-demand MCP lookup usually
        knows only the entry, and that is recorded honestly rather than by
        inventing a span.
        """
        lo = entry.static_addr if min_static is None else min_static
        hi = entry.static_addr if max_static is None else max_static
        if hi < lo:
            raise ValueError(f"max_static {hi:#x} is below min_static {lo:#x}")

        self._conn.execute(
            "INSERT OR REPLACE INTO pseudoc "
            "(module, function, static_addr, min_static, max_static, code, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (entry.module, entry.function, entry.static_addr, lo, hi, entry.code, source),
        )
        self._conn.commit()

    def put_many(self, rows: list[tuple[PseudoCEntry, int, int, str]]) -> int:
        self._conn.executemany(
            "INSERT OR REPLACE INTO pseudoc "
            "(module, function, static_addr, min_static, max_static, code, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (e.module, e.function, e.static_addr, lo, hi, e.code, src)
                for (e, lo, hi, src) in rows
            ],
        )
        self._conn.commit()
        return len(rows)

    # --- reading ---------------------------------------------------------

    def _to_entry(self, row: sqlite3.Row) -> PseudoCEntry:
        return PseudoCEntry(
            module=row["module"],
            static_addr=row["static_addr"],
            function=row["function"],
            code=row["code"],
        )

    def get_by_addr(
        self, addr: int, *, module: str | None = None
    ) -> PseudoCEntry | None:
        """The function CONTAINING ``addr``, by static address.

        A fault address is almost never a function's entry point, so this is a
        range lookup, not an exact match. Where several rows contain the address
        (inlining, overlapping bodies) the tightest span wins -- the innermost
        function is the informative one.
        """
        sql = (
            "SELECT * FROM pseudoc WHERE ? BETWEEN min_static AND max_static"
            + (" AND module = ?" if module else "")
            + " ORDER BY (max_static - min_static) ASC LIMIT 1"
        )
        params: tuple = (addr, module) if module else (addr,)
        row = self._conn.execute(sql, params).fetchone()
        return self._to_entry(row) if row else None

    def get_by_function(
        self, name: str, *, module: str | None = None
    ) -> PseudoCEntry | None:
        sql = "SELECT * FROM pseudoc WHERE function = ?" + (
            " AND module = ?" if module else ""
        )
        params: tuple = (name, module) if module else (name,)
        row = self._conn.execute(sql, params).fetchone()
        return self._to_entry(row) if row else None

    def functions(self, module: str | None = None) -> list[str]:
        sql = "SELECT function FROM pseudoc" + (" WHERE module = ?" if module else "")
        sql += " ORDER BY static_addr"
        params: tuple = (module,) if module else ()
        return [r["function"] for r in self._conn.execute(sql, params)]

    def __len__(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM pseudoc").fetchone()[0]

    def stats(self, module: str | None = None) -> CacheStats | None:
        sql = (
            "SELECT module, COUNT(*) AS n, SUM(LENGTH(code)) AS bytes, "
            "MIN(min_static) AS lo, MAX(max_static) AS hi FROM pseudoc"
            + (" WHERE module = ?" if module else "")
            + " GROUP BY module LIMIT 1"
        )
        params: tuple = (module,) if module else ()
        row = self._conn.execute(sql, params).fetchone()
        if row is None or row["n"] == 0:
            return None
        return CacheStats(
            module=row["module"],
            functions=row["n"],
            total_code_bytes=row["bytes"] or 0,
            min_static=row["lo"],
            max_static=row["hi"],
        )

    def context_for_addr(
        self, addr: int, *, module: str | None = None, max_chars: int = 8000
    ) -> str | None:
        """Pseudo-C for a fault address, trimmed for a prompt.

        Section 7.3: do not send raw dumps to the LLM. Truncation is marked so a
        model is never silently handed a function that stops mid-statement.
        """
        entry = self.get_by_addr(addr, module=module)
        if entry is None:
            return None
        code = entry.code
        if len(code) > max_chars:
            code = code[:max_chars] + "\n/* ...truncated by the pseudo-C cache... */\n"
        return f"// {entry.module}!{entry.function} @ {entry.static_addr:#x}\n{code}"


def build_from_export(export_path: Path, cache_path: Path) -> CacheStats:
    """Load an ExportPseudoC.java dump into A2."""
    raw = json.loads(Path(export_path).read_text(encoding="utf-8"))
    module = raw["module"]

    rows: list[tuple[PseudoCEntry, int, int, str]] = []
    for fn in raw["functions"]:
        entry = PseudoCEntry(
            module=module,
            static_addr=fn["entry_static"],
            function=fn["function"],
            code=fn["code"],
        )
        rows.append((entry, fn["min_static"], fn["max_static"], "headless"))

    if not rows:
        raise ValueError(
            f"{export_path} contains no decompiled functions. An empty A2 makes "
            f"seed generation and triage silently context-free rather than "
            f"failing, so this is an error."
        )

    with PseudoCCache(cache_path) as cache:
        cache.put_many(rows)
        stats = cache.stats(module)

    assert stats is not None
    return stats


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="ExportPseudoC output -> A2")
    b.add_argument("--export", required=True, type=Path)
    b.add_argument(
        "--cache", type=Path, default=REPO_ROOT / "artifacts" / "a2_pseudoc.sqlite"
    )

    q = sub.add_parser("query", help="look up pseudo-C")
    q.add_argument(
        "--cache", type=Path, default=REPO_ROOT / "artifacts" / "a2_pseudoc.sqlite"
    )
    q.add_argument("--addr", type=lambda s: int(s, 0), help="static address")
    q.add_argument("--function")
    q.add_argument("--list", action="store_true")

    args = ap.parse_args(argv)

    if args.cmd == "build":
        stats = build_from_export(args.export, args.cache)
        print(f"A2: {args.cache}")
        print(f"  module     = {stats.module}")
        print(f"  functions  = {stats.functions}")
        print(f"  pseudo-C   = {stats.total_code_bytes} chars")
        print(f"  span       = {stats.min_static:#x} .. {stats.max_static:#x}")
        return 0

    with PseudoCCache(args.cache) as cache:
        if args.list:
            for name in cache.functions():
                print(name)
            return 0
        entry = None
        if args.addr is not None:
            entry = cache.get_by_addr(args.addr)
        elif args.function:
            entry = cache.get_by_function(args.function)
        else:
            print("pass --addr, --function or --list")
            return 1

        if entry is None:
            print("not in the cache")
            return 1
        print(f"// {entry.module}!{entry.function} @ {entry.static_addr:#x}")
        print(entry.code)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
