"""Seed publishing for the slow clock (CLAUDE.md CP7, section 12.1).

The low-level write protocol lives in :class:`fuzzer.corpus.SeedSpool` so that
producer and consumer cannot drift apart. This module is the **sidecar-facing**
publisher on top of it, and it owns three things the raw protocol does not:

* **Provenance.** Only bytes cross into the spool -- the guest must never see our
  metadata -- so `origin` and `rationale` go to a side log keyed by the filename
  the seed became. GATE 7 needs coverage attributable to LLM seeds, and without
  this the seeds are anonymous the moment they are written.
* **Dedup across rounds.** A plateau that persists gets re-analysed, and an LLM
  asked twice about the same frontier tends to answer similarly. Re-spooling a
  seed already tried wastes a worker's time and makes the before/after
  measurement muddier.
* **Back-pressure.** If the mutator is not draining -- a misconfigured
  `SNAPFUZZ_SEED_SPOOL`, or the master not running -- the spool grows without
  bound and every generated seed is silently wasted. Publishing refuses past a
  depth cap and says so, rather than filling a directory nobody reads.

Ownership (RULE 4, DECISIONS R9): producer writes `<name>.tmp` then renames;
**the consumer deletes**. Every race falls through to the built-in mutator
because `GetNewTestcase()` must never block.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from arch.contracts import SeedRecord
from fuzzer.corpus import SeedSpool

__all__ = ["SpoolFull", "SeedPublisher", "PublishResult"]


class SpoolFull(RuntimeError):
    """The consumer is not draining. Generating more would be wasted work."""


@dataclass(frozen=True)
class PublishResult:
    published: list[Path]
    skipped_duplicates: int
    spool_depth: int

    @property
    def count(self) -> int:
        return len(self.published)


@dataclass
class SeedPublisher:
    spool_path: Path
    provenance_log: Path
    max_spool_depth: int = 64
    # Where a copy of every published seed is kept. MUST NOT be the spool: the
    # mutator deletes what it takes from there, so evidence stored in the spool
    # is evidence that disappears exactly when a campaign succeeds. Defaults to a
    # sibling of the provenance log.
    archive_dir: Path | None = None

    _spool: SeedSpool = field(init=False)
    _published_digests: set[str] = field(default_factory=set, init=False)
    _round: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self._spool = SeedSpool(Path(self.spool_path))
        self._spool.ensure()
        if self.archive_dir is None:
            self.archive_dir = Path(self.provenance_log).parent / "seed_archive"
        self.archive_dir = Path(self.archive_dir)
        if self.archive_dir.resolve() == Path(self.spool_path).resolve():
            raise ValueError(
                f"archive_dir must not be the spool ({self.spool_path}): the "
                f"master's mutator deletes seeds it consumes from there, so the "
                f"archive would be destroyed by a working campaign"
            )

    @staticmethod
    def _digest(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()[:16]

    @property
    def depth(self) -> int:
        return self._spool.depth()

    def publish(self, records: list[SeedRecord]) -> PublishResult:
        """Write a round of seeds, skipping ones already published."""
        depth = self.depth
        if depth >= self.max_spool_depth:
            raise SpoolFull(
                f"{depth} seeds still unconsumed in {self.spool_path} "
                f"(cap {self.max_spool_depth}). The master's CustomMutator_t is "
                f"not draining -- check that SNAPFUZZ_SEED_SPOOL points here and "
                f"that the master is running. Generating more would be wasted."
            )

        self._round += 1
        written: list[Path] = []
        duplicates = 0

        for index, record in enumerate(records):
            digest = self._digest(record.seed_bytes)
            if digest in self._published_digests:
                duplicates += 1
                continue
            self._published_digests.add(digest)

            path = self._spool.write(
                record.seed_bytes, name=f"llm-r{self._round:03d}-{index:02d}-{digest}"
            )
            self._spool.log_provenance(
                record, path, Path(self.provenance_log), archive_dir=self.archive_dir
            )
            written.append(path)

        return PublishResult(
            published=written,
            skipped_duplicates=duplicates,
            spool_depth=self.depth,
        )

    def pending(self) -> list[Path]:
        return self._spool.pending()

    def clear(self) -> int:
        """Drop unconsumed seeds. For starting a measured run from a clean slate."""
        removed = 0
        for path in self._spool.pending():
            try:
                path.unlink()
                removed += 1
            except OSError:
                pass
        return removed
