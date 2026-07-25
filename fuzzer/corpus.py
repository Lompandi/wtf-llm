"""Corpus and seed-spool I/O (CLAUDE.md CP4, section 12.1).

Section 12.1 settles how seeds reach a running campaign, and it is **not** by
dropping files into ``inputs/``: that is the startup seed directory only, and
assuming otherwise fails silently (section 10). The supported runtime path is
the module's ``CustomMutator_t``, which drains a spool directory on the master.

This module owns the **producer** side of that spool. CP7's ``llm/spool.py``
becomes the sidecar loop that calls into here; keeping the mechanism in one
place means the write protocol cannot drift between producer and consumer.

The protocol, matching ``fuzzer/module/fuzzer_snapfuzz.cc`` exactly
(DECISIONS R9):

* producer writes ``<name>.tmp``, then **renames** to ``<name>.json``. Rename is
  atomic, so a half-written seed is never visible to the consumer.
* consumer reads one seed and **deletes** it.
* every race falls through to the built-in mutator; nothing blocks, because
  ``GetNewTestcase()`` runs on the master's hot path with every worker waiting.

**NO LLM ANYWHERE IN THIS MODULE.** It writes bytes it is handed. Generating
them is the slow clock's job.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path

from arch.contracts import SeedRecord

__all__ = ["SeedSpool", "Corpus", "TARGET_SUBDIRS", "ensure_target_tree"]

# The five directories wtf expects under targets/<name>/ (section 13.1).
TARGET_SUBDIRS = ("inputs", "outputs", "coverage", "crashes", "state")

SPOOL_SUFFIX = ".json"
SPOOL_TEMP_SUFFIX = ".tmp"


def ensure_target_tree(target_dir: Path) -> list[Path]:
    """Create the target tree, except ``state/`` which must already exist.

    ``state/`` holds the snapshot and is produced by CP3, not by us. Creating an
    empty one would turn a missing-snapshot error into a confusing wtf failure
    much later.
    """
    made = []
    for name in TARGET_SUBDIRS:
        path = target_dir / name
        if name == "state":
            if not path.exists():
                raise FileNotFoundError(
                    f"{path} does not exist. The snapshot comes from CP3 "
                    f"(prep/snapshot_win.py); this function will not fabricate it."
                )
            continue
        if not path.exists():
            path.mkdir(parents=True)
            made.append(path)
    return made


@dataclass
class SeedSpool:
    """Producer side of the LLM seed spool."""

    path: Path

    def __post_init__(self) -> None:
        self.path = Path(self.path)

    def ensure(self) -> Path:
        self.path.mkdir(parents=True, exist_ok=True)
        return self.path

    def write(self, data: bytes | str, *, name: str | None = None) -> Path:
        """Write one seed atomically. Returns the final path.

        The temp file is created in the **same directory** as the destination so
        the rename cannot cross a filesystem boundary, which would make it
        non-atomic and reintroduce the torn-read the protocol exists to prevent.
        """
        self.ensure()
        if isinstance(data, str):
            data = data.encode("utf-8")
        if not data:
            raise ValueError("refusing to spool an empty seed: the consumer skips it")

        stem = name or f"llm-{uuid.uuid4().hex[:16]}"
        final = self.path / f"{stem}{SPOOL_SUFFIX}"
        temp = self.path / f"{stem}{SPOOL_TEMP_SUFFIX}"

        with temp.open("wb") as fd:
            fd.write(data)
            fd.flush()
            os.fsync(fd.fileno())
        temp.replace(final)  # atomic within one filesystem
        return final

    def write_record(self, record: SeedRecord) -> Path:
        """Spool a SeedRecord's bytes.

        Only ``seed_bytes`` crosses to the fuzzer -- ``origin`` and ``rationale``
        are ours, and the guest must never see them. They belong in the
        provenance log instead.
        """
        return self.write(record.seed_bytes)

    def pending(self) -> list[Path]:
        """Seeds waiting to be consumed. Excludes in-progress writes."""
        if not self.path.is_dir():
            return []
        return sorted(
            p
            for p in self.path.iterdir()
            if p.is_file() and p.suffix != SPOOL_TEMP_SUFFIX
        )

    def depth(self) -> int:
        return len(self.pending())

    def log_provenance(
        self,
        record: SeedRecord,
        spooled: Path,
        log: Path,
        archive_dir: Path | None = None,
    ) -> None:
        """Record why a seed was generated, keyed by the file it became.

        GATE 7 needs before/after coverage attributable to LLM seeds, and the
        seed file itself carries no metadata -- the guest gets bytes only.

        **The archive is not optional in practice.** The spool file is deleted by
        the consumer the moment it is taken (DECISIONS DEC-013), so once a
        campaign ends the seeds no longer exist anywhere and their coverage can
        never be re-measured. Recording only ``len(seed_bytes)`` -- which is all
        this did originally -- makes the attribution the docstring promises
        impossible after the fact. ``archive_dir`` keeps a copy that nobody
        deletes; it is evidence, not queue state, and the two must not share a
        directory or the mutator would consume the evidence.
        """
        archived_as: str | None = None
        if archive_dir is not None:
            archive_dir = Path(archive_dir)
            archive_dir.mkdir(parents=True, exist_ok=True)
            copy = archive_dir / spooled.name
            copy.write_bytes(record.seed_bytes)
            archived_as = copy.name

        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("a", encoding="utf-8") as fd:
            fd.write(
                json.dumps(
                    {
                        "spooled_as": spooled.name,
                        "archived_as": archived_as,
                        "origin": record.origin,
                        "rationale": record.rationale,
                        "bytes": len(record.seed_bytes),
                    }
                )
                + "\n"
            )


@dataclass
class Corpus:
    """Read-side view of a target's corpus directories.

    Deliberately read-only for ``outputs/``: that directory is the master's
    (``Corpus_t::SaveTestcase``, ``corpus.h:56-87``), and writing into it behind
    the master's back is the kind of assumption section 10 warns about.
    """

    target_dir: Path

    @property
    def inputs(self) -> Path:
        return self.target_dir / "inputs"

    @property
    def outputs(self) -> Path:
        return self.target_dir / "outputs"

    @property
    def crashes(self) -> Path:
        return self.target_dir / "crashes"

    @property
    def coverage(self) -> Path:
        return self.target_dir / "coverage"

    def _count(self, path: Path) -> int:
        return len([p for p in path.iterdir() if p.is_file()]) if path.is_dir() else 0

    def input_count(self) -> int:
        return self._count(self.inputs)

    def output_count(self) -> int:
        return self._count(self.outputs)

    def crash_count(self) -> int:
        return self._count(self.crashes)

    def coverage_files(self) -> list[Path]:
        """The ``*.cov`` files wtf will actually load.

        Only ``.cov`` counts -- wtf skips every other extension silently
        (``utils.cc:352``), which looks exactly like coverage never being
        instrumented.
        """
        if not self.coverage.is_dir():
            return []
        return sorted(p for p in self.coverage.iterdir() if p.name.endswith(".cov"))

    def add_startup_seed(self, data: bytes, name: str) -> Path:
        """Write a seed into ``inputs/``, atomically.

        Startup only. The master reads ``inputs/`` when it starts; a file added
        later is not picked up (section 12.1) -- use :class:`SeedSpool` for that.
        """
        self.inputs.mkdir(parents=True, exist_ok=True)
        final = self.inputs / name
        temp = self.inputs / f"{name}.tmp"
        temp.write_bytes(data)
        temp.replace(final)
        return final
