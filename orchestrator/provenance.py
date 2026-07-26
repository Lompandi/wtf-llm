"""Which target an artifact was produced for.

The pipeline's up-to-date check used to be "the file exists and is non-empty". That
is a statement about the filesystem, not about the run, and the difference is a real
reported bug (D-073):

    python -m orchestrator.pipeline --binary .../fuzzing-base-test.exe \
        --state-dir targets/fuzzing-snapshot-2/state \
        --target-name fuzzing-snapshot-2 --module demo

    [1/13] 01-pseudoc  SKIPPED, already produced: artifacts/a2_pseudoc_module.json
    [2/13] 02-a2       SKIPPED, already produced: artifacts/a2_pseudoc_module.sqlite
    [3/13] 03-entry    SKIPPED, already produced: artifacts/fuzz_entry_llm.json
    [4/13] 04-blocks   SKIPPED, already produced: artifacts/a3_ghidra_blocks_module.json
    [5/13] 05-covfile  cov file: .../tlv_server.cov  (613 RVAs, name='tlv_server')
                       FAILED: fuzzing-base-test.cov absent

Every one of those artifacts belonged to a **different program**, left by an earlier
run on the development target. The filenames carry the analysis SCOPE -- added because
a closure-scoped export silently satisfied a module-scoped request (D-057) -- and the
identical argument was never applied to the target. So the second target inherited the
first's pseudo-C, its chosen fuzz entry, and its 613 basic blocks, and the up-to-date
check called all of it done.

Stage 05 is the only reason this surfaced, and it surfaced by accident: it expects
`<binary stem>.cov` while `prep.bb_to_wtf` names the file from the export's own
`module` field. Those two disagreed, so the run stopped. **Had they agreed, the
campaign would have proceeded** -- fuzzing `fuzzing-base-test.exe` through
breakpoints computed for `tlv_server.exe`, reporting coverage, and finding nothing,
with no error anywhere. That is the failure this module exists to make impossible.

The rule here is the one RULE 3 states for gates, applied to artifacts: an artifact
that cannot prove which target it belongs to is not evidence that the stage ran for
*this* target. Absent or mismatched provenance means re-run, never reuse.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path

__all__ = [
    "STAMP_NAME",
    "ArtifactStamp",
    "TargetIdentity",
    "load_stamps",
    "record",
    "stale_reason",
]

STAMP_NAME = ".provenance.json"

# Read in blocks: the target binary is a PE that can be tens of MB, and the point is
# to notice a rebuild, not to be clever.
_BLOCK = 1 << 20


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fd:
        while chunk := fd.read(_BLOCK):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class TargetIdentity:
    """What makes two runs the same run, for the purpose of reusing artifacts.

    `binary_sha256` and not just the path, because rebuilding the target in place is
    the other way an artifact goes stale while its filename stays right -- and a
    rebuilt binary has different basic blocks at different offsets, so A3 is wrong in
    exactly the way that produces MISSING breakpoints rather than an error (D-027).
    """

    target_name: str
    binary: str
    binary_sha256: str
    scope: str

    @classmethod
    def of(cls, *, target_name: str, binary: Path, scope: str) -> TargetIdentity:
        return cls(
            target_name=target_name,
            binary=str(Path(binary).resolve()),
            binary_sha256=sha256_file(Path(binary)),
            scope=scope,
        )


@dataclass(frozen=True)
class ArtifactStamp:
    """Provenance for one produced file, plus enough to notice it changed since.

    (mtime_ns, size) is not integrity checking -- it is there so that an artifact
    edited or replaced by hand after being stamped is not covered by a stamp that no
    longer describes it. Hashing every artifact would be honest too, but A2 exports
    run to hundreds of MB and this check runs on every stage of every invocation.
    """

    identity: TargetIdentity
    stage: str
    mtime_ns: int
    size: int

    @classmethod
    def of(cls, path: Path, identity: TargetIdentity, stage: str) -> ArtifactStamp:
        stat = path.stat()
        return cls(
            identity=identity, stage=stage, mtime_ns=stat.st_mtime_ns, size=stat.st_size
        )


def _key(path: Path, artifacts_dir: Path) -> str:
    """Stable key for an artifact: relative to the artifacts dir where possible.

    Stage 05's real deliverable is `targets/<name>/coverage/<module>.cov`, which lives
    outside `artifacts/` entirely, so this has to cope with paths that are not under
    it rather than raising the way `relative_to` would.
    """
    try:
        return Path(path).resolve().relative_to(Path(artifacts_dir).resolve()).as_posix()
    except ValueError:
        return Path(path).resolve().as_posix()


def load_stamps(artifacts_dir: Path) -> dict[str, ArtifactStamp]:
    """Every stamp recorded in this artifacts directory, or {} if there are none.

    A corrupt or unreadable stamp file yields {} rather than raising: the effect of
    "no provenance" is that stages re-run, which is always safe. Failing the whole
    invocation because a cache annotation was truncated would not be.
    """
    path = Path(artifacts_dir) / STAMP_NAME
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    out: dict[str, ArtifactStamp] = {}
    for key, entry in (raw.get("artifacts") or {}).items():
        try:
            out[key] = ArtifactStamp(
                identity=TargetIdentity(**entry["identity"]),
                stage=entry["stage"],
                mtime_ns=int(entry["mtime_ns"]),
                size=int(entry["size"]),
            )
        except (KeyError, TypeError, ValueError):
            continue  # an entry we cannot read is an entry we do not trust
    return out


def record(
    artifacts_dir: Path,
    identity: TargetIdentity,
    stage: str,
    produced: list[Path],
) -> None:
    """Stamp everything a stage just produced, merging into what is already there.

    Merging rather than replacing, because two targets legitimately share this
    directory: stamping target B's artifacts must not erase the record of which
    artifacts belong to A. That record is what lets B's run tell them apart.
    """
    artifacts_dir = Path(artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    path = artifacts_dir / STAMP_NAME

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raw = {}
    entries = raw.get("artifacts")
    if not isinstance(entries, dict):
        entries = {}

    for artifact in produced:
        artifact = Path(artifact)
        if not artifact.exists():
            continue  # a stage that did not produce it does not get a stamp for it
        entries[_key(artifact, artifacts_dir)] = asdict(
            ArtifactStamp.of(artifact, identity, stage)
        )

    raw["artifacts"] = entries
    raw["note"] = (
        "Which target each artifact was produced for. Written by "
        "orchestrator/pipeline.py; read by its up-to-date check so one target's "
        "analysis is never reused for another (D-073). Deleting this file is safe -- "
        "stages re-run."
    )
    path.write_text(json.dumps(raw, indent=2, sort_keys=True), encoding="utf-8")


def stale_reason(
    path: Path,
    identity: TargetIdentity,
    stamps: dict[str, ArtifactStamp],
    artifacts_dir: Path,
) -> str | None:
    """Why this artifact must not be reused for `identity`, or None if it may be.

    Returns prose because it is printed. A user who sees "SKIPPED, already produced"
    for a target they have never run before has been misled, and the fix is not only
    to re-run but to say which of these it was.
    """
    stamp = stamps.get(_key(path, artifacts_dir))
    if stamp is None:
        return (
            "no provenance recorded, so there is nothing to show it was produced for "
            "this target"
        )

    was, now = stamp.identity, identity
    if was.binary_sha256 != now.binary_sha256:
        if was.binary != now.binary:
            return (
                f"produced for a different binary ({Path(was.binary).name}), so its "
                f"addresses describe another program"
            )
        return (
            f"{Path(was.binary).name} has been rebuilt since this was produced, so "
            f"its offsets no longer match the binary"
        )
    if was.target_name != now.target_name:
        return f"produced for target {was.target_name!r}"
    if was.scope != now.scope:
        return f"produced at {was.scope!r} scope, not {now.scope!r}"

    try:
        stat = Path(path).stat()
    except OSError:
        return "cannot be read"
    if (stat.st_mtime_ns, stat.st_size) != (stamp.mtime_ns, stamp.size):
        return "has changed since it was stamped, so the provenance no longer describes it"
    return None
