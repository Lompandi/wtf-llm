"""Build a release: the source, and the evidence, as two things.

`tools/evidence.py` records WHAT the evidence is and what each artifact proves. It does
not package anything, and the consequence was found by a reviewer rather than by us:
inside a release ZIP, `python -m tools.evidence verify` reported most artifacts missing.
The manifest shipped and the evidence did not, so the numbers in the write-up were
unreproducible by anyone who had only the archive (D-075).

Two archives, because they have different sizes and different audiences:

* **snapfuzz-source.zip** -- the code, the config, the tests, the manifest. Small.
  Enough to run the tool, and enough to check any evidence you obtain separately.
* **snapfuzz-evidence.zip** -- the recorded JSON, JSONL, logs, plots and gate results.
  Everything needed to re-check a claim without re-running a campaign.

**The 1.8 GB `mem.dmp` is in neither.** `EVIDENCE` marks two artifacts `large`, and the
point of D-069 was that hashes travel in git while gigabytes do not. So they are
recorded by hash, size, and where they came from, and `RELEASE-MANIFEST.json` says so
explicitly rather than leaving a reader to discover an absence.

Both archives carry:

* **RELEASE-MANIFEST.json** -- every file, its sha256 and size, plus which git commit
  this was cut from and whether the tree was dirty.
* **SHA256SUMS** -- the same hashes in the format `sha256sum -c` reads, because a
  reader with a shell should not have to write a script to check an archive.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

__all__ = [
    "FileRecord",
    "build_manifest",
    "collect_evidence",
    "collect_source",
    "collect_source_with_skips",
    "write_release",
]

MANIFEST_NAME = "RELEASE-MANIFEST.json"
SUMS_NAME = "SHA256SUMS"

# What belongs in the source archive. Directories are walked; a leading `!` is not
# supported on purpose -- an exclusion list that grows is how a 1.8 GB dump ends up in
# a "source" ZIP.
SOURCE_INCLUDE = (
    "arch", "config", "prep", "fuzzer", "engine_bridge", "llm", "analysis",
    "orchestrator", "eval", "tests", "tools", "docs",
    # The Linux snapshot path. Left out of the first version of this list, and the
    # release's own test run caught it: prep/snapshot_linux.py and two CP3 tests read
    # files under here, so a source archive without it ships a tool with one broken
    # half and a suite that fails on the ZIP (D-075).
    "linux_mode",
    "README.md", "README.zh-TW.md", "LICENSE", "requirements.txt", "pytest.ini",
    "snapfuzz.py",
)

# Never in any archive, whatever else matches: credentials, caches, and the artifacts
# that are large by policy.
ALWAYS_EXCLUDE_PARTS = frozenset({
    "__pycache__", ".git", ".venv", "node_modules", ".pytest_cache", ".ruff_cache",
})
ALWAYS_EXCLUDE_NAMES = frozenset({".env", ".env.local"})

# Evidence small enough to ship. Extensions rather than a file list, so a new recorded
# run is included without editing this.
EVIDENCE_SUFFIXES = frozenset({".json", ".jsonl", ".log", ".md", ".png", ".csv", ".txt"})
EVIDENCE_ROOTS = ("artifacts",)

# A cap, so a stray multi-hundred-MB log cannot quietly turn the evidence archive into
# the thing it exists to avoid being. Reported, never silently dropped.
MAX_EVIDENCE_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class FileRecord:
    path: str  # repo-relative, forward slashes
    sha256: str
    size: int


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _excluded(path: Path) -> bool:
    if path.name in ALWAYS_EXCLUDE_NAMES:
        return True
    return any(part in ALWAYS_EXCLUDE_PARTS for part in path.parts)


def _walk(root: Path, base: Path) -> list[Path]:
    if root.is_file():
        return [root] if not _excluded(root) else []
    out: list[Path] = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and not _excluded(path):
            out.append(path)
    return out


def collect_source(repo_root: Path = REPO_ROOT) -> list[Path]:
    """Every file the source archive should contain.

    Internal documents are gitignored and therefore absent from a clone, but they may be
    present here -- so they are filtered by asking git, not by listing names. A release
    cut from a working tree must not accidentally ship the spec and the failure log
    (D-072).
    """
    files, skipped = collect_source_with_skips(repo_root)
    if skipped:
        # NEVER silent. Cutting a release from a tree with new work in it dropped
        # tests/gates/test_cp1.py, tests/gates/pe_fixture.py and
        # linux_mode/qemu_snapshot/snapshot_trigger.py -- all uncommitted -- and the
        # archive's own test run then failed with ModuleNotFoundError. The filter is
        # right; being quiet about it was not (D-075).
        print(f"  [warn] {len(skipped)} file(s) under SOURCE_INCLUDE are untracked and")
        print("         were NOT packaged. Commit them, or they ship in nothing:")
        for path in skipped[:20]:
            print(f"           {path.relative_to(repo_root).as_posix()}")
        if len(skipped) > 20:
            print(f"           ... and {len(skipped) - 20} more")
    return files


def collect_source_with_skips(
    repo_root: Path = REPO_ROOT,
) -> tuple[list[Path], list[Path]]:
    """(packaged, skipped-because-untracked). Separated so callers can report."""
    tracked = _tracked_files(repo_root)
    ignored = _ignored_files(repo_root)
    out: list[Path] = []
    skipped: list[Path] = []
    for entry in SOURCE_INCLUDE:
        target = repo_root / entry
        if not target.exists():
            continue
        for path in _walk(target, repo_root):
            relative = path.relative_to(repo_root).as_posix()
            if tracked is not None and relative not in tracked:
                # Ignored on purpose is not "forgot to commit", so it is excluded
                # silently. Anything else is reported.
                if relative not in ignored:
                    skipped.append(path)
                continue
            out.append(path)
    return sorted(set(out)), sorted(set(skipped))


def _ignored_files(repo_root: Path) -> set[str]:
    """Paths git deliberately ignores, so the warning does not demand the impossible.

    The first version of the untracked warning listed CLAUDE.md and the four internal
    docs and said "commit them, or they ship in nothing" -- for files that must never
    ship (D-072). Ignored and merely-new are different things, and only the second is
    somebody forgetting to commit.
    """
    try:
        proc = subprocess.run(
            ["git", "ls-files", "--others", "--ignored", "--exclude-standard"],
            cwd=repo_root, capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    if proc.returncode != 0:
        return set()
    return {line.strip() for line in proc.stdout.splitlines() if line.strip()}


def _tracked_files(repo_root: Path) -> set[str] | None:
    """Every path git tracks, or None when this is not a checkout.

    None means "cannot filter", and the caller then ships what it was asked to ship. It
    does NOT mean "ship everything I can find": in a non-checkout there is no `.env` and
    no internal doc to leak, because those are exactly the files a clone lacks.
    """
    try:
        proc = subprocess.run(
            ["git", "ls-files"], cwd=repo_root, capture_output=True, text=True, timeout=120
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return {line.strip() for line in proc.stdout.splitlines() if line.strip()}


def collect_evidence(repo_root: Path = REPO_ROOT) -> tuple[list[Path], list[tuple[Path, int]]]:
    """(files to ship, files skipped for size). Both returned, so nothing is silent."""
    ship: list[Path] = []
    oversize: list[tuple[Path, int]] = []
    for root_name in EVIDENCE_ROOTS:
        root = repo_root / root_name
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file() or _excluded(path):
                continue
            if path.suffix.lower() not in EVIDENCE_SUFFIXES:
                continue
            size = path.stat().st_size
            if size > MAX_EVIDENCE_BYTES:
                oversize.append((path, size))
                continue
            ship.append(path)
    return ship, oversize


def _provenance(repo_root: Path) -> dict:
    def git(*args: str) -> str | None:
        try:
            proc = subprocess.run(
                ["git", *args], cwd=repo_root, capture_output=True, text=True, timeout=60
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return proc.stdout.strip() if proc.returncode == 0 else None

    status = git("status", "--porcelain")
    return {
        "commit": git("rev-parse", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        # A release cut from a dirty tree is not reproducible from the commit alone, and
        # a reader deserves to know before they try.
        "dirty": bool(status) if status is not None else None,
    }


def build_manifest(
    files: list[Path],
    *,
    kind: str,
    repo_root: Path = REPO_ROOT,
    excluded_large: list[dict] | None = None,
    notes: list[str] | None = None,
) -> dict:
    records = [
        FileRecord(
            path=path.relative_to(repo_root).as_posix(),
            sha256=_sha256(path),
            size=path.stat().st_size,
        )
        for path in files
    ]
    return {
        "kind": kind,
        "provenance": _provenance(repo_root),
        "file_count": len(records),
        "total_bytes": sum(r.size for r in records),
        "files": [r.__dict__ for r in records],
        # Named absences. An archive that quietly lacks the biggest artifact is how a
        # reviewer concludes the evidence does not exist.
        "excluded_large": excluded_large or [],
        "notes": notes or [],
    }


def _sums_text(manifest: dict) -> str:
    # `sha256sum -c` format: hash, two spaces, path.
    return "".join(f"{f['sha256']}  {f['path']}\n" for f in manifest["files"])


def _large_records(repo_root: Path) -> list[dict]:
    """The artifacts EVIDENCE marks too large to ship, recorded by hash instead."""
    from tools.evidence import EVIDENCE

    out: list[dict] = []
    for item in EVIDENCE:
        if not getattr(item, "large", False):
            continue
        path = repo_root / item.path
        record = {
            "path": item.path,
            "proves": item.proves,
            "regenerate": item.regenerate,
            "present_when_cut": path.is_file(),
        }
        if path.is_file():
            record["size"] = path.stat().st_size
            record["sha256"] = _sha256(path)
        out.append(record)
    return out


def write_release(
    out_dir: Path,
    *,
    repo_root: Path = REPO_ROOT,
    source: bool = True,
    evidence: bool = True,
) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    large = _large_records(repo_root)

    if source:
        files = collect_source(repo_root)
        manifest = build_manifest(
            files,
            kind="source",
            repo_root=repo_root,
            excluded_large=large,
            notes=[
                "Code, config, tests and docs/evidence-manifest.json. No recorded "
                "artifacts: see snapfuzz-evidence.zip.",
                "Internal documents (CLAUDE.md, docs/PROGRESS.md, DEVIATIONS.md, "
                "DECISIONS.md, RESULTS.md, ENVIRONMENT.md) are gitignored and are "
                "filtered by asking git, so a release cut from a working tree does not "
                "ship them.",
            ],
        )
        written.append(_write_zip(out_dir / "snapfuzz-source.zip", files, manifest, repo_root))

    if evidence:
        files, oversize = collect_evidence(repo_root)
        manifest = build_manifest(
            files,
            kind="evidence",
            repo_root=repo_root,
            excluded_large=large
            + [
                {
                    "path": path.relative_to(repo_root).as_posix(),
                    "size": size,
                    "proves": "excluded by size cap, not by policy",
                    "regenerate": "re-run the stage that produced it",
                    "present_when_cut": True,
                }
                for path, size in oversize
            ],
            notes=[
                "Recorded JSON, JSONL, logs, plots and gate results -- enough to "
                "re-check a claim without re-running a campaign.",
                f"Files over {MAX_EVIDENCE_BYTES // (1024 * 1024)} MB are listed under "
                f"excluded_large rather than shipped.",
                "Verify with: python -m tools.evidence verify",
            ],
        )
        written.append(_write_zip(out_dir / "snapfuzz-evidence.zip", files, manifest, repo_root))

    return written


def _write_zip(target: Path, files: list[Path], manifest: dict, repo_root: Path) -> Path:
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            archive.write(path, path.relative_to(repo_root).as_posix())
        archive.writestr(MANIFEST_NAME, json.dumps(manifest, indent=2))
        archive.writestr(SUMS_NAME, _sums_text(manifest))
    return target


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "dist")
    ap.add_argument("--source-only", action="store_true")
    ap.add_argument("--evidence-only", action="store_true")
    args = ap.parse_args(argv)

    written = write_release(
        args.out,
        source=not args.evidence_only,
        evidence=not args.source_only,
    )
    for path in written:
        size_mb = path.stat().st_size / (1024 * 1024)
        with zipfile.ZipFile(path) as archive:
            count = len(archive.namelist())
        try:
            shown = path.relative_to(REPO_ROOT)
        except ValueError:
            shown = path
        print(f"{shown}  {size_mb:.1f} MB  {count} entries")

    _, oversize = collect_evidence(REPO_ROOT)
    for path, size in oversize:
        print(
            f"  not shipped ({size / (1024 * 1024):.0f} MB): "
            f"{path.relative_to(REPO_ROOT)} -- recorded in {MANIFEST_NAME}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
