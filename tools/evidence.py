"""Record and verify the evidence behind each gate result.

`artifacts/` is gitignored -- correctly, because the tlv_server `mem.dmp` alone is
1.8 GB. The consequence was not thought through: `git ls-files artifacts/` returns
**nothing**, so a clone contains every PASS in `docs/PROGRESS.md` and not one byte
of what those PASSes were measured from. Nobody but this machine could audit or
reproduce any of them (D-069).

RULE 3 asks a gate to prove interfaces are wired with "the concrete artifacts that
must exist". A claim whose artifacts cannot be inspected is a claim, not a gate.

So this records a **manifest that is tracked**: for every expected artifact, its
sha256, size, and the command that regenerates it. The large files stay out of
git; their hashes do not. That makes three things possible that were not:

* tying a recorded result to specific bytes,
* noticing that an artifact changed under a result that still claims to describe
  it (`verify` reports drift),
* regenerating a missing one without reading the whole repo, because the command
  is recorded next to it.

    python -m tools.evidence record     # hash what is present, write the manifest
    python -m tools.evidence verify     # re-hash and report drift or absence
    python -m tools.evidence missing    # just list what is absent, with the command

`verify` exits non-zero on drift. Absence exits non-zero only under
SNAPFUZZ_STRICT_GATE=1, because a development clone legitimately has none of it --
and reporting that as a failure by default would make the tool something people
turn off.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = REPO_ROOT / "docs" / "evidence-manifest.json"

__all__ = ["EVIDENCE", "Evidence", "build_manifest", "verify_manifest"]


@dataclass(frozen=True)
class Evidence:
    """One artifact, what it proves, and how to make it again.

    ``regenerate`` is not documentation. It is the difference between "this file
    is missing" and "this file is missing and here is what produces it", and the
    second is the only one that lets someone else close the gap.
    """

    path: str
    gate: str
    proves: str
    regenerate: str
    # Files too large for git even as an occasional exception. Recorded by hash
    # only, and the distinction is stated so nobody waits for a commit that is
    # never coming.
    large: bool = False


EVIDENCE: tuple[Evidence, ...] = (
    # --- inputs the whole pipeline is measured against --------------------
    Evidence(
        "targets/tlv_server/target/tlv_server.exe",
        "cp1",
        "the target binary every number in docs/RESULTS.md was measured on",
        "extract target-tlv_server.7z from wtf's Releases into targets/",
    ),
    Evidence(
        "targets/tlv_server/state/mem.dmp",
        "cp3",
        "the snapshot A1 describes; 1.8 GB, produced by wtf's author on his own "
        "Hyper-V VM, NOT by this project's acquisition path",
        "extract target-tlv_server.7z from wtf's Releases into targets/",
        large=True,
    ),
    Evidence(
        "targets/tlv_server/state/regs.json",
        "cp3",
        "the register state at the snapshot point",
        "extract target-tlv_server.7z from wtf's Releases into targets/",
    ),
    Evidence(
        "targets/tlv_server/state/symbol-store.json",
        "cp3",
        "module base and symbol addresses; where module_base comes from",
        "extract target-tlv_server.7z from wtf's Releases into targets/",
    ),
    # --- derived artifacts ------------------------------------------------
    Evidence(
        "artifacts/tlv_server/a1_snapshot.json",
        "cp3",
        "A1: the SnapshotRef wtf loads, with module_base and entry_runtime_addr",
        "python -m prep.snapshot_win ingest --state targets/tlv_server/state "
        "--module tlv_server --binary targets/tlv_server/target/tlv_server.exe "
        "--entry-symbol ProcessPacket --out artifacts/tlv_server/a1_snapshot.json",
    ),
    Evidence(
        "artifacts/tlv_server/a3_bp_list.json",
        "cp2",
        "A3: the basic-block list the .cov breakpoint file is generated from",
        "python -m prep.ghidra_headless --what blocks --binary "
        "targets/tlv_server/target/tlv_server.exe --out "
        "artifacts/tlv_server/a3_ghidra_blocks_module.json --scope module --entry ProcessPacket "
        "&& python -m prep.bb_to_wtf --export artifacts/tlv_server/a3_ghidra_blocks_module.json "
        "--coverage-dir targets/snapfuzz/coverage --bp-list artifacts/tlv_server/a3_bp_list.json",
    ),
    Evidence(
        "artifacts/tlv_server/a2_pseudoc_module.sqlite",
        "cp6",
        "A2: the pseudo-C three of the four LLM stages read",
        "python -m prep.ghidra_headless --what pseudoc --binary "
        "targets/tlv_server/target/tlv_server.exe --out "
        "artifacts/tlv_server/a2_pseudoc_module.json --scope module --entry ProcessPacket "
        "&& python -m prep.pseudoc_cache build "
        "--export artifacts/tlv_server/a2_pseudoc_module.json "
        "--cache artifacts/tlv_server/a2_pseudoc_module.sqlite",
        large=True,
    ),
    Evidence(
        "artifacts/tlv_server/fuzz_entry_llm.json",
        "cp6",
        "the FuzzEntry the model chose from 84 candidates, matching ground truth",
        "python -m prep.entry_select --cache artifacts/tlv_server/a2_pseudoc_module.sqlite "
        "--module tlv_server --module-base 0x7ff719e50000 "
        "--ghidra-image-base 0x140000000 --out artifacts/tlv_server/fuzz_entry_llm.json",
    ),
    Evidence(
        "artifacts/tlv_server/input_spec.json",
        "cp11",
        "the InputSpec derived from pseudo-C; GATE 11's layout comparison reads it",
        "python -m prep.input_struct --entry artifacts/tlv_server/fuzz_entry_llm.json "
        "--cache artifacts/tlv_server/a2_pseudoc_module.sqlite --out artifacts/tlv_server/input_spec.json",
    ),
    # --- run evidence -----------------------------------------------------
    Evidence(
        "artifacts/runs/gate4/run_metadata.json",
        "cp4",
        "which module, backend and worker count the 663-second run used -- the "
        "field that caught a campaign running the WRONG module (D-056)",
        "python -m orchestrator.scheduler --label gate4 --workers 1 --minutes 11 "
        "--target-dir targets/snapfuzz --module snapfuzz",
    ),
    Evidence(
        "artifacts/runs/gate4/coverage_summaries.jsonl",
        "cp4",
        "the CoverageSummary ticks GATE 4's growth condition is read from",
        "same run as run_metadata.json above",
    ),
    Evidence(
        "artifacts/runs/gate4b/run_metadata.json",
        "cp4b",
        "the 4-worker run: aggregate coverage exceeding any single worker",
        "SNAPFUZZ_LIVE_CP4B=1 python -m orchestrator.scheduler --label gate4b "
        "--workers 4 --minutes 5 --target-dir targets/snapfuzz --module snapfuzz",
    ),
    Evidence(
        "artifacts/runs/gate8/buckets.json",
        "cp8",
        "53 crash files collapsing to 4 buckets from 52 distinct fault addresses",
        "python -m analysis.pipeline --target-dir targets/snapfuzz --label gate8 "
        "--replays 3",
    ),
    Evidence(
        "artifacts/runs/gate9/advisory.md",
        "cp9",
        "the GHSA advisory, confirmed findings only",
        "python -m analysis.triage_run --evidence artifacts/runs/gate8 --label gate9",
    ),
    Evidence(
        "artifacts/runs/gate9/discarded.jsonl",
        "cp9",
        "the false positives, kept for evaluation and NOT shipped",
        "same run as advisory.md above",
    ),
    Evidence(
        "artifacts/runs/gate10/comparison.json",
        "cp10",
        "the five-arm comparison behind every number in the README's results table",
        "python -m eval.baseline --minutes 5 --workers 2",
    ),
    Evidence(
        "artifacts/runs/gate7/seed_delta.json",
        "cp7",
        "coverage before and after seed injection -- the measurement GATE 7's "
        "unmet criterion is judged on",
        "python -m orchestrator.scheduler --label gate7 --workers 2 --minutes 15 "
        "--target-dir targets/snapfuzz --module snapfuzz --plateau-execs 20000",
    ),
    Evidence(
        "artifacts/gates/gate-results.json",
        "all",
        "which section 8 condition each gate proved, and where it is blocked",
        "python -m tools.gates run",
    ),
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _entry(item: Evidence, repo_root: Path) -> dict[str, Any]:
    path = repo_root / item.path
    record: dict[str, Any] = {
        "path": item.path,
        "gate": item.gate,
        "proves": item.proves,
        "regenerate": item.regenerate,
        "large": item.large,
        "present": path.is_file(),
    }
    if path.is_file():
        stat = path.stat()
        record["sha256"] = _sha256(path)
        record["size_bytes"] = stat.st_size
        record["mtime"] = stat.st_mtime
    return record


def build_manifest(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    def _git(*args: str) -> str | None:
        try:
            return subprocess.run(
                ["git", *args], cwd=repo_root, capture_output=True, text=True, timeout=30
            ).stdout.strip() or None
        except Exception:
            return None

    entries = [_entry(item, repo_root) for item in EVIDENCE]
    return {
        "type": "evidence-manifest",
        "recorded_at": time.time(),
        "commit": _git("rev-parse", "HEAD"),
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "note": (
            "artifacts/ and the large target files are gitignored. This manifest is "
            "tracked so a recorded gate result can be tied to specific bytes and "
            "regenerated -- see tools/evidence.py."
        ),
        "present": sum(1 for e in entries if e["present"]),
        "total": len(entries),
        "entries": entries,
    }


def verify_manifest(
    manifest: dict[str, Any], repo_root: Path = REPO_ROOT
) -> tuple[list[str], list[str]]:
    """Returns (drifted, absent).

    Drift is the interesting one: a file that exists but hashes differently means
    a recorded result is describing bytes that are no longer there. Absence on a
    fresh clone is expected.
    """
    drifted: list[str] = []
    absent: list[str] = []
    for entry in manifest["entries"]:
        path = repo_root / entry["path"]
        if not path.is_file():
            if entry.get("present"):
                absent.append(f"{entry['path']} (was present when recorded)")
            else:
                absent.append(entry["path"])
            continue
        if not entry.get("sha256"):
            continue
        if _sha256(path) != entry["sha256"]:
            drifted.append(entry["path"])
    return drifted, absent


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, help_text in (
        ("record", "hash what is present and write the manifest"),
        ("verify", "re-hash against the manifest and report drift or absence"),
        ("missing", "list absent evidence with the command that makes it"),
    ):
        parser = sub.add_parser(name, help=help_text)
        parser.add_argument("--manifest", type=Path, default=MANIFEST)

    args = ap.parse_args(argv)
    strict = os.environ.get("SNAPFUZZ_STRICT_GATE") == "1"

    if args.cmd == "record":
        manifest = build_manifest()
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(f"recorded {manifest['present']}/{manifest['total']} artifacts")
        for entry in manifest["entries"]:
            mark = "ok " if entry["present"] else "absent"
            size = f"  {entry['size_bytes'] / 1e6:.1f} MB" if entry.get("size_bytes") else ""
            print(f"  [{mark}] {entry['gate']:<5} {entry['path']}{size}")
        print(f"\nwritten to {args.manifest}")
        return 0

    if not args.manifest.exists():
        print(f"no manifest at {args.manifest}; run `python -m tools.evidence record`")
        return 1
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))

    if args.cmd == "missing":
        gaps = [e for e in manifest["entries"] if not (REPO_ROOT / e["path"]).is_file()]
        if not gaps:
            print("every recorded artifact is present")
            return 0
        print(f"{len(gaps)} of {manifest['total']} artifacts are absent:\n")
        for entry in gaps:
            print(f"  {entry['path']}  ({entry['gate']})")
            print(f"    proves: {entry['proves']}")
            print(f"    make it: {entry['regenerate']}\n")
        return 1 if strict else 0

    drifted, absent = verify_manifest(manifest)
    if drifted:
        print(f"{len(drifted)} artifact(s) CHANGED since the manifest was recorded:")
        for path in drifted:
            print(f"  ! {path}")
        print("\nA recorded gate result describes bytes that are no longer there.")
        print("Re-run the gate, then `python -m tools.evidence record`.")
    if absent:
        print(f"\n{len(absent)} artifact(s) absent:")
        for path in absent:
            print(f"  - {path}")
        print("`python -m tools.evidence missing` prints how to regenerate each.")
    if not drifted and not absent:
        print(f"all {manifest['total']} artifacts present and unchanged")
        return 0
    if drifted:
        return 1
    return 1 if strict else 0


if __name__ == "__main__":
    raise SystemExit(main())
