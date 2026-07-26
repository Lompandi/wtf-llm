"""One command that makes this repo runnable: check every tool, fetch what it can.

Why this exists. Ghidra is not optional any more. It used to supply only coverage
breakpoints (A3), which a determined person could hand-write; it now supplies the
pseudo-C that the model reads to derive the **input structure** and the **harness**
-- so without Ghidra there is no `InsertTestcase`, and the fuzzer has nothing to
run. That moved it from "a prerequisite" to "the thing the project is built on", and
a prerequisite that important should not be a paragraph in a README that everyone
configures slightly differently.

The pattern this replaces is worth naming, because it happened three separate times
in this project: a tool was installed, nothing wrote its path down, and every
consumer reported it missing (D-050 -- symbolizer-rs, then the snapshot extension,
then Ghidra itself). The fix each time was the same one line of config. So this
script's real job is not downloading; it is **recording**, and it reports which of
the two it did.

What it does NOT do: install a hypervisor, create a guest VM, or install the
Windows SDK. Those need administrator rights and reboots, so they are reported with
the exact command to run instead of being attempted. `--vm-check` prints what is
missing for snapshot acquisition specifically.

Usage:

    python -m tools.bootstrap              # check, fetch Ghidra if absent, record
    python -m tools.bootstrap --check      # report only, change nothing
    python -m tools.bootstrap --vm-check   # only the snapshot-acquisition chain
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
THIRD_PARTY = REPO_ROOT / "third_party"

# Pinned rather than "latest". A Ghidra upgrade changes decompiler output, which
# changes the pseudo-C the model reads, which changes the derived harness -- so an
# unpinned fetch would make two checkouts of the same commit produce different
# fuzzers. Raise it deliberately, and re-run the CP6 gate when you do.
GHIDRA_VERSION = "12.1.2"
GHIDRA_API = (
    "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags/"
    "Ghidra_{version}_build"
)
# Ghidra 12 requires JDK 21+. Below that analyzeHeadless fails with a class-version
# error that reads like a corrupt install.
MIN_JDK = 21


@dataclass
class Finding:
    """One tool: what we found, and what to do about it."""

    name: str
    ok: bool
    detail: str
    fix: str = ""
    # Whether the pipeline can run at all without it. Acquisition tools are not
    # required: a state/ directory produced elsewhere is the common case.
    required: bool = True


# --- config, read and written in place -----------------------------------
#
# Rewritten by line rather than by round-tripping through yaml.safe_load, because a
# dump would strip every comment in these files and the comments are where the
# reasons live.


def _read_yaml(path: Path) -> dict:
    import yaml

    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _set_scalar(path: Path, section: str, key: str, value: str) -> bool:
    """Set ``section: {key: value}`` in a YAML file, preserving comments.

    Returns True if the file changed. Only handles a two-level scalar, which is all
    this script needs; anything more would want a real round-tripping parser.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    in_section = False
    for i, line in enumerate(lines):
        if line.startswith(f"{section}:"):
            in_section = True
            continue
        if in_section and line and not line[0].isspace():
            break  # left the section without finding the key
        if in_section and line.strip().startswith(f"{key}:"):
            indent = line[: len(line) - len(line.lstrip())]
            new = f"{indent}{key}: {value}"
            if lines[i] == new:
                return False
            lines[i] = new
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return True
    raise KeyError(f"{path.name} has no {section}.{key} to set")


# --- Ghidra ---------------------------------------------------------------


def _ghidra_root_of(directory: Path) -> Path | None:
    """A Ghidra install under ``directory``, or None.

    An install is identified by ``support/analyzeHeadless``, not by the directory
    name: the name carries a build date that nobody types correctly.
    """
    if not directory.is_dir():
        return None
    candidates = [directory, *sorted(directory.glob("ghidra_*"))]
    for candidate in candidates:
        for script in ("analyzeHeadless.bat", "analyzeHeadless"):
            if (candidate / "support" / script).exists():
                return candidate
    return None


def _release_asset(version: str) -> tuple[str, str, int]:
    """(url, sha256, size) of the PUBLIC zip for ``version``."""
    request = urllib.request.Request(
        GHIDRA_API.format(version=version),
        headers={"Accept": "application/vnd.github+json", "User-Agent": "snapfuzz"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        release = json.load(response)
    assets = [
        a
        for a in release.get("assets", [])
        if a["name"].startswith("ghidra_") and a["name"].endswith("_PUBLIC.zip")
        or (a["name"].startswith("ghidra_") and "_PUBLIC_" in a["name"] and a["name"].endswith(".zip"))
    ]
    if len(assets) != 1:
        raise RuntimeError(
            f"expected one PUBLIC zip in Ghidra_{version}_build, found "
            f"{[a['name'] for a in assets]}"
        )
    asset = assets[0]
    digest = (asset.get("digest") or "").removeprefix("sha256:")
    return asset["browser_download_url"], digest, asset["size"]


def fetch_ghidra(version: str = GHIDRA_VERSION, *, dest: Path = THIRD_PARTY) -> Path:
    """Download and extract Ghidra into ``dest``. Returns the install root.

    The download is ~550 MB. It is fetched rather than committed: vendoring it would
    put 550 MB into every clone of this repo, for a file that is byte-identical for
    everyone and already hosted. The **digest is verified** -- an interrupted
    download extracts partially and then fails much later inside analyzeHeadless.
    """
    url, sha256, size = _release_asset(version)
    dest.mkdir(parents=True, exist_ok=True)
    archive = dest / url.rsplit("/", 1)[-1]

    if not (archive.exists() and archive.stat().st_size == size):
        print(f"  downloading {url}")
        print(f"  {size / 1e6:.0f} MB -> {archive}")
        # To a temp name first: a half-written file with the right name is
        # indistinguishable from a complete one on the next run.
        partial = archive.with_suffix(".part")
        with urllib.request.urlopen(url, timeout=120) as response, partial.open("wb") as out:
            copied = 0
            while chunk := response.read(1 << 20):
                out.write(chunk)
                copied += len(chunk)
                print(f"\r  {copied / 1e6:6.0f} / {size / 1e6:.0f} MB", end="", flush=True)
        print()
        partial.replace(archive)

    if sha256:
        digest = hashlib.sha256()
        with archive.open("rb") as handle:
            while chunk := handle.read(1 << 20):
                digest.update(chunk)
        if digest.hexdigest() != sha256:
            archive.unlink()
            raise RuntimeError(
                f"{archive.name} failed its digest check (removed). Re-run to retry."
            )
        print(f"  sha256 ok: {sha256[:16]}...")

    print(f"  extracting into {dest}")
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(dest)

    root = _ghidra_root_of(dest)
    if root is None:
        raise RuntimeError(f"{archive.name} extracted but no analyzeHeadless found under {dest}")

    # The unix scripts lose their execute bit through the zip on Windows. Harmless
    # here, fatal if the same third_party/ tree is used from WSL.
    for script in (root / "support").glob("*"):
        if script.is_file() and not script.suffix:
            script.chmod(script.stat().st_mode | 0o111)
    return root


def check_ghidra(*, fetch: bool) -> Finding:
    target_yaml = REPO_ROOT / "config" / "target.yaml"
    configured = (_read_yaml(target_yaml).get("ghidra") or {}).get("install_dir")

    root = None
    if configured and _ghidra_root_of(Path(configured)):
        root = Path(configured)
    elif env := os.environ.get("GHIDRA_INSTALL_DIR"):
        root = _ghidra_root_of(Path(env))
    if root is None:
        root = _ghidra_root_of(THIRD_PARTY)

    if root is None and fetch:
        print("Ghidra: not found, fetching")
        try:
            root = fetch_ghidra()
        except Exception as exc:
            return Finding(
                "Ghidra",
                False,
                f"not installed and the fetch failed: {exc}",
                fix="python -m tools.bootstrap  (or install manually and set "
                "ghidra.install_dir in config/target.yaml)",
            )

    if root is None:
        return Finding(
            "Ghidra",
            False,
            "not installed -- MANDATORY: the harness is derived from its pseudo-C",
            fix="python -m tools.bootstrap",
        )

    recorded = configured and Path(configured) == root
    if not recorded:
        _set_scalar(target_yaml, "ghidra", "install_dir", str(root))
        return Finding("Ghidra", True, f"{root} (recorded in config/target.yaml)")
    return Finding("Ghidra", True, str(root))


# --- everything else ------------------------------------------------------


def check_jdk() -> Finding:
    java = shutil.which("java")
    if java is None:
        return Finding(
            "JDK", False, f"no java on PATH; Ghidra needs JDK {MIN_JDK}+",
            fix="install Temurin JDK 21: winget install EclipseAdoptium.Temurin.21.JDK",
        )
    proc = subprocess.run(
        [java, "-version"], capture_output=True, text=True, errors="replace"
    )
    text = (proc.stderr or proc.stdout or "").strip()
    major = 0
    for token in text.replace('"', " ").split():
        head = token.split(".")[0]
        if head.isdigit():
            major = int(head)
            break
    if major and major < MIN_JDK:
        return Finding(
            "JDK", False, f"java {major} is too old; analyzeHeadless needs {MIN_JDK}+",
            fix="winget install EclipseAdoptium.Temurin.21.JDK",
        )
    return Finding("JDK", True, f"java {major or '?'} at {java}")


def check_python_deps() -> Finding:
    needed = [
        ("pydantic", "pydantic"), ("yaml", "pyyaml"), ("httpx", "httpx"),
        ("dspy", "dspy"), ("pytest", "pytest"), ("loguru", "loguru"),
        ("jinja2", "jinja2"), ("capstone", "capstone"),
    ]
    missing = []
    for module, package in needed:
        try:
            __import__(module)
        except ImportError:
            missing.append(package)
    if missing:
        return Finding(
            "Python packages", False, f"missing {', '.join(missing)}",
            fix=".venv\\Scripts\\pip install -r requirements.txt",
        )
    return Finding("Python packages", True, f"{len(needed)} present")


def check_wtf() -> Finding:
    exe = REPO_ROOT / "src" / "build" / "wtf.exe"
    if exe.exists():
        return Finding("wtf", True, str(exe))
    return Finding(
        "wtf", False, "not built",
        fix="python -m fuzzer.build   (needs a VS Developer Command Prompt)",
    )


def _recorded_tool(key: str, label: str, *, required: bool, fix: str) -> Finding:
    fuzz_yaml = REPO_ROOT / "config" / "fuzz.yaml"
    configured = (_read_yaml(fuzz_yaml).get("tools") or {}).get(key)
    if configured and Path(configured).exists():
        return Finding(label, True, str(configured), required=required)
    if configured:
        return Finding(
            label, False, f"config names {configured}, which does not exist",
            fix=f"fix tools.{key} in config/fuzz.yaml", required=required,
        )
    found = shutil.which(key.replace("_", "-")) or shutil.which(key)
    if found:
        _set_scalar(fuzz_yaml, "tools", key, found)
        return Finding(label, True, f"{found} (recorded in config/fuzz.yaml)", required=required)
    return Finding(label, False, "not found", fix=fix, required=required)


def check_api_key() -> Finding:
    """Report which PROVIDERS are usable, not whether one variable is set.

    Any provider's key is enough -- the client uses whichever resolves, in config
    order. Reporting a single hardcoded variable would tell someone with an
    Anthropic key that they have no LLM access, which is the same
    working-tool-reported-missing shape as D-050.
    """
    config = _read_yaml(REPO_ROOT / "config" / "llm.yaml")
    providers = config.get("providers") or {}
    if not providers:
        return Finding(
            "LLM provider", False,
            "config/llm.yaml declares no providers",
            fix="restore the `providers` block; see llm/client.py",
        )

    dotenv = REPO_ROOT / ".env"
    dotenv_text = dotenv.read_text(encoding="utf-8-sig") if dotenv.exists() else ""
    dotenv_keys = {
        line.split("=", 1)[0].strip()
        for line in dotenv_text.splitlines()
        if line.strip() and not line.strip().startswith("#") and "=" in line
    }

    usable: list[str] = []
    wanted: list[str] = []
    for name, provider in providers.items():
        var = (provider or {}).get("api_key_env")
        if not var:
            continue
        wanted.append(var)
        if os.environ.get(var) or var in dotenv_keys:
            usable.append(f"{name} ({var})")

    if usable:
        # The FIRST one is what will actually run, so name it rather than listing
        # a set and leaving the reader to guess the precedence.
        detail = f"{usable[0]} -- active"
        if len(usable) > 1:
            detail += f"; also configured: {', '.join(usable[1:])}"
        return Finding("LLM provider", True, detail)

    return Finding(
        "LLM provider", False,
        f"no key for any provider ({', '.join(wanted)})",
        fix=f"echo {wanted[0]}=sk-... >> .env     (.env is gitignored; never put "
        f"the key in config/llm.yaml -- a gate test fails if you do)",
    )


def check_hypervisor() -> Finding:
    """Snapshot acquisition needs a guest. Not required to fuzz an existing one."""
    if os.name != "nt":
        return Finding("Hyper-V guest", False, "not a Windows host", required=False)
    # Three distinguishable states, and conflating them sends people to fix the
    # wrong thing. The first version of this check printed "Hyper-V is not
    # available" on a host where Hyper-V was installed and working -- `Get-VM`
    # existed but returned a PERMISSION error, and the advice was to re-enable a
    # feature that was already on. That is the D-050 pattern once more: a working
    # tool reported as missing.
    script = (
        "if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) "
        "{ 'ABSENT'; exit }\n"
        "try { 'COUNT=' + (Get-VM -ErrorAction Stop | Measure-Object).Count } "
        "catch { 'DENIED=' + $_.Exception.Message }"
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=90, errors="replace",
        )
    except Exception as exc:
        return Finding("Hyper-V guest", False, f"could not query: {exc}", required=False)

    out = (proc.stdout or "").strip()
    if "ABSENT" in out:
        return Finding(
            "Hyper-V guest", False, "Hyper-V is not installed",
            fix="Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All"
            "  (as admin, then reboot)",
            required=False,
        )
    if "DENIED" in out:
        return Finding(
            "Hyper-V guest", False,
            "Hyper-V IS installed, but this shell cannot query it (permission "
            "denied) -- so whether a guest exists is unknown from here",
            fix="run as administrator, or add your account to the local "
            "'Hyper-V Administrators' group and sign in again",
            required=False,
        )
    count = next(
        (int(t) for t in out.replace("COUNT=", " ").split() if t.strip().isdigit()), 0
    )
    if count == 0:
        return Finding(
            "Hyper-V guest", False,
            "Hyper-V is enabled but there are no VMs -- acquisition needs a Windows "
            "guest with ONE vCPU, 4 GB RAM, kernel debugging on, COM1 on a named pipe",
            fix="see README, 'Preparing a guest VM'",
            required=False,
        )
    return Finding("Hyper-V guest", True, f"{count} VM(s) defined", required=False)


# --- driver ---------------------------------------------------------------


def run(*, fetch: bool, vm_only: bool) -> list[Finding]:
    if vm_only:
        return [
            check_hypervisor(),
            _recorded_tool("kd_exe", "kd.exe", required=False,
                           fix="install Debugging Tools for Windows (Windows SDK)"),
            _recorded_tool("snapshot_dll", "0vercl0k/snapshot", required=False,
                           fix="build 0vercl0k/snapshot and set tools.snapshot_dll"),
        ]
    return [
        check_python_deps(),
        check_jdk(),
        check_ghidra(fetch=fetch),
        check_wtf(),
        check_api_key(),
        _recorded_tool("symbolizer_rs", "symbolizer-rs", required=False,
                       fix="cargo install --git https://github.com/0vercl0k/symbolizer-rs"),
        _recorded_tool("kd_exe", "kd.exe", required=False,
                       fix="install Debugging Tools for Windows (Windows SDK)"),
        _recorded_tool("snapshot_dll", "0vercl0k/snapshot", required=False,
                       fix="build 0vercl0k/snapshot and set tools.snapshot_dll"),
        check_hypervisor(),
    ]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="report only, fetch nothing")
    ap.add_argument("--vm-check", action="store_true",
                    help="only the snapshot-acquisition chain")
    args = ap.parse_args(argv)

    findings = run(fetch=not args.check, vm_only=args.vm_check)

    width = max(len(f.name) for f in findings)
    print()
    for f in findings:
        mark = "ok" if f.ok else ("MISSING" if f.required else "absent")
        print(f"  [{mark:^7}] {f.name.ljust(width)}  {f.detail}")
        if not f.ok and f.fix:
            print(f"  {' ' * 9} {' ' * width}  -> {f.fix}")
    print()

    blocking = [f for f in findings if not f.ok and f.required]
    optional = [f for f in findings if not f.ok and not f.required]

    if blocking:
        print(f"{len(blocking)} required item(s) missing: the pipeline cannot run.")
        return 1

    if optional:
        # Distinguished deliberately: a campaign against an existing snapshot needs
        # none of these, so calling them failures would send people installing an
        # SDK they do not need.
        print("Ready to fuzz an EXISTING snapshot. Not ready to take a new one:")
        for f in optional:
            print(f"  - {f.name}: {f.detail}")
        return 0

    print("Ready, including snapshot acquisition.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
