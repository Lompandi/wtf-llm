# ENVIRONMENT

Everything installed, with versions (CLAUDE.md section 4). Also the state of
things that are **not** installed yet, because those are what block the next
checkpoints.

Surveyed 2026-07-25 on the development host.

## Host

| | |
|---|---|
| OS | Microsoft Windows 11 家用版 (Home), build 10.0.26200.0 |
| Arch | x86-64 |
| Repo | `d:\wtf-llm` — this **is** the wtf clone (DEVIATIONS D-000) |
| Upstream | `github.com/Lompandi/wtf-llm`, a fork of `0vercl0k/wtf` |
| Commit | `a490929` |

## Present

| Tool | Version | Path / note |
|---|---|---|
| git | 2.47.0.windows.2 | `C:\Program Files\Git\cmd\git.exe` |
| Visual Studio 2022 Community | 17.14.24 | `...\2022\Community` — has the C++ x64 toolset (MSVC 14.44.35207) but **no CMake component** |
| **Visual Studio 18 Community** | — | `...\18\Community` — **this is the one that builds wtf**; MSVC 14.51.36231, Windows SDK 10.0.26100 |
| cmake | 4.3.1-msvc1 | bundled with VS 18: `...\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe` |
| ninja | 1.13.2 | bundled with VS 18, alongside cmake |
| Python | **3.12.10** | installed 2026-07-25 via `winget install Python.Python.3.12`; the interpreter of record (DECISIONS DEC-006) |
| Python | 3.10.9, 3.8 | also installed; unused |
| 7-Zip | 26.02 | installed 2026-07-25 via winget; `C:\Program Files\7-Zip\7z.exe` (not on PATH — call by full path) |
| JDK (Temurin) | 21.0.6.7 | `C:\Program Files\Eclipse Adoptium\jdk-21.0.6.7-hotspot` — satisfies Ghidra 12.1.2 |
| Ghidra | 12.1.2 PUBLIC | `D:\tools\ghidra_12.1.2_PUBLIC`; set `GHIDRA_INSTALL_DIR` |
| winget | present | available for the installs below |

### wtf's vendored dependencies — all present, no submodule init needed

`git submodule status` prints nothing: `src/libs/` is vendored in-tree, not
submodules. All nine are populated: `BLAKE3`, `bochscpu-bins`, `CLI11`, `fmt`,
`json`, `kdmp-parser`, `libfuzzer`, `robin-map`, `yas`.

`src/libs/bochscpu-bins/lib/bochscpu_ffi.lib` (28 MB, Windows) is present, so
the bochscpu backend is buildable without building bochscpu from source.

### Project virtualenv

`.venv/` at the repo root, created from **Python 3.12.10**, satisfying section
4's 3.11+ requirement.

Note the `python` on PATH belongs to an unrelated project
(`PycharmProjects\RLtest\.venv`, Python 3.10) and must never be installed into.
**Always use `.venv\Scripts\python.exe` explicitly**; do not rely on PATH.

Installed for CP0 (`requirements.txt`): `pydantic` 2.13.4, `pyyaml` 6.0.3,
`pytest` 9.1.1. The rest of section 4's list is installed at the checkpoint
that first needs it.

### Target archives — extracted

Both wtf release targets are unpacked under `targets/` (gitignored; ~3.4 GB):

| Target | Snapshot | Notes |
|---|---|---|
| `targets/tlv_server` | `state/mem.dmp` 1.81 GB | **user-mode**; ships a real `.cov` (530 blocks), `interesting/` labelled bugs, and the exact CLI scripts — see DEVIATIONS D-013/D-014/D-015 |
| `targets/hevd` | `state/mem.dmp` 1.58 GB | kernel driver; also ships an `outputs/` corpus and `rip-traces/` |

Downloaded from wtf release **v0.5.7** (`target-tlv_server.7z` 257.5 MB,
`target-hevd.7z` 237.7 MB). Note this clone is at `a490929`, which is *newer*
than v0.5.7; the snapshot format is not expected to have changed, but if CP1
misbehaves this is the first thing to suspect.

### wtf — built

`src/build/wtf.exe`, 6.6 MB, built 2026-07-25 in **16 s** (41 ninja targets).
Also produced: `tlv_server.exe`, `hevd_client.exe`, `libs/kdmp-parser/.../parser.exe`.

Two obstacles, both recorded so `fuzzer/build.py` (CP4) reproduces the fix:

1. The "C++ CMake tools for Windows" component installed into **VS 18**, not
   VS 2022. Both instances have the C++ x64 toolset; only VS 18 has
   cmake/ninja, so VS 18 is the build toolchain of record.
2. `vcvars64.bat` **fails on this host** because the machine `PATH` contains an
   entry with a stray double quote (DEVIATIONS D-020). The build wrapper strips
   quotes from `PATH` in its own process first. Without that, every MSVC build
   here dies with `\VMware\VMware was unexpected at this time.`

Build recipe:

```powershell
$env:Path = ($env:Path -split ';' | % { $_.Trim().Trim('"') } | ? { $_ }) -join ';'
cmd /c 'call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" && cd /d d:\wtf-llm\src\build && cmake .. -GNinja -DCMAKE_BUILD_TYPE=RelWithDebInfo && cmake --build .'
```

cmake 4.x removed compatibility with `cmake_minimum_required` below 3.5. The
only two `CMakeLists.txt` actually processed are `src/` (3.16) and
`libs/kdmp-parser/` (3.21) — the other vendored libs are `include_directories`
only — so cmake 4.3.1 is fine.

### `_NT_SYMBOL_PATH` — required, and wtf does not set it

wtf resolves breakpoints by **symbol name** on Windows through dbgeng, but sets
no symbol path of its own (DEVIATIONS D-023). Without this, a fuzzer module
fails in `Init` with `Could not set a breakpoint at ...` and the worker exits.

```powershell
$env:_NT_SYMBOL_PATH = "srv*C:\symbols*https://msdl.microsoft.com/download/symbols;<target>\target"
```

Both halves are needed: the local directory supplies the target's own PDB
(shipped in the archive), the symbol server supplies the guest build's
`ntoskrnl.pdb` for `nt!*` breakpoints. `C:\symbols` is created on first use and
caches downloads — the first run cost 373 s, later runs seconds.

This must be set for **every worker process**, not just interactively: a worker
that cannot resolve its breakpoints dies at `Init` and contributes nothing
while the master keeps waiting for it.

### Ghidra 12.1.2 — installed

`D:\tools\ghidra_12.1.2_PUBLIC` (546 MB zip, ~914 MB extracted), from the
`Ghidra_12.1.2_build` release. Runs on the already-present Temurin JDK 21.

Point tooling at it with Ghidra's own convention:

```powershell
$env:GHIDRA_INSTALL_DIR = 'D:\tools\ghidra_12.1.2_PUBLIC'
```

`prep/ghidra_headless.py` reads that variable (or takes `--ghidra`). Headless
analysis of `tlv_server.exe` takes ~20 s, and picks up the shipped PDB
automatically, so functions carry real names.

Two things about this version that shape CP2, both in DEVIATIONS:

- **D-025** — Jython is now an optional extension and `.py` post-scripts are
  routed to PyGhidra, which `analyzeHeadless` cannot start. Our post-script is
  therefore Java (DEC-012). wtf's own `gen_coveragefile_ghidra.py` will not run
  here.
- **D-026** — `analyzeHeadless` exits **0 even when the post-script throws**.
  The output artifact is the only trustworthy success signal.

`analyzeHeadless.bat` is a batch file, so it needs the same `PATH`
quote-stripping as the MSVC build (D-020); `prep/ghidra_headless.py` does this
itself.

## Missing — and what each one blocks

### 1. `0vercl0k/snapshot` KD extension — blocks GATE 3

DEVIATIONS D-007: snapshots are taken by a **separate** project's `snapshot.dll`
loaded into KD, not by any script in this repo. Also needs Debugging Tools for
Windows (WinDbg/KD) and a Windows VM to snapshot.

### 2. `symbolizer-rs` — blocks GATE 4 and GATE 8

`0vercl0k/symbolizer-rs`, a **companion tool, not wtf** (section 3.1). Raw wtf
traces load into neither lighthouse nor Tenet without it, and it is needed
twice:

- **GATE 4, mandatory harness validation.** CP4 will not be done until a
  symbolized `rip` trace visibly proves execution reaches
  `FuzzEntry.static_addr`. A harness that runs and reports coverage but never
  enters the parser is the classic silent failure here.
- **GATE 8, triage signal 4.** The dynamic signal, and per section 13.3 the
  main compensation for having no ASAN — it is what lets the analysis walk
  backwards from a fault to where a bad pointer or length originated.

Recorded in `config/fuzz.yaml` as `tools.symbolizer_rs: null`.

### 3. Windows Hypervisor Platform — needed for GATE 4b

DECISIONS DEC-005 pins the scaled fuzzing run to the whv backend, because it is
the only backend on this host that actually consumes the CP2 coverage file.
`Get-WindowsOptionalFeature -FeatureName HypervisorPlatform` requires
administrator rights and has **not** been checked. Confirm before CP4b; CP1–CP4
all run on bochscpu with a single worker.

Note `kvm` is Linux-only, so on this host the worker backend choices are
`bochscpu` (deterministic, slow) and `whv`.

### 4. LLM endpoint details — blocks GATE 5

`config/llm.yaml` has `base_url: null` and every model string marked
`TODO(CP5)`. Section 7.1 requires reading
`https://github.com/chunying/ais3-ai-infra/` and recording base URL, auth
scheme, exact model names, context limits, rate limits and streaming support
here. Deliberately not guessed.

### 5. GhidraMCP — CP6, deliberately not yet

CLAUDE.md section 4 is explicit: install at CP6, not before.

## Reproducing the CP0 environment

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m pytest tests\ -q
```

Two of the address tests are skipped unless `targets/tlv_server` is extracted;
see "Target archives" above. They cross-check section 9's conversions against
wtf's own shipped files, so they are worth having present.
