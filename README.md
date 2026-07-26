# snapfuzz

LLM-guided snapshot fuzzing for x86-64 binaries, with no source. Windows is the
supported path; Linux works but is rougher.

Point it at an executable. It decompiles with Ghidra, has an LLM pick the fuzz entry
and derive the input format and harness, generates a C++
[wtf](https://github.com/0vercl0k/wtf) module, takes a snapshot, fuzzes it across a
master and N workers, then dedups, replays and triages the crashes into a GHSA
advisory.

[繁體中文](README.zh-TW.md)

---

## Install

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m tools.bootstrap    # checks tools, fetches Ghidra, records paths
.\.venv\Scripts\python.exe -m fuzzer.build       # needs the VS C++ toolchain
```

`bootstrap` downloads Ghidra if it is missing (pinned version, sha256 verified) and
writes every tool path into `config/`. `--check` reports without changing anything.

```
  [  ok   ] Python packages    8 present
  [  ok   ] JDK                java 21 at C:\Program Files\Eclipse Adoptium\jdk-21...
  [  ok   ] Ghidra             D:\tools\ghidra_12.1.2_PUBLIC
  [  ok   ] wtf                D:\wtf-llm\src\build\wtf.exe
  [  ok   ] LLM API key        SNAPFUZZ_LLM_API_KEY in .env
  [  ok   ] symbolizer-rs      D:\tools\symbolizer-rs\symbolizer-rs.exe
  [  ok   ] kd.exe             C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe
  [  ok   ] 0vercl0k/snapshot  D:\tools\snapshot\snapshot.dll
  [absent ] Hyper-V guest      Hyper-V IS installed, but this shell cannot query it
                               -> run as administrator, or join 'Hyper-V Administrators'

Ready to fuzz an EXISTING snapshot. Not ready to take a new one:
  - Hyper-V guest: ...
```

The LLM key goes in `.env`, which is gitignored:

```
SNAPFUZZ_LLM_API_KEY=sk-...
```

Requirements: Python 3.11+, JDK 21+, a C++ toolchain, an OpenAI-compatible LLM
endpoint. Ghidra is not optional — the harness is derived from its pseudo-C. Taking
your own snapshots also needs Hyper-V, `kd.exe` from the Windows SDK,
[0vercl0k/snapshot](https://github.com/0vercl0k/snapshot) and a guest VM
([docs/GUEST-VM.md](docs/GUEST-VM.md)).

## Usage

With a snapshot already in `state/` (`mem.dmp`, `regs.json`):

```powershell
python -m orchestrator.pipeline `
    --binary targets\tlv_server\target\tlv_server.exe `
    --state-dir targets\tlv_server\state `
    --target-name snapfuzz --module snapfuzz `
    --workers 2 --minutes 15
```

With only the binary, snapshotting it too:

```powershell
python -m orchestrator.pipeline `
    --binary targets\tlv_server\target\tlv_server.exe `
    --state-dir targets\tlv_server\state `
    --target-name snapfuzz --module snapfuzz `
    --kd-pipe \\.\pipe\snapfuzz `
    --kd-stimulus "python -m tools.poke_tcp --port 1337 --hex 00000000 3905 0200 0102" `
    --workers 2 --minutes 15
```

`--kd-pipe` adds the acquisition stage; that is the only difference.
`--entry-symbol` is optional — the LLM picks the entry in stage 03.

Output:

```
target    : snapfuzz (D:\wtf-llm\targets\snapfuzz)
binary    : D:\wtf-llm\targets\tlv_server\target\tlv_server.exe
entry     : (late-bound from stage 03)
module    : snapfuzz   scope: module
campaign  : 2 worker(s), 15 min
prerequisites: ok

==========================================================================
[1/13] 01-pseudoc: Ghidra: decompile at MODULE scope -> A2 dump
==========================================================================
  $ prep.ghidra_headless --what pseudoc --binary ... --scope module
  OK in 41s
...
==========================================================================
PIPELINE SUMMARY
==========================================================================
  ran                    41s  01-pseudoc: Ghidra: decompile at MODULE scope -> A2 dump
  ran                     2s  02-a2: A2 dump -> SQLite cache
  ...
  ran                    96s  13-triage: LLM: five-signal triage -> GHSA advisory

  13 ran, 0 skipped, 0 blocked, 0 failed, of 13 stage(s)
  all stages accounted for
```

### Flags

| Flag | Effect |
|---|---|
| `--list` | list the stages and exit |
| `--dry-run` | print the plan, run nothing |
| `--only 03 08` | run only these stages |
| `--from 10` | start here |
| `--force` | re-run stages that are up to date |
| `--scope function-closure` | narrow analysis to the entry's call closure |
| `--workers N` | worker count |
| `--minutes N` | campaign length |

### Stages

```
01-pseudoc    Ghidra: decompile at module scope       -> A2
02-a2         A2 -> SQLite cache
03-entry      LLM: choose the fuzz entry              -> FuzzEntry
04-blocks     Ghidra: enumerate basic blocks          -> A3
05-covfile    A3 -> wtf .cov breakpoint file
06-datasyms   Ghidra: global data symbols             -> A6
07a-acquire   drive KD to take the snapshot           (only with --kd-pipe)
07-snapshot   ingest state/                           -> A1
08-inputspec  LLM: derive the input structure         -> InputSpec
09-codegen    InputSpec -> C++ (no LLM)
10-build      build wtf + the module
11-fuzz       campaign: master + workers + slow clock
12-analysis   dedup, classify, replay, trace (no LLM)
13-triage     LLM: five-signal triage                 -> advisory.md
```

Each stage names an artifact it must produce, and that artifact is what counts as
done — `analyzeHeadless` and `wtf` both exit 0 having written nothing. Stages whose
work is time rather than a file are never skipped because an old output exists.

Stages also run standalone: [docs/STAGES.md](docs/STAGES.md).

## Linux targets

The Ghidra and analysis halves are OS-agnostic and ELF input works. Snapshotting is
the hard part: wtf's Linux mode is GDB against a full-system QEMU VM, not a user-mode
process.

```bash
# in the guest, first
sysctl -w kernel.randomize_va_space=0
```

Then follow wtf's `linux_mode/` procedure (`qemu_snapshot/setup.sh`, `gdb_server.sh`,
`gdb_client.sh`, a `bkpt.py` deriving from `gdb_fuzzbkpt.py`, then `cpu` in GDB) and
ingest by hand:

```bash
python -m prep.snapshot_linux ingest --state targets/mytarget/state \
    --module mytarget --module-base 0x555555554000 --ghidra-image-base 0x100000 \
    --entry-runtime-addr 0x5555555551a9 --randomize-va-space 0 \
    --out artifacts/a1_snapshot.json
```

Ingest refuses unless ASLR is off — with it on, `module_base` differs between snapshot
and replay and address translation quietly produces garbage. `state/symbol-store.json`
is required on Linux and cannot be generated there; carry it over from a Windows run.
The pipeline's snapshot stage is Windows-only, so run stage 07 yourself and use
`--from 08`. `python -m prep.snapshot_linux notes` prints the procedure.

## How it works

```
binary ──┬─> Ghidra ──> A2 pseudo-C ──> [LLM] entry, input format, harness
         │              A3 basic blocks ──> coverage breakpoints
         │              A6 global symbols
         └─> KD + !snapshot ──> A1 snapshot

               ┌─────────── fast clock ───────────┐   ┌─── slow clock ───┐
               │ wtf master  ──>  N wtf workers   │   │ sidecar process  │
               │ owns corpus      execute + report│<──│ plateau -> seeds │
               └──────────────────────────────────┘   └──────────────────┘

crashes ──> dedup ──> classify ──> replay ──> trace ──┐
                                    A2 pseudo-C ──────┴──> [LLM] triage ──> GHSA
```

- No LLM anywhere in the fast clock, including the master — it serves every worker, so
  one call there stalls the pool. The slow clock is a separate process that watches
  aggregate coverage and drops seeds into a spool the master's mutator drains without
  blocking. A gate test greps for the LLM client in fast-loop modules.
- The LLM fills pydantic-validated schemas (`InputSpec`, `HarnessSpec`);
  `fuzzer/codegen.py` renders the C++.
- Triage takes five independent signals: dedup bucket, fault classification,
  deterministic replay, symbolized trace, pseudo-C. The last two stay separate — one
  says what ran, the other what the code is.

## Results

`tlv_server`, same snapshot, same single poor seed, empty corpus, bochscpu, 2 workers,
5 minutes per arm:

| Arm | Executions | exec/s | Corpus | Bugs | Coverage | Execs/bug |
|---|---|---|---|---|---|---|
| baseline-libfuzzer | 2,269,008 | 7,914 | 28 | 2 | 9,686 | 1,134,504 |
| baseline-honggfuzz | 5,927,672 | 22,954 | 2 | 1 | 9,549 | 5,927,672 |
| snapfuzz | 64,736 | 746 | 41 | 4 | 12,781 | 16,184 |
| ablation: no seed gen | 80,161 | 738 | 35 | 4 | 12,761 | 20,040 |
| ablation: no pseudo-C | 101,788 | 862 | 36 | 3 | 12,751 | 33,929 |

70× fewer executions per bug than libFuzzer and 366× fewer than honggfuzz, at a tenth
to a thirtieth of the throughput. LLM seed generation is not supported by this data:
4 buckets against the no-seedgen ablation's 4.

Dedup collapsed 53 crash files with 52 distinct fault addresses into 4 buckets, all
four reproducing deterministically. Caveats and full numbers:
[docs/RESULTS.md](docs/RESULTS.md).

## Layout

```
arch/          pydantic contracts · graph.yaml (edge list) · address conversion
config/        llm.yaml (role -> model) · fuzz.yaml · target.yaml
tools/         bootstrap.py · poke_tcp.py
prep/          Ghidra headless · A2 cache · A3/A6 · entry_select · input_struct
               harness_derive · snapshot_win · snapshot_linux
fuzzer/        module/ (C++) · codegen · build · master · workers · corpus
engine_bridge/ coverage · plateau · crash_watch
llm/           client (role routing) · sidecar (slow clock) · seed_gen · spool
analysis/      dedup · classify · replay · trace · reverse · triage · report
orchestrator/  pipeline (the stage driver) · scheduler (master + workers + sidecar)
eval/          baseline (5 arms) · triage_eval · plot_curves
tests/gates/   one executable gate per checkpoint
```

## Tests

```powershell
python -m pytest tests\gates -q
```

```
424 passed, 12 skipped
```

The skips are live-endpoint tests behind `SNAPFUZZ_LIVE_LLM`, `SNAPFUZZ_LIVE_MCP` and
`SNAPFUZZ_LIVE_CP4B`.

## Credits

Built on [wtf](https://github.com/0vercl0k/wtf) by Axel Souchet, with
[0vercl0k/snapshot](https://github.com/0vercl0k/snapshot),
[symbolizer-rs](https://github.com/0vercl0k/symbolizer-rs),
[Ghidra](https://github.com/NationalSecurityAgency/ghidra) and
[GhidraMCP](https://github.com/LaurieWired/GhidraMCP). wtf's own README is at
[docs/README.wtf-upstream.md](docs/README.wtf-upstream.md).

Design notes: [CLAUDE.md](CLAUDE.md), [docs/DECISIONS.md](docs/DECISIONS.md),
[docs/DEVIATIONS.md](docs/DEVIATIONS.md).
