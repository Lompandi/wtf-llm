# snapfuzz

LLM-guided snapshot fuzzing for x86-64 binaries, no source needed. Windows PE and
Linux ELF.

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
.\.venv\Scripts\python.exe -m tools.bootstrap
.\.venv\Scripts\python.exe -m fuzzer.build
```

`bootstrap` fetches Ghidra if it is missing and writes every tool path into `config/`.
`--check` reports without changing anything.

```
  [  ok   ] Python packages    8 present
  [  ok   ] JDK                java 21 at C:\Program Files\Eclipse Adoptium\jdk-21...
  [  ok   ] Ghidra             D:\tools\ghidra_12.1.2_PUBLIC
  [  ok   ] wtf                D:\wtf-llm\src\build\wtf.exe
  [  ok   ] LLM provider       nchc (SNAPFUZZ_LLM_API_KEY) -- active
  [  ok   ] symbolizer-rs      D:\tools\symbolizer-rs\symbolizer-rs.exe
  [  ok   ] kd.exe             C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe
  [  ok   ] 0vercl0k/snapshot  D:\tools\snapshot\snapshot.dll
  [absent ] Hyper-V guest      Hyper-V IS installed, but this shell cannot query it
                               -> run as administrator, or join 'Hyper-V Administrators'
```

The LLM key goes in `.env`. **Whichever provider's key you set is the one that runs** —
Claude, OpenAI, or any OpenAI-compatible endpoint:

```
ANTHROPIC_API_KEY=sk-ant-...      # Claude, via the official SDK
OPENAI_API_KEY=sk-...             # OpenAI
SNAPFUZZ_LLM_API_KEY=sk-...       # any OpenAI-compatible endpoint
```

With more than one set, the order in `config/llm.yaml` decides; override with
`SNAPFUZZ_LLM_PROVIDER=anthropic`. Each role maps a model per provider there.

Needs Python 3.11+, JDK 21+, a C++ toolchain, Ghidra, and one provider key. Taking your own snapshots also needs Hyper-V, `kd.exe` from the Windows SDK,
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

`--entry-symbol` is optional; the LLM picks the entry in stage 03.

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

Results land in `targets/<name>/` and `artifacts/runs/<label>-triage/advisory.md`.

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
| `--kd-pipe`, `--kd-stimulus`, `--wow64` | snapshot acquisition |

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

Each stage runs standalone too: [docs/STAGES.md](docs/STAGES.md).

## Linux binaries

ELF targets work. The snapshot comes from wtf's own `linux_mode/` scripts (QEMU + GDB,
user-mode ELF snapshotting) rather than the KD path above, and it needs a Linux host
with KVM. Build the guest once:

```bash
cd linux_mode/qemu_snapshot && ./setup.sh     # builds QEMU, a kernel and a disk image
```

Then check the host and prepare the snapshot:

```bash
python -m prep.snapshot_linux check-host

python -m prep.snapshot_linux prepare \
    --target-name mytarget --binary ./mytarget --break-at parse_packet \
    --stimulus '/root/mytarget &'
```

`prepare` does the mechanical work — writes the `bkpt.py` gdb sources, puts the ELF
where `nm` and `readelf` will find it, clears stale state, refuses to overwrite an
existing snapshot — and prints the remaining steps in order, including the one that
**cannot** be automated: mid-snapshot, gdb asks you to press Ctrl+C in the QEMU tab
and run `cpu`, and only that writes `regs.json`. `--dry-run` shows the plan without
touching anything.

Unlike the Windows path, no amount of scripting removes that step: `cpu` lives in the
server gdb and nothing stops it on its own. When the three artifacts exist:

```bash
python -m prep.snapshot_linux verify --target-name mytarget
```

```bash
python -m prep.snapshot_linux ingest --state targets/mytarget/state \
    --module mytarget --module-base 0x555555554000 --ghidra-image-base 0x100000 \
    --entry-runtime-addr 0x5555555551a9 --randomize-va-space 0 \
    --out artifacts/a1_snapshot.json

python -m orchestrator.pipeline --binary ./mytarget \
    --state-dir targets/mytarget/state --target-name mytarget \
    --from 08 --workers 2 --minutes 15
```

Two things to know. Ingest refuses unless ASLR is off — with it on, `module_base` is one
sample of a moving value and every address conversion built on it is quietly wrong, so
set `kernel.randomize_va_space=0` in the guest. And the pipeline's stage 07 is
Windows-only, so on Linux you run ingest yourself and continue with `--from 08`.
`python -m prep.snapshot_linux notes` prints the manual procedure.

## How it works

```
binary ──┬─> Ghidra ──> A2 pseudo-C ──> [LLM] entry, input format, harness
         │              A3 basic blocks ──> coverage breakpoints
         │              A6 global symbols
         └─> KD or GDB + !snapshot ──> A1 snapshot

               ┌─────────── fast clock ───────────┐   ┌─── slow clock ───┐
               │ wtf master  ──>  N wtf workers   │   │ sidecar process  │
               │ owns corpus      execute + report│<──│ plateau -> seeds │
               └──────────────────────────────────┘   └──────────────────┘

crashes ──> dedup ──> classify ──> replay ──> trace ──┐
                                    A2 pseudo-C ──────┴──> [LLM] triage ──> GHSA
```

The LLM runs on the slow clock only: entry selection, input format, harness, seed
generation on plateau, and triage. The fast clock is wtf's execution loop and never
calls it.

Triage takes five independent signals: dedup bucket, fault classification,
deterministic replay, symbolized trace, pseudo-C.

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

70× fewer executions per bug than libFuzzer, 366× fewer than honggfuzz. Full numbers,
methodology and caveats: [docs/RESULTS.md](docs/RESULTS.md).

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

Skips are live-endpoint tests behind `SNAPFUZZ_LIVE_LLM`, `SNAPFUZZ_LIVE_MCP` and
`SNAPFUZZ_LIVE_CP4B`.

## Credits

Built on [wtf](https://github.com/0vercl0k/wtf) by Axel Souchet, with
[0vercl0k/snapshot](https://github.com/0vercl0k/snapshot),
[symbolizer-rs](https://github.com/0vercl0k/symbolizer-rs),
[Ghidra](https://github.com/NationalSecurityAgency/ghidra) and
[GhidraMCP](https://github.com/LaurieWired/GhidraMCP). wtf's own README is at
[docs/README.wtf-upstream.md](docs/README.wtf-upstream.md).

Design notes: [CLAUDE.md](CLAUDE.md), [docs/DECISIONS.md](docs/DECISIONS.md),
[docs/DEVIATIONS.md](docs/DEVIATIONS.md), [docs/RESULTS.md](docs/RESULTS.md).
