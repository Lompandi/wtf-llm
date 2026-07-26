# Running stages individually

`orchestrator.pipeline` runs these in order. Useful standalone when debugging or
iterating on a prompt.

Paths below use `<exe>` for the target binary and `snapfuzz` for the target name.

## Ghidra artifacts

```powershell
# A3 -- basic blocks for coverage breakpoints
python -m prep.ghidra_headless --what blocks --binary <exe> `
    --out artifacts\a3_ghidra_blocks_module.json --scope module --entry ProcessPacket

# A3 -> the .cov format wtf loads
python -m prep.bb_to_wtf --export artifacts\a3_ghidra_blocks_module.json `
    --coverage-dir targets\snapfuzz\coverage --bp-list artifacts\a3_bp_list.json

# A6 -- global data symbols; decompilation drops a table's capacity, this recovers it
python -m prep.ghidra_headless --what data-symbols --binary <exe> `
    --out artifacts\a6_data_symbols_module.json --scope module --entry ProcessPacket

# A2 -- batch-decompile, then load into SQLite
python -m prep.ghidra_headless --what pseudoc --binary <exe> `
    --out artifacts\a2_pseudoc_module.json --scope module --entry ProcessPacket
python -m prep.pseudoc_cache build --export artifacts\a2_pseudoc_module.json `
    --cache artifacts\a2_pseudoc_module.sqlite

# query by name or address (address lookup is a range query, tightest span wins)
python -m prep.pseudoc_cache query --cache artifacts\a2_pseudoc_module.sqlite `
    --function ProcessPacket
```

`--scope module` enumerates everything; `--scope function-closure` restricts to the
entry's call closure. The scope is part of the artifact filename — mixing them
silently produces the wrong breakpoint set.

## Snapshot

```powershell
# ingest an existing state/ -> A1
python -m prep.snapshot_win ingest --state targets\snapfuzz\state `
    --module tlv_server --binary <exe> --entry-symbol ProcessPacket `
    --out artifacts\a1_snapshot.json
```

Windows acquisition: see [GUEST-VM.md](GUEST-VM.md). Linux:

```bash
python -m prep.snapshot_linux check-host        # what is missing on this host

python -m prep.snapshot_linux prepare \
    --target-name mytarget --binary ./mytarget --break-at parse_packet \
    --stimulus '/root/mytarget &'               # --dry-run to see it first

python -m prep.snapshot_linux ingest --state targets/mytarget/state \
    --module mytarget --module-base 0x555555554000 --ghidra-image-base 0x100000 \
    --entry-runtime-addr 0x5555555551a9 --randomize-va-space 0
```

`prepare` writes `bkpt.py`, puts the ELF where `nm`/`readelf` will read it, clears
stale state, and prints the remaining steps — including the interactive `cpu` step in
the server gdb, which cannot be automated and which the snapshot hangs without. It
reports the ingest command with `--module-base` filled in, because `FuzzBkpt`'s
`target_base` — which `prepare` sets — *is* that value.

## Choosing a provider

Every LLM stage uses whichever provider's key is set, in `config/llm.yaml` order. To
pin one for a single command:

```bash
SNAPFUZZ_LLM_PROVIDER=anthropic python -m prep.entry_select ...
```

Each role maps a model per provider, so `entry_select` on `anthropic` is
`claude-opus-5` and on `nchc` is `ais3/nemotron-cascade-2-30b`. A role with no entry
for the active provider is an error, never a default — a model nobody chose is how a
campaign gets attributed to the wrong one (D-056).

## LLM derivation

```powershell
# choose the fuzz entry
python -m prep.entry_select --cache artifacts\a2_pseudoc_module.sqlite `
    --module tlv_server --module-base 0x7ff719e50000 --ghidra-image-base 0x140000000 `
    --out artifacts\fuzz_entry_llm.json

# derive the wire format from the entry's pseudo-C AND its callers
python -m prep.input_struct --entry artifacts\fuzz_entry_llm.json `
    --cache artifacts\a2_pseudoc_module.sqlite --out artifacts\input_spec.json

# derive the harness logic
python -m prep.harness_derive --entry artifacts\fuzz_entry_llm.json `
    --cache artifacts\a2_pseudoc_module.sqlite --out artifacts\harness_spec.json

# schema -> C++ (ordinary code, no LLM)
python -m fuzzer.codegen --spec artifacts\input_spec.json `
    --out fuzzer\module\generated_input.h
python -m fuzzer.codegen --module --spec artifacts\input_spec.json `
    --harness artifacts\harness_spec.json --out fuzzer\module\fuzzer_gen.cc
```

Notes that matter:

- Entry selection is two-phase — shortlist from signatures, then decide from full
  pseudo-C. Addresses always come from A2; the model never supplies one.
- The entry's callers go into the input-structure prompt. Whether a parser is
  called repeatedly is a property of the caller. Given only `ProcessPacket` the model
  answered `supports_sequence: False`; given `main`'s `recv` loop as well, it answered
  correctly.
- Validate a derived spec against a hand-written module by layout (offsets, widths,
  length semantics), never by field name — pseudo-C has no names, so comparing names
  tests the model's word choice rather than its understanding.

## Fuzzing

```powershell
# full campaign: master + N workers + slow-clock sidecar
python -m orchestrator.scheduler --label myrun --workers 2 --minutes 15 `
    --target-dir targets\snapfuzz --module snapfuzz `
    --plateau-execs 20000 --seeds 6 --samples 3

# no-LLM baseline
python -m orchestrator.scheduler --label baseline --workers 2 --minutes 15 `
    --target-dir targets\snapfuzz --no-sidecar

# one slow-clock round, for prompt iteration
python -m llm.sidecar --target-dir targets\snapfuzz --module snapfuzz `
    --once --seeds 6 --samples 3
```

`--samples N` issues N independent LLM calls per round and takes the union. The role
runs hot for input diversity, so reasoning quality varies with it: on the same
frontier, one sample worked out that a global table had to be exhausted and proposed a
5-packet sequence; the next reasoned about a single command and could not produce more
than one packet.

## Analysis and triage

```powershell
# dedup -> classify -> replay -> trace -> static context (no LLM)
python -m analysis.pipeline --target-dir targets\snapfuzz --label gate8 --replays 3

# five-signal triage + report
python -m analysis.triage_run --evidence artifacts\runs\gate8 --label gate9
```

Writes `artifacts/runs/gate9/advisory.md` (confirmed only) and `discarded.jsonl` (kept
for evaluation, not shipped).

## Evaluation

```powershell
python -m eval.build_cases                        # labelled triage case set
python -m eval.triage_eval [--optimise]           # score on the held-out split
python -m eval.baseline --minutes 5 --workers 2   # the five-arm comparison
python -m eval.plot_curves                        # coverage curves
python -m eval.coverage_gradient --target-dir targets\snapfuzz --command 0
```

Prompt optimisation happens on the train split; reported metrics come from the
held-out split.
