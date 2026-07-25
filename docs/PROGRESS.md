# PROGRESS

Checkpoint gate results and live-vs-pending edge tracking (CLAUDE.md RULE 3).

An edge is **live** only once the checkpoint gate named in its `gates` list has
passed. Code that compiles is not a gate. `tests/gates/test_cp0.py` asserts this
table and `arch/graph.yaml` agree, so they cannot drift apart.

## Gate status

| Gate | Checkpoint | Status | Date | Notes |
|---|---|---|---|---|
| 0 | Scaffold, contracts, config, graph | **PASS** | 2026-07-25 | Re-passed against the revised architecture (v2 graph, 50 edges) |
| 1 | Build wtf, run a bundled example | **PASS** | 2026-07-25 | tlv_server, 150 s, bochscpu: cov 12,636 and growing, corpus 0→32, 38 crashes, ~360 exec/s |
| 2 | Ghidra headless BB enumeration -> A3 | **PASS** | 2026-07-25 | 17 tests. Closure 58 blocks / module 613; 97.4% recall vs wtf's own `.cov` |
| 3 | Snapshot acquisition -> A1 | **PASS** | 2026-07-25 | **Scoped.** 19 tests; all four gate conditions met, but only edge 11 goes live — the *acquisition* path is unexercised, see the log below |
| 4 | Fuzzer module + first real run (1 worker) | **PASS** | 2026-07-25 | 33 tests. 663 s run, 32 new-coverage events, harness validation passes. Edge 22 held pending — bochscpu ignores `.cov` (D-004) |
| 4b | Distributed bring-up (>= 2 workers) | not started | — | Resolves edge 22 and the whv question (D-032) |
| 5 | LLM client | **PASS** | 2026-07-25 | 19 tests including live endpoint calls. All 5 roles answer; JSON round-trips into a contract; usage log and budget caps verified |
| 6 | GhidraMCP + A2 + LLM entry selection | not started | — | |
| 7 | Plateau detection + LLM seed gen | not started | — | |
| 8 | Dedup, classification, replay, traces | not started | — | Needs `symbolizer-rs` |
| 9 | DSPy triage (5 signals) + report | not started | — | |
| 10 | Evaluation harness | not started | — | |

## Edges

50 canonical edges from CLAUDE.md section 3.2 (including its lettered
sub-edges), plus 3 derived edges recorded in [DEVIATIONS.md](DEVIATIONS.md).

| Edge | From | To | Gate | Status |
|---|---|---|---|---|
| 1 | target_binary | snapshot.break_at_entry | 3 | pending |
| 2 | target_binary | ghidra.analyze | 2 | live |
| 3 | ghidra.fuzz_entry_selection | snapshot.break_at_entry | 6 | pending |
| 4 | ghidra.fuzz_entry_selection | ghidra.decompile | 6 | pending |
| 5 | ghidra.fuzz_entry_selection | ghidra.bb_enumerate | 2 | live |
| 6 | snapshot.break_at_entry | snapshot.windows_kd | 3 | pending |
| 6b | snapshot.break_at_entry | snapshot.linux_gdb *(derived)* | 3 | pending |
| 7 | snapshot.windows_kd | a1_snapshot | 3 | pending |
| 8 | snapshot.linux_gdb | a1_snapshot | 3 | pending |
| 9 | ghidra.decompile | a2_pseudoc_cache | 6 | pending |
| 10 | ghidra.bb_enumerate | a3_bp_list | 2 | live |
| 11 | a1_snapshot | fuzz_target.snapshot | 3 | live |
| 12 | a2_pseudoc_cache | fuzzer_module.llm_input_struct | 6 | pending |
| 13 | a3_bp_list | fuzz_target.bp_list | 4 | live |
| 14 | fuzzer_module.llm_input_struct | fuzzer_module.bus | 4 | live |
| 15 | fuzzer_module.insert_testcase | fuzzer_module.bus | 4 | live |
| 16 | fuzzer_module.restore_hook | fuzzer_module.bus | 4 | live |
| 17 | fuzzer_module.manual_tweaks | fuzzer_module.bus | 4 | live |
| 18 | fuzzer_module.bus | fuzz_target.fuzzer_module | 4 | live |
| 19 | fuzz_target.fuzzer_config | master.corpus *(interface 1 — master only)* | 4, 4b | live |
| 20 | fuzz_target.snapshot | worker.execute *(interface 2 — per worker)* | 4, 4b | live |
| 21a | fuzz_target.fuzzer_module | master.mutator *(interface 2 — master)* | 4, 4b | live |
| 21b | fuzz_target.fuzzer_module | worker.execute *(interface 2 — per worker)* | 4, 4b | live |
| 22 | fuzz_target.bp_list | worker.execute *(interface 3 — per worker)* | 4, 4b | pending |
| 23 | master.corpus | master.mutator *(generation on the MASTER)* | 4, 4b | live |
| 23b | master.mutator | worker.execute *(over the wire)* | 4, 4b | live |
| 24 | worker.execute | worker.coverage | 4, 4b | live |
| 25 | worker.coverage | master.aggregate_coverage | 4, 4b | live |
| 26 | master.aggregate_coverage | master.corpus *(requeue, fast clock)* | 4, 4b | live |
| 27 | master.aggregate_coverage | slow_clock.llm_seed_gen *(plateau)* | 7 | pending |
| 28 | a2_pseudoc_cache | slow_clock.llm_seed_gen | 6 | pending |
| 29 | slow_clock.llm_seed_gen | master.corpus *(new seeds)* | 7 | pending |
| 30 | master.corpus | a4_corpus | 4, 4b | live |
| 31 | worker.execute | master.crash_collect | 4, 4b | live |
| 31b | master.crash_collect | a5_crashes *(derived)* | 4, 4b | live |
| 32 | a4_corpus | analysis.cov_trace_gen | 10 | pending |
| 32b | analysis.cov_trace_gen | analysis.symbolize_cov | 10 | pending |
| 32c | analysis.symbolize_cov | analysis.lighthouse_report | 10 | pending |
| 33 | a5_crashes | analysis.crash_dedup | 8 | pending |
| 34 | analysis.crash_dedup | analysis.crash_classification | 8 | pending |
| 35 | analysis.crash_classification | analysis.deterministic_replay | 8 | pending |
| 36 | analysis.deterministic_replay | analysis.trace_gen | 8 | pending |
| 36b | analysis.trace_gen | analysis.symbolize_trace | 8 | pending |
| 37 | analysis.symbolize_trace | analysis.reverse_engineer | 6, 8 | pending |
| 37b | a2_pseudoc_cache | analysis.reverse_engineer | 6, 8 | pending |
| 38 | analysis.crash_dedup | analysis.llm_triage *(signal 1 — dedup)* | 9 | pending |
| 39 | analysis.crash_classification | analysis.llm_triage *(signal 2 — classification)* | 9 | pending |
| 40 | analysis.deterministic_replay | analysis.llm_triage *(signal 3 — replay)* | 9 | pending |
| 41 | analysis.symbolize_trace | analysis.llm_triage *(signal 4 — DYNAMIC)* | 9 | pending |
| 41b | analysis.reverse_engineer | analysis.llm_triage *(signal 5 — STATIC)* | 9 | pending |
| 42 | analysis.llm_triage | report *(confirmed)* | 9 | pending |
| 43 | analysis.llm_triage | discard *(false_positive)* | 9 | pending |
| 1000 | ghidra.analyze | ghidra.fuzz_entry_selection *(derived)* | 6 | pending |

## Log

### 2026-07-25 (3) — Re-aligned to the revised architecture

CLAUDE.md grew from 789 to 1245 lines, adding **RULE 4**, the master/N-worker
distributed topology (§12), a README-derived reference section (§13) that is
authoritative over earlier sections, a **fifth triage signal**, and **CP4b**.
Existing work was brought into line before any new work started.

Changed:

- **`arch/contracts.py`** — `SnapshotRef` gained `mem_dmp`, `regs_json`,
  `symbol_store_json`, `ghidra_image_base`; `CrashRecord` gained `worker_id`
  and `backend`; `ReplayResult` gained `backend`; new `TraceRef` for signal 4;
  new `TRIAGE_SIGNALS` naming all five. Two validators added, because both
  rules they enforce are silent failures rather than errors: a Linux
  `SnapshotRef` must have ASLR off and a symbol store, and a `ReplayResult`
  from whv/kvm must record a bochscpu re-check before its determinism claim is
  accepted.
- **`arch/graph.yaml`** — v2. Node set replaced: the single `engine.*` group
  became `master.*`, `worker.*` (with `fanout: per_worker`) and
  `slow_clock.*`. 42 canonical edges became 50.
- **`tests/gates/test_graph.py`** — string edge ids; five signals not four; and
  three new checks aimed at silent failures: no `calls_llm` node may carry
  `role: master` or `role: worker`; edges 21a/21b must both exist; every edge
  into a per-worker node must declare fan-out.
- **`tests/gates/test_cp0.py`** — new contract shapes, plus config assertions
  that topology, per-backend `--limit`, and an execution-based plateau
  threshold are all actually declared.
- **`config/fuzz.yaml`** — §12.4 topology block, seed spool, trace paths,
  companion-tool paths.

One modelling note worth flagging: the §3.1 diagram marks the custom
`Mutator_t` `[LLM]`, but `[LLM]` there means "our layer", not "calls an LLM".
The mutator *consumes* LLM seeds on the master's hot path and must never call
the LLM itself. `graph.yaml` therefore separates `ours: llm_layer` from
`calls_llm`, and the gate enforces it.

### 2026-07-25 (8) — GATE 4 PASS; 18 edges live

**GATE 4 PASS**, 33 tests. Final run: **663 s**, one worker on bochscpu, module
`snapfuzz`, **32 new-coverage events**, corpus 41 → 42, harness validation
passing. 18 edges now live (13–21b, 23–26, 30–31b).

**Edge 22 is deliberately held pending.** It delivers the coverage breakpoint
list to a worker, and bochscpu **ignores `.cov` files entirely** (D-004), so CP4
never exercised it. This is precisely what DEC-005 predicted and why it exists;
marking it live because the file is in place would be the "done because the code
exists" failure RULE 3 prohibits. It resolves at CP4b on `whv` — assuming WHP can
be enabled on Windows Home, which D-032 leaves open.

**Getting to a trustworthy result took three failed measurement approaches**, and
the lesson generalises past this checkpoint:

1. **Reading the master through a pipe.** A 90-second run yielded **zero**
   parsable stat lines while the fuzzer ran at 360 exec/s. The runner reported
   `coverage grew: False` about a completely healthy campaign.
2. **Redirecting to a file and tailing it.** Better, but a 663-second run left
   only **8 lines covering the first 72 seconds** — `TerminateProcess` never
   flushes C stdio.
3. **Ctrl+Break for a graceful exit.** The master accepts it and exits, and the
   log was still **0 bytes** after 123 seconds.

The signal that works is the **filesystem**: the master writes to `outputs/`
exactly when a testcase produces new coverage, and that is not buffered. During
the 0-byte-log run it had saved 30 new-coverage testcases. All of this is D-033.

Worth stating plainly because it nearly went the other way: at step 1 the
evidence said "coverage did not grow", and the correct conclusion was that the
*measurement* was wrong, not the fuzzer. The tell was `outputs/` growing by 30
while the metric said zero.

**A second measurement bug, caught the same way.** `CrashWatcher` de-slid every
fault address with the target module's slide. But 48 of 55 crashes faulted at
`0x7ff8aa3812de`–`0x7ff8aa38167c`, which is not the target and not any module in
`symbol-store.json` — ~192 KB below `verifier.dll`, most likely the Application
Verifier stack. De-sliding those produced `0x2d05312de`: a fictitious address
that would have hashed cleanly and bucketed consistently. Now a fault is de-slid
only when it lies inside the target module, and `CrashRecord.fault_module` records
the attribution. Full detail and the CP8 consequences in D-035.

That finding strengthens D-024's case considerably: fault-address bucketing does
not merely split one bug into 38 buckets, it buckets on *where the guard
mechanism noticed* rather than *what the parser did wrong*. It is also concrete
evidence for CP8's signal 4 — the execution trace is what walks back from the
verifier frame to the origin.

### 2026-07-25 (7) — GATE 5 PASS; VM prerequisites resolved

**GATE 5 PASS.** `llm/client.py` takes a **role**, never a model name. 19 tests,
including live endpoint calls behind `SNAPFUZZ_LIVE_LLM=1` so a normal test run
spends no allocation.

All four gate conditions met. Measured latencies for the same trivial prompt:

| role | model | latency |
|---|---|---|
| triage | nemotron-3-ultra-550b | 0.1 s |
| seed_gen / entry_select / dspy_bootstrap | nemotron-cascade-2-30b | 0.3 s |
| crash_prefilter | gemma-4-26b | 1.9 s |

Two findings went into the client rather than being worked around:

- **D-030** — `content` can be `null` on an HTTP 200 when a reasoning model
  exhausts `max_tokens`. The client treats that plus `finish_reason == "length"`
  as a retryable error and **doubles the budget**, rather than reporting an empty
  answer. A gate test asserts every reasoning model's role has >= 4096 tokens.
- **D-034** — describing the wanted fields in prose got well-formed JSON with
  *invented* field names (`memcpy_offset` for `length_offset`, one required field
  omitted), and the retry could not recover because it never learned the real
  names. `complete_json` now embeds `model_json_schema()` in the prompt. Same
  call, first-try success. This matters for CP6 and CP9, where `FuzzEntry` and
  `TriageVerdict` go through the same path.

The token is read from a gitignored `.env` (tolerating the BOM that PowerShell
5.1's `Set-Content -Encoding utf8` writes), and a gate test refuses a config with
an inline `api_key`.

**VM prerequisites — mostly already satisfied (D-032).** CLAUDE.md section 13.6
says "Hyper-V VM", and Hyper-V is **not available on this host** (Windows 11
Home; `HyperVisorPresent: False`) — though the CPU meets every requirement, so
it is purely an edition limit.

The requirement is weaker than the README implies: what is needed is a Windows
guest with KD attached over a serial-to-named-pipe, which is not Hyper-V
specific. Three of the four pieces were already here or are now:

| Piece | Status |
|---|---|
| Hypervisor | VMware Workstation 17.6.2 — already installed |
| Kernel debugger | `kd.exe` 10.0.26100.7705 — already installed |
| `!snapshot` extension | `snapshot.dll` v0.2.5 — downloaded to `D:\tools\snapshot` |
| **Windows guest VM** | **missing** — needs an ISO and an interactive install |

So no hypervisor to install; a guest to create. Steps 3–5 of the procedure are
scripted (`python -m prep.snapshot_win kd-script`).

**This does put DEC-005 in doubt**, and it is better flagged now than discovered
at CP4b: that decision pins the scaled run to `whv` because it is the only local
backend that consumes the CP2 coverage file, but `whv` needs the hypervisor
running. If WHP cannot be enabled on Home, GATE 4b proves coverage aggregation
on bochscpu but leaves edge 22 unexercised.

### 2026-07-25 (6) — CP4 in progress; LLM endpoint verified; symbolizer-rs installed

**Not GATE 4 yet.** The hard, high-risk half is done and proven; the Python
bridge and the >=10-minute run remain.

**LLM endpoint — verified, not assumed** (section 7.1). Credentials supplied by
the user. All seven model ids confirmed against `GET /v1/models`. Two findings
that changed `config/llm.yaml`:

- **D-030.** gemma-4-12b and gemma-4-26b are *reasoning* models whose
  `reasoning_content` is billed against `max_tokens`. Exhaust the budget and the
  API returns **HTTP 200 with `content: null`** — silently. Our config had
  `seed_gen: max_tokens: 2048`, which would have produced nulls under load and
  looked like the LLM having no suggestions. Also inverts §7.2's premise: it
  routes seed generation to gemma-4-12b as "cheap, fast", but gemma-4-12b took
  **18.6 s** against nemotron-cascade-2-30b's **1.9 s** on the same task.
- **D-029.** The vendor's matrix marks llama-3.3-70b 🔴 on all four coding
  agents, yet it answered our single-shot pseudo-C task correctly in 0.9 s — the
  matrix measures agentic tool-use, not comprehension. `entry_select` routes to
  nemotron-cascade-2-30b, the peer §7.2 already sanctions.

The token lives only in a gitignored `.env`; `config/llm.yaml` keeps
`api_key: null` and the gate enforces it.

**symbolizer-rs v0.4.0 installed**, and the whole harness-validation mechanism
proven end to end before writing any of our own C++.

**CP4 so far:**

- `fuzzer/module/fuzzer_snapfuzz.cc` — our module. Registers as `snapfuzz`
  (verified in wtf's own registry listing). Multi-packet delivery per §13.7,
  the crash oracle via `SetupUsermodeCrashDetectionHooks`, and a
  `CustomMutator_t` that drains the LLM seed spool.
- `fuzzer/build.py` — stages `fuzzer/module/*.cc` into `src/wtf/` (D-012),
  discovers the right VS instance, handles the `PATH` quote bug, and **fails if
  the module did not register** — a stale `wtf.exe` runs the old module and
  looks perfectly healthy otherwise.
- `targets/snapfuzz/` — target tree with interface 1 (5 startup seeds) and
  interface 3 (the CP2 `.cov`) wired; `state/` is a junction to tlv_server's, so
  the 1.8 GB dump is not duplicated.

**Harness validation — PASS.** CP4 calls this mandatory and warns that a harness
which runs and reports coverage but never reaches the parser is the classic
silent failure. Symbolized `rip` trace, line 1:

```
tlv_server.exe!ProcessPacket+0x0 [tlv_server.cc @ 29]
```

**Seed spool ingest — verified, no LLM involved** (R9, and a GATE 4b
requirement met early). 25 seeds hand-placed via temp-then-rename were **all 25
consumed** by the running master; corpus grew 0 → 34; 41 crashes found. The
master logs `snapfuzz: seed spool at <path>` at startup so a misconfigured spool
is visible rather than silent. This is the path CLAUDE.md warns "fails silently
— the worst kind of failure here".

**Also resolved:** RULE 4's **R7/R8** (`input_param: rcx` holding the buffer
address, `size_param: rdx` in bytes, from `fuzzer_tlv_server.cc:113-124`) and
**R9** (consumer deletes). Only R2 and R6 remain open.

**D-031** is worth flagging for the writeup: wtf's own module writes each packet
flush against the **end** of its page, so an overrun hits the guard page and
faults. That recovers part of what DEC-001 gives up by having no ASAN — §2 lists
out-of-bounds *reads* as undetectable, and this makes a slice of them
observable, free. Adopted in our module. It is not a sanitiser: overreads that
stay inside the page still pass silently.

**Remaining for GATE 4:** `fuzzer/run.py`, `fuzzer/corpus.py`,
`engine_bridge/coverage.py`, `engine_bridge/crash_watch.py`,
`analysis/trace.py`, a >=10-minute run showing growing coverage, and
`tests/gates/test_cp4.py` including the no-LLM-in-the-fast-path assertion.

### 2026-07-25 (5) — GATE 3 PASS, scoped

All four GATE 3 conditions are met, but **only edge 11 goes live**. The reason
is worth stating plainly rather than burying.

**What was proven.** `artifacts/a1_snapshot.json` exists and validates;
`module_base` (`0x7ff719e50000`) and `entry_runtime_addr` (`0x7ff719e51150`) are
recorded; wtf loads that snapshot and executes — the gate runs
`wtf run` for real and asserts nonzero coverage, 2.4 s warm. On the Linux side
`aslr_disabled == True` is enforced in two independent places.

That closes **edge 11** (A1 → `fuzz_target.snapshot`).

**What was not proven.** Edges 1, 6 and 7 are the *acquisition* chain
(`target_binary` → `break_at_entry` → `windows_kd` → A1). We **ingested a
snapshot wtf's author took**; we never ran the procedure. `build_kd_commands`
emits the KD sequence and is unit-tested, but has never driven a real KD
session, because that needs a Hyper-V VM with one vCPU and the
`0vercl0k/snapshot` extension. Marking those edges live because the code exists
is precisely the failure RULE 3 is written to prevent, so they stay `pending`.

To make them live: build the guest VM, run `scripts/disable-kva.cmd` inside it
(D-028), attach KD, and take a snapshot of a target we choose.

**Delivered:**

- `prep/snapshot_win.py` — `ingest_state_dir` (existing `state/` → A1) and
  `build_kd_commands` (the acquisition script). `read_pe_image_base` parses the
  PE optional header rather than trusting a constant.
- `prep/snapshot_linux.py` — EXPERIMENTAL. Asserts ASLR is off and fails loudly,
  as CP3 requires, while recording that the repo does not actually corroborate
  that requirement (D-010).
- `config/target.yaml` — the manual fuzz entry, as CP3 asks:
  `tlv_server!ProcessPacket`, static `0x140001150`, with the rationale.

**The check most likely to earn its keep** is `require_rip_at_entry`: a snapshot
taken somewhere other than the fuzz entry loads fine, runs fine, and reports
healthy coverage — it just fuzzes the wrong code. Nothing downstream would
notice, so ingest refuses it unless the caller opts out explicitly.

**Deliberately left null:** `entry.input_param` and `entry.size_param`. RULE 4
(R7/R8) fixed the *encoding* — `"<reg>"` vs `"&<reg>"`, and sizes always in
bytes — but the actual registers `ProcessPacket` uses have not been read out of
the disassembly. Guessing them yields a harness that runs, reports coverage, and
never parses our bytes. Settled at CP4 against `fuzzer_tlv_server.cc`.

### 2026-07-25 (4) — GATE 2 PASS

Ghidra 12.1.2 installed; A3 generated and validated against a real reference.
Edges **2, 5, 10** are now `live` — the first live edges in the project.

**Delivered:**

- `prep/ghidra_scripts/ExportBasicBlocks.java` — the post-script. Java, not
  Python: Ghidra 12 ships Jython only as an optional extension and routes `.py`
  to PyGhidra, which `analyzeHeadless` cannot start (D-025, DEC-012). So wtf's
  own `gen_coveragefile_ghidra.py` does not run here.
- `prep/ghidra_headless.py` — driver. Handles the D-020 `PATH` quote problem,
  and treats **the artifact, not the exit code, as the success signal**:
  `analyzeHeadless` returns 0 even when a post-script throws (D-026).
- `prep/bb_to_wtf.py` — A3 emitter and a `.cov` parser mirroring wtf's
  `ParseCovFiles`, so our own file can be checked with the logic wtf will apply.

**Results** on `tlv_server.exe` (image base `0x140000000`):

| scope | blocks |
|---|---|
| `--scope=module` | 613 |
| `--scope=function-closure` from `ProcessPacket` | **58** (14 functions) |

A 10.6× reduction, which is the entire point of scoping. The closure resolved
`ProcessPacket@140001150` — matching the address derived independently in
`tests/test_addr.py` from `symbol-store.json` and the PE header.

**Validation against wtf's own tooling** (D-027). The release archive ships a
`.cov` produced by the author's disassembler, so this is a diff against a real
answer rather than a self-consistency check:

- module scope recall: **97.4%** (516 of 530), 14 missed, 97 extra;
- closure blocks present in the reference: **58 / 58**.

The gate asserts recall rather than exact agreement, because the two error
directions are not symmetric: extra blocks are skipped with a warning and cost
a little speed, while missed blocks are coverage that is silently never counted.

**A gate-design fix went in alongside.** `test_progress_lists_every_edge_as_pending`
asserted *every* edge was pending — true at CP0, but a snapshot of a moment
rather than an invariant, and it would have blocked marking any edge live. It is
replaced by `test_live_edges_have_a_passed_gate`, which enforces RULE 3
directly: an edge may be `live` only if PROGRESS.md records one of its gates as
PASS. Verified non-vacuous with a negative control.

### 2026-07-25 (2) — GATE 1 PASS

wtf builds, and both bundled examples run. All three verbs exercised
(`run`, `master`, `fuzz`) as CP1 requires.

**Build.** VS 18 toolchain (MSVC 14.51.36231, cmake 4.3.1, ninja 1.13.2), 16 s,
`wtf.exe` 6.6 MB. Two host obstacles: the CMake component installed into a
*second* VS instance (VS 18, not VS 2022), and `vcvars64.bat` aborts here
because the machine `PATH` holds an entry with a stray double quote (D-020).

**`hevd`** — unmodified, bochscpu, `run`: exit 0, 81.2k instructions
(26.0k unique), 560 KB dirty pages.

**`tlv_server`** — the CP1-mandated target. Two blockers, both now resolved and
both worth the reading they took:

- **D-019**, the snapshot was rejected outright: its 2022-era `regs.json` uses
  an `fpst` encoding this revision no longer accepts. Repaired (DEC-011). The
  first fix I derived was *wrong in a silent way* — it would have loaded an x87
  tag word claiming eight valid registers on an empty stack — and only reading
  the branch that `BdumpGenerated` also feeds caught it.
- **D-023**, breakpoints resolve by symbol name and wtf sets no symbol path.
  Needs `_NT_SYMBOL_PATH` with both the local PDB directory and the Microsoft
  symbol server. First run 373 s, nearly all PDB download.

**GATE 1 evidence** — `master` + one `fuzz` worker, bochscpu, 150 s:

```
#0    cov: 0     (+0)     corp: 0  (0.0b)   exec/s: -     uptime: 4.0s
#3745 cov: 12631 (+12631) corp: 31 (27.3kb) exec/s: 374.0 uptime: 14.0s
#7158 cov: 12636 (+5)     corp: 32 (28.6kb) exec/s: 357.0 uptime: 24.0s
```

Coverage nonzero **and growing**; corpus grew 0 → 32 via requeue; 34 files
landed in `outputs/`, 38 in `crashes/`; ~360 exec/s on one bochscpu worker.

**The most useful result was not the pass.** The master counted **1113 crash
events** but wrote only **38 files**, because wtf keys crash filenames on
`(exception kind, fault address)` and skips files that already exist. All 38
addresses sit within a **926-byte window** — one function. So address-based
bucketing splits what is almost certainly **one bug into 38 buckets**, which at
one triage call per bucket is 38× the intended spend on a single bug from
150 seconds of fuzzing. That is the measured case for CP8's stack-hash dedup,
and *38 → 1* is a number the writeup can quote. Full detail in D-024.

Recorded in DEVIATIONS this round: D-016 through D-024.

### 2026-07-25 (1) — GATE 0 PASS

Scaffold, contracts, config and graph in place; `pytest tests/` green.

Delivered: section 5 layout at the repo root (D-000), `arch/contracts.py`,
`arch/addr.py` (section 9 conversions plus RVA helpers), `arch/graph.yaml`,
three gate/unit test files, and `config/{llm,fuzz,target}.yaml` with values
requiring an absent tool or an unread README marked `TODO(CPn)` rather than
guessed.
