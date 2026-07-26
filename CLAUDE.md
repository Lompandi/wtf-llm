# CLAUDE.md — LLM-Guided Snapshot Fuzzer (AIS3 2026)

Codename: `snapfuzz`. Build an automated fuzzing system for **x86-64 Windows and
Linux application binaries** (no source), using **wtf** (snapshot fuzzing) as the
execution engine, **Ghidra** as the static-analysis backbone, and an **LLM slow
clock** for seed generation and crash triage.

`wtf` is **already cloned** in this workspace. Locate it before doing anything else.

---

## 0. READ THIS FIRST — FOUR RULES THAT OVERRIDE EVERYTHING

### RULE 1 — The LLM is NEVER called from inside the fast loop
The fast loop (`corpus → mutate → restore snapshot → inject → execute → read
coverage`) runs thousands of iterations per second. One LLM call is 10²–10³ ms.
An LLM call inside that loop destroys throughput by 4–6 orders of magnitude and
defeats the entire design.

If you are writing an LLM API call in any function that also mutates input or
executes the target, **stop — you have broken the architecture.** LLM calls happen
only in the slow clock (§8, CP7).

### RULE 2 — Verify every wtf API detail against the cloned source
This document describes wtf's concepts (snapshot format, `InsertTestcase`,
coverage breakpoint file, backends, CLI verbs). **These descriptions may be stale
or wrong.** Before implementing against any wtf API:

1. Read the actual headers/sources and `README.md` in the cloned repo.
2. Read the bundled example targets/fuzzers — they are the ground truth for how a
   fuzzer module is written.
3. If this document conflicts with the source, **the source wins.** Record the
   discrepancy in `docs/DEVIATIONS.md` and continue.

Never invent a wtf function signature. Grep for it.

### RULE 3 — Every checkpoint ends with an INTERFACE GATE
Each checkpoint (§8) defines an explicit gate: the concrete artifacts that must
exist and the assertions that must pass, proving the interfaces are **actually
wired** — not merely that code compiles. **Do not start checkpoint N+1 until
checkpoint N's gate passes.** Implement each gate as an executable check under
`tests/gates/` and record the result in `docs/PROGRESS.md`.

### RULE 4 — A signature is not specified until you can write it without guessing

A function signature is only concrete enough when **all** of these hold:

- **Every parameter has a definite type.** Not `void *data` — you know whether it is
  a buffer pointer, a struct pointer, or an inline value.
- **Units and encoding are stated.** Is a length in **bytes or elements**? Is an
  address **absolute or an offset relative to a base**?
- **Boundary cases are defined.** What happens on empty input, on out-of-range
  values, on size zero.
- **Memory ownership is assigned.** If a pointer crosses the boundary, **who frees
  it**.

If writing the signature requires you to think *"I'll assume … for now"*, **the spec
is not finished.** Go read the source (RULE 2) or ask. Do not code around the gap —
in this project every one of these gaps produces a *silent* failure, not an error.

The places in this project where this bites, all of which must be answered before
the corresponding code is written:

| Interface | Question that must be answered first |
|---|---|
| `FuzzEntry.input_param` | Is the register holding a **pointer to** the buffer, or the buffer address itself? |
| `FuzzEntry.size_param` | **Bytes or element count?** Does the target expect it to include a header or terminator? |
| `InsertTestcase` | wtf's real signature: what is passed in, what must be returned, and **who owns the testcase memory after the call**? Does a false return mean "skip this testcase" or "abort the run"? |
| `Restore` | What state is wtf already restoring from the snapshot, and what is left for us? Restoring twice is as wrong as not restoring. |
| A3 BP list | **Absolute virtual addresses or RVAs?** Relative to which module base? |
| `arch/addr.py` | Three bases exist (Ghidra image base, snapshot module base, live runtime base). Which does each function take, and which does it return? |
| seed spool | **Who deletes a consumed seed** — the mutator or the sidecar? What happens if both touch it at once? |
| `coverage.cov` | Record format, and is a hit a **count or a boolean**? |
| crash oracle | Is a **timeout** a crash, an end-of-testcase, or neither? Same question for a clean return from the parser. |

Record every answer in `docs/DECISIONS.md` with the source file and line that
settled it.

---

## 1. Terminology (use these exact words in code, comments, and docs)

| Term | Meaning |
|---|---|
| **fast clock** | The wtf execution loop. No LLM. Microsecond–millisecond scale. |
| **slow clock** | LLM work: seed generation, crash triage. Seconds+. Event-driven. |
| **triage** | Deciding whether a crash is a real, interesting bug. **This is what the LLM does to crashes.** |
| **verification** | A *different* problem (adjudicating a static finding using source + PoC). **NOT part of this project.** Never label the triage stage "verification". |
| **plateau** | Coverage has stopped growing for N consecutive slow-clock ticks. Triggers LLM seed generation. |
| **grey-box** | We have the binary and can instrument it (snapshot + breakpoints), but no source. |

Terminology matters: the project author has a paper arguing fuzzing is the wrong
tool for *verification*. This project is *discovery*. Mislabeling the triage stage
as "verification" creates a contradiction that will be challenged.

---

## 2. Access level and what it costs us

- We have the **binary**, not the source.
- Coverage comes from **breakpoints on basic blocks** (enumerated by Ghidra), not
  compile-time instrumentation.
- **There is no ASAN.** Consequences, which must be documented honestly:
  - **Detectable:** access violations / SIGSEGV, aborts, illegal instruction,
    timeouts/hangs, and whatever fault classes the wtf backend surfaces.
  - **NOT detectable:** memory corruption that does not fault — an out-of-bounds
    read into mapped memory, a small heap overflow that never reaches a guard
    page. Under source+ASAN these are caught instantly; here they pass silently.
- Mitigation options (pick one, record in `docs/DECISIONS.md`):
  (a) investigate a binary-only sanitization approach and accept the slowdown, or
  (b) accept the limitation and state it explicitly in the report as
  *"binary-only instrumentation; the crash oracle covers observable faults only;
  silent memory corruption is out of scope."*
  **Default to (b) for v1** — defensible and does not risk the schedule.
- The **triage LLM therefore never receives a sanitizer report.** It receives
  fault address, registers, fault type, replay result, and Ghidra pseudo-C. Write
  triage prompts under that assumption. Never assume source is available.

**OS priority: Windows first.** wtf's Windows path (kernel-debugger snapshot,
WHV/KVM execution) is the mature one; its Linux user-mode path is experimental
(GDB-based ELF snapshot, ASLR must be disabled). Build the entire pipeline on a
Windows target first, then add Linux as a second target once the core works. If the
Linux path fights you, a complete working system already exists.

---

## 3. THE ARCHITECTURE

### 3.1 Skeleton

```
════ ① TARGET PREPARATION ═════════════════════════════════════════════════
                        ┌──────────────────────────────┐
                        │ Target binary                │
                        │ PE · ELF · x86-64 · no source │
                        └──────────────┬───────────────┘
              ┌────────────────────────┴───────────────────────┐
              ▼                                                ▼
 ┌ Snapshot acquisition ────────────┐  ┌ Ghidra static analysis ───────────┐
 │ ┌──────────────────────────────┐ │  │ ┌───────────────────────────────┐ │
 │ │ !snapshot at fuzz entry      │◀┼──┼─│ Fuzz entry selection    [LLM] │ │
 │ │ COMPANION TOOL (not wtf)     │ │  │ │ parser fn·input_param·size_par│ │
 │ │ target VM: 1 vCPU · 4GB      │ │  │ └──────────────┬────────────────┘ │
 │ └──────────────┬───────────────┘ │  │       ┌────────┴────────┐         │
 │       ┌────────┴────────┐        │  │       ▼                 ▼         │
 │       ▼                 ▼        │  │ ┌────────────┐  ┌──────────────┐  │
 │ ┌───────────┐   ┌────────────┐   │  │ │BB enumerate│  │  Decompile   │  │
 │ │ Windows   │   │ Linux      │   │  │ │ headless   │  │  GhidraMCP   │  │
 │ │ KD dump   │   │GDB·ASLR off│   │  │ └─────┬──────┘  └──────┬───────┘  │
 │ └─────┬─────┘   └─────┬──────┘   │  └───────┼────────────────┼──────────┘
 │       └────────┬──────┘          │          │                │
 └────────────────┼─────────────────┘          │                │
                  ▼                            ▼                ▼
       ┌───────────────────────┐  ┌──────────────────┐  ┌─────────────────┐
       │ A1 · state/           │  │ A3 · BP list     │  │ A2 · pseudo-C   │
       │ mem.dmp · regs.json   │  │ basic-block VAs  │  │ cache by addr   │
       │ symbol-store.json     │  │                  │  │                 │
       └──────────┬────────────┘  └────────┬─────────┘  └────────┬────────┘
                  │                        │                     │
════ ② FUZZING ════════════════════════════════════════════════════════════
                  │                        │                     ▼ (A2)
 ┌ Fuzzer module (C++) · ONE artifact · --name loads it on BOTH subcommands ┐
 │  ┌───────────────────────────────┐  ┌──────────────────────────────┐    │
 │  │ LLM-generated input struct    │  │ Manual tweaks                │    │
 │  │ reads pseudo-C (A2)     [LLM] │  │ length / checksum fixups     │    │
 │  └──────────────┬────────────────┘  └──────────────┬───────────────┘    │
 │                 └───────────┬──────────────────────┘                    │
 │       ┌─────────────────────┴─────────────────────┐                     │
 │       ▼                                           ▼                     │
 │ ┌ used by MASTER ─────────────┐  ┌ used by WORKERS ───────────────────┐ │
 │ │ custom Mutator_t     [LLM]  │  │ Init · InsertTestcase · Restore    │ │
 │ │ GetNewTestcase·OnNewCoverage │  │ + crash / end-of-testcase rules    │ │
 │ └──────────────┬──────────────┘  └──────────────┬─────────────────────┘ │
 └────────────────┼────────────────────────────────┼───────────────────────┘
                  └────────────────┬───────────────┘
                                   ▼
 ┌──────────────────────────────────────────────────────────────────────────┐
 │ harness validation                                                 [wtf] │
 │ wtf run --trace-type=rip  MUST show execution reaching FuzzEntry         │
 └────────────────────────────────┬─────────────────────────────────────────┘
                                  ▼
 ┌ Fuzz target · targets/<name>/ ─ inputs·outputs·coverage·crashes·state ───┐
 │ ┌─────────────┐ ┌──────────────┐ ┌───────────────┐ ┌───────────────┐    │
 │ │Fuzzer config│ │Fuzzer module │ │state/ snapshot│ │   BP list     │    │
 │ │max_len·runs │ │C++ 1 artifact│ │    (A1)       │ │    (A3)       │    │
 │ └──────┬──────┘ └──────┬───────┘ └───────┬───────┘ └───────┬───────┘    │
 └────────┼───────────────┼─────────────────┼─────────────────┼────────────┘
      if1 │           if2 │ BOTH roles  if2 │             if3 │
    seeds │        ┌──────┴──────┐  snapshot│              BPs│
          ▼        ▼             ▼          ▼                 ▼
 ┌ MASTER · wtf master ───[wtf]─┐   ┌ WORKERS × N · wtf fuzz ─────[wtf]────┐
 │ · owns inputs/ + corpus      │──▶│ · Init / InsertTestcase / Restore    │
 │ · runs Mutator_t → GENERATES │ tc│ · executes: KVM / WHV / bochscpu     │
 │ · aggregates coverage.cov    │◀──│ · detects crash per module rules     │
 │ · distributes over the wire  │res│ · reports coverage + crash back      │
 └──▲───────────────────┬───────┘   └──────────────────┬───────────────────┘
    │                   │                              │
 ┌──┴───────────────┐   ▼                              ▼
 │ seed spool       │ ┌──────────────────┐  ┌──────────────────┐
 │ non-blocking     │ │ A4 · outputs/    │  │ A5 · crashes/    │
 │ read by Mutator_t│ │ minset(--runs=0) │  │ all workers      │
 └──▲───────────────┘ └────────┬─────────┘  └────────┬─────────┘
    │                          │                     │
 ┌──┴──────────────────────┐   │                     │
 │ LLM seed gen · SIDECAR  │   │                     │
 │ separate process  [LLM] │◀── plateau on coverage.cov (read from MASTER)
 │ slow clock              │   │                     │
 └─────────────────────────┘   │                     │
════ ③ SECURITY ANALYSIS ══════════════════════════════════════════════════
                               ▼                     ▼
     ┌──────────────────────────┐  ┌───────────────────────────────────────┐
     │ wtf run --trace-type=cov │  │ Crash dedup             · signal 1    │──┐
     │ on minset          [wtf] │  │ stack hash(static)·cross-worker·no LLM│  │
     └────────────┬─────────────┘  └───────────────────┬───────────────────┘  │
                  ▼                                    ▼                      │
     ┌──────────────────────────┐  ┌───────────────────────────────────────┐  │
     │ symbolizer-rs            │  │ Crash classification    · signal 2    │──┤
     │ --style modoff           │  │ fault addr·regs·capstone·no LLM       │  │
     └────────────┬─────────────┘  └───────────────────┬───────────────────┘  │
                  ▼                                    ▼                      │
     ┌──────────────────────────┐  ┌───────────────────────────────────────┐  │
     │ lighthouse               │  │ Deterministic replay    · signal 3    │──┤
     │ coverage report          │  │ wtf run --input · N× bochscpu   [wtf] │  │
     └──────────────────────────┘  └───────────────────┬───────────────────┘  │
                                                       ▼                      │
                                   ┌───────────────────────────────────────┐  │
                                   │ Execution trace                       │  │
                                   │ wtf run --trace-type=rip/tenet  [wtf] │  │
                                   └───────────────────┬───────────────────┘  │
                                                       ▼                      │
                                   ┌───────────────────────────────────────┐  │
                                   │ symbolizer-rs → Tenet   · signal 4    │──┤
                                   │ walk back from the fault              │  │
                                   └───────────────────┬───────────────────┘  │
  ┌──────────────────┐                                 ▼                      │
  │ A2 · pseudo-C    │───────────▶┌───────────────────────────────────────┐   │
  │ from ①           │            │ Reverse-engineer        · signal 5    │   │
  └──────────────────┘            │ Ghidra pseudo-C + Tenet         [LLM] │   │
                                  └───────────────────┬───────────────────┘   │
                       5 independent signals ─────────┤◀─────────────────────┘
                                                      ▼
                                  ┌───────────────────────────────────────┐
                                  │ LLM triage (DSPy)               [LLM] │
                                  │ multi-signal verdict · 550B           │
                                  └───────┬───────────────────┬───────────┘
                                confirmed │                   │ false positive
                                          ▼                   ▼
                          ┌───────────────────────┐  ┌────────────────────┐
                          │ Report                │  │ Discard            │
                          │ confirmed · GHSA md   │  │ kept for eval      │
                          └───────────────────────┘  └────────────────────┘
```

**`[wtf]` marks the five places wtf itself executes:** the master, the workers, the
harness-validation trace, the deterministic replay, and the crash trace generation.
`[LLM]` marks our layer. Everything unmarked is a companion tool or our own code —
note in particular that **`!snapshot`, `symbolizer-rs`, and `lighthouse` are separate
tools, not wtf**.

Ownership: **wtf-owned** = snapshot acquisition, all of ②, deterministic replay.
**LLM layer (ours, not wtf)** = fuzz entry selection, LLM-generated input struct,
LLM seed gen, reverse-engineering assist, DSPy triage. Everything else = standard
tooling. Keep this distinction in the writeup: the LLM boxes sit *inside* the wtf
region positionally but are our contribution, not wtf features.

### 3.2 Complete edge list — verify EVERY edge exists

Interfaces are what break. This is the authoritative list; gates in §8 check
subsets of it.

**① internal**
1. `target_binary` → `snapshot.break_at_entry`
2. `target_binary` → `ghidra.analyze`
3. `ghidra.fuzz_entry_selection` → `snapshot.break_at_entry` *(the entry address tells the snapshotter where to break)*
4. `ghidra.fuzz_entry_selection` → `ghidra.decompile`
5. `ghidra.fuzz_entry_selection` → `ghidra.bb_enumerate`
6. `snapshot.break_at_entry` → `snapshot.windows_kd` **or** `snapshot.linux_gdb`
7. `snapshot.windows_kd` → **A1 snapshot**
8. `snapshot.linux_gdb` → **A1 snapshot**
9. `ghidra.decompile` → **A2 pseudo-C cache**
10. `ghidra.bb_enumerate` → **A3 coverage BP list**

**① → ② (the three cross-stage edges — most often forgotten)**
11. **A1 snapshot** → `fuzz_target.snapshot`
12. **A2 pseudo-C cache** → `fuzzer_module.llm_input_struct`
13. **A3 coverage BP list** → `fuzz_target.bp_list`

**② internal**
14. `fuzzer_module.llm_input_struct` → `fuzzer_module.bus`
15. `fuzzer_module.insert_testcase` → `fuzzer_module.bus`
16. `fuzzer_module.restore_hook` → `fuzzer_module.bus`
17. `fuzzer_module.manual_tweaks` → `fuzzer_module.bus`
18. `fuzzer_module.bus` → `fuzz_target.fuzzer_module`
19. `fuzz_target.fuzzer_config` → **interface 1** → `master.corpus`
20. `fuzz_target.snapshot` → **interface 2** → `worker[i].execute` *(every worker needs the snapshot)*
21a. `fuzz_target.fuzzer_module` → **interface 2** → `master.mutator` *(the master loads the module too, and uses its `Mutator_t` to generate)*
21b. `fuzz_target.fuzzer_module` → **interface 2** → `worker[i].execute` *(the worker loads the same module and uses `Init` / `InsertTestcase` / `Restore`)*
22. `fuzz_target.bp_list` → **interface 3** → `worker[i].execute` *(breakpoints installed per worker at execution setup)*
23. `master.corpus` → `master.mutator` *(**MUTATION/GENERATION HAPPENS ON THE MASTER**, not on the worker)*
23b. `master.mutator` → `worker[i].execute` *(generated testcase handed out over the wire — NOT a local directory read)*
24. `worker[i].execute` → `worker[i].coverage` *(per-worker local coverage)*
25. `worker[i].coverage` → `master.aggregate_coverage` *(worker reports back)*
26. `master.aggregate_coverage` → `master.corpus` *(requeue on new coverage — decided at the MASTER, fast clock, no LLM)*
27. `master.aggregate_coverage` → `slow_clock.llm_seed_gen` *(plateau trigger, computed on AGGREGATE coverage)*
28. **A2 pseudo-C cache** → `slow_clock.llm_seed_gen` *(the LLM reads decompiled code to reason about unreached branches)*
29. `slow_clock.llm_seed_gen` → `master.corpus` *(new seeds, via the master's documented ingest path — see §12)*
30. `master.corpus` → **A4 corpus artifact**
31. `worker[i].execute` → `master.crash_collect` → **A5 crashes artifact** *(confirm whether crashes are written worker-side, master-side, or both)*

**② → ③ and ③ internal**
32. **A4** → `analysis.cov_trace_gen` *(`wtf run --trace-type=cov` on the minset)*
32b. `analysis.cov_trace_gen` → `analysis.symbolize_cov` *(`symbolizer-rs --style modoff`)*
32c. `analysis.symbolize_cov` → `analysis.lighthouse_report`
33. **A5** → `analysis.crash_dedup`
34. `analysis.crash_dedup` → `analysis.crash_classification`
35. `analysis.crash_classification` → `analysis.deterministic_replay`
36. `analysis.deterministic_replay` → `analysis.trace_gen` *(`wtf run --trace-type=rip` / `tenet`)*
36b. `analysis.trace_gen` → `analysis.symbolize_trace` *(`symbolizer-rs`)*
37. `analysis.symbolize_trace` → `analysis.reverse_engineer`
37b. **A2 pseudo-C cache** → `analysis.reverse_engineer`
38. `analysis.crash_dedup` → `analysis.llm_triage` *(signal 1 — bucket id, hit count)*
39. `analysis.crash_classification` → `analysis.llm_triage` *(signal 2 — fault addr, regs, type)*
40. `analysis.deterministic_replay` → `analysis.llm_triage` *(signal 3 — reproduced, deterministic, backend)*
41. `analysis.symbolize_trace` → `analysis.llm_triage` *(signal 4 — **dynamic**: the path actually executed)*
41b. `analysis.reverse_engineer` → `analysis.llm_triage` *(signal 5 — **static**: pseudo-C + disasm)*
42. `analysis.llm_triage` → `report` *(verdict == confirmed)*
43. `analysis.llm_triage` → `discard` *(verdict == false_positive)*

Edges 38–41b implement **multi-signal independence**: five signals whose errors are
uncorrelated, so one can correct another. Signals 4 and 5 are deliberately separate —
one is dynamic (what executed), one is static (what the code says). Do not collapse
them into a single linear-chain input; triage must receive all five explicitly.

**Note the fan-out at edges 20–22.** Interface 1 (initial seeds) goes to the master
only. Interfaces 2 and 3 are delivered to *every worker*, not once to a single
engine. Getting this backwards is the classic distributed-fuzzing wiring bug.

**The fuzzer module is ONE artifact loaded by BOTH roles (edges 21a/21b).** Both
`master --name <m>` and `fuzz --name <m>` load the same module; each uses a
different part of it:

| Registration slot | Runs on | Purpose |
|---|---|---|
| `CustomMutator_t::Create` → `GetNewTestcase` / `OnNewCoverage` | **master** | generate test-cases; observe new coverage |
| `Init` | **worker** | one-time setup in the guest |
| `InsertTestcase` | **worker** | write the test-case into guest memory |
| `Restore` | **worker** | per-iteration state reset |
| crash / end-of-test-case conditions | **worker** | the crash oracle itself |

Do not model the module as belonging to one role. `tests/gates/test_graph.py` must
assert both 21a and 21b are live — a build where only the worker loads the module
means the master silently falls back to a built-in mutator and **every LLM seed is
ignored**.

Keep this as machine-checkable data in `arch/graph.yaml`;
`tests/gates/test_graph.py` asserts every edge has an implemented call path or
artifact handoff, and that `worker[i]` edges are validated for **i > 1** (not just
a single worker). Track live vs pending edges in `docs/PROGRESS.md`.

---

## 4. Environment & prerequisites

Record everything installed, with versions, in `docs/ENVIRONMENT.md`.

**Already present:** the `wtf` source tree. Locate it; do not re-clone.

**Build wtf:** follow the cloned repo's own instructions (CMake-based). Determine
from the source which backends exist on this host:
- `bochscpu` — full emulation, slowest, most deterministic. **Use for development
  and for deterministic replay.**
- `whv` — Windows Hypervisor Platform (Windows host).
- `kvm` — Linux host, fastest.
Record which backend is used where in `config/fuzz.yaml`.

**wtf is a master + N-worker distributed system, not one process.** Read §12 before
CP4 — it governs where the corpus lives, where coverage is aggregated, and where
the slow clock attaches. Treating wtf as single-node will produce a seed-injection
path that silently never executes.

**Per-target directory tree** — wtf expects exactly these five directories under
`targets/<name>/` (see §13.1). Create them before anything else:
`inputs/` (seed test-cases), `outputs/` (minset), `coverage/` (`.cov` files),
`crashes/`, `state/` (`mem.dmp`, `regs.json`, `symbol-store.json`).

**Snapshot tool:** snapshots are **not** taken by wtf itself. Install the separate
`0vercl0k/snapshot` project — a WinDbg/KD extension DLL loaded with `.load` and
invoked as `!snapshot <state_path>`. It writes `regs.json` and `mem.dmp`.

**symbolizer-rs:** install `0vercl0k/symbolizer-rs`. Required to symbolize execution
and coverage traces (§13.3). Without it, traces cannot be loaded into lighthouse or
Tenet.

**Ghidra:** install it, with **headless** operation (`analyzeHeadless`) working for
batch BB-enumeration and decompilation.

**GhidraMCP:** *do not install yet.* Install at **CP6**, when the LLM first needs
on-demand decompilation. Procedure in CP6.

**Python 3.11+**:
| Library | Purpose |
|---|---|
| `pydantic` | data contracts (§6) — all inter-stage payloads are pydantic models |
| `pyyaml` | config loading |
| `httpx` | HTTP client for the OpenAI-compatible LLM endpoint |
| `openai` | optional convenience client for the same endpoint |
| `dspy` | triage prompt program + optimization (CP9) |
| `pytest` | the interface gates |
| `loguru` | structured logging with a `clock=fast\|slow` field |
| `jinja2` | GHSA Markdown report templating |
| `capstone` | disassembly around a fault address during classification |
| `fastapi` + `uvicorn` | optional dashboard (CP10) |

**Platform debuggers:** Windows — Debugging Tools for Windows (WinDbg/KD), driven
by wtf's own snapshot script. Linux — `gdb` with wtf's Linux snapshot script;
**ASLR must be disabled** when taking the snapshot.

---

## 5. Repo layout

```
arch/
  contracts.py          # pydantic models (§6)
  graph.yaml            # the §3.2 edge list, machine-readable
  addr.py               # static <-> runtime address conversion (§9)
config/
  llm.yaml              # NCHC endpoint, auth, model routing (§7)
  fuzz.yaml             # backend, plateau thresholds, dedup params, budgets
  target.yaml           # binary path, fuzz entry, injection spec
prep/
  ghidra_headless.py    # drive analyzeHeadless: BB enumeration + decompile dump
  bb_to_wtf.py          # BB addresses -> wtf coverage BP file format
  pseudoc_cache.py      # store/query pseudo-C by (module, address)
  entry_select.py       # LLM picks the fuzz entry (slow clock)
  snapshot_win.py       # wrap wtf's Windows/KD snapshot procedure
  snapshot_linux.py     # wrap wtf's Linux/GDB procedure (ASLR off)
fuzzer/
  module/               # the wtf fuzzer module, C++ (InsertTestcase, restore)
  build.py              # build wtf + our module
  master.py             # launch/supervise the wtf master; read aggregate state
  workers.py            # launch/supervise N workers; restart on death
  run.py                # campaign entry point: master + worker pool
  corpus.py             # seed ingest via the master's ACTUAL path (see §12.1)
engine_bridge/
  coverage.py           # read coverage state from wtf output -> CoverageSummary
  plateau.py            # plateau detector; computes coverage frontier
  crash_watch.py        # watch wtf crash output -> CrashRecord
llm/
  client.py             # OpenAI-compatible client + role routing + usage log
  sidecar.py            # the slow-clock process: plateau watch + seed gen loop
  seed_gen.py           # slow-clock seed generation (reads pseudo-C)
  spool.py              # seed spool writer; ownership rules per RULE 4
  ghidra_mcp.py         # GhidraMCP client (CP6)
  prompts/              # prompt templates (separate artifacts from this doc)
analysis/
  dedup.py              # stack-hash bucketing — NO LLM
  classify.py           # fault addr / regs / fault type — NO LLM
  replay.py             # deterministic replay via `wtf run` — NO LLM
  trace.py              # `wtf run --trace-type` + symbolizer-rs — NO LLM
  coverage_report.py    # cov traces -> symbolizer-rs -> lighthouse — NO LLM
  reverse.py            # pseudo-C + disasm context for the crash site
  triage.py             # DSPy multi-signal triage (CP9)
  report.py             # assemble GHSA Markdown from verdicts
orchestrator/
  scheduler.py          # supervises master + N workers + slow-clock sidecar (§12.2)
eval/
  planted_bugs/         # planted-bug targets + ground-truth labels
  baseline.py           # vanilla wtf vs LLM-guided comparison harness
dashboard/app.py        # optional
tests/gates/            # one file per checkpoint gate
docs/
  PROGRESS.md  DECISIONS.md  DEVIATIONS.md  ENVIRONMENT.md  RESULTS.md
```

---

## 6. Data contracts

Define as **pydantic models** in `arch/contracts.py` before writing any stage.
Every stage boundary passes one of these; serialize to JSON on disk so each stage
is independently runnable and testable.

```python
class FuzzEntry(BaseModel):
    module: str
    symbol: str | None
    static_addr: int        # Ghidra static address space
    rationale: str          # why the LLM chose it
    input_param: str        # register/stack slot/pointer carrying the input
    size_param: str | None  # register/slot carrying the length, if any

class BasicBlock(BaseModel):
    module: str
    static_addr: int
    function: str | None

class PseudoCEntry(BaseModel):
    module: str
    static_addr: int
    function: str
    code: str

class SnapshotRef(BaseModel):
    path: str               # the state/ directory wtf consumes
    os: Literal["windows", "linux"]
    mem_dmp: str            # state/mem.dmp
    regs_json: str          # state/regs.json
    symbol_store_json: str | None  # state/symbol-store.json — REQUIRED on linux
    module_base: int        # runtime base of the target module in the snapshot
    ghidra_image_base: int  # static base, for addr conversion (see §9)
    entry_runtime_addr: int
    aslr_disabled: bool     # must be True for linux

class SeedRecord(BaseModel):
    seed_bytes: bytes
    origin: Literal["initial", "mutation", "llm_seed_gen"]
    rationale: str | None   # for llm_seed_gen: which branch it targets

class CoverageSummary(BaseModel):
    tick: int
    total_edges: int        # BPs hit
    new_edges: int          # since last tick
    plateau_ticks: int
    corpus_size: int
    crash_bucket_count: int
    frontier: list[int]     # covered BBs whose successors are still unreached

class CrashRecord(BaseModel):
    input_bytes: bytes
    fault_type: str         # access-violation / abort / illegal-insn / timeout
    fault_runtime_addr: int
    fault_static_addr: int  # de-slid — see §9
    registers: dict[str, int]
    backtrace: list[int]    # static addrs where recoverable
    coverage_delta: int
    worker_id: str | None   # which worker found it (§12.5)
    backend: Literal["bochscpu", "whv", "kvm"]  # matters for determinism (§13.5)
    timestamp: float

class CrashBucket(BaseModel):
    bucket_id: str          # stack hash
    representative: CrashRecord
    hit_count: int

class ReplayResult(BaseModel):
    bucket_id: str
    reproduced: bool
    deterministic: bool     # same fault addr across N replays
    replays: int
    backend: Literal["bochscpu", "whv", "kvm"]  # only bochscpu is fully det.
    notes: str

class TraceRef(BaseModel):
    bucket_id: str
    trace_type: Literal["rip", "tenet"]
    raw_path: str           # wtf output
    symbolized_path: str    # symbolizer-rs output
    reached_fuzz_entry: bool  # sanity: did it even enter the target parser?

class TriageVerdict(BaseModel):
    bucket_id: str
    verdict: Literal["confirmed", "false_positive"]
    confidence: float
    cwe_guess: str | None
    exploitability: Literal["dos", "info_leak", "possible_rce", "unknown"]
    root_cause: str
    signals_used: list[str]        # must name all four when available
    reproducer_input_path: str
```

---

## 7. LLM backend (NCHC / AIS3)

### 7.1 Getting the API details — do this yourself
Endpoint reference: **https://github.com/chunying/ais3-ai-infra/**. This document
deliberately does **not** contain the base URL or auth scheme (automated fetching
of that repo was blocked). At CP5:

1. Read that repo's README and any example client code.
2. Extract: base URL, auth header/token mechanism, exact model-name strings,
   context limits, rate limits, streaming support.
3. Write them into `config/llm.yaml`. **Never hardcode a URL or token in source.**
4. Record findings in `docs/ENVIRONMENT.md`.

Assume an **OpenAI-compatible** `POST /v1/chat/completions` taking
`{model, messages, temperature, max_tokens}` unless the README says otherwise.

### 7.2 Available models and routing
Confirm exact strings against the endpoint's model list; observed names:

```
ais3/llama-3.1-8b        ais3/gemma-4-12b        ais3/nemotron-cascade-2-30b
ais3/llama-guard-3-8b    ais3/gemma-4-26b        ais3/llama-3.3-70b
                                                 ais3/nemotron-3-ultra-550b
```

| Role | Model | Why |
|---|---|---|
| Seed generation (high volume, frequent) | `ais3/gemma-4-12b` or `ais3/llama-3.1-8b` | cheap, fast; no deep reasoning needed |
| Fuzz entry selection; reasoning over pseudo-C | `ais3/llama-3.3-70b` or `ais3/nemotron-cascade-2-30b` | real code comprehension, runs rarely |
| Optional crash-bucket pre-filter | `ais3/gemma-4-26b` | drop obviously-benign buckets before the big model |
| Deep crash triage + root cause | `ais3/nemotron-3-ultra-550b` | strongest reasoning, applied where judgment matters |

`ais3/llama-guard-3-8b` is a safety classifier — **not part of this pipeline.**

Make routing declarative in `config/llm.yaml` (`role -> model`) so models swap
without code changes. `llm/client.py` takes a **role**, never a model name.

### 7.3 Cost model
NCHC access is a **grant / allocation** (compute credits), **not** per-token
billing. Therefore:
- **Do not** micro-optimize tokens per call; multi-turn reasoning is fine.
- **Do** enforce crash dedup and coverage summarization rigorously. This grant gets
  wasted by sending thousands of duplicate crashes or raw corpus dumps to the 550B
  model — not by a few extra tokens per prompt.
- Log every call (role, model, prompt/completion tokens, latency) to
  `logs/llm_usage.jsonl`. Add a cumulative cap in `config/llm.yaml`; refuse calls
  past it and log loudly.

---

## 8. CHECKPOINTS

Each: goal → implementation detail → **INTERFACE GATE**. Implement the gate as
`tests/gates/test_cpN.py`; append results to `docs/PROGRESS.md`. Never proceed on a
failing gate.

### CP0 — Scaffold, contracts, config, graph
Create §5's layout. Implement `arch/contracts.py` (§6) and `arch/graph.yaml`
(every edge from §3.2, including the lettered sub-edges, each `status: pending`). Implement
`tests/gates/test_graph.py`: loads the YAML and asserts the graph is well-formed —
no orphan nodes, every node reachable from `target_binary`, every artifact both
produced and consumed.

**GATE 0:** contracts import cleanly; graph YAML parses; every edge in §3.2 present;
graph test passes; `docs/PROGRESS.md` lists every edge as pending.

### CP1 — Build wtf and run its own example unmodified
Locate the cloned tree. Build per its own instructions (Visual Studio Developer
Command Prompt → `src/build/build-release.bat` for Ninja, or
`build-release-msvc.bat` for a VS solution; prebuilt binaries also exist in the
repo's Releases/CI artifacts). Run **one bundled example target end-to-end,
unmodified**, on the `bochscpu` backend.

**Use `fuzzer_tlv_server`, not `fuzzer_hevd`.** Both ship as examples, but
`hevd` is a *kernel* IOCTL target while `tlv_server` is a **user-mode network
parser** — the same shape as our real target — and it additionally demonstrates the
two things we need most: a **custom `Mutator_t`** and **multi-packet delivery** in
one session. Download `target-tlv_server.7z` from the repo's Releases and extract
into `targets/`.

Run all three verbs so their semantics are understood before designing around them:
`master` (server; `--name`, `--max_len`, `--runs`, `--address`, `--inputs/--outputs/--crashes`),
`fuzz` (client; `--name`, `--backend`, `--limit`), and
`run` (single test-case or folder; `--input`, `--trace-type`).

This is the single most important de-risking step: it proves the engine works on
this host before any of our code exists.

While doing it, learn and **write into `docs/DEVIATIONS.md` as "observed wtf
behaviour"**: the CLI verbs and flags, the snapshot input file layout, the
coverage-breakpoint file format, where corpus and crash outputs land, and how
coverage is reported. Everything downstream depends on these exact formats.

**GATE 1:** wtf builds; a bundled example fuzzes ≥60s on `bochscpu` with nonzero
coverage; corpus and crash output paths identified; `docs/DEVIATIONS.md` records
the actual CLI, snapshot format, BP-file format, and output layout.

### CP2 — Ghidra headless: BB enumeration → wtf coverage BP list (A3)
- `prep/ghidra_headless.py`: drive `analyzeHeadless` with a post-script that walks
  functions and emits every basic block's start address. Scope it — whole-module
  enumeration can be enormous. Support `--scope=function-closure` (only the call
  closure reachable from the fuzz entry) and `--scope=module`. **Default to the
  closure.**
- `prep/bb_to_wtf.py`: convert the address list into **exactly** the coverage
  breakpoint format wtf expects (learned at CP1; wtf's own tooling generates this
  from a different disassembler — match its output format precisely and diff
  against a sample if the repo contains one).
- Emit `BasicBlock` records to `artifacts/a3_bp_list.json` plus the wtf-native file.

**GATE 2 (edges 2, 5, 10):** `a3_bp_list.json` exists with >0 blocks; the
wtf-native BP file passes format validation; a round-trip test parses our file with
the same logic wtf uses.

### CP3 — Snapshot acquisition → A1
**Windows first.**
- `prep/snapshot_win.py`: wrap wtf's documented Windows snapshot procedure
  (kernel debugger). Parameterize the break location. Capture `module_base` and the
  runtime entry address — both required for address normalization (§9).
- `prep/snapshot_linux.py`: wrap wtf's Linux/GDB procedure. **Assert ASLR is
  disabled**, fail loudly otherwise. Log this path as experimental.
- Emit `SnapshotRef` to `artifacts/a1_snapshot.json`.

For CP3 the fuzz entry may be chosen **manually** (a known parser function);
LLM-driven selection arrives at CP6. Record the manual choice in
`config/target.yaml`.

**GATE 3 (edges 1, 6, 7 or 8, 11):** `a1_snapshot.json` exists; wtf loads the
snapshot and executes ≥1 iteration from it; `module_base` and `entry_runtime_addr`
recorded; on Linux, `aslr_disabled == True`.

### CP4 — Fuzzer module + first real fuzzing run (NO LLM)
- `fuzzer/module/`: write the wtf fuzzer module in C++, following
  `fuzzer_tlv_server.cc` exactly. Registration is
  `Target_t target("<name>", Init, InsertTestcase, Restore, CustomMutator_t::Create);`
  — note there are **three** hooks plus an optional mutator factory, including an
  **`Init`** hook that earlier drafts of this document omitted. It must implement:
  - **InsertTestcase** — write the fuzz input into guest memory at the location
    given by `FuzzEntry.input_param`, and set the length register/slot from
    `size_param`. **Structural fixups belong here:** if the parser validates a
    length field or checksum, recompute it after mutation so inputs are not
    rejected at the first check. This is frequently the difference between 5% and
    50% coverage.
  - **Restore/reset** — per-iteration state restoration (snapshot restore handles
    most of it; handle target-specific residual state).
- `fuzzer/build.py`: reproducible build of wtf + our module.
- `fuzzer/run.py`: launch wtf with interfaces 1/2/3 wired — initial seeds → master
  corpus, snapshot + module → the worker, BP list → coverage. Parse wtf's output.
  **CP4 uses ONE worker on `bochscpu`** to keep the first bring-up simple; the
  distributed topology arrives at CP4b (§12.6). Do not hardcode single-worker
  assumptions — put the worker count in config from the start.
- `fuzzer/corpus.py`: corpus read/write. **Do not assume the ingest mechanism** —
  the corpus is owned by the master and the working injection path is resolved at
  CP4b (§12.1). Implement whichever mechanism the source proves correct; if it is
  directory-based, writes must be atomic (temp then rename).
- `engine_bridge/coverage.py`: emit `CoverageSummary` per tick.
- `engine_bridge/crash_watch.py`: watch the crash output dir → `CrashRecord`.

**Harness validation is mandatory, not optional.** The README is explicit that the
execution backends are a black box and that you must generate execution traces to
confirm the module goes through the right paths. Before claiming CP4 done: generate
a trace with `wtf run --name <ours> --input <a seed> --trace-type=rip`, symbolize it
with `symbolizer-rs`, and **visually confirm the trace enters the parser function
chosen in `FuzzEntry`**. A harness that runs and reports coverage but never reaches
the parser is the classic silent failure here.

**GATE 4 (edges 18–26, 30, 31; single worker only):** a ≥10-minute run on the real
target produces nonzero and **growing** coverage; corpus grows via requeue; ≥1
`CoverageSummary` tick written; any crash yields a well-formed `CrashRecord`; **a
symbolized `rip` trace proves execution reaches `FuzzEntry.static_addr`**. **Assert
no LLM call exists in this path** — grep the fast-loop modules for the LLM client
and fail the gate if found.

### CP4b — Distributed bring-up
**Defined in §12.6.** Do it here, between CP4 and CP5 — it resolves the corpus
ingest path and proves coverage aggregation across workers. Do not skip ahead.

### CP5 — LLM client
- Do §7.1 (read ais3-ai-infra, fill `config/llm.yaml`).
- `llm/client.py`: role-based routing, timeouts, bounded retry with backoff, usage
  logging, cumulative budget cap.
- Structured output: for any parsed result, instruct JSON-only output, strip code
  fences, validate against the relevant pydantic model, retry once on failure.

**GATE 5:** every configured role resolves to a model returning a valid
completion; a JSON-constrained call round-trips into a pydantic model; usage log
populated; budget cap triggers when set to a tiny value.

### CP6 — GhidraMCP + pseudo-C cache (A2) + LLM fuzz-entry selection
**This is where GhidraMCP gets installed. Not before.**
- Install **GhidraMCP** now: a Ghidra extension plus an MCP server exposing
  decompilation to an LLM/agent. Find the current release, install the extension
  into Ghidra, run its bridge/server, and verify with a trivial "decompile the
  function at address X" call. Record install steps and version in
  `docs/ENVIRONMENT.md`.
- `prep/pseudoc_cache.py`: build **A2** — batch-decompile the entry's call closure
  via headless Ghidra; store `PseudoCEntry` keyed by `(module, static_addr)` in
  SQLite (preferred, for address-range queries). Provide `get_by_addr(addr)` and
  `get_by_function(name)`.
- `llm/ghidra_mcp.py`: client for on-demand decompilation of addresses missing from
  the cache (needed at triage time when a fault lands somewhere uncached).
- `prep/entry_select.py`: the LLM reads pseudo-C of candidate functions and picks
  the fuzz entry, emitting a `FuzzEntry` including `input_param` / `size_param`.
  This automates what normally requires a reverse-engineering expert — snapshot
  fuzzing's main usability barrier — and is a headline contribution. Log the
  reasoning into `rationale`.

Note in `docs/DECISIONS.md`: decompiled pseudo-C is **lossy** (names lost, types
inferred, inlining flattened). It moves us from grey-box toward white-box but is
**not** source.

**GATE 6 (edges 3, 4, 9, 28, 37):** A2 populated for the entry closure;
`get_by_addr` returns pseudo-C for a known function address; GhidraMCP answers a
live decompile request; `entry_select.py` emits a valid `FuzzEntry` whose
`static_addr` is a real function; **re-run CP3 with the LLM-chosen entry and
confirm the snapshot still loads.**

### CP7 — Slow clock: plateau detection + LLM seed generation
- `engine_bridge/plateau.py`: detect plateau on the **master's aggregate** coverage
  (never one worker's) using `plateau_execs_threshold` — total executions without
  new coverage, not wall-clock time (§12.3). Also compute the **coverage frontier**:
  covered basic blocks with unreached successors. The frontier is the actionable
  signal.
- `llm/seed_gen.py`: on plateau, send a **compact summary** — `CoverageSummary` +
  frontier + pseudo-C of the functions containing frontier blocks. Ask for concrete
  inputs that reach the unreached branches (magic values, length/checksum-consistent
  frames, required orderings). Return `SeedRecord`s with `origin="llm_seed_gen"` and
  a `rationale` naming the target branch. Write them into the master's corpus via
  `fuzzer/corpus.py`, using the ingest path resolved at CP4b.
- **Never send the raw corpus or a full coverage bitmap to the LLM.** Summary plus
  targeted pseudo-C only.
- `orchestrator/scheduler.py`: supervise master + N workers + the **slow-clock
  sidecar as a separate process** (§12.2). The master is on the fast path — an LLM
  call inside it stalls every worker. Slow clock is **event-driven** (plateau, or
  crash-bucket count over threshold), never a fixed timer.

**GATE 7 (edges 27, 29; see §12.6 amendment):** an induced plateau (e.g. start from a deliberately poor
seed) triggers exactly one seed-gen call; generated seeds land in the corpus and
are demonstrably executed; **coverage increases after injection** on ≥1 target
(record before/after — this is a headline result); timing log shows the fast loop
never stalled on the LLM.

### CP8 — Crash dedup, classification, deterministic replay (NO LLM)
- `analysis/dedup.py`: bucket by **stack hash** — hash the top N frames of the
  crashing backtrace (N configurable, start at 5), normalized to **static**
  addresses (§9). Where backtrace recovery is unreliable, fall back to
  `(fault_static_addr, fault_type)`. One representative per bucket, with hit
  counts. **Must run before triage** — this is what protects the NCHC allocation.
- `analysis/classify.py`: from fault type, fault address, and registers, derive a
  preliminary characterization: fault kind, read vs write, near-null vs wild, and
  whether the faulting address looks attacker-influenced (compare against bytes
  present in the input). Disassemble around the fault with `capstone` for the
  faulting instruction. **No LLM.**
- `analysis/replay.py`: re-run the representative input with
  `wtf run --name <ours> --input <crash file> --limit <n>` **N times on
  `bochscpu`**, which is the only fully deterministic backend. Emit `ReplayResult`.
  **Interpretation caveat:** `whv` and `kvm` are only deterministic if sources of
  nondeterminism are handled manually (the README's example is patching a
  `rdrand`-using function). So a crash found on `kvm` that will not reproduce may be
  *backend nondeterminism* rather than a state-dependent bug — always re-check
  non-reproducing cases on `bochscpu` before drawing a conclusion, and record which
  backend each judgement came from. A non-reproducing crash is **not** automatically
  benign.
- `analysis/trace.py` (**new — signal 4**): for each bucket representative, generate
  an execution trace with `wtf run ... --trace-type=rip` (and `--trace-type=tenet`
  when deeper context is wanted; Tenet traces are `bochscpu`-only), then symbolize
  with `symbolizer-rs`. This is a **dynamic** signal, independent of the static
  pseudo-C, and it is the main thing that compensates for having no ASAN: it lets
  the analysis walk backwards from the fault to where a bad pointer or length
  originated. Store the trace path on the bucket.
- `analysis/reverse.py`: assemble crash-site context for triage — pseudo-C of the
  faulting function from A2 (or GhidraMCP on demand), plus disassembly and
  register state.

**GATE 8 (edges 33–37):** given a set of raw crashes (synthesize duplicates if
needed), dedup collapses them to a small bucket count with correct `hit_count`;
every bucket has a `ReplayResult`; `reverse.py` returns pseudo-C for each bucket's
fault address; **assert no LLM call occurs anywhere in CP8's path.**

### CP9 — DSPy multi-signal triage + report
- `analysis/triage.py`: a **DSPy** program with a typed signature whose inputs are
  the **four independent signals** and whose outputs are the `TriageVerdict`
  fields. DSPy fits because triage is structured classification + extraction with
  an evaluable metric.
  - Inputs — **five** independent signals: (1) dedup info (bucket id, hit count);
    (2) classification (fault type/addr/regs/attacker-influence); (3) replay result
    (reproduced/deterministic, and on which backend); (4) **symbolized execution
    trace** (dynamic — the path taken into the fault); (5) reverse-engineering
    context (static pseudo-C + disasm). Outputs: verdict, confidence, CWE guess,
    exploitability, root cause, `signals_used`.
  - Signals 4 and 5 are deliberately kept separate: one is dynamic (what actually
    executed), one is static (what the code says). Their errors are uncorrelated,
    which is the whole point of the multi-signal design. Do not merge them.
  - **No single signal decides alone.** Prompt for cross-checking: a
    non-reproducing crash with a wild write is a different case from a
    deterministic near-null read.
  - Distinguish **DoS** (crashing the process — already serious) from **possible
    RCE**.
- **Optimization requires labels.** Use `eval/planted_bugs/` as the labeled set.
  **Split it:** optimize prompts on the train split, report accuracy on a
  **held-out** split. Optimizing and evaluating on the same set is invalid and will
  be caught. Record the split in `docs/DECISIONS.md`.
- Use a cheap model for bootstrap/demo generation and
  `ais3/nemotron-3-ultra-550b` for final triage reasoning.
- **Keep DSPy to triage only in v1.** Do not wrap seed generation in DSPy: its
  metric would require running the fuzzer per candidate — far too slow and
  expensive for an optimization loop. Note as future work.
- `analysis/report.py`: **ordinary code**, not an LLM, assembles the report from
  `TriageVerdict`s — group by bucket, sort by severity, render **GHSA-format
  Markdown** with Jinja2. Only `confirmed` ships; `false_positive` goes to a
  discard log (kept for evaluation, not shipped).

**GATE 9 (edges 38–43):** triage consumes all four signals and `signals_used`
reflects that; verdicts validate against `TriageVerdict`; precision/recall of the
triage decision reported on the **held-out** planted-bug split; the GHSA report
renders with confirmed findings only; discards logged separately.

### CP10 — Evaluation harness, then optional dashboard
- `eval/baseline.py`: **wtf's built-in mutators vs our LLM-guided system** on the
  same target, budget, and initial seeds. wtf ships **libfuzzer** and **honggfuzz**
  mutators — run against **both** so the baseline cannot be dismissed as a weak
  straw man. Measure time-to-first-crash, coverage growth curve, unique crash
  buckets. Ablate: (a) no LLM seed gen (built-in mutator only), (b) no pseudo-C in
  prompts. Without this comparison the project's central claim is unsupported.
- **Corpus minset between runs.** Use `master --runs=0 --inputs=outputs
  --outputs=minset` to minimize the corpus (§13.2). Do this before measuring, so
  runs start from comparable corpora, and periodically during long campaigns — a
  bloated corpus slows the master and makes the LLM's coverage summary noisier.
- `eval/planted_bugs/`: targets with deliberately introduced, documented bugs
  across a mix of classes. This set serves **two** purposes — DSPy training/eval
  and triage accuracy measurement — so it is on the critical path. Build it early
  if there is slack.
- `dashboard/app.py` (optional): FastAPI serving confirmed findings, coverage
  curve, bucket list.

**GATE 10:** baseline vs system numbers for ≥1 target with both ablations;
coverage curves plotted; results written to `docs/RESULTS.md`.

---

## 9. Address normalization — a bug you will hit

Ghidra works in a **static** address space; the running process (and snapshot) uses
a **runtime** base differing by the ASLR/PIE slide. Every address crossing between
them must be converted:

```
static_addr  = runtime_addr - module_base + ghidra_image_base
runtime_addr = static_addr  - ghidra_image_base + module_base
```

Implement **once** in `arch/addr.py` as `to_static()` / `to_runtime()`, taking
`module_base` from `SnapshotRef`. Use it everywhere: BP list generation (static →
runtime for breakpoint installation), crash records (runtime → static before
hashing or pseudo-C lookup), and stack hashing — **always hash static addresses**,
or identical bugs will hash differently across runs.

Add a unit test round-tripping a known function address both directions.

---

## 10. Anti-patterns

- Any LLM call inside the fast loop, or the fast loop blocking on LLM latency.
- Any LLM call inside the **master**. The master serves every worker; blocking it
  stalls the whole campaign. The slow clock is a separate process (§12.2).
- Reading coverage from a single worker, or detecting plateau on non-aggregate
  coverage (§12.3).
- Assuming seeds written to a directory reach the master's corpus without having
  proven it (§12.1). This fails silently — the worst kind of failure here.
- Treating wtf as a single process anywhere in the design.
- Putting mutation/generation on the worker. **Generation happens on the master.**
- Blocking inside `CustomMutator_t::GetNewTestcase()` — it runs per test-case on the
  master and stalls every worker (§12.1).
- Dropping seeds into `inputs/` at runtime and assuming the master picks them up.
  `inputs/` is the startup seed directory; runtime injection goes through the
  mutator (§12.1).
- Declaring the harness working without a symbolized `rip` trace proving execution
  reaches the chosen fuzz entry (CP4).
- Concluding a crash is nondeterministic without re-checking it on `bochscpu` —
  `whv`/`kvm` are not deterministic by default (§13.5).
- Skipping corpus minset, then wondering why the master is slow and the LLM's
  coverage summary is noisy.
- Sending un-deduplicated crashes to the LLM. Dedup **always** comes first.
- Sending the raw corpus or a full coverage bitmap to the LLM. Summaries only.
- Calling the triage stage "verification" (§1).
- Collapsing the four triage signals into one blob, or letting one signal decide.
- Treating a non-reproducing crash as automatically benign.
- Assuming source-level or sanitizer information exists. It does not (§2).
- Hashing **runtime** addresses for dedup (breaks across runs — use static).
- Hardcoding the LLM base URL, token, or model names outside `config/llm.yaml`.
- Inventing a wtf API signature instead of reading the cloned source (RULE 2).
- Building the Linux snapshot path before the Windows pipeline works end-to-end.
- Optimizing DSPy prompts on the same planted-bug split used for reported metrics.
- Declaring a checkpoint done because code compiles. **The gate is the definition
  of done** (RULE 3).

---

## 11. Report framing (for the AIS3 writeup)

- This project is **discovery** (fuzzing). The author's separate paper is
  **verification** (targeted PoC). They sit on opposite sides of the
  discovery/verification line that paper itself draws. State this explicitly to
  preempt "doesn't your paper say fuzzing is unreliable?" — fuzzing is the right
  tool for discovery and the wrong tool for verification; the two are complementary
  halves.
- Contribution 1: **LLM-directed snapshot placement** — automating the fuzz-entry
  and injection decisions that normally require a reverse-engineering expert,
  which is snapshot fuzzing's main usability barrier.
- Contribution 2: **Ghidra as unified infrastructure** — one open-source tool
  supplying coverage breakpoints, seed-generation reasoning, and crash-triage
  context, replacing the proprietary-disassembler step in the standard workflow.
- Contribution 3: **migrating multi-signal independence from static verification
  into dynamic crash triage.**
- Limitations to state plainly: the binary-only crash oracle misses silent memory
  corruption; pseudo-C is lossy and is not source; wtf is x86-64 only; the Linux
  snapshot path is experimental.

---

## 12. DISTRIBUTED TOPOLOGY — master + N workers

wtf is **not** a single process. It runs a **master** plus **N worker/client
processes**. The master owns the corpus and aggregates coverage; the workers
execute testcases and report back. Every design decision below follows from that.

**RULE 2 applies with full force here.** Confirm all of the following against the
cloned source before implementing, and record findings in `docs/DEVIATIONS.md`:
the master and worker CLI verbs and flags, the transport between them, how many
workers one master can serve, where crashes are written, and — most importantly —
the corpus ingest question below.

### 12.1 RESOLVED — seeds enter through a custom `Mutator_t` on the master

Earlier drafts left this open. The README settles it: wtf's **sanctioned extension
point** is a custom mutator/generator, and the master invokes it.

- The master owns the corpus and **generates** test-cases; the `--name` option tells
  the master which fuzzing module to use so it can call that module's generator.
- Subclass `Mutator_t` and register the factory when defining the module:
  `Target_t target("target", Init, InsertTestcase, Restore, CustomMutator_t::Create);`
- `Mutator_t` exposes two virtuals: `GetNewTestcase(const Corpus_t &Corpus)` and
  `OnNewCoverage(const Testcase_t &Testcase)`.
- `fuzzer_tlv_server.cc` contains a complete `CustomMutator_t` example. **Read it
  before writing ours.**

**Therefore the design is:**

1. Our `CustomMutator_t::GetNewTestcase()` normally delegates to a built-in mutator
   (libfuzzer or honggfuzz, both shipped with wtf). When the LLM **seed spool** is
   non-empty, it returns an LLM-generated seed instead.
2. The spool is a directory or queue written by the slow-clock sidecar.
3. `OnNewCoverage()` is the natural plateau signal — record the testcase counter at
   each callback; no callback for N testcases means plateau.

**HARD CONSTRAINT:** `GetNewTestcase()` runs on the master in the hot path — it is
called to produce every single test-case. It **must not block**. Reading the spool
must be non-blocking (try-lock / stat-and-skip); on empty, fall straight through to
the built-in mutator. A blocking read here stalls every worker. This is RULE 1
applied to the master.

Do **not** rely on dropping files into `inputs/` and hoping the master rescans;
`inputs/` is the startup seed directory. The mutator path above is the supported
runtime injection mechanism.

For plateau detection there is also a simpler, C++-free option: the master
maintains an aggregated `coverage.cov` file (§13.4). The sidecar can watch that file
for growth. Prefer this for v1 monitoring, and use `OnNewCoverage()` only if finer
granularity turns out to be needed.

### 12.2 Where the slow clock lives

The LLM seed generator runs as a **separate process**, not inside the master and
not inside a worker. Reasons:

- The master is **on the fast path** — it serves testcases to every worker. Any LLM
  latency inside the master stalls the entire worker pool. This is RULE 1 applied to
  the distributed case: *the master counts as fast clock.*
- A worker is the wrong home too: each worker sees only its own coverage, so a
  plateau judgement made there is based on a fraction of the campaign.
- A separate process can be restarted, upgraded, or paused without stopping the
  fuzzing campaign.

So: `orchestrator/scheduler.py` supervises three kinds of process — one master, N
workers, and one slow-clock sidecar. The sidecar reads **aggregate** state from the
master and writes seeds back through the §12.1 ingest path.

### 12.3 Plateau detection must use aggregate coverage

Plateau is computed on the **master's aggregate** coverage, never on one worker's.
Two consequences:

- `engine_bridge/coverage.py` reads master-side state. If per-worker coverage is
  also available, keep it for diagnostics only.
- **Recalibrate the threshold for worker count.** Plateau should be defined in terms
  of *total executions without new coverage*, not wall-clock time — with 16 workers
  the campaign burns through the same execution budget roughly 16× faster, so a
  wall-clock threshold tuned on one worker will fire far too late. Store both
  `plateau_execs_threshold` (primary) and a wall-clock safety bound in
  `config/fuzz.yaml`.

### 12.4 Config additions (`config/fuzz.yaml`)

```yaml
topology:
  master:
    host: 127.0.0.1
    port: <from source>
    backend: <if the master runs one>
  workers:
    count: 4            # start at 4; scale after CP4b passes
    backend: kvm        # or whv / bochscpu
    pin_cpus: true      # one worker per physical core; document the host core count
  corpus_ingest: unresolved   # (a) dir-rescan | (b) restart-required | (c) control-api
plateau:
  plateau_execs_threshold: <calibrate>
  wall_clock_bound_s: <safety net>
```

Development note: use **1 worker on `bochscpu`** while building CP2–CP7 (fast to
reason about, deterministic). Scale to N workers on `kvm`/`whv` only after CP4b's
gate passes. Deterministic replay (CP8) always uses a single `bochscpu` worker.

### 12.5 Crash collection across workers

Determine whether crashes are written by each worker locally, forwarded to the
master, or both. Then:

- `engine_bridge/crash_watch.py` must collect from **all** sources, and tag each
  `CrashRecord` with the originating worker id.
- The **same crash will be found independently by multiple workers.** Dedup (CP8)
  therefore also collapses cross-worker duplicates — this makes dedup *more*
  important than in the single-node design, not less, because raw crash volume
  scales with worker count while the number of distinct bugs does not.
- Add `worker_id: str | None` to `CrashRecord` in `arch/contracts.py`.

### 12.6 New checkpoint — CP4b (insert between CP4 and CP5)

**CP4b — Distributed bring-up.**

- `fuzzer/master.py`: launch and supervise the master; expose a read path for
  aggregate coverage and corpus size.
- `fuzzer/workers.py`: launch and supervise N workers; each gets interfaces 2 and 3
  (snapshot, module, BP list); restart a dead worker without killing the campaign.
- Resolve **§12.1** and record the answer.
- Verify coverage aggregation is real: run with N=1, note the coverage number; run
  with N=4 on the same target and budget; confirm the master's aggregate reflects
  all workers rather than tracking a single one.

**GATE 4b (edges 19–26, 30, 31):** master starts and serves ≥2 workers
simultaneously; each worker executes and reports; master aggregate coverage is
strictly greater than any individual worker's contribution on a target where
workers diverge; killing one worker does not stop the campaign and the worker is
restarted; **the corpus ingest path is resolved and documented**, with a test that
injects a known seed by that mechanism and proves a worker executed it; crash
records carry `worker_id`. **Assert no LLM call in master or worker paths.**

CP7's gate is then amended: the plateau must be detected on aggregate coverage with
**N > 1 workers running**, and the injected seed must be shown to execute on a
worker — proving the full slow-clock → master → worker path, not just a file write.

---

## 13. README-DERIVED REFERENCE (authoritative over earlier sections)

Everything here comes from wtf's own README. Where an earlier section of this
document disagrees, **this section wins** — and RULE 2 still applies: confirm
against the cloned source, which wins over both.

### 13.1 Per-target directory tree
Under `targets/<name>/`:
| Dir | Contents |
|---|---|
| `inputs/` | input test-cases (startup seeds) |
| `outputs/` | current **minset** files |
| `coverage/` | `.cov` files |
| `crashes/` | saved crashes |
| `state/` | `mem.dmp`, `regs.json`, `symbol-store.json` |

`symbol-store.json` is a JSON file used **on Linux** to know where to place
breakpoints, because those platforms have no symbols/dbgeng support. On Windows wtf
regenerates it at runtime. **Add it to `SnapshotRef` in `arch/contracts.py`** — a
Linux run without it cannot place coverage breakpoints.

### 13.2 The three subcommands
- **`master`** — the server/brain. Keeps all state: aggregated code-coverage and the
  corpus; **generates and distributes** test-cases to clients.
  Options: `--name` (fuzzing module, also lets the master call our generator),
  `--max_len` (test-case size cap), `--runs` (number of test-cases to generate),
  `--address` (listen address), `--target`, and overrides
  `--inputs` / `--outputs` / `--crashes`.
- **`fuzz`** — a client node. Runs a distributed test-case and reports coverage and
  result back. Options: `--name`, `--backend`, `--limit` (max instructions per
  test-case; **meaning varies by backend**).
- **`run`** — run one test-case or a whole folder. Options: `--input`,
  `--trace-type`, `--trace-path`. This is our **deterministic replay** and **trace
  generation** mechanism.

**Minset** is `master` with `--runs=0`:
`master --name <n> --max_len=<n> --runs=0 --inputs=outputs --outputs=minset`
(needs a server plus as many clients as usual).

### 13.3 Traces — two uses, both required
- `--trace-type=rip` — RIP trace.
- `--trace-type=tenet` — loadable in the Tenet trace explorer (**bochscpu only**;
  exiting VMX is expensive on the others). Lets you start at a crash and walk
  backwards to find where a pointer came from.
- `--trace-type=cov` — code-coverage traces, written to `--trace-path`.
- Symbolize with **`symbolizer-rs`**; raw traces are not loadable in lighthouse.
  For coverage: `symbolizer-rs --trace <dir> -o <dir> --style modoff`, then load in
  **lighthouse**.

Use 1: **harness validation** — the backends are a black box; traces are the only way
to confirm the module reaches the intended code. Use 2: **triage signal 4** — a
dynamic signal independent of static pseudo-C, and the main compensation for having
no ASAN.

### 13.4 Coverage
- `bochscpu`: full-system coverage for free; **edge coverage via `--edges`**.
- `whv` / `kvm`: coverage via **software breakpoints**, which requires a JSON list of
  basic-block virtual addresses. wtf ships `scripts/gen_coveragefile_ida.py` for IDA,
  and the README explicitly states you may generate this JSON with any tool you like
  — **this is what sanctions our Ghidra-based generator (CP2)**. Match the JSON shape
  that wtf loads.
- The master maintains an aggregated **`coverage.cov`** holding the unique
  aggregated coverage. **This is the read path for §12.3 plateau detection** — watch
  it for growth rather than polling per-worker state.

### 13.5 Backend differences that change our design
| | bochscpu | whv | kvm |
|---|---|---|---|
| Coverage | full system, `--edges` | software breakpoints | software breakpoints |
| Demand paging | yes | **no** → slow startup (loads whole dump) | yes, via UFDD |
| Timeout | instruction count (precise) | timer | timer; PMU/PMI if HW supports |
| Traces | full, fastest to produce | supported but slow | supported but slow |
| Determinism | **fully deterministic** | only if nondeterminism handled manually | only if handled manually |
| Speed | ~100× slower than kvm on long runs | ~10× slower than kvm | fastest |

Consequences for us: develop and prototype on **bochscpu**; scale on **kvm**; always
replay on **bochscpu**. Non-reproducibility observed on `kvm`/`whv` may be backend
nondeterminism (the README's example is patching a `rdrand`-using function), not a
property of the bug — re-check on `bochscpu` before judging.

### 13.6 Snapshot workflow
1. Target in a Hyper-V VM, **one virtual CPU, 4GB RAM**.
2. Break at the desired state in **KD**, close to the code to be fuzzed.
3. Load the separate **`0vercl0k/snapshot`** extension and run
   `!snapshot <target>/state` → writes `regs.json` and `mem.dmp`.
4. For **WoW64** targets, issue `!wow64exts.sw` to switch to the 64-bit context
   *before* taking the snapshot.

### 13.7 Fuzzer module surface
`Target_t target("<name>", Init, InsertTestcase, Restore, CustomMutator_t::Create);`
- `Init`, `InsertTestcase`, `Restore` — three hooks (earlier drafts listed two).
- Crash conditions and end-of-test-case conditions are defined **by us** inside the
  module; wtf does not infer them. This is where the CP8 crash oracle actually
  originates — enumerate the conditions explicitly in `docs/DECISIONS.md`.
- Built-in mutators: **libfuzzer** and **honggfuzz**. Custom ones subclass
  `Mutator_t` (`GetNewTestcase`, `OnNewCoverage`).
- **Multi-packet / stateful delivery:** `fuzzer_tlv_server.cc` shows how to deliver
  more than one test-case per session, which the README notes is necessary for
  targets carrying complex state. If our parser needs a handshake or a message
  sequence, model it on that file rather than inventing an approach.

### 13.8 Reference examples
- `fuzzer_tlv_server` — user-mode network TLV parser, custom mutator, multi-packet.
  **Our primary model.**
- `fuzzer_hevd` — kernel-mode IOCTL target. Useful for understanding the tooling, not
  our shape.
Target archives (`target-tlv_server.7z`, `target-hevd.7z`) come from the repo's
Releases and extract into `targets/`.

---

## 14. ADDITIONS BUILT ON TOP OF THIS SPEC

Everything above is the original design. This section records what was **added**
while building it — components this document did not name, and decisions it left
open. It exists because §8's checkpoints are the definition of done (RULE 3), and
**three of the four components below had no checkpoint** — which is exactly why they
were the last things built and the buggiest when finally written (D-055, D-057).

If you extend this project, add the gate first.

### 14.1 One-command setup — `tools/bootstrap.py`

§4 says "record everything installed, with versions, in `docs/ENVIRONMENT.md`". That
is necessary and insufficient: a path recorded in a *document* is not read by any
consumer. The same failure happened **three times** — symbolizer-rs, the
`0vercl0k/snapshot` extension, and Ghidra itself were each installed and working
while every consumer reported them missing, because nothing wrote the path into
`config/` (D-050, D-060).

So: `python -m tools.bootstrap` checks each tool, **records its path into config**,
and reports which of the two it did. It also fetches Ghidra when absent (pinned
version, sha256 verified, into `third_party/`).

**Ghidra is MANDATORY, not a prerequisite among others.** §4 lists it alongside
WinDbg and symbolizer-rs, which understates it now: Ghidra supplies the pseudo-C
from which the model derives the input structure (§14.3) *and* the harness (§14.4),
so **without Ghidra there is no `InsertTestcase` and the fuzzer has nothing to run**.
Three of the four LLM stages read A2 directly.

Two rules for anything added here:

- **Config is consulted LAST**, after the explicit argument and the environment
  variable. A committed path must never win over an env var, or a machine where the
  committed path is wrong cannot be fixed without editing tracked files.
- **The bootstrap never installs anything needing administrator rights** (a
  hypervisor, a guest VM, the Windows SDK). It reports the exact command instead. A
  setup script that half-elevates is worse than one that explains.

### 14.2 Snapshot acquisition is automated — §13.6 by machine

§13.6 describes the snapshot workflow as four manual KD steps, and CP3 wraps them by
**emitting** the command list. That is now executed as well, non-interactively:

```
kd -k com:pipe,port=\\.\pipe\<name>,resets=0,reconnect
   -c ".load <snapshot.dll>; bp <module>!<entry> \"!snapshot -k full <state>; qq\"; g"
```

**The ordering rule, because the obvious form is wrong.** Do **not** write
`-c ".load ...; bp ...; g; !snapshot ...; qq"`. That assumes KD resumes executing the
`-c` string once the breakpoint fires, which KD does not promise. **Attach the
command list to the breakpoint itself.** The breakpoint then *is* the definition of
"the state worth snapshotting" — hitting it is the judgement, so no human has to
decide when to act.

`--wow64` issues `!wow64exts.sw` **before** `bp`/`!snapshot` (§13.6 item 4). After the
fact you capture the 32-bit view, which wtf cannot use, and it surfaces much later as
a puzzling wtf error.

**What is still not automatic, and cannot be:** something must drive the target to
its parser. For a service, `g` never returns until a client connects. `--kd-stimulus`
runs a command for that (`tools/poke_tcp.py` is a generic implementation), but *what*
to send and *on which port* is not derivable from the binary. That is target-specific
**stimulus**, not judgement — do not describe it as a limitation of the automation's
intelligence.

**Status: written, never executed.** No guest VM exists on the development host, so
what is tested is the argv, each refusal, and the Windows quoting — not the
orchestration. Edges 1/6/6b/7/8 remain `pending` and both the code and the README say
"NEVER EXERCISED". Two bugs were nevertheless caught before any VM existed, by
printing the command in `--dry-run` (D-058, D-059) — **the dry-run path is the only
checkable surface here, so build it first.**

### 14.3 LLM-derived input structure — the box §3.1 draws with no gate

§3.1 draws *"LLM-generated input struct / reads pseudo-C (A2)"* and §3.2 gives it
edges 12 and 14. **No gate in §8 covers either**, so it had no definition of done and
stayed a hand-written struct through CP4–CP10 while looking finished on the diagram
(D-055). Recorded as GATE 11.

Two things that must not be undone:

- **The model fills a schema; it never writes C++.** `prep/input_struct.py` produces
  a pydantic-validated `InputSpec` (fields, types, endianness, **whether a length is
  in bytes or elements**, magic values); `fuzzer/codegen.py` — ordinary code —
  renders the C++. Free-form C++ cannot be schema-checked, a compile error surfaces a
  long way from the model that caused it, and RULE 4's "units and encoding are
  stated" cannot be enforced in prose. The concrete failure: the model used U+2011 in
  a comment and MSVC killed the build with C4819 under `/WX` (D-054).
- **The entry's CALLERS go into the prompt.** Whether a parser is called repeatedly
  is a property of the *caller*, not of the parser. Given only `ProcessPacket` the
  model answered `supports_sequence: False`; given `main`'s `recv` loop as well, it
  answered correctly.

Validate against a hand-written module by **layout** (offsets, widths, length
semantics), never by field name — pseudo-C has no names, so comparing names tests the
model's word choice rather than its understanding.

### 14.4 LLM-derived harness — `HarnessSpec`

The same treatment for the harness logic itself: which breakpoints to set, what
counts as a crash, which calls to stub out. `prep/harness_derive.py` derives a
`HarnessSpec` from the entry closure's pseudo-C using the 550B role at temperature
0.0, and `fuzzer/codegen.py --module` renders a complete registered wtf module.

The contract carries one rule worth restating, because it is where a "helpful"
harness silently destroys the campaign: **`Generate()` makes length fields
consistent; writes into guest memory are verbatim.** A harness that repairs a
length field on the way in cannot find a length-handling bug — *the disagreement is
the bug*.

`HarnessSpec` requires **exactly one** `fuzz_entry` breakpoint. Without it nothing is
ever delivered and the campaign runs happily executing the untouched snapshot, at
full speed, reporting coverage.

### 14.5 Pipeline driver — `orchestrator/pipeline.py`

§8 defines no checkpoint for a driver, and the consequence was measurable: an
adversarial pass found **eleven** distinct ways it reported success without doing the
work (D-057). Recorded as GATE 12. The rules that came out of it generalise to
anything that orchestrates stages here:

- **Exit code 0 is not evidence.** `analyzeHeadless` and `wtf` both exit 0 having
  produced nothing. Every stage names the artifact that proves it ran.
- **Existence is not evidence either.** Check content: a zero-byte file, a directory
  where a file belongs, and a `scheduler_result.json` recording `peak_executions=0`
  all "exist".
- **Stages whose work is TIME are never skipped as up-to-date.** A requested
  15-minute campaign must not become zero seconds of fuzzing that points at the
  previous run's advisory.
- **A `--only`/`--from` typo is an error, not a no-op.** Prefix matching also means
  `--from 1` can match stage `10`.
- **Scope belongs in the artifact FILENAME.** A module-scoped export silently
  satisfied `--scope function-closure`, and the reverse dropped 555 breakpoints.
- **The stage ordering is not §3.1's diagram order.** Edges 4 and 5 read as
  "entry first", but the entry is chosen by a model reading pseudo-C, so **A2 at
  module scope must exist before the entry is known**. Then the entry, then
  everything scoped to its closure.

### 14.6 Derived artifact A6 — global data symbols

Added at CP7, not in §3.1's artifact list. Decompilation drops a table's declared
capacity, so the seed generator could not reason about how many entries it took to
exhaust a global array — the exact thing the frontier pointed at. A6 records each
global's address, size, and the gap to the next symbol, produced by the same
`prep/ghidra_headless.py` pass (edge 10b).

### 14.7 Three LLM providers, chosen by which key exists

§7 describes one OpenAI-compatible endpoint. There are now three providers in
`config/llm.yaml`, and **which one runs is decided by which API key resolves**, in
config order, overridable with `SNAPFUZZ_LLM_PROVIDER`. Roles map a model *per
provider*; a role with no entry for the active provider is an error, never a
default — a model nobody chose is how a campaign gets attributed to the wrong one
(D-056).

**Claude is not an OpenAI-compatible endpoint with a different URL.** Four things
break a naive port, and the first one breaks every role:

| | What happens |
|---|---|
| `temperature` / `top_p` / `top_k` | **HTTP 400** on the current models. All seven roles set one. |
| `system` | Top-level field, not a `{"role": "system"}` message (that is a separate, model-gated feature). |
| Response | A **list of blocks**. `content[0].text` is wrong whenever the first block is `thinking` — the default on Opus 5. |
| Policy decline | A **successful 200 with an empty content list** and `stop_reason: "refusal"`. Read `stop_reason` before touching `content`. |

**Do not simply drop the temperature.** The values are documented intent: 0.0 on
`input_struct` because there is exactly one right answer, 0.9 on `seed_gen` because
diversity is the goal. Dropping both makes the second behave like the first.
Translate to `output_config.effort` instead, and get diversity from the sidecar's
`N` independent samples — a mechanism that already exists and needs no sampling
knob (D-063).

**The refusal case is load-bearing for this project specifically.** Triage sends
fault addresses, register dumps and memory-corruption analysis, which is exactly
the material Claude's cyber classifiers screen. So server-side fallbacks are
requested by default and a decline raises a distinct `Refused`: "no verdict could
be obtained" and "the crash is judged benign" must stay different outcomes, or
findings are discarded silently.

Two structural rules that came out of the reshape:

- **One resolver owns the config's shape.** Five places used to read it themselves
  and two had reimplemented the same `.env` reader, BOM handling included (D-064).
- **`orchestrator/pipeline.py` is a deliberate exception** and keeps its own copy,
  because its docstring claims it imports no LLM client and a CP12 test enforces
  that against the *imports*. The duplication is a considered cost of RULE 1, and
  it is commented as such rather than left looking like an oversight.

### 14.8 Linux snapshot preparation — and the step that cannot be automated

§14.2 automates KD end to end. **The Linux flow cannot be**, and the difference is
worth understanding before trying again.

Mid-snapshot, `FuzzBkpt.stop()` calls `wait_for_cpu_regs_dump()`
(`gdb_fuzzbkpt.py:352-369`), which prints *"In the QEMU tab, press Ctrl+C, run the
`cpu` command"* and then spins in `while not REGS_JSON_FILENAME.exists()` — an
unbounded loop. `regs.json` is written only by `cpu`, `cpu` is registered by
`gdb_qemu.py` in the **server** gdb rather than the client one, and nothing stops
that gdb on its own. Reaching its prompt means interrupting it from a terminal.
Contrast §14.2, where hanging the work off the breakpoint removed the need for
anyone to decide when to act.

So `prep/snapshot_linux.py prepare` does the mechanical work and **prints the rest**,
including that step. The first version of it drove gdb anyway and did not perform
the `cpu` step at all: it would have hung in that loop until the timeout and then
reported a stimulus problem — the one explanation guaranteed to be believed and
wrong. If you extend this, that is the failure mode to design against.

Details that are not obvious from the scripts, each of which was a bug first:

- **The working directory is load-bearing.** `gdb_server.sh` and `gdb_client.sh` use
  `../` paths and `gdb_client.sh` sources `./bkpt.py`.
- **`sym_path` is read HOST-side.** FuzzBkpt shells out to `nm` and `readelf -S` on
  it relative to gdb's cwd, so the ELF must be in the work directory — copying it
  only into the guest leaves `bkpt.py` raising inside gdb, with gdb still running
  and no breakpoint installed.
- **`program_name` is compared against `task->comm`, which is `char[16]`.** A name
  longer than 15 characters never matches, so the breakpoint fires and declines to
  stop, forever, with no error.
- **`write_to_store` MERGES.** A second run in the same work directory ships the
  previous binary's symbols alongside the new ones unless the stale file is removed.
- **The stimulus runs INSIDE the guest**, over ssh, and only *after* the breakpoint
  is installed. Same shape as §14.2: target-specific, not derivable.
- **`prepare` knows `module_base`.** `FuzzBkpt` takes `target_base` and `prepare`
  sets it, so the reported `ingest` command has it filled in. `ghidra_image_base`
  and `entry_runtime_addr` stay placeholders on purpose — guessing either puts a
  wrong number into A1, where every address conversion is built on it.

**One prerequisite check to copy the shape of.** "Has `setup.sh` run?" was tested as
`(target_vm / "image").is_dir()`. That directory is *tracked in git*, so the check
could never fire and `check-host` printed "host can acquire" on a fresh clone. It now
looks for a `*.img`. Existence is not evidence (§14.5) applies to directories too.

**One correction to record here, because it is a RULE 2 failure mode the rule does
not name.** Both this project and its README claimed `symbol-store.json` "cannot be
produced on Linux". The citation was accurate — `wtf.cc:195-201` really does say
"You need to generate it from Windows" — and the conclusion was wrong: that branch
fires when the file is *absent*, and `linux_mode` writes it while snapshotting.
**RULE 2 says the source wins over the document. An error message is source that
describes the case where it fires, not the world** (D-062).

