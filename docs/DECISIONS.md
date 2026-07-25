# DECISIONS

Choices CLAUDE.md asks to be recorded, plus the engineering calls made along
the way. Each entry: the decision, the alternatives, and why.

---

# RULE 4 — resolved signatures

RULE 4: *"A signature is not specified until you can write it without
guessing."* Every row of its table, with the source file and line that settled
it. **Unresolved rows are marked as such and must not be coded around** — in
this project each gap produces a silent failure, not an error.

All references are to this clone at `a490929`.

| # | Interface | Status |
|---|---|---|
| R1 | `InsertTestcase` | **RESOLVED** |
| R2 | `Restore` | **PARTIAL** — confirm residual state at CP4 |
| R3 | A3 BP list | **RESOLVED** |
| R4 | `arch/addr.py` | **RESOLVED** |
| R5 | crash oracle | **RESOLVED** |
| R6 | `coverage.cov` | **PARTIAL** — in-memory settled, on-disk writer not found |
| R7 | `FuzzEntry.input_param` | **PER-TARGET** — convention settled, value is per target |
| R8 | `FuzzEntry.size_param` | **PER-TARGET** — same |
| R9 | seed spool ownership | **UNRESOLVED** — CP7 |

---

## R1 — `InsertTestcase`: a false return **aborts the worker**

Signature (`src/wtf/targets.h:16`):

```cpp
using InsertTestcase_t = bool (*)(const uint8_t *, const size_t);
```

Call site (`src/wtf/client.cc:102-104`):

```cpp
if (!Target.InsertTestcase(Buffer.data(), Buffer.size_bytes())) {
  fmt::print("Failed to insert testcase\n");
  std::abort();
}
```

RULE 4 asks: *does a false return mean "skip this testcase" or "abort the
run"?* **It aborts the run** — `std::abort()`, killing the worker process.

So the way to reject a malformed test-case is to **`return true` without doing
anything**. `fuzzer_hevd.cc:21-23` does exactly that for an undersized buffer,
and `:28-30` uses `return false` for an oversized one — a "this cannot happen"
assertion that holds only because `--max_len` caps the size upstream.

This is the single most dangerous row in the table: the intuitive reading
("false means skip") turns a routine malformed input into a dead worker, and
with N workers the campaign would bleed capacity while still looking alive.

**Decided:** our `InsertTestcase` returns `false` **only** for conditions that
indicate the harness itself is broken. Every input-shape rejection returns
`true` early. Each `return false` site carries a comment naming the invariant
it asserts.

- **Units:** `BufferSize` is **bytes** (`Buffer.size_bytes()`).
- **Ownership:** the buffer is **borrowed**. It belongs to the caller in
  `client.cc` and is valid only for the duration of the call. We must not free
  it and must not retain the pointer.
- **Empty input:** `BufferSize` may be 0; the module must handle it. hevd's
  guard is a length check that returns `true`.

## R2 — `Restore`: signature settled, residual state is per-target

`src/wtf/targets.h:17` and `:24`:

```cpp
using Restore_t = bool (*)();
const Restore_t _Restore = []() { return true; },   // default: no-op
```

The default is a no-op returning `true`, which tells us the snapshot restore
covers the normal case by itself. RULE 4 asks what is left for us, and
*"restoring twice is as wrong as not restoring"*.

**PARTIAL.** The signature is unambiguous, but which residual state our target
carries across iterations cannot be known before the target exists. Resolved at
CP4 against a real harness, and the answer recorded here before
`fuzzer/module/` gains a non-trivial `Restore`.

## R3 — A3 BP list: **RVAs**, resolved by `GetModuleBase(name)`

`src/wtf/utils.cc:365-374`:

```cpp
const std::string &ModuleName = Json["name"].get<std::string>();
const uint64_t Base = g_Dbg->GetModuleBase(ModuleName.c_str());
...
const uint64_t Rva = Item.get<uint64_t>();
const Gva_t Gva = Gva_t(Base + Rva);
```

**RVAs, not absolute addresses**, relative to whatever base the debugger
reports for `Json["name"]`. Generation therefore never needs `module_base` —
wtf applies the slide itself.

Two boundary conditions, both silent:

- `GetModuleBase` returning 0 fails the **whole** load (`utils.cc:367-370`), so
  `"name"` must match the debugger's module name. Verified against the shipped
  file: `"tlv_server"`, **no `.exe` suffix**, matching the `symbol-store.json`
  key.
- An address that fails `VirtTranslate` is **skipped with a warning**
  (`utils.cc:385-388`), not an error. A wrong base yields a near-empty
  breakpoint set and a fuzzer that runs happily with almost no coverage. CP2
  and CP4 must assert the loaded count against the file's count.

## R4 — `arch/addr.py`: which base each function takes

RULE 4 notes three bases exist. In this codebase only two are distinct:

| Base | Where it comes from |
|---|---|
| Ghidra image base | the PE optional header / Ghidra program (`0x140000000` for tlv_server) |
| snapshot module base | `state/symbol-store.json` (`0x7ff719e50000`) |
| live runtime base | **identical to the snapshot module base** — every worker restores the same snapshot, so there is no third value |

| Function | Takes | Returns |
|---|---|---|
| `to_static(runtime, module_base, ghidra_image_base)` | runtime | Ghidra static |
| `to_runtime(static, module_base, ghidra_image_base)` | Ghidra static | runtime |
| `to_rva(static, ghidra_image_base)` | Ghidra static | RVA — **no module_base** |
| `from_rva(rva, ghidra_image_base)` | RVA | Ghidra static |

`AddressSpace` binds both bases together so they cannot be swapped by accident,
which is the realistic failure given the free functions take two same-typed
`int`s in a row. Cross-checked end-to-end against wtf's own shipped files in
`tests/test_addr.py::test_chain_against_shipped_target_files`.

## R5 — crash oracle: a timeout is **neither** a crash nor an end-of-testcase

`src/wtf/backend.h:12-31`:

```cpp
struct Ok_t        { ... "ok"; };
struct Timedout_t  { ... "timedout"; };
struct Cr3Change_t { ... "cr3"; };
struct Crash_t     { std::string CrashName; ... "crash"; };
using TestcaseResult_t = std::variant<Ok_t, Timedout_t, Cr3Change_t, Crash_t>;
```

RULE 4 asks whether a timeout is a crash, an end-of-testcase, or neither.
**Neither** — it is a fourth outcome in its own right, alongside a CR3 change
(context switch). `CrashRecord.fault_type` keeps `timeout` distinct rather than
folding it into the crash classes.

A clean return from the parser is **not** inferred by wtf at all: end-of-test
and crash conditions are breakpoints *we* set that call `Backend->Stop(Ok_t())`
or `Backend->Stop(Crash_t(name))` (`fuzzer_hevd.cc:83-89`, `:132-146`;
section 13.7). The crash oracle originates in our module, so its conditions get
enumerated here before CP4 ships.

**Silent failure to guard against** (`src/wtf/server.h:861-866`):

```cpp
if (const auto &Crash = std::get_if<Crash_t>(&Result)) {
  if (Crash->CrashName.size() > 0) {
    const auto &OutputPath = Opts_.CrashesPath / Crash->CrashName;
```

A `Crash_t` with an **empty** `CrashName` is **not written to `crashes/` at
all** — no warning. Every `Stop(Crash_t(...))` in our module must pass a
non-empty, collision-resistant name, and CP4's gate must assert a crash
actually lands on disk.

## R6 — `coverage.cov`: a hit is a **boolean**, and the on-disk writer is unconfirmed

In memory (`src/wtf/server.h:822-830`):

```cpp
const size_t SizeBefore = Coverage_.size();
Coverage_.insert(Coverage.cbegin(), Coverage.cend());
const bool NewCoverage = Coverage_.size() > SizeBefore;
```

`Coverage_` is a **set**. RULE 4 asks whether a hit is a count or a boolean:
**boolean — set membership**. There are no hit counts anywhere, so any design
wanting hit frequency would have to add it. `CoverageSummary.total_edges` is
therefore a cardinality.

**PARTIAL / UNRESOLVED.** Section 13.4 says the master maintains an aggregated
`coverage.cov` on disk and section 12.1 suggests the sidecar watch it for
growth. Grepping the tree for a writer of that file found only *readers*
(`Opts.CoveragePath` feeds `ParseCovFiles`). Either it is written somewhere the
grep missed, or the README describes behaviour this revision does not have.

**Not coded around.** CP1 settles it empirically: run a master, watch whether
the file appears. If it does not, plateau detection reads master state by
another route, decided at CP4b. Recorded in DEVIATIONS D-021.

## R7 / R8 — RESOLVED for tlv_server: `rcx` holds the buffer, `rdx` is bytes

**Resolved at CP4** from `src/wtf/fuzzer_tlv_server.cc:113-124`, which is the
authoritative answer for this target:

```cpp
Backend->Rdx(PacketSize);                              // size, in BYTES
const auto &PacketOriginalAddress = Backend->Rcx();
auto PacketAddress = PacketOriginalAddress + (0x1000 - PacketSize);
Backend->Rcx(PacketAddress);                           // rcx HOLDS the address
```

So `input_param: rcx` (bare form — the register *holds* the buffer address) and
`size_param: rdx` in bytes. Recorded in `config/target.yaml`.

Note the target also demonstrates the page-tail alignment trick (D-031), which
is now part of our module.

The general convention below still governs every future target.

## R7 / R8 — the convention (unchanged)

RULE 4 asks whether `input_param` names a register holding a **pointer to** the
buffer or the buffer address itself, and whether `size_param` is bytes or
elements. Neither has a global answer — they describe a specific target's
calling convention. What *is* fixed is how we encode them.

From `fuzzer_hevd.cc:43-51`:

```cpp
g_Backend->Rdx(Ioctl);
const Gva_t IoctlBufferPtr = Gva_t(g_Backend->R8());        // r8 HOLDS a pointer
g_Backend->VirtWriteDirty(IoctlBufferPtr, IoctlBuffer, IoctlBufferSize);
g_Backend->R9(IoctlBufferSize);                             // r9 is a BYTE count
```

**Decided convention**, enforced in `config/target.yaml` and `FuzzEntry`:

- `input_param` is written as `"<reg>"` when the register **holds the buffer
  address** (dereference it, then `VirtWriteDirty` there), or `"&<reg>"` when
  the register **is** the buffer. hevd is the former.
- `size_param` is **always bytes**, and always the length of the payload wtf
  hands us — never including a header or terminator. If a target wants a
  different length, `injection.fixups` in `config/target.yaml` computes it;
  `size_param` itself stays honest.
- Stack arguments use `"arg:<n>"`, resolved with `GetArgAddress(n)` /
  `GetArgGva(n)` (`fuzzer_hevd.cc:52`).

The concrete values are recorded per target in `config/target.yaml` and, from
CP6, in the LLM-emitted `FuzzEntry.rationale`.

## R9 — seed spool ownership: **RESOLVED — the consumer deletes**

RULE 4 asks who deletes a consumed seed and what happens if the sidecar and the
mutator touch it at once. No source answer exists — the spool is **our**
mechanism (section 12.1), not wtf's — so it is decided here and implemented in
`fuzzer/module/fuzzer_snapfuzz.cc`.

**Producer (the sidecar):** writes `<name>.tmp`, then renames to `<name>.json`.
Rename is atomic, so a partially-written seed is never visible.

**Consumer (`CustomMutator_t::GetNewTestcase`, on the master):** lists the
directory, skips any `.tmp`, reads one file, then **deletes it**. Takes at most
one seed per call.

**Races** are resolved by treating every failure as "fall through to the
built-in mutator this iteration":

| Situation | Behaviour |
|---|---|
| spool directory absent | `std::error_code` from `directory_iterator`, no throw — normal before the sidecar starts |
| file vanished between listing and opening | `ifstream` fails, try the next entry |
| file is a half-written `.tmp` | skipped by extension |
| file is empty | skipped |

The hard constraint is section 12.1's: `GetNewTestcase()` runs on the master's
hot path with every worker waiting, so **nothing here blocks** — no locks, no
retries, no waiting. The cost of losing a seed to a race is one iteration of
built-in mutation; the cost of blocking is stalling the entire campaign.

**Verified 2026-07-25**, with no LLM involved: 25 seeds written to the spool by
hand were all 25 consumed by a running master, and the corpus grew 0 → 34. The
master also logs `snapfuzz: seed spool at <path>` at startup, so a misconfigured
spool is visible rather than silent.

This satisfies ahead of time the GATE 4b requirement to inject a known seed by
the documented mechanism and prove it is executed.

---

## DEC-001 — Crash oracle: accept the binary-only limitation (option b)

**Decided 2026-07-25. CLAUDE.md section 2 requires this choice to be recorded.**

There is no ASAN. Section 2 offers (a) investigate binary-only sanitisation and
accept the slowdown, or (b) accept the limitation and state it explicitly.

**We take (b)** — CLAUDE.md's own default for v1. It is defensible and does not
risk the schedule.

The report must state, in these terms:

> Binary-only instrumentation; the crash oracle covers observable faults only;
> silent memory corruption is out of scope.

Concretely:

- **Detectable:** access violations / SIGSEGV, aborts, illegal instruction,
  timeouts/hangs, plus whatever the wtf backend surfaces
  (`src/wtf/crash_detection_umode.cc`).
- **Not detectable:** memory corruption that never faults — an out-of-bounds
  read into mapped memory, a small heap overflow that never reaches a guard
  page. Under source+ASAN these are caught instantly; here they pass silently.

Downstream consequence, which shapes every triage prompt: **the triage LLM
never receives a sanitiser report.** It gets fault address, registers, fault
type, replay result and Ghidra pseudo-C. Prompts must never imply source or
sanitiser output exists.

Revisit only if a target proves to leak bugs we can show ASAN would catch, and
only after CP7 — a binary-only sanitiser is a schedule risk, not a v1 feature.

---

## DEC-002 — Section 5 layout lives at the repo root

**Decided 2026-07-25.**

The workspace *is* the wtf clone (DEVIATIONS D-000), so "put our code beside
wtf" was not available as written. Options were a `snapfuzz/` subdirectory or
the repo root.

**Chose the root.** Section 5's paths are then literal, which keeps CLAUDE.md
and the tree in agreement, and there are no name collisions with wtf's own
`src/`, `scripts/`, `targets/`, `linux_mode/`, `pics/`.

Cost: our directories interleave with upstream wtf's when merging from
`0vercl0k/wtf`. Judged small — upstream never adds top-level directories named
`arch/`, `prep/`, `analysis/` and so on, so conflicts would be confined to
files we also touch.

**Exception, forced by the build:** `src/CMakeLists.txt:19-23` globs `wtf/*.cc`,
so a fuzzer module is only compiled into `wtf.exe` if it lives under
`src/wtf/`. At CP4, `fuzzer/module/` holds our module's sources and
`fuzzer/build.py` places or links them into `src/wtf/` before building. The
alternative — editing upstream's `CMakeLists.txt` — was rejected as a worse
merge conflict in a file that matters.

---

## DEC-003 — Binary fields in contracts serialise as base64

**Decided 2026-07-25.**

Section 6 says every stage boundary serialises to JSON on disk, and gives
`SeedRecord.seed_bytes` / `CrashRecord.input_bytes` as `bytes`. Pydantic v2
defaults to UTF-8 for `bytes` in JSON, which **raises** on non-UTF-8 payloads —
i.e. on most interesting fuzz inputs.

Both models set `ConfigDict(ser_json_bytes="base64", val_json_bytes="base64")`
so a dump/load round trip is lossless in both directions. `tests/gates/test_cp0.py`
round-trips all 256 byte values to keep it that way.

Rejected: hex (bulkier), or a raw side-file per record (a second thing to keep
in sync, for no gain).

---

## DEC-004 — Reachability is asserted from a declared root set

**Decided 2026-07-25.** See DEVIATIONS D-002.

GATE 0 asks for "every node reachable from `target_binary`", but four nodes in
section 3.2 have no producer and are genuine external inputs. Rather than
inventing edges to satisfy the letter of the gate, `graph.yaml` marks them
`kind: input`, and the gate asserts both that every node is reachable from the
root set **and** that every non-input node is reachable from `target_binary`.

This is strictly stronger than a fudged edge would have been: a future node
that quietly lacks a producer fails `test_only_inputs_lack_producers` unless it
is explicitly declared an input.

---

## DEC-005 — GATE 4 must exercise edge 22 on the whv backend

**Decided 2026-07-25.** See DEVIATIONS D-004.

Coverage breakpoints (`ParseCovFiles`) are read only by the whv and kvm
backends; bochscpu ignores `.cov` files and derives coverage itself. So a
GATE 4 run on bochscpu would report healthy coverage while edge 22
(A3 -> interface 3 -> `engine.execute`) was never exercised — a green gate over
an unwired interface, exactly what RULE 3 exists to prevent.

`config/fuzz.yaml` splits the backends by purpose:

| Purpose | Backend | Why |
|---|---|---|
| development | bochscpu | deterministic, fast start-up, execution traces |
| replay (CP8) | bochscpu | determinism is the whole point of the replay signal |
| fuzzing (GATE 4) | whv | available on this Windows host, and the only local backend that actually consumes A3 |

GATE 4 must additionally assert the breakpoint set wtf loaded is close to the
size of the `.cov` file, because untranslatable addresses are skipped with a
warning rather than an error (D-005).

---

## DEC-006 — Python 3.12.10 is the interpreter of record

**Decided 2026-07-25 by the user. Settled.**

Section 4 requires Python 3.11+. The host had only 3.10.9 and 3.8, and the
`python` on PATH belongs to an unrelated project's virtualenv
(`PycharmProjects\RLtest\.venv`) which must not be installed into.

Options were: install 3.11+, or stay on 3.10 and record a deviation.
Everything written for CP0 is 3.10-compatible, so neither was blocking — but
**DSPy was the risk**: CP9 pins the requirement and discovering its supported
floor at CP9 is far more expensive than avoiding it now.

**Installed Python 3.12.10** (`winget install Python.Python.3.12`) and recreated
`.venv` from it. The gate suite is green on 3.12.10. No deviation to record.

Standing rule: always invoke `.venv\Scripts\python.exe` by full path. PATH
still resolves `python` to the unrelated project's 3.10 venv.

---

## DEC-007 — Pseudo-C is lossy and is not source

**Recorded 2026-07-25 as CLAUDE.md CP6 requires, ahead of the checkpoint.**

Ghidra's decompiler output moves us from grey-box toward white-box, but it is
**not** source:

- symbol names are gone unless the binary carries them; Ghidra invents
  `FUN_140001000`, `local_28`, `param_1`;
- types are inferred and frequently wrong — a struct pointer commonly appears
  as `undefined8 *` with hand-computed offsets;
- inlining is flattened, so one decompiled function may be several source
  functions and the call structure the LLM reasons over is not the author's;
- compiler idioms (vectorised `memcpy`, jump tables, tail calls) decompile into
  code that reads nothing like the original.

Consequences we hold ourselves to:

- prompts must never present pseudo-C as source, and must not ask for
  source-level artefacts (line numbers, original identifiers);
- a `TriageVerdict.root_cause` grounded only in an inferred type is weak
  evidence and should be reflected in `confidence`;
- the report states this as a limitation in plain terms.

---

## DEC-008 — Triage, never "verification"

**Recorded 2026-07-25.** CLAUDE.md section 1.

The LLM stage that adjudicates crashes is **triage**: deciding whether a crash
is a real, interesting bug. **Verification** — adjudicating a static finding
using source plus a PoC — is a different problem and is not part of this
project.

This is not pedantry about vocabulary. The project author has a paper arguing
fuzzing is the wrong tool for *verification*; this project is *discovery*.
Labelling the triage stage "verification" manufactures a contradiction with
that paper which will be challenged at review. `report`, `discard`, and every
prompt and docstring use "triage".

---

## DEC-009 — CP1 runs both example targets, tlv_server as the mandated one

**Decided 2026-07-25 by the user. Reaffirmed by the revised CLAUDE.md.**

GATE 1 requires one bundled example run end-to-end. We run **both**:
`tlv_server` as the primary, `hevd` as a cross-check.

The revised CP1 now settles the primary explicitly — *"Use `fuzzer_tlv_server`,
not `fuzzer_hevd`"* — for the reason we had already chosen it: `tlv_server` is
a **user-mode network parser**, the same shape as our real target, and it is
the only example demonstrating the two things CP4/CP4b need most, a **custom
`Mutator_t`** and **multi-packet delivery**. §13.8 makes it "our primary
model"; `hevd` is "useful for understanding the tooling, not our shape".

Keeping `hevd` as a cross-check is still worth its cost. GATE 1's real
deliverable is not "wtf runs" — it is the DEVIATIONS record of the actual CLI,
snapshot layout, BP-file format and output paths, which **every later
checkpoint parses**. A second target distinguishes a general format from one
target's accident, and it has already paid for itself twice: it is what exposed
the `regs.json` `fpst` incompatibility (D-019) by *working* where tlv_server
failed, and its 2024-era snapshot is the newer format of the two.

Both are extracted under `targets/`; see ENVIRONMENT.md.

---

## DEC-010 — `[LLM]` in the diagram means "our layer", not "calls an LLM"

**Decided 2026-07-25.**

The §3.1 diagram marks the custom `Mutator_t` with `[LLM]`, and §3.1's own
legend says *"`[LLM]` marks our layer"*. But §10 lists **"any LLM call inside
the master"** as an anti-pattern, and `GetNewTestcase()` runs on the master's
hot path for every single test-case.

Both are true and they are about different things: the mutator **consumes** LLM
seeds from the spool; it must never **call** the LLM. Conflating the two would
put an LLM round-trip in the one place guaranteed to stall every worker at once.

`arch/graph.yaml` therefore carries two separate attributes:

| Attribute | Meaning |
|---|---|
| `ours: llm_layer` | the diagram's `[LLM]` marker — our contribution, for the writeup |
| `calls_llm: true` | actually issues an LLM API call |

`tests/gates/test_graph.py::test_no_llm_call_on_master_or_worker` asserts no
node with `role: master` or `role: worker` sets `calls_llm`, and
`test_llm_calls_only_happen_off_the_fast_path` pins the caller set to exactly
four nodes, so adding a fifth has to be deliberate.

Note this also puts `analysis/reverse.py` on the non-calling side despite its
`[LLM]` marker: it lives inside CP8, whose gate asserts no LLM call occurs
anywhere in that path. It assembles context; CP9 does the reasoning.

---

## DEC-011 — Repair the tlv_server `fpst` encoding rather than defer the target

**Decided 2026-07-25.** Full technical analysis in DEVIATIONS D-019.

CP1 mandates `fuzzer_tlv_server` **and** says to run the example "unmodified".
The shipped 2022 snapshot will not load on this revision of wtf, so those two
requirements cannot both be met literally. Options:

- **(a)** repair the `fpst` encoding in `regs.json`;
- **(b)** check out the v0.5.7 tag for CP1, then return to `a490929`;
- **(c)** use `hevd` for GATE 1 and defer tlv_server to CP4.

**Chose (a).** The change rewrites eight `fpst` **sentinel strings** and
nothing else — 56 characters — and the CPU state wtf loads afterwards is
provably *more* correct, not merely equal: it makes `fptw` resolve to `0xFFFF`,
byte-identical to what `hevd` loads, whereas leaving the file alone means it
does not load at all. wtf confirms the interpretation itself on every run:

```
Setting @fptw to 0xffff as this is an old dump taken with bdump..
```

Why this is a *format repair* and not a modification of the target, which is
what "unmodified" is protecting against: nothing about the program under test,
the harness, the fuzzer module, or the memory image changes. `mem.dmp` is
untouched. What changed is the serialisation of a register whose value is
unchanged. The spirit of "unmodified" is *do not bend the target to make the
fuzzer look like it works*; this bends nothing.

Mitigations, so the decision stays auditable and reversible:

- the original is preserved verbatim at `state/regs.json.v0.5.7-original`;
- the diff is reproduced in full in DEVIATIONS D-019;
- `hevd` was run **unmodified** and passed, so GATE 1 does not rest solely on a
  repaired target.

Rejected (b) because it validates a build we will not use — the whole point of
GATE 1 is to de-risk *this* tree. Rejected (c) because CP1 chose tlv_server
precisely to front-load reading its `CustomMutator_t` and multi-packet
delivery, which CP4/CP4b depend on.

**Note on how this decision was reached.** The first version of this fix
converted `fpst` to the modern object form and was justified with a source
citation showing both encodings yield an all-zero x87 stack. That was wrong:
the citation stopped one branch short of `BdumpGenerated`, which also controls
an `fptw` abridged-to-full conversion. The object form would have loaded a tag
word claiming eight valid x87 registers on an empty stack — silently. Recorded
because it is a clean example of the failure RULE 4 exists to prevent, and
because "I verified it against the source" is evidently not sufficient on its
own; the question is whether you followed *every* branch the flag feeds.

---

## DEC-012 — The Ghidra post-script is Java, not Python

**Decided 2026-07-25.** See DEVIATIONS D-025.

wtf's reference `gen_coveragefile_ghidra.py` is Jython, which a stock Ghidra 12
cannot run: Jython is now an optional extension, and `.py` scripts are routed to
PyGhidra, which `analyzeHeadless` cannot start. Three ways forward:

| Option | Cost |
|---|---|
| **(a) Java post-script** | a second language in the repo |
| (b) install the Jython extension | keeps wtf's script runnable, but pins us to a deprecated Python 2.7 runtime and an extra install step on every machine |
| (c) adopt PyGhidra | Python 3, the supported direction — but a different driving model (`pyghidra.open_program()`), plus `jpype1` and a working JPype/JDK binding |

**Chose (a).** The deciding argument is RULE 3: the gate is the definition of
done, so CP2 must be reproducible on a clean machine. Java scripts work on every
Ghidra install with no extra install step and no Python-side binding that can
break independently of our venv. Ghidra's own 191 bundled scripts are Java, so
this is the well-trodden path, and the script language is invisible from outside
— `prep/ghidra_headless.py` is still the Python entry point CLAUDE.md §5 asks
for, and only shells out to `analyzeHeadless`.

Cost accepted: `prep/ghidra_scripts/ExportBasicBlocks.java` is the one non-Python
source file in the project outside `fuzzer/module/`.

This does **not** cost us the format oracle. What we need from wtf's script is
its *output shape*, and we have a better version of that: a real reference
`.cov` in the release archive to diff against (D-027, 97.4% recall).

Revisit at CP6 if GhidraMCP turns out to want PyGhidra in-process anyway — but
CP6's decompilation runs through the MCP server, which is a separate process, so
it probably will not force the issue.

---

## Pending decisions

| # | Decision | Needed by | Blocked on |
|---|---|---|---|
| — | The real fuzz target for CP3+ | CP3 | Not yet chosen. `tlv_server` is a plausible stand-in for CP4 development since its source is in-tree (`src/tlv_server/tlv_server.cc`), but the project needs a genuine no-source target |
| — | DSPy train/held-out split of `eval/planted_bugs/` | CP9 | The planted-bug set does not exist yet. Optimising and reporting on the same split is invalid (section 10) |
| — | Confirm DSPy's minimum supported Python | CP9 | Ties into DEC-006 |
