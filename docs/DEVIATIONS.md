# DEVIATIONS

Where CLAUDE.md and the cloned wtf source disagree, **the source wins** (RULE 2).
Each entry records what CLAUDE.md says, what the source actually does, and what
we did about it.

Also recorded here: observed wtf behaviour that downstream checkpoints depend
on (CP1's instruction to document the real CLI, snapshot format, BP-file format
and output layout).

All source references are to this clone at `a490929`
(`github.com/Lompandi/wtf-llm`, a fork of `0vercl0k/wtf`).

Status legend: **confirmed** = read directly out of the source.
**unverified** = observed but not yet exercised; re-check at the named
checkpoint before relying on it.

---

## D-000 — The workspace *is* the wtf clone, not a parent of one

**CLAUDE.md says:** "`wtf` is **already cloned** in this workspace. Locate it
before doing anything else", implying wtf sits in a subdirectory.

**Reality (confirmed):** `d:\wtf-llm` is itself the wtf clone —
`git remote -v` gives `github.com/Lompandi/wtf-llm.git`, a fork of
`0vercl0k/wtf`, and the tree root holds wtf's own `README.md`, `src/`,
`scripts/`, `targets/`, `linux_mode/`, `pics/`. CLAUDE.md was added at that
root.

**Action:** the section 5 layout was created **at the repo root**, alongside
`src/` and `scripts/`. No name collides: section 5 declares no `src`, `scripts`,
`targets`, `linux_mode` or `pics`. Section 5 paths are therefore literal —
`arch/contracts.py` is `d:\wtf-llm\arch\contracts.py`.

**Consequence to keep in mind:** our fuzzer module cannot live *only* in
`fuzzer/module/`. `src/CMakeLists.txt:19-23` globs `wtf/*.cc`, so a module is
compiled into `wtf.exe` only if it sits under `src/wtf/`. See D-008.

---

## D-001 — Section 3.2 is missing the edge into fuzz-entry selection

**CLAUDE.md says:** edge 2 is `target_binary -> ghidra.analyze`; edges 3-5 all
start at `ghidra.fuzz_entry_selection`. No edge produces
`ghidra.fuzz_entry_selection`, and `ghidra.analyze` has no outgoing edge.

**Problem:** GATE 0 requires "every node reachable from `target_binary`". With
exactly the 42 listed edges, `ghidra.fuzz_entry_selection` and everything
downstream of it is unreachable, so GATE 0 cannot pass as written.

**Resolution:** the section 3.1 diagram *does* show analysis feeding entry
selection (both sit inside the "Ghidra static analysis" box, with entry
selection fed from the target binary). The edge was restored as **id 1000**,
flagged `derived: true`. The canonical ids 1-42 are untouched.

---

## D-002 — Four nodes in section 3.2 have no producer

**Reality:** besides `target_binary`, these appear only as edge *sources*:

| Node | Only appears in |
|---|---|
| `fuzz_target.fuzzer_config` | edge 19 |
| `fuzzer_module.insert_testcase` | edge 15 |
| `fuzzer_module.restore_hook` | edge 16 |
| `fuzzer_module.manual_tweaks` | edge 17 |

The section 3.1 diagram agrees — those boxes have no inbound arrow.

**Resolution:** they are genuine external inputs (the initial seed corpus, and
the parts of the fuzzer module we hand-write), not omissions. Inventing an
inbound edge from `target_binary` would misrepresent the design. `graph.yaml`
declares them `kind: input` and lists them in `roots`. The gate therefore
asserts two things:

1. every node is reachable from the root set, and
2. every **non-input** node is reachable from `target_binary` — GATE 0's check,
   scoped to what the binary can actually produce.

---

## D-003 — Edge 6 is an or-split and cannot be one edge

**CLAUDE.md says:** edge 6 is
`snapshot.break_at_entry -> snapshot.windows_kd **or** snapshot.linux_gdb`.

**Resolution:** stored as **6** (Windows) and **6b** (Linux). Both
`snapshot.windows_kd` and `snapshot.linux_gdb` must exist as nodes because
edges 7 and 8 both do; without 6b, the Linux node would be an orphan. GATE 3
requires only one of the pair.

---

## D-004 — Coverage breakpoints do not apply to the bochscpu backend

**Confirmed.** `ParseCovFiles` is called from exactly two places:

- `src/wtf/whv_backend.cc:488`
- `src/wtf/kvm_backend.cc:2638`

Never from `bochscpu_backend.cc`. The README confirms the reason: bochscpu
gives "full system code-coverage" for free (with edge coverage via `--edges`),
whereas whv and kvm derive coverage from **software breakpoints** and so need
the `.cov` list.

**Why this matters a lot:**

- CLAUDE.md tells us to develop on bochscpu (section 4) *and* treats
  A3 -> interface 3 -> `engine.execute` (edge 22) as part of GATE 4. **On
  bochscpu that edge is inert** — the `--coverage` flag is accepted but the
  files are never parsed. A GATE 4 run on bochscpu alone would "pass" while
  edge 22 was never exercised.
- **Action:** edge 22 must be demonstrated on the **whv** backend (available on
  this Windows host). `config/fuzz.yaml` therefore pins `backend.fuzzing: whv`
  while keeping `backend.development` and `backend.replay` on bochscpu.
- Corollary: CP2's artifact is only load-bearing for whv/kvm. That is not a
  reason to skip it — it is the CP2 deliverable — but the gate must check the
  *format*, and GATE 4 must check it is actually *consumed*.

---

## D-005 — The `.cov` breakpoint file format (confirmed)

From `src/wtf/utils.cc:342-408`:

- `--coverage` takes a **directory**. Every file in it ending `.cov` is read;
  anything else is ignored.
- Each file is JSON:

  ```json
  {"name": "<module name>", "addresses": [<rva>, <rva>, ...]}
  ```

- `addresses` are **RVAs**, not absolute addresses. wtf resolves the module
  with `g_Dbg->GetModuleBase(name)` and computes `Base + Rva` at load time
  (`utils.cc:366,373-374`).
- If `GetModuleBase` returns 0 the whole load **fails**; the module name must
  match what the debugger knows.
- Each address is translated GVA -> GPA with
  `MemoryValidate_t::ValidateReadExecute`. Untranslatable addresses are
  **skipped with a warning, not an error** — so a silently tiny breakpoint set
  is a realistic failure mode worth asserting against at CP2/CP4.

**Consequence for section 9:** generating a `.cov` file needs only
`to_rva(static_addr, ghidra_image_base)`. It does **not** need `module_base`,
because wtf applies the slide itself. `arch/addr.py` provides `to_rva` /
`from_rva` for exactly this, separately from `to_static` / `to_runtime`.

### Verified against a real sample

CP2 says to "diff against a sample if the repo contains one". The repo does not,
but the **release archive does**: `targets/tlv_server/coverage/tlv_server.cov`,
530 basic blocks, 3416 bytes. Head of the actual file:

```json
{"name": "tlv_server", "addresses": [4096, 4112, 4138, 4145, 4176, ...
```

Points our generator must match:

- addresses are **plain decimal integers** in JSON, not hex strings;
- the lowest is `4096` = `0x1000`, i.e. the first section RVA of a PE — further
  confirmation these are RVAs;
- `"name"` is `tlv_server`, **without the `.exe` extension**, and must match the
  key `GetModuleBase` resolves. `state/symbol-store.json` uses the same bare
  `"tlv_server"` key. Emitting `tlv_server.exe` would make `GetModuleBase`
  return 0 and fail the whole load.

The full conversion chain closes on itself and is now asserted in
`tests/test_addr.py::test_chain_against_shipped_target_files`:

| Quantity | Value | Source |
|---|---|---|
| PE ImageBase | `0x140000000` | `target/tlv_server.exe` optional header |
| `module_base` | `0x7ff719e50000` | `state/symbol-store.json` |
| entry runtime addr | `0x7ff719e51150` | `symbol-store.json`, key `tlv_server!ProcessPacket` |
| ... equals snapshot `rip` | `0x7ff719e51150` | `state/regs.json` |
| RVA | `0x1150` | present in `coverage/tlv_server.cov` |
| Ghidra static addr | `0x140001150` | derived |

That the snapshot's `rip` **is** the fuzz entry is the concrete meaning of
"break at the fuzz entry", and it is what edges 1 -> 6 -> 7 rest on.

---

## D-006 — wtf already ships a Ghidra coverage script

**CLAUDE.md says (CP2):** "wtf's own tooling generates this from a different
disassembler — match its output format precisely".

**Reality (confirmed):** `scripts/` contains `gen_coveragefile_ida.py`,
`gen_coveragefile_binja.py` **and `gen_coveragefile_ghidra.py`**. The Ghidra one
is 28 lines and uses `BasicBlockModel(program).getCodeBlocks(monitor)`,
emitting `block.minAddress.getOffset() - base_address` — i.e. RVAs, matching
D-005.

**Action:** treat it as the reference implementation and the format oracle for
CP2 rather than reinventing it. Two things it does *not* do, which are the
actual CP2 work:

1. **No scoping.** It walks every basic block in the program. CP2 requires
   `--scope=function-closure` (default) as well as `--scope=module`.
2. **It is a GUI/`analyzeHeadless` post-script**, not a driver. It writes
   `<program name>.cov` next to `getExecutablePath()`, which is not where we
   want it. `prep/ghidra_headless.py` must drive `analyzeHeadless` and control
   the output path.

---

## D-007 — Snapshot acquisition is a separate project, not a wtf script

**CLAUDE.md says (section 4, CP3):** Windows snapshots are taken by "wtf's own
snapshot script".

**Reality (confirmed):** wtf ships no such script. The README ("How does it
work?", steps 2-3) directs the user to a **separate repository**,
`github.com/0vercl0k/snapshot`, whose `snapshot.dll` is loaded into KD:

```
kd> .load c:\...\snapshot.dll
kd> !snapshot [-k active-kernel|full] <state_path>
```

It writes `regs.json` (CPU state) and `mem.dmp` (kernel crash dump) into the
state directory.

**Action:** CP3 has an extra prerequisite — obtain/build `0vercl0k/snapshot`.
`prep/snapshot_win.py` wraps that KD extension, not a wtf script.

The only in-repo script named in the snapshot flow is
`scripts/disable-kva.cmd` (KVA shadow / Meltdown mitigation, which interferes
with snapshotting). Its role is **unverified**; confirm at CP3.

---

## D-008 — The real fuzzer-module API (confirmed)

`src/wtf/targets.h:14-32`. There is no "bus"; CLAUDE.md's `fuzzer_module.bus`
is the `Target_t` registration:

```cpp
struct Target_t {
  using Init_t           = bool (*)(const Options_t &, const CpuState_t &);
  using InsertTestcase_t = bool (*)(const uint8_t *, const size_t);
  using Restore_t        = bool (*)();
  using CreateMutator_t  = std::unique_ptr<Mutator_t> (*)(std::mt19937_64 &,
                                                          const size_t);

  explicit Target_t(
      const std::string &_Name, const Init_t _Init,
      const InsertTestcase_t _InsertTestcase,
      const Restore_t _Restore = []() { return true; },
      const CreateMutator_t _CreateMutator = LibfuzzerMutator_t::Create);
};
```

Registration is a file-scope object: `Target_t Hevd("hevd", Init, InsertTestcase);`
(`src/wtf/fuzzer_hevd.cc:166`). The name is what `--name` selects.

Notes for CP4, from `fuzzer_hevd.cc`:

- `InsertTestcase` returns `bool`; returning `false` rejects the testcase.
- Guest memory is written with `g_Backend->VirtWriteDirty(Gva_t, buf, len)` and
  `VirtWriteStructDirty`. Registers are accessed as `g_Backend->Rdx(v)`,
  `R8()`, `R9(v)`. Stack arguments come from `g_Backend->GetArgAddress(n)` /
  `GetArgGva(n)`.
- End-of-testcase and crash detection are **breakpoints set in `Init`**, which
  call `Backend->Stop(Ok_t())` or `Backend->Stop(Crash_t(name))`. The
  `Crash_t` string becomes the crash filename.
- `Backend->Stop(Cr3Change_t())` handles context switches.
- `Restore` defaults to a no-op returning `true` — a module supplies one only
  for residual state the snapshot restore does not cover.

`src/wtf/crash_detection_umode.cc` holds the user-mode crash oracle; read it
before writing CP4's stop conditions and CP8's classifier.

---

## D-009 — Observed CLI and directory layout (confirmed)

Verbs (`src/wtf/wtf.cc`): **`master`**, **`fuzz`**, **`run`**.

Selected flags, by verb:

| Verb | Flags |
|---|---|
| `master` | `--name` (req), `--max_len` (req), `--runs`, `--target`, `--inputs`, `--outputs`, `--crashes`, `--address`, `--seed` |
| `fuzz` | `--name` (req), `--backend`, `--edges`, `--target`, `--limit`, `--state`, `--guest-files`, `--seed`, `--address` |
| `run` | `--name` (req), `--input` (req), `--backend`, `--limit`, `--state`, `--coverage`, `--edges`, `--runs`, `--trace-path`, `--trace-type` |

`--trace-type` supports at least `rip`, `cov` and `tenet` (README).

Target directory tree (README "Usage"):

```
targets/<name>/
  inputs/     seed test-cases
  outputs/    current minset
  coverage/   the .cov files            <- interface 3 / A3
  crashes/    crashing inputs           <- A5
  state/      mem.dmp, regs.json, symbol-store.json   <- A1
```

`symbol-store.json` is generated at runtime on Windows and is what lets Linux
hosts place breakpoints without dbgeng.

The master maintains an aggregated `coverage.cov` for the whole job — a likely
cheap input for `engine_bridge/coverage.py`. **Unverified**; confirm at CP1.

---

## D-010 — Linux mode is GDB **against a QEMU VM**

**CLAUDE.md says:** "GDB-based ELF snapshot", "Linux user-mode path".

**Reality (confirmed by file listing):** `linux_mode/qemu_snapshot/` contains
`setup.sh`, `gdb_server.sh`, `gdb_client.sh`, `gdb_qemu.py`, `gdb_fuzzbkpt.py`,
`gdb_utils.py` and a `target_vm/` directory. `linux_mode/README.md` describes
starting a QEMU VM with `gdb_server.sh` and attaching with `gdb_client.sh`. So
it is GDB driving a **full-system QEMU VM with a kernel build**, not GDB on a
bare user-mode process — a substantially larger setup than CLAUDE.md implies.

A grep of `linux_mode/` for `aslr` / `randomize_va_space` returned **nothing**,
so CLAUDE.md's "ASLR must be disabled" is **not corroborated** by the repo. It
may still be true. Do not encode it as fact until CP3's Linux path is actually
attempted; `prep/snapshot_linux.py` should assert it and report, not assume it.

Windows is first regardless (section 2), so this is deferred.

---

## D-011 — `targets/` is empty; the example target must be downloaded

**Confirmed:** `targets/` contains only `empty.txt`. CP1 requires running "one
bundled example target end-to-end, unmodified", but the example *targets* are
not bundled in the repo — the README says to download `target-hevd.7z` or
`target-tlv_server.7z` from the GitHub Releases page and extract into
`targets/`. The fuzzer *modules* (`fuzzer_hevd.cc`, `fuzzer_tlv_server.cc`) are
in-tree; the snapshots are not.

**Action:** GATE 1 is blocked until an archive is fetched. See ENVIRONMENT.md.
`target-tlv_server` is the better first choice: it is a **user-mode** target,
which is what this project fuzzes, whereas hevd is a kernel driver.

---

## D-012 — `.gitignore` silently ignores new fuzzer modules

**Confirmed.** `.gitignore:35` contains:

```
src/wtf/fuzzer_*
```

Upstream's own modules (`fuzzer_hevd.cc`, `fuzzer_tlv_server.cc`, ...) predate
the rule and stay tracked because git ignores only *untracked* files. A **new**
file at `src/wtf/fuzzer_snapfuzz.cc` would be ignored — it would build fine
locally, then vanish from the commit with no warning. A quiet way to lose CP4's
main deliverable.

**Action:** this makes DECISIONS DEC-002's build arrangement the right one for
a second, independent reason. `fuzzer/module/` is the tracked source of record;
`fuzzer/build.py` copies into `src/wtf/` at build time, where being ignored is
correct — the copy is a build artifact. The upstream rule is left untouched.

CP4's gate should assert the module source is tracked
(`git check-ignore -q <path>` must fail for `fuzzer/module/`).

---

## D-013 — The release archives ship the exact CLI invocations

**Confirmed.** `targets/tlv_server/` contains runnable scripts written by wtf's
author. These outrank the README as ground truth for CP1:

```bat
:: server.bat
..\..\src\build\wtf.exe master --max_len=1000000 --runs=10000000 --target . --name tlv_server

:: fuzz-bochscpu.bat
..\..\src\build\wtf.exe fuzz --backend=bochscpu --name tlv_server --limit 10000000

:: fuzz-whv.bat
..\..\src\build\wtf.exe fuzz --backend=whv --name tlv_server --limit 3

:: run.bat
..\..\src\build\wtf.exe run --name tlv_server --state state --backend=bochscpu --input %* --limit 10000000
```

Things to take from this, all of which shape `fuzzer/run.py`:

- **`--limit` means different things per backend, and the gap is enormous:**
  `10000000` on bochscpu (an instruction count) versus `3` on whv/kvm (a
  timer). The README says only that it "has different meaning". Copying the
  bochscpu value onto whv, or the reverse, would be a silent misconfiguration —
  `config/fuzz.yaml` must carry a per-backend limit, not one number.
- The `fuzz` verb is run **from inside the target directory** and passes
  neither `--target` nor `--state`; both default relative to the working
  directory. `master` passes `--target .` explicitly.
- The build output is expected at `src/build/wtf.exe`, matching
  `config/fuzz.yaml`'s `wtf.binary`.

**Action taken:** `config/fuzz.yaml` splits `limit` per backend rather than
holding a single value.

---

## D-014 — `symbol-store.json` gives module base and entry for free

**Confirmed.** `targets/tlv_server/state/symbol-store.json` in full:

```json
{"tlv_server":"0x0007ff719e50000",
 "hal!HalpPerfInterrupt":"0xfffff80209500a20",
 "nt!KeBugCheck2":"0xfffff80208cc43e0",
 "nt!KiRaiseSecurityCheckFailure":"0xfffff80208bebb80",
 "nt!SwapContext":"0xfffff80208be2880",
 "ntdll!RtlDispatchException":"0x7ff8e54ea010",
 "tlv_server!ProcessPacket":"0x7ff719e51150",
 "tlv_server!printf":"0x7ff719e510f0",
 "verifier":"0x7ff8aa3b0000",
 "verifier!VerifierStopMessage":"0x7ff8aa3b6360"}
```

Two useful consequences:

1. **CP3 gets `module_base` and `entry_runtime_addr` from this file.** Both are
   required fields of `SnapshotRef`, and both are sitting in the state
   directory the snapshot already produces. `prep/snapshot_win.py` should read
   them here rather than re-deriving them from a debugger session. A bare
   module name maps to its base; `module!symbol` maps to a symbol address.
2. **The symbol list *is* the user-mode crash oracle.** `nt!KeBugCheck2`,
   `nt!KiRaiseSecurityCheckFailure`, `ntdll!RtlDispatchException` and
   `verifier!VerifierStopMessage` are exactly the breakpoints wtf places to
   detect faults. Read `src/wtf/crash_detection_umode.cc` alongside this before
   writing CP4's stop conditions and CP8's classifier — it defines what the
   crash oracle can and cannot see, which is the honest basis for DECISIONS
   DEC-001.

Note `verifier` is present, so the snapshot was taken with Application Verifier
enabled. That materially widens what faults are observable, and is worth
imitating on our own target.

---

## D-015 — tlv_server ships four labelled known bugs

**Confirmed.** `targets/tlv_server/interesting/` contains:

| File | Implied bug class |
|---|---|
| `big_overflow.json` | buffer overflow, large |
| `small_overflow.json` | buffer overflow, small |
| `iterator_bug.json` | iterator invalidation / logic |
| `read_av_allocate.json` | read access violation |

These are inputs that reach real bugs in `src/tlv_server/tlv_server.cc`, whose
source **is** in this repo.

**Why this matters beyond CP1:** CLAUDE.md notes `eval/planted_bugs/` is on the
critical path (it serves both DSPy training and triage accuracy) and says to
build it early if there is slack. This is a partial, ready-made, author-labelled
set with source available for ground truth — a much cheaper start than
authoring planted bugs from scratch.

Two cautions before it is used that way:

- four samples is far too small to split into train and held-out (CP9), so it
  supplements a planted-bug set rather than replacing it;
- `small_overflow` is precisely the class DEC-001 says we may **not** reliably
  detect without a sanitiser. If it fails to produce an observable fault, that
  is not a pipeline bug — it is the documented limitation, and it would make a
  concrete, honest example for the report.

---

## D-016 — `InsertTestcase` returning false **aborts the worker**

**Confirmed**, `src/wtf/client.cc:102-104`. Full analysis in DECISIONS R1.

Recorded here as a deviation because CLAUDE.md's CP4 description reads as
though `InsertTestcase` merely reports success, and RULE 4 asks the question
outright. The answer is the dangerous one: `false` reaches `std::abort()` and
kills the worker process. The way to skip a malformed test-case is to
**`return true`** without doing anything, which `fuzzer_hevd.cc:21-23` does.

Impact scales with the topology: with N workers, a module that returns `false`
on ordinary malformed input silently bleeds workers while the campaign still
looks alive from the master's side.

---

## D-017 — `fuzz` has no `--coverage` flag; the directory is implicit

**Confirmed**, `src/wtf/wtf.cc:308-310`:

```cpp
if (Opts.CoveragePath.empty()) {
  Opts.CoveragePath = Opts.Fuzz.TargetPath / "coverage";
}
```

`--coverage` exists **only on `run`** (`wtf.cc:270`). On `fuzz` the coverage
directory is derived from `--target` and cannot be overridden.

**This is the actual mechanism of edge 22** (interface 3 → every worker):
breakpoints are delivered by *placing `.cov` files in
`targets/<name>/coverage/`*, not by a CLI argument. `fuzzer/workers.py` must
therefore ensure every worker's `--target` points at a tree containing the
generated coverage files — there is no per-worker override to reach for.

Same pattern for the snapshot: `wtf.cc:305` defaults `--state` to
`<target>/state`, and `:312` derives `mem.dmp` from it.

Also confirmed at `wtf.cc:267-268`, the authoritative statement of D-013:
`--limit` is *"instruction count for bochscpu, time in second for whv"*.

---

## D-018 — Crashes are written by the MASTER, and an unnamed crash is dropped

**Confirmed**, `src/wtf/server.h:861-866`:

```cpp
if (const auto &Crash = std::get_if<Crash_t>(&Result)) {
  if (Crash->CrashName.size() > 0) {
    const auto &OutputPath = Opts_.CrashesPath / Crash->CrashName;
    const auto &Success = SaveFile(OutputPath, ...);
```

This answers §12.5's open question — *"whether crashes are written by each
worker locally, forwarded to the master, or both"* — as **master-side only**.
The worker reports a `Crash_t` result over the wire; the master writes the
file, named by `Crash_t::CrashName`.

Two consequences:

1. **An empty `CrashName` is silently discarded.** No warning, no file. Every
   `Backend->Stop(Crash_t(...))` in our module must pass a non-empty,
   collision-resistant name, and GATE 4 must assert a crash actually reaches
   `crashes/`.
2. **`CrashRecord.worker_id` is not available from the file.** The contract
   field required by §12.5 cannot be filled from the crash directory alone,
   because the master writes all of them into one place with no worker tag. It
   has to come from correlating the master's connection state, or by encoding
   the worker id into `CrashName` from inside the module. Decided at CP4b;
   until then `worker_id` stays `None` rather than being faked.

Related, `src/wtf/corpus.h:66-71`: files in `outputs/` are named
`[<result>-]<blake3hex>`, where the prefix is present only when the result is
not `Ok_t` — so `timedout-…`, `cr3-…`, `crash-…`.

---

## D-019 — BLOCKER: the tlv_server snapshot is rejected by this revision of wtf

**Confirmed by running it.** CP1 now *mandates* `fuzzer_tlv_server`, but:

```
> wtf.exe run --name tlv_server --state state --backend=bochscpu \
      --input inputs\normal.json --limit 10000000
There is a fpst register that isn't set to 0xInfinity which should not happen, bailing.
LoadCpuStateFromJSON failed, no take off today.
```

Root cause, `src/wtf/utils.cc:174-195`. `LoadCpuStateFromJSON` accepts **two**
encodings of the x87 `fpst` array:

```cpp
// This is what `bdump` outputs and what 'old' wtf used, so let's keep that working.
if (Json["fpst"][Idx].is_string()) {
  const std::string &Value = Json["fpst"][Idx].get<std::string>();
  const bool Infinity = Value.find("Infinity") != Value.npos;
  if (!Infinity) { ...bail... }
  BdumpGenerated = true;
} else {
  Fraction = ...Json["fpst"][Idx]["fraction"]...;
  Exp      = ...Json["fpst"][Idx]["exp"]...;
}
```

The two shipped snapshots use *different* encodings, and only one still loads:

| Target | `regs.json` dated | `fpst[0]` | Loads? |
|---|---|---|---|
| `tlv_server` | 2022-02-13 | `"0x0"` (string) | **NO** — string branch demands `Infinity` |
| `hevd` | 2024-05-26 | `{"exp":"0x0","fraction":"0x0"}` | yes |

So the string branch tolerates exactly one legacy value, `"0xInfinity"`, and
tlv_server predates even that. Our clone is at `a490929`, newer than the
v0.5.7 release the archives ship with — the compatibility window closed between
the two.

### The obvious fix is the wrong one

The tempting repair is to rewrite the eight `"0x0"` strings into the modern
object form `{"exp":"0x0","fraction":"0x0"}`, on the reasoning that both encode
an all-zero x87 stack: the string branch leaves `Fraction`/`Exp` at their
initialised `0` and `utils.cc:197-198` applies `.value_or(0)`.

**That reasoning is incomplete and the change would silently corrupt the CPU
state.** `BdumpGenerated` is not just a parse flag — `utils.cc:204-216`:

```cpp
if (BdumpGenerated) {
  // The bdump project dumps the @fptw correctly but WinDbg encodes it in a
  // special way that makes it uncorrect to be loaded directly into a CPU's
  // fptw. [...]
  const auto Fptw = Fptw_t::FromAbridged(CpuState.Fptw.Value);
```

The string form additionally means *"`fptw` in this file is the **abridged**
8-bit FXSAVE tag word, convert it"*. `Fptw_t::FromAbridged`
(`globals.h:1055-1067`) maps each 0 bit to `0b11` (empty), so
`FromAbridged(0x0)` = `0xFFFF`.

The two shipped snapshots agree on the *state* and differ only in *encoding* —
which is exactly what the flag exists to distinguish:

| Target | `fpst` form | `fptw` in file | `BdumpGenerated` | `fptw` loaded | meaning |
|---|---|---|---|---|---|
| `tlv_server` | string | `0x0` (abridged) | true | `0xFFFF` | 8 registers empty |
| `hevd` | object | `0xffff` (full) | false | `0xFFFF` | 8 registers empty |

So converting to the object form would set `BdumpGenerated = false`, skip the
conversion, and load `fptw = 0x0` raw — a tag word claiming **all eight x87
registers hold valid values** when the stack is empty. No error, no warning.

**Applied fix:** rewrite the `fpst` sentinels to the legacy value the string
branch expects, keeping `BdumpGenerated` true:

```diff
-"fpst":["0x0","0x0","0x0","0x0","0x0","0x0","0x0","0x0"]
+"fpst":["0xInfinity","0xInfinity","0xInfinity","0xInfinity","0xInfinity","0xInfinity","0xInfinity","0xInfinity"]
```

56 characters changed, nothing else. The original is preserved at
`state/regs.json.v0.5.7-original`. Confirmed by wtf itself on the next run:

```
Setting @fptw to 0xffff as this is an old dump taken with bdump..
```

which is byte-identical to the `fptw` hevd loads. See DECISIONS DEC-011 for why
this counts as a format repair rather than a modification of the target.

**Worth noting as a general lesson for this project:** the first fix looked
provably safe and was justified with a real source citation, and was still
wrong, because the citation stopped one branch short. This is the failure mode
RULE 4 describes — the gap produces a silent wrong answer, not an error.

---

## D-023 — Windows symbol resolution needs `_NT_SYMBOL_PATH`; wtf never sets it

**Confirmed by running it.** With the `fpst` issue fixed, `tlv_server` still
failed:

```
Could not set a breakpoint at tlv_server!ProcessPacket.
Could not initialize target fuzzer.
```

`fuzzer_tlv_server.cc:82` resolves breakpoints by **symbol name**
(`tlv_server!ProcessPacket`, `tlv_server!printf`), and
`SetupUsermodeCrashDetectionHooks` adds kernel ones (`nt!KeBugCheck2`, ...).

On Windows the resolver is `WindowsDebugger_t`, which uses dbgeng's
`IDebugSymbols3` (`debugger.h:111-115`). dbgeng needs PDBs, and **wtf sets no
symbol path** — it only copies `dbghelp/symsrv/dbgeng/dbgcore.dll` next to the
executable (`debugger.h:195-230`). This host had **no** `_NT_SYMBOL_PATH` at
machine, user or process scope and no local symbol cache.

Note `state/symbol-store.json` does contain every needed symbol, but on Windows
it is **write-only**: `DebuggerLess_t` reads it (`debugger.h:30-60`, the Linux
path) while `WindowsDebugger_t` merely *appends* to it via `AddSymbol`
(`debugger.h:146-166`). So the cache shipped in the archive does not help here.

Resolution, in two stages, because each exposed the next:

1. Local PDB — `targets/tlv_server/target/tlv_server.pdb` ships in the archive.
   Adding that directory resolved `tlv_server!*`.
2. Kernel symbols — then `nt!KeBugCheck2` failed, needing `ntoskrnl.pdb` for
   the *guest's* Windows build. Requires the Microsoft symbol server.

```
_NT_SYMBOL_PATH=srv*C:\symbols*https://msdl.microsoft.com/download/symbols;<target>\target
```

First run then took **373 s**, nearly all of it PDB download; subsequent runs
are fast because `C:\symbols` caches them.

`hevd` worked with no symbol path at all, which is why this surfaced only on the
second target — more evidence for DEC-009's "run both" (its kernel symbols
happen to be resolvable from the loaded module's exports in that dump).

**Actions:** `config/fuzz.yaml` records the symbol path as a required piece of
run configuration; `fuzzer/run.py` and `fuzzer/workers.py` must set it for every
worker, since a worker that cannot resolve its breakpoints fails at `Init` and
contributes nothing while the master keeps waiting for it.

---

## D-024 — wtf already dedups crashes by filename, and it is not enough

**Measured**, GATE 1 run: 150 s, one worker, bochscpu.

The master's own counter reached **1113 crashes** by 24 s uptime, but only
**38 files** exist in `crashes/`. The collapse happens because the crash
filename *is* the key:

```
crash-EXCEPTION_ACCESS_VIOLATION_READ-0x7ff8aa381423
      ^ exception kind                ^ fault address
```

`Crash_t::CrashName` is built from the exception kind and fault address
(`crash_detection_umode.cc`), the master writes `crashes/<CrashName>`
(`server.h:861-866`), and `SaveFile` (`utils.cc:410-414`) **skips a file that
already exists**. So wtf ships a de-facto dedup on `(fault_type, fault_addr)`.

That is exactly the fallback key CLAUDE.md CP8 proposes when backtrace recovery
is unreliable — good corroboration. **But the measurement also shows why the
fallback is not sufficient**, which is the more useful result:

| | count |
|---|---|
| crash events reported by the master | 1113 |
| files written (dedup by fault addr + kind) | 38 |
| distinct fault addresses | 38 |
| span from lowest to highest fault address | **926 bytes** |
| exception kinds | 37 READ, 1 WRITE |

All 38 "distinct" crashes land inside a **926-byte window** — a single
function, almost certainly one vectorised `memcpy`-style routine reached with a
bad length. Address-based bucketing splits **one bug into 38 buckets**.

Sent to a 550B model at one call per bucket, that is 38× the intended spend on
a single bug, on one target, from 150 seconds of fuzzing. Scaled to a real
campaign with N workers it is exactly how the NCHC allocation gets burned.

**This is the concrete, measured justification for CP8's stack-hash design**,
and a ready-made evaluation datapoint: *38 → 1* is a number the writeup can
quote. It also confirms two config choices already made:
`dedup.fallback_key: [fault_static_addr, fault_type]` is right as a *fallback*,
and `collapse_cross_worker_duplicates: true` matters because this volume is
per-worker.

One caveat for CP8: these filenames carry **runtime** addresses
(`0x7ff8aa38xxxx`). Section 10 forbids hashing those — they must be de-slid to
static addresses first (section 9), or the same bug buckets differently across
runs.

---

## D-020 — A stray quote in the machine `PATH` breaks every Developer Command Prompt

**Confirmed on this host.** `vcvars64.bat` aborts with:

```
\VMware\VMware was unexpected at this time.
```

The machine `PATH` contains an entry with an unbalanced double quote:

```
C:\Program Files\Cloudflare\Cloudflare WARP"
```

Batch parsing treats everything after it as one quoted string, so the `if`/`for`
handling inside `vcvars64.bat` hits `C:\Program Files (x86)\VMware\VMware
Workstation\bin\` unquoted and dies on the unescaped parentheses.

Nothing to do with wtf, but it blocks **every** MSVC build on this machine, so
`fuzzer/build.py` (CP4) must not assume a clean environment.

**Worked around, not fixed:** the build wrapper strips `"` from every `PATH`
entry in its own process before calling `vcvars64.bat`. No system state is
changed and no admin rights are needed. The permanent fix — editing the machine
`PATH` — is the user's to make, and is worth making: anything else invoking a
Developer Command Prompt on this host hits the same wall.

---

## D-021 — No writer for the aggregated `coverage.cov` was found in the source

**Unresolved.** §13.4 states the master maintains an aggregated `coverage.cov`
holding unique aggregated coverage, and §12.1 recommends the sidecar watch that
file for growth as the v1 plateau signal.

Grepping the tree for `coverage.cov`, `CoveragePath`, `WriteCoverage` and
`SaveCoverage` finds only **readers** — `Opts.CoveragePath` is consumed by
`ParseCovFiles` (`utils.cc:342`, via `whv_backend.cc:488` and
`kvm_backend.cc:2638`) and is otherwise a plain input path.

In memory the aggregate certainly exists: `server.h:822-830` maintains
`Coverage_` as a set and reports `Coverage_.size()` through `Stats_`. What is
unconfirmed is whether that set is ever serialised to disk in this revision.

**Deliberately not coded around** (RULE 4). CP1 settles it by observation — run
a master and see whether the file appears. If it does not, `engine_bridge/
coverage.py` needs a different read path (parsing the master's stats output is
the obvious fallback), and that decision belongs to CP4b.

---

## D-022 — CLAUDE.md still says "four signals" in two places

**Minor, internal to CLAUDE.md.** §3.2 (edges 38–41b), §8 CP9 and §9's
anti-pattern list all describe **five** triage signals. Two leftovers still say
four:

- §6, the `TriageVerdict.signals_used` comment: *"must name all four when
  available"*.
- §8 GATE 9's opening: *"triage consumes all four signals"*.

`arch/contracts.py` implements **five** (`TRIAGE_SIGNALS`), since the edge list
and CP9's own body are unambiguous and the fifth signal is the entire point of
separating dynamic from static evidence. Flagged so the writeup does not repeat
the stale count.

---

## D-025 — wtf's Ghidra script cannot run on a stock Ghidra 12

**Confirmed by running it.** D-006 recorded `scripts/gen_coveragefile_ghidra.py`
as the format oracle for CP2. It is a **Jython** script, and Jython is no longer
part of a default Ghidra install.

In Ghidra 12.1.2:

- Jython ships only as an **optional extension**, unpacked but not installed:
  `Extensions/Ghidra/ghidra_12.1.2_PUBLIC_20260605_Jython.zip`.
- `.py` scripts are routed to `PyGhidraScriptProvider`, and
  `analyzeHeadless` cannot start PyGhidra. A `.py` post-script fails with:

  ```
  ERROR REPORT SCRIPT ERROR: ProbeScript.py : Ghidra was not started with PyGhidra.
  Python is not available
      at ghidra.pyghidra.PyGhidraScriptProvider.getScriptInstance(PyGhidraScriptProvider.java:75)
  ```

- `support/analyzeHeadless.bat` contains no mention of pyghidra or python;
  PyGhidra has its own launcher (`support/pyghidraRun`) and a separate
  "Python drives Ghidra" model via the bundled `pypkg` wheels.
- Of the 191+4 scripts Ghidra bundles in `Ghidra/Features/Base/ghidra_scripts`,
  **191 are `.java`** and 4 are `.py`.

**Action:** `prep/ghidra_scripts/ExportBasicBlocks.java` is written in Java. See
DECISIONS DEC-012 for why that rather than installing Jython or adopting
PyGhidra. wtf's script remains the *format* oracle — we match its output shape —
but it is not runnable here and is not on our critical path.

Note this does not weaken CP2's validation, because the **output** of that
script is what matters and we have it: the shipped
`targets/tlv_server/coverage/tlv_server.cov` is a real reference answer to diff
against, which is better than re-running the generator.

---

## D-026 — `analyzeHeadless` exits 0 even when the post-script throws

**Confirmed.** The PyGhidra probe above failed with `SCRIPT ERROR`, and
`analyzeHeadless` still returned **exit code 0**. It also printed
`REPORT: Save succeeded` and `Import succeeded` afterwards.

So the exit code reports *import and analysis*, not script success. Anything
driving it must treat **the artifact as the only success signal**.

`prep/ghidra_headless.py` therefore checks that the output file exists and
contains at least one block, and raises otherwise. Without that, CP2 would
"succeed" and produce no coverage file, and the failure would only surface much
later as a fuzzing run with mysteriously low coverage — which wtf itself reports
as a warning, not an error (D-005).

---

## D-027 — Ghidra finds 97.4% of wtf's reference blocks, and 97 it did not

**Measured**, tlv_server.exe, Ghidra 12.1.2 vs the shipped `tlv_server.cov`.

| | count |
|---|---|
| shipped `.cov` (author's tooling) | 530 |
| ours, `--scope=module` | 613 |
| in both | 516 |
| shipped only (**we miss**) | 14 |
| ours only (extra) | 97 |
| **recall of the reference set** | **97.4%** |
| ours, `--scope=function-closure` from `ProcessPacket` | 58 |
| closure blocks also in the reference | **58 / 58** |

Reading these numbers correctly matters, because the two error directions have
very different costs:

- **Extra blocks are cheap.** An address wtf cannot translate is skipped with a
  warning (D-005); a genuine-but-redundant breakpoint costs a little speed.
- **Missing blocks are silent coverage loss.** They are simply never counted,
  and nothing anywhere reports it. The 14 misses are 2.6% of the reference.

That asymmetry is why `tests/gates/test_cp2.py` gates on **recall** (>= 95%)
rather than on exact agreement, and separately asserts the closure set is a
subset of the reference (58/58) so scoping cannot invent addresses.

The closure result is also a useful sanity check on its own: 14 functions,
`ProcessPacket` (38 blocks) plus allocation helpers (`operator_new`,
`make_unique<Chunk_t>`, `operator_delete[]`, ...) and `printf`. That is exactly
the shape a TLV parser's call closure should have, and the `Chunk_t` names come
from the PDB shipped alongside the binary.

**Known limitation, recorded rather than hidden:** the closure follows only
**static** call edges. Ghidra resolves few indirect calls, so the closure is a
*lower bound* on what executes. If a target dispatches through function
pointers or a vtable, `--scope=function-closure` will under-instrument it
silently. `--scope=module` is the escape hatch, and CP4's coverage numbers are
the place this would show up.

---

## D-028 — `disable-kva.cmd` is part of the snapshot procedure and is documented nowhere

**Confirmed.** D-007 listed this script's role as unverified. It is two
registry writes:

```bat
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" \
    /v FeatureSettingsOverride     /t REG_DWORD /d 3 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" \
    /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f
```

Those disable the Spectre v2 (CVE-2017-5715) and Meltdown (CVE-2017-5754)
mitigations. The relevant one is Meltdown: **KVA shadow** maintains separate
kernel and user page tables per process, which interferes with snapshot-based
execution.

A grep of the whole repo finds the script referenced **nowhere** — not in the
README, not in `linux_mode/`, not in any source file. It ships and is left for
the reader to notice.

Three things this means for CP3:

- it runs **inside the guest VM**, not on the host, and needs a **reboot**;
- it weakens the guest's security posture, which is acceptable for a
  throwaway fuzzing VM and would not be anywhere else — worth stating
  explicitly rather than having someone run it on a real machine;
- it belongs in the guest-preparation checklist alongside the README's own
  requirements (one virtual CPU, 4 GB RAM), which is where
  `prep/snapshot_win.py`'s `GUEST_PREP_NOTES` now puts it.

Whether snapshotting actually fails without it is **untested** — we have no VM.
It is included because wtf ships it for this purpose, not because we have
observed the failure.

---

## D-029 — `llama-3.3-70b` fails as an *agent* but is fine single-shot

**Measured** against the live endpoint, 2026-07-25.

CLAUDE.md §7.2 offers `ais3/llama-3.3-70b` **or**
`ais3/nemotron-cascade-2-30b` for fuzz-entry selection. The AIS3 README's own
evaluation matrix marks llama-3.3-70b **🔴 failed on all four coding agents**
(OpenCode, Claude Code, Codex, Copilot) — "stopped without producing the correct
flag or a valid output file".

Given a single-shot pseudo-C reasoning task with a JSON-only instruction,
however, it answered **correctly in 0.9 s**. So the matrix is measuring
*agentic tool-use over many turns*, not single-shot comprehension, and the two
do not transfer.

**Action:** `entry_select` routes to `nemotron-cascade-2-30b` — the alternative
§7.2 already sanctions. Both work for our shape of call, but there is no reason
to pick the one with a documented failure mode when the section offers a peer.
Recorded so the choice is not mistaken for an arbitrary deviation.

---

## D-030 — Reasoning models return `content: null` on HTTP 200

**Measured**, and the most dangerous LLM finding so far.

`ais3/gemma-4-12b` and `ais3/gemma-4-26b` are **reasoning models**: the response
carries `reasoning_content` alongside `content`, and the reasoning is billed
against `max_tokens`. Run the budget out during reasoning and the API returns
**HTTP 200**, `finish_reason: "length"`, and **`content: null`** — no error, no
exception, nothing a naive client would notice.

| model | max_tokens | finish_reason | reasoning chars | content |
|---|---|---|---|---|
| gemma-4-12b | 600 | length | 1,688 | **null** |
| gemma-4-12b | 4000 | stop | 5,737 | correct JSON |
| gemma-4-26b | 600 | length | 1,682 | **null** |
| gemma-4-26b | 4000 | stop | 10,682 | correct JSON |

Our own `config/llm.yaml` had `seed_gen: max_tokens: 2048` before this was
measured, which would have produced nulls under load and looked like "the LLM
had no suggestions".

Two further consequences:

- **§7.2's speed assumption is inverted.** It routes seed generation to
  gemma-4-12b as "cheap, fast; no deep reasoning needed". On the same task
  gemma-4-12b took **18.6 s** and gemma-4-26b **22.2 s**, versus **1.9 s** for
  nemotron-cascade-2-30b. You cannot ask a reasoning model to skip reasoning.
- `nemotron-3-ultra-550b`, the triage model, returns **no** `reasoning_content`
  and answered a trivial JSON prompt in 0.2 s — well-behaved.

**Actions:** `llm/client.py` (CP5) must treat `content is None` and
`finish_reason == "length"` as retryable errors, never as an empty answer;
`config/llm.yaml` records this under `response_handling` and sizes every
`max_tokens` for reasoning **plus** answer; `seed_gen` re-routed to
nemotron-cascade-2-30b on the measured latency.

---

## D-031 — Page-tail alignment recovers part of what having no ASAN costs

**Confirmed** in `src/wtf/fuzzer_tlv_server.cc:116-124`:

```cpp
// Calculate the address of the packet buffer and push it as close
// as possible to the end of the page so that out-of-bounds hit the
// guard page behind.
const auto &PacketOriginalAddress = Backend->Rcx();
auto PacketAddress = PacketOriginalAddress + (0x1'000 - PacketSize);
```

The packet is written flush against the **end** of its page, so the guard page
sits immediately behind the buffer and a read past it **faults** instead of
quietly succeeding.

This matters more than it looks. DEC-001 accepts that "silent memory corruption
is out of scope" because there is no ASAN, and §2 lists *"an out-of-bounds read
into mapped memory"* as specifically undetectable. Page-tail alignment converts
a slice of exactly that class into observable access violations, for free, with
no instrumentation and no slowdown.

It is **not** a sanitiser: it only catches overruns that cross the page
boundary, so an overread of a few bytes inside the same page still passes
silently, and it says nothing about writes to already-valid memory. But it is
a real, cheap partial mitigation and the report should say so rather than
presenting the binary-only oracle as uniformly blind.

**Action:** adopted in `fuzzer/module/fuzzer_snapfuzz.cc` and recorded in
`config/target.yaml` as `injection.page_tail_align`. Worth applying to any
target whose buffer placement we control.
