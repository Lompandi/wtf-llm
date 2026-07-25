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

---

## D-032 — Hyper-V is unavailable on this host; VMware is already installed

**Confirmed 2026-07-25.** CLAUDE.md section 13.6 step 1 says *"Target in a
Hyper-V VM, one virtual CPU, 4GB RAM"*, and CP3's acquisition path depends on it.

This host is **Windows 11 Home** (build 26200; `Get-ComputerInfo` reports the
product name as "Windows 10 Home"). **Hyper-V and Hyper-V Manager are
Pro/Enterprise features and are not available on Home.** `HyperVisorPresent` is
`False`, so no hypervisor is currently running. The hardware is fully capable —
DEP, SLAT, virtualization firmware and VM monitor mode extensions all report
available — so this is purely an edition restriction. (`Get-WindowsOptionalFeature`
needs administrator rights and was not run.)

**But the requirement is weaker than the README implies.** What the snapshot
procedure actually needs is a Windows guest with **KD attached**, one virtual
CPU and 4 GB of RAM. KD attaches over a serial port mapped to a named pipe,
which is not a Hyper-V-specific facility. Hyper-V is what the author used, not
an inherent dependency.

And two of the three pieces are already on this machine:

| Piece | Status |
|---|---|
| Hypervisor | **VMware Workstation 17.6.2** — installed (it is what put the stray quote adjacent to `PATH`, D-020) |
| Kernel debugger | **`kd.exe` 10.0.26100.7705** — installed, in the Windows 10 SDK Debuggers directory. This is also why wtf found `dbgeng.dll`/`symsrv.dll` to copy (`debugger.h:195-230`) |
| `!snapshot` extension | **`snapshot.dll` v0.2.5** — now downloaded to `D:\tools\snapshot` |
| A Windows guest VM | **MISSING** — no VMs exist on disk |

So the remaining work is *creating a guest*, not installing virtualisation:

1. obtain a Windows ISO (~5.5 GB) — interactive, and a licensing decision;
2. create the VM with **one vCPU** and 4 GB RAM, install Windows;
3. in the guest, run `scripts/disable-kva.cmd` and reboot (D-028);
4. add a serial port mapped to a named pipe and enable kernel debugging in the
   guest (`bcdedit /debug on /dbgsettings serial`), then attach `kd.exe`;
5. `.load D:\tools\snapshot\snapshot.dll` and `!snapshot <state_path>`.

Steps 1–2 need GUI interaction and a product key, so they are the user's; steps
3–5 are scripted by `prep/snapshot_win.py`'s `build_kd_commands` and
`GUEST_PREP_NOTES`.

**Consequence for DEC-005.** That decision pins the scaled GATE 4b run to the
`whv` backend because it is the only local backend that consumes the CP2
coverage file. `whv` needs the Windows Hypervisor Platform, which needs the
hypervisor running — and `HyperVisorPresent` is `False`. Whether WHP can be
enabled on Home was **not** established (it requires admin to query). If it
cannot, GATE 4b's options narrow to bochscpu with N workers, which exercises
coverage aggregation but **not** edge 22, since bochscpu ignores `.cov` files
(D-004). Flagged now rather than discovered at CP4b.

---

## D-033 — wtf block-buffers stdout, and terminating it loses the last buffer

**Measured.** wtf prints through C stdio, which block-buffers when stdout is not
a console. Consequences that broke a working-looking campaign runner:

* Through a **pipe**, a 90-second run produced **zero** parsable stat lines. The
  runner ticked six times, saw nothing, and reported `coverage grew: False` —
  while the fuzzer was in fact running at 360 exec/s the whole time.
* `terminate()` is `TerminateProcess` on Windows, which **never flushes**. So
  the final buffer is lost, and with it the last few minutes of stat lines.
* Flushes arrive roughly every 4 KB. At ~130 bytes per stat line every 10 s
  that is one flush per ~5 minutes.

This also explains the truncated tail (`Sa`) in the GATE 1 log, which at the
time looked like an artefact of killing the process mid-write.

**It is worse than block buffering, and three fixes failed before the right one.**

1. **Pipe → file.** Redirecting to a file and tailing it by offset is what the
   GATE 1 manual test happened to do, and it worked there. It is not enough: a
   663-second run left only **8 stat lines covering the first 72 seconds**.
2. **Ctrl+Break instead of terminate.** `TerminateProcess` never flushes, so the
   master is sent `CTRL_BREAK_EVENT` in its own process group first, on the
   theory that the C runtime's default handler exits normally and flushes. The
   master *accepts* it and exits — and a 123-second run still produced a
   **0-byte** log.
3. So **wtf's stat lines cannot be relied on at all**: not for short runs, and
   never for the tail of any run.

**The signal that does work is the filesystem.** The master writes a testcase
into `outputs/` exactly when one produced **new coverage**
(`server.h:830-836` → `Corpus_t::SaveTestcase`), and a file appearing on disk is
not buffered. During that same 0-byte-log run the fuzzer saved **30**
new-coverage testcases — it was perfectly healthy and entirely unobservable
through stdout.

**Actions:**

* `fuzzer/run.py` counts `outputs/` per tick as the **primary** coverage-growth
  signal, and records `new_coverage_events` in `artifacts/run_metadata.json`.
  Stat lines are parsed when they happen to arrive and treated as a bonus.
* Precisely what that counts: **new-coverage events**, not covered edges. It is
  monotonic, and sufficient to answer "is coverage growing" and to detect a
  plateau — which is what CP7 needs.
* `fuzzer/run.py` records its own `duration_s` rather than the master's
  `uptime`, which truncates with the log.
* `master_log_truncated` is recorded so a short observed history is never
  mistaken for a short run.

**Consequence for CP7.** Section 12.1 suggests watching an aggregated
`coverage.cov` for growth, and section 12.3 wants plateau on aggregate coverage.
No such file is written (D-021) and the master's stdout is unusable, so
`outputs/` growth is the plateau input. It is still genuinely *aggregate* —
the master owns `outputs/` and writes there on behalf of every worker — so
section 12.3's requirement is met, just by a different route than suggested.

The same buffering trap applies to our own Python output through a pipe, which is
why the first campaign's progress prints were invisible; `-u` fixes that side.

---

## D-034 — Structured output needs the schema, not a description of it

**Measured** while building CP5. `complete_json` originally instructed
"respond with a single JSON object" and described the wanted fields in prose.
The model returned well-formed JSON with **invented neighbouring field names**:
`memcpy_offset` where the contract said `length_offset`, and a required field
simply absent.

The retry could not recover, because the feedback said validation failed without
ever stating what the property names were meant to be. Two attempts, two
failures, allocation spent for nothing.

**Action:** `complete_json` now embeds `model_cls.model_json_schema()` in the
prompt and instructs the model to use exactly those property names. The same
call then succeeds first try.

Worth carrying into CP6 and CP9: every structured call goes through this path,
so `FuzzEntry` and `TriageVerdict` get their schemas handed to the model rather
than paraphrased. Paraphrasing a contract is how the contract and the prompt
drift apart.

---

## D-035 — Most faults are not in the target module, so de-sliding needs attribution

**Measured** on the GATE 4 run: 55 crash records, and **48 of them faulted in
`0x7ff8aa3812de`–`0x7ff8aa38167c`**. That range is nothing to do with
`tlv_server` (base `0x7ff719e50000`). It sits about **192 KB below
`verifier.dll`** (base `0x7ff8aa3b0000`) and matches no module
`symbol-store.json` lists — most plausibly part of the Application Verifier
stack the snapshot was taken with (D-014).

Section 9 says convert runtime addresses to static before hashing. Applied
naively that is wrong, because **the conversion is per-module**: de-sliding a
non-target address with the target's slide gave

```
0x7ff8aa3812de - 0x7ff719e50000 + 0x140000000 = 0x2d05312de
```

a number that means nothing. It would have hashed cleanly, bucketed
consistently, and been entirely fictitious — the failure mode is invisible.

**Fixed** in `engine_bridge/crash_watch.py`: a fault is de-slid **only** when it
falls inside the target module's range, and attributed only when it falls inside
some declared range. Otherwise `fault_static_addr` is 0 and `fault_module` is
None. `CrashRecord` gained `fault_module` so the distinction survives to CP8.

**Three consequences for CP8, which is where this really bites:**

1. **Fault-address bucketing is even weaker than D-024 suggested.** Not only did
   1113 crash events collapse to 38 files spanning 926 bytes of one function —
   that function is not even in the code under test. Bucketing on it groups by
   *where the heap manager noticed*, not by *what the parser did wrong*.
2. **The stack hash must skip non-target frames**, or every bug in the target
   will share the verifier-side prefix and collapse into one bucket. Section 8
   says hash the top N frames; the useful N here starts after the frames that
   are not ours.
3. **This is the no-ASAN limitation showing its other face.** We are not seeing
   the overflow; we are seeing a guard mechanism react to it several frames
   later. That is *why* CP8 needs the execution trace (signal 4) to walk back to
   the origin, and it is concrete evidence for that design rather than an
   assertion.

Also observed: `STATUS_HEAP_CORRUPTION` appeared as a fault type, which is not in
our name map. It passes through verbatim by design — an unfamiliar fault class is
information, not noise.

---

## D-036 — The Windows Hypervisor Platform is not enabled, so edge 22 stays pending

**Confirmed by running it.** `wtf run --backend=whv` fails immediately:

```
Failed WHvCreatePartition (Windows Hypervisor Platform enabled?)
Backend failed initialization.
```

`whv` is the only backend available on this host that **consumes** the CP2
coverage file — bochscpu ignores `.cov` files entirely (D-004) and `kvm` is
Linux-only. So **edge 22** (`fuzz_target.bp_list` → `worker[i].execute`) cannot
be exercised here, and it stays `pending` through GATE 4 and GATE 4b.

This is exactly what DEC-005 anticipated. The file is generated, validated
against wtf's own reference (D-027) and placed in `targets/<name>/coverage/`, but
placement is not consumption, and marking the edge live on the strength of the
file existing is the failure RULE 3 exists to prevent.

WHP is an optional Windows feature, not a VM, and is used by WSL2 and Docker —
so it is plausibly available even on Home (D-032 notes Hyper-V itself is not).
Enabling it needs administrator rights and a reboot:

```powershell
# Run as administrator, then reboot.
Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -All
```

Once the hypervisor is running, `python -m fuzzer.run --backend whv --workers 4`
should close edge 22. Deliberately **not** done here: it is a system-level change
with a reboot, and it is the user's to make.

---

## D-037 — Two campaigns collide on the default master address

**Observed** while running the CP4b tests against a background campaign: the
second master exits immediately and the test failed with "the master is not
running", which looked like a bug in the kill/restart logic.

`master --address` and `fuzz --address` both default to `tcp://localhost:31337`
(`wtf.cc:79`, `wtf.cc:392`), so a second campaign cannot bind and dies. Nothing
in the output says "port in use" — the master simply is not there.

`CampaignConfig` already carries `address`, so concurrent campaigns are possible
with distinct ports. Worth remembering for CP10's baseline comparison, which
will want to run vanilla-mutator and LLM-guided campaigns **simultaneously** on
the same host to control for machine load — they must be given different
addresses or the second one silently will not exist.

---

## D-038 — Gate evidence needs per-gate directories

**Observed.** GATE 4b's 4-worker run overwrote `artifacts/run_metadata.json`,
and GATE 4 — which requires a *single-worker* run of >= 10 minutes — began
failing retroactively on evidence that had been perfectly good an hour earlier.

Nothing was wrong with either run. The bookkeeping was wrong: one shared
artifact path meant each gate's evidence destroyed the previous gate's.

**Fixed:** `fuzzer/run.py --label <name>` writes to `artifacts/runs/<name>/`,
and each gate reads its own directory (`runs/gate4`, `runs/gate4b`). The master's
log is copied in alongside, since it is written live and cannot be redirected
after the fact.

Worth generalising: a gate that reads a mutable shared path is not reproducible,
and CP7 and CP10 both need before/after comparisons across runs. Every future
gate run gets a label.

---

## D-039 — GhidraMCP predates Ghidra 12 and needs repacking

**Confirmed.** GhidraMCP's latest release is **1.4 (2025-06-23)**; our Ghidra is
**12.1.2 (2026-06-05)**, a year and a major version newer. Two independent
incompatibilities, both fixed by repacking:

1. **Declared version.** `extension.properties` says `ghidraVersion=11.3.2`, and
   Ghidra refuses to load an extension whose declared version does not match.
2. **`Module.manifest` format changed.** GhidraMCP ships the old `KEY=VALUE`
   form and Ghidra 12 rejects it outright:

   ```
   Module manifest file error on line 2 of .../GhidraMCP/Module.manifest
       -> Invalid line encountered: GHIDRA_MODULE_NAME=GhidraMCP
   ```

   Ghidra 12 manifests contain `MODULE FILE LICENSE:` and `##MODULE IP:` lines
   instead, and a manifest holding only a comment is valid (see the bundled
   `BSimFeatureVisualizer`).

3. **The `extension.properties` schema itself changed**, and this is the one
   that actually mattered. A first repack set `version=1.4` and
   `ghidraVersion=12.1.2`, on the assumption that `version` was the extension's
   own version. Ghidra 12 **silently ignored the extension** — no log line, no
   dialog, and the extension-point count unchanged. It simply never appeared in
   File → Configure.

   Comparing against a bundled Ghidra 12 extension (`SampleTablePlugin`) showed
   the real schema:

   ```properties
   name=SampleTablePlugin
   description=Sample plugin for creating and manipulating a table
   author=Ghidra Team
   createdOn=pre-4/6/2015
   version=12.1.2          <- the GHIDRA version; this is the compatibility key
   ```

   There is **no `ghidraVersion` key at all** in Ghidra 12, and `Module.manifest`
   is **0 bytes**. So the correct repack is `version=12.1.2`, no `ghidraVersion`,
   and an empty manifest.

**Installed** at `D:\tools\ghidra_12.1.2_PUBLIC\Ghidra\Extensions\GhidraMCP`,
which is the right location (matches the bundled extensions' layout; there is no
user-level extension directory and no extension entry in `preferences`).

**API compatibility: checked, not assumed.** Every `ghidra/*` class the plugin
references was extracted from its constant pool and looked up across all 203
Ghidra 12 jars (55,793 classes): **51 referenced, 0 missing**, including
`ghidra.app.decompiler.DecompInterface` and `DecompileResults`, which is what
the `/decompile` endpoint needs. So the class will link.

Confirmed from the bytecode rather than the README: `DEFAULT_PORT = 8080`,
configurable via a "Server Port" option, and the endpoints are `/methods`,
`/classes`, `/decompile`, `/segments`, `/renameFunction`, `/renameData`,
`/renameVariable`.

4. **It is listed under the `Developer` plugin package, not `Miscellaneous`.**
   This cost the most time, because "the extension is installed but does not
   appear in File → Configure" looks exactly like a load failure. It was not.
   From the `@PluginInfo` annotation in the bytecode:

   ```
   status      = RELEASED
   packageName = Developer
   category    = Analysis
   ```

   Ghidra's Configure dialog groups by **package**, so it appears under
   **Developer**. Nothing was wrong by the time we looked there.

**Verified working, 2026-07-25.** `/methods` returns 200 functions including
`ProcessPacket`; `POST /decompile` with the function name as the request **body**
returns 4,867 characters of pseudo-C. GATE 6's "GhidraMCP answers a live
decompile request" is satisfied.

The endpoint contract, for `llm/ghidra_mcp.py`:

| | |
|---|---|
| base | `http://127.0.0.1:8080` (`DEFAULT_PORT`, configurable via the "Server Port" option) |
| `/methods` | function names, one per line; takes `limit` |
| `/decompile` | **POST**, function **name** as the raw body, returns pseudo-C |
| others | `/classes`, `/segments`, `/renameFunction`, `/renameData`, `/renameVariable` |

**The operational constraint remains, and it shapes CP6/CP8.** GhidraMCP is a GUI
plugin: the server runs only while a Ghidra GUI is open with the program loaded
and the plugin enabled. `analyzeHeadless` never instantiates it. So it cannot be
part of an unattended pipeline, which is why A2 is built by **batch headless
decompilation** and GhidraMCP serves only the interactive on-demand lookup for an
address missing from the cache.

Note also that this pseudo-C is unusually good because `tlv_server.pdb` ships
alongside the binary — real parameter and function names. A genuine no-source
target yields `FUN_140001150(long param_1, ...)`, which is the material
`entry_select` and triage must actually cope with (DEC-007).

**Scope consequence, worth being clear about.** GhidraMCP is *not* on the
critical path for **A2**: CP6 builds the pseudo-C cache by **batch headless
decompilation**, which needs no plugin. GhidraMCP serves only the **on-demand**
lookup for an address missing from the cache, which CP8 needs at triage time when
a fault lands somewhere uncached. So A2, `get_by_addr`, and `entry_select` can all
be built and gated before the GUI step happens.

If the plugin turns out to be broken on Ghidra 12, the fallback is a small
headless decompile service of our own — the same `analyzeHeadless` machinery CP2
already drives, exposed over a socket. Recorded now so the decision is not made
under pressure at CP8.

---

## D-040 — The frontier offered branches no input could steer

**Observed** at the first GATE 7 seed-generation round, which produced **zero new
coverage** while the LLM did everything asked of it: it aimed correctly at all five
frontier branches it was offered and reached none. Nothing was wrong with the
reasoning. The frontier itself was unactionable.

Of the five branches, one sat inside `operator_new`'s allocation-failure path, one
inside printf's internals, and one was a "packet is not big enough" guard that the
*harness* had no way to express — `InsertTestcase` always wrote the true byte count
into the size register, so the target could never be told that fewer bytes had
arrived.

Those are two different faults. A branch can be unreachable because **no input
steers it**, or because **our injection path cannot say the thing that steers it**.
Neither is visible in a frontier computed from the block graph plus coverage alone,
and they are fixed in different layers.

**Fixed in three layers, because no one of them covers the other two.**

1. **The harness gained the missing degree of freedom.** `Packet_t` now carries an
   optional per-packet `WireSize` (`fuzzer/module/fuzzer_snapfuzz.cc:85-100`) so a
   testcase can lie to the target about how many bytes arrived; `InsertTestcase`
   reports it in `rdx` when set (`fuzzer_snapfuzz.cc:230-241`), the generator
   occasionally emits a short one (`:477-481`), and `MutationTruncateWire` mutates
   it (`:605-614`). `ProcessPacket` opens with `if (param_2 < 8)`, so before this the
   branch was unreachable **by construction** — no seed, LLM-generated or otherwise,
   could have worked. It is also the realistic behaviour rather than a testing hack:
   a peer on a socket can send fewer bytes than its header claims, and a harness
   that cannot express that is under-testing the target.
2. **The frontier stopped offering allocator and stdio internals.** `_INPUT_OPAQUE`
   (`engine_bridge/plateau.py:179-189`) and `is_input_reachable()` (`:192-200`),
   applied by `compute_frontier(input_reachable_only=True)` (`:203-225`). The filter
   is about **reachability by input**, not about the code being uninteresting —
   worth keeping straight, because the second reading would justify filtering things
   that must stay. It is deliberately conservative for the same reason: an unknown
   function counts as reachable, since dropping a real parser is worse than
   including an allocator.
3. **The prompt now describes what the harness can do**, via
   `SeedGenRequest.format_notes` (`llm/seed_gen.py:178-181`). The example seed shows
   only the fields some corpus file happens to use; a capability it does not exhibit
   is one the model cannot know exists. A field the model cannot know about, guarding
   a branch it can never reach, is not a reasoning failure at any temperature.

**Generalise it:** the frontier is a claim that a branch is *worth aiming at*, and
computing it from coverage alone overstates that claim. Before a slow-clock round is
spent on a branch there are two questions — can any input steer it, and can our
injection path express that input. Only the first was being asked, and even that one
only implicitly.

---

## D-041 — Eight seeds, five bytes each

**Observed** at the second GATE 7 round, which also produced zero new coverage, for
a reason entirely unrelated to D-040 — which is what earns it its own entry.
`artifacts/seed_provenance.jsonl` gives it away immediately: all **eight** published
seeds of that round were **5 bytes** long.

The seed schema offered two content fields, `content` (text) and `content_hex` (hex
bytes). At temperature 0.9 (`config/llm.yaml:49`) the model chose `content_hex` for
a target that reads JSON text, and a short hex string unhexlifies into a handful of
raw bytes that `InsertTestcase` discards.

**Why this is worse than an error.** Those seeds were well-formed against the
schema, passed validation, consumed spool slots, were handed to a worker and
executed, and produced nothing. So the round looked exactly like the LLM having no
useful ideas — which is the failure mode that matters here, because it is
indistinguishable from a genuine dead end, and a genuine dead end is a legitimate
outcome the slow clock has to be allowed to report.

**Fixed:** `_matches_wire_format()` (`llm/seed_gen.py:153-166`) asks whether the
target could parse the bytes **at all** before a worker is spent on them, and
`generate_seeds` drops the ones that fail (`:363-372`). For a JSON target the test
is that the bytes decode as UTF-8 and parse to an object or an array — a structural
check on the *encoding*, deliberately not semantic validation. The prompt also
gained an explicit statement of which field to answer in for a textual target
(`:290-297`).

The prose half of that fix turned out not to be the half that worked. See D-046.

---

## D-042 — The sidecar launched wtf with no symbol path, and an empty frontier reads as "nothing left to explore"

**Observed** during CP7 bring-up. The worst-shaped failure in the project so far:
nothing errored, and the campaign politely reported that there was nothing left
to explore.

`llm/sidecar.py`'s `build_config()` never populated
`SidecarConfig.symbol_paths`. The field existed (`llm/sidecar.py:68`) and
`measure_coverage()` honours it (`llm/sidecar.py:182-183`), but nothing ever
filled it, so the `wtf run --trace-type=cov` child inherited no
`_NT_SYMBOL_PATH`.

That is D-023 again. wtf resolves breakpoints by symbol name through dbgeng and
sets no symbol path itself (`src/wtf/backend.cc:333-341`), and our module breaks
on `tlv_server!ProcessPacket` (`fuzzer/module/fuzzer_snapfuzz.cc:45`, `:210`), so
`Init` printed

```
Could not set a breakpoint at tlv_server!ProcessPacket.
```

and wrote **zero** trace files. From there every step is individually
well-behaved:

| step | result |
|---|---|
| `wtf run --trace-type=cov` | no `*.trace` files |
| `measure_coverage()` | empty set |
| `compute_frontier()` over an empty covered set | empty frontier |
| `generate_and_publish()` | logs `skipped`, reason **"frontier is empty"**, returns 0 |

**Which is exactly what makes it dangerous.** "frontier is empty" is the
*correct* thing to say about an empty coverage set — it is what the sidecar would
report on a target fuzzed to exhaustion. Zero seeds, zero LLM calls, zero errors,
and a plausible-sounding reason for all three.

`fuzzer/run.py` already had a preflight check for precisely this
(`fuzzer/run.py:236-240`, added at D-023). The sidecar was a second, independent
launcher of wtf that had never been given the same check — the cost of computing
symbol paths *inside* `CampaignConfig.from_yaml` instead of once, at module
level.

**Fixed**, three ways, because any one alone would have left the shape intact:

1. `resolve_symbol_paths()` factored out to module level in
   `fuzzer/run.py:49-75` and exported (`fuzzer/run.py:46`); `build_config()` now
   calls the same function (`llm/sidecar.py:397-399`).
2. `build_config()` raises on Windows when it comes back empty
   (`llm/sidecar.py:400-405`) rather than constructing a sidecar that cannot
   measure anything.
3. `measure_coverage()` raises `RuntimeError` when the run produced no `*.trace`
   files (`llm/sidecar.py:211-219`), quoting wtf's own output tail. An empty
   coverage set is never again returned as though it were a measurement.

**Generalise it:** every process that launches wtf needs the same environment, so
the code that builds that environment must be shared, not copied. Check for other
launchers before adding a third.

---

## D-043 — A reasoning model spends 60,000 characters before writing a seed

**Measured** from `logs/llm_usage.jsonl`. The same failure class as D-030, one
scale up, and it surfaced only once the seed-generation prompt grew by ~60 tokens.

`config/llm.yaml` had `seed_gen: max_tokens: 4096`. `seed_gen` routes to
`ais3/nemotron-cascade-2-30b`, which D-030 established is a reasoning model whose
reasoning is billed against `max_tokens`. On the **real** seed-generation prompt —
frontier blocks, pseudo-C, format notes — the reasoning is an order of magnitude
longer than on the trivial pseudo-C task D-030 measured:

| max_tokens | attempt | finish_reason | reasoning chars | completion tokens |
|---|---|---|---|---|
| 4,096 | 1 | length | 13,543-15,075 | 4,096 |
| 8,192 | 2 | length | 28,355-29,928 | 8,192 |
| 16,384 | 3 | length | 42,335-59,892 | 16,384 |
| 32,768 | 2 | stop | 38,352 | 11,823 |

Completion tokens equal `max_tokens` exactly on every `length` row: the budget was
consumed entirely by reasoning, and `content` came back null.

The client's doubling on truncation (`llm/client.py:325`) is what kept this
survivable — starting at 4096, attempt 3 reaches 16384 and often succeeds. But
`max_retries` is 3 (`config/llm.yaml:19`), so a round where 16384 was *also* not
enough had no attempt left, and one whole round died as

```
role 'seed_gen' failed after 3 attempts (final max_tokens=16384): ...
```

**Fixed:** `seed_gen: max_tokens: 16384` (`config/llm.yaml:56`, with the
measurement recorded in the comment above it). The client doubles from there, so
attempt 1 normally succeeds and the two wasted attempts are gone. And
`llm/client.py:340-343` now carries the final `max_tokens` and the underlying
`EmptyCompletion` into the terminal `LlmError` — the error string quoted above is
itself part of the fix, since the previous one named neither and diagnosing it
required a trip to the usage log.

**The lesson is not "use bigger budgets".** It is that reasoning cost scales with
the prompt's *substance*, not its length, so a `max_tokens` calibrated on a toy
prompt is not calibrated at all. Every future prompt change gets re-checked
against `finish_reason` in the usage log.

---

## D-044 — Seed generation had no feedback from its own results

**Observed** across consecutive rounds in `artifacts/sidecar_events.jsonl`, whose
`targets` fields read:

```
round A:  0x12de 0x12de 0x12ed 0x12ed 0x12ed 0x131c 0x131c 0x12ed
round B:  0x12de 0x12de 0x12ed 0x131c 0x12ed 0x12de 0x12de 0x131c
```

Six of eight seeds, twice over, aimed at the same two branches — and those two
are the ones no input has ever reached.

Nothing was wrong with the model's reasoning. The prompt simply contained no
record that a branch had already been aimed at and missed, so every round
re-derived the same idea from the same inputs. Temperature 0.9
(`config/llm.yaml:49`) buys diversity of wording, not diversity of strategy.

**This is the one quantity in the loop that could be measured and was not.** The
frontier is a static property of the block graph plus current coverage, so it
looks identical every round; the *outcome of the previous round* is the only new
information the slow clock has, and it was being discarded.

**Fixed:** the sidecar keeps `attempted: dict[static_addr, rounds aimed at it
without it becoming covered]` (`llm/sidecar.py:91-93`):

- **counted** after each round from what the model actually named
  (`llm/sidecar.py:307-314`), via `parse_target`, which is paired with
  `format_target` so the two cannot drift (`llm/seed_gen.py:105-116`);
- **retired the moment measured coverage proves a branch was reached**
  (`_retire_reached_attempts`, `llm/sidecar.py:233-247`). This half matters as
  much as the counting: a branch a seed genuinely hit must stop being reported as
  a failure, or the next round is told to avoid the one thing that worked. The log
  shows it firing —
  `attempts_retired reached=['0x1400012c9', '0x1400012e3', '0x14000130c']`;
- **passed to the prompt** as `ALREADY TRIED AND STILL NOT REACHED: <addr>
  (tried Nx)` (`llm/seed_gen.py:236-257`), which also gives the model explicit
  permission to call a branch dead code and spend the seed elsewhere rather than
  producing a seed it does not believe in;
- **rebuilt from `artifacts/sidecar_events.jsonl` on startup**
  (`_load_attempts`, `llm/sidecar.py:108-156`), because section 12.2 requires the
  sidecar to be restartable without stopping the campaign, and a counter living
  only in memory would make a restarted sidecar re-try the same dead branches from
  scratch. Note the normalisation at `llm/sidecar.py:121-133`: rounds logged before
  D-045 recorded RVAs, so an address that is not a known static address is retried
  as an RVA before being discarded. Old evidence is still evidence.

**Why the model's persistence was wrong here, established by experiment.** Of the
three surviving frontier branches, `0x1400012de` and `0x1400012ed` are each
guarded by a null test on a pointer that the immediately preceding `unique_ptr`
move set to null — dead code the decompiler still renders as a branch, and no
input across 44 corpus files plus 24 LLM seeds has reached either. The third,
`0x14000131c`, **is** reachable: a hand-written input carrying 8 `Allocate`
packets in one testcase reaches it and 4 does not
(`artifacts/runs/gate7/control_probe.json`), which puts `ChunkList`'s capacity
between 5 and 8 and makes that branch a free-slot search running off the end of a
fixed-size global table — an out-of-bounds write shape. It is reachable only by
**repeating** one command enough times in a single input, which is something the
pseudo-C tells you and random mutation finds only by luck. So the attempt counter
is not merely noise suppression: it pushes the model off two dead branches and
onto the one that is both live and interesting.

---

## D-045 — `FrontierBlock` mixed two address spaces in one field, and the prompt printed both

**Observed**, and a textbook RULE 4 failure: a field whose units were never
stated.

`FrontierBlock` carried `static_addr` — a Ghidra static address — next to an
unlabelled `unreached_successors` holding **RVAs**. Both were formatted into the
same sentence of the seed-generation prompt:

```
reached 0x1400012c9, but never took the branch to 0x12de
```

Two address spaces, one sentence, neither labelled. The model did the reasonable
thing and echoed the short form back in `targets_branch`, which is visible in
`artifacts/sidecar_events.jsonl` as `targets 0x12de` — where a sibling round that
had copied the *reached* address instead logged `targets 0x1400012c9`.

**The consequence was silent and total.** Measured coverage is keyed by static
address (`llm/sidecar.py:240-241`), so an attempt recorded as `0x12de` could never
match a covered block, could never be retired, and the D-044 attempt counter it
feeds could never be correct. Nothing errored; the numbers were simply
meaningless.

**Fixed:** the field is split, with each half named for its space —
`unreached_successor_rvas` and `unreached_successor_statics`
(`engine_bridge/plateau.py:115-119`) — populated together at construction
(`engine_bridge/plateau.py:245-253`), with a `__post_init__` asserting the two
correspond element-for-element (`engine_bridge/plateau.py:121-128`). The prompt
now prints static addresses throughout (`llm/seed_gen.py:186-196`), and
`targets_branch`'s field description instructs the model to copy the address
"verbatim and in full from the list given in the prompt, e.g. 0x1400012de"
(`llm/seed_gen.py:70-75`).

**Where this bites next.** Section 9 names three bases, and the RULE 4 table asks
which base each function takes and returns. That discipline was applied to
`arch/addr.py` and then not applied to the dataclass sitting directly on top of
it. Any field holding an address needs its space in the **name**, not in a
docstring: `addr` is not a type.

---

## D-046 — The schema is the only instruction the model cannot ignore

**Measured**, and it is the sequel to D-041: the prose instruction was not enough. A
later round, with that instruction present in the prompt, returned eight seeds of
which **all eight** were rejected as not valid JSON. From
`artifacts/sidecar_events.jsonl.pre-gate7`:

```
the model returned 8 seeds and none survived validation (8 rejected as not
valid json). Analysis was: 'Target each uncovered branch by constructing
inputs that either miss the expected chunk (Edit/Delete error) or exhaust the
chunk table before delete, forcing the cleanup path.'
```

The `analysis` field is why this is a deviation and not a bug report. That is a
**correct** reading of the target: it names the two error paths and, unprompted, the
table-exhaustion route that D-047 then spends an entire Ghidra export chasing. The
reasoning was sound and only the output channel was wrong — the model answered in
`content_hex` again.

**Fixed by removing the field rather than asking for it not to be used.**
`_batch_model(wire_format)` returns `_TextBatch` or `_BinaryBatch`
(`llm/seed_gen.py:105-126`), so for a JSON target `content_hex` **does not exist** in
the schema the completion is constrained by. What remains in the prompt about the
channel is now a reminder of the *format*, not of which field to use (`:290-297`).

Also fixed, and it accounts for most of the diagnosis time: the `SeedGenError` raised
when no seed survives now carries the count, the wire format, the first rejected
seed's leading bytes and the model's own `analysis` (`llm/seed_gen.py:383-389`). The
log line quoted above has no bytes in it, so establishing *what* those eight seeds
actually were meant cross-referencing the spool by hand.

**The general rule, worth stating plainly because it applies to every structured call
in this project:** for a constrained-output call, prose asking the model to leave a
field empty is **advisory**; removing the field is **binding**. D-034 established that
structured output needs the schema and not a description of it. This is the same
lesson from the other side — the schema is not only how a field is requested, it is
the only way to forbid one.

---

## D-047 — Decompilation drops the capacity of a global table

**Measured.** This is the concrete form of CLAUDE.md section 2's "pseudo-C is lossy":
one specific fact, destroyed at one specific point, with a cost that can be put in
numbers.

`ProcessPacket`'s free-slot search decompiles to a loop bounded by an unrelated
adjacent symbol:

```c
puVar11 = ChunkList;
pp_Var9 = &__dyn_tls_dtor_callback;
do { ... } while (puVar11 != pp_Var9);
```

which says nothing whatever about how many slots the table holds. A human
reverse-engineer reads the capacity off Ghidra's listing in seconds — two addresses,
an element size, one division. An LLM handed only the pseudo-C cannot, because the
division's inputs are not in the pseudo-C.

**Ghidra has the fact and was never asked for it.** From
`artifacts/a6_data_symbols.json`:

| symbol | address | applied size |
|---|---|---|
| `ChunkList` | `0x140006a18` | 32 bytes, typed `unique_ptr<Chunk_t,...>[4]` |
| `__dyn_tls_dtor_callback` | `0x140006a38` | (the next data symbol) |

32 bytes is four pointer-sized slots, and the next symbol sits `0x20` later, which
confirms the four independently of the type.

**Four slots is not the answer to the branch, and the gap is instructive.** A control
probe (`artifacts/runs/gate7/capacity_probe.json`) ran one testcase per allocation
count: 1 through 5 allocations do **not** reach block `0x14000131c`, and 6 through 11
do. The four-slot figure explains that exactly:

- allocations 1-4 fill the table;
- allocation 5 finds no free slot, runs off the end, and **writes** a chunk pointer
  to `0x140006a38` — an out-of-bounds write past the table;
- allocation 6 is the first to **read** that now-non-null value back, and that read
  is the null test guarding `0x14000131c`.

So the branch needs **six** — not five, and not the four that "four slots" naively
suggests. Recorded because the same three steps are also the shape of the bug: the
write happens on 5 and nothing observes it until 6.

**Implemented as a fourth Ghidra export.**

- `prep/ghidra_scripts/ExportDataSymbols.java` emits every global data symbol with
  its address, applied size and span to the next symbol, at `module` or
  `function-closure` scope (`ExportDataSymbols.java:25-29`). Java rather than Python
  for D-025's reason.
- `prep/data_symbols.py` filters and formats them for a prompt. Of tlv_server's
  **493** symbols, **35** are referenced from the fuzz entry's closure, and **3**
  survive dropping `.rdata` (`prep/data_symbols.py:37-40`) — string literals,
  vftables and `__imp_` import thunks, none of which bound a mutable table.
- `llm/sidecar.py:256-271` adds the table to the prompt **non-fatally**: a missing
  export costs reasoning quality and never correctness, since its absence is exactly
  the pre-CP7 situation rather than a broken campaign. `SeedGenRequest.globals_table`
  carries it (`llm/seed_gen.py:189-192`).
- `prep/ghidra_headless.py` was refactored so both exports share one
  `_run_post_script()` (`:117-133`, called at `:214` and `:257`), keeping D-020's
  PATH sanitising and D-025's Java-not-Python constraint in one place instead of two.

**Outcome, stated honestly: necessary and not sufficient.** With the capacity in the
prompt the model stopped guessing at the number and reasoned about it — "Four
allocations fill a fixed-size chunk table; subsequent delete operations repeatedly
hit the branch that checks for table overflow" — proposing sequences of exactly
**four** allocations. That fills the table rather than overflowing it, and it still
did not reach the branch. The remaining step is the one the mechanism above spells
out: the overflow slot has to be **populated by an earlier overflowing write** before
a later read can observe it, so a sequence has to cross the boundary twice, not
arrive at it.

---

## D-048 — One sample at a diversity temperature is a coin flip

**Measured** on consecutive rounds against an identical frontier and an identical
prompt shape, so the only variable was the draw.

`seed_gen` runs at temperature 0.9 (`config/llm.yaml:49`) because diversity of
*inputs* is the point of the role. The cost, which was not priced in: the
**reasoning** varies as much as the output. One sample worked out that the branch
needed a global table exhausted and proposed a five-packet sequence. The very next
sample reasoned only about single commands and proposed nothing longer than one
packet, with rationales like `Delete command that finds an existing chunk clears it`
(`artifacts/seed_provenance.jsonl`).

Same model, same temperature, same prompt. A round of one call therefore bets the
entire plateau response on which of those two comes back — and a round is expensive
in a way that has nothing to do with tokens: it is one plateau, and a campaign has
only so many.

**Fixed:** a round is now several independent samples unioned with byte-level dedup —
`samples_per_round`, default 3 (`llm/sidecar.py:78-80`, `--samples` at `:530-534`),
with the loop and its dedup at `:314-347`.

This is free in the sense that matters. It is the **slow clock**: the samples are
drawn in a separate process and the fast loop never waits for any of them (RULE 1),
so three calls cost three times the latency of one and zero fuzzing throughput.
Measured on one round: three samples produced **24 seeds with zero cross-sample
duplicates** in **321 s** of LLM time.

Note the interaction with D-044. Dedup is on seed **bytes**, not on the branch aimed
at, so several samples converging on the same target still yield distinct inputs for
it — which is the wanted behaviour when the target was right and the inputs were
wrong, and the attempt counter is what handles the case where the target itself is
wrong.

---

## D-049 — A units suffix hid the plateau signal completely

**Observed** in `artifacts/runs/gate7/master.log`. `_STAT_RE`
(`engine_bridge/coverage.py:41-58`) matched the master's `lastcov` field as **seconds
only**, while the sibling `uptime` group in the very same regex already accepted `s`,
`min` or `h`.

wtf switches `lastcov` to minutes once a minute has passed without new coverage. That
is **exactly the plateau window**. So every stat line printed *during a plateau*
failed to parse, and the failure cascaded through the whole slow clock:

| stage | effect |
|---|---|
| `parse_stat_line` | no match on any plateau line |
| the master's execution counter | frozen at its last sub-minute value |
| `orchestrator/scheduler.py` | writes that frozen number to the campaign state file |
| the sidecar's `executions_since_new_coverage` | stays 0 forever |
| the execution-based plateau trigger | can never fire |

Which removes the **primary** plateau signal section 12.3 requires — total executions
without new coverage. Only the 900-second wall-clock safety net could still fire, by
which point the campaign was over.

**The numbers, from that log.** 42 stat lines, of which **9** parsed before the fix
and **41** after; **32** of them carry `lastcov` in minutes, for example

```
#74406 cov: 12762 (+0) corp: 44 (34.4kb) exec/s: 930.0 (2 nodes) lastcov: 1.1min crash: 19292 timeout: 0 cr3: 0 uptime: 1.4min
```

The same log records a real **378-second plateau at 350,747 executions** with
`nodes: 2` — aggregate and multi-worker, exactly the shape GATE 7 asks for — that the
detector never saw.

**Fixed:** `lastcov` takes the same `(s|min|h)` suffix and is scaled through the same
`_UPTIME_SCALE` table as `uptime` (`engine_bridge/coverage.py:53`, `:60-62`, applied
at `:108` and `:113`), since wtf formats both with the same helper and both therefore
switch units as they grow.

**For the writeup: this is the third instance of one class in this project** (see
D-033 and D-042). The fuzzer kept running, the master kept printing healthy numbers,
nothing raised — and the one signal the entire slow clock depends on was silently
absent. A parser that quietly returns nothing on an unrecognised line is
indistinguishable from a quiet campaign, so every regex that reads another tool's
human-readable output needs its *rate* of parse failures watched, not merely a code
path that tolerates them.


## D-050 — symbolizer-rs was installed at CP4 and never written into the config

**Observed at CP8.** `analysis/trace.py`'s `find_symbolizer()` looked in an explicit
argument, then `SYMBOLIZER_RS`, then `PATH` — deliberately *not* in
`config/fuzz.yaml`, on the stated grounds that an absolute path to a tool outside the
repo is machine-specific and does not belong in a committed file. Meanwhile
`config/fuzz.yaml` carried `tools.symbolizer_rs: null # TODO(CP8)`.

The binary had been sitting at `D:\tools\symbolizer-rs\symbolizer-rs.exe` since CP4.
So CP8 opened by reporting a missing prerequisite for a tool that was already on disk,
and the whole crash-analysis stage looked blocked on an install.

**The premise was false.** The same file carries
`symbols.nt_symbol_path: [srv*C:\symbols*https://msdl.microsoft.com/download/symbols, {pdb_dir}]`
and `symbols.cache_dir: C:\symbols`. `config/fuzz.yaml` is not machine-portable and was
never pretending to be, so refusing to record one absolute path in a file full of
absolute paths bought nothing.

**Fix.** `find_symbolizer()` consults `config/fuzz.yaml` **last** — after the explicit
argument, the env var and `PATH` — so a machine where the committed path is wrong can
still override it. `tools.symbolizer_rs` is now set.

Worth stating generally: a rule that is right in the abstract ("no machine-specific
paths in committed files") is worth re-checking against what the file actually contains
before it costs a checkpoint.

## D-051 — `wtf run` never reports the fault address, and the trace does not stop at the fault

**Measured at CP8**, and it invalidates the obvious approach twice over.

Section 8 defines a deterministic crash as one with the **same fault address across N
replays**. Neither half of that is readable from wtf's output:

* `wtf run` prints a crash only as `crash: 1` in its final stat line. It never prints
  the address.
* It also writes **no crash file**: `wtf run --help` lists no `--crashes` option, and
  the crash directory is unchanged after a crashing run (measured — 53 files before,
  53 after).

So the address has to come from a trace, and the first guess — the last line of the rip
trace — is also wrong. Measured on
`crash-EXCEPTION_ACCESS_VIOLATION_READ-0x7ff8aa381378`:

```
43,305 trace lines total
  index 38,752   0x7ff8aa381378      <- the fault
  index 38,753   0xfffff80208be95c0  <- kernel: the exception dispatcher
  ...            4,552 further lines
  last line      0x7ff8e54ea010      <- NOT the fault
```

Control passes to the kernel and the trace runs on for thousands of instructions.

**Fix.** `fault_index_from_trace()` / `fault_address_from_trace()` take the last
**user-mode** address before the final user→kernel transition, testing against
`KERNEL_BASE = 0xFFFF_8000_0000_0000`. It must be the *last* such transition, because
ordinary syscalls produce earlier ones. This needs no symbols, which matters because the
fault is usually in a system DLL.

**Verified** against the address wtf itself put in the crash filename, on three crashes
with different fault addresses: exact match each time.

An index is returned as well as an address, because symbolizer-rs emits one output line
per input line in order, so the index locates the fault in the *symbolized* trace too.
The boundary cannot be found in the symbolized file directly: after the fault the kernel
returns to user-mode `ntdll!RtlDispatchException` and re-enters, so the last user→kernel
transition *there* sits in the post-fault dispatch path.

**A stronger check falls out of this.** bochscpu is deterministic, so two runs of one
input produce a **byte-identical** trace — measured on three crashes. Comparing trace
digests proves the whole execution matched, not merely its endpoint, which is more than
`ReplayResult.deterministic` asks for.

## D-052 — `exec/s: 8.3k` parsed as 8.3

**Measured at CP10.** `parse_stat_line()` extracted the rate with
`float(re.sub(r"[^\d.]", "", raw))`, which strips a magnitude suffix along with
everything else non-numeric. wtf prints `374.0` at low rates but `8.3k` and `1.2m` as
they grow, so the parse silently divided by 1000.

It stayed invisible for eight checkpoints because our own mutator never exceeded ~830
exec/s. It surfaced in the only way that would have been noticed: a CP10 **baseline arm
was recorded as slower than ours** — 8 exec/s against 746 — which is the opposite of the
truth by three orders of magnitude.

**Fix.** `_parse_magnitude()` handles `k`/`m`/`g` and returns 0.0 on anything
unparseable, so one malformed rate cannot lose a stat line that also carries the
execution and coverage counters. Verified: `8.3k → 8300.0`, `1.2m → 1200000.0`,
`374.0 → 374.0`.

The same run exposed a related bias: `peak_executions` came from the scheduler's live
ticks, which lag the master's block-buffered output (D-033) by an **arm-dependent**
amount — a noisy arm fills the buffer with `Saving crash in ...` lines faster than a
quiet one. libfuzzer's true count was **2,269,008 against 82,831 recorded**, a 27×
under-report, while the quieter arms were already accurate. It now comes from the final
log, and `eval/baseline.py --recompute` re-derives archived results without re-running
any fuzzing.

## D-053 — the baseline arms were credited with LLM seeds they never received

**Measured at CP10, and this one would have invalidated the comparison outright.**

`Scheduler._sidecar_events()` read `artifacts/sidecar_events.jsonl`, a **single file
shared across runs**. Baseline arms start no sidecar at all, so they must report zero
rounds. The recorded comparison instead showed:

```
baseline-libfuzzer   sidecar_rounds 2   seeds_consumed 30
baseline-honggfuzz   sidecar_rounds 2   seeds_consumed 30
ablation-no-seedgen  sidecar_rounds 3   seeds_consumed 42
```

Every one of those is a no-LLM arm reading a *previous* arm's events. A baseline
crediting itself with 30 LLM seeds makes the whole comparison meaningless — and nothing
about the numbers looked wrong. They were plausible counts of the right order.

**Fix, in two parts**, because either alone leaves a hole:

* `SidecarConfig.label` names a per-run log (`sidecar_events_<label>.jsonl`), passed
  through as `--label`, and the scheduler reads the same per-label path. Without this
  the two *sidecar* arms still read each other's rounds.
* `_sidecar_events()` returns empty when `sidecar_cmd is None`. An arm with no sidecar
  then reports zero **by construction** rather than by reading a file, which is the
  stronger guarantee of the two.

`eval/baseline.py --recompute` also clears the field for any non-sidecar arm, since the
arm definition is the authority there and not the log.

`tests/gates/test_cp10.py::test_the_ablation_arms_consumed_no_seeds_where_they_should_not`
asserts the property, and it is what caught this.
