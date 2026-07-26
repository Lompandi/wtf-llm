"""Run the whole snapfuzz pipeline, one stage at a time, in order.

Until this existed the pipeline was thirteen commands run by hand, and the
ordering had a trap in it worth naming: **A3's closure scope needs the fuzz entry,
and the fuzz entry needs A2.** Running the stages in the order they appear in
CLAUDE.md section 3.1 therefore deadlocks. The resolution is that A2 is built at
*module* scope first (which needs no entry), the entry is chosen from it, and only
then can anything be scoped to the entry's call closure. That order is encoded
here so nobody has to rediscover it.

Design rules this driver follows, all of which exist because a pipeline runner is
the easiest place in a project to hide a failure:

* **A skipped stage is reported, never silent.** ``--from``/``--only`` and the
  up-to-date check all print what they skipped and why. A run that quietly did
  three of fourteen stages and printed "done" is worse than a crash.
* **A stage that cannot run stops the pipeline.** The snapshot stage is the
  case that motivated the rule: acquisition is not performed here, so the driver
  *ingests* an existing ``state/`` and refuses to invent one, and stage 07 simply
  fails on a missing ``mem.dmp``. (The ``blocked`` field exists for a stage that
  cannot even be attempted; no stage currently sets it, so that path is
  unexercised -- said plainly rather than described as a live example.)
* **Prerequisites are checked before anything runs**, not discovered halfway.
  A missing ``GHIDRA_INSTALL_DIR`` after twenty minutes of fuzzing is a waste of
  twenty minutes.
* **No stage is marked done because its command exited 0.** Every stage names the
  artifact it must produce, and the artifact is the evidence -- the same rule the
  rest of this project runs on, because analyzeHeadless and wtf both exit 0 having
  produced nothing (D-026, D-042).

**NO LLM IN THIS MODULE**, but it launches four stages that use one, all as
subprocesses with their own interpreter and their own client:

* **entry selection** and **input-structure derivation** -- build time, once per
  target;
* the **campaign**, whose scheduler starts the slow-clock sidecar (section 12.2);
* **triage** -- one call per crash bucket, and the largest consumer of the four.

Worth stating precisely because section 7.3 makes LLM spend a governed resource
with a cumulative cap, and this docstring is where a reader learns what one
invocation of the driver will spend.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

# Stdlib-only, like the rest of this module's imports: provenance is a
# filesystem question. RULE 1 forbids `llm.*` here (test_cp12), not local
# helpers.
from orchestrator.provenance import (
    ArtifactStamp,
    TargetIdentity,
    load_stamps,
    record as record_provenance,
    stale_reason,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
PYTHON = REPO_ROOT / ".venv" / "Scripts" / "python.exe"

__all__ = ["Stage", "PipelineConfig", "run_pipeline", "ENTRY_PLACEHOLDER"]

# Stands in for the fuzz entry symbol until stage 03 has chosen one. Substituted
# per stage at run time; see build_stages.
ENTRY_PLACEHOLDER = "<ENTRY>"


@dataclass(frozen=True)
class Stage:
    """One pipeline step.

    ``produces`` is what proves it worked. ``needs`` is checked before it runs so
    a missing input is reported as a missing input rather than as whatever the
    downstream tool says about it.
    """

    key: str
    title: str
    argv: list[str]
    produces: list[Path]
    needs: list[Path] = field(default_factory=list)
    calls_llm: bool = False
    # Stages that cannot be performed here at all. The message is shown instead of
    # running anything, and the pipeline stops unless `produces` already exists.
    blocked: str | None = None
    note: str = ""
    # Stages whose work is TIME, not a file. Their artifact existing proves only
    # that some earlier run happened, so skipping them on that basis silently turns
    # a requested campaign into zero seconds of fuzzing that reports success and
    # points at the previous run's advisory (D-057).
    idempotent: bool = True
    # An extra check on the artifact's CONTENT, run after a zero exit. Existence is
    # not enough for a stage that can complete having achieved nothing: the
    # scheduler writes scheduler_result.json and returns 0 even when it printed
    # "all workers dead" with peak_executions=0.
    verify: Callable[[], str | None] | None = None
    # Whether an UNCHANGED artifact is legitimate. Default False, because for a
    # generator -- a Ghidra export, codegen -- byte-identical output means the tool
    # did not run, which is the false success D-057 exists to catch.
    #
    # An INCREMENTAL BUILD is the exception, and getting this wrong broke the
    # pipeline for real: stage 10 is deliberately never skipped as up-to-date, so
    # it always invokes the build, and Ninja then correctly relinks nothing when no
    # source changed. Byte-identical there means "had nothing to do", not "did not
    # run" -- so the two rules together made stage 10 impossible to pass twice in a
    # row (D-065). Stages that set this must carry a `verify` hook that checks the
    # property the comparison was standing in for.
    output_may_be_unchanged: bool = False


@dataclass
class PipelineConfig:
    target_name: str
    binary: Path
    entry_symbol: str | None
    state_dir: Path
    module: str = "snapfuzz"
    scope: str = "module"
    workers: int = 2
    minutes: float = 15.0
    plateau_execs: int = 20_000
    seeds: int = 6
    samples: int = 2
    replays: int = 3
    label: str = "pipeline"
    # Snapshot ACQUISITION. Off unless --kd-pipe names a guest, because the
    # overwhelmingly common case is a state/ directory someone else produced, and a
    # stage that needs a VM must not fail a run that never wanted one.
    kd_pipe: str | None = None
    kd_stimulus: str | None = None
    kd_timeout_s: int = 900
    wow64: bool = False
    # WHICH HARNESS DELIVERS THE BYTES. None resolves per target: generated for a
    # binary `config/target.yaml` does not describe, hand-written for the one it does.
    #
    # The default has to be per-target because neither answer is right for both. The
    # hand-written module parses tlv_server's TLV format, so for any other program it
    # delivers a structure the target does not accept -- the campaign runs, reports
    # coverage and finds nothing. And adopting the generated module for the
    # development target renames the test-case JSON keys, invalidating the recorded
    # corpus and crash files, which is why edge 14 sat unwired (D-055, D-073).
    generated_harness: bool | None = None
    # WHO WRITES THE MODULE C++. "template" renders it from the InputSpec with
    # deterministic code; "llm" asks the 550B for the translation unit directly.
    #
    # fuzzer/codegen.py argues for the template split and the argument is real -- a
    # compile error from model-written C++ lands far from the mistake, and free-form C++
    # cannot be schema-checked. What makes "llm" defensible is that the check here is not
    # a schema: the result must COMPILE under /WX and the campaign built from it must
    # produce coverage, both of which this pipeline already enforces. Those are stronger
    # conditions than schema-validity, which a harness that never delivers input can
    # satisfy.
    #
    # Default stays "template" because it is the path with measured results behind it.
    codegen: str = "template"
    repo_root: Path = REPO_ROOT

    def __post_init__(self) -> None:
        # `binary` and `state_dir` arrive from the command line and may be relative;
        # everything else is built from repo_root and is absolute. Resolving them
        # here keeps that invariant in ONE place -- the alternative was every
        # consumer coping, and the first one that did not crashed the up-to-date
        # message on `relative_to(repo_root)`.
        self.binary = Path(self.binary).resolve()
        self.state_dir = Path(self.state_dir).resolve()

    @property
    def target_module(self) -> str:
        """The target's module name AS THE SNAPSHOT KNOWS IT.

        The PE's own CodeView record beats the filename, because wtf resolves
        breakpoints and .cov files by this name and a snapshot loaded the image under
        whatever it was called then. A renamed executable otherwise produces a harness
        whose `GetModuleBase` returns 0, a breakpoint at `0 + rva`, and a campaign that
        completes with zero coverage and no error (D-075).
        """
        from prep.layout import pe_module_name

        return pe_module_name(self.binary) or self.binary.stem

    @property
    def use_generated_harness(self) -> bool:
        """Resolve `generated_harness`, defaulting per target.

        The predicate is the same one every other `config/target.yaml` fallback now
        uses: is that file describing the binary we are about to fuzz. If it is not,
        the hand-written harness is known-wrong for this program, so generating is the
        only defensible default -- "it ran and found nothing" is the worst outcome
        available, because it looks like a result.
        """
        if self.generated_harness is not None:
            return self.generated_harness
        import yaml

        try:
            target_cfg = yaml.safe_load(
                (self.repo_root / "config" / "target.yaml").read_text(encoding="utf-8")
            )["target"]
        except (OSError, KeyError, TypeError):
            return True
        return not _config_describes(target_cfg, self.binary)

    @property
    def target_dir(self) -> Path:
        return self.repo_root / "targets" / self.target_name

    @property
    def artifacts(self) -> Path:
        return self.repo_root / "artifacts"


def build_stages(config: PipelineConfig) -> list[Stage]:
    """The fourteen stages, in the only order that resolves for a NEW target.

    The ordering is the part of this module worth reading, because the obvious
    order does not work and the failure is quiet.

    CLAUDE.md's diagram has entry selection feeding decompilation and BB
    enumeration (edges 4 and 5), which reads as "entry first". It cannot be first:
    the entry is chosen by a model reading pseudo-C, so **A2 must exist before the
    entry is known**, and at *module* scope because there is no entry yet to take a
    closure of.

    But the reverse is also true for A6 and for closure-scoped A3: they take an
    entry, and with none supplied `referenced_from_scope` is false for every symbol
    -- so `load_globals(referenced_only=True)` returns nothing and the prompt
    silently loses the global bounds that D-047 exists to provide. Nothing errors;
    the seed generator just reasons without them again.

    So the resolution is: **A2 at module scope, then the entry, then everything
    that needs the entry.** Edges 4 and 5 are real and describe exactly this --
    they are just not the *first* thing that happens.
    """
    art = config.artifacts
    # The SCOPE is in the filename. Without it, `--scope function-closure` was
    # silently satisfied by a module-scoped export left over from an earlier run,
    # and the reverse is worse: asking for module scope and getting a closure file
    # means 555 MISSING breakpoints, which D-027 calls silent coverage loss (D-057).
    scope_tag = "module" if config.scope == "module" else "closure"
    a3_json = art / f"a3_ghidra_blocks_{scope_tag}.json"
    a2_json = art / f"a2_pseudoc_{scope_tag}.json"
    a2_db = art / f"a2_pseudoc_{scope_tag}.sqlite"
    a6_json = art / f"a6_data_symbols_{scope_tag}.json"
    entry_json = art / "fuzz_entry_llm.json"
    spec_json = art / "input_spec.json"
    a1_json = art / "a1_snapshot.json"
    layout_json = art / "a0_layout.json"
    generated = config.repo_root / "fuzzer" / "module" / "generated_input.h"
    harness_json = art / "harness_spec.json"
    # The GENERATED MODULE. `fuzzer/build.py` copies `fuzzer/module/*.cc` into
    # `src/wtf/`, where CMake's glob compiles it, so writing this file is all it takes
    # to get it into wtf.exe -- it is already linked (build.ninja:174).
    generated_module = config.repo_root / "fuzzer" / "module" / "fuzzer_gen.cc"
    # wtf's --name for the generated module, matching what fuzzer_gen.cc registers.
    generated_target_name = f"{config.module}_gen"
    use_generated_harness = config.use_generated_harness
    # The module stage 10 builds and stage 11 runs. These were `config.module`
    # unconditionally, so the generated module was compiled into wtf.exe (it is in the
    # link line) and never selected at run time.
    fuzzer_module = generated_target_name if use_generated_harness else config.module
    wtf_exe = config.repo_root / "src" / "build" / "wtf.exe"
    gate8 = art / "runs" / f"{config.label}-analysis"
    gate9 = art / "runs" / f"{config.label}-triage"

    def py(module: str, *args: str) -> list[str]:
        return [str(PYTHON), "-u", "-m", module, *args]

    def campaign_actually_fuzzed() -> str | None:
        """The campaign's own numbers, not merely that it wrote a file.

        The scheduler writes scheduler_result.json and returns 0 even when it
        printed "all workers dead; aborting" with peak_executions=0 -- which is what
        every worker dying in Init looks like (D-023/D-042). Existence alone
        therefore certified the single most consequential failure in this project as
        a green stage, and the analysis stage then built a fresh-looking advisory
        from the previous run's crashes (D-057).
        """
        path = art / "runs" / config.label / "scheduler_result.json"
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return f"{path.name} is unreadable: {exc}"
        # EITHER signal. `peak_executions` comes from the master's stat lines, and
        # D-033 established that wtf block-buffers stdout and never flushes it -- a
        # 123-second run leaves a 0-byte master log while the fuzzer is healthily
        # saving new-coverage testcases. So requiring it failed every healthy campaign,
        # including the development target's, and this hook was enforcing the one signal
        # `fuzzer/run.py` documents as unreliable (D-075).
        #
        # `new_coverage_events` is the filesystem signal: the master writes into
        # outputs/ exactly when a testcase produced new coverage, and a file appearing
        # on disk is not buffered. Zero of BOTH is what every worker dying in Init
        # looks like; zero of just the first is normal.
        executions = payload.get("peak_executions", 0)
        coverage_events = payload.get("new_coverage_events", 0)
        if executions <= 0 and coverage_events <= 0:
            return (
                "the campaign produced ZERO executions and ZERO new-coverage events. "
                "That is what every worker dying in Init looks like -- check "
                "_NT_SYMBOL_PATH, and that the harness can place its breakpoints "
                "(a stripped target needs them by ADDRESS, and the module name has to "
                "be the one the DUMP uses, not the filename on disk) (D-023, D-042, "
                "D-075)"
            )
        if payload.get("ticks", 0) <= 0:
            return "the campaign recorded no ticks, so it never observed the master"
        return None

    def generated_code_matches_the_spec() -> str | None:
        """The generated C++ must describe THIS run's InputSpec.

        Replaces a byte comparison that produced a false failure the first time the
        pipeline was run twice on equivalent input: codegen is a deterministic renderer,
        so identical input gives identical output, and "byte-for-byte the file that was
        already there" means the generator agreed with itself rather than that it did
        not run. Same shape as stage 10 and the same reason (D-065).

        What the comparison was standing in for is that the code on disk corresponds to
        the spec on disk, so that is what this checks -- by name, which is the thing that
        changes when the spec changes.
        """
        try:
            spec = json.loads(spec_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return f"{spec_json.name} is unreadable: {exc}"

        wanted = [spec.get("struct_name")] + [
            f.get("name") for f in (spec.get("fields") or [])
        ]
        wanted = [w for w in wanted if w]
        if not wanted:
            return f"{spec_json.name} names no struct and no fields"

        if config.codegen == "llm" and use_generated_harness:
            # The model writes the module and no header, so that is what to check.
            targets = [generated_module]
        else:
            targets = [generated] + ([generated_module] if use_generated_harness else [])
        for path in targets:
            if not path.exists():
                return f"{path.name} was not written"
            text = path.read_text(encoding="utf-8", errors="replace")
            missing = [name for name in wanted if name not in text]
            if missing:
                return (
                    f"{path.name} does not mention {missing} from "
                    f"{spec_json.name}, so it was generated from a different spec"
                )
        return None

    def inputs_hold_a_seed() -> str | None:
        """After stage 09b, inputs/ must not be empty.

        This stage cannot name a `produces` path: writing nothing is the CORRECT
        outcome when the user already supplied a seed, so a required artifact would
        make it fail for having respected them. The property that actually matters is
        not "a file was written" but "there is something to fuzz from", which is what
        this checks -- the same shape as the `output_may_be_unchanged` stages, which
        also trade a byte comparison for a hook that checks the real thing (D-065).
        """
        inputs = config.target_dir / "inputs"
        if not inputs.is_dir():
            return f"{inputs} does not exist"
        if not any(p.is_file() for p in inputs.iterdir()):
            return (
                f"{inputs} is still empty. The InputSpec described no usable structure "
                f"to build a first test-case from, so a seed has to be supplied by "
                f"hand: one input your target accepts, byte for byte"
            )
        return None

    def input_spec_matches_entry() -> str | None:
        """The derived spec must describe the entry this run is scoped to."""
        if not config.entry_symbol:
            return None
        try:
            payload = json.loads(spec_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return f"{spec_json.name} is unreadable: {exc}"
        derived = payload.get("entry_symbol")
        wanted = config.entry_symbol.split("!", 1)[-1]
        if derived and derived != wanted:
            return (
                f"the input structure was derived for {derived!r} but this run is "
                f"scoped to {wanted!r} -- the harness and the coverage would describe "
                f"different functions"
            )
        return None

    def build_is_fresh() -> str | None:
        """wtf.exe must be newer than every module source.

        fuzzer/build.py already guards this and names it "a genuinely silent failure
        -- a stale wtf.exe runs the OLD module and looks completely healthy". The
        driver skipped stage 10 whenever the binary merely existed, so the header
        stage 09 had just regenerated was never compiled (D-057).
        """
        exe = config.repo_root / "src" / "build" / "wtf.exe"
        if not exe.exists():
            return "wtf.exe is absent"
        newest = max(
            (p.stat().st_mtime_ns for p in (config.repo_root / "fuzzer" / "module").glob("*")),
            default=0,
        )
        if newest > exe.stat().st_mtime_ns:
            return (
                "a module source is newer than wtf.exe, so the binary would run the "
                "OLD module while looking completely healthy"
            )
        return None

    # LATE-BOUND entry symbol. Stages 04, 06 and 07 need one, and for a new target
    # it does not exist until stage 03 has run -- finding it is the pipeline's job,
    # so requiring it up front would defeat the point. `ENTRY_PLACEHOLDER` is
    # substituted from the FuzzEntry artifact immediately before each stage runs,
    # and a stage whose placeholder cannot be resolved fails loudly rather than
    # being handed a plausible-looking wrong symbol.
    entry_for_scoping = config.entry_symbol or ENTRY_PLACEHOLDER

    return [
        Stage(
            key="01-pseudoc",
            title="Ghidra: decompile at MODULE scope -> A2 dump",
            argv=py(
                "prep.ghidra_headless", "--what", "pseudoc",
                "--binary", str(config.binary), "--out", str(a2_json),
                "--scope", "module",
            ),
            needs=[config.binary],
            produces=[a2_json],
            note=(
                "module scope, not the entry's closure: the entry is not known yet "
                "and choosing it is stage 03's job"
            ),
        ),
        Stage(
            key="02-a2",
            title="A2 dump -> SQLite cache",
            argv=py(
                "prep.pseudoc_cache", "build",
                "--export", str(a2_json), "--cache", str(a2_db),
            ),
            needs=[a2_json],
            produces=[a2_db],
        ),
        Stage(
            key="02b-layout",
            title="Snapshot -> module base + fuzz entry (no LLM)",
            argv=py(
                "prep.layout",
                "--binary", str(config.binary),
                "--regs", str(config.state_dir / "regs.json"),
                "--mem-dmp", str(config.state_dir / "mem.dmp"),
                "--export", str(a2_json),
                "--module", config.target_module,
                "--out", str(layout_json),
            ),
            needs=[config.binary, config.state_dir / "regs.json", a2_json],
            produces=[layout_json],
            note=(
                "reads the mapped image list out of the dump and identifies your "
                "executable by its PE header, so module_base needs no "
                "symbol-store.json and no config. rip is where the snapshot stopped, "
                "so it IS the fuzz entry -- not something to be guessed and checked "
                "later (D-075)"
            ),
        ),
        Stage(
            key="03-entry",
            title="LLM: describe the fuzz entry",
            argv=py(
                "prep.entry_select", "--cache", str(a2_db),
                "--module", config.target_module, "--out", str(entry_json),
                # The entry is not open for choice once a snapshot exists: rip decided
                # it in stage 02b. This stage derives the input REGISTERS for that
                # function. Left free, the model chose a different function and derived
                # input_param for it -- and input_param is compiled into the harness's
                # register writes (D-075).
                "--layout", str(layout_json),
            ),
            needs=[a2_db, layout_json],
            produces=[entry_json],
            calls_llm=True,
            note=(
                "two stages: function signatures produce a shortlist, then full "
                "pseudo-C decides. The address always comes from A2 -- the model "
                "never supplies one."
            ),
        ),
        Stage(
            key="04-blocks",
            title="Ghidra: enumerate basic blocks -> A3 (edge 5)",
            argv=py(
                "prep.ghidra_headless", "--what", "blocks",
                "--binary", str(config.binary), "--out", str(a3_json),
                "--scope", config.scope, "--entry", entry_for_scoping,
            ),
            needs=[config.binary, entry_json],
            produces=[a3_json],
        ),
        Stage(
            key="05-covfile",
            title="A3 -> wtf .cov breakpoint file",
            argv=py(
                "prep.bb_to_wtf", "--export", str(a3_json),
                "--coverage-dir", str(config.target_dir / "coverage"),
                "--bp-list", str(art / "a3_bp_list.json"),
                # The module this run is for. `produces` below expects
                # `<binary stem>.cov`, and bb_to_wtf used to name the file from the
                # export's own field instead -- so a stale export produced
                # `tlv_server.cov` and the stage failed complaining that
                # `fuzzing-base-test.cov` was absent, which described the symptom and
                # not the cause (D-073). Passing it makes the two agree by
                # construction and turns a disagreement into a message about the
                # wrong program.
                "--module", config.target_module,
            ),
            needs=[a3_json],
            # BOTH: the .cov in the target's coverage/ directory is the actual
            # interface-3 deliverable (D-017), and the bp-list JSON is the
            # by-product. Naming only the JSON let a stage pass while the file wtf
            # actually reads was absent.
            produces=[
                art / "a3_bp_list.json",
                config.target_dir / "coverage" / f"{config.target_module}.cov",
            ],
            note=(
                "bochscpu ignores .cov and takes full-system coverage instead, so "
                "this only becomes load-bearing on whv/kvm (edge 22 is pending, "
                "D-004/D-036)"
            ),
        ),
        Stage(
            key="06-datasyms",
            title="Ghidra: global data symbols -> A6 (edge 10b)",
            argv=py(
                "prep.ghidra_headless", "--what", "data-symbols",
                "--binary", str(config.binary), "--out", str(a6_json),
                "--scope", config.scope, "--entry", entry_for_scoping,
            ),
            needs=[config.binary, entry_json],
            produces=[a6_json],
            note=(
                "AFTER the entry, not before: with no entry every symbol is marked "
                "unreferenced, load_globals returns nothing, and the prompt silently "
                "loses the table capacities D-047 exists to supply. Edge 10b is "
                "PENDING under RULE 3 -- because GATE 7's coverage criterion is "
                "unmet, not because this export does not run"
            ),
        ),
        *(
            [
                Stage(
                    key="07a-acquire",
                    title="Take the snapshot by driving KD (needs a guest VM)",
                    argv=py(
                        "prep.snapshot_win", "acquire",
                        "--state", str(config.state_dir),
                        "--pipe", config.kd_pipe,
                        # SEPARATE arguments: the entry may still be the
                        # placeholder here, and substitution is by whole argument.
                        "--module", config.target_module,
                        "--break-at", entry_for_scoping,
                        "--kind", "full",
                        "--timeout", str(config.kd_timeout_s),
                        *(["--wow64"] if config.wow64 else []),
                        *(
                            ["--stimulus", config.kd_stimulus]
                            if config.kd_stimulus
                            else []
                        ),
                    ),
                    # The ENTRY must exist first: the breakpoint address is what
                    # defines "the state worth snapshotting", so acquisition cannot
                    # precede entry selection even though the diagram draws the
                    # snapshot column beside the Ghidra one.
                    needs=[entry_json],
                    produces=[
                        config.state_dir / "mem.dmp",
                        config.state_dir / "regs.json",
                    ],
                    note=(
                        "`bp <module>!<entry> \"!snapshot ...; qq\"` -- the work hangs "
                        "off the BREAKPOINT rather than being sequenced after `g` in "
                        "the -c string, because KD does not promise to run the rest "
                        "of that string once the break fires. NEVER EXERCISED: there "
                        "is no guest VM on this host, so this stage is written from "
                        "`kd -?` and section 13.6 and has not run end to end. What is "
                        "still target-specific is the STIMULUS -- for a network "
                        "service a client must connect or `g` never returns and this "
                        "times out"
                    ),
                )
            ]
            if config.kd_pipe
            else []
        ),
        Stage(
            key="07-snapshot",
            title="Ingest an existing state/ -> A1",
            argv=py(
                "prep.snapshot_win", "ingest",
                "--state", str(config.state_dir),
                "--module", config.target_module,
                "--binary", str(config.binary),
                "--entry-symbol", entry_for_scoping,
                # From stage 02b, so a snapshot with no symbol-store.json ingests --
                # which is the whole point: a dump, a register state and the
                # executable, nothing else (D-075).
                "--layout", str(layout_json),
                "--out", str(a1_json),
            ),
            needs=[
                config.state_dir / "mem.dmp",
                config.state_dir / "regs.json",
                layout_json,
            ],
            produces=[a1_json],
            note=(
                "INGEST only -- this reads a state/ directory and derives A1. "
                "Acquisition is stage 07a, which appears only when --kd-pipe names a "
                "guest VM; without it this stage needs a state/ someone else "
                "produced. The hypervisor, kd.exe and 0vercl0k/snapshot are all "
                "installed and recorded in config/fuzz.yaml -- an earlier note named "
                "them as blockers and was wrong (D-032 is stale). What acquisition "
                "still needs is a Windows guest with one vCPU and KD attached over a "
                "named pipe, plus a stimulus that drives the target to its parser."
            ),
        ),
        Stage(
            key="08-inputspec",
            title="LLM: derive the input structure",
            argv=py(
                "prep.input_struct", "--entry", str(entry_json),
                "--cache", str(a2_db), "--out", str(spec_json),
            ),
            needs=[entry_json, a2_db],
            produces=[spec_json],
            calls_llm=True,
            verify=input_spec_matches_entry,
            note=(
                "reads the FuzzEntry ARTIFACT, so if --entry-symbol was supplied by "
                "hand the verify hook checks the artifact agrees with it. Otherwise "
                "coverage and the snapshot get scoped to one function while the "
                "input structure -- and therefore InsertTestcase -- is derived for "
                "another (D-057)"
            ),
        ),
        Stage(
            key="08b-harness",
            title="LLM: derive the harness spec (breakpoints, input register)",
            argv=py(
                "prep.harness_derive",
                "--entry", str(entry_json),
                "--input-spec", str(spec_json),
                "--cache", str(a2_db),
                "--target-name", generated_target_name,
                # For turning A2's static addresses into RVAs, so breakpoints are
                # placed by ADDRESS. A stripped target has no symbols for dbgeng to
                # resolve, and a name-resolved breakpoint then kills every worker in
                # Init (D-075).
                "--export", str(a2_json),
                "--out", str(harness_json),
            ),
            needs=[entry_json, spec_json, a2_db],
            produces=[harness_json],
            calls_llm=True,
            note=(
                "prep/harness_derive.py existed from CP11 and NO STAGE RAN IT, so the "
                "harness spec could only be produced by hand -- which is why the "
                "generated module in the tree was built once for tlv_server and never "
                "again (D-073)"
            ),
        ),
        Stage(
            key="09-codegen",
            title=(
                "InputSpec + HarnessSpec -> generated module [the model writes the C++]"
                if config.codegen == "llm" and use_generated_harness
                else "InputSpec + HarnessSpec -> generated module (no LLM)"
                if use_generated_harness
                else "InputSpec -> C++ header (no LLM)"
            ),
            argv=(
                py(
                    "fuzzer.codegen_llm",
                    "--spec", str(spec_json),
                    "--harness", str(harness_json),
                    "--module-out", str(generated_module),
                )
                if config.codegen == "llm" and use_generated_harness
                else py(
                    "fuzzer.codegen", "--spec", str(spec_json), "--out", str(generated),
                    *(
                        ["--harness", str(harness_json),
                         "--module-out", str(generated_module)]
                        if use_generated_harness
                        else []
                    ),
                )
            ),
            needs=[spec_json] + ([harness_json] if use_generated_harness else []),
            produces=(
                [generated_module]
                if config.codegen == "llm" and use_generated_harness
                else [generated, generated_module]
                if use_generated_harness
                else [generated]
            ),
            # A deterministic renderer given the same spec writes the same bytes. That
            # is agreement, not a no-op, and treating it as failure made a second run on
            # one target impossible (D-065/D-075). The hook below checks the property
            # the byte comparison stood in for.
            output_may_be_unchanged=True,
            verify=generated_code_matches_the_spec,
            calls_llm=(config.codegen == "llm" and use_generated_harness),
            note=(
                "EDGE 14: the generated module is compiled by stage 10 and run by "
                "stage 11, so the derived structure is what reaches the guest. The "
                "hand-written module parses tlv_server's TLV format, which is simply "
                "wrong for any other program -- so for a target config/target.yaml "
                "does not describe, generating is the only correct default (D-073)"
                if use_generated_harness
                else "the hand-written tlv_server module is in use, so this header is "
                     "generated but NOT compiled -- adopting it for the development "
                     "target would rename the test-case JSON keys and invalidate the "
                     "recorded corpus and crash files (D-055). Pass "
                     "--generated-harness to use the derived one anyway"
            ),
        ),
        Stage(
            key="09b-seed",
            title="InputSpec -> a first test-case, if inputs/ is empty",
            argv=py(
                "fuzzer.seed",
                "--spec", str(spec_json),
                "--inputs", str(config.target_dir / "inputs"),
            ),
            needs=[spec_json],
            # No `produces`: writing nothing is the CORRECT outcome when the user
            # already put a seed there, and a stage that must produce a file would
            # then fail for having respected them. `idempotent=False` keeps it from
            # being skipped as up to date, so it always gets to look.
            produces=[],
            idempotent=False,
            verify=inputs_hold_a_seed,
            note=(
                "the pipeline used to refuse to start without a seed, which asked the "
                "user for something it already knew: the InputSpec gives the field "
                "widths, the length fields and any magic value, so a structurally "
                "valid first case follows from it. Anything already in inputs/ is left "
                "alone -- a captured real input is worth more than a derived one (D-075)"
            ),
        ),
        Stage(
            key="10-build",
            title="Build wtf + our module",
            argv=py("fuzzer.build", "--expect-target", fuzzer_module),
            produces=[wtf_exe],
            # Existence is not freshness. build.py's own guard exists for exactly
            # this case and the driver was bypassing it (D-057).
            idempotent=False,
            # Ninja is incremental: with no source change it relinks nothing and
            # wtf.exe is legitimately byte-identical. Comparing bytes here fought
            # `idempotent=False` and made this stage unpassable on any second run
            # (D-065). `build_is_fresh` below is the check that actually matters --
            # wtf.exe newer than every module source -- and it catches the real
            # danger, a stale binary running the OLD module while looking healthy.
            output_may_be_unchanged=True,
            verify=build_is_fresh,
        ),
        Stage(
            key="11-fuzz",
            title="Campaign: master + workers + slow clock",
            argv=py(
                "orchestrator.scheduler", "--label", config.label,
                "--workers", str(config.workers), "--minutes", str(config.minutes),
                "--target-dir", str(config.target_dir), "--a1", str(a1_json),
                "--plateau-execs", str(config.plateau_execs),
                "--seeds", str(config.seeds), "--samples", str(config.samples),
                # Otherwise the scheduler falls back to config/target.yaml's
                # `target.module` and runs the hand-written tlv_server harness whatever
                # this run generated and built (D-073).
                "--module", fuzzer_module,
            ),
            needs=[wtf_exe, a1_json],
            produces=[art / "runs" / config.label / "scheduler_result.json"],
            calls_llm=True,
            # A campaign's work is TIME. Re-using a label made it look produced, so
            # --minutes 60 --workers 8 became zero seconds of fuzzing that reported
            # success and pointed at the previous run's advisory (D-057).
            idempotent=False,
            verify=campaign_actually_fuzzed,
            note=(
                "the LLM runs in the sidecar, a separate process (section 12.2). "
                "Never skipped as up-to-date: its work is elapsed time, not a file"
            ),
        ),
        Stage(
            key="12-analysis",
            title="Crash dedup, classify, replay, trace (no LLM)",
            argv=py(
                "analysis.pipeline", "--target-dir", str(config.target_dir),
                "--module", config.module, "--label", f"{config.label}-analysis",
                "--replays", str(config.replays),
                # THIS run's target, not config/target.yaml's. Absent these, analysis
                # symbolized with the dev target's module prefix, disassembled the dev
                # target's PE at the fault address, and handed the dev target's
                # pseudo-C to triage -- four wrong answers, no error (D-073).
                "--module-prefix", config.target_module,
                "--target-binary", str(config.binary),
                "--entry-symbol", entry_for_scoping,
                "--a1", str(a1_json),
                "--a2-cache", str(a2_db),
                "--data-symbols", str(a6_json),
            ),
            needs=[a1_json, a2_db],
            produces=[gate8 / "buckets.json", gate8 / "summary.json"],
            # Derived from whatever crashes/ holds now, so a previous run's output
            # must never stand in for this one's.
            idempotent=False,
        ),
        Stage(
            key="13-triage",
            title="LLM: five-signal triage -> GHSA advisory",
            argv=py(
                "analysis.triage_run", "--evidence", str(gate8),
                "--label", f"{config.label}-triage",
                "--target-dir", str(config.target_dir), "--module", config.module,
                # So the advisory names the program it is about (D-073).
                "--target-binary", str(config.binary),
                "--entry-symbol", entry_for_scoping,
            ),
            needs=[gate8 / "buckets.json"],
            produces=[gate9 / "advisory.md", gate9 / "verdicts.json"],
            calls_llm=True,
            idempotent=False,
        ),
    ]


# --- prerequisites -------------------------------------------------------


def _read_dotenv_value(dotenv: Path, name: str) -> str | None:
    """One value from a ``.env``, properly parsed.

    ``utf-8-sig`` because PowerShell writes a BOM, which otherwise lands in the
    first key's name and produces a baffling auth failure. Comments and blank lines
    are skipped, which is the whole point: a substring test accepted a key that had
    been commented out.
    """
    if not dotenv.exists():
        return None
    for line in dotenv.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        if key.strip() == name:
            return value.strip().strip("'\"") or None
    return None


def _same_dir(a: Path, b: Path) -> bool:
    """Whether two paths are the same directory, following links."""
    try:
        return a.resolve() == b.resolve() or a.samefile(b)
    except OSError:
        return False


def _link_state(state_dir: Path, canonical: Path, repo_root: Path) -> str | None:
    """Make `targets/<name>/state` resolve to the supplied snapshot. Reason on failure.

    A junction rather than a symlink on Windows: creating a symlink needs either
    developer mode or elevation, and needing to elevate to fuzz a binary is not a
    trade anybody should be asked to make. `mklink /J` needs neither.
    """
    if canonical.exists() or canonical.is_symlink():
        if _same_dir(canonical, state_dir):
            return None
        return (
            f"{canonical} already exists and is not the snapshot you passed "
            f"({state_dir}). wtf resolves --state from the target directory, so these "
            f"have to be the same place. Remove it, or use --target-name to pick a "
            f"different target directory."
        )

    canonical.parent.mkdir(parents=True, exist_ok=True)
    try:
        canonical.symlink_to(state_dir, target_is_directory=True)
        print(
            f"linked {_display(canonical, repo_root)} -> {state_dir}  "
            f"(wtf resolves --state from the target directory)"
        )
        return None
    except (OSError, NotImplementedError):
        pass  # no symlink privilege; a junction needs none

    if os.name == "nt":
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(canonical), str(state_dir)],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            print(
                f"linked {_display(canonical, repo_root)} -> {state_dir}  "
                f"(junction; wtf resolves --state from the target directory)"
            )
            return None
        detail = (result.stderr or result.stdout).strip()
        return (
            f"could not link {canonical} to your snapshot at {state_dir}: {detail}. "
            f"wtf resolves --state from the target directory, so either move the "
            f"snapshot there or create the link by hand: "
            f"mklink /J \"{canonical}\" \"{state_dir}\""
        )
    return (
        f"could not link {canonical} to your snapshot at {state_dir}. wtf resolves "
        f"--state from the target directory, so link or move it: "
        f"ln -s \"{state_dir}\" \"{canonical}\""
    )


def _config_describes(target_cfg: dict, binary: Path) -> bool:
    """Whether ``config/target.yaml`` is describing the binary about to be fuzzed.

    The gate on every fallback that reads that file. It describes the development
    target, so any value taken from it is that target's value -- correct when they are
    the same program and a hardcoded default dressed as configuration when they are
    not (D-073).

    Compared by filename stem rather than by full path: the same executable is
    legitimately reached through `targets/tlv_server/target/` and through an absolute
    path on another machine, and a mismatch there is not a different program.
    """
    configured = target_cfg.get("binary")
    if not configured:
        return False
    return Path(configured).stem.lower() == Path(binary).stem.lower()


def registered_fuzzer_modules(repo_root: Path = REPO_ROOT) -> set[str]:
    """The names our module source passes to wtf's ``Target_t`` constructor.

    Parsed from the source rather than listed here, so adding a second harness cannot
    leave this rejecting a module that now exists. Returns an empty set when nothing
    can be parsed, which the caller treats as "cannot check" rather than as "no
    modules" -- a regex that stops matching must not start failing every run.
    """
    import re

    names: set[str] = set()
    module_dir = repo_root / "fuzzer" / "module"
    for source in sorted(module_dir.glob("*.cc")):
        try:
            text = source.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        names.update(re.findall(r'Target_t\s+\w+\s*\(\s*"([^"]+)"', text))
    return names


def check_prerequisites(config: PipelineConfig, stages: list[Stage]) -> list[str]:
    """Everything that would fail mid-run, checked up front.

    Deliberately checked before ANY stage runs. Discovering a missing symbol path
    after a twenty-minute campaign wastes the campaign, and discovering a missing
    API key after Ghidra has run wastes the Ghidra time.
    """
    problems: list[str] = []

    if not PYTHON.exists():
        problems.append(f"no interpreter at {PYTHON}; create the venv first")
    if not config.binary.exists():
        problems.append(f"target binary {config.binary} does not exist")

    # `--module` is wtf's --name: the fuzzer module compiled into wtf.exe, not the
    # target's module name. The two are easy to confuse -- config/target.yaml calls
    # the fuzzer module `module` under `target:` and the TARGET's module `module`
    # under `entry:` -- and a wrong value here got as far as stage 10 before
    # `fuzzer.build --expect-target` rejected it, after Ghidra and entry selection had
    # already run. Checked against what the module source actually registers.
    # Only meaningful for the HAND-WRITTEN harness. With the generated one the module
    # stage 10 builds is `<module>_gen`, written by stage 09 from this run's specs, so
    # its registration is an output rather than a precondition -- and any `--module`
    # value is then a legitimate name for it.
    #
    # An earlier version of this added `<module>_gen` to the set before the emptiness
    # guard below, which turned "no .cc could be parsed, so this cannot be checked"
    # into a set of exactly one name and rejected every run. Caught by
    # test_a_complete_target_tree_has_no_prerequisite_problems.
    registered = registered_fuzzer_modules(config.repo_root)
    if registered and not config.use_generated_harness and config.module not in registered:
        problems.append(
            f"--module {config.module!r} is not a fuzzer module this repo builds "
            f"(it registers {sorted(registered)}). --module is wtf's --name, the "
            f"harness compiled into wtf.exe -- NOT the target's module name, which "
            f"is derived from --binary as {config.binary.stem!r}, and not the target "
            f"directory, which is --target-name"
        )

    # Derived from the stage list rather than hardcoded, so a reorder cannot leave
    # this naming stages that no longer exist -- which it already did once.
    ghidra_stages = [s.key for s in stages if "ghidra_headless" in " ".join(s.argv)]
    if ghidra_stages:
        from prep.ghidra_headless import find_ghidra, GhidraError

        # ALWAYS validated, never inferred from the variable being set. Trusting
        # its presence meant GHIDRA_INSTALL_DIR pointing at the wrong directory --
        # the misconfiguration a human actually makes -- passed the check and failed
        # twenty minutes later (D-057).
        try:
            find_ghidra(os.environ.get("GHIDRA_INSTALL_DIR"))
        except GhidraError as exc:
            problems.append(
                f"{exc} -- {', '.join(ghidra_stages)} need analyzeHeadless. "
                f"Run `python -m tools.bootstrap` to fetch and record it."
            )

    # Acquisition prerequisites, checked only when acquisition was asked for. A run
    # against an existing state/ needs none of these, so checking them always would
    # send people installing an SDK they do not need.
    if any(s.key == "07a-acquire" for s in stages):
        from prep.snapshot_win import _kd_from_config, _snapshot_dll_from_config

        kd_exe = _kd_from_config()
        if kd_exe is None or not Path(kd_exe).exists():
            problems.append(
                f"--kd-pipe asks for a snapshot but kd.exe is not usable ({kd_exe}). "
                f"Set tools.kd_exe in config/fuzz.yaml, or run "
                f"`python -m tools.bootstrap --vm-check`."
            )
        dll = _snapshot_dll_from_config()
        if dll is None or not Path(dll).exists():
            problems.append(
                f"--kd-pipe asks for a snapshot but the 0vercl0k/snapshot extension "
                f"is not usable ({dll}). Set tools.snapshot_dll in config/fuzz.yaml."
            )

    # symbolizer-rs is needed by the ANALYSIS stage, which runs after the campaign.
    # Discovering it missing there wastes exactly the minutes this check exists to
    # protect (D-057).
    if any("analysis." in " ".join(s.argv) for s in stages):
        from analysis.trace import find_symbolizer, TraceError

        try:
            find_symbolizer()
        except TraceError as exc:
            problems.append(f"{exc}")

    # The build stage needs a C++ toolchain with CMake.
    if any("fuzzer.build" in " ".join(s.argv) for s in stages):
        from fuzzer.build import find_vcvars, BuildError

        try:
            find_vcvars()
        except (BuildError, Exception) as exc:  # noqa: BLE001 - reported, not raised
            problems.append(f"no usable C++ toolchain for the build stage: {exc}")

    if any(s.calls_llm for s in stages):
        import yaml

        config_path = config.repo_root / "config" / "llm.yaml"
        llm_config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        providers = llm_config.get("providers") or {}
        # ANY provider's key is enough -- the client picks whichever resolves
        # (llm/client.py resolve_provider). Checking one hardcoded variable would
        # fail a machine that has an Anthropic key and no NCHC one, which is the
        # whole point of the multi-provider config.
        #
        # Parsed, not substring-matched: `# KEY=...` commented out in .env
        # satisfied `env_var in text` and passed a check whose entire job is to fail
        # before Ghidra runs (D-057).
        #
        # Duplicated here rather than imported from llm/client.py on purpose.
        # Importing it would make this module import the LLM client, and the RULE 1
        # claim in the docstring -- "holds no client, sends no prompt, reads no key"
        # -- has to be true of the imports too, not just of the calls.
        # tests/gates/test_cp12.py enforces that, and it caught this.
        wanted = [
            (p or {}).get("api_key_env")
            for p in providers.values()
            if (p or {}).get("api_key_env")
        ]
        dotenv = config.repo_root / ".env"
        found = [
            var
            for var in wanted
            if os.environ.get(var) or _read_dotenv_value(dotenv, var)
        ]
        if not wanted:
            problems.append(
                "config/llm.yaml declares no providers with an api_key_env"
            )
        elif not found:
            problems.append(
                f"no LLM API key: set one of [{', '.join(wanted)}] in the "
                f"environment or in a gitignored .env at the repo root"
            )

    # wtf resolves breakpoints by symbol name through dbgeng and sets no symbol
    # path itself, so without this every worker dies in Init (D-023, D-042).
    from fuzzer.run import resolve_symbol_paths
    import yaml as _yaml

    fuzz = _yaml.safe_load(
        (config.repo_root / "config" / "fuzz.yaml").read_text(encoding="utf-8")
    )
    target_cfg = _yaml.safe_load(
        (config.repo_root / "config" / "target.yaml").read_text(encoding="utf-8")
    )["target"]
    if os.name == "nt" and not resolve_symbol_paths(
        fuzz, target_cfg, target_dir=config.target_dir, repo_root=config.repo_root
    ):
        problems.append(
            "config/fuzz.yaml has no symbols.nt_symbol_path; wtf would die in Init "
            "unable to resolve its breakpoints"
        )

    # CREATED, not demanded. These four are this tool's own layout inside
    # `targets/<name>/`, they are empty, and wtf needs them to exist -- so telling a
    # user to mkdir four directories before their first run on a new target is
    # friction with nothing on the other side of it. Reported when created, because a
    # prerequisites section that silently changes the tree is worse than one that asks.
    #
    # `state/` is deliberately NOT created: it must contain a snapshot somebody
    # produced, and conjuring an empty one would turn "no snapshot" into a stage-07
    # failure about a missing mem.dmp inside a directory this code invented.
    created: list[str] = []
    for sub in ("inputs", "outputs", "coverage", "crashes"):
        path = config.target_dir / sub
        if path.is_dir():
            continue
        try:
            path.mkdir(parents=True, exist_ok=True)
            created.append(sub)
        except OSError as exc:
            problems.append(
                f"{path} is missing and could not be created ({exc}); section 13.1 "
                f"requires all five per-target directories"
            )
    if created:
        print(
            f"created {', '.join(created)} under "
            f"{_display(config.target_dir, config.repo_root)}"
        )

    # THE SNAPSHOT HAS TO BE FINDABLE AT targets/<name>/state.
    #
    # wtf is launched with `--state` derived from the target directory, and section
    # 13.1's per-target tree is what the campaign, the corpus and the crash watcher all
    # resolve against. So a user who keeps their dump somewhere else -- which is the
    # normal case, since a 1.8 GB mem.dmp does not belong in a repo -- got the whole
    # analysis half of the pipeline working and then `PREFLIGHT: mem.dmp missing` (D-075).
    #
    # Linked, not copied: copying a multi-gigabyte dump per target is not a reasonable
    # thing to do to somebody's disk. A junction needs no privileges on Windows.
    canonical_state = config.target_dir / "state"
    if config.state_dir.is_dir() and not _same_dir(config.state_dir, canonical_state):
        problem = _link_state(config.state_dir, canonical_state, config.repo_root)
        if problem:
            problems.append(problem)

    if not config.state_dir.is_dir():
        problems.append(
            f"{config.state_dir} is missing, and unlike the four directories above "
            f"it is NOT produced by this pipeline -- it has to be supplied. It needs "
            f"mem.dmp, regs.json and symbol-store.json from a snapshot of your target "
            f"taken at its parser. Point --state-dir at one you already have. "
            f"`--kd-pipe` runs the acquisition wrapper against a guest VM, but edges "
            f"1/6/7 are still pending: that path has never been executed end to end, "
            f"so treat it as untested rather than as the easy option "
            f"(docs/GUEST-VM.md)."
        )
    # Derived from the stage list, like the Ghidra check above: stage 09b builds a
    # first test-case from the InputSpec, so demanding one up front would ask the user
    # for something this run is about to produce. Still demanded when 09b is not in the
    # plan -- `--only 11` on an empty corpus is a campaign that explores nothing.
    seed_stage = any("fuzzer.seed" in " ".join(s.argv) for s in stages)
    if not seed_stage and not any((config.target_dir / "inputs").glob("*")):
        problems.append(
            f"{config.target_dir / 'inputs'} holds no seeds. Put at least one file "
            f"there: a single input your target accepts, byte for byte, as it would "
            f"arrive at the parser -- one captured packet or message is enough, and "
            f"the mutator and the slow clock build from it. The master starts from "
            f"inputs/ and an empty corpus gives the mutator nothing to work from"
        )
    return problems


# --- running -------------------------------------------------------------


@dataclass
class StageResult:
    key: str
    title: str
    status: str  # ran | skipped-uptodate | skipped-selected | blocked | failed
    seconds: float = 0.0
    detail: str = ""


def _artifact_problem(path: Path) -> str | None:
    """Why ``path`` does not count as a produced artifact, or None.

    Existence alone was the original test and it is too weak. A zero-byte file and
    a directory-where-a-file-belongs are the normal residue of an interrupted stage
    -- Ctrl-C during a Ghidra export, a full disk, a killed campaign -- and every
    one of them satisfied ``exists()`` and was reported as done (D-057).
    """
    if not path.exists():
        return "absent"
    if path.is_dir():
        return "is a directory where a file was expected"
    if path.stat().st_size == 0:
        return "is zero bytes -- the residue of an interrupted stage"
    return None


def _up_to_date(
    stage: Stage,
    identity: TargetIdentity | None = None,
    stamps: dict[str, ArtifactStamp] | None = None,
    artifacts_dir: Path | None = None,
) -> tuple[bool, str | None]:
    """Whether the stage's artifacts can be reused, and if not, why not.

    "Present and non-empty" was the whole check, and presence is a fact about the
    filesystem rather than about this run. Running a second target therefore skipped
    the first four stages and inherited another program's pseudo-C, fuzz entry and
    basic blocks -- see orchestrator/provenance.py for the transcript (D-073).

    Returns the reason as well as the verdict because the reason has to be printed:
    "SKIPPED, already produced" in front of a target the user has never analysed
    before is the message that hid the bug.

    Never reusable for a non-idempotent stage: see :class:`Stage`.
    """
    if not stage.produces or not stage.idempotent:
        return False, None
    if any(_artifact_problem(p) is not None for p in stage.produces):
        return False, None
    if identity is None or stamps is None or artifacts_dir is None:
        # No identity to check against. Callers inside the pipeline always pass one;
        # this branch keeps the "does the output exist" question answerable on its
        # own, which is what the `blocked` path below actually wants to know.
        return True, None
    for path in stage.produces:
        reason = stale_reason(path, identity, stamps, artifacts_dir)
        if reason is not None:
            return False, f"{_display(path, REPO_ROOT)} {reason}"
    return True, None


def _fingerprint(paths: list[Path]) -> dict[Path, tuple[int, int] | None]:
    """(mtime_ns, size) per artifact, or None where absent."""
    out: dict[Path, tuple[int, int] | None] = {}
    for path in paths:
        try:
            stat = path.stat()
            out[path] = (stat.st_mtime_ns, stat.st_size)
        except OSError:
            out[path] = None
    return out


def _display(path: Path, repo_root: Path) -> str:
    """Repo-relative when it can be, absolute otherwise.

    `--state-dir` may legitimately point outside the repo (another drive, a shared
    snapshot store), and finding that out via a ValueError raised while printing a
    progress message is the wrong way to learn it.
    """
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def resolve_entry(
    argv: list[str], entry_json: Path, layout_json: Path | None = None
) -> list[str] | str:
    """Substitute ``ENTRY_PLACEHOLDER`` from the snapshot, or from the FuzzEntry.

    The LAYOUT wins when there is one, and the reason is not preference: rip is where
    the snapshot stopped, so it is where fuzzing resumes whatever any model concluded
    from reading pseudo-C. Resolving from the layout also means the placeholder is
    answerable at stage 02b instead of stage 03, which matters because stage 07 would
    otherwise reject a snapshot whose rip disagreed with the model's choice -- and
    reject it with a message about re-taking the snapshot, for a function the user never
    asked for (D-075).

    Returns the resolved argv, or an error string. An error rather than a
    fallback: the alternative is guessing a symbol name, and a plausible wrong
    entry produces a harness that runs, reports coverage, and never enters the
    parser -- the exact silent failure CP4's trace validation exists to catch.
    """
    # Substitution is by WHOLE ELEMENT, so an argv that embeds the placeholder in a
    # larger string is a bug in the stage, not a missing entry: it silently survives
    # this function unchanged. It happened immediately -- stage 07a first built its
    # breakpoint as f"{module}!{entry}", which would have reached kd as the literal
    # `bp tlv_server!<ENTRY>`, an unbindable breakpoint that looks exactly like "the
    # stimulus never arrived". Refuse rather than pass it through.
    embedded = [
        part for part in argv if ENTRY_PLACEHOLDER in part and part != ENTRY_PLACEHOLDER
    ]
    if embedded:
        return (
            f"{embedded} embeds {ENTRY_PLACEHOLDER} inside a larger argument. "
            f"Substitution replaces whole arguments only, so this would be passed "
            f"through unresolved. Pass the placeholder as its own argument."
        )
    if ENTRY_PLACEHOLDER not in argv:
        return argv

    if layout_json is not None and layout_json.exists():
        try:
            from prep.layout import Layout

            symbol = Layout.load(layout_json).entry_symbol
        except Exception as exc:
            return f"{layout_json} is not a readable Layout: {exc}"
        if symbol:
            return [symbol if part == ENTRY_PLACEHOLDER else part for part in argv]

    if not entry_json.exists():
        return (
            f"the fuzz entry is not known yet and {entry_json.name} does not exist. "
            f"Run stage 03 first, or pass --entry-symbol."
        )
    try:
        from arch.contracts import FuzzEntry

        entry = FuzzEntry.model_validate_json(entry_json.read_text(encoding="utf-8"))
    except Exception as exc:
        return f"{entry_json} is not a readable FuzzEntry: {exc}"

    if not entry.symbol:
        return (
            f"{entry_json.name} names no symbol, only address "
            f"{entry.static_addr:#x}. Pass --entry-symbol, or use the address."
        )
    return [entry.symbol if part == ENTRY_PLACEHOLDER else part for part in argv]


def run_pipeline(
    config: PipelineConfig,
    *,
    only: set[str] | None = None,
    start_from: str | None = None,
    force: bool = False,
    dry_run: bool = False,
) -> list[StageResult]:
    stages = build_stages(config)
    results: list[StageResult] = []

    all_stages = list(stages)
    keys = [s.key for s in stages]

    if start_from:
        matches = [k for k in keys if k.startswith(start_from)]
        if not matches:
            raise SystemExit(f"--from {start_from!r} matches no stage; have {keys}")
        if len(matches) > 1:
            # `--from 1` matched 10, 11, 12 and 13 as a raw prefix and silently
            # started at 10 -- i.e. it skipped the entire static-analysis half while
            # the summary claimed everything was accounted for (D-057).
            raise SystemExit(
                f"--from {start_from!r} is ambiguous: it matches {matches}. Give "
                f"enough of the key to pick one, e.g. {matches[0]!r}."
            )
        stages = stages[keys.index(matches[0]) :]

    if only:
        unmatched = sorted(
            o for o in only if not any(k.startswith(o) for k in keys)
        )
        if unmatched:
            # Unvalidated, a one-character typo skipped all fourteen stages and
            # reported "all stages accounted for" with exit 0. `--from` already
            # guarded against the same typo; `--only` did not (D-057).
            raise SystemExit(
                f"--only {unmatched} matches no stage; have {keys}"
            )

    env = dict(os.environ)
    parts = (p.strip().strip('"') for p in env.get("PATH", "").split(os.pathsep))
    env["PATH"] = os.pathsep.join(p for p in parts if p)

    # WHICH TARGET THIS RUN IS FOR. Hashing the binary once here, not per stage:
    # every stage compares against the same identity, and a target rebuilt midway
    # through a run should not have half its artifacts stamped against each version.
    identity = TargetIdentity.of(
        target_name=config.target_name, binary=config.binary, scope=config.scope
    )
    stamps = load_stamps(config.artifacts)

    for index, stage in enumerate(stages, start=1):
        marker = " [LLM]" if stage.calls_llm else ""
        print(f"\n{'=' * 74}")
        print(f"[{index}/{len(stages)}] {stage.key}: {stage.title}{marker}")
        if stage.note:
            print(f"  note: {stage.note}")
        print("=" * 74, flush=True)

        if only and not any(stage.key.startswith(o) for o in only):
            print("  SKIPPED (not selected by --only)")
            results.append(StageResult(stage.key, stage.title, "skipped-selected"))
            continue

        if stage.blocked:
            if _up_to_date(stage)[0]:
                print(f"  BLOCKED but its output exists, continuing: {stage.blocked}")
                results.append(
                    StageResult(stage.key, stage.title, "skipped-uptodate",
                                detail=stage.blocked)
                )
                continue
            print(f"  BLOCKED: {stage.blocked}")
            results.append(StageResult(stage.key, stage.title, "blocked",
                                       detail=stage.blocked))
            break

        if not force:
            reusable, why_not = _up_to_date(stage, identity, stamps, config.artifacts)
            if reusable:
                produced = ", ".join(
                    _display(p, config.repo_root) for p in stage.produces
                )
                print(f"  SKIPPED, already produced: {produced}")
                print("  (pass --force to re-run)")
                results.append(StageResult(stage.key, stage.title, "skipped-uptodate"))
                continue
            if why_not:
                # The output is there and is NOT ours. Saying so is the difference
                # between this run and the one in D-073, which printed "SKIPPED,
                # already produced" for a target it had never seen.
                print(f"  RE-RUNNING: {why_not}")

        missing = [p for p in stage.needs if not p.exists()]
        if missing and dry_run:
            # In a dry run nothing has been produced, so an input an EARLIER stage
            # would create is expected to be absent -- reporting that as a failure
            # would stop the plan at the first such stage and defeat the purpose.
            # An input no stage produces is still a real problem and still fails.
            upstream = {p: s.key for s in stages for p in s.produces}
            unexplained = [p for p in missing if p not in upstream]
            if unexplained:
                names = ", ".join(str(p) for p in unexplained)
                print(f"  CANNOT RUN, missing input(s) nothing produces: {names}")
                results.append(
                    StageResult(stage.key, stage.title, "failed",
                                detail=f"missing inputs: {names}")
                )
                break
            produced_by = ", ".join(
                f"{p.name} (from {upstream[p]})" for p in missing
            )
            print(f"  would use: {produced_by}")
            missing = []

        if missing:
            names = ", ".join(str(p) for p in missing)
            print(f"  CANNOT RUN, missing input(s): {names}")
            results.append(
                StageResult(stage.key, stage.title, "failed",
                            detail=f"missing inputs: {names}")
            )
            break

        resolved = resolve_entry(
            stage.argv,
            config.artifacts / "fuzz_entry_llm.json",
            config.artifacts / "a0_layout.json",
        )
        if isinstance(resolved, str) and dry_run:
            # Same exemption the needs check above already makes: in a dry run the
            # entry has not been chosen yet BECAUSE stage 03 has not run. Two lines
            # in this file used to disagree about that, and the stricter one won --
            # so a correct dry run of a new target reported `failed` and exit 1,
            # a false alarm in the one place these summaries must be trustworthy
            # (D-057).
            producer = next(
                (s.key for s in stages
                 if config.artifacts / "fuzz_entry_llm.json" in s.produces),
                "an earlier stage",
            )
            print(f"  would resolve the entry symbol from {producer}")
            resolved = [
                part for part in stage.argv if part != ENTRY_PLACEHOLDER
            ]
        elif isinstance(resolved, str):
            print(f"  CANNOT RUN: {resolved}")
            results.append(
                StageResult(stage.key, stage.title, "failed", detail=resolved)
            )
            break

        print(f"  $ {' '.join(resolved[3:])}", flush=True)
        if dry_run:
            # A distinct status: a dry run legitimately performs no work, so its
            # success criterion is a COMPLETE PLAN, not that something happened.
            # Reusing skipped-selected made the no-op check below fire on every
            # dry run -- a false alarm in the check written against false alarms.
            results.append(StageResult(stage.key, stage.title, "planned"))
            continue

        # Fingerprint BEFORE launching. Checking only that the artifact exists
        # afterwards made the rule vacuous: a previous run's file satisfies it, so a
        # stage that exits 0 having written nothing -- which is exactly D-026's
        # documented analyzeHeadless behaviour, the reason the rule exists -- was
        # reported OK. With --force, all fourteen stages reported "ran" and the
        # summary printed success while not one artifact had been touched (D-057).
        before = _fingerprint(stage.produces)

        started = time.time()
        completed = subprocess.run(resolved, cwd=config.repo_root, env=env)
        elapsed = time.time() - started

        if completed.returncode != 0:
            print(f"  FAILED, exit {completed.returncode} after {elapsed:.0f}s")
            results.append(
                StageResult(stage.key, stage.title, "failed", elapsed,
                            f"exit {completed.returncode}")
            )
            break

        # The artifact is the evidence, and it has to be THIS run's artifact.
        complaints: list[str] = []
        after = _fingerprint(stage.produces)
        for path in stage.produces:
            problem = _artifact_problem(path)
            if problem:
                complaints.append(f"{path.name} {problem}")
            elif (
                not stage.output_may_be_unchanged
                and before[path] is not None
                and after[path] == before[path]
            ):
                complaints.append(
                    f"{path.name} is byte-for-byte the file that was already there "
                    f"-- this stage exited 0 without writing it"
                )
        if complaints:
            detail = "; ".join(complaints)
            print(f"  FAILED: exit 0 but the evidence is wrong -- {detail}")
            results.append(
                StageResult(stage.key, stage.title, "failed", elapsed, detail)
            )
            break

        if stage.verify is not None:
            problem = stage.verify()
            if problem:
                print(f"  FAILED: the artifact exists but {problem}")
                results.append(
                    StageResult(stage.key, stage.title, "failed", elapsed, problem)
                )
                break

        # Stamp only now -- after exit 0, after the artifact checks, after `verify`.
        # Stamping earlier would record provenance for output that the checks above
        # went on to reject, and a stamp on a rejected artifact is worse than none:
        # the next run would reuse it.
        record_provenance(config.artifacts, identity, stage.key, stage.produces)
        stamps = load_stamps(config.artifacts)

        print(f"  OK in {elapsed:.0f}s")
        results.append(StageResult(stage.key, stage.title, "ran", elapsed))

    return results


def _summarise(results: list[StageResult], total: int) -> int:
    print(f"\n{'=' * 74}")
    print("PIPELINE SUMMARY")
    print("=" * 74)
    for result in results:
        seconds = f"{result.seconds:>6.0f}s" if result.seconds else "       "
        print(f"  {result.status:<18} {seconds}  {result.key}: {result.title}")
        if result.detail:
            print(f"                              {result.detail}")

    ran = [r for r in results if r.status == "ran"]
    failed = [r for r in results if r.status == "failed"]
    blocked = [r for r in results if r.status == "blocked"]
    skipped = [r for r in results if r.status.startswith("skipped")]
    selected_out = [r for r in results if r.status == "skipped-selected"]

    print(
        f"\n  {len(ran)} ran, {len(skipped)} skipped, {len(blocked)} blocked, "
        f"{len(failed)} failed, of {total} stage(s)"
    )
    # Never print an unqualified success. A run that did 3 of 13 stages and said
    # "done" is the failure mode this whole module is written against.
    if failed or blocked:
        print("  PIPELINE DID NOT COMPLETE")
        return 1
    if len(results) < total:
        print(f"  INCOMPLETE: {total - len(results)} stage(s) were never reached")
        return 1
    # Nothing ran and nothing was already done: whatever was asked for, it did not
    # happen. Reporting that as success is how a mistyped selector became a silent
    # no-op with exit 0 (D-057).
    planned = [r for r in results if r.status == "planned"]
    if planned:
        print(f"  planned only -- {len(planned)} stage(s) would run; nothing executed")
        return 0
    if not ran and len(selected_out) == len(results):
        print("  NOTHING RAN: every stage was excluded by the selection")
        return 1
    print("  all stages accounted for")
    return 0


def main(argv: list[str] | None = None) -> int:
    import yaml

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target-name", default=None, help="targets/<name>; default from config")
    ap.add_argument("--binary", type=Path, default=None)
    ap.add_argument("--entry-symbol", default=None)
    ap.add_argument("--state-dir", type=Path, default=None)
    ap.add_argument(
        "--module",
        default=None,
        help="wtf's --name: the FUZZER harness compiled into wtf.exe "
             "(default from config/target.yaml). This is not the target's "
             "module name -- that comes from --binary -- and not the target "
             "directory, which is --target-name",
    )
    harness = ap.add_mutually_exclusive_group()
    harness.add_argument(
        "--generated-harness",
        dest="generated_harness",
        action="store_true",
        default=None,
        help="derive the harness from this binary's pseudo-C and compile it "
             "(edge 14). Default for any target config/target.yaml does not "
             "describe, because the hand-written harness parses tlv_server's "
             "format and would deliver nothing meaningful to another program",
    )
    harness.add_argument(
        "--handwritten-harness",
        dest="generated_harness",
        action="store_false",
        help="use the checked-in fuzzer_snapfuzz.cc. Default for the "
             "development target, whose recorded corpus and crash files are "
             "keyed to its test-case JSON",
    )
    ap.add_argument(
        "--codegen",
        choices=("template", "llm"),
        default="template",
        help="who writes the module C++: the deterministic renderer, or the "
             "550B directly. `llm` is checked by the compiler and by the "
             "campaign having to produce coverage, not by a schema",
    )
    ap.add_argument("--scope", choices=("module", "function-closure"), default="module")
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--minutes", type=float, default=15.0)
    ap.add_argument("--plateau-execs", type=int, default=20_000)
    ap.add_argument("--seeds", type=int, default=6)
    ap.add_argument("--samples", type=int, default=2)
    ap.add_argument("--replays", type=int, default=3)
    # Defaults to the target name, not "pipeline". Campaign, analysis and triage
    # outputs all live in artifacts/runs/<label>/, so a constant default put two
    # different targets' results in one directory -- and stage 08 is
    # idempotent=False, so a failure there left the PREVIOUS target's
    # buckets.json in place for anything reading that path (D-073).
    ap.add_argument("--label", default=None)
    ap.add_argument(
        "--kd-pipe",
        default=None,
        help=r"host named pipe for the guest COM port (e.g. \\.\pipe\snapfuzz). "
        r"Supplying it ADDS stage 07a, which takes the snapshot instead of "
        r"requiring one; without it a state/ directory must already exist",
    )
    ap.add_argument(
        "--kd-stimulus",
        default=None,
        help="command that drives the target to its parser; without one `g` never "
        "returns for a service that is waiting for input",
    )
    ap.add_argument("--kd-timeout", type=int, default=900, dest="kd_timeout_s")
    ap.add_argument(
        "--wow64",
        action="store_true",
        help="32-bit target: switch to the 64-bit context before snapshotting",
    )
    ap.add_argument("--only", nargs="*", help="run only these stage key prefixes")
    ap.add_argument("--from", dest="start_from", help="start at this stage key prefix")
    ap.add_argument("--force", action="store_true", help="re-run up-to-date stages")
    ap.add_argument("--dry-run", action="store_true", help="print the plan, run nothing")
    ap.add_argument("--list", action="store_true", help="list the stages and exit")
    args = ap.parse_args(argv)

    full_config = yaml.safe_load(
        (REPO_ROOT / "config" / "target.yaml").read_text(encoding="utf-8")
    )
    target_cfg = full_config["target"]
    binary = args.binary or REPO_ROOT / target_cfg["binary"]
    config = PipelineConfig(
        target_name=args.target_name
        or target_cfg.get("target_dir", "targets/snapfuzz").split("/")[-1],
        binary=binary,
        # Precedence: the flag, then the entry config/target.yaml records IF THAT FILE
        # IS ABOUT THIS BINARY, then late-binding from stage 03.
        #
        # The middle clause used to be unconditional. D-057 added it because the
        # driver was ignoring an entry the repo already recorded -- correct for the
        # development target and wrong for every other one, because `entry.symbol` is
        # tlv_server's `ProcessPacket`. The consequence was that `entry_for_scoping`
        # was NEVER the placeholder, so late binding from stage 03 became dead code
        # and every new target was scoped to a function it may not contain. The
        # reported run shows it: `entry : ProcessPacket` printed for
        # `fuzzing-base-test.exe`, before stage 03 had chosen anything (D-073).
        #
        # Fixing one hardcoded default by reading a config file only moves the
        # hardcoding, unless the read is conditional on the file being about the thing
        # you are doing.
        entry_symbol=(
            args.entry_symbol
            or (
                (full_config.get("entry") or {}).get("symbol")
                or target_cfg.get("entry_symbol")
                if _config_describes(target_cfg, binary)
                else None
            )
        ),
        state_dir=args.state_dir or (REPO_ROOT / target_cfg.get("target_dir", "targets/snapfuzz") / "state"),
        module=args.module or target_cfg.get("module") or "snapfuzz",
        scope=args.scope,
        workers=args.workers,
        minutes=args.minutes,
        plateau_execs=args.plateau_execs,
        seeds=args.seeds,
        samples=args.samples,
        replays=args.replays,
        label=args.label or args.target_name or "pipeline",
        generated_harness=args.generated_harness,
        codegen=args.codegen,
        kd_pipe=args.kd_pipe,
        kd_stimulus=args.kd_stimulus,
        kd_timeout_s=args.kd_timeout_s,
        wow64=args.wow64,
    )

    stages = build_stages(config)

    if args.list:
        print(f"{len(stages)} stages for {config.target_name} "
              f"({config.binary.name}!{config.entry_symbol or '?'}):\n")
        for index, stage in enumerate(stages, start=1):
            marker = " [LLM]" if stage.calls_llm else ""
            print(f"  {index:>2}. {stage.key:<14} {stage.title}{marker}")
            if stage.note:
                print(f"      {stage.note}")
        return 0

    print(f"target    : {config.target_name} ({config.target_dir})")
    print(f"binary    : {config.binary}")
    print(f"entry     : {config.entry_symbol or '(late-bound from stage 03)'}")
    # THREE different module-ish names, printed as three lines. One line reading
    # "module : demo" is what a user saw immediately before the run wrote
    # `tlv_server.cov`, and neither string was wrong -- they were answers to
    # different questions (D-073).
    print(f"target mod: {config.target_module}   (what symbols and .cov are named for)")
    if config.use_generated_harness:
        print(f"fuzzer mod: {config.module}_gen   (GENERATED from this binary's "
              f"pseudo-C, compiled by stage 10)")
    else:
        print(f"fuzzer mod: {config.module}   (hand-written fuzzer_snapfuzz.cc, "
              f"parses tlv_server's TLV format)")
    print(f"scope     : {config.scope}")
    print(f"campaign  : {config.workers} worker(s), {config.minutes:.0f} min")
    print(f"artifacts : {_display(config.artifacts, config.repo_root)}  "
          f"runs/{config.label}")

    problems = check_prerequisites(config, stages)
    if problems:
        print("\nPREREQUISITES NOT MET -- nothing was run:")
        for problem in problems:
            print(f"  ! {problem}")
        return 1
    print("prerequisites: ok")

    results = run_pipeline(
        config,
        only=set(args.only) if args.only else None,
        start_from=args.start_from,
        force=args.force,
        dry_run=args.dry_run,
    )
    return _summarise(results, len(stages) if not args.start_from else len(results))


if __name__ == "__main__":
    raise SystemExit(main())
