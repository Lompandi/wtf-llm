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
  three of thirteen stages and printed "done" is worse than a crash.
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
    def target_dir(self) -> Path:
        return self.repo_root / "targets" / self.target_name

    @property
    def artifacts(self) -> Path:
        return self.repo_root / "artifacts"


def build_stages(config: PipelineConfig) -> list[Stage]:
    """The thirteen stages, in the only order that resolves for a NEW target.

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
    generated = config.repo_root / "fuzzer" / "module" / "generated_input.h"
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
        if payload.get("peak_executions", 0) <= 0:
            return (
                "the campaign executed ZERO test-cases. That is what every worker "
                "dying in Init looks like -- check _NT_SYMBOL_PATH and that the "
                "module resolves its breakpoints (D-023, D-042)"
            )
        if payload.get("ticks", 0) <= 0:
            return "the campaign recorded no ticks, so it never observed the master"
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
            key="03-entry",
            title="LLM: choose the fuzz entry",
            argv=py(
                "prep.entry_select", "--cache", str(a2_db),
                "--module", Path(config.binary).stem, "--out", str(entry_json),
            ),
            needs=[a2_db],
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
            ),
            needs=[a3_json],
            # BOTH: the .cov in the target's coverage/ directory is the actual
            # interface-3 deliverable (D-017), and the bp-list JSON is the
            # by-product. Naming only the JSON let a stage pass while the file wtf
            # actually reads was absent.
            produces=[
                art / "a3_bp_list.json",
                config.target_dir / "coverage" / f"{Path(config.binary).stem}.cov",
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
                        "--module", Path(config.binary).stem,
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
                "--module", Path(config.binary).stem,
                "--binary", str(config.binary),
                "--entry-symbol", entry_for_scoping,
                "--out", str(a1_json),
            ),
            needs=[config.state_dir / "mem.dmp", config.state_dir / "regs.json"],
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
            key="09-codegen",
            title="InputSpec -> C++ header (no LLM)",
            argv=py(
                "fuzzer.codegen", "--spec", str(spec_json), "--out", str(generated),
            ),
            needs=[spec_json],
            produces=[generated],
            note=(
                "the shipped tlv_server module does NOT include this yet -- edge 14 "
                "is pending because adopting it would rename the JSON keys and "
                "invalidate the existing corpus and crash files (D-055)"
            ),
        ),
        Stage(
            key="10-build",
            title="Build wtf + our module",
            argv=py("fuzzer.build", "--expect-target", config.module),
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

    for sub in ("inputs", "outputs", "coverage", "crashes"):
        if not (config.target_dir / sub).is_dir():
            problems.append(
                f"{config.target_dir / sub} is missing; section 13.1 requires all "
                f"five per-target directories"
            )
    if not config.state_dir.is_dir():
        problems.append(
            f"{config.state_dir} is missing. The snapshot is NOT produced by this "
            f"pipeline (edges 1/6/7 pending) -- it has to be supplied."
        )
    if not any((config.target_dir / "inputs").glob("*")):
        problems.append(
            f"{config.target_dir / 'inputs'} holds no seeds; the master starts from "
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


def _up_to_date(stage: Stage) -> bool:
    """Whether the stage's artifacts are all present and non-empty.

    Never true for a non-idempotent stage: see :class:`Stage`.
    """
    if not stage.produces or not stage.idempotent:
        return False
    return all(_artifact_problem(p) is None for p in stage.produces)


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


def resolve_entry(argv: list[str], entry_json: Path) -> list[str] | str:
    """Substitute ``ENTRY_PLACEHOLDER`` from the FuzzEntry artifact.

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
            # Unvalidated, a one-character typo skipped all thirteen stages and
            # reported "all stages accounted for" with exit 0. `--from` already
            # guarded against the same typo; `--only` did not (D-057).
            raise SystemExit(
                f"--only {unmatched} matches no stage; have {keys}"
            )

    env = dict(os.environ)
    parts = (p.strip().strip('"') for p in env.get("PATH", "").split(os.pathsep))
    env["PATH"] = os.pathsep.join(p for p in parts if p)

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
            if _up_to_date(stage):
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

        if not force and _up_to_date(stage):
            produced = ", ".join(_display(p, config.repo_root) for p in stage.produces)
            print(f"  SKIPPED, already produced: {produced}")
            print("  (pass --force to re-run)")
            results.append(StageResult(stage.key, stage.title, "skipped-uptodate"))
            continue

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

        resolved = resolve_entry(stage.argv, config.artifacts / "fuzz_entry_llm.json")
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
        # reported OK. With --force, all thirteen stages reported "ran" and the
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
    ap.add_argument("--module", default=None)
    ap.add_argument("--scope", choices=("module", "function-closure"), default="module")
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--minutes", type=float, default=15.0)
    ap.add_argument("--plateau-execs", type=int, default=20_000)
    ap.add_argument("--seeds", type=int, default=6)
    ap.add_argument("--samples", type=int, default=2)
    ap.add_argument("--replays", type=int, default=3)
    ap.add_argument("--label", default="pipeline")
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
        # Precedence: the flag, then the entry config/target.yaml ALREADY RECORDS,
        # then late-binding from stage 03.
        #
        # An earlier comment here claimed the config records no entry. It does --
        # under a TOP-LEVEL `entry:` key, with symbol, input_param and size_param --
        # and this read `target.entry_symbol`, which does not exist. So the driver
        # ignored a fact the repo already had, and the comment justifying late
        # binding rested on a misread config (D-057). Late binding is still right
        # for a genuinely new target, which is why it remains the fallback.
        entry_symbol=(
            args.entry_symbol
            or (full_config.get("entry") or {}).get("symbol")
            or target_cfg.get("entry_symbol")
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
        label=args.label,
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
    print(f"module    : {config.module}   scope: {config.scope}")
    print(f"campaign  : {config.workers} worker(s), {config.minutes:.0f} min")

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
