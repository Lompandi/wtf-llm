"""Does the repair loop CONVERGE now that it quotes the line MSVC named?

Pass rate at n=5 is weak evidence -- the failure it is chasing appeared once in five. But
convergence is observable in a single failure and is the thing that changed: the previous
run's one failure reported

    fuzzer_gen.cc(124): error C2440: cannot convert from 'uint64_t' to 'Gva_t'

three times, byte-identical, across the original answer and both repairs. So this records
the error set at EVERY repair attempt, not just the last, and reports whether consecutive
attempts differ. Identical sets mean the loop is blind; different sets mean it is working on
the problem even if it runs out of attempts.

Two gates per attempt, as before:
  compiled   MSVC under /WX, after up to 2 repairs driven by the diagnostics
  delivered  the seed and an EMPTY test-case trace DIFFERENTLY (analysis.trace)

Writes fuzzer/module/fuzzer_gen.cc because that is where fuzzer/build.py stages from; the
committed file is saved first and restored at the end, pass or fail.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(r"d:\wtf-llm")
PY = REPO / ".venv" / "Scripts" / "python.exe"
MODULE = REPO / "fuzzer" / "module" / "fuzzer_gen.cc"
BACKUP = MODULE.with_suffix(".cc.measure-backup")
ART = REPO / "artifacts" / "fuzzing-base-test"
TARGET_DIR = REPO / "targets" / "fuzzing-base-test"
BINARY_DIR = REPO / "fuzzing-snapshot-2" / "target"
OUT = REPO / "artifacts" / "measure"
ATTEMPTS = int(sys.argv[1]) if len(sys.argv) > 1 else 5

# This script lives in the scratchpad, not the repo, so `import fuzzer` needs help. The
# instrumentation below asks `_offending_lines` directly rather than grepping stdout, which
# is the only honest way to know whether the quoting fired.
sys.path.insert(0, str(REPO))


def harness_env() -> dict[str, str]:
    env = dict(os.environ)
    a1 = json.loads((ART / "a1_snapshot.json").read_text(encoding="utf-8"))
    env["SNAPFUZZ_MODULE_BASE"] = hex(int(a1["module_base"]))
    spec = json.loads((ART / "harness_spec.json").read_text(encoding="utf-8"))
    if spec.get("input_buffer_bytes"):
        env["SNAPFUZZ_INPUT_BUFFER_BYTES"] = str(spec["input_buffer_bytes"])
    return env


def error_rounds(out: str) -> list[list[str]]:
    """The error set at each repair attempt, in order.

    The loop prints `compile attempt N failed:` then its diagnostics, so the rounds are
    delimited by that line. A trailing round with no header is the final failure.
    """
    rounds: list[list[str]] = []
    current: list[str] | None = None
    for line in out.splitlines():
        if "compile attempt" in line and "failed" in line:
            if current is not None:
                rounds.append(current)
            current = []
            continue
        if current is not None and re.search(r"error [A-Z]\d+:", line):
            # Normalised: the message, without the absolute path, so two rounds are
            # comparable by content rather than by formatting.
            current.append(re.sub(r"^.*fuzzer_gen\.cc", "fuzzer_gen.cc", line.strip()))
    if current:
        rounds.append(current)
    return rounds


def delivery_check(attempt: int) -> tuple[bool, str]:
    proc = subprocess.run(
        [
            str(PY), "-m", "analysis.trace",
            "--wtf", str(REPO / "src" / "build" / "wtf.exe"),
            "--target-dir", str(TARGET_DIR),
            "--name", "snapfuzz_gen",
            "--input", str(TARGET_DIR / "inputs"),
            "--entry-symbol", "fuzzme",
            "--binary-dir", str(BINARY_DIR),
            "--out", str(OUT / f"attempt{attempt}"),
        ],
        cwd=REPO, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=1800, env=harness_env(),
    )
    out = proc.stdout + proc.stderr
    line = next(
        (l.strip() for l in out.splitlines() if l.startswith("delivery")), "no verdict"
    )
    return proc.returncode == 0 and "delivery    : YES" in out, line


shutil.copy2(MODULE, BACKUP)
results = []
try:
    for attempt in range(1, ATTEMPTS + 1):
        MODULE.unlink(missing_ok=True)
        proc = subprocess.run(
            [
                str(PY), "-m", "fuzzer.codegen_llm",
                "--spec", str(ART / "input_spec.json"),
                "--harness", str(ART / "harness_spec.json"),
                "--module-out", str(MODULE),
                "--compile-retries", "2",
            ],
            cwd=REPO, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=3600,
        )
        out = proc.stdout + proc.stderr
        compiled = "compiles clean" in out
        rounds = error_rounds(out)
        # NOT from stdout. `_offending_lines` output goes into the PROMPT, never to the
        # console, so checking stdout for it reported line_quoted=False on a run where the
        # quoting had fired -- a measurement bug that would have been read as evidence the
        # fix did nothing. Asked of the function directly instead.
        from fuzzer.codegen_llm import _offending_lines
        first_round = rounds[0] if rounds else []
        quoted_line = bool(
            _offending_lines(MODULE.read_text(encoding="utf-8"), first_round).strip()
        ) if (rounds and MODULE.exists()) else None

        delivered, verdict = (False, "not run -- did not compile")
        if compiled:
            delivered, verdict = delivery_check(attempt)

        # Did consecutive repair rounds actually change? Identical sets are the signature
        # the fix targets.
        progressed = None
        if len(rounds) > 1:
            progressed = any(rounds[i] != rounds[i + 1] for i in range(len(rounds) - 1))

        record = {
            "attempt": attempt,
            "compiled": compiled,
            "delivered": delivered,
            "repair_rounds": len(rounds),
            "errors_changed_between_rounds": progressed,
            "line_was_quoted": quoted_line,
            "lines": len(MODULE.read_text(encoding="utf-8").splitlines())
            if MODULE.exists() else 0,
            "rounds": rounds,
            "delivery": verdict[:200],
        }
        results.append(record)
        print(
            f"attempt {attempt}: compiled={compiled} delivered={delivered} "
            f"rounds={len(rounds)} lines={record['lines']}"
            + ("" if progressed is None else f" errors_changed={progressed}"),
            flush=True,
        )
        for i, r in enumerate(rounds, 1):
            print(f"    round {i}: {len(r)} error(s)", flush=True)
            for e in r[:2]:
                print(f"      {e[:130]}", flush=True)
        if compiled:
            print(f"    {verdict[:150]}", flush=True)
finally:
    shutil.copy2(BACKUP, MODULE)
    BACKUP.unlink(missing_ok=True)
    print("\nrestored the committed module", flush=True)

comp = sum(1 for r in results if r["compiled"])
deliv = sum(1 for r in results if r["delivered"])
print(f"\n=== compiled {comp}/{len(results)}   delivered {deliv}/{len(results)} ===")
needed_repair = [r for r in results if r["repair_rounds"]]
print(f"needed at least one repair: {len(needed_repair)}")
for r in needed_repair:
    print(
        f"  attempt {r['attempt']}: rounds={r['repair_rounds']} "
        f"line_quoted={r['line_was_quoted']} "
        f"errors_changed={r['errors_changed_between_rounds']} "
        f"compiled={r['compiled']}"
    )
OUT.mkdir(parents=True, exist_ok=True)
(OUT / "codegen_reliability_run2.json").write_text(
    json.dumps(results, indent=2), encoding="utf-8"
)
print("wrote artifacts/measure/codegen_reliability_run2.json")
