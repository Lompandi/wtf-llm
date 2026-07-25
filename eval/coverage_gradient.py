"""Measure the coverage gradient along a structural axis (CLAUDE.md CP7/CP10).

A coverage-guided fuzzer hill-climbs: it keeps an input because that input
covered something new. Where a branch needs N repetitions of the same operation
and repetitions 1..N-1 cover nothing new, there is **no gradient** -- the search
has no reason to prefer 4 repetitions over 3, so it never accumulates its way to
N. Reasoning over the code is the only way across.

This measures exactly that: coverage as a function of how many times one command
is repeated in a single test-case.

Measured on tlv_server's ProcessPacket, with Allocate as the repeated command:

    1 allocation  -> 22 blocks
    2             -> 23   (+1)
    3             -> 23   (+0)
    4             -> 23   (+0)
    5             -> 23   (+0)   <-- the out-of-bounds write happens HERE
    6             -> 30   (+7)
    7..11         -> 30   (+0)

Two conclusions, both load-bearing for the writeup:

* The gap from 3 to 6 is three consecutive zero-reward steps. A coverage-guided
  mutator cannot climb it, and measurement agrees: after ~330,000 executions from
  a poor seed, the retained corpus topped out at exactly 4 allocations -- the
  table's capacity, one short of the out-of-bounds write.
* The out-of-bounds write itself is **invisible to coverage**. It occurs at 5
  allocations and covers nothing new; only the *subsequent free* of the clobbered
  pointer, at 6, shows up. This is CLAUDE.md section 2's limitation made concrete:
  a binary-only oracle sees observable faults, and here even the coverage signal
  that would draw a fuzzer toward the corruption is absent.

**NO LLM HERE.** This is measurement.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from engine_bridge.plateau import BlockGraph, parse_cov_traces  # noqa: E402
from llm.sidecar import build_config  # noqa: E402

__all__ = ["measure_gradient"]


def _repeat_command(command: int, count: int, body_size: int = 4) -> bytes:
    """One test-case repeating ``command`` ``count`` times, with distinct ids."""
    return json.dumps(
        {
            "Packets": [
                {
                    "Id": i + 1,
                    "Command": command,
                    "BodySize": body_size,
                    "Body": [0xAA, 0xBB, 0xCC, i & 0xFF][:body_size],
                }
                for i in range(count)
            ]
        }
    ).encode()


def measure_gradient(
    *,
    target_dir: Path,
    module: str,
    a1: Path,
    command: int = 0,
    counts: tuple[int, ...] = tuple(range(1, 12)),
) -> dict:
    """Coverage as a function of repetition count. One wtf run per count.

    Separate runs, not one folder, because a single ``wtf run`` over a directory
    unions the coverage of everything in it -- which would report the maximum and
    hide the shape, and the shape is the whole point.
    """
    cfg = build_config(target_dir=target_dir, module=module, a1=a1)
    graph = BlockGraph.from_export(cfg.a3_export)
    known = set(graph.blocks)

    env = dict(os.environ)
    parts = (p.strip().strip('"') for p in env.get("PATH", "").split(os.pathsep))
    env["PATH"] = os.pathsep.join(p for p in parts if p)
    if cfg.symbol_paths:
        env["_NT_SYMBOL_PATH"] = ";".join(cfg.symbol_paths)

    stage = cfg.artifacts_dir / "gradient" / "inputs"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)

    steps: list[dict] = []
    previous: set[int] | None = None

    for count in counts:
        path = stage / f"repeat{count:03d}"
        path.write_bytes(_repeat_command(command, count))

        trace_dir = cfg.artifacts_dir / "gradient" / f"traces{count:03d}"
        if trace_dir.exists():
            shutil.rmtree(trace_dir)
        trace_dir.mkdir(parents=True)

        completed = subprocess.run(
            [
                str(cfg.wtf_exe), "run",
                "--name", cfg.module,
                "--state", str((target_dir / "state").resolve()),
                f"--backend={cfg.backend}",
                "--input", str(path.resolve()),
                "--limit", "200000000",
                "--trace-type=cov",
                f"--trace-path={trace_dir.resolve()}",
            ],
            cwd=target_dir, env=env, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=3600,
        )
        if not list(trace_dir.glob("*.trace")):
            raise RuntimeError(
                f"no traces at count={count} (rc={completed.returncode}): "
                f"{(completed.stdout or '')[-300:]}"
            )

        covered = parse_cov_traces(trace_dir, cfg.space) & known
        # None, not 0, for the first count: it has no predecessor, so calling it
        # a zero-reward step would inflate the flat region by one.
        gained = sorted(covered - previous) if previous is not None else None
        steps.append(
            {
                "repetitions": count,
                "blocks": len(covered),
                "new_vs_previous": None if gained is None else len(gained),
                "new_block_static_addrs": [
                    graph.blocks[r]["static_addr"] for r in (gained or [])
                ],
                "new_block_functions": sorted(
                    {graph.function_of(r) or "?" for r in (gained or [])}
                ),
            }
        )
        previous = covered

    flat = [s["repetitions"] for s in steps if s["new_vs_previous"] == 0]
    return {
        "module": module,
        "command": command,
        "steps": steps,
        "zero_reward_repetition_counts": flat,
        # The number that matters. A trailing flat region past the last reward is
        # uninteresting -- the search has already been paid by then. What a
        # coverage-guided mutator has to cross blind is the run of zero-reward
        # steps immediately BEFORE a reward, so that is reported separately.
        "gap_before_largest_gain": _gap_before_largest_gain(steps),
        "longest_flat_region": _longest_run(flat),
    }


def _gap_before_largest_gain(steps: list[dict]) -> dict:
    """Width of the zero-reward run immediately preceding the biggest reward."""
    rewards = [
        (i, s) for i, s in enumerate(steps) if (s["new_vs_previous"] or 0) > 0
    ]
    if not rewards:
        return {"width": 0, "reward_at_repetitions": None, "blocks_gained": 0}

    index, step = max(rewards, key=lambda pair: pair[1]["new_vs_previous"])
    width = 0
    for previous in reversed(steps[:index]):
        if previous["new_vs_previous"] != 0:
            break
        width += 1
    return {
        "width": width,
        "reward_at_repetitions": step["repetitions"],
        "blocks_gained": step["new_vs_previous"],
    }


def _longest_run(values: list[int]) -> int:
    """Longest run of consecutive integers -- the width of a flat region."""
    best = run = 0
    previous: int | None = None
    for value in values:
        run = run + 1 if previous is not None and value == previous + 1 else 1
        best = max(best, run)
        previous = value
    return best


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target-dir", type=Path, required=True)
    ap.add_argument("--module", default="snapfuzz")
    ap.add_argument("--a1", type=Path, default=REPO_ROOT / "artifacts/a1_snapshot.json")
    ap.add_argument("--command", type=int, default=0)
    ap.add_argument("--max-repetitions", type=int, default=11)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)

    result = measure_gradient(
        target_dir=args.target_dir,
        module=args.module,
        a1=args.a1,
        command=args.command,
        counts=tuple(range(1, args.max_repetitions + 1)),
    )

    for step in result["steps"]:
        addrs = ", ".join(f"{a:#x}" for a in step["new_block_static_addrs"][:8])
        gain = step["new_vs_previous"]
        marker = "  --" if gain is None else f"  +{gain}"
        print(
            f"  {step['repetitions']:>3} x command {args.command}: "
            f"{step['blocks']:>3} blocks{marker}"
            + (f"  -> {addrs}" if addrs else "")
        )

    gap = result["gap_before_largest_gain"]
    print(
        f"\nlargest reward: +{gap['blocks_gained']} blocks at "
        f"{gap['reward_at_repetitions']} repetitions, preceded by "
        f"{gap['width']} zero-reward step(s)."
    )
    if gap["width"]:
        print(
            "  A coverage-guided mutator has no gradient across those steps: "
            "nothing prefers a longer sequence until the reward appears, so it "
            "cannot accumulate its way there."
        )

    out = args.out or REPO_ROOT / "artifacts" / "coverage_gradient.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
