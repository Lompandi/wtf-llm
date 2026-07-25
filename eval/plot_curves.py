"""Plot the coverage growth curves from a baseline comparison (CP10, GATE 10).

One figure, one line per arm, coverage against wall clock. GATE 10 asks for the
curves plotted, and a curve is the metric that a single end-of-run number hides:
two arms can finish at the same coverage having got there very differently.

The y axis is the master's **aggregate** coverage, which on bochscpu is
full-system and therefore large (roughly 12,700 on tlv_server) and dominated by
system code. Absolute values are not comparable to the module-only block counts
elsewhere in this project; what is comparable is the shape and the *relative*
position of the arms, which is what this figure is for. That caveat is drawn onto
the figure rather than left in a docstring nobody reads.

**NO LLM IN THIS MODULE.**
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

__all__ = ["plot_comparison"]

# Baselines dashed, our arms solid, ablations dotted: readable in greyscale, which
# a printed report will be.
_STYLE = {
    "baseline-libfuzzer": ("--", "tab:gray"),
    "baseline-honggfuzz": ("--", "tab:brown"),
    "llm-guided": ("-", "tab:blue"),
    "ablation-no-seedgen": (":", "tab:orange"),
    "ablation-no-pseudoc": (":", "tab:green"),
}


def plot_comparison(comparison: Path, out_path: Path) -> Path:
    import matplotlib

    matplotlib.use("Agg")  # headless: there is no display on this host
    import matplotlib.pyplot as plt

    data = json.loads(comparison.read_text(encoding="utf-8"))
    arms = data["arms"]
    if not arms:
        raise SystemExit(f"{comparison} lists no arms")

    figure, (top, bottom) = plt.subplots(
        2, 1, figsize=(9, 8), gridspec_kw={"height_ratios": [3, 2]}
    )

    for arm in arms:
        curve = arm["coverage_curve"]
        if not curve:
            continue
        style, colour = _STYLE.get(arm["arm"], ("-", None))
        top.plot(
            [point[0] for point in curve],
            [point[1] for point in curve],
            style,
            color=colour,
            label=arm["arm"],
            linewidth=1.8,
        )

    top.set_xlabel("wall clock (s)")
    top.set_ylabel("aggregate coverage (full-system, bochscpu)")
    top.set_title(
        f"Coverage growth -- {data['budget_minutes']:.0f} min budget, "
        f"{data['workers']} workers, identical single poor seed"
    )
    top.legend(loc="lower right", fontsize=8)
    top.grid(alpha=0.3)

    # Distinct crash buckets per arm -- the count that means "bugs", as opposed to
    # crash files, which measure wtf's filename collapsing (D-024).
    names = [arm["arm"] for arm in arms]
    buckets = [arm["distinct_buckets"] or 0 for arm in arms]
    colours = [_STYLE.get(name, ("-", "tab:blue"))[1] for name in names]
    bars = bottom.bar(range(len(names)), buckets, color=colours)
    bottom.set_xticks(range(len(names)))
    bottom.set_xticklabels(names, rotation=20, ha="right", fontsize=8)
    bottom.set_ylabel("distinct crash buckets")
    bottom.set_title("Unique crashes after dedup (not crash files)")
    bottom.grid(alpha=0.3, axis="y")
    for bar, arm in zip(bars, arms):
        bottom.annotate(
            f"{arm['distinct_buckets']}\n({arm['crash_files']} files)",
            (bar.get_x() + bar.get_width() / 2, bar.get_height()),
            ha="center",
            va="bottom",
            fontsize=7,
        )

    figure.text(
        0.01,
        0.005,
        "Aggregate coverage is full-system on bochscpu and dominated by system "
        "code; compare arms to each other, not to module-only block counts "
        "elsewhere in this project. Lines end at each arm's last FLUSHED stat "
        "line, not where its run ended -- the master block-buffers its output "
        "(D-033), so a slower arm emits fewer stat lines and its line stops "
        "earlier. Every arm ran the full budget.",
        fontsize=7,
        style="italic",
        wrap=True,
    )
    figure.tight_layout(rect=(0, 0.03, 1, 1))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(out_path, dpi=150)
    plt.close(figure)
    return out_path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--comparison",
        type=Path,
        default=REPO_ROOT / "artifacts" / "runs" / "gate10" / "comparison.json",
    )
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)

    out = args.out or args.comparison.parent / "coverage_curves.png"
    path = plot_comparison(args.comparison, out)
    print(f"wrote {path} ({path.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
