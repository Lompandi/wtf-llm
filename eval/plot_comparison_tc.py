"""Print-quality figures for the CP10 comparison, labelled in Traditional Chinese.

Companion to `eval/plot_curves.py`, which draws one chart for one comparison file. This
draws the three the writeup needs, from BOTH targets, with the same encoding decisions the
interactive figure makes -- because a report figure and a browser figure that disagree
about what a colour means is worse than having only one of them.

The decisions, and why each is not a style preference:

* **Two series, not five.** The comparison is group-level -- our mutator family against
  wtf's built-ins -- so colour carries the GROUP and arm identity comes from direct labels.
  The hexes are the validated pair (blue #2a78d6 / orange #eb6834, every gate passing in
  both light and dark).
* **An arm that did not run is a dashed empty outline captioned "沒跑起來", never a
  zero-height bar.** A zero reads as "honggfuzz found nothing", which is a claim about the
  mutator; the truth is that wtf's master died with 0xC0000409. `ArmDidNotRun` exists so
  those two cannot share a representation, and a chart can undo that faster than a table.
* **No dual axis.** Coverage and executions are separate figures with one scale each.
  Executions span two orders of magnitude, so that one is log and says so.

Writes PNG at 300 dpi for print and SVG for the paper, into `docs/figures/`.

Run: ``python -m eval.plot_comparison_tc``
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# The validated categorical pair, light mode. A report figure is printed on white, so the
# light steps are the correct ones -- the dark steps exist for the dark surface and would
# be wrong here.
LLM = "#2a78d6"
BASE = "#eb6834"
INK = "#101318"
INK2 = "#4a5260"
INK3 = "#7b8494"
RULE = "#e2e6ec"
RULE_STRONG = "#cdd3dd"

NAMES = {
    "baseline-libfuzzer": "libfuzzer",
    "baseline-honggfuzz": "honggfuzz",
    "llm-guided": "llm-guided",
    "ablation-no-seedgen": "no-seedgen",
    "ablation-no-pseudoc": "no-pseudoc",
}
ORDER = [
    "baseline-libfuzzer",
    "baseline-honggfuzz",
    "llm-guided",
    "ablation-no-seedgen",
    "ablation-no-pseudoc",
]


def is_base(arm: str) -> bool:
    return arm.startswith("baseline")


def hue(arm: str) -> str:
    return BASE if is_base(arm) else LLM


def _setup():
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    # A CJK family FIRST, or every Chinese label renders as a tofu box -- which looks like
    # a broken figure rather than a font gap and would be shipped without noticing.
    plt.rcParams.update({
        "font.family": ["Microsoft JhengHei", "Noto Sans TC", "DejaVu Sans"],
        "axes.unicode_minus": False,
        "figure.facecolor": "white",
        "axes.facecolor": "white",
        "axes.edgecolor": RULE_STRONG,
        "axes.labelcolor": INK2,
        "text.color": INK,
        "xtick.color": INK3,
        "ytick.color": INK3,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "axes.titlesize": 12,
        "axes.titleweight": "bold",
        "axes.spines.top": False,
        "axes.spines.right": False,
        "savefig.bbox": "tight",
        "savefig.facecolor": "white",
    })
    return plt


def _save(fig, out_dir: Path, stem: str) -> list[Path]:
    written = []
    for ext, kw in (("png", {"dpi": 300}), ("svg", {})):
        path = out_dir / f"{stem}.{ext}"
        fig.savefig(path, **kw)
        written.append(path)
    return written


def coverage_figure(data: dict, out_dir: Path, plt) -> list[Path]:
    """Coverage over time on tlv_server -- the panel that carries the result."""
    arms = data["tlv_server"]
    fig, ax = plt.subplots(figsize=(8.2, 3.5))

    ends = []
    for arm in ORDER:
        pts = [(t, v) for t, v in arms[arm]["curve"] if v > 0]
        if not pts:
            continue
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        ax.plot(xs, ys, color=hue(arm), linewidth=2, solid_capstyle="round", zorder=3)
        ax.plot(xs[-1], ys[-1], "o", color=hue(arm), markersize=5,
                markeredgecolor="white", markeredgewidth=1.5, zorder=4)
        ends.append((ys[-1], xs[-1], arm))

    # Stack the end-labels: three LLM plateaus land within 30 events of each other, so
    # placing each at its own y overlaps them into an unreadable smear.
    ends.sort(reverse=True)
    span = max(e[0] for e in ends) * 1.12
    gap = span * 0.075
    prev = None
    for value, x_at, arm in ends:
        y = value if prev is None else min(value, prev - gap)
        prev = y
        ax.annotate(f"{NAMES[arm]}  {value:,}", xy=(x_at, value),
                    xytext=(max(e[1] for e in ends) * 1.03, y),
                    color=hue(arm), fontsize=9, fontweight="bold",
                    va="center", annotation_clip=False)

    ax.set_ylim(0, span)
    ax.set_xlim(0, max(e[1] for e in ends) * 1.02)
    ax.set_ylabel("unique coverage event 數", fontsize=10)
    ax.set_xlabel("秒", fontsize=10)
    ax.set_title("覆蓋率隨時間變化 — tlv_server", loc="left", pad=12)
    ax.yaxis.grid(True, color=RULE, linewidth=1)
    ax.set_axisbelow(True)
    ax.yaxis.set_major_formatter(lambda v, _: "0" if v == 0 else f"{v/1000:.0f}k")

    handles = [
        plt.Line2D([], [], color=LLM, lw=2, label="我們的 mutator + sidecar，及兩個 ablation"),
        plt.Line2D([], [], color=BASE, lw=2, label="wtf 內建 mutator"),
    ]
    ax.legend(handles=handles, loc="lower right", frameon=False, fontsize=9,
              labelcolor=INK2, borderaxespad=0.6)

    # BELOW the xlabel, not level with it. At -0.10 in axes coordinates this note ran
    # straight through the tick labels and the "秒" xlabel -- rendered, unreadable, and
    # invisible in the console output. The validator checks colour, not layout; the only
    # way to catch this was to open the PNG and look at it.
    fig.text(0.0, -0.30,
             "每條線在該臂的 master log 停止 flush 處結束（D-033），不是在它停止 fuzzing 處；"
             "五臂都跑滿五分鐘。",
             fontsize=8, color=INK3, ha="left", transform=ax.transAxes)
    return _save(fig, out_dir, "cp10-coverage")


def buckets_figure(data: dict, out_dir: Path, plt) -> list[Path]:
    """Distinct crash buckets, both targets side by side."""
    from matplotlib.patches import Rectangle

    fig, axes = plt.subplots(1, 2, figsize=(8.2, 3.1), sharey=True)
    for ax, target in zip(axes, ("tlv_server", "fuzzing-base-test")):
        arms = data[target]
        for i, arm in enumerate(ORDER):
            d = arms.get(arm)
            if not d or not d["ran"]:
                # Absent, not zero.
                ax.add_patch(Rectangle((i - 0.34, 0), 0.68, 1, fill=False,
                                       edgecolor=RULE_STRONG, linewidth=1.4,
                                       linestyle=(0, (3, 3)), zorder=3))
                ax.text(i, 1.15, "沒跑起來", ha="center", va="bottom",
                        fontsize=8, color=INK3)
                continue
            ax.bar(i, d["buckets"], width=0.68, color=hue(arm), zorder=3)
            ax.text(i, d["buckets"] + 0.12, str(d["buckets"]), ha="center",
                    va="bottom", fontsize=10, fontweight="bold", color=INK)

        ax.set_xticks(range(len(ORDER)))
        ax.set_xticklabels([NAMES[a] for a in ORDER], rotation=32, ha="right", fontsize=8.5)
        ax.set_title(target, loc="left", fontsize=10.5, pad=8)
        ax.set_ylim(0, 5)
        ax.yaxis.grid(True, color=RULE, linewidth=1)
        ax.set_axisbelow(True)
        ax.spines["left"].set_visible(False)
        ax.tick_params(axis="y", length=0)

    axes[0].set_ylabel("不同的 crash bucket 數", fontsize=10)
    fig.suptitle("不同的 crash bucket 數（以靜態位址的 stack hash 去重）",
                 x=0.005, ha="left", fontsize=12, fontweight="bold", y=1.04)
    fig.text(0.005, -0.16, "虛線框 = 該臂沒有產出數據，不是 0",
             fontsize=8, color=INK3, ha="left")
    return _save(fig, out_dir, "cp10-buckets")


def execs_figure(data: dict, out_dir: Path, plt) -> list[Path]:
    """Executions on tlv_server, log scale -- the cost side."""
    arms = data["tlv_server"]
    rows = [a for a in ORDER if arms.get(a, {}).get("execs")]
    fig, ax = plt.subplots(figsize=(8.2, 2.6))

    ys = range(len(rows))
    ax.barh(list(ys), [arms[a]["execs"] for a in rows], height=0.6,
            color=[hue(a) for a in rows], zorder=3)
    for i, a in enumerate(rows):
        n = arms[a]["execs"]
        ax.text(n * 1.15, i, f"{n:,}", va="center", fontsize=9,
                fontweight="bold", color=INK)

    ax.set_yticks(list(ys))
    ax.set_yticklabels([NAMES[a] for a in rows], fontsize=9, fontweight="bold")
    for tick, a in zip(ax.get_yticklabels(), rows):
        tick.set_color(hue(a))
    ax.invert_yaxis()
    ax.set_xscale("log")
    ax.set_xlim(1e4, 3e7)
    ax.set_xlabel("執行的 test-case 數（log 尺度）", fontsize=10)
    ax.set_title("為此執行了多少 test-case — tlv_server", loc="left", pad=12)
    ax.xaxis.grid(True, color=RULE, linewidth=1)
    ax.set_axisbelow(True)
    ax.spines["left"].set_visible(False)
    ax.tick_params(axis="y", length=0)

    per = ", ".join(
        f"{NAMES[a]} {round(arms[a]['execs']/max(arms[a]['buckets'],1)):,}"
        for a in rows
    )
    fig.text(0.0, -0.34, "每個 bucket 花費的執行次數： " + per,
             fontsize=8, color=INK3, ha="left", transform=ax.transAxes)
    return _save(fig, out_dir, "cp10-executions")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data", type=Path,
                    default=REPO_ROOT / "artifacts" / "measure" / "comparison_data.json")
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "docs" / "figures")
    args = ap.parse_args(argv)

    if not args.data.is_file():
        raise SystemExit(
            f"{args.data} is absent. It is written by the comparison; run "
            f"`python -m eval.baseline` first, or point --data at a comparison_data.json."
        )
    data = json.loads(args.data.read_text(encoding="utf-8"))
    args.out.mkdir(parents=True, exist_ok=True)

    plt = _setup()
    written: list[Path] = []
    written += coverage_figure(data, args.out, plt)
    written += buckets_figure(data, args.out, plt)
    written += execs_figure(data, args.out, plt)

    for path in written:
        print(f"wrote {path.relative_to(REPO_ROOT)} ({path.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
