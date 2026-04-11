#!/usr/bin/env python3
"""Render justification-gap visualization charts from measure_gap.py output.

Reads .cache/analysis/justification_gap_results.json and writes four PNGs
into docs/assets/research/ for the research post to reference.

Charts:
1. jg-histogram.png        -- global gap distribution, 20 bins
2. jg-radar.png            -- 6D mean impact radar, one polygon per group
3. jg-verdict-by-group.png -- stacked verdict shares by model:domain
4. jg-top-tools.png        -- top 12 tools by mean gap (horizontal bar)

Usage:
    python research/justification_gap_tau_bench/visualize.py \\
        --input .cache/analysis/justification_gap_results.json \\
        --out-dir docs/assets/research
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError as e:  # pragma: no cover
    raise SystemExit(
        "matplotlib is required for visualize.py. Install with: pip install matplotlib"
    ) from e


_GROUP_ORDER = [
    "gpt-4o:retail",
    "gpt-4o:airline",
    "sonnet-35-new:retail",
    "sonnet-35-new:airline",
]

_GROUP_COLORS = {
    "gpt-4o:retail": "#1f77b4",
    "gpt-4o:airline": "#2ca02c",
    "sonnet-35-new:retail": "#d62728",
    "sonnet-35-new:airline": "#ff7f0e",
}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render justification-gap charts from measure_gap results"
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=REPO_ROOT / ".cache/analysis/justification_gap_results.json",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=REPO_ROOT / "docs/assets/research",
    )
    return parser.parse_args()


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def plot_histogram(results: dict[str, Any], out: Path) -> None:
    hist = results["global"]["gap_histogram"]
    lo = [b["lo"] for b in hist]
    counts = [b["count"] for b in hist]
    width = hist[0]["hi"] - hist[0]["lo"] if hist else 0.05

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(lo, counts, width=width * 0.95, color="#3f51b5", align="edge")
    ax.axvline(0.15, color="#2ca02c", linestyle="--", linewidth=1, label="approve ≤ 0.15")
    ax.axvline(0.40, color="#d62728", linestyle="--", linewidth=1, label="block > 0.40")
    ax.set_xlabel("asymmetric justification gap (silent baseline)")
    ax.set_ylabel("tool calls")
    title_n = results["dataset"]["matched_rows"]
    ax.set_title(f"Justification gap distribution across {title_n:,} tau-bench calls")
    ax.set_xlim(0.0, 1.0)
    ax.legend(loc="upper right")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)


def plot_radar(results: dict[str, Any], out: Path) -> None:
    dims = results["dimensions"]
    groups = results["groups"]

    angles = [(i / len(dims)) * 2 * math.pi for i in range(len(dims))]
    angles += [angles[0]]

    fig = plt.figure(figsize=(8, 8))
    ax = fig.add_subplot(111, polar=True)

    max_val = 0.0
    for group in _GROUP_ORDER:
        if group not in groups:
            continue
        dim_stats = groups[group]["dim_distribution"]
        means = [dim_stats[d]["mean"] for d in dims]
        max_val = max(max_val, max(means))
        values = means + [means[0]]
        ax.plot(
            angles,
            values,
            linewidth=2,
            color=_GROUP_COLORS[group],
            label=group,
        )
        ax.fill(angles, values, alpha=0.10, color=_GROUP_COLORS[group])

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels([d.replace("_", "\n") for d in dims], fontsize=10)
    upper = max(0.1, round(max_val * 1.25, 2))
    ax.set_ylim(0, upper)
    ax.set_yticks([upper / 4, upper / 2, upper * 3 / 4, upper])
    ax.set_yticklabels(
        [f"{v:.2f}" for v in (upper / 4, upper / 2, upper * 3 / 4, upper)],
        fontsize=8,
    )
    ax.set_title(
        "Mean 6D assessed impact per group (tau-bench)",
        pad=22,
        fontsize=13,
    )
    ax.legend(loc="upper right", bbox_to_anchor=(1.25, 1.10), fontsize=9)
    fig.tight_layout()
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)


def plot_verdict_by_group(results: dict[str, Any], out: Path) -> None:
    groups = results["groups"]
    labels: list[str] = []
    approve: list[float] = []
    escalate: list[float] = []
    block: list[float] = []

    for group in _GROUP_ORDER:
        if group not in groups:
            continue
        share = groups[group]["verdict_shares"]
        labels.append(group)
        approve.append(share.get("approve", 0.0) * 100)
        escalate.append(share.get("escalate", 0.0) * 100)
        block.append(share.get("block", 0.0) * 100)

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.barh(labels, approve, color="#2ca02c", label="approve")
    ax.barh(
        labels,
        escalate,
        left=approve,
        color="#ff7f0e",
        label="escalate",
    )
    if any(b > 0 for b in block):
        bottom = [a + e for a, e in zip(approve, escalate, strict=False)]
        ax.barh(labels, block, left=bottom, color="#d62728", label="block")

    for i, (a, e) in enumerate(zip(approve, escalate, strict=False)):
        ax.text(a / 2, i, f"{a:.1f}%", va="center", ha="center", color="white", fontsize=9)
        if e > 3:
            ax.text(a + e / 2, i, f"{e:.1f}%", va="center", ha="center", color="white", fontsize=9)

    ax.set_xlabel("share of tool calls (%)")
    ax.set_xlim(0, 100)
    ax.set_title("Aegis verdict distribution by model:domain")
    ax.legend(loc="lower right")
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)


def plot_top_tools(results: dict[str, Any], out: Path) -> None:
    ranking = [t for t in results["top_tools_by_mean_gap"] if t["mean_gap"] > 0.0][:12]
    ranking.reverse()  # so largest appears at top in horizontal bar
    names = [t["tool_name"] for t in ranking]
    gaps = [t["mean_gap"] for t in ranking]
    calls = [t["calls"] for t in ranking]

    colors = ["#d62728" if g > 0.40 else "#ff7f0e" if g > 0.15 else "#2ca02c" for g in gaps]

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.barh(names, gaps, color=colors)
    for i, (g, c) in enumerate(zip(gaps, calls, strict=False)):
        ax.text(g + 0.005, i, f" n={c}", va="center", fontsize=9)
    ax.axvline(0.15, color="#2ca02c", linestyle="--", linewidth=1, alpha=0.5)
    ax.axvline(0.40, color="#d62728", linestyle="--", linewidth=1, alpha=0.5)
    ax.set_xlabel("mean asymmetric gap")
    ax.set_title("Top tau-bench tools by mean assessed gap (silent baseline)")
    ax.set_xlim(0, max(gaps) * 1.25)
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)


def main() -> None:
    args = _parse_args()
    if not args.input.exists():
        raise SystemExit(f"Input not found: {args.input}. Run measure_gap.py first.")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    results = _load(args.input)

    plot_histogram(results, args.out_dir / "jg-histogram.png")
    plot_radar(results, args.out_dir / "jg-radar.png")
    plot_verdict_by_group(results, args.out_dir / "jg-verdict-by-group.png")
    plot_top_tools(results, args.out_dir / "jg-top-tools.png")

    print(f"Wrote 4 charts to {args.out_dir}")


if __name__ == "__main__":
    main()
