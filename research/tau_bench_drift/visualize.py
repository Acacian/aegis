#!/usr/bin/env python3
"""Visualize drift_results.json into 4 publication-ready charts.

Outputs:
    docs/assets/research/drift-histogram.png
    docs/assets/research/drift-by-model.png
    docs/assets/research/drift-by-trajectory-length.png
    docs/assets/research/drift-cumulative.png

Run after analyze.py.

Usage:
    python research/tau_bench_drift/visualize.py \
        --input .cache/analysis/drift_results.json \
        --out-dir docs/assets/research
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from statistics import mean

import matplotlib.pyplot as plt
import matplotlib.ticker as mtick

# Aegis brand-ish palette (kept simple, no external dependency)
COLORS = {
    "gpt-4o:retail": "#1f77b4",
    "gpt-4o:airline": "#aec7e8",
    "sonnet-35-new:retail": "#d62728",
    "sonnet-35-new:airline": "#ff9896",
}
ACCENT = "#2c3e50"
GRID = "#ecf0f1"


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def fig_histogram(report: dict, out: Path) -> None:
    """Histogram of entropy delta across all scored trajectories."""
    deltas = [m["entropy_delta"] for m in report["per_trajectory"]]
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.hist(
        deltas,
        bins=30,
        color="#3498db",
        edgecolor="white",
        linewidth=0.6,
    )
    ax.axvline(0.0, color=ACCENT, linewidth=1.0, linestyle="--", label="no drift")
    ax.axvline(
        0.3,
        color="#e74c3c",
        linewidth=1.0,
        linestyle="--",
        label="collapse threshold (delta>=0.3 nats)",
    )
    ax.set_title(
        f"Tool distribution entropy drift across {len(deltas):,} tau-bench trajectories",
        fontsize=12,
        color=ACCENT,
    )
    ax.set_xlabel("Entropy delta (early window - late window, nats)")
    ax.set_ylabel("Trajectory count")
    ax.legend(frameon=False)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", color=GRID, linewidth=0.7)
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {out}")


def fig_by_model(report: dict, out: Path) -> None:
    """Bar chart: % of trajectories collapsed (delta>=0.3) by model:domain."""
    groups = report["by_group"]
    labels = sorted(groups.keys())
    pct = [groups[k]["collapsed_30pct"] for k in labels]
    n = [groups[k]["total_trajectories"] for k in labels]

    fig, ax = plt.subplots(figsize=(8, 4.5))
    bars = ax.bar(
        labels,
        pct,
        color=[COLORS.get(k, "#7f8c8d") for k in labels],
        edgecolor="white",
        linewidth=0.8,
    )
    for bar, count, value in zip(bars, n, pct, strict=False):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            value + 1.0,
            f"{value:.1f}%\n(n={count})",
            ha="center",
            fontsize=9,
            color=ACCENT,
        )
    ax.set_ylim(0, max(pct) * 1.25)
    ax.set_title(
        "Trajectories with tool distribution collapse (delta entropy >= 0.3 nats)",
        fontsize=12,
        color=ACCENT,
    )
    ax.set_ylabel("% of trajectories")
    ax.yaxis.set_major_formatter(mtick.PercentFormatter(decimals=0))
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(axis="y", color=GRID, linewidth=0.7)
    ax.set_axisbelow(True)
    plt.setp(ax.get_xticklabels(), rotation=10, ha="right")
    fig.tight_layout()
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {out}")


def fig_by_length(report: dict, out: Path) -> None:
    """Mean entropy delta vs trajectory length bucket."""
    buckets: dict[int, list[float]] = {}
    for m in report["per_trajectory"]:
        # Bucket length to nearest 2
        length = m["total_calls"]
        b = (length // 2) * 2
        buckets.setdefault(b, []).append(m["entropy_delta"])

    keys = sorted(buckets.keys())
    means = [mean(buckets[k]) for k in keys]
    counts = [len(buckets[k]) for k in keys]

    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.plot(keys, means, marker="o", color="#16a085", linewidth=2.0, markersize=6)
    ax2 = ax.twinx()
    ax2.bar(keys, counts, color="#bdc3c7", alpha=0.35, width=1.6, edgecolor="white")
    ax2.set_ylabel("Trajectory count", color="#7f8c8d")
    ax2.tick_params(axis="y", labelcolor="#7f8c8d")

    ax.axhline(0.0, color=ACCENT, linewidth=0.8, linestyle="--")
    ax.set_xlabel("Trajectory length (tool calls, bucketed by 2)")
    ax.set_ylabel("Mean entropy delta (nats)", color="#16a085")
    ax.tick_params(axis="y", labelcolor="#16a085")
    ax.set_title(
        "Tool drift magnitude grows with trajectory length",
        fontsize=12,
        color=ACCENT,
    )
    ax.spines["top"].set_visible(False)
    ax2.spines["top"].set_visible(False)
    fig.tight_layout()
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {out}")


def fig_cumulative(report: dict, out: Path) -> None:
    """Cumulative distribution of entropy delta - how many fall above threshold."""
    fig, ax = plt.subplots(figsize=(8, 4.5))
    for grp, color in COLORS.items():
        deltas = [
            m["entropy_delta"] for m in report["per_trajectory"] if m["key"].startswith(grp + ":")
        ]
        if not deltas:
            continue
        deltas_sorted = sorted(deltas, reverse=True)
        n = len(deltas_sorted)
        x = deltas_sorted
        y = [(i + 1) / n * 100 for i in range(n)]
        ax.plot(x, y, label=f"{grp} (n={n})", color=color, linewidth=2.0)

    ax.axvline(0.3, color="#e74c3c", linewidth=1.0, linestyle="--", label="collapse threshold")
    ax.set_xlabel("Entropy delta (nats)")
    ax.set_ylabel("% of trajectories with delta >= x")
    ax.yaxis.set_major_formatter(mtick.PercentFormatter(decimals=0))
    ax.set_title(
        "Reverse cumulative distribution by model:domain",
        fontsize=12,
        color=ACCENT,
    )
    ax.legend(frameon=False, loc="upper right", fontsize=9)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(color=GRID, linewidth=0.7)
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  wrote {out}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        type=Path,
        default=Path(".cache/analysis/drift_results.json"),
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("docs/assets/research"),
    )
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    report = load(args.input)

    print(f"== Generating 4 figures from {args.input} ==")
    fig_histogram(report, args.out_dir / "drift-histogram.png")
    fig_by_model(report, args.out_dir / "drift-by-model.png")
    fig_by_length(report, args.out_dir / "drift-by-trajectory-length.png")
    fig_cumulative(report, args.out_dir / "drift-cumulative.png")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
