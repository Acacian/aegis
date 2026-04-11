#!/usr/bin/env python3
"""Analyze tool distribution drift across tau-bench trajectories.

Loads a flattened tau-bench JSONL, groups tool calls into trajectories by
model/domain/task ID, and measures tool distribution entropy drift within each
trajectory (early window vs late window).

Output: JSON report with per-trajectory metrics plus aggregate statistics
(overall and per model:domain group).

Usage:
    python research/tau_bench_drift/analyze.py \
        --input .cache/traces/tau_bench_all.jsonl \
        --output .cache/analysis/drift_results.json \
        --window-size 4 \
        --min-calls 8
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean, median, stdev
from typing import Any

_TRAJ_RE = re.compile(r"^(gpt-4o|sonnet-35-new)-(retail|airline)-(t\d+)-s(\d+)-c(\d+)")


def entropy(counts: Counter[str]) -> float:
    """Shannon entropy of a tool-call distribution (natural log)."""
    total = sum(counts.values())
    if total == 0:
        return 0.0
    probs = [c / total for c in counts.values() if c > 0]
    return -sum(p * math.log(p) for p in probs)


def load_trajectories(path: Path) -> dict[str, list[dict[str, Any]]]:
    """Group tool calls by (model, domain, trajectory) key."""
    trajectories: dict[str, list[dict[str, Any]]] = defaultdict(list)
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            tid = str(row.get("id", ""))
            m = _TRAJ_RE.match(tid)
            if not m:
                continue
            model, domain, traj, step, call = m.groups()
            key = f"{model}:{domain}:{traj}"
            row["_step"] = int(step)
            row["_call"] = int(call)
            trajectories[key].append(row)

    # Sort each trajectory by (step, call) order.
    for k in trajectories:
        trajectories[k].sort(key=lambda r: (r["_step"], r["_call"]))

    return trajectories


def score_trajectory(calls: list[dict[str, Any]], window_size: int) -> dict[str, Any] | None:
    """Compute entropy drift metrics for a single trajectory.

    Returns None if the trajectory is too short for two non-overlapping windows.
    """
    if len(calls) < window_size * 2:
        return None

    early = [c.get("tool_name", "?") for c in calls[:window_size]]
    late = [c.get("tool_name", "?") for c in calls[-window_size:]]

    early_dist = Counter(early)
    late_dist = Counter(late)

    e_early = entropy(early_dist)
    e_late = entropy(late_dist)
    entropy_delta = e_early - e_late  # positive = collapsed

    # Tool diversity ratio
    unique_early = len(early_dist)
    unique_late = len(late_dist)
    diversity_ratio = unique_late / unique_early if unique_early else 0.0

    # Top-tool dominance
    top_early_share = max(early_dist.values()) / window_size
    top_late_share = max(late_dist.values()) / window_size
    dominance_delta = top_late_share - top_early_share  # positive = more concentrated

    # Entropy as % of max possible (log W) — normalized
    max_entropy = math.log(window_size) if window_size > 1 else 1.0
    e_early_norm = e_early / max_entropy
    e_late_norm = e_late / max_entropy

    return {
        "total_calls": len(calls),
        "window_size": window_size,
        "entropy_early": e_early,
        "entropy_late": e_late,
        "entropy_early_norm": e_early_norm,
        "entropy_late_norm": e_late_norm,
        "entropy_delta": entropy_delta,
        "unique_tools_early": unique_early,
        "unique_tools_late": unique_late,
        "diversity_ratio": diversity_ratio,
        "top_tool_share_early": top_early_share,
        "top_tool_share_late": top_late_share,
        "dominance_delta": dominance_delta,
        "early_tools": list(early_dist.keys()),
        "late_tools": list(late_dist.keys()),
    }


def aggregate(
    per_traj: list[tuple[str, dict[str, Any]]],
) -> dict[str, Any]:
    """Compute aggregate statistics across all scored trajectories."""
    if not per_traj:
        return {}
    deltas = [m["entropy_delta"] for _, m in per_traj]
    norms_early = [m["entropy_early_norm"] for _, m in per_traj]
    norms_late = [m["entropy_late_norm"] for _, m in per_traj]
    dominance = [m["dominance_delta"] for _, m in per_traj]

    collapsed_30 = sum(1 for d in deltas if d >= 0.3)
    collapsed_50 = sum(1 for d in deltas if d >= 0.5)
    collapsed_any = sum(1 for d in deltas if d > 0.0)

    return {
        "total_trajectories": len(per_traj),
        "entropy_delta_mean": mean(deltas),
        "entropy_delta_median": median(deltas),
        "entropy_delta_stdev": stdev(deltas) if len(deltas) > 1 else 0.0,
        "entropy_early_norm_mean": mean(norms_early),
        "entropy_late_norm_mean": mean(norms_late),
        "dominance_delta_mean": mean(dominance),
        "collapsed_any_pct": 100 * collapsed_any / len(deltas),
        "collapsed_30pct": 100 * collapsed_30 / len(deltas),
        "collapsed_50pct": 100 * collapsed_50 / len(deltas),
    }


def split_by_model_domain(
    per_traj: list[tuple[str, dict[str, Any]]],
) -> dict[str, list[tuple[str, dict[str, Any]]]]:
    """Split scored trajectories into groups by model:domain."""
    groups: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for key, m in per_traj:
        model, domain, _ = key.split(":")
        groups[f"{model}:{domain}"].append((key, m))
    return groups


def main() -> int:
    parser = argparse.ArgumentParser(description="Tool distribution drift analysis on tau-bench.")
    parser.add_argument(
        "--input",
        type=Path,
        default=Path(".cache/traces/tau_bench_all.jsonl"),
        help="Combined tau-bench JSONL file.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(".cache/analysis/drift_results.json"),
        help="Output JSON with per-trajectory + aggregate metrics.",
    )
    parser.add_argument(
        "--window-size",
        type=int,
        default=4,
        help="Window size in tool calls (default 4). Min trajectory length = 2 * W.",
    )
    parser.add_argument(
        "--min-calls",
        type=int,
        default=8,
        help="Minimum trajectory length to include (default 8 = 2 * window).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print top-drift trajectories.",
    )
    args = parser.parse_args()

    if not args.input.exists():
        print(f"error: {args.input} not found", file=sys.stderr)
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)

    print(f"== Loading trajectories from {args.input} ==")
    trajectories = load_trajectories(args.input)
    print(f"   loaded {len(trajectories)} trajectories")

    scored: list[tuple[str, dict[str, Any]]] = []
    skipped_short = 0
    for key, calls in trajectories.items():
        if len(calls) < args.min_calls:
            skipped_short += 1
            continue
        m = score_trajectory(calls, args.window_size)
        if m is None:
            skipped_short += 1
            continue
        scored.append((key, m))

    print(f"   scored: {len(scored)} (skipped_short: {skipped_short})")

    # Overall aggregate
    overall = aggregate(scored)
    # By model:domain
    by_group = {k: aggregate(g) for k, g in split_by_model_domain(scored).items()}

    report = {
        "input_file": str(args.input),
        "window_size": args.window_size,
        "min_calls": args.min_calls,
        "total_input_trajectories": len(trajectories),
        "scored_trajectories": len(scored),
        "overall": overall,
        "by_group": by_group,
        "per_trajectory": [{"key": k, **m} for k, m in scored],
    }

    args.output.write_text(json.dumps(report, indent=2))
    print(f"   wrote {args.output}")

    # Console summary
    print()
    print("== Overall drift summary ==")
    print(f"   total scored trajectories: {overall['total_trajectories']}")
    print(f"   entropy delta  mean: {overall['entropy_delta_mean']:+.3f}")
    print(f"                 median: {overall['entropy_delta_median']:+.3f}")
    print(f"                  stdev: {overall['entropy_delta_stdev']:.3f}")
    early_norm = overall["entropy_early_norm_mean"]
    late_norm = overall["entropy_late_norm_mean"]
    print(f"   entropy (norm) early->late: {early_norm:.3f} -> {late_norm:.3f}")
    print(f"   dominance delta mean:     {overall['dominance_delta_mean']:+.3f}")
    print(f"   trajectories with ANY collapse (delta>0): {overall['collapsed_any_pct']:.1f}%")
    print(f"   trajectories with delta>=0.3 nats:        {overall['collapsed_30pct']:.1f}%")
    print(f"   trajectories with delta>=0.5 nats:        {overall['collapsed_50pct']:.1f}%")

    print()
    print("== By model:domain ==")
    for grp, stats in sorted(by_group.items()):
        print(
            f"   {grp:32s} "
            f"n={stats['total_trajectories']:4d}  "
            f"delta_mean={stats['entropy_delta_mean']:+.3f}  "
            f"collapsed>=0.3={stats['collapsed_30pct']:5.1f}%"
        )

    if args.verbose:
        print()
        print("== Top 15 drift trajectories (by entropy delta) ==")
        scored.sort(key=lambda kv: -kv[1]["entropy_delta"])
        for key, m in scored[:15]:
            print(
                f"   delta={m['entropy_delta']:+.3f} "
                f"early={m['entropy_early_norm']:.2f}->late={m['entropy_late_norm']:.2f}  "
                f"{key}  "
                f"tools early={m['early_tools'][:3]}... late={m['late_tools'][:3]}..."
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
