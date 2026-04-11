"""CLI command for ``aegis check drift`` — offline tool distribution drift check.

Stdlib-only by design (privacy + 30-second-reproducible pillar).

Reads a JSONL trace where each row has at least a ``tool_name`` field. All other
fields (``tool_args``, ``cot_text``, ``input``, ``output``, ``user_message``…)
are **never read**. The privacy guarantee is that this command cannot exfiltrate
prompt content even if the trace file contains it.

Usage:
    aegis check drift --trace path/to/trace.jsonl
    aegis check drift --trace trace.jsonl --baseline gpt4o-retail.json
    aegis check drift --trace trace.jsonl --window 4 --json
    aegis check drift --trace trace.jsonl --strict   # exit 1 if collapse

The CLI is the second entry point to the same drift signal that
``aegis.auto_instrument()`` exposes at runtime; it operates offline on saved
traces so users with existing trace stores (LangSmith, OTel, custom JSONL) can
evaluate the metric without instrumenting their agent.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from pathlib import Path
from typing import Any

# Mode classification thresholds (nats)
MODE_STABLE_MAX = 0.10  # |Δ| ≤ 0.10 → stable
MODE_COLLAPSE_MIN = 0.30  # Δ ≥ 0.30 → collapse
# Anything between is "midband" (drift detectable but not severe)


def _entropy(counts: Counter[str]) -> float:
    """Shannon entropy of a tool-call distribution (natural log).

    Pure stdlib. No numpy. ~µs of arithmetic.
    """
    total = sum(counts.values())
    if total == 0:
        return 0.0
    h = -sum((c / total) * math.log(c / total) for c in counts.values() if c > 0)
    # Normalize -0.0 → 0.0 (cosmetic; round() preserves the negative sign).
    return h + 0.0


def _read_tool_names(path: Path) -> list[str]:
    """Load a JSONL trace and return ONLY the tool name sequence.

    Privacy invariant: no other field is touched. If a row has no ``tool_name``,
    it is silently skipped (most likely a system / user message turn).
    """
    names: list[str] = []
    with path.open() as fh:
        for line_num, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                print(
                    f"  [warn] skipping malformed line {line_num}",
                    file=sys.stderr,
                )
                continue
            name = row.get("tool_name")
            if isinstance(name, str) and name:
                names.append(name)
    return names


def _classify_mode(delta: float) -> str:
    """Map an entropy delta to bimodal position."""
    if abs(delta) <= MODE_STABLE_MAX:
        return "stable"
    if delta >= MODE_COLLAPSE_MIN:
        return "collapse"
    return "midband"


def _score(tools: list[str], window: int) -> dict[str, Any]:
    """Compute the per-trace drift signal."""
    n = len(tools)
    if n < window * 2:
        return {
            "error": (
                f"trace has {n} tool calls; need at least {window * 2} "
                f"for two non-overlapping windows of size {window}"
            ),
            "tool_calls": n,
            "window": window,
        }

    early = tools[:window]
    late = tools[-window:]
    early_dist = Counter(early)
    late_dist = Counter(late)

    e_early = _entropy(early_dist)
    e_late = _entropy(late_dist)
    delta = e_early - e_late

    max_entropy = math.log(window) if window > 1 else 1.0
    normalized_delta = delta / max_entropy if max_entropy > 0 else 0.0

    return {
        "tool_calls": n,
        "window": window,
        "entropy_early": round(e_early, 4),
        "entropy_late": round(e_late, 4),
        "entropy_delta": round(delta, 4),
        "normalized_delta": round(normalized_delta, 4),
        "max_entropy": round(max_entropy, 4),
        "tool_count_early": len(early_dist),
        "tool_count_late": len(late_dist),
        "mode": _classify_mode(delta),
        "mode_thresholds": {
            "stable_max": MODE_STABLE_MAX,
            "collapse_min": MODE_COLLAPSE_MIN,
        },
    }


def _compare_baseline(score: dict[str, Any], baseline_path: Path) -> dict[str, Any]:
    """Compare the trace's normalized_delta against a baseline JSON.

    Baseline file format (produced by analyze_drift_on_tau_bench.py or by hand):
        {
            "name": "gpt-4o:retail",
            "normalized_delta_mean": 0.029,
            "collapse_rate_pct": 28.1,
            "n": 178
        }
    """
    try:
        baseline = json.loads(baseline_path.read_text())
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        return {"error": f"could not read baseline: {exc}"}

    base_norm = baseline.get("normalized_delta_mean")
    if base_norm is None:
        return {"error": "baseline missing 'normalized_delta_mean' field"}

    delta_vs_baseline = score["normalized_delta"] - base_norm
    return {
        "baseline_name": baseline.get("name", str(baseline_path)),
        "baseline_normalized_delta_mean": base_norm,
        "baseline_collapse_rate_pct": baseline.get("collapse_rate_pct"),
        "baseline_n": baseline.get("n"),
        "delta_vs_baseline": round(delta_vs_baseline, 4),
        "verdict": ("above_baseline" if delta_vs_baseline > 0 else "at_or_below_baseline"),
    }


def _human_verdict(score: dict[str, Any]) -> str:
    """One-line human-readable summary."""
    if "error" in score:
        return f"check drift: ERROR — {score['error']}"
    mode = score["mode"]
    n = score["tool_calls"]
    delta = score["entropy_delta"]
    norm = score["normalized_delta"]
    if mode == "collapse":
        return (
            f"check drift: COLLAPSE — {n} tool calls, "
            f"Δ={delta:+.3f} nats (norm {norm:+.2f}). "
            f"The agent narrowed its tool distribution by the end of the run."
        )
    if mode == "midband":
        return (
            f"check drift: MIDBAND — {n} tool calls, "
            f"Δ={delta:+.3f} nats (norm {norm:+.2f}). "
            f"Some narrowing detected but below the collapse threshold."
        )
    return (
        f"check drift: STABLE — {n} tool calls, "
        f"Δ={delta:+.3f} nats (norm {norm:+.2f}). "
        f"Tool distribution preserved through the trace."
    )


def register(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """Register the ``check`` subcommand and its drift sub-subcommand."""
    check_parser = subparsers.add_parser(
        "check",
        help="Run a deterministic offline check on a saved agent trace",
    )
    check_subs = check_parser.add_subparsers(dest="check_kind")

    drift_parser = check_subs.add_parser(
        "drift",
        help="Tool distribution entropy drift (deterministic, privacy-preserving)",
    )
    drift_parser.add_argument(
        "--trace",
        type=Path,
        required=True,
        help="JSONL trace file. Only the 'tool_name' field is read.",
    )
    drift_parser.add_argument(
        "--window",
        type=int,
        default=4,
        help="Window size in tool calls (default 4).",
    )
    drift_parser.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help="Optional baseline JSON for cross-model comparison.",
    )
    drift_parser.add_argument(
        "--json",
        action="store_true",
        dest="emit_json",
        help="Emit machine-readable JSON to stdout.",
    )
    drift_parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with code 1 if mode is 'collapse'.",
    )


def run(args: argparse.Namespace) -> int:
    """Execute the ``check`` command. Returns the exit code."""
    if getattr(args, "check_kind", None) != "drift":
        print("usage: aegis check drift --trace TRACE [--window N]", file=sys.stderr)
        return 2

    trace_path: Path = args.trace
    if not trace_path.exists():
        print(f"error: trace file not found: {trace_path}", file=sys.stderr)
        return 2

    tools = _read_tool_names(trace_path)
    score = _score(tools, args.window)

    output: dict[str, Any] = {
        "trace": str(trace_path),
        **score,
    }
    if args.baseline is not None and "error" not in score:
        output["baseline_comparison"] = _compare_baseline(score, args.baseline)

    if args.emit_json:
        json.dump(output, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(_human_verdict(score))
        if "baseline_comparison" in output:
            bc = output["baseline_comparison"]
            if "error" in bc:
                print(f"  baseline: {bc['error']}")
            else:
                base_norm = bc["baseline_normalized_delta_mean"]
                print(
                    f"  vs baseline {bc['baseline_name']}: "
                    f"this trace {output['normalized_delta']:+.2f} norm vs "
                    f"{base_norm:+.2f} mean ({bc['verdict']})"
                )

    if args.strict and score.get("mode") == "collapse":
        return 1
    return 0
