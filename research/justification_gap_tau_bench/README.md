# Justification Gap on tau-bench

Measurement scripts for [The Justification Gap in 14,285 Tau-Bench Tool Calls](https://acacian.github.io/aegis/research/tripartite-action-claim/).

## Reproduction (30 seconds)

```bash
# 1. Clone Aegis and install
git clone https://github.com/Acacian/aegis.git
cd aegis
pip install -e .

# 2. Fetch the tau-bench historical trajectories
mkdir -p .cache/traces
curl -L https://github.com/sierra-research/tau-bench/archive/refs/heads/main.tar.gz \
  | tar -xz --strip-components=2 -C .cache/traces \
    "tau-bench-main/historical_trajectories"

# Flatten all trajectories into a single JSONL (the scripts expect this shape).
# See .cache/traces/tau_bench_all.jsonl in your local build.

# 3. Run the assessor (stdlib only, ~30 seconds on 14,285 calls)
python research/justification_gap_tau_bench/measure_gap.py \
  --input  .cache/traces/tau_bench_all.jsonl \
  --output .cache/analysis/justification_gap_results.json

# 4. Render the four charts
python research/justification_gap_tau_bench/visualize.py \
  --input  .cache/analysis/justification_gap_results.json \
  --out-dir docs/assets/research
```

## What these scripts do

- **`measure_gap.py`** — iterates the tau-bench tool-call log, runs `aegis.core.justification_gap.ClaimAssessor` on every call in the **silent baseline framing** (agent declares zero impact), and emits per-call, per-trajectory, and per-group aggregates. Stdlib only — no NumPy, no Pandas, no matplotlib in the measurement path.
- **`visualize.py`** — loads `measure_gap.py`'s JSON output and renders four charts used in the paper (`jg-histogram.png`, `jg-radar.png`, `jg-verdict-by-group.png`, `jg-top-tools.png`). Uses matplotlib only; separate from the core measurement path so the numbers are reproducible without any visualization dependency.

## Why silent baseline

In the silent-baseline framing the agent declares an all-zero `ImpactVector`, so the asymmetric per-dim gap `max(0, assessed - declared)` collapses to `assessed` directly. The gap distribution then **is** the distribution of impact that a null declaration would entirely fail to report — which is the failure mode the paper's §1 enumerates. Running in this framing cleanly separates the assessor's behavior from any agent-side self-reporting noise.

## Results summary (see the paper for the full writeup)

- **14,285 tool calls** across 1,960 trajectories — GPT-4o and Claude Sonnet 3.5 New on the retail and airline tau-bench task families.
- **Global split: 90.3% approve / 9.7% escalate / 0.0% block** at thresholds `approve ≤ 0.15`, `0.15 < escalate ≤ 0.40`, `block > 0.40`.
- **Airline escalates ~2× more often than retail** for both models.
- **Top tool by mean gap** is `find_user_id_by_email` at 0.367 on 695 calls — a transparent rule-based false positive (triple-collision on the `email` keyword across three rule sets). Discussed in §9 of the paper; motivates the escalate-not-block design.

See [`docs/research/tripartite-action-claim.md`](../../docs/research/tripartite-action-claim.md) for the formal definition, operational semantics, soundness sketches for the three structural invariants, and the full empirical writeup.

## Raw data

The per-call scored JSONL (14,285 rows × 10 columns with verdict, gap, and 6D vector) is not checked into the repository to keep the repo small. Open an issue on [github.com/Acacian/aegis](https://github.com/Acacian/aegis) if you need it and it will be shared.
