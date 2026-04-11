# Tool Distribution Drift on tau-bench

Measurement scripts for [Tool Distribution Drift in 1,960 Tau-Bench Trajectories](https://acacian.github.io/aegis/research/tau-bench-tool-distribution-drift/).

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

# 3. Run the analyzer (stdlib only, ~30 seconds on 14,285 calls)
python research/tau_bench_drift/analyze.py \
  --input  .cache/traces/tau_bench_all.jsonl \
  --output .cache/analysis/drift_results.json

# 4. Render the four charts
python research/tau_bench_drift/visualize.py \
  --input  .cache/analysis/drift_results.json \
  --out-dir docs/assets/research
```

## What these scripts do

- **`analyze.py`** — loads a flattened tau-bench JSONL, groups calls into trajectories by `(model, domain, task_id)`, computes Shannon entropy on the first `W` and last `W` tool calls of each trajectory, and reports the delta. Stdlib only — no NumPy, no Pandas, no matplotlib in the measurement path. Default window size `W=4`, minimum trajectory length `2W=8`.
- **`visualize.py`** — loads `analyze.py`'s JSON output and renders four charts used in the paper (`drift-histogram.png`, `drift-by-model.png`, `drift-by-trajectory-length.png`, `drift-cumulative.png`). Uses matplotlib only; separate from the measurement path so the numbers are reproducible without any visualization dependency.

## Why entropy delta

Shannon entropy on the tool-name distribution captures **how many distinct tools the agent is currently using, weighted by frequency**. A trajectory that starts by exploring many tools and ends by hammering one tool has `entropy_early > entropy_late`, i.e., `entropy_delta > 0`. The 0.3-nat threshold corresponds roughly to collapsing from "~4 tools in use" to "~2 tools in use" inside the window — a visible behavioral change but not a panic metric. Window size `W=4` is the smallest that keeps `log W = 1.386` enough resolution to detect 0.3-nat moves.

The metric is purely observational. We do **not** claim that tool distribution collapse *causes* task failure — only that the signal exists, varies systematically by model and task family, and is cheap to compute.

## Results summary (see the paper for the full writeup)

- **1,960 trajectories** across GPT-4o and Claude Sonnet 3.5 New on the retail and airline tau-bench task families. 812 trajectories meet the `>=8 calls` minimum and are scored.
- **39.8% of scored trajectories collapse onto one or two tools by the end** (`entropy_delta >= 0.3 nats`).
- **Bimodal distribution**: the histogram shows a sharp mode near zero (stable agents) and a second mode near the collapse threshold.
- **1.7× cross-model gap**: Sonnet 3.5 New collapses on a much higher fraction of trajectories than GPT-4o on the same task family.
- Companion metric to the [Justification Gap paper](https://acacian.github.io/aegis/research/tripartite-action-claim/), which measures impact magnitude per call rather than distribution shape over time.

See [`docs/research/tau-bench-tool-distribution-drift.md`](../../docs/research/tau-bench-tool-distribution-drift.md) for the full empirical writeup, limitations, and honest caveats on single-task framing and window choice.

## Raw data

The per-trajectory JSON (812 rows × 13 columns with entropy delta, diversity ratio, dominance delta, and tool lists) is not checked into the repository to keep the repo small. Open an issue on [github.com/Acacian/aegis](https://github.com/Acacian/aegis) if you need it and it will be shared.
