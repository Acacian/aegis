"""Policy engine micro-benchmarks.

Run with:
    python benchmarks/bench_policy.py

Measures policy evaluation throughput for different rule counts.
"""

from __future__ import annotations

import time

from aegis.core.action import Action
from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.risk import RiskLevel


def _make_policy(n_rules: int) -> Policy:
    rules = []
    for i in range(n_rules):
        rules.append(
            PolicyRule(
                match_type=f"action_{i}",
                match_target=f"target_{i}",
                risk_level=RiskLevel.MEDIUM,
                approval=Approval.APPROVE,
                name=f"rule_{i}",
            )
        )
    # Add a catch-all at the end
    rules.append(
        PolicyRule(
            match_type="*",
            match_target="*",
            risk_level=RiskLevel.LOW,
            approval=Approval.AUTO,
            name="catch_all",
        )
    )
    return Policy(rules=rules, default_risk=RiskLevel.MEDIUM, default_approval=Approval.APPROVE)


def bench(n_rules: int, n_evals: int) -> float:
    policy = _make_policy(n_rules)
    action = Action("unknown_action", "unknown_target")  # hits catch-all (worst case)

    start = time.perf_counter()
    for _ in range(n_evals):
        policy.evaluate(action)
    elapsed = time.perf_counter() - start
    return elapsed


def main() -> None:
    n_evals = 100_000
    print(f"Policy evaluation benchmark ({n_evals:,} evaluations per run)")
    print(f"{'Rules':>8} {'Time (s)':>10} {'Evals/sec':>12}")
    print("-" * 34)

    for n_rules in [10, 50, 100, 500, 1000]:
        elapsed = bench(n_rules, n_evals)
        rate = n_evals / elapsed
        print(f"{n_rules:>8} {elapsed:>10.3f} {rate:>12,.0f}")


if __name__ == "__main__":
    main()
