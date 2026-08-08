"""
Security hardening demo — defense-in-depth patterns with Aegis.

Usage:
    python examples/security_hardening_demo.py

Demonstrates:
- Fail-closed policy (default=block)
- Time-based access windows
- Parameter validation via conditions
- Multi-layer policy hierarchy
- Audit every action, even auto-approved ones
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from aegis import Action, Policy, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.core.result import Result, ResultStatus

HARDENED_POLICY = """\
version: "1"
# SECURITY: Default to block. Every allowed action must be explicitly listed.
defaults:
  risk_level: critical
  approval: block

rules:
  # Explicitly whitelist safe operations
  - name: read_allow
    match: { type: "read" }
    risk_level: low
    approval: auto

  - name: list_allow
    match: { type: "list" }
    risk_level: low
    approval: auto

  # Writes only during business hours, weekdays
  - name: write_business_hours
    match: { type: "write" }
    conditions:
      time_after: "09:00"
      time_before: "18:00"
      weekdays: [1, 2, 3, 4, 5]
    risk_level: medium
    approval: approve

  # Small updates auto-approve, large need review
  - name: update_small
    match: { type: "update" }
    conditions:
      param_lte: { count: 10 }
    risk_level: medium
    approval: auto

  - name: update_large
    match: { type: "update" }
    conditions:
      param_gt: { count: 10 }
    risk_level: high
    approval: approve

  # Everything else stays blocked (default)
  # No catch-all auto-approve rule — unknown actions are denied
"""


class SecureExecutor(BaseExecutor):
    async def execute(self, action: Action) -> Result:
        print(f"    [SECURE] {action.type}:{action.target}")
        return Result(action=action, status=ResultStatus.SUCCESS)


async def main() -> None:
    print("=" * 60)
    print("  Security Hardening Demo")
    print("  Fail-closed + time-based + parameter validation")
    print("=" * 60)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(HARDENED_POLICY)
        policy_path = f.name

    policy = Policy.from_yaml(policy_path)

    async with Runtime(executor=SecureExecutor(), policy=policy) as runtime:
        test_actions = [
            ("Read data (whitelisted)", Action("read", "db")),
            ("List resources (whitelisted)", Action("list", "resources")),
            (
                "Small update (auto, count=5)",
                Action("update", "db", params={"count": 5}),
            ),
            (
                "Large update (needs approval, count=100)",
                Action("update", "db", params={"count": 100}),
            ),
            (
                "Write (time-dependent)",
                Action("write", "db", params={"data": "test"}),
            ),
            (
                "Delete (not whitelisted → BLOCKED)",
                Action("delete", "db"),
            ),
            (
                "Execute shell (not whitelisted → BLOCKED)",
                Action("shell", "system", params={"cmd": "ls"}),
            ),
            (
                "Unknown action type (→ BLOCKED by default)",
                Action("foobar_unknown", "anywhere"),
            ),
        ]

        print()
        for desc, action in test_actions:
            print(f"  {desc}")
            plan = runtime.plan([action])
            results = await runtime.execute(plan)
            r = results[0]
            status = "ALLOWED" if r.status == ResultStatus.SUCCESS else "BLOCKED"
            # Risk lives on the PolicyDecision the plan produced, not on Result.
            risk = plan.decisions[0].risk_level if plan.decisions else "N/A"
            print(f"    → {status} (risk: {risk})")
            print()

        print("---")
        print("  Key principle: fail-closed default (block)")
        print("  Only explicitly whitelisted actions are allowed.")
        print(f"  Audit trail: {runtime.audit.count()} entries")

    Path(policy_path).unlink(missing_ok=True)


if __name__ == "__main__":
    asyncio.run(main())
