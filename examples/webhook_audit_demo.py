"""
Webhook audit demo — stream audit events to external systems.

Usage:
    python examples/webhook_audit_demo.py

Demonstrates using runtime hooks to send audit events to external
systems (Slack, PagerDuty, custom dashboards) in real-time.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

from aegis import Action, Policy, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.core.result import Result, ResultStatus

POLICY_YAML = """\
version: "1"
defaults:
  risk_level: medium
  approval: approve

rules:
  - name: read_auto
    match: { type: "read" }
    risk_level: low
    approval: auto

  - name: delete_block
    match: { type: "delete" }
    risk_level: critical
    approval: block
"""


class DemoExecutor(BaseExecutor):
    async def execute(self, action: Action) -> Result:
        return Result(action=action, status=ResultStatus.SUCCESS)


# Simulated webhook endpoints
webhook_log: list[dict] = []


async def on_decision_webhook(action, decision):
    """Simulate sending decision events to a webhook."""
    event = {
        "type": "decision",
        "action": action.type,
        "target": action.target,
        "risk": str(decision.risk_level),
        "approval": str(decision.approval),
        "rule": decision.matched_rule,
    }
    webhook_log.append(event)
    print(f"  [WEBHOOK] {json.dumps(event)}")


async def on_block_alert(action, decision):
    """Simulate alerting on blocked actions (PagerDuty, Slack)."""
    if str(decision.approval) == "block":
        alert = {
            "severity": "critical",
            "message": f"BLOCKED: {action.type}:{action.target}",
            "rule": decision.matched_rule,
        }
        print(f"  [ALERT] {json.dumps(alert)}")


async def main() -> None:
    print("=" * 55)
    print("  Webhook Audit Demo")
    print("  Real-time event streaming")
    print("=" * 55)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as f:
        f.write(POLICY_YAML)
        policy_path = f.name

    policy = Policy.from_yaml(policy_path)

    async with Runtime(
        executor=DemoExecutor(),
        policy=policy,
    ) as runtime:
        actions = [
            Action("read", "crm", description="Fetch data"),
            Action("write", "crm", description="Update record"),
            Action("delete", "crm", description="Drop table"),
        ]

        print()
        for action in actions:
            # Evaluate and trigger hooks manually
            decision = policy.evaluate(action)
            await on_decision_webhook(action, decision)
            await on_block_alert(action, decision)

            # Execute through runtime
            plan = runtime.plan([action])
            await runtime.execute(plan)
            print()

        print(f"  Webhook events sent: {len(webhook_log)}")
        print(
            "  In production, replace print() with httpx.post() "
            "to your webhook endpoint."
        )

    Path(policy_path).unlink(missing_ok=True)


if __name__ == "__main__":
    asyncio.run(main())
