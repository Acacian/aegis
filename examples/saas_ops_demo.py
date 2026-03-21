"""
SaaS Operations demo — AI support agent with governance.

Usage:
    python examples/saas_ops_demo.py

Scenario: AI support agent handling customer tickets.
- Can view tickets freely
- Can respond to customers (with review)
- Can issue refunds (high risk, needs approval)
- Cannot delete accounts or modify billing directly
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from aegis import Action, Policy, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.core.result import Result, ResultStatus

POLICY = """\
version: "1"
defaults:
  risk_level: medium
  approval: approve

rules:
  - name: view_tickets
    match: { type: "view_ticket" }
    risk_level: low
    approval: auto

  - name: search_tickets
    match: { type: "search" }
    risk_level: low
    approval: auto

  - name: view_customer
    match: { type: "view_customer" }
    risk_level: low
    approval: auto

  - name: respond_ticket
    match: { type: "respond" }
    risk_level: medium
    approval: approve

  - name: escalate_ticket
    match: { type: "escalate" }
    risk_level: medium
    approval: auto

  - name: small_refund
    match: { type: "refund" }
    conditions:
      param_lte: { amount: 50 }
    risk_level: medium
    approval: approve

  - name: large_refund
    match: { type: "refund" }
    conditions:
      param_gt: { amount: 50 }
    risk_level: high
    approval: approve

  - name: delete_account
    match: { type: "delete_account" }
    risk_level: critical
    approval: block

  - name: modify_billing
    match: { type: "modify_billing" }
    risk_level: critical
    approval: block
"""


class SaaSExecutor(BaseExecutor):
    async def execute(self, action: Action) -> Result:
        print(f"    [SaaS] Executing: {action.type} on {action.target}")
        return Result(action=action, status=ResultStatus.SUCCESS)


async def main() -> None:
    print("=" * 60)
    print("  Aegis SaaS Ops Demo")
    print("  AI Support Agent with Governance")
    print("=" * 60)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as f:
        f.write(POLICY)
        policy_path = f.name

    policy = Policy.from_yaml(policy_path)

    async with Runtime(
        executor=SaaSExecutor(), policy=policy
    ) as runtime:
        # Simulate a support agent workflow
        ticket_flow = [
            (
                "Customer reports billing issue",
                Action(
                    "search",
                    "tickets",
                    params={"query": "billing issue"},
                    description="Search for similar tickets",
                ),
            ),
            (
                "View the specific ticket",
                Action(
                    "view_ticket",
                    "tickets",
                    params={"ticket_id": "T-5678"},
                ),
            ),
            (
                "Look up customer details",
                Action(
                    "view_customer",
                    "customers",
                    params={"customer_id": "C-1234"},
                ),
            ),
            (
                "Reply to the customer",
                Action(
                    "respond",
                    "tickets",
                    params={
                        "ticket_id": "T-5678",
                        "message": "We apologize for the issue...",
                    },
                ),
            ),
            (
                "Issue small courtesy refund ($25)",
                Action(
                    "refund",
                    "billing",
                    params={"customer_id": "C-1234", "amount": 25},
                ),
            ),
            (
                "Customer demands full refund ($200)",
                Action(
                    "refund",
                    "billing",
                    params={"customer_id": "C-1234", "amount": 200},
                ),
            ),
            (
                "Agent tries to delete the account",
                Action(
                    "delete_account",
                    "customers",
                    params={"customer_id": "C-1234"},
                ),
            ),
        ]

        print()
        for step_desc, action in ticket_flow:
            print(f"  Step: {step_desc}")
            plan = runtime.plan([action])
            results = await runtime.execute(plan)
            r = results[0]
            status = (
                "ALLOWED"
                if r.status == ResultStatus.SUCCESS
                else "BLOCKED"
            )
            risk = r.decision.risk_level if r.decision else "N/A"
            rule = r.decision.matched_rule if r.decision else "N/A"
            print(f"    Result: {status} | Risk: {risk} | Rule: {rule}")
            print()

        print("---")
        print(
            f"  Audit trail: {len(runtime.audit_log.entries)} entries logged"
        )
        print(
            "  The support agent handled the ticket safely — dangerous"
            " actions were blocked."
        )

    Path(policy_path).unlink(missing_ok=True)


if __name__ == "__main__":
    asyncio.run(main())
