"""Demo: AI agent managing Salesforce contacts with Aegis governance.

This example shows how Aegis provides policy checks, approval gates,
and audit logging for a simulated Salesforce CRM workflow.

No external dependencies needed -- uses a mock executor.

Run:
    python examples/salesforce_demo.py
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from aegis import Action, Policy, Result, ResultStatus, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.runtime.approval import AutoApprovalHandler
from aegis.runtime.audit import AuditLogger


class SalesforceSimulator(BaseExecutor):
    """Mock executor that simulates Salesforce CRM operations."""

    async def execute(self, action: Action) -> Result:
        print(f"    [salesforce] {action.type} -> {action.target}: {action.description}")
        return Result(
            action=action,
            status=ResultStatus.SUCCESS,
            data={"simulated": True},
            completed_at=datetime.now(UTC),
        )


POLICY = {
    "version": "1",
    "defaults": {"risk_level": "medium", "approval": "approve"},
    "rules": [
        {
            "name": "navigate_auto",
            "match": {"type": "navigate"},
            "risk_level": "low",
            "approval": "auto",
        },
        {
            "name": "read_auto",
            "match": {"type": "read"},
            "risk_level": "low",
            "approval": "auto",
        },
        {
            "name": "fill_approve",
            "match": {"type": "fill"},
            "risk_level": "medium",
            "approval": "approve",
        },
        {
            "name": "click_approve",
            "match": {"type": "click"},
            "risk_level": "medium",
            "approval": "approve",
        },
        {
            "name": "bulk_ops_high",
            "match": {"type": "bulk_*"},
            "conditions": {"param_gt": {"count": 100}},
            "risk_level": "high",
            "approval": "approve",
        },
        {
            "name": "delete_block",
            "match": {"type": "delete"},
            "risk_level": "critical",
            "approval": "block",
        },
    ],
}


async def main() -> None:
    runtime = Runtime(
        executor=SalesforceSimulator(),
        policy=Policy.from_dict(POLICY),
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=":memory:"),
    )

    actions = [
        Action(
            "navigate",
            target="salesforce",
            params={"url": "https://login.salesforce.com"},
            description="Open Salesforce login page",
        ),
        Action(
            "read",
            target="salesforce",
            params={"selector": ".contact-list"},
            description="Read current contact list",
        ),
        Action(
            "fill",
            target="salesforce",
            params={"selector": "#contact-name", "value": "Jane Doe"},
            description="Fill in new contact name",
        ),
        Action(
            "click",
            target="salesforce",
            params={"selector": "#save-button"},
            description="Save the new contact",
        ),
        Action(
            "bulk_update",
            target="salesforce",
            params={"field": "status", "value": "active", "count": 150},
            description="Bulk update 150 contacts to active status",
        ),
        Action(
            "delete",
            target="salesforce",
            params={"selector": "#delete-all"},
            description="Delete all inactive contacts",
        ),
    ]

    plan = runtime.plan(actions)
    print("=" * 60)
    print("  EXECUTION PLAN")
    print("=" * 60)
    print(plan.summary())
    print()

    results = await runtime.execute(plan)

    print()
    print("=" * 60)
    print("  RESULTS")
    print("=" * 60)
    for r in results:
        print(f"  {r}")

    print()
    print("=" * 60)
    print("  AUDIT LOG")
    print("=" * 60)
    for entry in runtime.audit.get_log(session_id=runtime.session_id):
        print(
            f"  {entry['action_type']:>14} | risk={entry['risk_level']:<8} | "
            f"result={entry.get('result_status') or '-'}"
        )


if __name__ == "__main__":
    asyncio.run(main())
