"""Quickstart: see Aegis governance in action without Playwright.

This uses a fake executor that just prints what it would do,
so you can see the policy engine, approval flow, and audit log
without needing a browser.

Run:
    python examples/quickstart.py
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from aegis import Action, Policy, Result, ResultStatus, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.runtime.approval import AutoApprovalHandler
from aegis.runtime.audit import AuditLogger


class DryRunExecutor(BaseExecutor):
    """Executor that simulates actions without actually doing anything."""

    async def execute(self, action: Action) -> Result:
        print(f"    [dry-run] Would execute: {action}")
        return Result(
            action=action,
            status=ResultStatus.SUCCESS,
            data={"dry_run": True},
            completed_at=datetime.now(UTC),
        )


POLICY = {
    "version": "1",
    "defaults": {"risk_level": "medium", "approval": "approve"},
    "rules": [
        {"name": "read_auto", "match": {"type": "read"}, "risk_level": "low", "approval": "auto"},
        {
            "name": "navigate_auto",
            "match": {"type": "navigate"},
            "risk_level": "low",
            "approval": "auto",
        },
        {
            "name": "write_approve",
            "match": {"type": "write"},
            "risk_level": "medium",
            "approval": "approve",
        },
        {
            "name": "bulk_approve",
            "match": {"type": "bulk_*"},
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
        executor=DryRunExecutor(),
        policy=Policy.from_dict(POLICY),
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=":memory:"),
    )

    actions = [
        Action("navigate", "crm", params={"url": "https://crm.example.com"}),
        Action("read", "crm", params={"selector": ".contacts"}, description="Read contact list"),
        Action(
            "write",
            "crm",
            params={"field": "name", "value": "Alice"},
            description="Update contact",
        ),
        Action("bulk_update", "crm", params={"count": 50}, description="Bulk status change"),
        Action("delete", "crm", params={"id": "all"}, description="Delete all records"),
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
            f"  {entry['action_type']:>12} | risk={entry['risk_level']:<8} | "
            f"decision={entry.get('human_decision') or entry['approval']:<8} | "
            f"result={entry.get('result_status') or '-'}"
        )


if __name__ == "__main__":
    asyncio.run(main())
