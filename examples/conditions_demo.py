"""Demo: Policy conditions in action.

Shows time-based, param-based, and weekday conditions
that go beyond simple glob matching.

Run:
    python examples/conditions_demo.py
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from aegis import Action, Policy, Result, ResultStatus, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.runtime.approval import AutoApprovalHandler
from aegis.runtime.audit import AuditLogger


class MockExecutor(BaseExecutor):
    async def execute(self, action: Action) -> Result:
        return Result(
            action=action,
            status=ResultStatus.SUCCESS,
            data={"mock": True},
            completed_at=datetime.now(UTC),
        )


POLICY = {
    "version": "1",
    "defaults": {"risk_level": "medium", "approval": "approve"},
    "rules": [
        # Block large bulk operations
        {
            "name": "bulk_block",
            "match": {"type": "update*"},
            "conditions": {"param_gt": {"count": 1000}},
            "risk_level": "critical",
            "approval": "block",
        },
        # Allow small updates
        {
            "name": "update_auto",
            "match": {"type": "update*"},
            "risk_level": "low",
            "approval": "auto",
        },
        # Only allow deploys on weekdays
        {
            "name": "weekday_deploy",
            "match": {"type": "deploy*"},
            "conditions": {"weekdays": [1, 2, 3, 4, 5]},
            "risk_level": "medium",
            "approval": "approve",
        },
        # Block weekend deploys
        {
            "name": "weekend_deploy_block",
            "match": {"type": "deploy*"},
            "risk_level": "critical",
            "approval": "block",
        },
        # Auto-approve reads
        {
            "name": "read_auto",
            "match": {"type": "read*"},
            "risk_level": "low",
            "approval": "auto",
        },
    ],
}


async def main() -> None:
    runtime = Runtime(
        executor=MockExecutor(),
        policy=Policy.from_dict(POLICY),
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=":memory:"),
    )

    actions = [
        Action("update", "db", params={"count": 5}, description="Small update (5 rows)"),
        Action("update", "db", params={"count": 5000}, description="Bulk update (5000 rows)"),
        Action("deploy", "production", description=f"Deploy (today is {_day_name()})"),
        Action("read", "metrics"),
    ]

    print("=" * 60)
    print("  POLICY CONDITIONS DEMO")
    print("=" * 60)
    print()

    plan = runtime.plan(actions)
    print(plan.summary())
    print()

    results = await runtime.execute(plan)

    print("=" * 60)
    print("  RESULTS")
    print("=" * 60)
    for r in results:
        desc = r.action.description or r.action.type
        print(f"  [{r.status.value:>7}] {desc}")
    print()

    print("=" * 60)
    print("  AUDIT TRAIL")
    print("=" * 60)
    for entry in runtime.audit.get_log():
        print(
            f"  {entry['action_type']:>10} | risk={entry['risk_level']:<8} | "
            f"rule={entry['matched_rule']:<20} | "
            f"result={entry.get('result_status') or '-'}"
        )


def _day_name() -> str:
    days = {1: "Monday", 2: "Tuesday", 3: "Wednesday", 4: "Thursday",
            5: "Friday", 6: "Saturday", 7: "Sunday"}
    return days[datetime.now(UTC).isoweekday()]


if __name__ == "__main__":
    asyncio.run(main())
