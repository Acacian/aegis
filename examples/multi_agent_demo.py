"""Demo: Multi-agent governance with policy hierarchy.

Shows how Aegis enforces org → team → agent policy layers
when multiple AI agents operate under the same governance framework.

No external dependencies needed — uses mock executors.

Run:
    python examples/multi_agent_demo.py
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from aegis import Action, Policy, Result, ResultStatus, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.core.hierarchy import PolicyHierarchy
from aegis.runtime.approval import AutoApprovalHandler
from aegis.runtime.audit import AuditLogger


class MockExecutor(BaseExecutor):
    """Executor that logs what it would do."""

    async def execute(self, action: Action) -> Result:
        print(f"    [exec] {action.type} -> {action.target}")
        return Result(
            action=action,
            status=ResultStatus.SUCCESS,
            data={"mock": True},
            completed_at=datetime.now(UTC),
        )


# Organization-wide policy: very conservative
ORG_POLICY = Policy.from_dict(
    {
        "version": "1",
        "defaults": {"risk_level": "high", "approval": "approve"},
        "rules": [
            {
                "name": "org_read_auto",
                "match": {"type": "read"},
                "risk_level": "low",
                "approval": "auto",
            },
            {
                "name": "org_delete_block",
                "match": {"type": "delete"},
                "risk_level": "critical",
                "approval": "block",
            },
        ],
    }
)

# Team policy: slightly more permissive for the CRM team
TEAM_POLICY = Policy.from_dict(
    {
        "version": "1",
        "defaults": {"risk_level": "medium", "approval": "approve"},
        "rules": [
            {
                "name": "team_write_approve",
                "match": {"type": "write"},
                "risk_level": "medium",
                "approval": "approve",
            },
        ],
    }
)

# Agent-specific policy: an agent that should be able to navigate freely
AGENT_POLICY = Policy.from_dict(
    {
        "version": "1",
        "defaults": {"risk_level": "low", "approval": "auto"},
        "rules": [
            {
                "name": "agent_navigate_auto",
                "match": {"type": "navigate"},
                "risk_level": "low",
                "approval": "auto",
            },
        ],
    }
)


async def main() -> None:
    # Build the hierarchy: org -> team -> agent
    hierarchy = PolicyHierarchy(
        org=ORG_POLICY,
        team=TEAM_POLICY,
        agent=AGENT_POLICY,
    )

    # Actions to test
    actions = [
        Action("read", "crm", description="Read contacts"),
        Action("navigate", "crm", params={"url": "https://crm.example.com"}),
        Action("write", "crm", params={"field": "name", "value": "Bob"}),
        Action("delete", "crm", params={"id": "all"}, description="Delete everything"),
    ]

    print("=" * 60)
    print("  MULTI-AGENT POLICY HIERARCHY DEMO")
    print("  Layers: Org (strict) → Team (moderate) → Agent (permissive)")
    print("=" * 60)
    print()

    for action in actions:
        decision, conflicts = hierarchy.evaluate(action)
        status = "ALLOWED" if decision.is_allowed else "BLOCKED"
        conflict_str = ""
        if conflicts:
            c = conflicts[0]
            layers = ", ".join(
                f"{k}={v.approval.value}" for k, v in c.layer_decisions.items()
            )
            conflict_str = f" [CONFLICT: {layers} -> {c.resolution}]"

        print(
            f"  {action.type:>10} | risk={decision.risk_level.name:<8} | "
            f"approval={decision.approval.value:<8} | {status}{conflict_str}"
        )

    print()

    # Now run through a full Runtime with the hierarchy's resolved policy
    runtime = Runtime(
        executor=MockExecutor(),
        policy=ORG_POLICY,  # Use org policy as the base
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=":memory:"),
    )

    plan = runtime.plan(actions)
    print("=" * 60)
    print("  EXECUTION PLAN (Org-level policy)")
    print("=" * 60)
    print(plan.summary())

    results = await runtime.execute(plan)
    print()
    print("=" * 60)
    print("  RESULTS")
    print("=" * 60)
    for r in results:
        print(f"  {r}")


if __name__ == "__main__":
    asyncio.run(main())
