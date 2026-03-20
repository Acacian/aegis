"""End-to-end demo: CrewAI + Aegis governance.

Shows how to use AegisCrewAITool to create governed tools
for CrewAI agents.

This demo uses a simulated runtime (no API key needed).

Run:
    pip install 'agent-aegis[crewai]'
    python examples/crewai_demo.py
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from aegis import Action, Policy, Result, ResultStatus, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.runtime.approval import AutoApprovalHandler
from aegis.runtime.audit import AuditLogger


class SimulatedExecutor(BaseExecutor):
    async def execute(self, action: Action) -> Result:
        print(f"  [executor] {action.type}({action.target})")
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
        {
            "name": "search_auto",
            "match": {"type": "search*"},
            "risk_level": "low",
            "approval": "auto",
        },
        {
            "name": "write_block",
            "match": {"type": "write*"},
            "risk_level": "high",
            "approval": "block",
        },
    ],
}


async def main() -> None:
    runtime = Runtime(
        executor=SimulatedExecutor(),
        policy=Policy.from_dict(POLICY),
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=":memory:"),
    )

    print("=" * 60)
    print("  CREWAI + AEGIS DEMO")
    print("=" * 60)
    print()

    # Simulate what AegisCrewAITool would do
    actions = [
        Action("search", "web", params={"query": "AI governance"}),
        Action("write", "database", params={"data": "sensitive"}),
    ]

    for action in actions:
        print(f"  Action: {action}")
        result = await runtime.run_one(action)
        print(f"  Result: {result.status.value}")
        print()

    print("=" * 60)
    print("  AUDIT TRAIL")
    print("=" * 60)
    for entry in runtime.audit.get_log():
        print(
            f"  {entry['action_type']:>10} | risk={entry['risk_level']:<8} | "
            f"result={entry.get('result_status') or '-'}"
        )


if __name__ == "__main__":
    asyncio.run(main())
