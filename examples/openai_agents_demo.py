"""End-to-end demo: OpenAI Agents SDK + Aegis governance.

Shows how to use @governed_tool to wrap function tools
with Aegis policy checks.

This demo uses a simulated runtime (no API key needed).

Run:
    pip install 'agent-aegis[openai-agents]'
    python examples/openai_agents_demo.py
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from aegis import Action, Policy, Result, ResultStatus, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.runtime.approval import AutoApprovalHandler
from aegis.runtime.audit import AuditLogger


class SimulatedExecutor(BaseExecutor):
    """Simulates tool execution without calling real APIs."""

    async def execute(self, action: Action) -> Result:
        responses = {
            "search": {"results": ["AI safety paper", "Governance framework"]},
            "write": {"written": True, "target": action.target},
            "delete": {"deleted": True},
        }
        data = responses.get(action.type, {"result": "ok"})
        print(f"  [executor] {action.type}({action.target}) -> {data}")
        return Result(
            action=action,
            status=ResultStatus.SUCCESS,
            data=data,
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
            "name": "write_approve",
            "match": {"type": "write*"},
            "risk_level": "medium",
            "approval": "approve",
        },
        {
            "name": "delete_block",
            "match": {"type": "delete*"},
            "risk_level": "critical",
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
    print("  OPENAI AGENTS SDK + AEGIS DEMO")
    print("=" * 60)
    print()
    print("Simulating @governed_tool execution...")
    print()

    # Simulate what governed_tool would do
    tool_calls = [
        ("search", "web", {"query": "AI governance"}),
        ("write", "database", {"record": "meeting_notes"}),
        ("delete", "database", {"table": "all"}),
    ]

    for action_type, target, params in tool_calls:
        action = Action(action_type, target, params=params)
        plan = runtime.plan([action])
        print(f"  Tool: {action_type}({target})")
        print(f"  Plan: {plan.summary().strip()}")

        results = await runtime.execute(plan)
        for r in results:
            print(f"  Result: {r.status.value}")
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
