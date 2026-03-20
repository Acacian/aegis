"""End-to-end demo: Claude + Aegis governed tool calls.

Shows how to intercept Claude's tool_use responses and run them
through Aegis policy checks before executing.

Prerequisites:
    pip install 'agent-aegis[anthropic]'
    export ANTHROPIC_API_KEY=sk-...

Run:
    python examples/anthropic_demo.py
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

from aegis import Action, Policy, Result, ResultStatus, Runtime
from aegis.adapters.anthropic import govern_tool_call, tool_results_to_api_format
from aegis.adapters.base import BaseExecutor
from aegis.runtime.approval import AutoApprovalHandler
from aegis.runtime.audit import AuditLogger

# -- Fake executor that simulates tool execution --


class SimulatedExecutor(BaseExecutor):
    """Simulates tool execution without calling real APIs."""

    async def execute(self, action: Action) -> Result:
        responses = {
            "get_contacts": {"contacts": [{"name": "Alice"}, {"name": "Bob"}]},
            "update_contact": {"updated": True, "name": action.params.get("name")},
            "delete_contact": {"deleted": True},
        }
        data = responses.get(action.type, {"result": "ok"})
        print(f"  [executor] {action.type}({json.dumps(action.params)}) -> {json.dumps(data)}")
        return Result(
            action=action,
            status=ResultStatus.SUCCESS,
            data=data,
            completed_at=datetime.now(UTC),
        )


# -- Policy --

POLICY = {
    "version": "1",
    "defaults": {"risk_level": "medium", "approval": "approve"},
    "rules": [
        {
            "name": "read_auto",
            "match": {"type": "get_*"},
            "risk_level": "low",
            "approval": "auto",
        },
        {
            "name": "update_approve",
            "match": {"type": "update_*"},
            "risk_level": "medium",
            "approval": "approve",
        },
        {
            "name": "delete_blocked",
            "match": {"type": "delete_*"},
            "risk_level": "critical",
            "approval": "block",
        },
    ],
}


async def main() -> None:
    runtime = Runtime(
        executor=SimulatedExecutor(),
        policy=Policy.from_dict(POLICY),
        approval_handler=AutoApprovalHandler(),  # Auto-approve for demo
        audit_logger=AuditLogger(db_path=":memory:"),
    )

    # Simulate what Claude's tool_use responses would look like
    simulated_tool_calls = [
        {"name": "get_contacts", "input": {"limit": 10}},
        {"name": "update_contact", "input": {"name": "Alice", "email": "alice@new.com"}},
        {"name": "delete_contact", "input": {"id": "all"}},
    ]

    print("=" * 60)
    print("  CLAUDE + AEGIS GOVERNANCE DEMO")
    print("=" * 60)
    print()
    print("Simulating Claude tool_use responses going through Aegis...")
    print()

    all_results = []
    for tool_call in simulated_tool_calls:
        print(f"  Tool call: {tool_call['name']}({json.dumps(tool_call['input'])})")
        result = await govern_tool_call(
            runtime=runtime,
            tool_name=tool_call["name"],
            tool_input=tool_call["input"],
            target="crm",
        )
        print(f"  Result:    {result}")
        print()
        all_results.append(result)

    # Convert to API format
    api_results = tool_results_to_api_format(all_results)
    print("=" * 60)
    print("  RESULTS (Anthropic API format)")
    print("=" * 60)
    print(json.dumps(api_results, indent=2))

    # Audit
    print()
    print("=" * 60)
    print("  AUDIT TRAIL")
    print("=" * 60)
    for entry in runtime.audit.get_log():
        print(
            f"  {entry['action_type']:>15} | risk={entry['risk_level']:<8} | "
            f"result={entry.get('result_status') or '-'}"
        )


if __name__ == "__main__":
    asyncio.run(main())
