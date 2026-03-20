"""End-to-end demo: LangChain tools governed by Aegis.

Shows two patterns:
1. Run existing LangChain tools through Aegis policy
2. Expose Aegis-governed actions as LangChain tools

This demo uses mock tools to avoid external dependencies.

Run:
    pip install 'agent-aegis[langchain]'
    python examples/langchain_demo.py
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
        print(f"  [mock] Executing: {action}")
        return Result(
            action=action,
            status=ResultStatus.SUCCESS,
            data={"mock": True, "action": action.type},
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


async def demo_pattern_1() -> None:
    """Pattern 1: Route actions through Aegis directly."""
    print("=" * 60)
    print("  PATTERN 1: Direct Aegis governance")
    print("=" * 60)
    print()

    runtime = Runtime(
        executor=MockExecutor(),
        policy=Policy.from_dict(POLICY),
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=":memory:"),
    )

    actions = [
        Action("search", "web", params={"query": "AI governance frameworks"}),
        Action("write", "database", params={"table": "contacts", "data": {"name": "Alice"}}),
        Action("delete", "database", params={"table": "contacts", "where": "all"}),
    ]

    plan = runtime.plan(actions)
    print(plan.summary())
    print()

    results = await runtime.execute(plan)
    for r in results:
        print(f"  {r}")
    print()


async def demo_pattern_2() -> None:
    """Pattern 2: Create LangChain tools from Aegis-governed actions."""
    print("=" * 60)
    print("  PATTERN 2: Aegis as LangChain tool provider")
    print("=" * 60)
    print()

    try:
        from aegis.adapters.langchain import AegisTool
    except ImportError:
        print("  Skipping: langchain-core not installed")
        print("  Install with: pip install 'agent-aegis[langchain]'")
        return

    runtime = Runtime(
        executor=MockExecutor(),
        policy=Policy.from_dict(POLICY),
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=":memory:"),
    )

    search_tool = AegisTool.from_runtime(
        runtime=runtime,
        name="governed_search",
        description="Search the web with policy governance",
        action_type="search",
        action_target="web",
    )

    print(f"  Tool name: {search_tool.name}")
    print(f"  Tool desc: {search_tool.description}")
    result = await search_tool.ainvoke({"query": "AI governance"})
    print(f"  Result: {result}")
    print()


async def main() -> None:
    await demo_pattern_1()
    await demo_pattern_2()


if __name__ == "__main__":
    asyncio.run(main())
