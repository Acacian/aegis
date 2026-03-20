"""End-to-end demo: REST API governance with httpx.

Shows how to govern REST API calls through Aegis policy.
Uses httpbin.org as a safe target.

Run:
    pip install 'agent-aegis[httpx]'
    python examples/httpx_demo.py
"""

from __future__ import annotations

import asyncio

from aegis import Action, Policy, Runtime
from aegis.adapters.httpx_adapter import HttpxExecutor
from aegis.runtime.approval import AutoApprovalHandler
from aegis.runtime.audit import AuditLogger

POLICY = {
    "version": "1",
    "defaults": {"risk_level": "medium", "approval": "approve"},
    "rules": [
        {
            "name": "get_auto",
            "match": {"type": "get"},
            "risk_level": "low",
            "approval": "auto",
        },
        {
            "name": "post_approve",
            "match": {"type": "post"},
            "risk_level": "medium",
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
        executor=HttpxExecutor(base_url="https://httpbin.org"),
        policy=Policy.from_dict(POLICY),
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=":memory:"),
    )

    actions = [
        Action("get", "/get", params={"query": {"q": "aegis"}}),
        Action("post", "/post", params={"json": {"name": "Alice", "role": "admin"}}),
        Action("delete", "/delete", params={"json": {"id": "all"}}),
    ]

    print("=" * 60)
    print("  HTTPX REST API GOVERNANCE DEMO")
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
        status = r.status.value.upper()
        body_preview = ""
        if r.data and "body" in r.data:
            body = r.data["body"]
            if isinstance(body, dict):
                body_preview = f" (keys: {', '.join(list(body.keys())[:3])}...)"
            elif isinstance(body, str):
                body_preview = f" ({len(body)} chars)"
        print(f"  [{status:>7}] {r.action.type:>6} {r.action.target}{body_preview}")
    print()

    print("=" * 60)
    print("  AUDIT TRAIL")
    print("=" * 60)
    for entry in runtime.audit.get_log():
        print(
            f"  {entry['action_type']:>6} {entry['action_target']:<10} | "
            f"risk={entry['risk_level']:<8} | "
            f"result={entry.get('result_status') or '-'}"
        )


if __name__ == "__main__":
    asyncio.run(main())
