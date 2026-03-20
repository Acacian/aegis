"""Live browser demo using httpbin.org — a public HTTP testing service.

This example demonstrates Aegis governing real Playwright browser actions:
- Navigate to httpbin.org (auto-approved, low risk)
- Read page content (auto-approved, low risk)
- Fill and submit a form (requires human approval, medium risk)
- Attempt to "delete" something (blocked by policy, critical risk)

Prerequisites:
    pip install 'agent-aegis[playwright]'
    playwright install chromium

Run:
    python examples/browser_demo.py
"""

from __future__ import annotations

import asyncio

from aegis import Action, Policy, Runtime
from aegis.adapters.playwright import PlaywrightExecutor
from aegis.runtime.audit import AuditLogger

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
            "name": "screenshot_auto",
            "match": {"type": "screenshot"},
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
            "name": "delete_blocked",
            "match": {"type": "delete"},
            "risk_level": "critical",
            "approval": "block",
        },
    ],
}


async def main() -> None:
    runtime = Runtime(
        executor=PlaywrightExecutor(headless=False),
        policy=Policy.from_dict(POLICY),
        audit_logger=AuditLogger(db_path=":memory:"),
    )

    actions = [
        Action(
            "navigate",
            target="httpbin",
            params={"url": "https://httpbin.org/forms/post"},
            description="Open httpbin form page",
        ),
        Action(
            "read",
            target="httpbin",
            params={"selector": "html"},
            description="Read the page content",
        ),
        Action(
            "fill",
            target="httpbin",
            params={"selector": "input[name='custname']", "value": "Aegis Demo User"},
            description="Fill in customer name",
        ),
        Action(
            "click",
            target="httpbin",
            params={"selector": "input[type='submit']"},
            description="Submit the form",
        ),
        Action(
            "screenshot",
            target="httpbin",
            params={"path": "aegis_demo_result.png"},
            description="Capture the result page",
        ),
        Action(
            "delete",
            target="httpbin",
            params={"selector": "#dangerous-button"},
            description="Attempt destructive action (will be blocked)",
        ),
    ]

    # Plan
    plan = runtime.plan(actions)
    print("=" * 60)
    print("  AEGIS BROWSER DEMO")
    print("=" * 60)
    print(plan.summary())
    print()

    # Execute
    results = await runtime.execute(plan)

    # Results
    print()
    print("=" * 60)
    print("  RESULTS")
    print("=" * 60)
    for r in results:
        print(f"  {r}")

    # Audit
    print()
    print("=" * 60)
    print("  AUDIT TRAIL")
    print("=" * 60)
    for entry in runtime.audit.get_log(session_id=runtime.session_id):
        print(
            f"  {entry['action_type']:>12} | risk={entry['risk_level']:<8} | "
            f"decision={entry.get('human_decision') or entry['approval']:<8} | "
            f"result={entry.get('result_status') or '-'}"
        )


if __name__ == "__main__":
    asyncio.run(main())
