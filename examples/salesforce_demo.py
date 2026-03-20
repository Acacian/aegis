"""Demo: AI agent managing Salesforce contacts with Aegis governance.

This example shows how Aegis provides policy checks, approval gates,
and audit logging for AI agent browser automation.

Run:
    python examples/salesforce_demo.py
"""

from __future__ import annotations

import asyncio

from aegis import Action, Policy, Runtime
from aegis.adapters.playwright import PlaywrightExecutor


async def main() -> None:
    # 1. Set up the runtime with policy
    runtime = Runtime(
        executor=PlaywrightExecutor(headless=False),
        policy=Policy.from_yaml("policy.example.yaml"),
    )

    # 2. Define the actions the AI agent wants to take
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

    # 3. Plan: evaluate all actions against policy
    plan = runtime.plan(actions)
    print("=" * 60)
    print("  EXECUTION PLAN")
    print("=" * 60)
    print(plan.summary())
    print()

    # 4. Execute with governance
    results = await runtime.execute(plan)

    # 5. Print results
    print()
    print("=" * 60)
    print("  RESULTS")
    print("=" * 60)
    for r in results:
        print(f"  {r}")

    # 6. Show audit log
    print()
    print("=" * 60)
    print("  AUDIT LOG")
    print("=" * 60)
    for entry in runtime.audit.get_log(session_id=runtime.session_id):
        print(
            f"  [{entry['timestamp'][:19]}] {entry['action_type']:>12} -> "
            f"{entry['action_target']}  "
            f"risk={entry['risk_level']}  result={entry.get('result_status', '-')}"
        )


if __name__ == "__main__":
    asyncio.run(main())
