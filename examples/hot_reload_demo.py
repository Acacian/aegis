"""
Hot-reload demo — change policies without restarting your agent.

Usage:
    python examples/hot_reload_demo.py

Demonstrates:
- Start with permissive policy
- Update to strict policy at runtime
- Same action gets different results before/after
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from aegis import Action, Policy, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.core.result import Result, ResultStatus

PERMISSIVE_POLICY = """\
version: "1"
defaults:
  risk_level: low
  approval: auto

rules:
  - name: all_auto
    match: { type: "*" }
    risk_level: low
    approval: auto
"""

STRICT_POLICY = """\
version: "1"
defaults:
  risk_level: critical
  approval: block

rules:
  - name: read_only
    match: { type: "read" }
    risk_level: low
    approval: auto
"""


class DemoExecutor(BaseExecutor):
    async def execute(self, action: Action) -> Result:
        print(f"    Executed: {action.type}:{action.target}")
        return Result(action=action, status=ResultStatus.SUCCESS)


def load_policy(yaml_str: str) -> Policy:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as f:
        f.write(yaml_str)
        path = f.name
    policy = Policy.from_yaml(path)
    Path(path).unlink(missing_ok=True)
    return policy


async def main() -> None:
    print("=" * 50)
    print("  Hot-Reload Demo")
    print("=" * 50)

    policy = load_policy(PERMISSIVE_POLICY)
    async with Runtime(
        executor=DemoExecutor(), policy=policy
    ) as runtime:
        actions = [
            Action("read", "db"),
            Action("write", "db"),
            Action("delete", "db"),
        ]

        print("\n  Phase 1: Permissive policy (all auto-approve)")
        for a in actions:
            plan = runtime.plan([a])
            results = await runtime.execute(plan)
            r = results[0]
            print(
                f"    {a.type}: "
                f"{'ALLOWED' if r.status == ResultStatus.SUCCESS else 'BLOCKED'}"
            )

        # Hot-reload to strict policy
        strict = load_policy(STRICT_POLICY)
        runtime.update_policy(strict)

        print("\n  Phase 2: Strict policy (read only)")
        for a in actions:
            plan = runtime.plan([a])
            results = await runtime.execute(plan)
            r = results[0]
            print(
                f"    {a.type}: "
                f"{'ALLOWED' if r.status == ResultStatus.SUCCESS else 'BLOCKED'}"
            )

        print(
            "\n  Same actions, different results — policy "
            "changed at runtime without restart."
        )


if __name__ == "__main__":
    asyncio.run(main())
