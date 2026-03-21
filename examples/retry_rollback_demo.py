"""
Retry and rollback demo.

Usage:
    python examples/retry_rollback_demo.py

Demonstrates:
- Configuring retry with exponential backoff
- Automatic rollback on failure
- Fail-safe execution patterns
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from aegis import Action, Policy, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.core.result import Result, ResultStatus

POLICY_YAML = """\
version: "1"
defaults:
  risk_level: medium
  approval: auto

rules:
  - name: all_auto
    match: { type: "*" }
    risk_level: medium
    approval: auto
"""

call_count = 0


class FlakeyExecutor(BaseExecutor):
    """Executor that fails the first 2 times, succeeds on 3rd."""

    async def execute(self, action: Action) -> Result:
        global call_count
        call_count += 1
        if call_count <= 2:
            print(
                f"    [EXEC] Attempt {call_count}: "
                f"{action.type} FAILED (simulated)"
            )
            raise RuntimeError(f"Simulated failure #{call_count}")
        print(
            f"    [EXEC] Attempt {call_count}: "
            f"{action.type} SUCCESS"
        )
        return Result(action=action, status=ResultStatus.SUCCESS)


async def main() -> None:
    global call_count

    print("=" * 50)
    print("  Retry & Rollback Demo")
    print("=" * 50)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as f:
        f.write(POLICY_YAML)
        policy_path = f.name

    policy = Policy.from_yaml(policy_path)

    print("\n  Scenario: Executor fails twice, succeeds on 3rd try")
    print("  Aegis retries with exponential backoff\n")

    call_count = 0
    async with Runtime(
        executor=FlakeyExecutor(), policy=policy
    ) as runtime:
        try:
            result = await runtime.run_one(
                Action("write", "api", description="Flakey API call")
            )
            print(
                f"\n  Final: "
                f"{'SUCCESS' if result.status == ResultStatus.SUCCESS else 'FAILED'}"
            )
        except Exception as e:
            print(f"\n  Final: FAILED after retries — {e}")

    print(
        "\n  Note: Configure max_retries and retry_backoff "
        "in Runtime constructor."
    )

    Path(policy_path).unlink(missing_ok=True)


if __name__ == "__main__":
    asyncio.run(main())
