"""
Rate-limiting demo with rolling window tracking.

Usage:
    python examples/rate_limit_demo.py

Demonstrates:
- Using Aegis policies to enforce rate limits on AI agent calls
- Rolling window counter for in-memory call tracking
- Tiered enforcement: auto -> approve -> block
- Real-time ANSI-colored output showing policy decisions
"""

from __future__ import annotations

import asyncio
import tempfile
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from aegis import Action, Approval, Policy, PolicyDecision, Result, ResultStatus, Runtime
from aegis.adapters.base import BaseExecutor

# --- ANSI colors -----------------------------------------------------------

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

# --- Policy -----------------------------------------------------------------
# Three tiers keyed on action *type*:
#   api_call       -> auto   (first N calls, agent self-assigns this type)
#   api_call_warn  -> approve (N+1 to 2N, agent re-labels when nearing limit)
#   api_call_block -> block   (beyond 2N, hard stop)

POLICY_YAML = """\
version: "1"
defaults:
  risk_level: low
  approval: auto

rules:
  - name: api_call_normal
    match: { type: "api_call" }
    risk_level: low
    approval: auto

  - name: api_call_throttled
    match: { type: "api_call_warn" }
    risk_level: high
    approval: approve

  - name: api_call_blocked
    match: { type: "api_call_block" }
    risk_level: critical
    approval: block
"""

# --- Rolling window counter -------------------------------------------------


@dataclass
class RollingWindowCounter:
    """Tracks call timestamps in a fixed-size rolling window.

    Args:
        window_secs: Length of the rolling window in seconds.
        soft_limit: Calls allowed at 'auto' approval (first N).
        hard_limit: Calls allowed at 'approve' approval (N+1 to 2N).
                    Beyond this, calls are blocked.
    """

    window_secs: float = 10.0
    soft_limit: int = 5
    hard_limit: int = 10
    _timestamps: deque[float] = field(default_factory=deque)

    def record(self) -> None:
        """Record a call timestamp."""
        self._timestamps.append(time.monotonic())

    def _prune(self) -> None:
        """Remove timestamps outside the rolling window."""
        cutoff = time.monotonic() - self.window_secs
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()

    @property
    def count(self) -> int:
        """Number of calls within the current window."""
        self._prune()
        return len(self._timestamps)

    def action_type_for_next(self) -> str:
        """Return the action type the agent should use for its next call.

        - count < soft_limit  -> "api_call"       (auto)
        - count < hard_limit  -> "api_call_warn"  (approve / throttle)
        - count >= hard_limit -> "api_call_block"  (block)
        """
        current = self.count
        if current < self.soft_limit:
            return "api_call"
        if current < self.hard_limit:
            return "api_call_warn"
        return "api_call_block"


# --- Executor ---------------------------------------------------------------


class SimulatedAPIExecutor(BaseExecutor):
    """Pretends to call an external API."""

    async def execute(self, action: Action) -> Result:
        await asyncio.sleep(0.05)  # simulate network latency
        return Result(action=action, status=ResultStatus.SUCCESS)


# --- Main -------------------------------------------------------------------


async def main() -> None:
    print(f"\n{BOLD}{'=' * 58}")
    print("  Rate-Limit Demo  —  Rolling Window + Aegis Policy")
    print(f"{'=' * 58}{RESET}\n")

    # Write policy to a temp file and load it
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as f:
        f.write(POLICY_YAML)
        policy_path = f.name

    policy = Policy.from_yaml(policy_path)
    counter = RollingWindowCounter(window_secs=10.0, soft_limit=5, hard_limit=10)

    print(f"  {CYAN}Window:{RESET}     {counter.window_secs}s")
    print(f"  {CYAN}Soft limit:{RESET} {counter.soft_limit} calls  (auto)")
    print(f"  {CYAN}Hard limit:{RESET} {counter.hard_limit} calls  (approve, then block)")
    print("\n  Simulating 18 rapid API calls...\n")
    print(f"  {'#':>3}  {'Type':<17} {'Decision':<10} {'Window':<8} Status")
    print(f"  {'—' * 55}")

    total_calls = 18
    stats = {"auto": 0, "approve": 0, "block": 0}

    async with Runtime(
        executor=SimulatedAPIExecutor(), policy=policy
    ) as runtime:
        for i in range(1, total_calls + 1):
            action_type = counter.action_type_for_next()
            action = Action(
                action_type,
                "external_api",
                description=f"API call #{i}",
            )

            decision: PolicyDecision = policy.evaluate(action)

            # Color and symbol per tier
            if decision.approval == Approval.AUTO:
                color, symbol, label = GREEN, "+", "auto"
                stats["auto"] += 1
            elif decision.approval == Approval.APPROVE:
                color, symbol, label = YELLOW, "~", "approve"
                stats["approve"] += 1
            else:
                color, symbol, label = RED, "x", "BLOCK"
                stats["block"] += 1

            window_count = counter.count

            # Execute only if not blocked
            if decision.approval != Approval.BLOCK:
                result = await runtime.run_one(action)
                status = (
                    f"{GREEN}OK{RESET}"
                    if result.status == ResultStatus.SUCCESS
                    else f"{RED}FAIL{RESET}"
                )
                counter.record()
            else:
                status = f"{RED}DENIED{RESET}"

            print(
                f"  {color}{symbol}{RESET} "
                f"{i:>2}  "
                f"{DIM}{action_type:<17}{RESET} "
                f"{color}{label:<10}{RESET} "
                f"{window_count:>3}/{counter.hard_limit}    "
                f"{status}"
            )

            await asyncio.sleep(0.02)  # tiny pause between calls

    # Summary
    print(f"\n  {'—' * 55}")
    print(f"  {BOLD}Summary{RESET}")
    print(f"    {GREEN}Auto (passed):{RESET}     {stats['auto']}")
    print(f"    {YELLOW}Throttled:{RESET}         {stats['approve']}")
    print(f"    {RED}Blocked:{RESET}           {stats['block']}")
    print(
        f"\n  {DIM}In production, 'approve' calls would pause for human"
        f" confirmation.{RESET}"
    )
    print(
        f"  {DIM}Here they execute immediately for demonstration"
        f" purposes.{RESET}\n"
    )

    Path(policy_path).unlink(missing_ok=True)


if __name__ == "__main__":
    asyncio.run(main())
