"""
Slack approval handler demo.

Usage:
    python examples/slack_approval_demo.py

Demonstrates:
- Implementing a custom ApprovalHandler for Slack
- Simulated Slack message + button interaction
- Approval flow with timeout
- How to wire a custom handler into the Aegis Runtime
"""

from __future__ import annotations

import asyncio
import random
import tempfile
from pathlib import Path

from aegis import Action, Policy, RiskLevel, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.core.policy import PolicyDecision
from aegis.core.result import Result, ResultStatus
from aegis.runtime.approval import ApprovalHandler

# -- ANSI helpers ----------------------------------------------------------

BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"

POLICY_YAML = """\
version: "1"
defaults:
  risk_level: medium
  approval: approve

rules:
  - name: read_ops
    match: { type: "read" }
    risk_level: low
    approval: auto

  - name: high_risk_write
    match: { type: "write", target: "production_db" }
    risk_level: high
    approval: approve

  - name: delete_ops
    match: { type: "delete" }
    risk_level: critical
    approval: approve
"""


# ---------------------------------------------------------------------------
# Simulated Slack Approval Handler
# ---------------------------------------------------------------------------


class SlackApprovalHandler(ApprovalHandler):
    """Approval handler that simulates sending a Slack message with
    Approve / Deny buttons and waiting for a user response.

    In a real implementation you would:
    1. POST to the Slack Web API (chat.postMessage) with a Block Kit
       message containing interactive buttons.
    2. Expose a webhook endpoint (e.g. via FastAPI) that Slack calls
       when a user clicks a button.
    3. Correlate the callback to the pending approval via a unique
       request_id.

    This demo replaces the network round-trip with an asyncio.sleep
    and a random approval/denial so you can see the full flow without
    needing a Slack workspace.
    """

    def __init__(
        self,
        channel: str = "#approvals",
        timeout_seconds: float = 30.0,
        *,
        simulated_response: bool | None = None,
    ) -> None:
        self.channel = channel
        self.timeout_seconds = timeout_seconds
        # None = random; True/False = force a specific outcome
        self._simulated_response = simulated_response

    # -- real implementation sketch (commented out) -------------------------
    #
    # async def _post_slack_message(self, decision: PolicyDecision) -> str:
    #     """Post a Block Kit message and return its ``ts`` (message ID).
    #
    #     from slack_sdk.web.async_client import AsyncWebClient
    #     client = AsyncWebClient(token=os.environ["SLACK_BOT_TOKEN"])
    #     resp = await client.chat_postMessage(
    #         channel=self.channel,
    #         blocks=[
    #             {
    #                 "type": "section",
    #                 "text": {
    #                     "type": "mrkdwn",
    #                     "text": (
    #                         f"*Approval Required*\n"
    #                         f">Action: `{decision.action.type}`\n"
    #                         f">Target: `{decision.action.target}`\n"
    #                         f">Risk:   `{decision.risk_level.name}`\n"
    #                         f">Rule:   `{decision.matched_rule}`"
    #                     ),
    #                 },
    #             },
    #             {
    #                 "type": "actions",
    #                 "elements": [
    #                     {
    #                         "type": "button",
    #                         "text": {"type": "plain_text", "text": "Approve"},
    #                         "style": "primary",
    #                         "action_id": "approve",
    #                         "value": request_id,
    #                     },
    #                     {
    #                         "type": "button",
    #                         "text": {"type": "plain_text", "text": "Deny"},
    #                         "style": "danger",
    #                         "action_id": "deny",
    #                         "value": request_id,
    #                     },
    #                 ],
    #             },
    #         ],
    #         text="Aegis approval request",  # fallback for notifications
    #     )
    #     return resp["ts"]
    #     """
    #
    # async def _wait_for_callback(self, request_id: str) -> bool:
    #     """Block until the webhook handler sets the result for request_id,
    #     or raise asyncio.TimeoutError after self.timeout_seconds.
    #
    #     In production you would use an asyncio.Event per request_id,
    #     stored in a shared dict and set by your webhook handler.
    #     """
    #     ...

    async def request_approval(self, decision: PolicyDecision) -> bool:
        """Simulate the full Slack approval round-trip."""
        action = decision.action

        # 1. "Send" a Slack message
        print()
        chan = f"{BLUE}{self.channel}{RESET}"
        print(f"  {CYAN}{BOLD}[SLACK]{RESET}  Posting approval request to {chan}")
        print(f"  {CYAN}{BOLD}[SLACK]{RESET}  {DIM}-----------------------------------{RESET}")
        print(f"  {CYAN}{BOLD}[SLACK]{RESET}  {BOLD}Approval Required{RESET}")
        print(f"  {CYAN}{BOLD}[SLACK]{RESET}    Action:  {YELLOW}{action.type}{RESET}")
        print(f"  {CYAN}{BOLD}[SLACK]{RESET}    Target:  {YELLOW}{action.target}{RESET}")
        risk = f"{_risk_color(decision.risk_level)}{decision.risk_level.name}{RESET}"
        print(f"  {CYAN}{BOLD}[SLACK]{RESET}    Risk:    {risk}")
        print(f"  {CYAN}{BOLD}[SLACK]{RESET}    Rule:    {DIM}{decision.matched_rule}{RESET}")
        if action.description:
            print(f"  {CYAN}{BOLD}[SLACK]{RESET}    Desc:    {DIM}{action.description}{RESET}")
        print(f"  {CYAN}{BOLD}[SLACK]{RESET}    Timeout: {self.timeout_seconds}s")
        print(f"  {CYAN}{BOLD}[SLACK]{RESET}    {GREEN}[ Approve ]{RESET}  {RED}[ Deny ]{RESET}")
        print(f"  {CYAN}{BOLD}[SLACK]{RESET}  {DIM}-----------------------------------{RESET}")

        # 2. Wait for a simulated button click
        delay = random.uniform(0.5, 2.0)
        print(f"  {CYAN}{BOLD}[SLACK]{RESET}  Waiting for response ...", end="", flush=True)
        await asyncio.sleep(delay)

        approved = (
            self._simulated_response
            if self._simulated_response is not None
            else random.random() < 0.7  # 70% chance of approval
        )

        # 3. Print the result
        if approved:
            print(f"  {GREEN}{BOLD}APPROVED{RESET}  ({delay:.1f}s)")
        else:
            print(f"  {RED}{BOLD}DENIED{RESET}  ({delay:.1f}s)")

        return approved


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _risk_color(level: RiskLevel) -> str:
    return {
        RiskLevel.LOW: GREEN,
        RiskLevel.MEDIUM: YELLOW,
        RiskLevel.HIGH: RED,
        RiskLevel.CRITICAL: f"{RED}{BOLD}",
    }.get(level, RESET)


class NoopExecutor(BaseExecutor):
    """Executor that simply succeeds. Focus is on the approval flow."""

    async def execute(self, action: Action) -> Result:
        print(f"    {MAGENTA}[EXEC]{RESET} Executing: {action.type} -> {action.target}")
        return Result(action=action, status=ResultStatus.SUCCESS)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def main() -> None:
    print(f"\n{'=' * 56}")
    print(f"  {BOLD}Slack Approval Handler Demo{RESET}")
    print(f"{'=' * 56}")

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as f:
        f.write(POLICY_YAML)
        policy_path = f.name

    policy = Policy.from_yaml(policy_path)

    # Wire the Slack handler into the runtime
    handler = SlackApprovalHandler(
        channel="#deploy-approvals",
        timeout_seconds=30.0,
    )

    async with Runtime(
        executor=NoopExecutor(),
        policy=policy,
        approval_handler=handler,
    ) as runtime:
        # -- Scenario 1: auto-approved (low risk, no Slack message) ---------
        print(f"\n  {BOLD}Scenario 1:{RESET} Low-risk read (auto-approved, no Slack)")
        print(f"  {DIM}{'—' * 48}{RESET}")
        result = await runtime.run_one(
            Action("read", "cache", description="Read cache stats")
        )
        print(f"    Result: {GREEN}{result.status.name}{RESET}")

        # -- Scenario 2: requires approval (forced approve) -----------------
        print(f"\n  {BOLD}Scenario 2:{RESET} High-risk write (Slack approval)")
        print(f"  {DIM}{'—' * 48}{RESET}")
        handler._simulated_response = True  # force approve for demo
        try:
            result = await runtime.run_one(
                Action(
                    "write",
                    "production_db",
                    description="Migrate user table schema",
                )
            )
            print(f"    Result: {GREEN}{result.status.name}{RESET}")
        except Exception as e:
            print(f"    Result: {RED}BLOCKED{RESET} -- {e}")

        # -- Scenario 3: requires approval (forced deny) --------------------
        print(f"\n  {BOLD}Scenario 3:{RESET} Critical delete (Slack denial)")
        print(f"  {DIM}{'—' * 48}{RESET}")
        handler._simulated_response = False  # force deny for demo
        try:
            result = await runtime.run_one(
                Action(
                    "delete",
                    "production_db",
                    description="Drop legacy audit logs",
                )
            )
            print(f"    Result: {GREEN}{result.status.name}{RESET}")
        except Exception as e:
            print(f"    Result: {RED}DENIED{RESET} -- {e}")

    print(f"\n{'=' * 56}")
    print(f"  {BOLD}Integration Notes{RESET}")
    print(f"{'=' * 56}")
    print(
        "  1. Subclass ApprovalHandler and implement request_approval().\n"
        "  2. Use the Slack SDK (slack_sdk) to post Block Kit messages.\n"
        "  3. Run a webhook server (e.g. FastAPI) to receive button clicks.\n"
        "  4. Pass your handler to Runtime(approval_handler=...).\n"
        "  5. Aegis calls your handler only when the policy requires approval.\n"
    )

    Path(policy_path).unlink(missing_ok=True)


if __name__ == "__main__":
    asyncio.run(main())
