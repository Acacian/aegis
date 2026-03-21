"""Slack-based approval handler.

Posts an interactive Block Kit message to a Slack channel and polls for
a threaded reply containing "approve" or "deny".

Example::

    handler = SlackApprovalHandler(
        token="xoxb-...",
        channel="#approvals",
    )
    runtime = Runtime(executor=..., policy=..., approval_handler=handler)
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from aegis.core.policy import PolicyDecision
from aegis.runtime.approval import ApprovalHandler

logger = logging.getLogger(__name__)

_RISK_EMOJI = {
    "LOW": ":large_green_circle:",
    "MEDIUM": ":large_yellow_circle:",
    "HIGH": ":large_orange_circle:",
    "CRITICAL": ":red_circle:",
}


def _require_httpx() -> Any:
    try:
        import httpx

        return httpx
    except ImportError:
        msg = "httpx is required for SlackApprovalHandler: pip install 'agent-aegis[httpx]'"
        raise ImportError(msg) from None


def _build_blocks(decision: PolicyDecision) -> list[dict[str, Any]]:
    """Build Slack Block Kit blocks for the approval message."""
    risk_name = decision.risk_level.name
    emoji = _RISK_EMOJI.get(risk_name, ":white_circle:")
    return [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": ":shield: Aegis Approval Required",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Action:*\n`{decision.action.type}`"},
                {"type": "mrkdwn", "text": f"*Target:*\n`{decision.action.target}`"},
                {"type": "mrkdwn", "text": f"*Risk:*\n{emoji} {risk_name}"},
                {"type": "mrkdwn", "text": f"*Rule:*\n`{decision.matched_rule}`"},
            ],
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "Reply in thread with *approve* or *deny*.",
            },
        },
    ]


class SlackApprovalHandler(ApprovalHandler):
    """Post an approval request to Slack and wait for a threaded reply.

    The handler posts a Block Kit message via ``chat.postMessage``, then polls
    ``conversations.replies`` for a thread reply containing "approve" or "deny".

    Args:
        token: Slack Bot OAuth token (``xoxb-...``).
        channel: Channel ID or name to post the approval message to.
        timeout: Maximum seconds to wait for a reply (default 300).
        poll_interval: Seconds between reply polls (default 5).
    """

    SLACK_API = "https://slack.com/api"

    def __init__(
        self,
        token: str,
        channel: str,
        *,
        timeout: float = 300.0,
        poll_interval: float = 5.0,
    ) -> None:
        self._token = token
        self._channel = channel
        self._timeout = timeout
        self._poll_interval = poll_interval

    async def request_approval(self, decision: PolicyDecision) -> bool:
        """Post to Slack and poll for threaded approve/deny reply."""
        httpx = _require_httpx()

        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json; charset=utf-8",
        }

        blocks = _build_blocks(decision)
        fallback = (
            f"Approval required: {decision.action.type} -> "
            f"{decision.action.target} (risk: {decision.risk_level.name})"
        )

        try:
            async with httpx.AsyncClient() as client:
                # Post the approval message
                post_resp = await client.post(
                    f"{self.SLACK_API}/chat.postMessage",
                    headers=headers,
                    json={
                        "channel": self._channel,
                        "text": fallback,
                        "blocks": blocks,
                    },
                    timeout=30.0,
                )
                post_resp.raise_for_status()
                post_data = post_resp.json()

                if not post_data.get("ok"):
                    logger.error("Slack postMessage failed: %s", post_data.get("error"))
                    return False

                ts = post_data["ts"]
                channel_id = post_data["channel"]

                # Poll for threaded reply
                elapsed = 0.0
                while elapsed < self._timeout:
                    await asyncio.sleep(self._poll_interval)
                    elapsed += self._poll_interval

                    replies_resp = await client.get(
                        f"{self.SLACK_API}/conversations.replies",
                        headers=headers,
                        params={"channel": channel_id, "ts": ts},
                        timeout=30.0,
                    )
                    replies_resp.raise_for_status()
                    replies_data = replies_resp.json()

                    if not replies_data.get("ok"):
                        continue

                    # Skip the first message (the original post)
                    for msg in replies_data.get("messages", [])[1:]:
                        text = msg.get("text", "").strip().lower()
                        if "approve" in text:
                            return True
                        if "deny" in text:
                            return False

                logger.warning("Slack approval timed out after %.0fs", self._timeout)
                return False

        except Exception:
            logger.exception("Slack approval request failed")
            return False
