"""Discord webhook-based approval handler.

Posts a rich embed message to a Discord channel via webhook and polls
a callback URL for the approval response.

Example::

    handler = DiscordApprovalHandler(
        webhook_url="https://discord.com/api/webhooks/...",
    )
    runtime = Runtime(executor=..., policy=..., approval_handler=handler)
"""

from __future__ import annotations

import logging
from typing import Any

from aegis.core.policy import PolicyDecision
from aegis.runtime.approval import ApprovalHandler

logger = logging.getLogger(__name__)

_RISK_COLOR = {
    "LOW": 0x2ECC71,  # green
    "MEDIUM": 0xF1C40F,  # yellow
    "HIGH": 0xE67E22,  # orange
    "CRITICAL": 0xE74C3C,  # red
}


def _require_httpx() -> Any:
    try:
        import httpx

        return httpx
    except ImportError:
        msg = "httpx is required for DiscordApprovalHandler: pip install 'agent-aegis[httpx]'"
        raise ImportError(msg) from None


def _build_embed(decision: PolicyDecision) -> dict[str, Any]:
    """Build a Discord embed for the approval request."""
    risk_name = decision.risk_level.name
    color = _RISK_COLOR.get(risk_name, 0x95A5A6)
    return {
        "title": "Aegis Approval Required",
        "color": color,
        "fields": [
            {"name": "Action", "value": f"`{decision.action.type}`", "inline": True},
            {"name": "Target", "value": f"`{decision.action.target}`", "inline": True},
            {"name": "Risk", "value": risk_name, "inline": True},
            {"name": "Rule", "value": f"`{decision.matched_rule}`", "inline": True},
        ],
        "footer": {"text": "Aegis Policy Engine"},
    }


class DiscordApprovalHandler(ApprovalHandler):
    """Post an approval request to Discord via webhook.

    The handler sends a rich embed to Discord using the provided webhook URL.
    If a ``callback_url`` is supplied, it then polls that URL for the approval
    decision (expecting ``{"approved": true/false}``).  Without a callback URL,
    the handler sends the notification and returns the ``default_approved`` value.

    Args:
        webhook_url: Discord webhook URL.
        callback_url: Optional URL to poll for the approval decision.
        timeout: Maximum seconds to wait for callback response (default 300).
        default_approved: Value to return when no callback URL is set.
    """

    def __init__(
        self,
        webhook_url: str,
        *,
        callback_url: str | None = None,
        timeout: float = 300.0,
        default_approved: bool = False,
    ) -> None:
        self._webhook_url = webhook_url
        self._callback_url = callback_url
        self._timeout = timeout
        self._default_approved = default_approved

    async def request_approval(self, decision: PolicyDecision) -> bool:
        """Post embed to Discord and optionally poll callback for response."""
        httpx = _require_httpx()

        embed = _build_embed(decision)
        payload: dict[str, Any] = {
            "embeds": [embed],
            "content": "**Approval Required** — please respond via the approval dashboard.",
        }

        try:
            async with httpx.AsyncClient() as client:
                # Send the webhook message
                resp = await client.post(
                    self._webhook_url,
                    json=payload,
                    timeout=30.0,
                )
                resp.raise_for_status()

                # If no callback URL, return the default
                if not self._callback_url:
                    return self._default_approved

                # Poll the callback URL for a decision
                poll_resp = await client.get(
                    self._callback_url,
                    timeout=self._timeout,
                )
                poll_resp.raise_for_status()
                data = poll_resp.json()
                return bool(data.get("approved", False))

        except Exception:
            logger.exception("Discord approval request failed")
            return False
