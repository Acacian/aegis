"""Telegram Bot API-based approval handler.

Sends an inline keyboard message via the Telegram Bot API and polls
``getUpdates`` for a callback_query response.

Example::

    handler = TelegramApprovalHandler(
        bot_token="123456:ABC-DEF...",
        chat_id="-1001234567890",
    )
    runtime = Runtime(executor=..., policy=..., approval_handler=handler)
"""

from __future__ import annotations

import asyncio
import html
import logging
from typing import Any

from aegis.core.policy import PolicyDecision
from aegis.runtime.approval import ApprovalHandler

logger = logging.getLogger(__name__)

_RISK_EMOJI = {
    "LOW": "\u2705",  # green check
    "MEDIUM": "\u26a0\ufe0f",  # warning
    "HIGH": "\U0001f7e0",  # orange circle
    "CRITICAL": "\U0001f534",  # red circle
}


def _require_httpx() -> Any:
    try:
        import httpx

        return httpx
    except ImportError:
        msg = "httpx is required for TelegramApprovalHandler: pip install 'agent-aegis[httpx]'"
        raise ImportError(msg) from None


def _build_text(decision: PolicyDecision) -> str:
    """Build a formatted Telegram message for the approval request."""
    risk_name = decision.risk_level.name
    emoji = _RISK_EMOJI.get(risk_name, "")
    action_type = html.escape(decision.action.type)
    action_target = html.escape(decision.action.target)
    matched_rule = html.escape(decision.matched_rule)
    lines = [
        "<b>Aegis Approval Required</b>",
        "",
        f"<b>Action:</b> <code>{action_type}</code>",
        f"<b>Target:</b> <code>{action_target}</code>",
        f"<b>Risk:</b> {emoji} {risk_name}",
        f"<b>Rule:</b> <code>{matched_rule}</code>",
    ]
    if decision.action.description:
        lines.append(f"<b>Description:</b> {html.escape(decision.action.description)}")
    return "\n".join(lines)


def _build_inline_keyboard() -> dict[str, Any]:
    """Build Telegram inline keyboard with Approve/Deny buttons."""
    return {
        "inline_keyboard": [
            [
                {"text": "Approve", "callback_data": "aegis_approve"},
                {"text": "Deny", "callback_data": "aegis_deny"},
            ]
        ]
    }


class TelegramApprovalHandler(ApprovalHandler):
    """Send approval request via Telegram Bot API and poll for callback response.

    Posts a message with inline keyboard buttons to the specified chat,
    then polls ``getUpdates`` for a ``callback_query`` matching the message.

    Args:
        bot_token: Telegram Bot API token.
        chat_id: Target chat ID (group or user).
        timeout: Maximum seconds to wait for a response (default 300).
        poll_interval: Seconds between ``getUpdates`` polls (default 3).
    """

    TELEGRAM_API = "https://api.telegram.org"

    def __init__(
        self,
        bot_token: str,
        chat_id: str | int,
        *,
        timeout: float = 300.0,
        poll_interval: float = 3.0,
    ) -> None:
        self._bot_token = bot_token
        self._chat_id = str(chat_id)
        self._timeout = timeout
        self._poll_interval = poll_interval

    @property
    def _base_url(self) -> str:
        return f"{self.TELEGRAM_API}/bot{self._bot_token}"

    async def request_approval(self, decision: PolicyDecision) -> bool:
        """Send Telegram message with inline keyboard and poll for response."""
        httpx = _require_httpx()

        text = _build_text(decision)
        keyboard = _build_inline_keyboard()

        try:
            async with httpx.AsyncClient() as client:
                # Send the message with inline keyboard
                send_resp = await client.post(
                    f"{self._base_url}/sendMessage",
                    json={
                        "chat_id": self._chat_id,
                        "text": text,
                        "parse_mode": "HTML",
                        "reply_markup": keyboard,
                    },
                    timeout=30.0,
                )
                send_resp.raise_for_status()
                send_data = send_resp.json()

                if not send_data.get("ok"):
                    logger.error("Telegram sendMessage failed: %s", send_data)
                    return False

                message_id = send_data["result"]["message_id"]

                # Poll getUpdates for callback_query
                update_offset = 0
                elapsed = 0.0
                while elapsed < self._timeout:
                    await asyncio.sleep(self._poll_interval)
                    elapsed += self._poll_interval

                    params: dict[str, Any] = {"timeout": 1}
                    if update_offset:
                        params["offset"] = update_offset

                    updates_resp = await client.get(
                        f"{self._base_url}/getUpdates",
                        params=params,
                        timeout=30.0,
                    )
                    updates_resp.raise_for_status()
                    updates_data = updates_resp.json()

                    if not updates_data.get("ok"):
                        continue

                    for update in updates_data.get("result", []):
                        update_offset = update["update_id"] + 1
                        cb = update.get("callback_query")
                        if not cb:
                            continue
                        msg = cb.get("message", {})
                        if msg.get("message_id") != message_id:
                            continue

                        data = cb.get("data", "")
                        if data == "aegis_approve":
                            # Answer the callback query to remove spinner
                            await client.post(
                                f"{self._base_url}/answerCallbackQuery",
                                json={
                                    "callback_query_id": cb["id"],
                                    "text": "Approved",
                                },
                                timeout=10.0,
                            )
                            return True
                        if data == "aegis_deny":
                            await client.post(
                                f"{self._base_url}/answerCallbackQuery",
                                json={
                                    "callback_query_id": cb["id"],
                                    "text": "Denied",
                                },
                                timeout=10.0,
                            )
                            return False

                logger.warning("Telegram approval timed out after %.0fs", self._timeout)
                return False

        except Exception:
            logger.exception("Telegram approval request failed")
            return False
