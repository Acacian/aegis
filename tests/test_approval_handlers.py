"""Tests for platform-specific approval handlers (Slack, Discord, Telegram, Email)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aegis.core.action import Action
from aegis.core.policy import Approval, PolicyDecision
from aegis.core.risk import RiskLevel


@pytest.fixture()
def decision() -> PolicyDecision:
    return PolicyDecision(
        action=Action(
            "delete",
            "production_db",
            params={"table": "users"},
            description="Drop users table",
        ),
        risk_level=RiskLevel.CRITICAL,
        approval=Approval.APPROVE,
        matched_rule="delete_rule",
    )


@pytest.fixture()
def low_risk_decision() -> PolicyDecision:
    return PolicyDecision(
        action=Action("read", "cache"),
        risk_level=RiskLevel.LOW,
        approval=Approval.APPROVE,
        matched_rule="read_rule",
    )


# ---------------------------------------------------------------------------
# Helpers for httpx mocking
# ---------------------------------------------------------------------------


def _mock_httpx_client(responses: list[MagicMock]) -> tuple[MagicMock, AsyncMock]:
    """Create a mock httpx module and async client that returns responses in order.

    Returns (mock_httpx_module, mock_client).
    """
    mock_client = AsyncMock()

    # Queue up responses: first call gets responses[0], etc.
    if len(responses) == 1:
        mock_client.post = AsyncMock(return_value=responses[0])
        mock_client.get = AsyncMock(return_value=responses[0])
    else:
        mock_client.post = AsyncMock(side_effect=responses)
        mock_client.get = AsyncMock(side_effect=responses[1:] if len(responses) > 1 else responses)

    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    mock_httpx = MagicMock()
    mock_httpx.AsyncClient.return_value = mock_client
    return mock_httpx, mock_client


def _json_response(data: dict, status_code: int = 200) -> MagicMock:
    """Create a mock response."""
    resp = MagicMock()
    resp.json.return_value = data
    resp.status_code = status_code
    resp.raise_for_status = MagicMock()
    return resp


def _ok_response() -> MagicMock:
    """Create a 204-style response (no body)."""
    resp = MagicMock()
    resp.status_code = 204
    resp.raise_for_status = MagicMock()
    return resp


# =========================================================================
# SLACK
# =========================================================================


class TestSlackApprovalHandler:
    """Tests for SlackApprovalHandler."""

    def test_import(self) -> None:
        from aegis.runtime.approval_slack import SlackApprovalHandler

        handler = SlackApprovalHandler(token="xoxb-test", channel="#approvals")
        assert handler is not None

    @pytest.mark.asyncio
    async def test_approved_via_thread_reply(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_slack import SlackApprovalHandler

        handler = SlackApprovalHandler(
            token="xoxb-test",
            channel="#approvals",
            timeout=10,
            poll_interval=0.01,
        )

        post_resp = _json_response({"ok": True, "ts": "1234.5678", "channel": "C123"})
        replies_resp = _json_response(
            {
                "ok": True,
                "messages": [
                    {"text": "Approval required", "ts": "1234.5678"},
                    {"text": "approve", "ts": "1234.5679"},
                ],
            }
        )

        mock_httpx, mock_client = _mock_httpx_client([post_resp])
        mock_client.get = AsyncMock(return_value=replies_resp)

        with patch("aegis.runtime.approval_slack._require_httpx", return_value=mock_httpx):
            result = await handler.request_approval(decision)

        assert result is True

    @pytest.mark.asyncio
    async def test_denied_via_thread_reply(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_slack import SlackApprovalHandler

        handler = SlackApprovalHandler(
            token="xoxb-test",
            channel="#approvals",
            timeout=10,
            poll_interval=0.01,
        )

        post_resp = _json_response({"ok": True, "ts": "1234.5678", "channel": "C123"})
        replies_resp = _json_response(
            {
                "ok": True,
                "messages": [
                    {"text": "Approval required", "ts": "1234.5678"},
                    {"text": "deny this action", "ts": "1234.5679"},
                ],
            }
        )

        mock_httpx, mock_client = _mock_httpx_client([post_resp])
        mock_client.get = AsyncMock(return_value=replies_resp)

        with patch("aegis.runtime.approval_slack._require_httpx", return_value=mock_httpx):
            result = await handler.request_approval(decision)

        assert result is False

    @pytest.mark.asyncio
    async def test_post_failure_returns_false(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_slack import SlackApprovalHandler

        handler = SlackApprovalHandler(
            token="xoxb-test",
            channel="#approvals",
        )

        post_resp = _json_response({"ok": False, "error": "channel_not_found"})
        mock_httpx, _ = _mock_httpx_client([post_resp])

        with patch("aegis.runtime.approval_slack._require_httpx", return_value=mock_httpx):
            result = await handler.request_approval(decision)

        assert result is False

    @pytest.mark.asyncio
    async def test_network_error_returns_false(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_slack import SlackApprovalHandler

        handler = SlackApprovalHandler(token="xoxb-test", channel="#approvals")

        mock_httpx = MagicMock()
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=ConnectionError("network down"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_httpx.AsyncClient.return_value = mock_client

        with patch("aegis.runtime.approval_slack._require_httpx", return_value=mock_httpx):
            result = await handler.request_approval(decision)

        assert result is False

    @pytest.mark.asyncio
    async def test_timeout_returns_false(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_slack import SlackApprovalHandler

        handler = SlackApprovalHandler(
            token="xoxb-test",
            channel="#approvals",
            timeout=0.02,
            poll_interval=0.01,
        )

        post_resp = _json_response({"ok": True, "ts": "1234.5678", "channel": "C123"})
        # Replies never contain approve/deny
        no_reply = _json_response(
            {"ok": True, "messages": [{"text": "Approval required", "ts": "1234.5678"}]}
        )

        mock_httpx, mock_client = _mock_httpx_client([post_resp])
        mock_client.get = AsyncMock(return_value=no_reply)

        with patch("aegis.runtime.approval_slack._require_httpx", return_value=mock_httpx):
            result = await handler.request_approval(decision)

        assert result is False

    @pytest.mark.asyncio
    async def test_payload_contains_block_kit(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_slack import SlackApprovalHandler

        handler = SlackApprovalHandler(
            token="xoxb-test",
            channel="#approvals",
            timeout=10,
            poll_interval=0.01,
        )

        post_resp = _json_response({"ok": True, "ts": "1234.5678", "channel": "C123"})
        replies_resp = _json_response(
            {
                "ok": True,
                "messages": [
                    {"text": "Approval required", "ts": "1234.5678"},
                    {"text": "approve", "ts": "1234.5679"},
                ],
            }
        )

        mock_httpx, mock_client = _mock_httpx_client([post_resp])
        mock_client.get = AsyncMock(return_value=replies_resp)

        with patch("aegis.runtime.approval_slack._require_httpx", return_value=mock_httpx):
            await handler.request_approval(decision)

        call_kwargs = mock_client.post.call_args
        payload = call_kwargs.kwargs["json"]
        assert "blocks" in payload
        assert payload["channel"] == "#approvals"
        # Verify blocks contain action info
        blocks_str = str(payload["blocks"])
        assert "delete" in blocks_str
        assert "production_db" in blocks_str
        assert "CRITICAL" in blocks_str


# =========================================================================
# DISCORD
# =========================================================================


class TestDiscordApprovalHandler:
    """Tests for DiscordApprovalHandler."""

    def test_import(self) -> None:
        from aegis.runtime.approval_discord import DiscordApprovalHandler

        handler = DiscordApprovalHandler(webhook_url="https://discord.com/api/webhooks/test")
        assert handler is not None

    @pytest.mark.asyncio
    async def test_no_callback_returns_default_false(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_discord import DiscordApprovalHandler

        handler = DiscordApprovalHandler(
            webhook_url="https://discord.com/api/webhooks/test",
        )

        webhook_resp = _ok_response()
        mock_httpx, _ = _mock_httpx_client([webhook_resp])

        with patch("aegis.runtime.approval_discord._require_httpx", return_value=mock_httpx):
            result = await handler.request_approval(decision)

        assert result is False

    @pytest.mark.asyncio
    async def test_no_callback_returns_default_true(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_discord import DiscordApprovalHandler

        handler = DiscordApprovalHandler(
            webhook_url="https://discord.com/api/webhooks/test",
            default_approved=True,
        )

        webhook_resp = _ok_response()
        mock_httpx, _ = _mock_httpx_client([webhook_resp])

        with patch("aegis.runtime.approval_discord._require_httpx", return_value=mock_httpx):
            result = await handler.request_approval(decision)

        assert result is True

    @pytest.mark.asyncio
    async def test_callback_approved(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_discord import DiscordApprovalHandler

        handler = DiscordApprovalHandler(
            webhook_url="https://discord.com/api/webhooks/test",
            callback_url="https://example.com/callback/123",
        )

        webhook_resp = _ok_response()
        callback_resp = _json_response({"approved": True})

        mock_httpx, mock_client = _mock_httpx_client([webhook_resp])
        mock_client.get = AsyncMock(return_value=callback_resp)

        with patch("aegis.runtime.approval_discord._require_httpx", return_value=mock_httpx):
            result = await handler.request_approval(decision)

        assert result is True

    @pytest.mark.asyncio
    async def test_callback_denied(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_discord import DiscordApprovalHandler

        handler = DiscordApprovalHandler(
            webhook_url="https://discord.com/api/webhooks/test",
            callback_url="https://example.com/callback/123",
        )

        webhook_resp = _ok_response()
        callback_resp = _json_response({"approved": False})

        mock_httpx, mock_client = _mock_httpx_client([webhook_resp])
        mock_client.get = AsyncMock(return_value=callback_resp)

        with patch("aegis.runtime.approval_discord._require_httpx", return_value=mock_httpx):
            result = await handler.request_approval(decision)

        assert result is False

    @pytest.mark.asyncio
    async def test_network_error_returns_false(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_discord import DiscordApprovalHandler

        handler = DiscordApprovalHandler(
            webhook_url="https://discord.com/api/webhooks/test",
        )

        mock_httpx = MagicMock()
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=ConnectionError("network down"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_httpx.AsyncClient.return_value = mock_client

        with patch("aegis.runtime.approval_discord._require_httpx", return_value=mock_httpx):
            result = await handler.request_approval(decision)

        assert result is False

    @pytest.mark.asyncio
    async def test_embed_payload_format(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_discord import DiscordApprovalHandler

        handler = DiscordApprovalHandler(
            webhook_url="https://discord.com/api/webhooks/test",
        )

        webhook_resp = _ok_response()
        mock_httpx, mock_client = _mock_httpx_client([webhook_resp])

        with patch("aegis.runtime.approval_discord._require_httpx", return_value=mock_httpx):
            await handler.request_approval(decision)

        call_kwargs = mock_client.post.call_args
        payload = call_kwargs.kwargs["json"]
        assert "embeds" in payload
        embed = payload["embeds"][0]
        assert embed["title"] == "Aegis Approval Required"
        # CRITICAL = red
        assert embed["color"] == 0xE74C3C
        field_names = [f["name"] for f in embed["fields"]]
        assert "Action" in field_names
        assert "Target" in field_names
        assert "Risk" in field_names

    @pytest.mark.asyncio
    async def test_embed_color_by_risk(self, low_risk_decision: PolicyDecision) -> None:
        from aegis.runtime.approval_discord import DiscordApprovalHandler

        handler = DiscordApprovalHandler(
            webhook_url="https://discord.com/api/webhooks/test",
        )

        webhook_resp = _ok_response()
        mock_httpx, mock_client = _mock_httpx_client([webhook_resp])

        with patch("aegis.runtime.approval_discord._require_httpx", return_value=mock_httpx):
            await handler.request_approval(low_risk_decision)

        payload = mock_client.post.call_args.kwargs["json"]
        embed = payload["embeds"][0]
        # LOW = green
        assert embed["color"] == 0x2ECC71


# =========================================================================
# TELEGRAM
# =========================================================================


class TestTelegramApprovalHandler:
    """Tests for TelegramApprovalHandler."""

    def test_import(self) -> None:
        from aegis.runtime.approval_telegram import TelegramApprovalHandler

        handler = TelegramApprovalHandler(bot_token="123:ABC", chat_id="-100123")
        assert handler is not None

    @pytest.mark.asyncio
    async def test_approved_via_callback_query(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_telegram import TelegramApprovalHandler

        handler = TelegramApprovalHandler(
            bot_token="123:ABC",
            chat_id="-100123",
            timeout=10,
            poll_interval=0.01,
        )

        send_resp = _json_response({"ok": True, "result": {"message_id": 42}})
        updates_resp = _json_response(
            {
                "ok": True,
                "result": [
                    {
                        "update_id": 100,
                        "callback_query": {
                            "id": "cb_1",
                            "data": "aegis_approve",
                            "message": {"message_id": 42},
                        },
                    }
                ],
            }
        )
        answer_resp = _json_response({"ok": True})

        mock_httpx, mock_client = _mock_httpx_client([send_resp, answer_resp])
        mock_client.get = AsyncMock(return_value=updates_resp)

        with patch("aegis.runtime.approval_telegram._require_httpx", return_value=mock_httpx):
            result = await handler.request_approval(decision)

        assert result is True

    @pytest.mark.asyncio
    async def test_denied_via_callback_query(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_telegram import TelegramApprovalHandler

        handler = TelegramApprovalHandler(
            bot_token="123:ABC",
            chat_id="-100123",
            timeout=10,
            poll_interval=0.01,
        )

        send_resp = _json_response({"ok": True, "result": {"message_id": 42}})
        updates_resp = _json_response(
            {
                "ok": True,
                "result": [
                    {
                        "update_id": 100,
                        "callback_query": {
                            "id": "cb_1",
                            "data": "aegis_deny",
                            "message": {"message_id": 42},
                        },
                    }
                ],
            }
        )
        answer_resp = _json_response({"ok": True})

        mock_httpx, mock_client = _mock_httpx_client([send_resp, answer_resp])
        mock_client.get = AsyncMock(return_value=updates_resp)

        with patch("aegis.runtime.approval_telegram._require_httpx", return_value=mock_httpx):
            result = await handler.request_approval(decision)

        assert result is False

    @pytest.mark.asyncio
    async def test_sendmessage_failure_returns_false(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_telegram import TelegramApprovalHandler

        handler = TelegramApprovalHandler(
            bot_token="123:ABC",
            chat_id="-100123",
        )

        send_resp = _json_response({"ok": False, "description": "Bad Request"})
        mock_httpx, _ = _mock_httpx_client([send_resp])

        with patch("aegis.runtime.approval_telegram._require_httpx", return_value=mock_httpx):
            result = await handler.request_approval(decision)

        assert result is False

    @pytest.mark.asyncio
    async def test_network_error_returns_false(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_telegram import TelegramApprovalHandler

        handler = TelegramApprovalHandler(bot_token="123:ABC", chat_id="-100123")

        mock_httpx = MagicMock()
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=ConnectionError("network down"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_httpx.AsyncClient.return_value = mock_client

        with patch("aegis.runtime.approval_telegram._require_httpx", return_value=mock_httpx):
            result = await handler.request_approval(decision)

        assert result is False

    @pytest.mark.asyncio
    async def test_timeout_returns_false(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_telegram import TelegramApprovalHandler

        handler = TelegramApprovalHandler(
            bot_token="123:ABC",
            chat_id="-100123",
            timeout=0.02,
            poll_interval=0.01,
        )

        send_resp = _json_response({"ok": True, "result": {"message_id": 42}})
        # No matching callback queries
        empty_updates = _json_response({"ok": True, "result": []})

        mock_httpx, mock_client = _mock_httpx_client([send_resp])
        mock_client.get = AsyncMock(return_value=empty_updates)

        with patch("aegis.runtime.approval_telegram._require_httpx", return_value=mock_httpx):
            result = await handler.request_approval(decision)

        assert result is False

    @pytest.mark.asyncio
    async def test_payload_contains_inline_keyboard(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_telegram import TelegramApprovalHandler

        handler = TelegramApprovalHandler(
            bot_token="123:ABC",
            chat_id="-100123",
            timeout=10,
            poll_interval=0.01,
        )

        send_resp = _json_response({"ok": True, "result": {"message_id": 42}})
        updates_resp = _json_response(
            {
                "ok": True,
                "result": [
                    {
                        "update_id": 100,
                        "callback_query": {
                            "id": "cb_1",
                            "data": "aegis_approve",
                            "message": {"message_id": 42},
                        },
                    }
                ],
            }
        )
        answer_resp = _json_response({"ok": True})

        mock_httpx, mock_client = _mock_httpx_client([send_resp, answer_resp])
        mock_client.get = AsyncMock(return_value=updates_resp)

        with patch("aegis.runtime.approval_telegram._require_httpx", return_value=mock_httpx):
            await handler.request_approval(decision)

        # First post call is sendMessage
        first_call = mock_client.post.call_args_list[0]
        payload = first_call.kwargs["json"]
        assert payload["chat_id"] == "-100123"
        assert payload["parse_mode"] == "HTML"
        assert "inline_keyboard" in payload["reply_markup"]
        buttons = payload["reply_markup"]["inline_keyboard"][0]
        assert any(b["text"] == "Approve" for b in buttons)
        assert any(b["text"] == "Deny" for b in buttons)

    @pytest.mark.asyncio
    async def test_ignores_unrelated_callback(self, decision: PolicyDecision) -> None:
        """Callback queries for different messages are ignored."""
        from aegis.runtime.approval_telegram import TelegramApprovalHandler

        handler = TelegramApprovalHandler(
            bot_token="123:ABC",
            chat_id="-100123",
            timeout=0.03,
            poll_interval=0.01,
        )

        send_resp = _json_response({"ok": True, "result": {"message_id": 42}})
        # Callback for a different message_id
        unrelated_updates = _json_response(
            {
                "ok": True,
                "result": [
                    {
                        "update_id": 100,
                        "callback_query": {
                            "id": "cb_1",
                            "data": "aegis_approve",
                            "message": {"message_id": 999},
                        },
                    }
                ],
            }
        )

        mock_httpx, mock_client = _mock_httpx_client([send_resp])
        mock_client.get = AsyncMock(return_value=unrelated_updates)

        with patch("aegis.runtime.approval_telegram._require_httpx", return_value=mock_httpx):
            result = await handler.request_approval(decision)

        # Should time out and return False since no matching callback
        assert result is False


# =========================================================================
# EMAIL
# =========================================================================


class TestEmailApprovalHandler:
    """Tests for EmailApprovalHandler."""

    def test_import(self) -> None:
        from aegis.runtime.approval_email import EmailApprovalHandler

        handler = EmailApprovalHandler(
            smtp_host="smtp.example.com",
            smtp_port=587,
            sender="aegis@example.com",
            recipient="admin@example.com",
        )
        assert handler is not None

    @pytest.mark.asyncio
    async def test_sends_email_returns_false_by_default(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_email import EmailApprovalHandler

        handler = EmailApprovalHandler(
            smtp_host="smtp.example.com",
            smtp_port=587,
            sender="aegis@example.com",
            recipient="admin@example.com",
            username="user",
            password="pass",
        )

        with patch("aegis.runtime.approval_email.smtplib") as mock_smtplib:
            mock_smtp = MagicMock()
            mock_smtplib.SMTP.return_value = mock_smtp

            result = await handler.request_approval(decision)

        assert result is False
        mock_smtp.starttls.assert_called_once()
        mock_smtp.login.assert_called_once_with("user", "pass")
        mock_smtp.sendmail.assert_called_once()
        mock_smtp.quit.assert_called_once()

    @pytest.mark.asyncio
    async def test_default_approved_true(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_email import EmailApprovalHandler

        handler = EmailApprovalHandler(
            smtp_host="smtp.example.com",
            smtp_port=587,
            sender="aegis@example.com",
            recipient="admin@example.com",
            default_approved=True,
        )

        with patch("aegis.runtime.approval_email.smtplib") as mock_smtplib:
            mock_smtp = MagicMock()
            mock_smtplib.SMTP.return_value = mock_smtp

            result = await handler.request_approval(decision)

        assert result is True

    @pytest.mark.asyncio
    async def test_smtp_failure_returns_false(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_email import EmailApprovalHandler

        handler = EmailApprovalHandler(
            smtp_host="smtp.example.com",
            smtp_port=587,
            sender="aegis@example.com",
            recipient="admin@example.com",
            default_approved=True,  # Even with default True, failure returns False
        )

        with patch("aegis.runtime.approval_email.smtplib") as mock_smtplib:
            mock_smtplib.SMTP.side_effect = ConnectionRefusedError("refused")

            result = await handler.request_approval(decision)

        assert result is False

    @pytest.mark.asyncio
    async def test_email_contains_action_details(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_email import EmailApprovalHandler

        handler = EmailApprovalHandler(
            smtp_host="smtp.example.com",
            smtp_port=587,
            sender="aegis@example.com",
            recipient="admin@example.com",
        )

        with patch("aegis.runtime.approval_email.smtplib") as mock_smtplib:
            mock_smtp = MagicMock()
            mock_smtplib.SMTP.return_value = mock_smtp

            await handler.request_approval(decision)

        # Get the email body from sendmail call
        call_args = mock_smtp.sendmail.call_args
        raw_email = call_args[0][2]  # Third positional arg is the message string
        assert "delete" in raw_email
        assert "production_db" in raw_email
        assert "CRITICAL" in raw_email
        assert "delete_rule" in raw_email

    @pytest.mark.asyncio
    async def test_email_subject_format(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_email import EmailApprovalHandler

        handler = EmailApprovalHandler(
            smtp_host="smtp.example.com",
            smtp_port=587,
            sender="aegis@example.com",
            recipient="admin@example.com",
        )

        with patch("aegis.runtime.approval_email.smtplib") as mock_smtplib:
            mock_smtp = MagicMock()
            mock_smtplib.SMTP.return_value = mock_smtp

            await handler.request_approval(decision)

        raw_email = mock_smtp.sendmail.call_args[0][2]
        assert "Subject:" in raw_email
        assert "[Aegis]" in raw_email
        assert "delete" in raw_email
        assert "production_db" in raw_email

    @pytest.mark.asyncio
    async def test_email_with_approve_deny_urls(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_email import EmailApprovalHandler

        handler = EmailApprovalHandler(
            smtp_host="smtp.example.com",
            smtp_port=587,
            sender="aegis@example.com",
            recipient="admin@example.com",
            approve_url="https://example.com/approve/123",
            deny_url="https://example.com/deny/123",
        )

        with patch("aegis.runtime.approval_email.smtplib") as mock_smtplib:
            mock_smtp = MagicMock()
            mock_smtplib.SMTP.return_value = mock_smtp

            await handler.request_approval(decision)

        raw_email = mock_smtp.sendmail.call_args[0][2]
        assert "https://example.com/approve/123" in raw_email
        assert "https://example.com/deny/123" in raw_email

    @pytest.mark.asyncio
    async def test_no_tls(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_email import EmailApprovalHandler

        handler = EmailApprovalHandler(
            smtp_host="localhost",
            smtp_port=25,
            sender="aegis@example.com",
            recipient="admin@example.com",
            use_tls=False,
        )

        with patch("aegis.runtime.approval_email.smtplib") as mock_smtplib:
            mock_smtp = MagicMock()
            mock_smtplib.SMTP.return_value = mock_smtp

            await handler.request_approval(decision)

        mock_smtp.starttls.assert_not_called()
        mock_smtp.sendmail.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_auth(self, decision: PolicyDecision) -> None:
        from aegis.runtime.approval_email import EmailApprovalHandler

        handler = EmailApprovalHandler(
            smtp_host="localhost",
            smtp_port=25,
            sender="aegis@example.com",
            recipient="admin@example.com",
            use_tls=False,
        )

        with patch("aegis.runtime.approval_email.smtplib") as mock_smtplib:
            mock_smtp = MagicMock()
            mock_smtplib.SMTP.return_value = mock_smtp

            await handler.request_approval(decision)

        mock_smtp.login.assert_not_called()


# =========================================================================
# CROSS-HANDLER: Interface compliance
# =========================================================================


class TestInterfaceCompliance:
    """Verify all handlers implement ApprovalHandler correctly."""

    def test_slack_is_approval_handler(self) -> None:
        from aegis.runtime.approval_slack import SlackApprovalHandler

        assert issubclass(SlackApprovalHandler, ApprovalHandler)

    def test_discord_is_approval_handler(self) -> None:
        from aegis.runtime.approval_discord import DiscordApprovalHandler

        assert issubclass(DiscordApprovalHandler, ApprovalHandler)

    def test_telegram_is_approval_handler(self) -> None:
        from aegis.runtime.approval_telegram import TelegramApprovalHandler

        assert issubclass(TelegramApprovalHandler, ApprovalHandler)

    def test_email_is_approval_handler(self) -> None:
        from aegis.runtime.approval_email import EmailApprovalHandler

        assert issubclass(EmailApprovalHandler, ApprovalHandler)


# We need ApprovalHandler for the interface tests
from aegis.runtime.approval import ApprovalHandler  # noqa: E402
