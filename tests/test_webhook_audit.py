"""Tests for WebhookAuditLogger."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from aegis.core.action import Action
from aegis.core.policy import Approval, PolicyDecision
from aegis.core.result import Result, ResultStatus
from aegis.core.risk import RiskLevel
from aegis.runtime.audit_webhook import WebhookAuditLogger


def _make_decision(
    action_type: str = "read",
    target: str = "crm",
) -> PolicyDecision:
    return PolicyDecision(
        action=Action(action_type, target),
        risk_level=RiskLevel.LOW,
        approval=Approval.AUTO,
    )


def test_log_returns_incrementing_id() -> None:
    with patch("aegis.runtime.audit_webhook._require_httpx") as mock_httpx:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=None)
        mock_httpx.return_value.Client.return_value = mock_client

        logger = WebhookAuditLogger(url="https://example.com/audit")
        d = _make_decision()

        id1 = logger.log("s1", d, result=Result(action=d.action, status=ResultStatus.SUCCESS))
        id2 = logger.log("s1", d, result=Result(action=d.action, status=ResultStatus.SUCCESS))

        assert id1 == 1
        assert id2 == 2


def test_log_buffers_entries() -> None:
    with patch("aegis.runtime.audit_webhook._require_httpx") as mock_httpx:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=None)
        mock_httpx.return_value.Client.return_value = mock_client

        logger = WebhookAuditLogger(url="https://example.com/audit")
        d = _make_decision()
        logger.log("s1", d, result=Result(action=d.action, status=ResultStatus.SUCCESS))
        logger.log("s2", d, result=Result(action=d.action, status=ResultStatus.SUCCESS))

        all_entries = logger.get_log()
        assert len(all_entries) == 2

        s1_entries = logger.get_log(session_id="s1")
        assert len(s1_entries) == 1


def test_log_sends_webhook() -> None:
    with patch("aegis.runtime.audit_webhook._require_httpx") as mock_httpx:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=None)
        mock_httpx.return_value.Client.return_value = mock_client

        logger = WebhookAuditLogger(
            url="https://example.com/audit",
            headers={"X-Token": "abc"},
        )
        d = _make_decision("delete", "db")
        logger.log(
            "s1",
            d,
            result=Result(action=d.action, status=ResultStatus.BLOCKED),
        )

        mock_client.post.assert_called_once()
        call_kwargs = mock_client.post.call_args
        assert call_kwargs.kwargs["json"]["action_type"] == "delete"
        assert call_kwargs.kwargs["headers"] == {"X-Token": "abc"}


def test_export_jsonl(tmp_path: Path) -> None:
    with patch("aegis.runtime.audit_webhook._require_httpx") as mock_httpx:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=None)
        mock_httpx.return_value.Client.return_value = mock_client

        logger = WebhookAuditLogger(url="https://example.com/audit")
        d = _make_decision()
        logger.log("s1", d, result=Result(action=d.action, status=ResultStatus.SUCCESS))

        out = tmp_path / "export.jsonl"
        count = logger.export_jsonl(out)
        assert count == 1
        assert out.exists()


def test_buffer_size_limit() -> None:
    with patch("aegis.runtime.audit_webhook._require_httpx") as mock_httpx:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=None)
        mock_httpx.return_value.Client.return_value = mock_client

        logger = WebhookAuditLogger(
            url="https://example.com/audit",
            buffer_size=5,
        )
        d = _make_decision()
        for _ in range(10):
            logger.log("s1", d, result=Result(action=d.action, status=ResultStatus.SUCCESS))

        entries = logger.get_log()
        assert len(entries) == 5  # Only last 5 kept


def test_close_is_noop() -> None:
    with patch("aegis.runtime.audit_webhook._require_httpx"):
        logger = WebhookAuditLogger(url="https://example.com/audit")
        logger.close()  # Should not raise
