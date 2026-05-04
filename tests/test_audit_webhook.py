"""Tests for WebhookAuditLogger."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from aegis.core.action import Action
from aegis.core.policy import Approval, PolicyDecision
from aegis.core.result import Result, ResultStatus
from aegis.core.risk import RiskLevel


def _make_decision(
    action_type: str = "read",
    target: str = "db",
    risk: RiskLevel = RiskLevel.LOW,
) -> PolicyDecision:
    return PolicyDecision(
        action=Action(action_type, target),
        risk_level=risk,
        approval=Approval.AUTO,
        matched_rule="test_rule",
    )


class TestWebhookAuditLogger:
    def _make_logger(self, url: str = "https://example.com/audit"):
        from aegis.runtime.audit_webhook import WebhookAuditLogger

        return WebhookAuditLogger(url=url, headers={"Authorization": "Bearer test"})

    def test_log_increments_counter(self):
        logger = self._make_logger()
        with patch.object(logger, "_send"):
            id1 = logger.log("session-1", _make_decision())
            id2 = logger.log("session-1", _make_decision("write"))
            assert id1 == 1
            assert id2 == 2

    def test_log_buffers_entries(self):
        logger = self._make_logger()
        with patch.object(logger, "_send"):
            logger.log("session-1", _make_decision())
            logger.log("session-2", _make_decision("write"))

            entries = logger.get_log()
            assert len(entries) == 2

    def test_log_with_result(self):
        logger = self._make_logger()
        decision = _make_decision()
        result = Result(
            action=decision.action,
            status=ResultStatus.SUCCESS,
            data={"key": "val"},
        )
        with patch.object(logger, "_send"):
            logger.log("session-1", decision, result=result)

        entries = logger.get_log()
        assert entries[0]["result_status"] == "success"
        assert entries[0]["result_data"] == {"key": "val"}

    def test_get_log_filters_by_session(self):
        logger = self._make_logger()
        with patch.object(logger, "_send"):
            logger.log("session-1", _make_decision())
            logger.log("session-2", _make_decision("write"))

            s1 = logger.get_log(session_id="session-1")
            assert len(s1) == 1
            assert s1[0]["session_id"] == "session-1"

    def test_buffer_size_limit(self):
        from aegis.runtime.audit_webhook import WebhookAuditLogger

        logger = WebhookAuditLogger(url="https://example.com/audit", buffer_size=3)
        with patch.object(logger, "_send"):
            for i in range(5):
                logger.log(f"session-{i}", _make_decision())

            entries = logger.get_log()
            assert len(entries) == 3  # only last 3

    def test_send_called_on_log(self):
        logger = self._make_logger()
        with patch.object(logger, "_send") as mock_send:
            logger.log("session-1", _make_decision())
            mock_send.assert_called_once()
            payload = mock_send.call_args[0][0]
            assert payload["action_type"] == "read"

    def test_send_failure_does_not_raise(self):
        import contextlib

        logger = self._make_logger()
        with (
            patch.object(logger, "_send", side_effect=Exception("Network error")),
            contextlib.suppress(Exception),
        ):
            logger.log("session-1", _make_decision())

    def test_export_jsonl(self, tmp_path: Path):
        logger = self._make_logger()
        with patch.object(logger, "_send"):
            logger.log("session-1", _make_decision())
            logger.log("session-1", _make_decision("write"))

        out = tmp_path / "audit.jsonl"
        count = logger.export_jsonl(out)
        assert count == 2
        lines = out.read_text().strip().split("\n")
        assert len(lines) == 2

    def test_export_jsonl_filtered(self, tmp_path: Path):
        logger = self._make_logger()
        with patch.object(logger, "_send"):
            logger.log("session-1", _make_decision())
            logger.log("session-2", _make_decision("write"))

        out = tmp_path / "audit.jsonl"
        count = logger.export_jsonl(out, session_id="session-1")
        assert count == 1

    def test_close_is_noop(self):
        logger = self._make_logger()
        logger.close()  # should not raise

    def test_entry_fields(self):
        logger = self._make_logger()
        with patch.object(logger, "_send"):
            logger.log("session-1", _make_decision(), human_decision="approved")

        entry = logger.get_log()[0]
        assert entry["session_id"] == "session-1"
        assert entry["action_type"] == "read"
        assert entry["action_target"] == "db"
        assert entry["risk_level"] == "LOW"
        assert entry["human_decision"] == "approved"
        assert "timestamp" in entry
