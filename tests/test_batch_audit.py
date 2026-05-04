"""Tests for BatchAuditLogger."""

from __future__ import annotations

from pathlib import Path

from aegis.core.action import Action
from aegis.core.policy import Approval, PolicyDecision
from aegis.core.result import Result, ResultStatus
from aegis.core.risk import RiskLevel
from aegis.runtime.batch_audit import BatchAuditLogger


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


class TestBatchAuditLogger:
    def test_buffers_entries(self, tmp_path: Path):
        db = tmp_path / "test.db"
        logger = BatchAuditLogger(db_path=db, batch_size=10)

        logger.log("session-1", _make_decision())
        logger.log("session-1", _make_decision("write"))

        assert logger.pending == 2
        # Not yet written to DB
        entries = logger.get_log()
        assert len(entries) == 0  # nothing flushed yet

        logger.close()

    def test_flush_writes_to_db(self, tmp_path: Path):
        db = tmp_path / "test.db"
        logger = BatchAuditLogger(db_path=db, batch_size=100)

        logger.log("session-1", _make_decision())
        logger.log("session-1", _make_decision("write"))
        assert logger.pending == 2

        flushed = logger.flush()
        assert flushed == 2
        assert logger.pending == 0

        entries = logger.get_log()
        assert len(entries) == 2
        logger.close()

    def test_auto_flush_on_batch_size(self, tmp_path: Path):
        db = tmp_path / "test.db"
        logger = BatchAuditLogger(db_path=db, batch_size=3)

        logger.log("s1", _make_decision())
        logger.log("s1", _make_decision())
        assert logger.pending == 2

        # Third entry triggers flush
        logger.log("s1", _make_decision())
        assert logger.pending == 0

        entries = logger.get_log()
        assert len(entries) == 3
        logger.close()

    def test_close_flushes_remaining(self, tmp_path: Path):
        db = tmp_path / "test.db"
        logger = BatchAuditLogger(db_path=db, batch_size=100)

        logger.log("session-1", _make_decision())
        logger.log("session-1", _make_decision("write"))
        assert logger.pending == 2

        logger.close()
        # Reopen to verify data was written
        reader = BatchAuditLogger(db_path=db, batch_size=100)
        entries = reader.get_log()
        assert len(entries) == 2
        reader.close()

    def test_log_returns_zero(self, tmp_path: Path):
        db = tmp_path / "test.db"
        logger = BatchAuditLogger(db_path=db, batch_size=100)

        row_id = logger.log("session-1", _make_decision())
        assert row_id == 0  # placeholder, not actual row id
        logger.close()

    def test_log_with_result(self, tmp_path: Path):
        db = tmp_path / "test.db"
        logger = BatchAuditLogger(db_path=db, batch_size=100)
        decision = _make_decision()
        result = Result(
            action=decision.action,
            status=ResultStatus.SUCCESS,
            data={"key": "val"},
        )

        logger.log("session-1", decision, result=result)
        logger.flush()

        entries = logger.get_log()
        assert len(entries) == 1
        assert entries[0]["result_status"] == "success"
        logger.close()

    def test_flush_empty_buffer(self, tmp_path: Path):
        db = tmp_path / "test.db"
        logger = BatchAuditLogger(db_path=db, batch_size=100)

        flushed = logger.flush()
        assert flushed == 0
        logger.close()
