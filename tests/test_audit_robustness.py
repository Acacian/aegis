"""Tests for audit logger edge cases: non-serializable params, concurrent writes, DB locking."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegis.core.action import Action
from aegis.core.policy import Approval, PolicyDecision
from aegis.core.result import Result, ResultStatus
from aegis.core.risk import RiskLevel
from aegis.runtime.audit import AuditLogger


def _decision(
    action_type: str = "read",
    target: str = "db",
    params: dict | None = None,
    risk: RiskLevel = RiskLevel.LOW,
    approval: Approval = Approval.AUTO,
) -> PolicyDecision:
    return PolicyDecision(
        action=Action(action_type, target, params=params or {}),
        risk_level=risk,
        approval=approval,
        matched_rule="test_rule",
    )


# -- Non-serializable params -----------------------------------------------


def test_non_serializable_params_do_not_crash(tmp_path: Path) -> None:
    """Params containing non-JSON-serializable objects should be logged safely."""
    logger = AuditLogger(db_path=tmp_path / "test.db")
    decision = _decision(params={"obj": object(), "func": lambda x: x})
    result = Result(action=decision.action, status=ResultStatus.SUCCESS)

    row_id = logger.log("sess", decision, result=result)
    assert row_id >= 1

    entries = logger.get_log()
    assert len(entries) == 1
    # The non-serializable objects should have been converted to strings
    params_json = entries[0]["action_params"]
    assert params_json is not None
    parsed = json.loads(str(params_json))
    assert "obj" in parsed
    assert "func" in parsed
    logger.close()


def test_non_serializable_result_data(tmp_path: Path) -> None:
    """Result.data with non-serializable content should be logged safely."""
    logger = AuditLogger(db_path=tmp_path / "test.db")
    decision = _decision()
    result = Result(
        action=decision.action,
        status=ResultStatus.SUCCESS,
        data={"callback": lambda: None, "timestamp": datetime.now(UTC)},
    )

    row_id = logger.log("sess", decision, result=result)
    assert row_id >= 1
    logger.close()


# -- Unicode in audit entries -----------------------------------------------


def test_unicode_in_all_fields(tmp_path: Path) -> None:
    """Unicode characters in all action fields should be logged correctly."""
    logger = AuditLogger(db_path=tmp_path / "test.db")
    decision = _decision(
        action_type="읽기",
        target="데이터베이스",
        params={"query": "SELECT * FROM 사용자"},
    )
    result = Result(
        action=decision.action,
        status=ResultStatus.SUCCESS,
        data={"결과": "성공"},
    )

    logger.log("세션-1", decision, result=result)
    entries = logger.get_log(session_id="세션-1")
    assert len(entries) == 1
    assert entries[0]["action_type"] == "읽기"
    assert entries[0]["action_target"] == "데이터베이스"
    logger.close()


# -- DB already exists / reopening ------------------------------------------


def test_reopen_existing_db(tmp_path: Path) -> None:
    """AuditLogger should work correctly with an existing DB file."""
    db_path = tmp_path / "test.db"

    # First session
    logger1 = AuditLogger(db_path=db_path)
    result1 = Result(action=Action("read", "db"), status=ResultStatus.SUCCESS)
    logger1.log("s1", _decision(), result=result1)
    logger1.close()

    # Second session (reopens same file)
    logger2 = AuditLogger(db_path=db_path)
    result2 = Result(action=Action("write", "db"), status=ResultStatus.SUCCESS)
    logger2.log("s2", _decision("write"), result=result2)

    entries = logger2.get_log()
    assert len(entries) == 2
    logger2.close()


# -- Close idempotency ------------------------------------------------------


def test_close_is_idempotent(tmp_path: Path) -> None:
    """Calling close() multiple times should not raise."""
    logger = AuditLogger(db_path=tmp_path / "test.db")
    logger.close()
    # Second close should not raise
    logger.close()


# -- Export JSONL -----------------------------------------------------------


def test_export_jsonl(tmp_path: Path) -> None:
    """export_jsonl should produce valid JSON Lines output."""
    logger = AuditLogger(db_path=tmp_path / "test.db")
    for i in range(5):
        d = _decision(action_type=f"op_{i}")
        logger.log("s1", d, result=Result(action=d.action, status=ResultStatus.SUCCESS))

    out_file = tmp_path / "export.jsonl"
    count = logger.export_jsonl(out_file)
    assert count == 5

    lines = out_file.read_text().strip().split("\n")
    assert len(lines) == 5
    for line in lines:
        parsed = json.loads(line)
        assert "session_id" in parsed
        assert "action_type" in parsed
    logger.close()


def test_export_jsonl_with_session_filter(tmp_path: Path) -> None:
    """export_jsonl with session filter should only export matching entries."""
    logger = AuditLogger(db_path=tmp_path / "test.db")
    r1 = Result(action=Action("read", "db"), status=ResultStatus.SUCCESS)
    logger.log("s1", _decision("read"), result=r1)
    r2 = Result(action=Action("write", "db"), status=ResultStatus.SUCCESS)
    logger.log("s2", _decision("write"), result=r2)

    out_file = tmp_path / "export.jsonl"
    count = logger.export_jsonl(out_file, session_id="s1")
    assert count == 1
    logger.close()


# -- Concurrent async writes -----------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_async_audit_writes(tmp_path: Path) -> None:
    """Multiple async tasks writing to the audit logger concurrently should not corrupt data."""
    logger = AuditLogger(db_path=tmp_path / "test.db")

    async def write_entries(session: str, count: int) -> None:
        for i in range(count):
            d = _decision(action_type=f"op_{i}", target=session)
            logger.log(session, d, result=Result(action=d.action, status=ResultStatus.SUCCESS))

    # Run concurrent tasks
    await asyncio.gather(
        write_entries("session_a", 20),
        write_entries("session_b", 20),
        write_entries("session_c", 20),
    )

    entries = logger.get_log()
    assert len(entries) == 60

    # Verify per-session counts
    assert len(logger.get_log(session_id="session_a")) == 20
    assert len(logger.get_log(session_id="session_b")) == 20
    assert len(logger.get_log(session_id="session_c")) == 20
    logger.close()
