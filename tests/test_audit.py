"""Tests for the audit logger."""

from pathlib import Path

from aegis.core.action import Action
from aegis.core.policy import Approval, PolicyDecision
from aegis.core.result import Result, ResultStatus
from aegis.core.risk import RiskLevel
from aegis.runtime.audit import AuditLogger


def _make_decision(
    action_type: str = "read",
    target: str = "salesforce",
    risk: RiskLevel = RiskLevel.LOW,
    approval: Approval = Approval.AUTO,
) -> PolicyDecision:
    return PolicyDecision(
        action=Action(action_type, target),
        risk_level=risk,
        approval=approval,
        matched_rule="test_rule",
    )


def test_audit_log_and_retrieve(tmp_path: Path):
    db = tmp_path / "test.db"
    logger = AuditLogger(db_path=db)

    decision = _make_decision()
    result = Result(action=decision.action, status=ResultStatus.SUCCESS, data={"key": "val"})

    row_id = logger.log("session-1", decision, result=result)
    assert row_id == 1

    entries = logger.get_log()
    assert len(entries) == 1
    assert entries[0]["session_id"] == "session-1"
    assert entries[0]["action_type"] == "read"
    assert entries[0]["result_status"] == "success"
    logger.close()


def test_audit_filter_by_session(tmp_path: Path):
    db = tmp_path / "test.db"
    logger = AuditLogger(db_path=db)

    d1 = _make_decision("read")
    d2 = _make_decision("write", risk=RiskLevel.MEDIUM, approval=Approval.APPROVE)

    logger.log("session-a", d1, result=Result(action=d1.action, status=ResultStatus.SUCCESS))
    logger.log("session-b", d2, result=Result(action=d2.action, status=ResultStatus.DENIED))

    all_entries = logger.get_log()
    assert len(all_entries) == 2

    a_entries = logger.get_log(session_id="session-a")
    assert len(a_entries) == 1
    assert a_entries[0]["action_type"] == "read"

    b_entries = logger.get_log(session_id="session-b")
    assert len(b_entries) == 1
    assert b_entries[0]["result_status"] == "denied"
    logger.close()


def test_audit_log_without_result(tmp_path: Path):
    db = tmp_path / "test.db"
    logger = AuditLogger(db_path=db)

    decision = _make_decision("delete", risk=RiskLevel.CRITICAL, approval=Approval.BLOCK)
    logger.log("session-1", decision, human_decision="blocked")

    entries = logger.get_log()
    assert len(entries) == 1
    assert entries[0]["result_status"] is None
    assert entries[0]["human_decision"] == "blocked"
    logger.close()


def test_audit_human_decision_recorded(tmp_path: Path):
    db = tmp_path / "test.db"
    logger = AuditLogger(db_path=db)

    decision = _make_decision("write", risk=RiskLevel.MEDIUM, approval=Approval.APPROVE)
    result = Result(action=decision.action, status=ResultStatus.SUCCESS)
    logger.log("session-1", decision, result=result, human_decision="approved")

    entries = logger.get_log()
    assert entries[0]["human_decision"] == "approved"
    logger.close()


def test_subscribe_notifies_on_log(tmp_path: Path):
    db = tmp_path / "sub.db"
    logger = AuditLogger(db_path=db)

    received: list[dict] = []  # type: ignore[type-arg]
    logger.subscribe(lambda entry: received.append(entry))

    decision = _make_decision("read", risk=RiskLevel.LOW, approval=Approval.AUTO)
    result = Result(action=decision.action, status=ResultStatus.SUCCESS)
    logger.log("s1", decision, result=result)

    assert len(received) == 1
    assert received[0]["action_type"] == "read"
    assert received[0]["risk_level"] == "LOW"
    logger.close()


def test_unsubscribe_stops_notifications(tmp_path: Path):
    db = tmp_path / "unsub.db"
    logger = AuditLogger(db_path=db)

    received: list[dict] = []  # type: ignore[type-arg]
    cb = lambda entry: received.append(entry)  # noqa: E731
    logger.subscribe(cb)

    decision = _make_decision("read")
    logger.log("s1", decision)
    assert len(received) == 1

    logger.unsubscribe(cb)
    logger.log("s2", decision)
    assert len(received) == 1  # No new notification
    logger.close()
