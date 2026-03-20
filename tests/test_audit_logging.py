"""Tests for the Python logging audit backend."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from aegis.core.action import Action
from aegis.core.policy import Approval, PolicyDecision
from aegis.core.result import Result, ResultStatus
from aegis.core.risk import RiskLevel
from aegis.runtime.audit_logging import LoggingAuditLogger


def _make_decision(
    action_type: str = "read",
    risk: RiskLevel = RiskLevel.LOW,
) -> PolicyDecision:
    return PolicyDecision(
        action=Action(action_type, "api"),
        risk_level=risk,
        approval=Approval.AUTO,
        matched_rule="test_rule",
    )


def test_log_emits_to_logger(caplog):
    """Should emit structured JSON to Python logging."""
    with caplog.at_level(logging.DEBUG, logger="aegis.audit"):
        audit = LoggingAuditLogger()
        d = _make_decision()
        row_id = audit.log("s1", d, result=Result(action=d.action, status=ResultStatus.SUCCESS))

    assert row_id == 1
    assert len(caplog.records) == 1
    record = json.loads(caplog.records[0].message)
    assert record["action_type"] == "read"
    assert record["session_id"] == "s1"


def test_risk_level_maps_to_log_level(caplog):
    """LOW → DEBUG, MEDIUM → INFO, HIGH → WARNING, CRITICAL → ERROR."""
    expected_levels = ["DEBUG", "INFO", "WARNING", "ERROR"]
    risks = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]

    with caplog.at_level(logging.DEBUG, logger="aegis.audit"):
        audit = LoggingAuditLogger()
        for risk in risks:
            d = _make_decision(risk=risk)
            audit.log("s1", d)

    levels = [r.levelname for r in caplog.records]
    assert levels == expected_levels


def test_get_log_returns_entries():
    """get_log() should return in-memory entries."""
    audit = LoggingAuditLogger()
    d1 = _make_decision("read")
    d2 = _make_decision("write")
    audit.log("s1", d1)
    audit.log("s2", d2)

    all_entries = audit.get_log()
    assert len(all_entries) == 2

    s1_entries = audit.get_log(session_id="s1")
    assert len(s1_entries) == 1
    assert s1_entries[0]["action_type"] == "read"


def test_export_jsonl(tmp_path: Path):
    """export_jsonl() should write JSON Lines file."""
    audit = LoggingAuditLogger()
    d = _make_decision()
    audit.log("s1", d, result=Result(action=d.action, status=ResultStatus.SUCCESS))

    out = tmp_path / "log.jsonl"
    count = audit.export_jsonl(out)
    assert count == 1

    entry = json.loads(out.read_text().strip())
    assert entry["action_type"] == "read"


def test_works_with_runtime():
    """LoggingAuditLogger should be usable as a drop-in for AuditLogger."""
    from aegis.core.policy import Policy, PolicyRule
    from aegis.runtime.approval import AutoApprovalHandler
    from aegis.runtime.engine import Runtime

    class FakeExec:
        async def execute(self, action):
            from datetime import UTC, datetime

            return Result(
                action=action, status=ResultStatus.SUCCESS, completed_at=datetime.now(UTC)
            )

        async def verify(self, action, result):
            return True

        async def setup(self):
            pass

        async def teardown(self):
            pass

    audit = LoggingAuditLogger()
    runtime = Runtime(
        executor=FakeExec(),
        policy=Policy(rules=[PolicyRule(match_type="*", approval=Approval.AUTO)]),
        approval_handler=AutoApprovalHandler(),
        audit_logger=audit,
    )

    import asyncio

    plan = runtime.plan([Action("read", "test")])
    results = asyncio.get_event_loop().run_until_complete(runtime.execute(plan))
    assert results[0].ok
    assert len(audit.get_log()) == 1
