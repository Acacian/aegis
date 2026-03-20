"""Tests for JSONL audit export."""

from __future__ import annotations

import json
from pathlib import Path

from aegis.core.action import Action
from aegis.core.policy import Approval, PolicyDecision
from aegis.core.result import Result, ResultStatus
from aegis.core.risk import RiskLevel
from aegis.runtime.audit import AuditLogger


def _make_decision(
    action_type: str = "read",
    target: str = "api",
) -> PolicyDecision:
    return PolicyDecision(
        action=Action(action_type, target),
        risk_level=RiskLevel.LOW,
        approval=Approval.AUTO,
        matched_rule="test_rule",
    )


def test_export_jsonl(tmp_path: Path):
    """Export should create a valid JSONL file."""
    db = tmp_path / "test.db"
    logger = AuditLogger(db_path=db)

    for i in range(3):
        d = _make_decision(f"action_{i}")
        logger.log(
            "session-1",
            d,
            result=Result(action=d.action, status=ResultStatus.SUCCESS),
        )

    out = tmp_path / "export.jsonl"
    count = logger.export_jsonl(out, session_id="session-1")
    logger.close()

    assert count == 3
    lines = out.read_text().strip().split("\n")
    assert len(lines) == 3

    for line in lines:
        entry = json.loads(line)
        assert "session_id" in entry
        assert "action_type" in entry
        assert entry["session_id"] == "session-1"


def test_export_jsonl_empty(tmp_path: Path):
    """Export of empty log should create an empty file."""
    db = tmp_path / "test.db"
    logger = AuditLogger(db_path=db)

    out = tmp_path / "empty.jsonl"
    count = logger.export_jsonl(out)
    logger.close()

    assert count == 0
    assert out.read_text() == ""


def test_export_jsonl_session_filter(tmp_path: Path):
    """Export should filter by session_id."""
    db = tmp_path / "test.db"
    logger = AuditLogger(db_path=db)

    d1 = _make_decision("read")
    d2 = _make_decision("write")
    logger.log("s1", d1, result=Result(action=d1.action, status=ResultStatus.SUCCESS))
    logger.log("s2", d2, result=Result(action=d2.action, status=ResultStatus.SUCCESS))

    out = tmp_path / "filtered.jsonl"
    count = logger.export_jsonl(out, session_id="s1")
    logger.close()

    assert count == 1
    entry = json.loads(out.read_text().strip())
    assert entry["action_type"] == "read"


def test_cli_jsonl_format(tmp_path: Path, capsys):
    """aegis audit --format jsonl should export to file."""
    db = tmp_path / "audit.db"
    logger = AuditLogger(db_path=db)
    d = _make_decision()
    logger.log("s1", d, result=Result(action=d.action, status=ResultStatus.SUCCESS))
    logger.close()

    out = tmp_path / "out.jsonl"
    from aegis.cli.main import main

    main(["audit", "--db", str(db), "--format", "jsonl", "-o", str(out)])
    captured = capsys.readouterr()
    assert "Exported 1 entries" in captured.out
    assert out.exists()
