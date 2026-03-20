"""Extended tests for the CLI module covering uncovered lines."""

from __future__ import annotations

import textwrap
from pathlib import Path

from aegis.cli.main import main
from aegis.core.action import Action
from aegis.core.policy import Approval, PolicyDecision
from aegis.core.result import Result, ResultStatus
from aegis.core.risk import RiskLevel
from aegis.runtime.audit import AuditLogger


def test_no_command_prints_help(capsys):
    """Calling main with no args should print help."""
    main([])
    captured = capsys.readouterr()
    assert "aegis" in captured.out.lower() or "usage" in captured.out.lower()


def test_schema_command(capsys):
    """aegis schema should print JSON schema."""
    main(["schema"])
    captured = capsys.readouterr()
    assert "version" in captured.out
    # Should be valid JSON
    import json

    schema = json.loads(captured.out)
    assert isinstance(schema, dict)


def test_audit_table_format(tmp_path: Path, capsys):
    """aegis audit with table format should display column headers and data rows."""
    db = tmp_path / "audit.db"
    logger = AuditLogger(db_path=db)

    decision = PolicyDecision(
        action=Action("read", "salesforce"),
        risk_level=RiskLevel.LOW,
        approval=Approval.AUTO,
        matched_rule="read_auto",
    )
    logger.log(
        "sess123",
        decision,
        result=Result(action=decision.action, status=ResultStatus.SUCCESS),
        human_decision=None,
    )
    logger.close()

    main(["audit", "--db", str(db), "--format", "table"])
    captured = capsys.readouterr()

    # Should contain table headers
    assert "Session" in captured.out
    assert "Action" in captured.out
    assert "Risk" in captured.out
    assert "Decision" in captured.out
    assert "Result" in captured.out
    # Should contain data
    assert "sess123" in captured.out
    assert "read" in captured.out
    assert "salesforce" in captured.out
    assert "success" in captured.out


def test_audit_table_with_human_decision(tmp_path: Path, capsys):
    """Table format should show human_decision when present."""
    db = tmp_path / "audit.db"
    logger = AuditLogger(db_path=db)

    decision = PolicyDecision(
        action=Action("write", "salesforce"),
        risk_level=RiskLevel.MEDIUM,
        approval=Approval.APPROVE,
        matched_rule="write_approve",
    )
    logger.log(
        "sess456",
        decision,
        result=Result(action=decision.action, status=ResultStatus.SUCCESS),
        human_decision="approved",
    )
    logger.close()

    main(["audit", "--db", str(db), "--format", "table"])
    captured = capsys.readouterr()

    assert "approved" in captured.out


def test_audit_filter_by_session(tmp_path: Path, capsys):
    """aegis audit --session should filter entries."""
    db = tmp_path / "audit.db"
    logger = AuditLogger(db_path=db)

    d1 = PolicyDecision(
        action=Action("read", "sf"),
        risk_level=RiskLevel.LOW,
        approval=Approval.AUTO,
        matched_rule="r1",
    )
    d2 = PolicyDecision(
        action=Action("write", "sf"),
        risk_level=RiskLevel.MEDIUM,
        approval=Approval.APPROVE,
        matched_rule="r2",
    )
    logger.log("s1", d1, result=Result(action=d1.action, status=ResultStatus.SUCCESS))
    logger.log("s2", d2, result=Result(action=d2.action, status=ResultStatus.SUCCESS))
    logger.close()

    main(["audit", "--db", str(db), "--format", "json", "--session", "s1"])
    captured = capsys.readouterr()

    assert '"session_id": "s1"' in captured.out
    assert "s2" not in captured.out


def test_audit_jsonl_default_output(tmp_path: Path, capsys, monkeypatch):
    """aegis audit --format jsonl without -o should use default filename."""
    db = tmp_path / "audit.db"
    logger = AuditLogger(db_path=db)

    d = PolicyDecision(
        action=Action("read", "api"),
        risk_level=RiskLevel.LOW,
        approval=Approval.AUTO,
        matched_rule="r1",
    )
    logger.log("s1", d, result=Result(action=d.action, status=ResultStatus.SUCCESS))
    logger.close()

    # Change to tmp_path so the default output goes there
    monkeypatch.chdir(tmp_path)
    main(["audit", "--db", str(db), "--format", "jsonl"])
    captured = capsys.readouterr()

    assert "Exported" in captured.out
    assert "aegis_audit.jsonl" in captured.out


def test_audit_jsonl_with_session_filter(tmp_path: Path, capsys):
    """aegis audit --format jsonl --session should filter."""
    db = tmp_path / "audit.db"
    logger = AuditLogger(db_path=db)

    d1 = PolicyDecision(
        action=Action("read", "api"),
        risk_level=RiskLevel.LOW,
        approval=Approval.AUTO,
        matched_rule="r1",
    )
    d2 = PolicyDecision(
        action=Action("write", "api"),
        risk_level=RiskLevel.MEDIUM,
        approval=Approval.APPROVE,
        matched_rule="r2",
    )
    logger.log("s1", d1, result=Result(action=d1.action, status=ResultStatus.SUCCESS))
    logger.log("s2", d2, result=Result(action=d2.action, status=ResultStatus.SUCCESS))
    logger.close()

    out = tmp_path / "filtered.jsonl"
    main(["audit", "--db", str(db), "--format", "jsonl", "-o", str(out), "--session", "s1"])
    captured = capsys.readouterr()

    assert "Exported 1 entries" in captured.out


def test_validate_detailed_output(tmp_path: Path, capsys):
    """aegis validate should show rule details."""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        textwrap.dedent("""\
        version: "1"
        defaults:
          risk_level: medium
          approval: approve
        rules:
          - name: read_auto
            match:
              type: read*
              target: "*"
            risk_level: low
            approval: auto
          - name: delete_block
            match:
              type: delete*
            risk_level: critical
            approval: block
    """)
    )
    main(["validate", str(policy_file)])
    captured = capsys.readouterr()

    assert "2 rule(s) loaded" in captured.out
    assert "read_auto" in captured.out
    assert "delete_block" in captured.out
    assert "LOW" in captured.out
    assert "CRITICAL" in captured.out
