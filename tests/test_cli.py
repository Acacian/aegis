"""Tests for the CLI."""

import textwrap
from pathlib import Path

from aegis.cli.main import main
from aegis.core.action import Action
from aegis.core.policy import Approval, PolicyDecision
from aegis.core.result import Result, ResultStatus
from aegis.core.risk import RiskLevel
from aegis.runtime.audit import AuditLogger


def test_validate_valid_policy(tmp_path: Path, capsys):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        textwrap.dedent("""\
        version: "1"
        defaults:
          risk_level: low
          approval: auto
        rules:
          - name: block_delete
            match:
              type: delete
            risk_level: critical
            approval: block
    """)
    )
    main(["validate", str(policy_file)])
    captured = capsys.readouterr()
    assert "1 rule(s) loaded" in captured.out
    assert "block_delete" in captured.out


def test_validate_invalid_policy(tmp_path: Path):
    bad_file = tmp_path / "bad.yaml"
    bad_file.write_text("rules:\n  - match: {type: read}\n    risk_level: nonexistent\n")
    import pytest

    with pytest.raises(SystemExit):
        main(["validate", str(bad_file)])


def test_audit_json_format(tmp_path: Path, capsys):
    db = tmp_path / "audit.db"
    logger = AuditLogger(db_path=db)
    decision = PolicyDecision(
        action=Action("read", "sf"),
        risk_level=RiskLevel.LOW,
        approval=Approval.AUTO,
        matched_rule="test",
    )
    logger.log("s1", decision, result=Result(action=decision.action, status=ResultStatus.SUCCESS))
    logger.close()

    main(["audit", "--db", str(db), "--format", "json"])
    captured = capsys.readouterr()
    assert '"session_id": "s1"' in captured.out
    assert '"action_type": "read"' in captured.out


def test_audit_empty(tmp_path: Path, capsys):
    db = tmp_path / "empty.db"
    main(["audit", "--db", str(db)])
    captured = capsys.readouterr()
    assert "No audit entries" in captured.out


def test_version(capsys):
    main(["--version"])
    captured = capsys.readouterr()
    assert "aegis 0.1.1" in captured.out
