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
    # Create an empty DB so the file-existence check passes
    logger = AuditLogger(db_path=db)
    logger.close()

    main(["audit", "--db", str(db)])
    captured = capsys.readouterr()
    assert "No audit entries" in captured.out


def test_version(capsys):
    import pytest

    with pytest.raises(SystemExit, match="0"):
        main(["--version"])
    captured = capsys.readouterr()
    from aegis import __version__

    assert f"aegis {__version__}" in captured.out


def test_init_creates_policy(tmp_path: Path, capsys):
    output = tmp_path / "policy.yaml"
    main(["init", "-o", str(output)])
    captured = capsys.readouterr()
    assert "Created" in captured.out
    assert output.exists()
    content = output.read_text(encoding="utf-8")
    assert 'version: "1"' in content
    assert "read_auto" in content
    assert "delete_block" in content


def test_init_refuses_overwrite(tmp_path: Path):
    output = tmp_path / "existing.yaml"
    output.write_text("existing")
    import pytest

    with pytest.raises(SystemExit):
        main(["init", "-o", str(output)])


# -- aegis simulate ----------------------------------------------------------


def _write_policy(tmp_path: Path) -> Path:
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        textwrap.dedent("""\
        version: "1"
        defaults:
          risk_level: medium
          approval: approve
        rules:
          - name: read_auto
            match: { type: "read*" }
            risk_level: low
            approval: auto
          - name: delete_block
            match: { type: "delete*" }
            risk_level: critical
            approval: block
    """)
    )
    return policy_file


def test_simulate_table(tmp_path: Path, capsys):
    policy_file = _write_policy(tmp_path)
    main(["simulate", str(policy_file), "read:crm", "delete:db"])
    out = capsys.readouterr().out
    assert "2 actions" in out
    assert "read_auto" in out
    assert "delete_block" in out
    assert "BLOCKED" in out
    assert "ALLOWED" in out
    assert "1 auto-execute" in out
    assert "1 blocked" in out


def test_simulate_json(tmp_path: Path, capsys):
    policy_file = _write_policy(tmp_path)
    main(
        [
            "simulate",
            str(policy_file),
            "read:crm",
            "write:crm",
            "--format",
            "json",
        ]
    )
    out = capsys.readouterr().out
    data = __import__("json").loads(out)
    assert len(data) == 2
    assert data[0]["action_type"] == "read"
    assert data[0]["approval"] == "auto"
    assert data[0]["is_allowed"] is True
    assert data[1]["action_type"] == "write"
    assert data[1]["approval"] == "approve"


def test_simulate_without_target(tmp_path: Path, capsys):
    policy_file = _write_policy(tmp_path)
    main(["simulate", str(policy_file), "read"])
    out = capsys.readouterr().out
    assert "read_auto" in out


def test_simulate_default_rule(tmp_path: Path, capsys):
    policy_file = _write_policy(tmp_path)
    main(["simulate", str(policy_file), "custom:api"])
    out = capsys.readouterr().out
    assert "<default>" in out
    assert "need approval" in out


# -- aegis audit with filters ------------------------------------------------


def test_audit_filter_by_action_type(tmp_path: Path, capsys):
    db = tmp_path / "audit.db"
    logger = AuditLogger(db_path=db)
    d1 = PolicyDecision(
        action=Action("read", "crm"),
        risk_level=RiskLevel.LOW,
        approval=Approval.AUTO,
    )
    d2 = PolicyDecision(
        action=Action("write", "crm"),
        risk_level=RiskLevel.HIGH,
        approval=Approval.APPROVE,
    )
    logger.log(
        "s1",
        d1,
        result=Result(
            action=d1.action,
            status=ResultStatus.SUCCESS,
        ),
    )
    logger.log(
        "s1",
        d2,
        result=Result(
            action=d2.action,
            status=ResultStatus.SUCCESS,
        ),
    )
    logger.close()

    main(
        [
            "audit",
            "--db",
            str(db),
            "--action-type",
            "read",
            "--format",
            "json",
        ]
    )
    out = capsys.readouterr().out
    data = __import__("json").loads(out)
    assert len(data) == 1
    assert data[0]["action_type"] == "read"
