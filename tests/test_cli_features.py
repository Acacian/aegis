"""Tests for CLI features: colors, stats command, simulate/validate with colors."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from unittest.mock import patch

from aegis.cli import colors
from aegis.cli.main import main
from aegis.core.action import Action
from aegis.core.policy import Approval, PolicyDecision
from aegis.core.result import Result, ResultStatus
from aegis.core.risk import RiskLevel
from aegis.runtime.audit import AuditLogger

# ---------------------------------------------------------------------------
# Color helper tests
# ---------------------------------------------------------------------------


class TestColorHelpers:
    """Test color wrapping functions."""

    def setup_method(self) -> None:
        colors.force_color(True)

    def teardown_method(self) -> None:
        colors.reset_cache()

    def test_green(self) -> None:
        result = colors.green("ok")
        assert result == "\033[32mok\033[0m"

    def test_red(self) -> None:
        result = colors.red("fail")
        assert result == "\033[31mfail\033[0m"

    def test_yellow(self) -> None:
        result = colors.yellow("warn")
        assert result == "\033[33mwarn\033[0m"

    def test_bright_red(self) -> None:
        result = colors.bright_red("crit")
        assert result == "\033[91mcrit\033[0m"

    def test_bold(self) -> None:
        result = colors.bold("title")
        assert result == "\033[1mtitle\033[0m"

    def test_cyan(self) -> None:
        result = colors.cyan("info")
        assert result == "\033[36minfo\033[0m"

    def test_risk_color_low(self) -> None:
        result = colors.risk_color("LOW")
        assert "\033[32m" in result  # green

    def test_risk_color_medium(self) -> None:
        result = colors.risk_color("MEDIUM")
        assert "\033[33m" in result  # yellow

    def test_risk_color_high(self) -> None:
        result = colors.risk_color("HIGH")
        assert "\033[31m" in result  # red

    def test_risk_color_critical(self) -> None:
        result = colors.risk_color("CRITICAL")
        assert "\033[91m" in result  # bright red

    def test_risk_color_unknown(self) -> None:
        result = colors.risk_color("UNKNOWN")
        assert result == "UNKNOWN"

    def test_status_color_success(self) -> None:
        result = colors.status_color("SUCCESS")
        assert "\033[32m" in result

    def test_status_color_allowed(self) -> None:
        result = colors.status_color("ALLOWED")
        assert "\033[32m" in result

    def test_status_color_blocked(self) -> None:
        result = colors.status_color("BLOCKED")
        assert "\033[31m" in result

    def test_status_color_failed(self) -> None:
        result = colors.status_color("FAILED")
        assert "\033[31m" in result

    def test_status_color_unknown(self) -> None:
        result = colors.status_color("skipped")
        assert result == "skipped"


class TestColorDisabled:
    """When colors are disabled, functions return plain text."""

    def setup_method(self) -> None:
        colors.force_color(False)

    def teardown_method(self) -> None:
        colors.reset_cache()

    def test_green_no_color(self) -> None:
        assert colors.green("ok") == "ok"

    def test_red_no_color(self) -> None:
        assert colors.red("fail") == "fail"

    def test_risk_color_no_color(self) -> None:
        assert colors.risk_color("HIGH") == "HIGH"

    def test_status_color_no_color(self) -> None:
        assert colors.status_color("BLOCKED") == "BLOCKED"


class TestColorNoColorEnv:
    """Test NO_COLOR environment variable support."""

    def teardown_method(self) -> None:
        colors.reset_cache()

    def test_no_color_env(self) -> None:
        colors.reset_cache()
        with patch.dict("os.environ", {"NO_COLOR": "1"}):
            colors.reset_cache()
            assert colors.green("ok") == "ok"


# ---------------------------------------------------------------------------
# Stats command tests
# ---------------------------------------------------------------------------


def _populate_db(db_path: Path) -> None:
    """Populate an audit DB with sample entries for stats testing."""
    logger = AuditLogger(db_path=db_path)
    decisions = [
        (
            "s1",
            PolicyDecision(
                action=Action("read", "crm"),
                risk_level=RiskLevel.LOW,
                approval=Approval.AUTO,
                matched_rule="read_auto",
            ),
            ResultStatus.SUCCESS,
        ),
        (
            "s1",
            PolicyDecision(
                action=Action("read", "api"),
                risk_level=RiskLevel.LOW,
                approval=Approval.AUTO,
                matched_rule="read_auto",
            ),
            ResultStatus.SUCCESS,
        ),
        (
            "s1",
            PolicyDecision(
                action=Action("write", "crm"),
                risk_level=RiskLevel.MEDIUM,
                approval=Approval.APPROVE,
                matched_rule="write_approve",
            ),
            ResultStatus.SUCCESS,
        ),
        (
            "s2",
            PolicyDecision(
                action=Action("delete", "db"),
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
                matched_rule="delete_block",
            ),
            ResultStatus.BLOCKED,
        ),
        (
            "s2",
            PolicyDecision(
                action=Action("bulk_update", "stripe"),
                risk_level=RiskLevel.HIGH,
                approval=Approval.APPROVE,
                matched_rule="bulk_high",
            ),
            ResultStatus.FAILED,
        ),
    ]
    for session_id, decision, status in decisions:
        logger.log(
            session_id,
            decision,
            result=Result(action=decision.action, status=status),
        )
    logger.close()


class TestStatsCommand:
    """Test `aegis stats` command."""

    def setup_method(self) -> None:
        colors.force_color(False)

    def teardown_method(self) -> None:
        colors.reset_cache()

    def test_stats_table(self, tmp_path: Path, capsys: object) -> None:
        db = tmp_path / "audit.db"
        _populate_db(db)
        main(["stats", "--db", str(db)])
        import _pytest.capture

        assert isinstance(capsys, _pytest.capture.CaptureFixture)
        out = capsys.readouterr().out

        assert "Aegis Audit Statistics" in out
        assert "Total actions processed:" in out
        assert "5" in out
        assert "Risk Level Breakdown" in out
        assert "LOW" in out
        assert "MEDIUM" in out
        assert "HIGH" in out
        assert "CRITICAL" in out
        assert "Result Status Breakdown" in out
        assert "success" in out
        assert "blocked" in out
        assert "failed" in out
        assert "Top 5 Action Types" in out
        assert "read" in out
        assert "Top 5 Matched Rules" in out
        assert "read_auto" in out

    def test_stats_json(self, tmp_path: Path, capsys: object) -> None:
        db = tmp_path / "audit.db"
        _populate_db(db)
        main(["stats", "--db", str(db), "--format", "json"])
        import _pytest.capture

        assert isinstance(capsys, _pytest.capture.CaptureFixture)
        out = capsys.readouterr().out
        data = json.loads(out)

        assert data["total_actions"] == 5
        assert data["by_risk_level"]["LOW"] == 2
        assert data["by_risk_level"]["CRITICAL"] == 1
        assert data["by_result_status"]["success"] == 3
        assert data["by_result_status"]["blocked"] == 1
        assert "read" in data["top_action_types"]
        assert data["top_action_types"]["read"] == 2
        assert "read_auto" in data["top_matched_rules"]

    def test_stats_missing_db(self, tmp_path: Path) -> None:
        import pytest

        with pytest.raises(SystemExit):
            main(["stats", "--db", str(tmp_path / "missing.db")])


# ---------------------------------------------------------------------------
# Simulate with colors
# ---------------------------------------------------------------------------


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


class TestSimulateWithColors:
    """Test simulate command output includes expected content."""

    def setup_method(self) -> None:
        colors.force_color(False)

    def teardown_method(self) -> None:
        colors.reset_cache()

    def test_simulate_table_content(self, tmp_path: Path, capsys: object) -> None:
        policy_file = _write_policy(tmp_path)
        main(["simulate", str(policy_file), "read:crm", "delete:db"])
        import _pytest.capture

        assert isinstance(capsys, _pytest.capture.CaptureFixture)
        out = capsys.readouterr().out
        assert "ALLOWED" in out
        assert "BLOCKED" in out
        assert "LOW" in out
        assert "CRITICAL" in out
        assert "auto-execute" in out
        assert "blocked" in out

    def test_simulate_with_color_enabled(self, tmp_path: Path, capsys: object) -> None:
        colors.force_color(True)
        policy_file = _write_policy(tmp_path)
        main(["simulate", str(policy_file), "read:crm", "delete:db"])
        import _pytest.capture

        assert isinstance(capsys, _pytest.capture.CaptureFixture)
        out = capsys.readouterr().out
        # When colors are enabled, ANSI codes should be present
        assert "\033[" in out
        assert "ALLOWED" in out
        assert "BLOCKED" in out


# ---------------------------------------------------------------------------
# Validate with colors
# ---------------------------------------------------------------------------


class TestValidateWithColors:
    """Test validate command output with colors."""

    def setup_method(self) -> None:
        colors.force_color(False)

    def teardown_method(self) -> None:
        colors.reset_cache()

    def test_validate_success_message(self, tmp_path: Path, capsys: object) -> None:
        policy_file = _write_policy(tmp_path)
        main(["validate", str(policy_file)])
        import _pytest.capture

        assert isinstance(capsys, _pytest.capture.CaptureFixture)
        out = capsys.readouterr().out
        assert "Policy valid" in out
        assert "2 rule(s) loaded" in out

    def test_validate_with_color_enabled(self, tmp_path: Path, capsys: object) -> None:
        colors.force_color(True)
        policy_file = _write_policy(tmp_path)
        main(["validate", str(policy_file)])
        import _pytest.capture

        assert isinstance(capsys, _pytest.capture.CaptureFixture)
        out = capsys.readouterr().out
        # Green for success, color codes for risk levels
        assert "\033[" in out
        assert "Policy valid" in out

    def test_validate_failure_with_color(self, tmp_path: Path, capsys: object) -> None:
        colors.force_color(True)
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("rules:\n  - match: {type: read}\n    risk_level: nonexistent\n")
        import pytest

        with pytest.raises(SystemExit):
            main(["validate", str(bad_file)])
        import _pytest.capture

        assert isinstance(capsys, _pytest.capture.CaptureFixture)
        err = capsys.readouterr().err
        assert "validation failed" in err


# ---------------------------------------------------------------------------
# Audit with colors
# ---------------------------------------------------------------------------


class TestAuditWithColors:
    """Test audit command table output with colors."""

    def setup_method(self) -> None:
        colors.force_color(False)

    def teardown_method(self) -> None:
        colors.reset_cache()

    def test_audit_table_has_risk_and_result(self, tmp_path: Path, capsys: object) -> None:
        db = tmp_path / "audit.db"
        _populate_db(db)
        main(["audit", "--db", str(db)])
        import _pytest.capture

        assert isinstance(capsys, _pytest.capture.CaptureFixture)
        out = capsys.readouterr().out
        assert "ID" in out
        assert "Session" in out
        assert "read" in out
        assert "LOW" in out

    def test_audit_table_with_color(self, tmp_path: Path, capsys: object) -> None:
        colors.force_color(True)
        db = tmp_path / "audit.db"
        _populate_db(db)
        main(["audit", "--db", str(db)])
        import _pytest.capture

        assert isinstance(capsys, _pytest.capture.CaptureFixture)
        out = capsys.readouterr().out
        # Color codes should be present when enabled
        assert "\033[" in out


# ---------------------------------------------------------------------------
# --no-color flag test
# ---------------------------------------------------------------------------


class TestNoColorFlag:
    """Test --no-color CLI flag."""

    def teardown_method(self) -> None:
        colors.reset_cache()

    def test_no_color_flag_disables_ansi(self, tmp_path: Path, capsys: object) -> None:
        db = tmp_path / "audit.db"
        _populate_db(db)
        main(["--no-color", "audit", "--db", str(db)])
        import _pytest.capture

        assert isinstance(capsys, _pytest.capture.CaptureFixture)
        out = capsys.readouterr().out
        assert "\033[" not in out
        assert "LOW" in out
