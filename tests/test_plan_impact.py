"""Tests for aegis.core.plan_impact — deep policy impact analysis."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from aegis.core.plan_impact import (
    ActionImpact,
    ImpactReport,
    PatternGroup,
    PolicyImpactAnalyzer,
    RiskMigration,
    _classify_change,
    _risk_direction,
    load_actions_from_audit_db,
    parse_period,
)
from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.risk import RiskLevel

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _permissive_policy() -> Policy:
    return Policy(
        rules=[
            PolicyRule(
                name="allow_all",
                match_type="*",
                match_target="*",
                risk_level=RiskLevel.LOW,
                approval=Approval.AUTO,
            ),
        ],
        default_risk_level=RiskLevel.LOW,
        default_approval=Approval.AUTO,
    )


def _strict_policy() -> Policy:
    return Policy(
        rules=[
            PolicyRule(
                name="block_all",
                match_type="*",
                match_target="*",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
            ),
        ],
        default_risk_level=RiskLevel.CRITICAL,
        default_approval=Approval.BLOCK,
    )


def _granular_policy() -> Policy:
    return Policy(
        rules=[
            PolicyRule(
                name="read_ops",
                match_type="read*",
                match_target="*",
                risk_level=RiskLevel.LOW,
                approval=Approval.AUTO,
            ),
            PolicyRule(
                name="write_ops",
                match_type="write*",
                match_target="*",
                risk_level=RiskLevel.MEDIUM,
                approval=Approval.APPROVE,
            ),
            PolicyRule(
                name="delete_ops",
                match_type="delete*",
                match_target="*",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
            ),
        ],
        default_risk_level=RiskLevel.MEDIUM,
        default_approval=Approval.APPROVE,
    )


def _stricter_granular_policy() -> Policy:
    """Like granular but blocks writes to 'production' and raises web_search risk."""
    return Policy(
        rules=[
            PolicyRule(
                name="read_ops",
                match_type="read*",
                match_target="*",
                risk_level=RiskLevel.LOW,
                approval=Approval.AUTO,
            ),
            PolicyRule(
                name="write_production_block",
                match_type="write*",
                match_target="production",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
            ),
            PolicyRule(
                name="web_search_high",
                match_type="web_search*",
                match_target="external",
                risk_level=RiskLevel.HIGH,
                approval=Approval.APPROVE,
            ),
            PolicyRule(
                name="write_ops",
                match_type="write*",
                match_target="*",
                risk_level=RiskLevel.MEDIUM,
                approval=Approval.APPROVE,
            ),
            PolicyRule(
                name="delete_ops",
                match_type="delete*",
                match_target="*",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
            ),
        ],
        default_risk_level=RiskLevel.MEDIUM,
        default_approval=Approval.APPROVE,
    )


def _create_audit_db(db_path: Path, rows: list[dict[str, object]]) -> None:
    """Create a SQLite audit DB with the given rows."""
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """\
        CREATE TABLE IF NOT EXISTS audit_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id      TEXT    NOT NULL,
            timestamp       TEXT    NOT NULL,
            action_type     TEXT    NOT NULL,
            action_target   TEXT    NOT NULL,
            action_params   TEXT,
            action_desc     TEXT,
            risk_level      TEXT    NOT NULL,
            approval        TEXT    NOT NULL,
            matched_rule    TEXT,
            human_decision  TEXT,
            result_status   TEXT,
            result_data     TEXT,
            result_error    TEXT,
            agent_id        TEXT,
            parent_agent_id TEXT,
            chain_id        TEXT,
            chain_depth     INTEGER DEFAULT 0
        )
        """
    )
    for row in rows:
        conn.execute(
            """INSERT INTO audit_log
               (session_id, timestamp, action_type, action_target,
                action_params, action_desc, risk_level, approval,
                matched_rule, agent_id, parent_agent_id, chain_id, chain_depth)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                row.get("session_id", "sess-1"),
                row.get("timestamp", "2026-03-01T12:00:00"),
                row["action_type"],
                row["action_target"],
                json.dumps(row.get("action_params", {})),
                row.get("action_desc", ""),
                row.get("risk_level", "LOW"),
                row["approval"],
                row.get("matched_rule", ""),
                row.get("agent_id", "agent-1"),
                row.get("parent_agent_id", ""),
                row.get("chain_id", ""),
                row.get("chain_depth", 0),
            ),
        )
    conn.commit()
    conn.close()


def _make_audit_rows(
    entries: list[tuple[str, str, str]],
    *,
    timestamp: str = "2026-03-01T12:00:00",
    agent_id: str = "agent-1",
) -> list[dict[str, object]]:
    """Build audit rows from (action_type, target, approval) tuples."""
    return [
        {
            "session_id": "sess-1",
            "timestamp": timestamp,
            "action_type": at,
            "action_target": tgt,
            "action_params": "{}",
            "action_desc": "",
            "risk_level": "LOW",
            "approval": appr,
            "matched_rule": "",
            "agent_id": agent_id,
            "parent_agent_id": "",
            "chain_id": "",
            "chain_depth": 0,
        }
        for at, tgt, appr in entries
    ]


# ---------------------------------------------------------------------------
# _classify_change tests
# ---------------------------------------------------------------------------


class TestClassifyChange:
    """Tests for the _classify_change helper."""

    def test_unchanged(self) -> None:
        assert _classify_change("auto", "auto") == "unchanged"
        assert _classify_change("block", "block") == "unchanged"

    def test_newly_blocked(self) -> None:
        assert _classify_change("auto", "block") == "newly_blocked"
        assert _classify_change("approve", "block") == "newly_blocked"

    def test_newly_allowed(self) -> None:
        assert _classify_change("block", "auto") == "newly_allowed"
        assert _classify_change("block", "approve") == "newly_allowed"

    def test_restricted(self) -> None:
        assert _classify_change("auto", "approve") == "restricted"

    def test_promoted(self) -> None:
        assert _classify_change("approve", "auto") == "promoted"


# ---------------------------------------------------------------------------
# _risk_direction tests
# ---------------------------------------------------------------------------


class TestRiskDirection:
    """Tests for risk level direction classification."""

    def test_same(self) -> None:
        assert _risk_direction("LOW", "LOW") == "same"
        assert _risk_direction("CRITICAL", "CRITICAL") == "same"

    def test_higher(self) -> None:
        assert _risk_direction("LOW", "HIGH") == "higher"
        assert _risk_direction("MEDIUM", "CRITICAL") == "higher"

    def test_lower(self) -> None:
        assert _risk_direction("HIGH", "LOW") == "lower"
        assert _risk_direction("CRITICAL", "MEDIUM") == "lower"


# ---------------------------------------------------------------------------
# parse_period tests
# ---------------------------------------------------------------------------


class TestParsePeriod:
    """Tests for period string parsing."""

    def test_duration_days(self) -> None:
        now = datetime(2026, 3, 29, 12, 0, 0)
        start, end = parse_period("30d", now=now)
        assert end == now
        assert start == now - timedelta(days=30)

    def test_duration_hours(self) -> None:
        now = datetime(2026, 3, 29, 12, 0, 0)
        start, end = parse_period("24h", now=now)
        assert end == now
        assert start == now - timedelta(hours=24)

    def test_duration_weeks(self) -> None:
        now = datetime(2026, 3, 29, 12, 0, 0)
        start, end = parse_period("4w", now=now)
        assert end == now
        assert start == now - timedelta(weeks=4)

    def test_duration_months(self) -> None:
        now = datetime(2026, 3, 29, 12, 0, 0)
        start, end = parse_period("2m", now=now)
        assert end == now
        assert start == now - timedelta(days=60)

    def test_quarter_q1(self) -> None:
        start, end = parse_period("2026-Q1")
        assert start == datetime(2026, 1, 1)
        assert end.month == 3
        assert end.day == 31

    def test_quarter_q4(self) -> None:
        start, end = parse_period("2026-Q4")
        assert start == datetime(2026, 10, 1)
        assert end.month == 12
        assert end.day == 31

    def test_iso_range(self) -> None:
        start, end = parse_period("2026-01-01..2026-03-31")
        assert start == datetime(2026, 1, 1)
        assert end == datetime(2026, 3, 31)

    def test_invalid_format_raises(self) -> None:
        with pytest.raises(ValueError, match="Unrecognized period format"):
            parse_period("invalid")

    def test_quarter_lowercase(self) -> None:
        start, end = parse_period("2026-q2")
        assert start == datetime(2026, 4, 1)


# ---------------------------------------------------------------------------
# PolicyImpactAnalyzer.analyze tests
# ---------------------------------------------------------------------------


class TestAnalyze:
    """Tests for PolicyImpactAnalyzer.analyze()."""

    def test_empty_audit_data(self) -> None:
        analyzer = PolicyImpactAnalyzer()
        report = analyzer.analyze(_permissive_policy(), _strict_policy(), [])
        assert report.total_actions == 0
        assert report.newly_blocked == 0
        assert report.unchanged == 0

    def test_all_unchanged(self) -> None:
        analyzer = PolicyImpactAnalyzer()
        rows = _make_audit_rows(
            [
                ("read", "db", "auto"),
                ("read", "crm", "auto"),
            ]
        )
        report = analyzer.analyze(_permissive_policy(), _permissive_policy(), rows)
        assert report.total_actions == 2
        assert report.unchanged == 2
        assert report.newly_blocked == 0
        assert report.newly_allowed == 0

    def test_newly_blocked_detection(self) -> None:
        analyzer = PolicyImpactAnalyzer()
        rows = _make_audit_rows(
            [
                ("read", "db", "auto"),
                ("write", "crm", "auto"),
                ("delete", "backup", "auto"),
            ]
        )
        report = analyzer.analyze(_permissive_policy(), _strict_policy(), rows)
        assert report.total_actions == 3
        assert report.newly_blocked == 3
        assert report.unchanged == 0

    def test_newly_allowed_detection(self) -> None:
        analyzer = PolicyImpactAnalyzer()
        rows = _make_audit_rows(
            [
                ("read", "db", "block"),
                ("write", "crm", "block"),
            ]
        )
        report = analyzer.analyze(_strict_policy(), _permissive_policy(), rows)
        assert report.total_actions == 2
        assert report.newly_allowed == 2
        assert report.newly_blocked == 0

    def test_mixed_changes(self) -> None:
        analyzer = PolicyImpactAnalyzer()
        rows = _make_audit_rows(
            [
                ("read", "db", "auto"),  # unchanged (auto->auto)
                ("write", "crm", "auto"),  # restricted (auto->approve)
                ("delete", "backup", "auto"),  # newly_blocked (auto->block)
            ]
        )
        report = analyzer.analyze(_permissive_policy(), _granular_policy(), rows)
        assert report.total_actions == 3
        assert report.unchanged == 1
        assert report.restricted == 1
        assert report.newly_blocked == 1

    def test_risk_level_tracking(self) -> None:
        analyzer = PolicyImpactAnalyzer()
        rows = _make_audit_rows(
            [
                ("write", "production", "approve"),
            ]
        )
        # Granular: write->MEDIUM, stricter_granular: write@production->CRITICAL
        report = analyzer.analyze(_granular_policy(), _stricter_granular_policy(), rows)
        assert report.risk_higher >= 1

    def test_risk_lower_tracking(self) -> None:
        analyzer = PolicyImpactAnalyzer()
        rows = _make_audit_rows(
            [
                ("write", "production", "block"),
            ]
        )
        # Stricter: write@production->CRITICAL, granular: write->MEDIUM
        report = analyzer.analyze(_stricter_granular_policy(), _granular_policy(), rows)
        assert report.risk_lower >= 1

    def test_top_newly_blocked_patterns(self) -> None:
        analyzer = PolicyImpactAnalyzer()
        rows = _make_audit_rows(
            [
                ("web_search", "external", "auto"),
                ("web_search", "external", "auto"),
                ("web_search", "external", "auto"),
                ("write", "production", "auto"),
            ]
        )
        report = analyzer.analyze(_permissive_policy(), _strict_policy(), rows)
        assert len(report.top_newly_blocked_patterns) >= 1
        # web_search@external should be top pattern with 3 actions
        top = report.top_newly_blocked_patterns[0]
        assert top.count == 3
        assert top.action_type == "web_search"
        assert top.target == "external"

    def test_top_newly_allowed_patterns(self) -> None:
        analyzer = PolicyImpactAnalyzer()
        rows = _make_audit_rows(
            [
                ("read", "docs", "block"),
                ("read", "docs", "block"),
                ("read", "docs", "block"),
            ]
        )
        report = analyzer.analyze(_strict_policy(), _permissive_policy(), rows)
        assert len(report.top_newly_allowed_patterns) >= 1
        top = report.top_newly_allowed_patterns[0]
        assert top.count == 3
        assert top.action_type == "read"

    def test_risk_migrations_detail(self) -> None:
        analyzer = PolicyImpactAnalyzer()
        rows = _make_audit_rows(
            [
                ("write", "production", "approve"),
                ("write", "production", "approve"),
            ]
        )
        report = analyzer.analyze(_granular_policy(), _stricter_granular_policy(), rows)
        # Should have risk migration from MEDIUM to CRITICAL
        if report.risk_migrations:
            migration = report.risk_migrations[0]
            assert migration.from_risk == "MEDIUM"
            assert migration.to_risk == "CRITICAL"
            assert migration.count == 2


# ---------------------------------------------------------------------------
# ImpactReport serialization tests
# ---------------------------------------------------------------------------


class TestImpactReport:
    """Tests for ImpactReport output methods."""

    def test_to_text_empty(self) -> None:
        report = ImpactReport()
        text = report.to_text()
        assert "No historical actions" in text

    def test_to_text_with_data(self) -> None:
        report = ImpactReport(
            total_actions=100,
            newly_blocked=10,
            newly_allowed=5,
            restricted=3,
            promoted=2,
            unchanged=80,
            top_newly_blocked_patterns=[
                PatternGroup(action_type="web_search", target="external", count=7),
            ],
            top_newly_allowed_patterns=[
                PatternGroup(action_type="read", target="docs", count=3),
            ],
            risk_higher=8,
            risk_lower=4,
            risk_migrations=[
                RiskMigration(from_risk="MEDIUM", to_risk="CRITICAL", count=5),
            ],
        )
        text = report.to_text()
        assert "100" in text
        assert "NEWLY BLOCKED" in text
        assert "NEWLY ALLOWED" in text
        assert "web_search" in text
        assert "read" in text
        assert "HIGHER risk" in text
        assert "LOWER risk" in text
        assert "MEDIUM -> CRITICAL" in text

    def test_to_dict_structure(self) -> None:
        report = ImpactReport(
            total_actions=50,
            newly_blocked=5,
            newly_allowed=3,
            restricted=2,
            promoted=1,
            unchanged=39,
        )
        d = report.to_dict()
        assert d["total_actions"] == 50
        assert d["newly_blocked"] == 5
        assert d["newly_allowed"] == 3
        assert d["restricted"] == 2
        assert d["promoted"] == 1
        assert d["unchanged"] == 39
        assert isinstance(d["top_newly_blocked_patterns"], list)
        assert isinstance(d["risk_migrations"], list)

    def test_to_dict_json_serializable(self) -> None:
        report = ImpactReport(
            total_actions=10,
            newly_blocked=1,
            impacts=[
                ActionImpact(
                    action_type="write",
                    target="prod",
                    params={"key": "val"},
                    agent_id="a1",
                    timestamp=datetime(2026, 1, 1),
                    old_decision="auto",
                    new_decision="block",
                    old_risk="LOW",
                    new_risk="CRITICAL",
                    change="newly_blocked",
                ),
            ],
        )
        d = report.to_dict()
        # Must be JSON-serializable
        serialized = json.dumps(d)
        assert "write" in serialized

    def test_to_text_percentages(self) -> None:
        report = ImpactReport(
            total_actions=200,
            newly_blocked=10,
            newly_allowed=0,
            unchanged=190,
        )
        text = report.to_text()
        assert "5.0%" in text  # 10/200
        assert "95.0%" in text  # 190/200


# ---------------------------------------------------------------------------
# load_actions_from_audit_db tests
# ---------------------------------------------------------------------------


class TestLoadActionsFromDb:
    """Tests for audit DB loading with period filtering."""

    def test_load_basic(self, tmp_path: Path) -> None:
        db = tmp_path / "audit.db"
        _create_audit_db(
            db,
            [
                {"action_type": "read", "action_target": "db", "approval": "auto"},
                {"action_type": "write", "action_target": "crm", "approval": "approve"},
            ],
        )
        rows = load_actions_from_audit_db(db)
        assert len(rows) == 2

    def test_load_with_session_filter(self, tmp_path: Path) -> None:
        db = tmp_path / "audit.db"
        _create_audit_db(
            db,
            [
                {
                    "action_type": "read",
                    "action_target": "db",
                    "approval": "auto",
                    "session_id": "s1",
                },
                {
                    "action_type": "write",
                    "action_target": "crm",
                    "approval": "approve",
                    "session_id": "s2",
                },
            ],
        )
        rows = load_actions_from_audit_db(db, session_id="s1")
        assert len(rows) == 1
        assert rows[0]["action_type"] == "read"

    def test_load_with_period_filter(self, tmp_path: Path) -> None:
        db = tmp_path / "audit.db"
        _create_audit_db(
            db,
            [
                {
                    "action_type": "read",
                    "action_target": "db",
                    "approval": "auto",
                    "timestamp": "2026-01-15T12:00:00",
                },
                {
                    "action_type": "write",
                    "action_target": "crm",
                    "approval": "approve",
                    "timestamp": "2026-03-15T12:00:00",
                },
                {
                    "action_type": "delete",
                    "action_target": "backup",
                    "approval": "block",
                    "timestamp": "2026-06-15T12:00:00",
                },
            ],
        )
        # Only Q1 2026
        period = (datetime(2026, 1, 1), datetime(2026, 3, 31, 23, 59, 59))
        rows = load_actions_from_audit_db(db, period=period)
        assert len(rows) == 2  # Jan and Mar, not Jun

    def test_load_empty_db(self, tmp_path: Path) -> None:
        db = tmp_path / "audit.db"
        _create_audit_db(db, [])
        rows = load_actions_from_audit_db(db)
        assert rows == []


# ---------------------------------------------------------------------------
# analyze_from_db integration test
# ---------------------------------------------------------------------------


class TestAnalyzeFromDb:
    """Integration tests for analyze_from_db."""

    def test_full_pipeline(self, tmp_path: Path) -> None:
        db = tmp_path / "audit.db"
        _create_audit_db(
            db,
            [
                {"action_type": "read", "action_target": "db", "approval": "auto"},
                {"action_type": "write", "action_target": "crm", "approval": "auto"},
                {"action_type": "write", "action_target": "production", "approval": "approve"},
                {"action_type": "delete", "action_target": "backup", "approval": "auto"},
                {"action_type": "web_search", "action_target": "external", "approval": "auto"},
            ],
        )
        analyzer = PolicyImpactAnalyzer()
        report = analyzer.analyze_from_db(
            _permissive_policy(),
            _granular_policy(),
            db,
        )
        assert report.total_actions == 5
        # read -> unchanged, write -> restricted, write -> restricted,
        # delete -> newly_blocked, web_search -> approve (default)
        assert report.newly_blocked >= 1

    def test_pipeline_with_period(self, tmp_path: Path) -> None:
        db = tmp_path / "audit.db"
        _create_audit_db(
            db,
            [
                {
                    "action_type": "read",
                    "action_target": "db",
                    "approval": "auto",
                    "timestamp": "2026-01-10T12:00:00",
                },
                {
                    "action_type": "write",
                    "action_target": "crm",
                    "approval": "auto",
                    "timestamp": "2026-06-10T12:00:00",
                },
            ],
        )
        analyzer = PolicyImpactAnalyzer()
        period = (datetime(2026, 1, 1), datetime(2026, 3, 31, 23, 59, 59))
        report = analyzer.analyze_from_db(
            _permissive_policy(),
            _strict_policy(),
            db,
            period=period,
        )
        # Only the Jan entry should be included
        assert report.total_actions == 1

    def test_pipeline_with_session_filter(self, tmp_path: Path) -> None:
        db = tmp_path / "audit.db"
        _create_audit_db(
            db,
            [
                {
                    "action_type": "read",
                    "action_target": "db",
                    "approval": "auto",
                    "session_id": "target-session",
                },
                {
                    "action_type": "write",
                    "action_target": "crm",
                    "approval": "auto",
                    "session_id": "other-session",
                },
            ],
        )
        analyzer = PolicyImpactAnalyzer()
        report = analyzer.analyze_from_db(
            _permissive_policy(),
            _strict_policy(),
            db,
            session_id="target-session",
        )
        assert report.total_actions == 1


# ---------------------------------------------------------------------------
# Dataclass frozen tests
# ---------------------------------------------------------------------------


class TestDataclassesFrozen:
    """Verify frozen dataclass behavior."""

    def test_action_impact_frozen(self) -> None:
        ai = ActionImpact(
            action_type="read",
            target="db",
            params={},
            agent_id="a1",
            timestamp=datetime(2026, 1, 1),
            old_decision="auto",
            new_decision="block",
            old_risk="LOW",
            new_risk="CRITICAL",
            change="newly_blocked",
        )
        with pytest.raises(AttributeError):
            ai.change = "promoted"  # type: ignore[misc]

    def test_pattern_group_frozen(self) -> None:
        pg = PatternGroup(action_type="read", target="db", count=5)
        with pytest.raises(AttributeError):
            pg.count = 10  # type: ignore[misc]

    def test_risk_migration_frozen(self) -> None:
        rm = RiskMigration(from_risk="LOW", to_risk="HIGH", count=3)
        with pytest.raises(AttributeError):
            rm.count = 5  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_single_action(self) -> None:
        analyzer = PolicyImpactAnalyzer()
        rows = _make_audit_rows([("read", "db", "auto")])
        report = analyzer.analyze(_permissive_policy(), _strict_policy(), rows)
        assert report.total_actions == 1
        assert report.newly_blocked == 1

    def test_no_policy_changes_identical_results(self) -> None:
        """Same policy for old and new should yield all unchanged."""
        analyzer = PolicyImpactAnalyzer()
        rows = _make_audit_rows(
            [
                ("read", "db", "auto"),
                ("write", "crm", "approve"),
                ("delete", "backup", "block"),
            ]
        )
        policy = _granular_policy()
        report = analyzer.analyze(policy, policy, rows)
        assert report.unchanged == 3
        assert report.newly_blocked == 0
        assert report.newly_allowed == 0
        assert report.restricted == 0
        assert report.promoted == 0

    def test_large_batch(self) -> None:
        """Verify no accumulation bugs with many actions."""
        analyzer = PolicyImpactAnalyzer()
        rows = _make_audit_rows(
            [("read", "db", "auto")] * 500
            + [("write", "crm", "auto")] * 300
            + [("delete", "backup", "auto")] * 200
        )
        report = analyzer.analyze(_permissive_policy(), _granular_policy(), rows)
        assert report.total_actions == 1000
        assert report.unchanged == 500  # reads stay auto
        assert report.restricted == 300  # writes go to approve
        assert report.newly_blocked == 200  # deletes go to block

    def test_action_params_preserved(self) -> None:
        """Verify params are carried through to ActionImpact."""
        analyzer = PolicyImpactAnalyzer()
        rows = [
            {
                "session_id": "s1",
                "timestamp": "2026-03-01T12:00:00",
                "action_type": "write",
                "action_target": "db",
                "action_params": json.dumps({"table": "users", "count": 42}),
                "action_desc": "",
                "risk_level": "MEDIUM",
                "approval": "auto",
                "matched_rule": "",
                "agent_id": "agent-1",
                "parent_agent_id": "",
                "chain_id": "",
                "chain_depth": 0,
            }
        ]
        report = analyzer.analyze(_permissive_policy(), _strict_policy(), rows)
        assert report.impacts[0].params == {"table": "users", "count": 42}
