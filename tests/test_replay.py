"""Tests for aegis.core.replay — Action Replay & Simulation Engine."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

import pytest

from aegis.core.action import Action
from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.replay import (
    ReplayEngine,
    ReplayEvent,
    ReplayReport,
    ReplayResult,
    _classify_change,
    load_events_from_audit_db,
    load_events_from_jsonl,
)
from aegis.core.risk import RiskLevel

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_TS = datetime(2025, 6, 1, 12, 0, 0)


def _action(
    type_: str = "read",
    target: str = "db",
    agent_id: str = "agent-1",
) -> Action:
    return Action(type=type_, target=target, agent_id=agent_id)


def _event(
    type_: str = "read",
    target: str = "db",
    agent_id: str = "agent-1",
    decision: str = "auto",
    ts: datetime = _TS,
    metadata: dict[str, object] | None = None,
) -> ReplayEvent:
    return ReplayEvent(
        action=_action(type_=type_, target=target, agent_id=agent_id),
        agent_id=agent_id,
        timestamp=ts,
        original_decision=decision,
        metadata=metadata or {},
    )


def _permissive_policy() -> Policy:
    """Policy that auto-approves everything."""
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
    """Policy that blocks everything."""
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


def _moderate_policy() -> Policy:
    """Policy that requires approval for everything."""
    return Policy(
        rules=[
            PolicyRule(
                name="approve_all",
                match_type="*",
                match_target="*",
                risk_level=RiskLevel.MEDIUM,
                approval=Approval.APPROVE,
            ),
        ],
        default_risk_level=RiskLevel.MEDIUM,
        default_approval=Approval.APPROVE,
    )


def _granular_policy() -> Policy:
    """Policy with separate rules for reads, writes, and deletes."""
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
                row.get("timestamp", "2025-06-01T12:00:00"),
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


def _write_jsonl(path: Path, records: list[dict[str, object]]) -> None:
    """Write a list of dicts as JSONL."""
    with path.open("w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


# ---------------------------------------------------------------------------
# ReplayEvent dataclass tests
# ---------------------------------------------------------------------------


class TestReplayEvent:
    """Tests for the ReplayEvent frozen dataclass."""

    def test_creation(self) -> None:
        e = _event()
        assert e.agent_id == "agent-1"
        assert e.original_decision == "auto"
        assert e.timestamp == _TS

    def test_frozen(self) -> None:
        e = _event()
        with pytest.raises(AttributeError):
            e.agent_id = "x"  # type: ignore[misc]

    def test_metadata_defaults_to_empty(self) -> None:
        e = ReplayEvent(
            action=_action(),
            agent_id="a",
            timestamp=_TS,
            original_decision="auto",
        )
        assert e.metadata == {}

    def test_metadata_preserved(self) -> None:
        meta = {"source": "test", "version": 2}
        e = _event(metadata=meta)
        assert e.metadata == meta


# ---------------------------------------------------------------------------
# ReplayResult dataclass tests
# ---------------------------------------------------------------------------


class TestReplayResult:
    """Tests for the ReplayResult frozen dataclass."""

    def test_creation(self) -> None:
        e = _event()
        r = ReplayResult(event=e, new_decision="auto", changed=False, change_type="unchanged")
        assert r.changed is False
        assert r.change_type == "unchanged"

    def test_frozen(self) -> None:
        e = _event()
        r = ReplayResult(event=e, new_decision="auto", changed=False, change_type="unchanged")
        with pytest.raises(AttributeError):
            r.changed = True  # type: ignore[misc]

    def test_changed_result(self) -> None:
        e = _event()
        r = ReplayResult(event=e, new_decision="block", changed=True, change_type="newly_blocked")
        assert r.changed is True
        assert r.new_decision == "block"


# ---------------------------------------------------------------------------
# ReplayReport dataclass tests
# ---------------------------------------------------------------------------


class TestReplayReport:
    """Tests for the ReplayReport frozen dataclass."""

    def test_creation(self) -> None:
        rpt = ReplayReport(
            total_events=5,
            changed_count=2,
            unchanged_count=3,
            promoted_count=1,
            restricted_count=1,
            newly_blocked=0,
            results=[],
            summary="test",
        )
        assert rpt.total_events == 5
        assert rpt.changed_count == 2

    def test_frozen(self) -> None:
        rpt = ReplayReport(
            total_events=0,
            changed_count=0,
            unchanged_count=0,
            promoted_count=0,
            restricted_count=0,
            newly_blocked=0,
            results=[],
            summary="",
        )
        with pytest.raises(AttributeError):
            rpt.total_events = 10  # type: ignore[misc]


# ---------------------------------------------------------------------------
# _classify_change tests
# ---------------------------------------------------------------------------


class TestClassifyChange:
    """Tests for the _classify_change helper."""

    def test_unchanged(self) -> None:
        assert _classify_change("auto", "auto") == "unchanged"
        assert _classify_change("approve", "approve") == "unchanged"
        assert _classify_change("block", "block") == "unchanged"

    def test_promoted(self) -> None:
        assert _classify_change("approve", "auto") == "promoted"

    def test_restricted(self) -> None:
        assert _classify_change("auto", "approve") == "restricted"

    def test_newly_blocked(self) -> None:
        assert _classify_change("auto", "block") == "newly_blocked"
        assert _classify_change("approve", "block") == "newly_blocked"

    def test_newly_allowed(self) -> None:
        assert _classify_change("block", "auto") == "newly_allowed"
        assert _classify_change("block", "approve") == "newly_allowed"


# ---------------------------------------------------------------------------
# ReplayEngine.replay_events tests
# ---------------------------------------------------------------------------


class TestReplayEvents:
    """Tests for ReplayEngine.replay_events()."""

    def test_unchanged_actions(self) -> None:
        policy = _permissive_policy()
        engine = ReplayEngine(policy)
        events = [_event(decision="auto")]
        report = engine.replay_events(events)

        assert report.total_events == 1
        assert report.unchanged_count == 1
        assert report.changed_count == 0
        assert report.results[0].change_type == "unchanged"

    def test_promoted_actions(self) -> None:
        """Originally approve, new policy says auto -> promoted."""
        policy = _permissive_policy()
        engine = ReplayEngine(policy)
        events = [_event(decision="approve")]
        report = engine.replay_events(events)

        assert report.promoted_count == 1
        assert report.results[0].change_type == "promoted"
        assert report.results[0].new_decision == "auto"

    def test_restricted_actions(self) -> None:
        """Originally auto, new policy says approve -> restricted."""
        policy = _moderate_policy()
        engine = ReplayEngine(policy)
        events = [_event(decision="auto")]
        report = engine.replay_events(events)

        assert report.restricted_count == 1
        assert report.results[0].change_type == "restricted"

    def test_newly_blocked_actions(self) -> None:
        """Originally auto, new policy says block -> newly_blocked."""
        policy = _strict_policy()
        engine = ReplayEngine(policy)
        events = [_event(decision="auto")]
        report = engine.replay_events(events)

        assert report.newly_blocked == 1
        assert report.results[0].change_type == "newly_blocked"
        assert report.results[0].changed is True

    def test_newly_allowed_actions(self) -> None:
        """Originally block, new policy says auto -> newly_allowed."""
        policy = _permissive_policy()
        engine = ReplayEngine(policy)
        events = [_event(decision="block")]
        report = engine.replay_events(events)

        assert report.changed_count == 1
        assert report.results[0].change_type == "newly_allowed"

    def test_empty_events(self) -> None:
        engine = ReplayEngine(_permissive_policy())
        report = engine.replay_events([])

        assert report.total_events == 0
        assert report.changed_count == 0
        assert report.unchanged_count == 0
        assert report.results == []

    def test_mixed_results(self) -> None:
        """Some events changed, some not."""
        policy = _granular_policy()
        engine = ReplayEngine(policy)
        events = [
            _event(type_="read", decision="auto"),  # unchanged (auto -> auto)
            _event(type_="write", decision="auto"),  # restricted (auto -> approve)
            _event(type_="delete", decision="auto"),  # newly_blocked (auto -> block)
            _event(type_="read", decision="approve"),  # promoted (approve -> auto)
        ]
        report = engine.replay_events(events)

        assert report.total_events == 4
        assert report.unchanged_count == 1
        assert report.changed_count == 3
        assert report.promoted_count == 1
        assert report.restricted_count == 1
        assert report.newly_blocked == 1

    def test_preserves_event_order(self) -> None:
        policy = _permissive_policy()
        engine = ReplayEngine(policy)
        events = [
            _event(type_="read", agent_id="a1"),
            _event(type_="write", agent_id="a2"),
            _event(type_="delete", agent_id="a3"),
        ]
        report = engine.replay_events(events)

        assert len(report.results) == 3
        assert report.results[0].event.agent_id == "a1"
        assert report.results[1].event.agent_id == "a2"
        assert report.results[2].event.agent_id == "a3"

    def test_single_event_report_counts(self) -> None:
        engine = ReplayEngine(_strict_policy())
        events = [_event(decision="auto")]
        report = engine.replay_events(events)

        assert report.total_events == 1
        assert report.changed_count == 1
        assert report.unchanged_count == 0


# ---------------------------------------------------------------------------
# Summary text tests
# ---------------------------------------------------------------------------


class TestSummaryText:
    """Tests for the generated summary string."""

    def test_empty_summary(self) -> None:
        engine = ReplayEngine(_permissive_policy())
        report = engine.replay_events([])
        assert report.summary == "No events to replay."

    def test_all_unchanged_summary(self) -> None:
        engine = ReplayEngine(_permissive_policy())
        events = [_event(decision="auto"), _event(decision="auto")]
        report = engine.replay_events(events)

        assert "2 event(s)" in report.summary
        assert "unchanged" in report.summary

    def test_mixed_summary_includes_details(self) -> None:
        engine = ReplayEngine(_granular_policy())
        events = [
            _event(type_="read", decision="auto"),
            _event(type_="write", decision="auto"),
            _event(type_="delete", decision="auto"),
        ]
        report = engine.replay_events(events)

        assert "3 event(s)" in report.summary
        assert "changed" in report.summary

    def test_newly_blocked_in_summary(self) -> None:
        engine = ReplayEngine(_strict_policy())
        events = [_event(decision="auto")]
        report = engine.replay_events(events)

        assert "newly blocked" in report.summary


# ---------------------------------------------------------------------------
# JSONL loading tests
# ---------------------------------------------------------------------------


class TestJsonlLoading:
    """Tests for load_events_from_jsonl and replay_from_jsonl."""

    def test_load_basic_jsonl(self, tmp_path: Path) -> None:
        records = [
            {
                "action_type": "read",
                "action_target": "db",
                "agent_id": "agent-1",
                "timestamp": "2025-06-01T12:00:00",
                "approval": "auto",
            },
            {
                "action_type": "write",
                "action_target": "crm",
                "agent_id": "agent-2",
                "timestamp": "2025-06-01T13:00:00",
                "approval": "approve",
            },
        ]
        p = tmp_path / "events.jsonl"
        _write_jsonl(p, records)

        events = load_events_from_jsonl(p)
        assert len(events) == 2
        assert events[0].action.type == "read"
        assert events[1].action.type == "write"
        assert events[1].agent_id == "agent-2"

    def test_load_jsonl_with_params(self, tmp_path: Path) -> None:
        records = [
            {
                "action_type": "write",
                "action_target": "db",
                "agent_id": "a1",
                "timestamp": "2025-06-01T12:00:00",
                "approval": "auto",
                "action_params": json.dumps({"key": "value"}),
            },
        ]
        p = tmp_path / "events.jsonl"
        _write_jsonl(p, records)

        events = load_events_from_jsonl(p)
        assert events[0].action.params == {"key": "value"}

    def test_load_jsonl_with_dict_params(self, tmp_path: Path) -> None:
        records = [
            {
                "action_type": "write",
                "action_target": "db",
                "agent_id": "a1",
                "timestamp": "2025-06-01T12:00:00",
                "approval": "auto",
                "action_params": {"key": "value"},
            },
        ]
        p = tmp_path / "events.jsonl"
        _write_jsonl(p, records)

        events = load_events_from_jsonl(p)
        assert events[0].action.params == {"key": "value"}

    def test_load_jsonl_skips_blank_lines(self, tmp_path: Path) -> None:
        p = tmp_path / "events.jsonl"
        content = json.dumps(
            {
                "action_type": "read",
                "action_target": "db",
                "agent_id": "a1",
                "timestamp": "2025-06-01T12:00:00",
                "approval": "auto",
            }
        )
        p.write_text(content + "\n\n\n")

        events = load_events_from_jsonl(p)
        assert len(events) == 1

    def test_load_jsonl_with_metadata(self, tmp_path: Path) -> None:
        records = [
            {
                "action_type": "read",
                "action_target": "db",
                "agent_id": "a1",
                "timestamp": "2025-06-01T12:00:00",
                "approval": "auto",
                "metadata": {"source": "test"},
            },
        ]
        p = tmp_path / "events.jsonl"
        _write_jsonl(p, records)

        events = load_events_from_jsonl(p)
        assert events[0].metadata == {"source": "test"}

    def test_replay_from_jsonl(self, tmp_path: Path) -> None:
        records = [
            {
                "action_type": "read",
                "action_target": "db",
                "agent_id": "a1",
                "timestamp": "2025-06-01T12:00:00",
                "approval": "approve",
            },
        ]
        p = tmp_path / "events.jsonl"
        _write_jsonl(p, records)

        engine = ReplayEngine(_permissive_policy())
        report = engine.replay_from_jsonl(p)

        assert report.total_events == 1
        assert report.promoted_count == 1

    def test_empty_jsonl(self, tmp_path: Path) -> None:
        p = tmp_path / "empty.jsonl"
        p.write_text("")

        events = load_events_from_jsonl(p)
        assert events == []


# ---------------------------------------------------------------------------
# Audit DB loading tests
# ---------------------------------------------------------------------------


class TestAuditDbLoading:
    """Tests for load_events_from_audit_db and replay_from_audit_db."""

    def test_load_from_audit_db(self, tmp_path: Path) -> None:
        db = tmp_path / "audit.db"
        _create_audit_db(
            db,
            [
                {"action_type": "read", "action_target": "db", "approval": "auto"},
                {"action_type": "write", "action_target": "crm", "approval": "approve"},
            ],
        )

        events = load_events_from_audit_db(db)
        assert len(events) == 2
        assert events[0].action.type == "read"
        assert events[1].original_decision == "approve"

    def test_load_from_audit_db_with_session_filter(self, tmp_path: Path) -> None:
        db = tmp_path / "audit.db"
        _create_audit_db(
            db,
            [
                {
                    "action_type": "read",
                    "action_target": "db",
                    "approval": "auto",
                    "session_id": "sess-1",
                },
                {
                    "action_type": "write",
                    "action_target": "crm",
                    "approval": "approve",
                    "session_id": "sess-2",
                },
            ],
        )

        events = load_events_from_audit_db(db, session_id="sess-1")
        assert len(events) == 1
        assert events[0].action.type == "read"

    def test_audit_db_metadata_includes_session(self, tmp_path: Path) -> None:
        db = tmp_path / "audit.db"
        _create_audit_db(
            db,
            [
                {
                    "action_type": "read",
                    "action_target": "db",
                    "approval": "auto",
                    "session_id": "sess-x",
                },
            ],
        )

        events = load_events_from_audit_db(db)
        assert events[0].metadata["session_id"] == "sess-x"

    def test_replay_from_audit_db(self, tmp_path: Path) -> None:
        db = tmp_path / "audit.db"
        _create_audit_db(
            db,
            [
                {"action_type": "read", "action_target": "db", "approval": "approve"},
            ],
        )

        engine = ReplayEngine(_permissive_policy())
        report = engine.replay_from_audit_db(db)

        assert report.total_events == 1
        assert report.promoted_count == 1

    def test_replay_from_audit_db_with_session(self, tmp_path: Path) -> None:
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
                    "action_type": "delete",
                    "action_target": "db",
                    "approval": "auto",
                    "session_id": "s2",
                },
            ],
        )

        engine = ReplayEngine(_strict_policy())
        report = engine.replay_from_audit_db(db, session_id="s1")

        assert report.total_events == 1

    def test_empty_audit_db(self, tmp_path: Path) -> None:
        db = tmp_path / "audit.db"
        _create_audit_db(db, [])

        events = load_events_from_audit_db(db)
        assert events == []


# ---------------------------------------------------------------------------
# what_if tests
# ---------------------------------------------------------------------------


class TestWhatIf:
    """Tests for ReplayEngine.what_if()."""

    def test_what_if_stricter(self) -> None:
        engine = ReplayEngine(_permissive_policy())
        events = [_event(decision="auto")]
        report = engine.what_if(events, _strict_policy())

        assert report.newly_blocked == 1
        assert report.results[0].new_decision == "block"

    def test_what_if_more_permissive(self) -> None:
        engine = ReplayEngine(_strict_policy())
        events = [_event(decision="block")]
        report = engine.what_if(events, _permissive_policy())

        assert report.changed_count == 1
        assert report.results[0].change_type == "newly_allowed"

    def test_what_if_no_change(self) -> None:
        engine = ReplayEngine(_permissive_policy())
        events = [_event(decision="auto")]
        report = engine.what_if(events, _permissive_policy())

        assert report.unchanged_count == 1
        assert report.changed_count == 0

    def test_what_if_multiple_events(self) -> None:
        engine = ReplayEngine(_permissive_policy())
        events = [
            _event(type_="read", decision="auto"),
            _event(type_="write", decision="auto"),
            _event(type_="delete", decision="auto"),
        ]
        report = engine.what_if(events, _granular_policy())

        assert report.total_events == 3
        # read -> auto (unchanged), write -> approve (restricted), delete -> block (newly_blocked)
        assert report.unchanged_count == 1
        assert report.restricted_count == 1
        assert report.newly_blocked == 1

    def test_what_if_does_not_mutate_engine(self) -> None:
        """Ensure what_if does not change the engine's internal policy."""
        original = _permissive_policy()
        engine = ReplayEngine(original)
        events = [_event(decision="auto")]

        engine.what_if(events, _strict_policy())

        # Engine still uses original policy
        report = engine.replay_events(events)
        assert report.unchanged_count == 1


# ---------------------------------------------------------------------------
# compare_policies tests
# ---------------------------------------------------------------------------


class TestComparePolicies:
    """Tests for ReplayEngine.compare_policies()."""

    def test_compare_returns_two_reports(self) -> None:
        engine = ReplayEngine(_permissive_policy())
        events = [_event(decision="auto")]
        report_a, report_b = engine.compare_policies(
            events, _permissive_policy(), _strict_policy()
        )

        assert report_a.total_events == 1
        assert report_b.total_events == 1

    def test_compare_policies_diverge(self) -> None:
        engine = ReplayEngine(_permissive_policy())
        events = [_event(decision="auto")]
        report_a, report_b = engine.compare_policies(
            events, _permissive_policy(), _strict_policy()
        )

        assert report_a.unchanged_count == 1
        assert report_b.newly_blocked == 1

    def test_compare_identical_policies(self) -> None:
        engine = ReplayEngine(_permissive_policy())
        events = [_event(decision="auto")]
        report_a, report_b = engine.compare_policies(
            events, _permissive_policy(), _permissive_policy()
        )

        assert report_a.unchanged_count == report_b.unchanged_count
        assert report_a.changed_count == 0
        assert report_b.changed_count == 0

    def test_compare_with_granular_policy(self) -> None:
        engine = ReplayEngine(_permissive_policy())
        events = [
            _event(type_="read", decision="auto"),
            _event(type_="write", decision="auto"),
            _event(type_="delete", decision="auto"),
        ]
        report_a, report_b = engine.compare_policies(
            events, _permissive_policy(), _granular_policy()
        )

        # Policy A (permissive): all unchanged
        assert report_a.unchanged_count == 3
        # Policy B (granular): read unchanged, write restricted, delete blocked
        assert report_b.unchanged_count == 1
        assert report_b.restricted_count == 1
        assert report_b.newly_blocked == 1

    def test_compare_empty_events(self) -> None:
        engine = ReplayEngine(_permissive_policy())
        report_a, report_b = engine.compare_policies([], _permissive_policy(), _strict_policy())

        assert report_a.total_events == 0
        assert report_b.total_events == 0


# ---------------------------------------------------------------------------
# Policy configuration tests
# ---------------------------------------------------------------------------


class TestDifferentPolicyConfigs:
    """Tests with various policy configurations."""

    def test_default_fallback_policy(self) -> None:
        """When no rules match, defaults apply."""
        policy = Policy(default_approval=Approval.BLOCK)
        engine = ReplayEngine(policy)
        events = [_event(decision="auto")]
        report = engine.replay_events(events)

        assert report.newly_blocked == 1

    def test_agent_specific_rule(self) -> None:
        """Test that agent-specific rules are evaluated."""
        policy = Policy(
            rules=[
                PolicyRule(
                    name="agent_x_block",
                    match_type="*",
                    match_target="*",
                    match_agent="agent-x",
                    risk_level=RiskLevel.CRITICAL,
                    approval=Approval.BLOCK,
                ),
                PolicyRule(
                    name="allow_others",
                    match_type="*",
                    match_target="*",
                    risk_level=RiskLevel.LOW,
                    approval=Approval.AUTO,
                ),
            ],
        )
        engine = ReplayEngine(policy)
        events = [
            _event(agent_id="agent-x", decision="auto"),
            _event(agent_id="agent-y", decision="auto"),
        ]
        report = engine.replay_events(events)

        assert report.results[0].new_decision == "block"
        assert report.results[0].change_type == "newly_blocked"
        assert report.results[1].new_decision == "auto"
        assert report.results[1].change_type == "unchanged"

    def test_target_specific_rule(self) -> None:
        policy = Policy(
            rules=[
                PolicyRule(
                    name="block_prod",
                    match_type="*",
                    match_target="production",
                    approval=Approval.BLOCK,
                ),
                PolicyRule(
                    name="allow_staging",
                    match_type="*",
                    match_target="staging",
                    approval=Approval.AUTO,
                ),
            ],
            default_approval=Approval.APPROVE,
        )
        engine = ReplayEngine(policy)
        events = [
            _event(target="production", decision="auto"),
            _event(target="staging", decision="block"),
        ]
        report = engine.replay_events(events)

        assert report.results[0].change_type == "newly_blocked"
        assert report.results[1].change_type == "newly_allowed"

    def test_multiple_rules_first_match_wins(self) -> None:
        """Verify first-match-wins semantics are preserved."""
        policy = Policy(
            rules=[
                PolicyRule(
                    name="first",
                    match_type="read*",
                    approval=Approval.BLOCK,
                ),
                PolicyRule(
                    name="second",
                    match_type="read*",
                    approval=Approval.AUTO,
                ),
            ],
        )
        engine = ReplayEngine(policy)
        events = [_event(type_="read", decision="auto")]
        report = engine.replay_events(events)

        # First rule matches -> block, not auto
        assert report.results[0].new_decision == "block"

    def test_large_batch_replay(self) -> None:
        """Replay a larger batch to verify no accumulation bugs."""
        engine = ReplayEngine(_strict_policy())
        events = [_event(decision="auto") for _ in range(100)]
        report = engine.replay_events(events)

        assert report.total_events == 100
        assert report.newly_blocked == 100
        assert report.unchanged_count == 0
