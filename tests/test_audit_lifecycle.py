"""Tests for Audit Trails for Accountability in LLMs — lifecycle audit.

Covers:
- Lifecycle event recording and hash chaining
- Timeline report generation
- Hash chain integrity verification
- Compliance checking (EU AI Act, SOC2, GDPR)
- JSON export
- Phase filtering
- Thread safety under concurrent operations
- Edge cases (empty IDs, empty chains, unknown frameworks)
- Frozen dataclass immutability

Reference: arXiv:2601.20727
"""

from __future__ import annotations

import json
import threading
from datetime import datetime

import pytest

from aegis.core.audit_lifecycle import (
    _GENESIS_HASH,
    AuditLifecycle,
    LifecycleEvent,
    LifecyclePhase,
    _compute_event_hash,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def lc() -> AuditLifecycle:
    return AuditLifecycle()


def _record_default(
    lc: AuditLifecycle,
    agent_id: str = "agent-1",
    phase: LifecyclePhase = LifecyclePhase.CREATION,
    action: str = "initialized",
    metadata: dict | None = None,
) -> LifecycleEvent:
    return lc.record_event(agent_id, phase, action, metadata=metadata)


# ---------------------------------------------------------------------------
# Event recording
# ---------------------------------------------------------------------------


class TestEventRecording:
    def test_record_event_basic(self, lc: AuditLifecycle) -> None:
        event = _record_default(lc)
        assert event.agent_id == "agent-1"
        assert event.phase == LifecyclePhase.CREATION
        assert event.action == "initialized"

    def test_event_has_unique_id(self, lc: AuditLifecycle) -> None:
        e1 = _record_default(lc)
        e2 = _record_default(lc, action="configured")
        assert e1.event_id != e2.event_id

    def test_event_has_timestamp(self, lc: AuditLifecycle) -> None:
        event = _record_default(lc)
        assert event.timestamp != ""
        datetime.fromisoformat(event.timestamp)

    def test_event_with_metadata(self, lc: AuditLifecycle) -> None:
        event = _record_default(lc, metadata={"version": "1.0"})
        assert event.metadata["version"] == "1.0"

    def test_event_hash_is_computed(self, lc: AuditLifecycle) -> None:
        event = _record_default(lc)
        assert len(event.event_hash) == 64

    def test_first_event_prev_hash_is_genesis(self, lc: AuditLifecycle) -> None:
        event = _record_default(lc)
        assert event.prev_hash == _GENESIS_HASH

    def test_second_event_chains_to_first(self, lc: AuditLifecycle) -> None:
        e1 = _record_default(lc)
        e2 = _record_default(lc, action="configured")
        assert e2.prev_hash == e1.event_hash

    def test_event_hash_formula(self, lc: AuditLifecycle) -> None:
        event = _record_default(lc)
        expected = _compute_event_hash(
            event.event_id,
            event.phase.value,
            event.action,
            event.timestamp,
            event.prev_hash,
        )
        assert event.event_hash == expected

    def test_empty_agent_id_raises(self, lc: AuditLifecycle) -> None:
        with pytest.raises(ValueError, match="agent_id"):
            lc.record_event("", LifecyclePhase.CREATION, "test")

    def test_empty_action_raises(self, lc: AuditLifecycle) -> None:
        with pytest.raises(ValueError, match="action"):
            lc.record_event("agent-1", LifecyclePhase.CREATION, "")

    def test_all_lifecycle_phases(self, lc: AuditLifecycle) -> None:
        for phase in LifecyclePhase:
            event = lc.record_event("agent-phases", phase, f"action_{phase.value}")
            assert event.phase == phase


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------


class TestTimeline:
    def test_timeline_basic(self, lc: AuditLifecycle) -> None:
        _record_default(lc)
        _record_default(lc, phase=LifecyclePhase.DEPLOYMENT, action="deployed")
        report = lc.get_timeline("agent-1")
        assert report.agent_id == "agent-1"
        assert len(report.events) == 2

    def test_timeline_phase_counts(self, lc: AuditLifecycle) -> None:
        _record_default(lc)
        _record_default(lc, phase=LifecyclePhase.OPERATION, action="action_a")
        _record_default(lc, phase=LifecyclePhase.OPERATION, action="action_b")
        report = lc.get_timeline("agent-1")
        assert report.phase_counts["creation"] == 1
        assert report.phase_counts["operation"] == 2

    def test_timeline_integrity(self, lc: AuditLifecycle) -> None:
        _record_default(lc)
        _record_default(lc, phase=LifecyclePhase.DEPLOYMENT, action="deployed")
        report = lc.get_timeline("agent-1")
        assert report.integrity_valid is True

    def test_timeline_empty_agent(self, lc: AuditLifecycle) -> None:
        report = lc.get_timeline("nonexistent")
        assert len(report.events) == 0
        assert report.integrity_valid is True

    def test_timeline_duration(self, lc: AuditLifecycle) -> None:
        _record_default(lc)
        _record_default(lc, action="later")
        report = lc.get_timeline("agent-1")
        # Duration should be a non-empty string when 2+ events
        assert report.total_duration != "" or len(report.events) < 2


# ---------------------------------------------------------------------------
# Integrity verification
# ---------------------------------------------------------------------------


class TestIntegrity:
    def test_verify_empty_chain(self, lc: AuditLifecycle) -> None:
        assert lc.verify_integrity("agent-1") is True

    def test_verify_single_event(self, lc: AuditLifecycle) -> None:
        _record_default(lc)
        assert lc.verify_integrity("agent-1") is True

    def test_verify_multi_event_chain(self, lc: AuditLifecycle) -> None:
        for i in range(10):
            lc.record_event("agent-1", LifecyclePhase.OPERATION, f"action-{i}")
        assert lc.verify_integrity("agent-1") is True

    def test_verify_separate_agents(self, lc: AuditLifecycle) -> None:
        lc.record_event("agent-a", LifecyclePhase.CREATION, "init")
        lc.record_event("agent-b", LifecyclePhase.CREATION, "init")
        assert lc.verify_integrity("agent-a") is True
        assert lc.verify_integrity("agent-b") is True


# ---------------------------------------------------------------------------
# Compliance checking
# ---------------------------------------------------------------------------


class TestCompliance:
    def _setup_full_lifecycle(self, lc: AuditLifecycle) -> None:
        lc.record_event("agent-1", LifecyclePhase.CREATION, "created")
        lc.record_event("agent-1", LifecyclePhase.CONFIGURATION, "configured")
        lc.record_event("agent-1", LifecyclePhase.DEPLOYMENT, "deployed")
        lc.record_event("agent-1", LifecyclePhase.OPERATION, "running")
        lc.record_event("agent-1", LifecyclePhase.UPDATE, "updated")
        lc.record_event("agent-1", LifecyclePhase.SUSPENSION, "suspended")
        lc.record_event("agent-1", LifecyclePhase.AUDIT, "audited")
        lc.record_event("agent-1", LifecyclePhase.TERMINATION, "terminated")

    def test_eu_ai_act_full_compliance(self, lc: AuditLifecycle) -> None:
        self._setup_full_lifecycle(lc)
        result = lc.check_compliance("agent-1", "eu_ai_act")
        assert result.framework == "eu_ai_act"
        assert result.coverage_pct == 100.0

    def test_soc2_full_compliance(self, lc: AuditLifecycle) -> None:
        self._setup_full_lifecycle(lc)
        result = lc.check_compliance("agent-1", "soc2")
        assert result.coverage_pct == 100.0

    def test_gdpr_full_compliance(self, lc: AuditLifecycle) -> None:
        self._setup_full_lifecycle(lc)
        result = lc.check_compliance("agent-1", "gdpr")
        assert result.coverage_pct == 100.0

    def test_partial_compliance(self, lc: AuditLifecycle) -> None:
        lc.record_event("agent-1", LifecyclePhase.CREATION, "created")
        result = lc.check_compliance("agent-1", "eu_ai_act")
        assert 0 < result.coverage_pct < 100.0
        assert len(result.requirements_met) > 0
        assert len(result.requirements_failed) > 0

    def test_zero_compliance(self, lc: AuditLifecycle) -> None:
        # No events recorded
        result = lc.check_compliance("agent-1", "eu_ai_act")
        assert result.coverage_pct == 0.0
        assert len(result.requirements_failed) > 0

    def test_unknown_framework_raises(self, lc: AuditLifecycle) -> None:
        with pytest.raises(ValueError, match="Unknown framework"):
            lc.check_compliance("agent-1", "unknown_framework")

    def test_compliance_result_structure(self, lc: AuditLifecycle) -> None:
        lc.record_event("agent-1", LifecyclePhase.CREATION, "created")
        result = lc.check_compliance("agent-1", "eu_ai_act")
        assert isinstance(result.requirements_met, tuple)
        assert isinstance(result.requirements_failed, tuple)
        assert isinstance(result.coverage_pct, float)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


class TestExport:
    def test_export_trail_json(self, lc: AuditLifecycle) -> None:
        _record_default(lc)
        exported = lc.export_trail("agent-1")
        data = json.loads(exported)
        assert data["agent_id"] == "agent-1"
        assert data["event_count"] == 1
        assert data["integrity_valid"] is True
        assert len(data["events"]) == 1

    def test_export_empty_trail(self, lc: AuditLifecycle) -> None:
        exported = lc.export_trail("nonexistent")
        data = json.loads(exported)
        assert data["event_count"] == 0
        assert data["events"] == []

    def test_export_preserves_event_data(self, lc: AuditLifecycle) -> None:
        _record_default(lc, metadata={"key": "value"})
        exported = lc.export_trail("agent-1")
        data = json.loads(exported)
        event = data["events"][0]
        assert event["phase"] == "creation"
        assert event["action"] == "initialized"
        assert event["metadata"]["key"] == "value"
        assert len(event["event_hash"]) == 64


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------


class TestQueries:
    def test_get_events_all(self, lc: AuditLifecycle) -> None:
        _record_default(lc)
        _record_default(lc, phase=LifecyclePhase.DEPLOYMENT, action="deployed")
        events = lc.get_events("agent-1")
        assert len(events) == 2

    def test_get_events_by_phase(self, lc: AuditLifecycle) -> None:
        _record_default(lc)
        _record_default(lc, phase=LifecyclePhase.OPERATION, action="op1")
        _record_default(lc, phase=LifecyclePhase.OPERATION, action="op2")
        events = lc.get_events("agent-1", phase=LifecyclePhase.OPERATION)
        assert len(events) == 2

    def test_agent_ids(self, lc: AuditLifecycle) -> None:
        lc.record_event("agent-a", LifecyclePhase.CREATION, "init")
        lc.record_event("agent-b", LifecyclePhase.CREATION, "init")
        ids = lc.agent_ids()
        assert "agent-a" in ids
        assert "agent-b" in ids


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_event_recording(self) -> None:
        lc = AuditLifecycle()
        errors: list[str] = []

        def record(i: int) -> None:
            try:
                lc.record_event("agent-1", LifecyclePhase.OPERATION, f"action-{i}")
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=record, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        events = lc.get_events("agent-1")
        assert len(events) == 50
        # Verify chain integrity after concurrent writes
        assert lc.verify_integrity("agent-1") is True

    def test_concurrent_record_and_verify(self) -> None:
        lc = AuditLifecycle()
        errors: list[str] = []

        def record_events() -> None:
            try:
                for i in range(20):
                    lc.record_event("agent-1", LifecyclePhase.OPERATION, f"op-{i}")
            except Exception as e:
                errors.append(str(e))

        def verify_events() -> None:
            try:
                for _ in range(20):
                    lc.verify_integrity("agent-1")
            except Exception as e:
                errors.append(str(e))

        t1 = threading.Thread(target=record_events)
        t2 = threading.Thread(target=verify_events)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert len(errors) == 0


# ---------------------------------------------------------------------------
# Frozen dataclass immutability
# ---------------------------------------------------------------------------


class TestImmutability:
    def test_event_is_frozen(self, lc: AuditLifecycle) -> None:
        event = _record_default(lc)
        with pytest.raises(AttributeError):
            event.action = "tampered"  # type: ignore[misc]

    def test_report_is_frozen(self, lc: AuditLifecycle) -> None:
        _record_default(lc)
        report = lc.get_timeline("agent-1")
        with pytest.raises(AttributeError):
            report.integrity_valid = False  # type: ignore[misc]

    def test_compliance_check_is_frozen(self, lc: AuditLifecycle) -> None:
        _record_default(lc)
        result = lc.check_compliance("agent-1", "eu_ai_act")
        with pytest.raises(AttributeError):
            result.coverage_pct = 0.0  # type: ignore[misc]

    def test_lifecycle_phase_values(self) -> None:
        """All lifecycle phases should have string values."""
        for phase in LifecyclePhase:
            assert isinstance(phase.value, str)
            assert len(phase.value) > 0
