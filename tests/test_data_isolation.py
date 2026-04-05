"""Tests for IsolateGPT — execution isolation architecture.

Covers:
- Boundary creation and management
- Data classification and sensitivity levels
- Access control checks (allowed, denied, ungoverned)
- Transfer logging (allowed and denied transfers)
- Leakage detection (violations, multi-boundary patterns)
- Isolation health reporting
- Thread safety under concurrent operations
- Edge cases (empty IDs, duplicate boundaries, unknown data)
- Frozen dataclass immutability

Reference: arXiv:2403.04960
"""

from __future__ import annotations

import threading

import pytest

from aegis.core.data_isolation import (
    DataClass,
    DataIsolator,
    IsolationBoundary,
    IsolationViolation,
    SensitivityLevel,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def isolator() -> DataIsolator:
    return DataIsolator()


def _setup_hr_boundary(isolator: DataIsolator) -> IsolationBoundary:
    return isolator.create_boundary(
        "hr-boundary",
        "HR Data Boundary",
        allowed_agents=frozenset({"hr-agent"}),
        data_classes=frozenset({DataClass.PII}),
    )


def _setup_finance_boundary(isolator: DataIsolator) -> IsolationBoundary:
    return isolator.create_boundary(
        "finance-boundary",
        "Finance Data Boundary",
        allowed_agents=frozenset({"finance-agent"}),
        data_classes=frozenset({DataClass.FINANCIAL}),
    )


# ---------------------------------------------------------------------------
# Boundary creation
# ---------------------------------------------------------------------------


class TestBoundaryCreation:
    def test_create_boundary(self, isolator: DataIsolator) -> None:
        boundary = _setup_hr_boundary(isolator)
        assert boundary.boundary_id == "hr-boundary"
        assert boundary.name == "HR Data Boundary"
        assert "hr-agent" in boundary.allowed_agents

    def test_boundary_data_classes(self, isolator: DataIsolator) -> None:
        boundary = _setup_hr_boundary(isolator)
        assert DataClass.PII in boundary.data_classes

    def test_boundary_with_policy(self, isolator: DataIsolator) -> None:
        boundary = isolator.create_boundary(
            "secure",
            "Secure Boundary",
            allowed_agents=frozenset({"admin"}),
            data_classes=frozenset({DataClass.CREDENTIALS}),
            policy={"encryption_required": True},
        )
        assert boundary.policy["encryption_required"] is True

    def test_duplicate_boundary_raises(self, isolator: DataIsolator) -> None:
        _setup_hr_boundary(isolator)
        with pytest.raises(ValueError, match="already exists"):
            _setup_hr_boundary(isolator)

    def test_empty_boundary_id_raises(self, isolator: DataIsolator) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            isolator.create_boundary("", "Empty", frozenset({"a"}), frozenset({DataClass.PII}))

    def test_list_boundaries(self, isolator: DataIsolator) -> None:
        _setup_hr_boundary(isolator)
        _setup_finance_boundary(isolator)
        boundaries = isolator.list_boundaries()
        assert len(boundaries) == 2

    def test_get_boundary(self, isolator: DataIsolator) -> None:
        _setup_hr_boundary(isolator)
        b = isolator.get_boundary("hr-boundary")
        assert b is not None
        assert b.boundary_id == "hr-boundary"

    def test_get_boundary_unknown(self, isolator: DataIsolator) -> None:
        assert isolator.get_boundary("nonexistent") is None


# ---------------------------------------------------------------------------
# Data classification
# ---------------------------------------------------------------------------


class TestDataClassification:
    def test_classify_data(self, isolator: DataIsolator) -> None:
        dc = isolator.classify_data(
            "emp-records",
            DataClass.PII,
            owner="hr-agent",
            level=SensitivityLevel.CONFIDENTIAL,
        )
        assert dc.data_id == "emp-records"
        assert dc.classification == DataClass.PII
        assert dc.owner == "hr-agent"
        assert dc.sensitivity_level == SensitivityLevel.CONFIDENTIAL

    def test_classify_default_level(self, isolator: DataIsolator) -> None:
        dc = isolator.classify_data("doc", DataClass.SYSTEM, owner="sys")
        assert dc.sensitivity_level == SensitivityLevel.INTERNAL

    def test_classify_empty_id_raises(self, isolator: DataIsolator) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            isolator.classify_data("", DataClass.PII, owner="x")

    def test_get_classification(self, isolator: DataIsolator) -> None:
        isolator.classify_data("data-1", DataClass.FINANCIAL, owner="fin")
        dc = isolator.get_classification("data-1")
        assert dc is not None
        assert dc.classification == DataClass.FINANCIAL

    def test_get_classification_unknown(self, isolator: DataIsolator) -> None:
        assert isolator.get_classification("nonexistent") is None

    def test_all_sensitivity_levels_ordered(self) -> None:
        levels = [s.value for s in SensitivityLevel]
        assert levels == sorted(levels)

    def test_all_data_classes_exist(self) -> None:
        expected = {
            "PII",
            "CREDENTIALS",
            "FINANCIAL",
            "HEALTH",
            "PROPRIETARY",
            "SYSTEM",
            "USER_CONTENT",
        }
        actual = {dc.name for dc in DataClass}
        assert actual == expected


# ---------------------------------------------------------------------------
# Access control
# ---------------------------------------------------------------------------


class TestAccessControl:
    def test_allowed_access(self, isolator: DataIsolator) -> None:
        _setup_hr_boundary(isolator)
        isolator.classify_data("emp-records", DataClass.PII, owner="hr-agent")
        assert isolator.check_access("hr-agent", "emp-records", "hr-boundary") is True

    def test_denied_access(self, isolator: DataIsolator) -> None:
        _setup_hr_boundary(isolator)
        isolator.classify_data("emp-records", DataClass.PII, owner="hr-agent")
        assert isolator.check_access("sales-agent", "emp-records", "hr-boundary") is False

    def test_ungoverned_data_class_allowed(self, isolator: DataIsolator) -> None:
        _setup_hr_boundary(isolator)
        # SYSTEM data is not governed by hr-boundary
        isolator.classify_data("logs", DataClass.SYSTEM, owner="sys")
        assert isolator.check_access("sales-agent", "logs", "hr-boundary") is True

    def test_unknown_boundary_denied(self, isolator: DataIsolator) -> None:
        isolator.classify_data("data", DataClass.PII, owner="x")
        assert isolator.check_access("agent", "data", "nonexistent") is False

    def test_unclassified_data_denied(self, isolator: DataIsolator) -> None:
        _setup_hr_boundary(isolator)
        assert isolator.check_access("hr-agent", "unknown-data", "hr-boundary") is False

    def test_multiple_allowed_agents(self, isolator: DataIsolator) -> None:
        isolator.create_boundary(
            "shared",
            "Shared Boundary",
            allowed_agents=frozenset({"agent-a", "agent-b"}),
            data_classes=frozenset({DataClass.USER_CONTENT}),
        )
        isolator.classify_data("doc", DataClass.USER_CONTENT, owner="agent-a")
        assert isolator.check_access("agent-a", "doc", "shared") is True
        assert isolator.check_access("agent-b", "doc", "shared") is True
        assert isolator.check_access("agent-c", "doc", "shared") is False


# ---------------------------------------------------------------------------
# Transfer logging
# ---------------------------------------------------------------------------


class TestTransferLogging:
    def test_allowed_transfer(self, isolator: DataIsolator) -> None:
        _setup_hr_boundary(isolator)
        isolator.classify_data("emp-records", DataClass.PII, owner="hr-agent")
        transfer = isolator.record_transfer("hr-agent", "hr-agent", "emp-records", "hr-boundary")
        assert transfer.allowed is True
        assert transfer.source_agent == "hr-agent"
        assert transfer.target_agent == "hr-agent"

    def test_denied_transfer(self, isolator: DataIsolator) -> None:
        _setup_hr_boundary(isolator)
        isolator.classify_data("emp-records", DataClass.PII, owner="hr-agent")
        transfer = isolator.record_transfer(
            "hr-agent", "sales-agent", "emp-records", "hr-boundary"
        )
        assert transfer.allowed is False

    def test_transfer_has_id_and_timestamp(self, isolator: DataIsolator) -> None:
        _setup_hr_boundary(isolator)
        isolator.classify_data("data", DataClass.PII, owner="hr-agent")
        transfer = isolator.record_transfer("a", "hr-agent", "data", "hr-boundary")
        assert len(transfer.transfer_id) == 32
        assert transfer.timestamp != ""

    def test_get_transfers_all(self, isolator: DataIsolator) -> None:
        _setup_hr_boundary(isolator)
        isolator.classify_data("data", DataClass.PII, owner="hr-agent")
        isolator.record_transfer("a", "hr-agent", "data", "hr-boundary")
        isolator.record_transfer("b", "hr-agent", "data", "hr-boundary")
        transfers = isolator.get_transfers()
        assert len(transfers) == 2

    def test_get_transfers_by_agent(self, isolator: DataIsolator) -> None:
        _setup_hr_boundary(isolator)
        isolator.classify_data("data", DataClass.PII, owner="hr-agent")
        isolator.record_transfer("agent-a", "hr-agent", "data", "hr-boundary")
        isolator.record_transfer("agent-b", "hr-agent", "data", "hr-boundary")
        transfers = isolator.get_transfers(agent_id="agent-a")
        assert len(transfers) == 1

    def test_get_transfers_by_boundary(self, isolator: DataIsolator) -> None:
        _setup_hr_boundary(isolator)
        _setup_finance_boundary(isolator)
        isolator.classify_data("pii-data", DataClass.PII, owner="hr-agent")
        isolator.classify_data("fin-data", DataClass.FINANCIAL, owner="finance-agent")
        isolator.record_transfer("a", "hr-agent", "pii-data", "hr-boundary")
        isolator.record_transfer("b", "finance-agent", "fin-data", "finance-boundary")
        transfers = isolator.get_transfers(boundary_id="hr-boundary")
        assert len(transfers) == 1


# ---------------------------------------------------------------------------
# Leakage detection
# ---------------------------------------------------------------------------


class TestLeakageDetection:
    def test_no_leakage(self, isolator: DataIsolator) -> None:
        _setup_hr_boundary(isolator)
        isolator.classify_data("data", DataClass.PII, owner="hr-agent")
        isolator.record_transfer("x", "hr-agent", "data", "hr-boundary")
        leaks = isolator.detect_leakage()
        assert len(leaks) == 0

    def test_single_violation_detected(self, isolator: DataIsolator) -> None:
        _setup_hr_boundary(isolator)
        isolator.classify_data("data", DataClass.PII, owner="hr-agent")
        isolator.record_transfer("hr-agent", "attacker", "data", "hr-boundary")
        leaks = isolator.detect_leakage()
        assert len(leaks) >= 1
        assert any(v.source_agent == "hr-agent" for v in leaks)

    def test_multi_boundary_violation_pattern(self, isolator: DataIsolator) -> None:
        _setup_hr_boundary(isolator)
        _setup_finance_boundary(isolator)
        isolator.classify_data("pii-data", DataClass.PII, owner="hr-agent")
        isolator.classify_data("fin-data", DataClass.FINANCIAL, owner="finance-agent")
        # Same attacker violates both boundaries
        isolator.record_transfer("attacker", "attacker", "pii-data", "hr-boundary")
        isolator.record_transfer("attacker", "attacker", "fin-data", "finance-boundary")
        leaks = isolator.detect_leakage()
        # Should detect the multi-boundary pattern
        multi = [v for v in leaks if "multiple boundaries" in v.description]
        assert len(multi) >= 1


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


class TestReporting:
    def test_report_no_activity(self, isolator: DataIsolator) -> None:
        report = isolator.report()
        assert report.total_boundaries == 0
        assert report.total_checks == 0
        assert report.isolation_score == 100.0

    def test_report_with_boundaries(self, isolator: DataIsolator) -> None:
        _setup_hr_boundary(isolator)
        _setup_finance_boundary(isolator)
        report = isolator.report()
        assert report.total_boundaries == 2

    def test_report_with_checks(self, isolator: DataIsolator) -> None:
        _setup_hr_boundary(isolator)
        isolator.classify_data("data", DataClass.PII, owner="hr-agent")
        isolator.check_access("hr-agent", "data", "hr-boundary")
        report = isolator.report()
        assert report.total_checks >= 1

    def test_report_perfect_score(self, isolator: DataIsolator) -> None:
        _setup_hr_boundary(isolator)
        isolator.classify_data("data", DataClass.PII, owner="hr-agent")
        isolator.record_transfer("x", "hr-agent", "data", "hr-boundary")
        report = isolator.report()
        assert report.isolation_score == 100.0

    def test_report_with_violations(self, isolator: DataIsolator) -> None:
        _setup_hr_boundary(isolator)
        isolator.classify_data("data", DataClass.PII, owner="hr-agent")
        isolator.record_transfer("hr-agent", "attacker", "data", "hr-boundary")
        report = isolator.report()
        assert len(report.violations) > 0
        assert report.isolation_score < 100.0


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_boundary_creation(self) -> None:
        isolator = DataIsolator()
        errors: list[str] = []

        def create(i: int) -> None:
            try:
                isolator.create_boundary(
                    f"boundary-{i}",
                    f"Boundary {i}",
                    allowed_agents=frozenset({f"agent-{i}"}),
                    data_classes=frozenset({DataClass.PII}),
                )
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=create, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(isolator.list_boundaries()) == 50

    def test_concurrent_access_checks(self) -> None:
        isolator = DataIsolator()
        isolator.create_boundary(
            "boundary",
            "Test Boundary",
            allowed_agents=frozenset({"allowed-agent"}),
            data_classes=frozenset({DataClass.PII}),
        )
        isolator.classify_data("data", DataClass.PII, owner="allowed-agent")

        results: list[bool] = []
        lock = threading.Lock()

        def check(agent: str) -> None:
            r = isolator.check_access(agent, "data", "boundary")
            with lock:
                results.append(r)

        threads = []
        for i in range(25):
            threads.append(threading.Thread(target=check, args=("allowed-agent",)))
            threads.append(threading.Thread(target=check, args=(f"deny-{i}",)))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        allowed_count = sum(1 for r in results if r)
        denied_count = sum(1 for r in results if not r)
        assert allowed_count == 25
        assert denied_count == 25

    def test_concurrent_transfers(self) -> None:
        isolator = DataIsolator()
        isolator.create_boundary(
            "boundary",
            "Test",
            allowed_agents=frozenset({"allowed"}),
            data_classes=frozenset({DataClass.PII}),
        )
        isolator.classify_data("data", DataClass.PII, owner="allowed")

        errors: list[str] = []

        def transfer(i: int) -> None:
            try:
                isolator.record_transfer(f"src-{i}", "allowed", "data", "boundary")
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=transfer, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(isolator.get_transfers()) == 50


# ---------------------------------------------------------------------------
# Frozen dataclass immutability
# ---------------------------------------------------------------------------


class TestImmutability:
    def test_boundary_is_frozen(self, isolator: DataIsolator) -> None:
        boundary = _setup_hr_boundary(isolator)
        with pytest.raises(AttributeError):
            boundary.name = "tampered"  # type: ignore[misc]

    def test_classification_is_frozen(self, isolator: DataIsolator) -> None:
        dc = isolator.classify_data("data", DataClass.PII, owner="x")
        with pytest.raises(AttributeError):
            dc.owner = "tampered"  # type: ignore[misc]

    def test_violation_is_frozen(self) -> None:
        v = IsolationViolation(
            source_agent="a",
            target_agent="b",
            data_class=DataClass.PII,
            boundary_id="x",
            description="test",
        )
        with pytest.raises(AttributeError):
            v.description = "tampered"  # type: ignore[misc]

    def test_report_is_frozen(self, isolator: DataIsolator) -> None:
        report = isolator.report()
        with pytest.raises(AttributeError):
            report.isolation_score = 0.0  # type: ignore[misc]

    def test_transfer_record_is_frozen(self, isolator: DataIsolator) -> None:
        _setup_hr_boundary(isolator)
        isolator.classify_data("data", DataClass.PII, owner="hr-agent")
        transfer = isolator.record_transfer("a", "hr-agent", "data", "hr-boundary")
        with pytest.raises(AttributeError):
            transfer.allowed = False  # type: ignore[misc]
