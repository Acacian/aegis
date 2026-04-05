"""Tests for the Autonomy Level module."""

from __future__ import annotations

import threading
import time

import pytest

from aegis.core.autonomy_level import (
    ActionCategory,
    AutonomyCertificate,
    AutonomyLevel,
    AutonomyManager,
    AutonomyPolicy,
    AutonomyViolation,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_manager(**kwargs) -> AutonomyManager:
    return AutonomyManager(**kwargs)


# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------


class TestAutonomyLevelEnum:
    def test_five_levels(self) -> None:
        levels = list(AutonomyLevel)
        assert len(levels) == 5

    def test_ordering(self) -> None:
        assert AutonomyLevel.OBSERVER < AutonomyLevel.APPROVER
        assert AutonomyLevel.APPROVER < AutonomyLevel.CONSULTANT
        assert AutonomyLevel.CONSULTANT < AutonomyLevel.COLLABORATOR
        assert AutonomyLevel.COLLABORATOR < AutonomyLevel.OPERATOR

    def test_int_values(self) -> None:
        assert int(AutonomyLevel.OBSERVER) == 0
        assert int(AutonomyLevel.OPERATOR) == 4


class TestActionCategory:
    def test_five_categories(self) -> None:
        cats = list(ActionCategory)
        assert len(cats) == 5

    def test_values(self) -> None:
        assert ActionCategory.READ == "read"
        assert ActionCategory.APPROVE == "approve"
        assert ActionCategory.SUGGEST == "suggest"
        assert ActionCategory.ACT_WITH_NOTIFY == "act_with_notify"
        assert ActionCategory.ACT_AUTONOMOUS == "act_autonomous"


# ---------------------------------------------------------------------------
# Frozen dataclass tests
# ---------------------------------------------------------------------------


class TestFrozenDataclasses:
    def test_policy_frozen(self) -> None:
        policy = AutonomyPolicy(
            agent_id="a",
            level=AutonomyLevel.OBSERVER,
            max_level=AutonomyLevel.OPERATOR,
        )
        with pytest.raises(AttributeError):
            policy.level = AutonomyLevel.OPERATOR  # type: ignore[misc]

    def test_certificate_frozen(self) -> None:
        cert = AutonomyCertificate(
            agent_id="a",
            level=AutonomyLevel.OBSERVER,
            issuer="admin",
            valid_from=1.0,
            valid_until=None,
            scope="*",
            cert_hash="abc",
        )
        with pytest.raises(AttributeError):
            cert.level = AutonomyLevel.OPERATOR  # type: ignore[misc]

    def test_violation_frozen(self) -> None:
        v = AutonomyViolation(
            agent_id="a",
            attempted_level=AutonomyLevel.OPERATOR,
            allowed_level=AutonomyLevel.OBSERVER,
            action="act_autonomous",
            reason="denied",
        )
        with pytest.raises(AttributeError):
            v.reason = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# AutonomyManager: basic operations
# ---------------------------------------------------------------------------


class TestAutonomyManagerBasic:
    def test_default_level_observer(self) -> None:
        mgr = _build_manager()
        policy = mgr.get_policy("agent-1")
        assert policy.level == AutonomyLevel.OBSERVER

    def test_set_level(self) -> None:
        mgr = _build_manager()
        policy = mgr.set_level("a", AutonomyLevel.COLLABORATOR)
        assert policy.level == AutonomyLevel.COLLABORATOR

    def test_set_level_with_max(self) -> None:
        mgr = _build_manager()
        policy = mgr.set_level("a", AutonomyLevel.CONSULTANT, max_level=AutonomyLevel.CONSULTANT)
        assert policy.level == AutonomyLevel.CONSULTANT
        assert policy.max_level == AutonomyLevel.CONSULTANT

    def test_set_level_exceeds_max_raises(self) -> None:
        mgr = _build_manager()
        with pytest.raises(ValueError, match="exceeds max"):
            mgr.set_level(
                "a",
                AutonomyLevel.OPERATOR,
                max_level=AutonomyLevel.CONSULTANT,
            )

    def test_set_level_with_constraints(self) -> None:
        mgr = _build_manager()
        policy = mgr.set_level(
            "a",
            AutonomyLevel.COLLABORATOR,
            constraints=("no-delete", "no-write-prod"),
        )
        assert "no-delete" in policy.constraints
        assert "no-write-prod" in policy.constraints

    def test_custom_default_level(self) -> None:
        mgr = _build_manager(default_level=AutonomyLevel.CONSULTANT)
        policy = mgr.get_policy("a")
        assert policy.level == AutonomyLevel.CONSULTANT


# ---------------------------------------------------------------------------
# Level-to-action mapping (check_action)
# ---------------------------------------------------------------------------


class TestCheckAction:
    def test_observer_can_read(self) -> None:
        mgr = _build_manager()
        assert mgr.check_action("a", ActionCategory.READ) is True

    def test_observer_cannot_approve(self) -> None:
        mgr = _build_manager()
        assert mgr.check_action("a", ActionCategory.APPROVE) is False

    def test_observer_cannot_act_autonomous(self) -> None:
        mgr = _build_manager()
        assert mgr.check_action("a", ActionCategory.ACT_AUTONOMOUS) is False

    def test_approver_can_approve(self) -> None:
        mgr = _build_manager()
        mgr.set_level("a", AutonomyLevel.APPROVER)
        assert mgr.check_action("a", ActionCategory.APPROVE) is True

    def test_approver_cannot_suggest(self) -> None:
        mgr = _build_manager()
        mgr.set_level("a", AutonomyLevel.APPROVER)
        assert mgr.check_action("a", ActionCategory.SUGGEST) is False

    def test_consultant_can_suggest(self) -> None:
        mgr = _build_manager()
        mgr.set_level("a", AutonomyLevel.CONSULTANT)
        assert mgr.check_action("a", ActionCategory.SUGGEST) is True

    def test_collaborator_can_act_with_notify(self) -> None:
        mgr = _build_manager()
        mgr.set_level("a", AutonomyLevel.COLLABORATOR)
        assert mgr.check_action("a", ActionCategory.ACT_WITH_NOTIFY) is True

    def test_collaborator_cannot_act_autonomous(self) -> None:
        mgr = _build_manager()
        mgr.set_level("a", AutonomyLevel.COLLABORATOR)
        assert mgr.check_action("a", ActionCategory.ACT_AUTONOMOUS) is False

    def test_operator_can_do_everything(self) -> None:
        mgr = _build_manager()
        mgr.set_level("a", AutonomyLevel.OPERATOR)
        for cat in ActionCategory:
            assert mgr.check_action("a", cat) is True


# ---------------------------------------------------------------------------
# Violations
# ---------------------------------------------------------------------------


class TestViolations:
    def test_violation_recorded_on_denial(self) -> None:
        mgr = _build_manager()
        mgr.check_action("a", ActionCategory.ACT_AUTONOMOUS)
        violations = mgr.get_violations("a")
        assert len(violations) == 1
        assert violations[0].action == "act_autonomous"

    def test_no_violation_on_allowed_action(self) -> None:
        mgr = _build_manager()
        mgr.check_action("a", ActionCategory.READ)
        violations = mgr.get_violations("a")
        assert len(violations) == 0

    def test_violation_fields(self) -> None:
        mgr = _build_manager()
        mgr.check_action("a", ActionCategory.SUGGEST)
        v = mgr.get_violations("a")[0]
        assert v.agent_id == "a"
        assert v.allowed_level == AutonomyLevel.OBSERVER
        assert "CONSULTANT" in v.reason

    def test_violations_for_unknown_agent_empty(self) -> None:
        mgr = _build_manager()
        assert mgr.get_violations("nonexistent") == []


# ---------------------------------------------------------------------------
# Policy expiry
# ---------------------------------------------------------------------------


class TestPolicyExpiry:
    def test_expired_policy_resets_to_default(self) -> None:
        mgr = _build_manager()
        now = time.monotonic()
        mgr.set_level(
            "a",
            AutonomyLevel.OPERATOR,
            expires_at=now - 1.0,  # already expired
        )
        policy = mgr.get_policy("a")
        assert policy.level == AutonomyLevel.OBSERVER

    def test_non_expired_policy_persists(self) -> None:
        mgr = _build_manager()
        now = time.monotonic()
        mgr.set_level("a", AutonomyLevel.OPERATOR, expires_at=now + 3600.0)
        policy = mgr.get_policy("a")
        assert policy.level == AutonomyLevel.OPERATOR

    def test_expired_policy_blocks_action(self) -> None:
        mgr = _build_manager()
        now = time.monotonic()
        mgr.set_level("a", AutonomyLevel.OPERATOR, expires_at=now - 1.0)
        assert mgr.check_action("a", ActionCategory.ACT_AUTONOMOUS) is False


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------


class TestCertificates:
    def test_issue_certificate(self) -> None:
        mgr = _build_manager()
        mgr.set_level("a", AutonomyLevel.COLLABORATOR)
        cert = mgr.issue_certificate("a", issuer="admin")
        assert cert.agent_id == "a"
        assert cert.level == AutonomyLevel.COLLABORATOR
        assert cert.issuer == "admin"
        assert len(cert.cert_hash) == 64  # SHA-256 hex

    def test_verify_valid_certificate(self) -> None:
        mgr = _build_manager()
        mgr.set_level("a", AutonomyLevel.CONSULTANT)
        cert = mgr.issue_certificate("a", issuer="admin", scope="read-only")
        assert mgr.verify_certificate(cert) is True

    def test_verify_tampered_certificate(self) -> None:
        mgr = _build_manager()
        mgr.set_level("a", AutonomyLevel.CONSULTANT)
        cert = mgr.issue_certificate("a", issuer="admin")
        # Tamper with the certificate
        tampered = AutonomyCertificate(
            agent_id=cert.agent_id,
            level=AutonomyLevel.OPERATOR,  # changed!
            issuer=cert.issuer,
            valid_from=cert.valid_from,
            valid_until=cert.valid_until,
            scope=cert.scope,
            cert_hash=cert.cert_hash,  # hash won't match
        )
        assert mgr.verify_certificate(tampered) is False

    def test_certificate_with_duration(self) -> None:
        mgr = _build_manager()
        cert = mgr.issue_certificate("a", issuer="admin", valid_duration=3600.0)
        assert cert.valid_until is not None
        assert mgr.verify_certificate(cert) is True

    def test_no_expiry_certificate(self) -> None:
        mgr = _build_manager()
        cert = mgr.issue_certificate("a", issuer="admin")
        assert cert.valid_until is None
        assert mgr.verify_certificate(cert) is True


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------


class TestPermissions:
    def test_observer_permissions(self) -> None:
        mgr = _build_manager()
        perms = mgr.get_permissions("a")
        assert perms == frozenset({ActionCategory.READ})

    def test_operator_permissions(self) -> None:
        mgr = _build_manager()
        mgr.set_level("a", AutonomyLevel.OPERATOR)
        perms = mgr.get_permissions("a")
        assert len(perms) == 5


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


class TestReport:
    def test_empty_report(self) -> None:
        mgr = _build_manager()
        report = mgr.report()
        assert report.total_agents == 0

    def test_report_counts(self) -> None:
        mgr = _build_manager()
        mgr.set_level("a", AutonomyLevel.OPERATOR)
        mgr.set_level("b", AutonomyLevel.CONSULTANT)
        mgr.check_action("b", ActionCategory.ACT_AUTONOMOUS)
        mgr.issue_certificate("a", issuer="admin")
        report = mgr.report()
        assert report.total_agents == 2
        assert report.total_violations == 1
        assert report.active_certificates == 1

    def test_report_level_distribution(self) -> None:
        mgr = _build_manager()
        mgr.set_level("a", AutonomyLevel.OPERATOR)
        mgr.set_level("b", AutonomyLevel.OPERATOR)
        mgr.set_level("c", AutonomyLevel.OBSERVER)
        report = mgr.report()
        assert report.level_distribution[AutonomyLevel.OPERATOR.value] == 2
        assert report.level_distribution[AutonomyLevel.OBSERVER.value] == 1


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_set_level(self) -> None:
        mgr = _build_manager()
        errors: list[Exception] = []

        def worker(agent_id: str) -> None:
            try:
                for level in AutonomyLevel:
                    mgr.set_level(agent_id, level)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(f"a-{i}",)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors

    def test_concurrent_check_action(self) -> None:
        mgr = _build_manager()
        mgr.set_level("shared", AutonomyLevel.CONSULTANT)
        errors: list[Exception] = []

        def worker() -> None:
            try:
                for _ in range(100):
                    mgr.check_action("shared", ActionCategory.SUGGEST)
                    mgr.check_action("shared", ActionCategory.ACT_AUTONOMOUS)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors

    def test_concurrent_mixed_operations(self) -> None:
        mgr = _build_manager()
        errors: list[Exception] = []

        def setter() -> None:
            try:
                for _ in range(50):
                    mgr.set_level("shared", AutonomyLevel.COLLABORATOR)
                    mgr.set_level("shared", AutonomyLevel.OBSERVER)
            except Exception as e:
                errors.append(e)

        def checker() -> None:
            try:
                for _ in range(50):
                    mgr.check_action("shared", ActionCategory.READ)
                    mgr.get_policy("shared")
                    mgr.report()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=setter) for _ in range(2)]
        threads += [threading.Thread(target=checker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_set_same_level_twice(self) -> None:
        mgr = _build_manager()
        mgr.set_level("a", AutonomyLevel.CONSULTANT)
        mgr.set_level("a", AutonomyLevel.CONSULTANT)
        policy = mgr.get_policy("a")
        assert policy.level == AutonomyLevel.CONSULTANT

    def test_empty_constraints(self) -> None:
        mgr = _build_manager()
        policy = mgr.set_level("a", AutonomyLevel.OPERATOR, constraints=())
        assert policy.constraints == ()

    def test_multiple_agents_independent(self) -> None:
        mgr = _build_manager()
        mgr.set_level("a", AutonomyLevel.OPERATOR)
        mgr.set_level("b", AutonomyLevel.OBSERVER)
        assert mgr.check_action("a", ActionCategory.ACT_AUTONOMOUS) is True
        assert mgr.check_action("b", ActionCategory.ACT_AUTONOMOUS) is False
