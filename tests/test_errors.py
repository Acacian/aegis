"""Tests for error hierarchy."""

from __future__ import annotations

from aegis.integrations.errors import (
    AegisApprovalTimeout,
    AegisAuditError,
    AegisBlockedError,
    AegisConfigError,
    AegisConnectionError,
    AegisError,
    AegisExecutionError,
    AegisGuardrailError,
    AegisPolicyError,
)


class TestErrorHierarchy:
    def test_all_inherit_from_aegis_error(self):
        errors = [
            AegisBlockedError,
            AegisGuardrailError,
            AegisPolicyError,
            AegisConfigError,
            AegisConnectionError,
            AegisApprovalTimeout,
            AegisExecutionError,
            AegisAuditError,
        ]
        for err_cls in errors:
            assert issubclass(err_cls, AegisError), f"{err_cls.__name__} must inherit AegisError"

    def test_aegis_error_is_exception(self):
        assert issubclass(AegisError, Exception)

    def test_guardrail_error_inherits_blocked(self):
        assert issubclass(AegisGuardrailError, AegisBlockedError)

    def test_catch_all_with_aegis_error(self):
        with __import__("pytest").raises(AegisError):
            raise AegisPolicyError("bad policy")

    def test_blocked_error_attributes(self):
        err = AegisBlockedError("blocked", decision="d", guardrail_results=["r1"])
        assert err.reason == "blocked"
        assert err.decision == "d"
        assert err.guardrail_results == ["r1"]
        assert str(err) == "blocked"

    def test_blocked_error_defaults(self):
        err = AegisBlockedError("test")
        assert err.decision is None
        assert err.guardrail_results == []

    def test_top_level_import(self):
        import aegis

        assert aegis.AegisError is AegisError
        assert aegis.AegisPolicyError is AegisPolicyError
        assert aegis.AegisConfigError is AegisConfigError
        assert aegis.AegisConnectionError is AegisConnectionError
        assert aegis.AegisApprovalTimeout is AegisApprovalTimeout
        assert aegis.AegisExecutionError is AegisExecutionError
        assert aegis.AegisAuditError is AegisAuditError

    def test_each_error_can_be_raised_and_caught(self):
        import pytest

        for err_cls in [
            AegisPolicyError,
            AegisConfigError,
            AegisConnectionError,
            AegisApprovalTimeout,
            AegisExecutionError,
            AegisAuditError,
        ]:
            with pytest.raises(err_cls):
                raise err_cls(f"test {err_cls.__name__}")
