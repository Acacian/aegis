"""Tests for aegis.integrations.errors error classes."""

from __future__ import annotations

from aegis.integrations.errors import AegisBlockedError, AegisGuardrailError

# -- AegisBlockedError ---------------------------------------------------


def test_blocked_error_has_reason():
    err = AegisBlockedError("policy violation")
    assert err.reason == "policy violation"


def test_blocked_error_has_decision():
    sentinel = object()
    err = AegisBlockedError("blocked", decision=sentinel)
    assert err.decision is sentinel


def test_blocked_error_decision_defaults_none():
    err = AegisBlockedError("blocked")
    assert err.decision is None


def test_blocked_error_guardrail_results_default():
    err = AegisBlockedError("blocked")
    assert err.guardrail_results == []


def test_blocked_error_guardrail_results_passed():
    results = [{"rule": "pii"}]
    err = AegisBlockedError("blocked", guardrail_results=results)
    assert err.guardrail_results is results


def test_blocked_error_message_includes_reason():
    err = AegisBlockedError("something was blocked")
    assert "something was blocked" in str(err)


def test_blocked_error_is_exception():
    assert issubclass(AegisBlockedError, Exception)


# -- AegisGuardrailError ------------------------------------------------


def test_guardrail_error_is_subclass_of_blocked():
    assert issubclass(AegisGuardrailError, AegisBlockedError)


def test_guardrail_error_instance_of_blocked():
    err = AegisGuardrailError("pii detected")
    assert isinstance(err, AegisBlockedError)


def test_guardrail_error_has_reason():
    err = AegisGuardrailError("guardrail triggered")
    assert err.reason == "guardrail triggered"


def test_guardrail_error_message_includes_reason():
    err = AegisGuardrailError("injection detected")
    assert "injection detected" in str(err)


def test_guardrail_error_accepts_guardrail_results():
    results = [{"guardrail": "pii_detector", "action": "blocked"}]
    err = AegisGuardrailError("pii", guardrail_results=results)
    assert err.guardrail_results == results


def test_guardrail_error_accepts_decision():
    sentinel = object()
    err = AegisGuardrailError("blocked", decision=sentinel)
    assert err.decision is sentinel
