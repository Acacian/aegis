"""Tests for aegis.integrations.decorators — the @guard decorator."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from aegis.core.action import Action
from aegis.core.policy import Approval, PolicyDecision
from aegis.core.risk import RiskLevel
from aegis.integrations.decorators import guard
from aegis.integrations.errors import AegisBlockedError

# -- Helpers to build mock policy decisions ------------------------------


def _make_decision(approval: Approval, matched_rule: str = "test_rule") -> PolicyDecision:
    action = Action(type="execute", target="test")
    return PolicyDecision(
        action=action,
        risk_level=RiskLevel.LOW,
        approval=approval,
        matched_rule=matched_rule,
    )


def _mock_policy(approval: Approval = Approval.AUTO, matched_rule: str = "test_rule"):
    """Return a mock Policy whose evaluate() returns the given approval."""
    decision = _make_decision(approval, matched_rule)
    policy = MagicMock()
    policy.evaluate.return_value = decision
    return policy


# -- Sync function tests -------------------------------------------------


@patch("aegis.integrations.decorators._load_policy")
def test_guard_sync_allowed(mock_load):
    """Decorated sync function runs normally when policy allows."""
    mock_load.return_value = _mock_policy(Approval.AUTO)

    @guard
    def my_func(x, y):
        return x + y

    assert my_func(2, 3) == 5


@patch("aegis.integrations.decorators._load_policy")
def test_guard_sync_blocked_raises(mock_load):
    """Blocked action raises AegisBlockedError by default."""
    mock_load.return_value = _mock_policy(Approval.BLOCK)

    @guard
    def my_func():
        return "should not reach"

    with pytest.raises(AegisBlockedError):
        my_func()


# -- Async function tests ------------------------------------------------


@patch("aegis.integrations.decorators._load_policy")
def test_guard_async_allowed(mock_load):
    """Decorated async function runs normally when policy allows."""
    mock_load.return_value = _mock_policy(Approval.AUTO)

    @guard
    async def my_async_func(x):
        return x * 2

    result = asyncio.run(my_async_func(5))
    assert result == 10


@patch("aegis.integrations.decorators._load_policy")
def test_guard_async_blocked_raises(mock_load):
    """Blocked async action raises AegisBlockedError."""
    mock_load.return_value = _mock_policy(Approval.BLOCK)

    @guard
    async def my_async_func():
        return "nope"

    with pytest.raises(AegisBlockedError):
        asyncio.run(my_async_func())


# -- Parenthesized vs bare usage ----------------------------------------


@patch("aegis.integrations.decorators._load_policy")
def test_guard_with_parentheses(mock_load):
    """@guard(action_type='write') works with explicit kwargs."""
    mock_load.return_value = _mock_policy(Approval.AUTO)

    @guard(action_type="write")
    def save_data(data):
        return data

    assert save_data({"key": "value"}) == {"key": "value"}


@patch("aegis.integrations.decorators._load_policy")
def test_guard_without_parentheses(mock_load):
    """@guard (bare, no parens) works as a decorator."""
    mock_load.return_value = _mock_policy(Approval.AUTO)

    @guard
    def read_data():
        return "data"

    assert read_data() == "data"


# -- on_block strategies -------------------------------------------------


@patch("aegis.integrations.decorators._load_policy")
def test_on_block_raise(mock_load):
    """on_block='raise' raises AegisBlockedError."""
    mock_load.return_value = _mock_policy(Approval.BLOCK, matched_rule="block_rule")

    @guard(on_block="raise")
    def blocked_func():
        return "never"

    with pytest.raises(AegisBlockedError, match="block_rule"):
        blocked_func()


@patch("aegis.integrations.decorators._load_policy")
def test_on_block_return_none(mock_load):
    """on_block='return_none' returns None instead of raising."""
    mock_load.return_value = _mock_policy(Approval.BLOCK)

    @guard(on_block="return_none")
    def blocked_func():
        return "unreachable"

    result = blocked_func()
    assert result is None


@patch("aegis.integrations.decorators._load_policy")
def test_on_block_log(mock_load):
    """on_block='log' logs a warning and returns None (does not call function)."""
    mock_load.return_value = _mock_policy(Approval.BLOCK)

    call_tracker = MagicMock()

    @guard(on_block="log")
    def blocked_func():
        call_tracker()
        return "value"

    result = blocked_func()
    # The function is NOT called when blocked — _handle_block returns None
    assert result is None
    call_tracker.assert_not_called()


# -- Result preservation -------------------------------------------------


@patch("aegis.integrations.decorators._load_policy")
def test_function_result_preserved(mock_load):
    """The original return value is passed through when allowed."""
    mock_load.return_value = _mock_policy(Approval.AUTO)

    @guard
    def compute():
        return {"status": "ok", "count": 42}

    result = compute()
    assert result == {"status": "ok", "count": 42}


@patch("aegis.integrations.decorators._load_policy")
def test_async_function_result_preserved(mock_load):
    """The async return value is passed through when allowed."""
    mock_load.return_value = _mock_policy(Approval.AUTO)

    @guard
    async def compute_async():
        return [1, 2, 3]

    result = asyncio.run(compute_async())
    assert result == [1, 2, 3]


# -- functools.wraps metadata preservation --------------------------------


@patch("aegis.integrations.decorators._load_policy")
def test_wraps_preserves_name(mock_load):
    """functools.wraps preserves __name__."""
    mock_load.return_value = _mock_policy(Approval.AUTO)

    @guard
    def my_special_function():
        """My docstring."""
        return True

    assert my_special_function.__name__ == "my_special_function"


@patch("aegis.integrations.decorators._load_policy")
def test_wraps_preserves_doc(mock_load):
    """functools.wraps preserves __doc__."""
    mock_load.return_value = _mock_policy(Approval.AUTO)

    @guard
    def documented_func():
        """This function has documentation."""
        return True

    assert documented_func.__doc__ == "This function has documentation."


@patch("aegis.integrations.decorators._load_policy")
def test_wraps_preserves_module(mock_load):
    """functools.wraps preserves __module__."""
    mock_load.return_value = _mock_policy(Approval.AUTO)

    @guard
    def some_func():
        return True

    assert some_func.__module__ == __name__


@patch("aegis.integrations.decorators._load_policy")
def test_wraps_preserves_async_name(mock_load):
    """functools.wraps preserves __name__ on async functions."""
    mock_load.return_value = _mock_policy(Approval.AUTO)

    @guard
    async def async_named_func():
        """Async docstring."""
        return True

    assert async_named_func.__name__ == "async_named_func"
    assert async_named_func.__doc__ == "Async docstring."


# -- Keyword arguments passed through ------------------------------------


@patch("aegis.integrations.decorators._load_policy")
def test_kwargs_passed_through(mock_load):
    """Keyword arguments are correctly forwarded to the wrapped function."""
    mock_load.return_value = _mock_policy(Approval.AUTO)

    @guard
    def greet(name, greeting="hello"):
        return f"{greeting}, {name}"

    assert greet("world", greeting="hi") == "hi, world"


# -- AegisBlockedError attributes ----------------------------------------


@patch("aegis.integrations.decorators._load_policy")
def test_blocked_error_has_decision_attr(mock_load):
    """AegisBlockedError carries the decision object."""
    mock_load.return_value = _mock_policy(Approval.BLOCK, matched_rule="deny_all")

    @guard(on_block="raise")
    def forbidden():
        return None

    with pytest.raises(AegisBlockedError) as exc_info:
        forbidden()

    err = exc_info.value
    assert err.decision is not None
    assert err.decision.approval == Approval.BLOCK
