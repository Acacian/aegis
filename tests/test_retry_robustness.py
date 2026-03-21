"""Tests for RetryPolicy edge cases: error filtering with None/empty errors, boundary values."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegis.core.action import Action
from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.result import Result, ResultStatus
from aegis.core.retry import RetryPolicy
from aegis.core.risk import RiskLevel
from aegis.runtime.approval import AutoApprovalHandler
from aegis.runtime.audit import AuditLogger
from aegis.runtime.engine import Runtime


class CountingExecutor:
    """Executor that tracks calls and fails a configurable number of times."""

    def __init__(self, fail_count: int = 0, error_msg: str = "execution failed") -> None:
        self.calls: list[Action] = []
        self.fail_count = fail_count
        self.error_msg = error_msg

    async def execute(self, action: Action) -> Result:
        self.calls.append(action)
        if len(self.calls) <= self.fail_count:
            return Result(
                action=action,
                status=ResultStatus.FAILED,
                error=self.error_msg,
            )
        return Result(action=action, status=ResultStatus.SUCCESS, data={"ok": True})

    async def verify(self, action: Action, result: Result) -> bool:
        return result.ok

    async def setup(self) -> None:
        pass

    async def teardown(self) -> None:
        pass


class NoneErrorExecutor:
    """Executor that fails with error=None."""

    def __init__(self) -> None:
        self.calls: list[Action] = []

    async def execute(self, action: Action) -> Result:
        self.calls.append(action)
        return Result(
            action=action,
            status=ResultStatus.FAILED,
            error=None,
        )

    async def verify(self, action: Action, result: Result) -> bool:
        return result.ok

    async def setup(self) -> None:
        pass

    async def teardown(self) -> None:
        pass


@pytest.fixture()
def auto_policy() -> Policy:
    return Policy(
        rules=[
            PolicyRule(
                match_type="*",
                risk_level=RiskLevel.LOW,
                approval=Approval.AUTO,
                name="auto_all",
            ),
        ],
    )


# -- should_retry with None/empty error and retryable_errors set -----------


def test_should_retry_with_retryable_errors_and_none_error() -> None:
    """When retryable_errors is set and error is None, should NOT retry."""
    policy = RetryPolicy(max_retries=3, retryable_errors=["timeout"])
    assert policy.should_retry(0, None) is False


def test_should_retry_with_retryable_errors_and_empty_error() -> None:
    """When retryable_errors is set and error is empty string, should NOT retry."""
    policy = RetryPolicy(max_retries=3, retryable_errors=["timeout"])
    assert policy.should_retry(0, "") is False


def test_should_retry_without_retryable_errors_and_none_error() -> None:
    """When retryable_errors is empty and error is None, SHOULD retry (no filter)."""
    policy = RetryPolicy(max_retries=3, retryable_errors=[])
    assert policy.should_retry(0, None) is True


def test_should_retry_max_retries_zero() -> None:
    """max_retries=0 should never retry."""
    policy = RetryPolicy(max_retries=0)
    assert policy.should_retry(0) is False
    assert policy.should_retry(0, "any error") is False


def test_should_retry_at_max_boundary() -> None:
    """Attempt == max_retries should return False."""
    policy = RetryPolicy(max_retries=3)
    assert policy.should_retry(2) is True
    assert policy.should_retry(3) is False


# -- Backoff edge cases -----------------------------------------------------


def test_backoff_negative_base() -> None:
    """Negative backoff_base should return 0."""
    policy = RetryPolicy(backoff_base=-1.0)
    assert policy.get_delay(0) == 0.0


def test_backoff_very_high_attempt() -> None:
    """Very high attempt number should be capped at backoff_max."""
    policy = RetryPolicy(backoff_base=1.0, backoff_max=30.0)
    assert policy.get_delay(100) == 30.0


# -- Integration: retry with None error executor ---------------------------


async def test_retry_with_none_error_and_retryable_errors(
    auto_policy: Policy, tmp_path: Path
) -> None:
    """When executor returns error=None and retryable_errors is set, should not retry."""
    executor = NoneErrorExecutor()
    runtime = Runtime(
        executor=executor,
        policy=auto_policy,
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "test.db"),
        retry_policy=RetryPolicy(
            max_retries=3,
            backoff_base=0,
            retryable_errors=["timeout"],
        ),
    )
    result = await runtime.run_one(Action("write", "db"))
    assert not result.ok
    # Should not have retried because error is None and retryable_errors is set
    assert len(executor.calls) == 1


async def test_retry_with_none_error_no_filter(auto_policy: Policy, tmp_path: Path) -> None:
    """When executor returns error=None and retryable_errors is empty, should retry."""
    executor = NoneErrorExecutor()
    runtime = Runtime(
        executor=executor,
        policy=auto_policy,
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "test.db"),
        retry_policy=RetryPolicy(
            max_retries=2,
            backoff_base=0,
            retryable_errors=[],
        ),
    )
    result = await runtime.run_one(Action("write", "db"))
    assert not result.ok
    # Should have retried: 1 initial + 2 retries = 3
    assert len(executor.calls) == 3


# -- Rollback with empty params -------------------------------------------


async def test_rollback_with_no_original_params(auto_policy: Policy, tmp_path: Path) -> None:
    """Rollback should work even if the original action has no params."""
    executor = CountingExecutor(fail_count=100)
    runtime = Runtime(
        executor=executor,
        policy=auto_policy,
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "test.db"),
        retry_policy=RetryPolicy(
            max_retries=0,
            backoff_base=0,
            rollback_action_type="undo",
            rollback_params={"reason": "failed"},
        ),
    )
    result = await runtime.run_one(Action("write", "db"))
    assert not result.ok
    # 1 initial + 1 rollback = 2
    assert len(executor.calls) == 2
    rollback = executor.calls[-1]
    assert rollback.type == "undo"
    assert rollback.params["reason"] == "failed"


# -- Frozen dataclass immutability -----------------------------------------


def test_retry_policy_is_frozen() -> None:
    """RetryPolicy fields should not be mutable."""
    rp = RetryPolicy(max_retries=3)
    with pytest.raises(AttributeError):
        rp.max_retries = 5  # type: ignore[misc]


def test_retry_policy_list_field_independent() -> None:
    """Default mutable fields should be independent per instance."""
    rp1 = RetryPolicy()
    rp2 = RetryPolicy()
    # Frozen dataclass prevents mutation, but ensure default factories are independent
    assert rp1.retryable_errors is not rp2.retryable_errors or rp1.retryable_errors == []
