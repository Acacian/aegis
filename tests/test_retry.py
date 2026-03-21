"""Tests for retry and rollback policy."""

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
    """Executor that tracks calls and can fail N times before succeeding."""

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


# -- RetryPolicy unit tests ---------------------------------------------------


def test_should_retry_within_limit() -> None:
    policy = RetryPolicy(max_retries=3)
    assert policy.should_retry(0) is True
    assert policy.should_retry(2) is True
    assert policy.should_retry(3) is False


def test_should_retry_with_error_filter() -> None:
    policy = RetryPolicy(max_retries=3, retryable_errors=["timeout", "rate_limit"])
    assert policy.should_retry(0, "connection timeout") is True
    assert policy.should_retry(0, "rate_limit exceeded") is True
    assert policy.should_retry(0, "permission denied") is False


def test_backoff_delay() -> None:
    policy = RetryPolicy(backoff_base=1.0, backoff_max=10.0)
    assert policy.get_delay(0) == 1.0
    assert policy.get_delay(1) == 2.0
    assert policy.get_delay(2) == 4.0
    assert policy.get_delay(3) == 8.0
    assert policy.get_delay(4) == 10.0  # Capped at max


def test_backoff_zero_base() -> None:
    policy = RetryPolicy(backoff_base=0)
    assert policy.get_delay(0) == 0.0
    assert policy.get_delay(5) == 0.0


def test_has_rollback() -> None:
    assert RetryPolicy().has_rollback is False
    assert RetryPolicy(rollback_action_type="undo").has_rollback is True


# -- Runtime retry integration ------------------------------------------------


async def test_no_retry_on_success(auto_policy: Policy, tmp_path: Path) -> None:
    executor = CountingExecutor(fail_count=0)
    runtime = Runtime(
        executor=executor,
        policy=auto_policy,
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "test.db"),
        retry_policy=RetryPolicy(max_retries=3, backoff_base=0),
    )
    result = await runtime.run_one(Action("read", "crm"))
    assert result.ok
    assert len(executor.calls) == 1


async def test_retry_succeeds_after_failures(auto_policy: Policy, tmp_path: Path) -> None:
    executor = CountingExecutor(fail_count=2)
    runtime = Runtime(
        executor=executor,
        policy=auto_policy,
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "test.db"),
        retry_policy=RetryPolicy(max_retries=3, backoff_base=0),
    )
    result = await runtime.run_one(Action("write", "db"))
    assert result.ok
    assert len(executor.calls) == 3  # 2 failures + 1 success


async def test_retry_exhausted(auto_policy: Policy, tmp_path: Path) -> None:
    executor = CountingExecutor(fail_count=10)
    runtime = Runtime(
        executor=executor,
        policy=auto_policy,
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "test.db"),
        retry_policy=RetryPolicy(max_retries=2, backoff_base=0),
    )
    result = await runtime.run_one(Action("write", "db"))
    assert not result.ok
    assert result.status == ResultStatus.FAILED
    assert len(executor.calls) == 3  # 1 initial + 2 retries


async def test_retry_with_error_filter(auto_policy: Policy, tmp_path: Path) -> None:
    executor = CountingExecutor(fail_count=5, error_msg="permission denied")
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
    # Should not retry because error doesn't match filter
    assert len(executor.calls) == 1


async def test_rollback_on_exhaustion(auto_policy: Policy, tmp_path: Path) -> None:
    executor = CountingExecutor(fail_count=100)
    runtime = Runtime(
        executor=executor,
        policy=auto_policy,
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "test.db"),
        retry_policy=RetryPolicy(
            max_retries=1,
            backoff_base=0,
            rollback_action_type="undo_write",
            rollback_params={"reason": "retry_exhausted"},
        ),
    )
    result = await runtime.run_one(Action("write", "db", params={"table": "users"}))
    assert not result.ok
    # 1 initial + 1 retry + 1 rollback = 3 calls
    assert len(executor.calls) == 3
    rollback = executor.calls[-1]
    assert rollback.type == "undo_write"
    assert rollback.target == "db"
    assert rollback.params["table"] == "users"
    assert rollback.params["reason"] == "retry_exhausted"


async def test_no_retry_by_default(auto_policy: Policy, tmp_path: Path) -> None:
    """Default RetryPolicy has max_retries=0, so no retries."""
    executor = CountingExecutor(fail_count=5)
    runtime = Runtime(
        executor=executor,
        policy=auto_policy,
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "test.db"),
    )
    result = await runtime.run_one(Action("write", "db"))
    assert not result.ok
    assert len(executor.calls) == 1  # No retries
