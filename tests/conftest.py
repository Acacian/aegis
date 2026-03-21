"""Shared test fixtures for Aegis test suite."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegis.adapters.base import BaseExecutor
from aegis.core.action import Action
from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.result import Result, ResultStatus
from aegis.core.risk import RiskLevel
from aegis.runtime.approval import AutoApprovalHandler
from aegis.runtime.audit import AuditLogger
from aegis.runtime.engine import Runtime


class FakeExecutor(BaseExecutor):
    """Executor that records calls and returns configurable results."""

    def __init__(self, fail_on: set[str] | None = None) -> None:
        self.executed: list[Action] = []
        self.setup_called = False
        self.teardown_called = False
        self._fail_on = fail_on or set()

    async def setup(self) -> None:
        self.setup_called = True

    async def teardown(self) -> None:
        self.teardown_called = True

    async def execute(self, action: Action) -> Result:
        self.executed.append(action)
        if action.type in self._fail_on:
            return Result(
                action=action,
                status=ResultStatus.FAILED,
                error=f"Fake failure on {action.type}",
                completed_at=datetime.now(UTC),
            )
        return Result(
            action=action,
            status=ResultStatus.SUCCESS,
            completed_at=datetime.now(UTC),
        )


@pytest.fixture
def sample_policy() -> Policy:
    """Standard test policy with auto/approve/block rules."""
    return Policy(
        rules=[
            PolicyRule(
                match_type="read",
                risk_level=RiskLevel.LOW,
                approval=Approval.AUTO,
                name="read_auto",
            ),
            PolicyRule(
                match_type="write",
                risk_level=RiskLevel.MEDIUM,
                approval=Approval.APPROVE,
                name="write_approve",
            ),
            PolicyRule(
                match_type="delete",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
                name="delete_block",
            ),
        ],
        default_risk_level=RiskLevel.MEDIUM,
        default_approval=Approval.APPROVE,
    )


@pytest.fixture
def fake_executor() -> FakeExecutor:
    """Executor that records calls."""
    return FakeExecutor()


@pytest.fixture
def runtime(tmp_path: Path, sample_policy: Policy, fake_executor: FakeExecutor) -> Runtime:
    """Pre-configured runtime with fake executor and auto-approval."""
    return Runtime(
        executor=fake_executor,
        policy=sample_policy,
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "test.db"),
    )
