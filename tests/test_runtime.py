"""Tests for the runtime engine."""

from __future__ import annotations

from datetime import datetime, timezone
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


# -- Fake executor for testing -------------------------------------------


class FakeExecutor(BaseExecutor):
    """Executor that records calls and returns configurable results."""

    def __init__(self, fail_on: set[str] | None = None) -> None:
        self.executed: list[Action] = []
        self.setup_called = False
        self.teardown_called = False
        self._fail_on = fail_on or set()

    async def execute(self, action: Action) -> Result:
        self.executed.append(action)
        if action.type in self._fail_on:
            return Result(
                action=action,
                status=ResultStatus.FAILED,
                error=f"Fake failure on {action.type}",
                completed_at=datetime.now(timezone.utc),
            )
        return Result(
            action=action,
            status=ResultStatus.SUCCESS,
            data={"fake": True},
            completed_at=datetime.now(timezone.utc),
        )

    async def setup(self) -> None:
        self.setup_called = True

    async def teardown(self) -> None:
        self.teardown_called = True


# -- Helpers -------------------------------------------------------------


def _make_runtime(
    tmp_path: Path,
    executor: BaseExecutor | None = None,
    policy: Policy | None = None,
) -> Runtime:
    return Runtime(
        executor=executor or FakeExecutor(),
        policy=policy
        or Policy(
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
            ]
        ),
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "test_audit.db"),
        session_id="test-session",
    )


# -- Tests ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_plan_evaluates_actions(tmp_path: Path):
    runtime = _make_runtime(tmp_path)
    plan = runtime.plan(
        [
            Action("read", "salesforce"),
            Action("write", "salesforce"),
            Action("delete", "salesforce"),
        ]
    )
    assert len(plan) == 3
    assert plan.decisions[0].approval == Approval.AUTO
    assert plan.decisions[1].approval == Approval.APPROVE
    assert plan.decisions[2].approval == Approval.BLOCK
    assert plan.has_blocked
    assert plan.requires_approval


@pytest.mark.asyncio
async def test_execute_auto_action(tmp_path: Path):
    executor = FakeExecutor()
    runtime = _make_runtime(tmp_path, executor=executor)
    plan = runtime.plan([Action("read", "salesforce")])
    results = await runtime.execute(plan)

    assert len(results) == 1
    assert results[0].ok
    assert len(executor.executed) == 1
    assert executor.setup_called
    assert executor.teardown_called


@pytest.mark.asyncio
async def test_execute_blocked_action(tmp_path: Path):
    executor = FakeExecutor()
    runtime = _make_runtime(tmp_path, executor=executor)
    plan = runtime.plan([Action("delete", "salesforce")])
    results = await runtime.execute(plan)

    assert len(results) == 1
    assert results[0].status == ResultStatus.BLOCKED
    assert len(executor.executed) == 0  # Never reached the executor


@pytest.mark.asyncio
async def test_execute_approved_action(tmp_path: Path):
    executor = FakeExecutor()
    runtime = _make_runtime(tmp_path, executor=executor)
    plan = runtime.plan([Action("write", "salesforce")])
    results = await runtime.execute(plan)

    # AutoApprovalHandler approves everything
    assert len(results) == 1
    assert results[0].ok
    assert len(executor.executed) == 1


@pytest.mark.asyncio
async def test_fail_fast_skips_remaining(tmp_path: Path):
    executor = FakeExecutor(fail_on={"write"})
    runtime = _make_runtime(tmp_path, executor=executor)
    plan = runtime.plan(
        [
            Action("read", "salesforce"),
            Action("write", "salesforce"),  # This will fail
            Action("read", "stripe"),  # This should be skipped
        ]
    )
    results = await runtime.execute(plan)

    assert len(results) == 3
    assert results[0].ok
    assert results[1].status == ResultStatus.FAILED
    assert results[2].status == ResultStatus.SKIPPED


@pytest.mark.asyncio
async def test_blocked_does_not_trigger_fail_fast(tmp_path: Path):
    executor = FakeExecutor()
    runtime = _make_runtime(tmp_path, executor=executor)
    plan = runtime.plan(
        [
            Action("delete", "salesforce"),  # Blocked
            Action("read", "salesforce"),  # Should still execute
        ]
    )
    results = await runtime.execute(plan)

    assert len(results) == 2
    assert results[0].status == ResultStatus.BLOCKED
    assert results[1].ok


@pytest.mark.asyncio
async def test_audit_trail(tmp_path: Path):
    runtime = _make_runtime(tmp_path)
    plan = runtime.plan(
        [
            Action("read", "salesforce"),
            Action("delete", "salesforce"),
        ]
    )
    await runtime.execute(plan)

    entries = runtime.audit.get_log(session_id="test-session")
    assert len(entries) == 2
    assert entries[0]["action_type"] == "read"
    assert entries[0]["result_status"] == "success"
    assert entries[1]["action_type"] == "delete"
    assert entries[1]["result_status"] == "blocked"


@pytest.mark.asyncio
async def test_teardown_called_on_error(tmp_path: Path):
    """Teardown should be called even if execution raises."""

    class ExplodingExecutor(BaseExecutor):
        teardown_called = False

        async def execute(self, action: Action) -> Result:
            raise RuntimeError("boom")

        async def teardown(self) -> None:
            self.teardown_called = True

    executor = ExplodingExecutor()
    runtime = Runtime(
        executor=executor,
        policy=Policy(rules=[PolicyRule(match_type="*", approval=Approval.AUTO)]),
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "test.db"),
    )
    plan = runtime.plan([Action("read", "test")])

    with pytest.raises(RuntimeError, match="boom"):
        await runtime.execute(plan)

    assert executor.teardown_called


@pytest.mark.asyncio
async def test_plan_summary(tmp_path: Path):
    runtime = _make_runtime(tmp_path)
    plan = runtime.plan(
        [
            Action("read", "salesforce"),
            Action("write", "salesforce"),
            Action("delete", "salesforce"),
        ]
    )
    summary = plan.summary()
    assert "AUTO" in summary
    assert "APPROVE" in summary
    assert "BLOCK" in summary
