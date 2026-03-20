"""Extended tests for the runtime engine covering edge cases."""

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
from aegis.runtime.approval_callback import CallbackApprovalHandler
from aegis.runtime.audit import AuditLogger
from aegis.runtime.engine import Runtime


class FakeExecutor(BaseExecutor):
    """Executor that records calls and returns configurable results."""

    def __init__(self, fail_on: set[str] | None = None):
        self.executed: list[Action] = []
        self._fail_on = fail_on or set()

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
            data={"fake": True},
            completed_at=datetime.now(UTC),
        )

    async def setup(self):
        pass

    async def teardown(self):
        pass


class VerifyFailExecutor(BaseExecutor):
    """Executor where verify always returns False."""

    async def execute(self, action: Action) -> Result:
        return Result(
            action=action,
            status=ResultStatus.SUCCESS,
            data={"ok": True},
            completed_at=datetime.now(UTC),
        )

    async def verify(self, action: Action, result: Result) -> bool:
        return False

    async def setup(self):
        pass

    async def teardown(self):
        pass


@pytest.mark.asyncio
async def test_denied_by_human_operator(tmp_path: Path):
    """When the approval handler denies, result should be DENIED."""
    runtime = Runtime(
        executor=FakeExecutor(),
        policy=Policy(
            rules=[
                PolicyRule(
                    match_type="write",
                    approval=Approval.APPROVE,
                    risk_level=RiskLevel.MEDIUM,
                    name="write_approve",
                ),
            ]
        ),
        approval_handler=CallbackApprovalHandler(lambda d: False),
        audit_logger=AuditLogger(db_path=tmp_path / "deny.db"),
        session_id="test-deny",
    )

    plan = runtime.plan([Action("write", "salesforce")])
    results = await runtime.execute(plan)

    assert len(results) == 1
    assert results[0].status == ResultStatus.DENIED
    assert "Denied by human operator" in results[0].error

    # Verify audit trail records the denial
    entries = runtime.audit.get_log(session_id="test-deny")
    assert len(entries) == 1
    assert entries[0]["human_decision"] == "denied"


@pytest.mark.asyncio
async def test_verification_failure(tmp_path: Path):
    """When verify returns False, result should be FAILED."""
    runtime = Runtime(
        executor=VerifyFailExecutor(),
        policy=Policy(
            rules=[
                PolicyRule(match_type="*", approval=Approval.AUTO, risk_level=RiskLevel.LOW),
            ]
        ),
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "verify_fail.db"),
        session_id="test-verify",
    )

    plan = runtime.plan([Action("read", "test")])
    results = await runtime.execute(plan)

    assert len(results) == 1
    assert results[0].status == ResultStatus.FAILED
    assert "Post-execution verification failed" in results[0].error


@pytest.mark.asyncio
async def test_verification_failure_triggers_fail_fast(tmp_path: Path):
    """Verification failure should trigger fail-fast for remaining actions."""
    runtime = Runtime(
        executor=VerifyFailExecutor(),
        policy=Policy(
            rules=[
                PolicyRule(match_type="*", approval=Approval.AUTO, risk_level=RiskLevel.LOW),
            ]
        ),
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "verify_ff.db"),
        session_id="test-ff",
    )

    plan = runtime.plan(
        [
            Action("read", "a"),
            Action("read", "b"),
        ]
    )
    results = await runtime.execute(plan)

    assert len(results) == 2
    assert results[0].status == ResultStatus.FAILED
    assert results[1].status == ResultStatus.SKIPPED


@pytest.mark.asyncio
async def test_denied_then_skip_remaining(tmp_path: Path):
    """Denied action should trigger fail-fast (DENIED is not BLOCKED/SKIPPED)."""
    runtime = Runtime(
        executor=FakeExecutor(),
        policy=Policy(
            rules=[
                PolicyRule(
                    match_type="write",
                    approval=Approval.APPROVE,
                    risk_level=RiskLevel.MEDIUM,
                    name="write_approve",
                ),
                PolicyRule(
                    match_type="read",
                    approval=Approval.AUTO,
                    risk_level=RiskLevel.LOW,
                    name="read_auto",
                ),
            ]
        ),
        approval_handler=CallbackApprovalHandler(lambda d: False),
        audit_logger=AuditLogger(db_path=tmp_path / "deny_skip.db"),
        session_id="test-deny-skip",
    )

    plan = runtime.plan(
        [
            Action("write", "sf"),  # Will be denied
            Action("read", "sf"),  # Should be skipped (denied != blocked, triggers fail-fast)
        ]
    )
    results = await runtime.execute(plan)

    assert len(results) == 2
    assert results[0].status == ResultStatus.DENIED
    # DENIED is not in the BLOCKED/SKIPPED exclusion, so fail-fast should skip remaining
    assert results[1].status == ResultStatus.SKIPPED


@pytest.mark.asyncio
async def test_session_id_auto_generated(tmp_path: Path):
    """Runtime should auto-generate session_id if not provided."""
    runtime = Runtime(
        executor=FakeExecutor(),
        policy=Policy(rules=[PolicyRule(match_type="*", approval=Approval.AUTO)]),
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "auto.db"),
    )

    assert runtime.session_id is not None
    assert len(runtime.session_id) == 12


@pytest.mark.asyncio
async def test_approved_action_logs_human_decision(tmp_path: Path):
    """When approval is granted, human_decision='approved' should be logged."""
    runtime = Runtime(
        executor=FakeExecutor(),
        policy=Policy(
            rules=[
                PolicyRule(
                    match_type="write",
                    approval=Approval.APPROVE,
                    risk_level=RiskLevel.MEDIUM,
                    name="write_approve",
                ),
            ]
        ),
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "approve_log.db"),
        session_id="test-approve-log",
    )

    plan = runtime.plan([Action("write", "salesforce")])
    results = await runtime.execute(plan)

    assert results[0].ok

    entries = runtime.audit.get_log(session_id="test-approve-log")
    assert entries[0]["human_decision"] == "approved"
