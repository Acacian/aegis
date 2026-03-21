"""Tests for concurrent usage: multiple async tasks, runtime safety, watcher lifecycle."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from aegis.core.action import Action
from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.result import Result, ResultStatus
from aegis.core.risk import RiskLevel
from aegis.runtime.approval import AutoApprovalHandler
from aegis.runtime.audit import AuditLogger
from aegis.runtime.engine import Runtime
from tests.conftest import FakeExecutor

# -- Runtime with multiple async tasks --------------------------------------


@pytest.mark.asyncio
async def test_multiple_run_one_concurrent(tmp_path: Path) -> None:
    """Multiple concurrent run_one calls should not corrupt state."""
    executor = FakeExecutor()
    policy = Policy(
        rules=[
            PolicyRule(
                match_type="*",
                risk_level=RiskLevel.LOW,
                approval=Approval.AUTO,
                name="auto_all",
            ),
        ]
    )
    runtime = Runtime(
        executor=executor,
        policy=policy,
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "test.db"),
        session_id="concurrent-test",
    )

    # Run 20 actions concurrently
    tasks = [runtime.run_one(Action(f"read_{i}", "db")) for i in range(20)]
    results = await asyncio.gather(*tasks)

    assert len(results) == 20
    assert all(r.ok for r in results)

    # Audit should have 20 entries
    entries = runtime.audit.get_log(session_id="concurrent-test")
    assert len(entries) == 20
    runtime.audit.close()


@pytest.mark.asyncio
async def test_concurrent_plan_and_execute(tmp_path: Path) -> None:
    """Concurrent plan + execute should produce correct results."""
    executor = FakeExecutor()
    policy = Policy(
        rules=[
            PolicyRule(match_type="read*", approval=Approval.AUTO, name="auto_read"),
            PolicyRule(match_type="delete*", approval=Approval.BLOCK, name="block_delete"),
        ]
    )
    runtime = Runtime(
        executor=executor,
        policy=policy,
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "test.db"),
    )

    async def plan_and_execute(action: Action) -> Result:
        plan = runtime.plan([action])
        results = await runtime.execute(plan)
        return results[0]

    tasks = [
        plan_and_execute(Action("read", "db")),
        plan_and_execute(Action("delete", "db")),
        plan_and_execute(Action("read", "cache")),
    ]
    results = await asyncio.gather(*tasks)

    assert results[0].ok
    assert results[1].status == ResultStatus.BLOCKED
    assert results[2].ok
    runtime.audit.close()


# -- Runtime context manager resource cleanup --------------------------------


@pytest.mark.asyncio
async def test_runtime_context_manager_cleanup(tmp_path: Path) -> None:
    """Runtime async context manager should set up and tear down executor."""
    executor = FakeExecutor()
    runtime = Runtime(
        executor=executor,
        policy=Policy(rules=[PolicyRule(match_type="*", approval=Approval.AUTO)]),
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "ctx.db"),
    )

    async with runtime:
        assert executor.setup_called

    assert executor.teardown_called


@pytest.mark.asyncio
async def test_runtime_context_manager_cleanup_on_error(tmp_path: Path) -> None:
    """Runtime should clean up even if execution raises."""
    from aegis.adapters.base import BaseExecutor

    class ExplodingExecutor(BaseExecutor):
        setup_called = False
        teardown_called = False

        async def execute(self, action: Action) -> Result:
            raise RuntimeError("boom")

        async def setup(self) -> None:
            self.setup_called = True

        async def teardown(self) -> None:
            self.teardown_called = True

    executor = ExplodingExecutor()
    runtime = Runtime(
        executor=executor,
        policy=Policy(rules=[PolicyRule(match_type="*", approval=Approval.AUTO)]),
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "ctx.db"),
    )

    async with runtime:
        assert executor.setup_called
        plan = runtime.plan([Action("read", "test")])
        with pytest.raises(RuntimeError, match="boom"):
            await runtime.execute(plan)

    assert executor.teardown_called


# -- Policy update during execution -----------------------------------------


@pytest.mark.asyncio
async def test_policy_update_between_executions(tmp_path: Path) -> None:
    """Updating policy between executions should affect subsequent plans."""
    executor = FakeExecutor()
    runtime = Runtime(
        executor=executor,
        policy=Policy(
            rules=[PolicyRule(match_type="read", approval=Approval.BLOCK, name="block")]
        ),
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=tmp_path / "test.db"),
    )

    # First: read is blocked
    r1 = await runtime.run_one(Action("read", "db"))
    assert r1.status == ResultStatus.BLOCKED

    # Update policy
    runtime.update_policy(
        Policy(rules=[PolicyRule(match_type="read", approval=Approval.AUTO, name="allow")])
    )

    # Second: read is now allowed
    r2 = await runtime.run_one(Action("read", "db"))
    assert r2.ok
    runtime.audit.close()
