"""Tests for product features: dry-run, hot-reload, plan filtering, audit queries, hooks."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegis.core.action import Action
from aegis.core.plan import ExecutionPlan
from aegis.core.policy import Approval, Policy, PolicyDecision, PolicyRule
from aegis.core.result import Result, ResultStatus
from aegis.core.risk import RiskLevel
from aegis.runtime.approval import AutoApprovalHandler
from aegis.runtime.audit import AuditLogger
from aegis.runtime.engine import Runtime, RuntimeHooks

# -- Helpers -----------------------------------------------------------------


def _decision(
    action_type: str = "read",
    target: str = "crm",
    risk: RiskLevel = RiskLevel.LOW,
    approval: Approval = Approval.AUTO,
) -> PolicyDecision:
    return PolicyDecision(
        action=Action(action_type, target),
        risk_level=risk,
        approval=approval,
    )


# -- Fixtures ----------------------------------------------------------------


@pytest.fixture()
def policy() -> Policy:
    return Policy(
        rules=[
            PolicyRule(
                match_type="read*",
                risk_level=RiskLevel.LOW,
                approval=Approval.AUTO,
                name="read_auto",
            ),
            PolicyRule(
                match_type="write*",
                risk_level=RiskLevel.HIGH,
                approval=Approval.APPROVE,
                name="write_approve",
            ),
            PolicyRule(
                match_type="delete*",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
                name="delete_block",
            ),
        ]
    )


@pytest.fixture()
def audit(tmp_path: Path) -> AuditLogger:
    return AuditLogger(db_path=tmp_path / "test.db")


# -- ExecutionPlan.to_dict ---------------------------------------------------


def test_plan_to_dict(policy: Policy) -> None:
    plan = ExecutionPlan(
        decisions=[
            policy.evaluate(Action("read", "crm")),
            policy.evaluate(Action("delete", "crm")),
        ]
    )
    data = plan.to_dict()
    decisions = data["decisions"]
    assert len(decisions) == 2
    assert decisions[0]["action_type"] == "read"
    assert decisions[0]["risk_level"] == "low"
    assert decisions[0]["approval"] == "auto"
    assert decisions[0]["is_allowed"] is True
    assert decisions[1]["action_type"] == "delete"
    assert decisions[1]["is_allowed"] is False
    assert data["plan_violations"] == []


# -- ExecutionPlan.filter ----------------------------------------------------


def test_plan_filter_allowed_only(policy: Policy) -> None:
    plan = ExecutionPlan(
        decisions=[
            policy.evaluate(Action("read", "crm")),
            policy.evaluate(Action("delete", "crm")),
            policy.evaluate(Action("write", "crm")),
        ]
    )
    filtered = plan.filter(allowed_only=True)
    assert len(filtered) == 2
    assert all(d.is_allowed for d in filtered)


def test_plan_filter_by_approval(policy: Policy) -> None:
    plan = ExecutionPlan(
        decisions=[
            policy.evaluate(Action("read", "crm")),
            policy.evaluate(Action("write", "crm")),
        ]
    )
    auto_only = plan.filter(approval=Approval.AUTO)
    assert len(auto_only) == 1
    assert auto_only[0].matched_rule == "read_auto"


def test_plan_filter_by_risk_level(policy: Policy) -> None:
    plan = ExecutionPlan(
        decisions=[
            policy.evaluate(Action("read", "crm")),
            policy.evaluate(Action("write", "crm")),
            policy.evaluate(Action("delete", "crm")),
        ]
    )
    high_risk = plan.filter(risk_level=RiskLevel.HIGH)
    assert len(high_risk) == 1
    assert high_risk[0].matched_rule == "write_approve"


def test_plan_filter_combined(policy: Policy) -> None:
    plan = ExecutionPlan(
        decisions=[
            policy.evaluate(Action("read", "crm")),
            policy.evaluate(Action("write", "crm")),
            policy.evaluate(Action("delete", "crm")),
        ]
    )
    safe = plan.filter(approval=Approval.AUTO, allowed_only=True)
    assert len(safe) == 1
    assert safe[0].matched_rule == "read_auto"


# -- ExecutionPlan iteration -------------------------------------------------


def test_plan_iteration(policy: Policy) -> None:
    plan = ExecutionPlan(
        decisions=[
            policy.evaluate(Action("read", "crm")),
            policy.evaluate(Action("write", "crm")),
        ]
    )
    types = [d.action.type for d in plan]
    assert types == ["read", "write"]


def test_plan_indexing(policy: Policy) -> None:
    plan = ExecutionPlan(
        decisions=[
            policy.evaluate(Action("read", "crm")),
            policy.evaluate(Action("write", "crm")),
        ]
    )
    assert plan[0].action.type == "read"
    assert plan[1].action.type == "write"


def test_plan_auto_only(policy: Policy) -> None:
    auto_plan = ExecutionPlan(decisions=[policy.evaluate(Action("read", "crm"))])
    assert auto_plan.auto_only is True

    mixed_plan = ExecutionPlan(
        decisions=[
            policy.evaluate(Action("read", "crm")),
            policy.evaluate(Action("write", "crm")),
        ]
    )
    assert mixed_plan.auto_only is False


# -- Dry-run mode ------------------------------------------------------------


class FakeExecutor:
    """Executor that tracks calls for testing."""

    def __init__(self) -> None:
        self.executed: list[Action] = []

    async def execute(self, action: Action) -> Result:
        self.executed.append(action)
        return Result(action=action, status=ResultStatus.SUCCESS)

    async def verify(self, action: Action, result: Result) -> bool:
        return result.ok

    async def setup(self) -> None:
        pass

    async def teardown(self) -> None:
        pass


async def test_dry_run_does_not_execute(policy: Policy, audit: AuditLogger) -> None:
    executor = FakeExecutor()
    runtime = Runtime(
        executor=executor,
        policy=policy,
        approval_handler=AutoApprovalHandler(),
        audit_logger=audit,
    )
    plan = runtime.plan([Action("read", "crm"), Action("read", "db")])
    results = await runtime.execute(plan, dry_run=True)

    assert len(results) == 2
    assert all(r.status == ResultStatus.SUCCESS for r in results)
    assert all(r.data.get("dry_run") is True for r in results)
    # Executor should NOT have been called
    assert len(executor.executed) == 0


async def test_dry_run_shows_blocked(policy: Policy, audit: AuditLogger) -> None:
    runtime = Runtime(
        executor=FakeExecutor(),
        policy=policy,
        approval_handler=AutoApprovalHandler(),
        audit_logger=audit,
    )
    result = await runtime.run_one(Action("delete", "crm"), dry_run=True)
    assert result.status == ResultStatus.BLOCKED


async def test_dry_run_shows_approval_required(policy: Policy, audit: AuditLogger) -> None:
    runtime = Runtime(
        executor=FakeExecutor(),
        policy=policy,
        approval_handler=AutoApprovalHandler(),
        audit_logger=audit,
    )
    result = await runtime.run_one(Action("write", "crm"), dry_run=True)
    assert result.status == ResultStatus.SUCCESS
    assert result.data["approval_required"] is True


async def test_dry_run_does_not_audit(policy: Policy, audit: AuditLogger) -> None:
    runtime = Runtime(
        executor=FakeExecutor(),
        policy=policy,
        approval_handler=AutoApprovalHandler(),
        audit_logger=audit,
    )
    await runtime.run_one(Action("read", "crm"), dry_run=True)
    entries = audit.get_log()
    assert len(entries) == 0


# -- Policy hot-reload -------------------------------------------------------


async def test_update_policy(audit: AuditLogger) -> None:
    initial = Policy(
        rules=[
            PolicyRule(
                match_type="read",
                approval=Approval.BLOCK,
                name="block_all",
            )
        ]
    )
    runtime = Runtime(
        executor=FakeExecutor(),
        policy=initial,
        approval_handler=AutoApprovalHandler(),
        audit_logger=audit,
    )

    # Initially blocked
    result = await runtime.run_one(Action("read", "crm"))
    assert result.status == ResultStatus.BLOCKED

    # Hot-reload to allow reads
    new_policy = Policy(
        rules=[
            PolicyRule(
                match_type="read",
                approval=Approval.AUTO,
                name="allow_reads",
            )
        ]
    )
    runtime.update_policy(new_policy)

    result = await runtime.run_one(Action("read", "crm"))
    assert result.status == ResultStatus.SUCCESS


# -- Runtime hooks -----------------------------------------------------------


async def test_hooks_on_decision(policy: Policy, audit: AuditLogger) -> None:
    decisions_seen: list[PolicyDecision] = []

    async def track_decision(d: PolicyDecision) -> None:
        decisions_seen.append(d)

    hooks = RuntimeHooks(on_decision=track_decision)
    runtime = Runtime(
        executor=FakeExecutor(),
        policy=policy,
        approval_handler=AutoApprovalHandler(),
        audit_logger=audit,
        hooks=hooks,
    )
    await runtime.run_one(Action("read", "crm"))
    assert len(decisions_seen) == 1
    assert decisions_seen[0].action.type == "read"


async def test_hooks_on_execute(policy: Policy, audit: AuditLogger) -> None:
    results_seen: list[Result] = []

    async def track_result(r: Result) -> None:
        results_seen.append(r)

    hooks = RuntimeHooks(on_execute=track_result)
    runtime = Runtime(
        executor=FakeExecutor(),
        policy=policy,
        approval_handler=AutoApprovalHandler(),
        audit_logger=audit,
        hooks=hooks,
    )
    plan = runtime.plan([Action("read", "crm"), Action("read", "db")])
    await runtime.execute(plan)
    assert len(results_seen) == 2


async def test_hooks_on_approval(audit: AuditLogger) -> None:
    approvals_seen: list[tuple[PolicyDecision, bool]] = []

    async def track_approval(d: PolicyDecision, approved: bool) -> None:
        approvals_seen.append((d, approved))

    policy = Policy(
        rules=[
            PolicyRule(
                match_type="write",
                approval=Approval.APPROVE,
                name="w",
            )
        ]
    )
    hooks = RuntimeHooks(on_approval=track_approval)
    runtime = Runtime(
        executor=FakeExecutor(),
        policy=policy,
        approval_handler=AutoApprovalHandler(),
        audit_logger=audit,
        hooks=hooks,
    )
    await runtime.run_one(Action("write", "crm"))
    assert len(approvals_seen) == 1
    assert approvals_seen[0][1] is True


# -- Audit query filters ----------------------------------------------------


def test_audit_query_by_action_type(audit: AuditLogger) -> None:
    d1 = _decision("read", risk=RiskLevel.LOW)
    d2 = _decision("write", risk=RiskLevel.HIGH, approval=Approval.APPROVE)
    r = Result(action=d1.action, status=ResultStatus.SUCCESS)

    audit.log("s1", d1, result=r)
    audit.log(
        "s1",
        d2,
        result=Result(action=d2.action, status=ResultStatus.SUCCESS),
    )

    reads = audit.get_log(action_type="read")
    assert len(reads) == 1
    assert reads[0]["action_type"] == "read"


def test_audit_query_by_risk_level(audit: AuditLogger) -> None:
    d_low = _decision("read", risk=RiskLevel.LOW)
    d_high = _decision(
        "write",
        risk=RiskLevel.HIGH,
        approval=Approval.APPROVE,
    )

    audit.log(
        "s1",
        d_low,
        result=Result(action=d_low.action, status=ResultStatus.SUCCESS),
    )
    audit.log(
        "s1",
        d_high,
        result=Result(action=d_high.action, status=ResultStatus.SUCCESS),
    )

    highs = audit.get_log(risk_level="HIGH")
    assert len(highs) == 1
    assert highs[0]["risk_level"] == "HIGH"


def test_audit_query_by_result_status(audit: AuditLogger) -> None:
    d = _decision(
        "delete",
        risk=RiskLevel.CRITICAL,
        approval=Approval.BLOCK,
    )
    audit.log(
        "s1",
        d,
        result=Result(action=d.action, status=ResultStatus.BLOCKED),
    )
    audit.log(
        "s1",
        _decision("read"),
        result=Result(
            action=Action("read", "crm"),
            status=ResultStatus.SUCCESS,
        ),
    )

    blocked = audit.get_log(result_status="blocked")
    assert len(blocked) == 1
    assert blocked[0]["result_status"] == "blocked"


def test_audit_query_with_limit(audit: AuditLogger) -> None:
    for i in range(10):
        d = _decision("read", target=f"target_{i}")
        audit.log(
            "s1",
            d,
            result=Result(action=d.action, status=ResultStatus.SUCCESS),
        )

    limited = audit.get_log(limit=3)
    assert len(limited) == 3


def test_audit_count(audit: AuditLogger) -> None:
    for _ in range(5):
        d = _decision("read")
        audit.log(
            "s1",
            d,
            result=Result(action=d.action, status=ResultStatus.SUCCESS),
        )

    d_high = _decision(
        "write",
        risk=RiskLevel.HIGH,
        approval=Approval.APPROVE,
    )
    audit.log(
        "s1",
        d_high,
        result=Result(action=d_high.action, status=ResultStatus.SUCCESS),
    )

    assert audit.count() == 6
    assert audit.count(action_type="read") == 5
    assert audit.count(risk_level="HIGH") == 1


def test_audit_query_by_date_range(audit: AuditLogger) -> None:
    d = _decision("read")
    audit.log(
        "s1",
        d,
        result=Result(action=d.action, status=ResultStatus.SUCCESS),
    )

    # Query for entries since far past — should find it
    since = datetime(2020, 1, 1, tzinfo=UTC)
    entries = audit.get_log(since=since)
    assert len(entries) == 1

    # Query for entries since far future — should not find it
    future = datetime(2030, 1, 1, tzinfo=UTC)
    entries = audit.get_log(since=future)
    assert len(entries) == 0
