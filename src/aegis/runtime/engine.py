"""Main runtime engine: plan -> approve -> execute -> verify -> log."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from aegis.adapters.base import BaseExecutor
from aegis.core.action import Action
from aegis.core.plan import ExecutionPlan
from aegis.core.policy import Approval, Policy, PolicyDecision
from aegis.core.result import Result, ResultStatus
from aegis.runtime.approval import ApprovalHandler, CLIApprovalHandler
from aegis.runtime.audit import AuditLogger


class Runtime:
    """Aegis runtime: policy-gated execution of AI agent actions.

    Orchestrates the full governance pipeline:
    policy check -> approval gate -> execution -> verification -> audit log.

    Args:
        executor: Adapter that carries out actions (e.g. PlaywrightExecutor).
        policy: Policy rules that govern which actions are allowed.
        approval_handler: Handler for human-in-the-loop approval. Defaults to CLI.
        audit_logger: Logger for audit trail. Defaults to local SQLite.
        session_id: Optional session identifier for audit grouping.

    Example::

        runtime = Runtime(
            executor=PlaywrightExecutor(),
            policy=Policy.from_yaml("policy.yaml"),
        )
        plan = runtime.plan([
            Action("read", target="salesforce", params={"selector": ".list"}),
        ])
        results = await runtime.execute(plan)
    """

    def __init__(
        self,
        *,
        executor: BaseExecutor,
        policy: Policy,
        approval_handler: ApprovalHandler | None = None,
        audit_logger: AuditLogger | None = None,
        session_id: str | None = None,
    ) -> None:
        self.executor = executor
        self.policy = policy
        self.approval = approval_handler or CLIApprovalHandler()
        self.audit = audit_logger or AuditLogger()
        self.session_id = session_id or uuid.uuid4().hex[:12]

    def plan(self, actions: list[Action]) -> ExecutionPlan:
        """Evaluate actions against the policy and produce an execution plan."""
        decisions = [self.policy.evaluate(action) for action in actions]
        return ExecutionPlan(decisions=decisions)

    async def execute(self, plan: ExecutionPlan) -> list[Result]:
        """Execute a plan through the full governance pipeline.

        Actions are executed sequentially. If an action fails,
        all remaining actions are marked as skipped (fail-fast).
        """
        results: list[Result] = []

        await self.executor.setup()
        try:
            for idx, decision in enumerate(plan.decisions):
                result = await self._execute_one(decision)
                results.append(result)

                # Fail-fast: skip remaining on non-skip failure
                if not result.ok and result.status not in (
                    ResultStatus.BLOCKED,
                    ResultStatus.SKIPPED,
                ):
                    for remaining in plan.decisions[idx + 1 :]:
                        skip = Result(
                            action=remaining.action,
                            status=ResultStatus.SKIPPED,
                            error="Skipped due to prior failure",
                            completed_at=datetime.now(timezone.utc),
                        )
                        results.append(skip)
                        self.audit.log(self.session_id, remaining, result=skip)
                    break
        finally:
            await self.executor.teardown()

        return results

    async def _execute_one(self, decision: PolicyDecision) -> Result:
        """Execute a single action through the governance pipeline."""
        # 1. Blocked by policy
        if not decision.is_allowed:
            result = Result(
                action=decision.action,
                status=ResultStatus.BLOCKED,
                error=f"Blocked by policy rule: {decision.matched_rule}",
                completed_at=datetime.now(timezone.utc),
            )
            self.audit.log(self.session_id, decision, result=result)
            return result

        # 2. Approval gate
        human_decision: str | None = None
        if decision.approval == Approval.APPROVE:
            approved = await self.approval.request_approval(decision)
            if not approved:
                result = Result(
                    action=decision.action,
                    status=ResultStatus.DENIED,
                    error="Denied by human operator",
                    completed_at=datetime.now(timezone.utc),
                )
                self.audit.log(
                    self.session_id, decision, result=result, human_decision="denied"
                )
                return result
            human_decision = "approved"

        # 3. Execute
        result = await self.executor.execute(decision.action)

        # 4. Verify
        verified = await self.executor.verify(decision.action, result)
        if not verified and result.ok:
            result = Result(
                action=decision.action,
                status=ResultStatus.FAILED,
                error="Post-execution verification failed",
                completed_at=datetime.now(timezone.utc),
            )

        # 5. Audit
        self.audit.log(
            self.session_id, decision, result=result, human_decision=human_decision
        )

        return result
