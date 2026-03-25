"""Main runtime engine: plan -> approve -> execute -> verify -> log."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from aegis.adapters.base import BaseExecutor
from aegis.core.action import Action
from aegis.core.plan import ExecutionPlan
from aegis.core.policy import Approval, Policy, PolicyDecision
from aegis.core.result import Result, ResultStatus
from aegis.core.retry import RetryPolicy
from aegis.runtime.approval import ApprovalHandler, CLIApprovalHandler
from aegis.runtime.audit import AuditLogger


@dataclass
class RuntimeHooks:
    """Optional callbacks for runtime lifecycle events.

    Attach hooks to observe or react to governance pipeline events
    without modifying the core execution flow.

    Example::

        async def log_decision(decision: PolicyDecision) -> None:
            print(f"{decision.action.type}: {decision.approval.value}")

        hooks = RuntimeHooks(on_decision=log_decision)
        runtime = Runtime(executor=..., policy=..., hooks=hooks)
    """

    on_decision: Callable[[PolicyDecision], Awaitable[None]] | None = None
    on_approval: Callable[[PolicyDecision, bool], Awaitable[None]] | None = None
    on_execute: Callable[[Result], Awaitable[None]] | None = None


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
        hooks: Optional callbacks for lifecycle events.
        retry_policy: Optional retry/rollback policy for failed actions.
        agent_id: Optional agent identifier. If provided, auto-populates
            into Actions that don't already have an agent_id set.
        parent_session_id: Optional session ID of the parent runtime,
            for cross-runtime session correlation in delegation chains.

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
        hooks: RuntimeHooks | None = None,
        retry_policy: RetryPolicy | None = None,
        agent_id: str = "",
        parent_session_id: str = "",
    ) -> None:
        self.executor = executor
        self.policy = policy
        self.approval = approval_handler or CLIApprovalHandler()
        self.audit = audit_logger or AuditLogger()
        self.session_id = session_id or uuid.uuid4().hex[:12]
        self.hooks = hooks or RuntimeHooks()
        self.retry_policy = retry_policy or RetryPolicy()
        self.agent_id = agent_id
        self.parent_session_id = parent_session_id

    async def __aenter__(self) -> Runtime:
        """Enter async context: set up the executor."""
        await self.executor.setup()
        return self

    async def __aexit__(self, *exc: object) -> None:
        """Exit async context: tear down the executor and close the audit log."""
        await self.executor.teardown()
        self.audit.close()

    def plan(self, actions: list[Action]) -> ExecutionPlan:
        """Evaluate actions against the policy and produce an execution plan.

        If the policy has ``plan_rules``, the plan is also evaluated for
        sequence violations and cumulative risk after individual action
        evaluation.
        """
        resolved = [self._with_agent_context(a) for a in actions]
        decisions = [self.policy.evaluate(action) for action in resolved]
        exec_plan = ExecutionPlan(decisions=decisions)

        # Plan-level evaluation
        if self.policy.plan_rules is not None:
            exec_plan.plan_violations = self.policy.plan_rules.evaluate(exec_plan)

        return exec_plan

    def _with_agent_context(self, action: Action) -> Action:
        """Return the action with agent_id populated if not already set."""
        if self.agent_id and not action.agent_id:
            from dataclasses import replace

            return replace(action, agent_id=self.agent_id)
        return action

    def update_policy(self, policy: Policy) -> None:
        """Hot-reload the policy without restarting the runtime.

        This replaces the current policy atomically. All subsequent
        ``plan()`` calls will use the new policy. In-flight executions
        are not affected.

        Example::

            runtime.update_policy(Policy.from_yaml("new_policy.yaml"))
        """
        self.policy = policy

    async def execute(
        self,
        plan: ExecutionPlan,
        *,
        dry_run: bool = False,
        parallel: bool = False,
    ) -> list[Result]:
        """Execute a plan through the full governance pipeline.

        Args:
            plan: The execution plan to run.
            dry_run: If True, evaluate policy and approval requirements
                but do not actually execute actions. Returns results with
                predicted statuses. Useful for testing policies.
            parallel: If True, execute all actions concurrently via
                ``asyncio.gather``.  Actions are assumed independent;
                fail-fast is disabled in parallel mode.
        """
        # Block entire plan if plan-level violations require it
        blocking_violations = [v for v in plan.plan_violations if v.approval == Approval.BLOCK]
        if blocking_violations:
            reason = blocking_violations[0].description
            return [
                Result(
                    action=d.action,
                    status=ResultStatus.BLOCKED,
                    error=f"Blocked by plan rule: {reason}",
                    completed_at=datetime.now(UTC),
                )
                for d in plan.decisions
            ]

        if not dry_run:
            await self.executor.setup()
        try:
            if parallel:
                return await self._execute_parallel(plan, dry_run=dry_run)
            return await self._execute_sequential(plan, dry_run=dry_run)
        finally:
            if not dry_run:
                await self.executor.teardown()

    async def _execute_sequential(
        self, plan: ExecutionPlan, *, dry_run: bool = False
    ) -> list[Result]:
        """Execute actions one by one with fail-fast semantics."""
        results: list[Result] = []
        for idx, decision in enumerate(plan.decisions):
            result = await self._execute_one(decision, dry_run=dry_run)
            results.append(result)

            if self.hooks.on_execute:
                await self.hooks.on_execute(result)

            # Fail-fast: skip remaining on non-skip failure
            if (
                not dry_run
                and not result.ok
                and result.status
                not in (
                    ResultStatus.BLOCKED,
                    ResultStatus.SKIPPED,
                )
            ):
                for remaining in plan.decisions[idx + 1 :]:
                    skip = Result(
                        action=remaining.action,
                        status=ResultStatus.SKIPPED,
                        error="Skipped due to prior failure",
                        completed_at=datetime.now(UTC),
                    )
                    results.append(skip)
                    self.audit.log(self.session_id, remaining, result=skip)
                break
        return results

    async def _execute_parallel(
        self, plan: ExecutionPlan, *, dry_run: bool = False
    ) -> list[Result]:
        """Execute all actions concurrently via ``asyncio.gather``."""

        async def _run(decision: PolicyDecision) -> Result:
            result = await self._execute_one(decision, dry_run=dry_run)
            if self.hooks.on_execute:
                await self.hooks.on_execute(result)
            return result

        return list(await asyncio.gather(*[_run(d) for d in plan.decisions]))

    async def run_one(self, action: Action, *, dry_run: bool = False) -> Result:
        """Convenience: evaluate + execute a single action.

        Equivalent to ``plan([action])`` + ``execute(plan)`` but returns
        a single :class:`Result` instead of a list.
        """
        plan = self.plan([action])
        results = await self.execute(plan, dry_run=dry_run)
        return results[0]

    async def _execute_one(self, decision: PolicyDecision, *, dry_run: bool = False) -> Result:
        """Execute a single action through the governance pipeline."""
        if self.hooks.on_decision:
            await self.hooks.on_decision(decision)

        # 1. Blocked by policy
        if not decision.is_allowed:
            result = Result(
                action=decision.action,
                status=ResultStatus.BLOCKED,
                error=f"Blocked by policy rule: {decision.matched_rule}",
                completed_at=datetime.now(UTC),
            )
            if not dry_run:
                self.audit.log(self.session_id, decision, result=result)
            return result

        # 2. Approval gate
        human_decision: str | None = None
        if decision.approval == Approval.APPROVE:
            if dry_run:
                # In dry-run, report that approval would be required
                result = Result(
                    action=decision.action,
                    status=ResultStatus.SUCCESS,
                    data={"dry_run": True, "approval_required": True},
                    completed_at=datetime.now(UTC),
                )
                return result

            approved = await self.approval.request_approval(decision)
            if self.hooks.on_approval:
                await self.hooks.on_approval(decision, approved)
            if not approved:
                result = Result(
                    action=decision.action,
                    status=ResultStatus.DENIED,
                    error="Denied by human operator",
                    completed_at=datetime.now(UTC),
                )
                self.audit.log(self.session_id, decision, result=result, human_decision="denied")
                return result
            human_decision = "approved"

        # 3. Dry-run: skip actual execution
        if dry_run:
            return Result(
                action=decision.action,
                status=ResultStatus.SUCCESS,
                data={"dry_run": True, "would_execute": True},
                completed_at=datetime.now(UTC),
            )

        # 4. Execute (with retry support)
        result = await self._execute_with_retry(decision.action)

        # 5. Audit
        self.audit.log(self.session_id, decision, result=result, human_decision=human_decision)

        return result

    async def _execute_with_retry(self, action: Action) -> Result:
        """Execute an action with retry and optional rollback."""
        retry = self.retry_policy
        last_result: Result | None = None

        for attempt in range(retry.max_retries + 1):
            if attempt > 0:
                await retry.wait(attempt - 1)

            result = await self.executor.execute(action)

            # Verify
            verified = await self.executor.verify(action, result)
            if not verified and result.ok:
                result = Result(
                    action=action,
                    status=ResultStatus.FAILED,
                    error="Post-execution verification failed",
                    completed_at=datetime.now(UTC),
                )

            if result.ok:
                return result

            last_result = result

            # Check if we should retry
            if not retry.should_retry(attempt, result.error):
                break

        # All retries exhausted — try rollback if configured
        assert last_result is not None
        if retry.has_rollback:
            rollback_params = {**action.params, **retry.rollback_params}
            rollback_action = Action(
                type=retry.rollback_action_type,
                target=action.target,
                params=rollback_params,
                description=f"Rollback for failed: {action.type}",
            )
            await self.executor.execute(rollback_action)

        return last_result
