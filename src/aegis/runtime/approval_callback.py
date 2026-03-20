"""Callback-based approval handler for programmatic approval logic.

Lets you define approval logic as a simple function — no interactive
CLI prompt needed. Useful for:

- Automated testing with custom approval rules
- Webhook-based approvals (wrap your webhook client in the callback)
- Conditional auto-approval (e.g. approve reads, deny writes after hours)

Example::

    from aegis.runtime.approval_callback import CallbackApprovalHandler

    async def my_approval_logic(decision):
        if decision.risk_level <= RiskLevel.MEDIUM:
            return True  # Auto-approve low/medium risk
        # Call external approval service for high/critical
        return await slack_bot.request_approval(decision)

    runtime = Runtime(
        executor=my_executor,
        policy=my_policy,
        approval_handler=CallbackApprovalHandler(my_approval_logic),
    )
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from aegis.core.policy import PolicyDecision
from aegis.runtime.approval import ApprovalHandler


class CallbackApprovalHandler(ApprovalHandler):
    """Approval handler that delegates to a user-provided callback function.

    The callback receives a ``PolicyDecision`` and must return a bool.
    It can be either sync or async.

    Args:
        callback: A function ``(PolicyDecision) -> bool`` or
                  ``async (PolicyDecision) -> bool``.
    """

    def __init__(self, callback: Callable[[PolicyDecision], Any]) -> None:
        self._callback = callback

    async def request_approval(self, decision: PolicyDecision) -> bool:
        result = self._callback(decision)
        if asyncio.iscoroutine(result):
            result = await result
        return bool(result)
