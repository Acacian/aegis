"""Tests for approval handlers."""

from __future__ import annotations

import pytest

from aegis.core.action import Action
from aegis.core.policy import Approval, PolicyDecision
from aegis.core.risk import RiskLevel
from aegis.runtime.approval import AutoApprovalHandler
from aegis.runtime.approval_callback import CallbackApprovalHandler


def _make_decision(risk: RiskLevel = RiskLevel.MEDIUM) -> PolicyDecision:
    return PolicyDecision(
        action=Action("test", "target"),
        risk_level=risk,
        approval=Approval.APPROVE,
        matched_rule="test_rule",
    )


@pytest.mark.asyncio
async def test_auto_approval():
    handler = AutoApprovalHandler()
    assert await handler.request_approval(_make_decision()) is True


@pytest.mark.asyncio
async def test_callback_sync_approve():
    handler = CallbackApprovalHandler(lambda d: True)
    assert await handler.request_approval(_make_decision()) is True


@pytest.mark.asyncio
async def test_callback_sync_deny():
    handler = CallbackApprovalHandler(lambda d: False)
    assert await handler.request_approval(_make_decision()) is False


@pytest.mark.asyncio
async def test_callback_async():
    async def async_approve(decision: PolicyDecision) -> bool:
        return decision.risk_level <= RiskLevel.MEDIUM

    handler = CallbackApprovalHandler(async_approve)
    assert await handler.request_approval(_make_decision(RiskLevel.LOW)) is True
    assert await handler.request_approval(_make_decision(RiskLevel.HIGH)) is False


@pytest.mark.asyncio
async def test_callback_risk_based():
    """Callback that approves only low-risk actions."""

    def risk_gate(decision: PolicyDecision) -> bool:
        return decision.risk_level == RiskLevel.LOW

    handler = CallbackApprovalHandler(risk_gate)
    assert await handler.request_approval(_make_decision(RiskLevel.LOW)) is True
    assert await handler.request_approval(_make_decision(RiskLevel.MEDIUM)) is False
    assert await handler.request_approval(_make_decision(RiskLevel.CRITICAL)) is False
