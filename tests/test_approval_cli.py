"""Tests for CLIApprovalHandler."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from aegis.core.action import Action
from aegis.core.policy import Approval, PolicyDecision
from aegis.core.risk import RiskLevel
from aegis.runtime.approval import CLIApprovalHandler


def _make_decision(
    action_type: str = "write",
    target: str = "salesforce",
    risk: RiskLevel = RiskLevel.MEDIUM,
    params: dict | None = None,
    description: str = "",
) -> PolicyDecision:
    return PolicyDecision(
        action=Action(action_type, target, params=params or {}, description=description),
        risk_level=risk,
        approval=Approval.APPROVE,
        matched_rule="test_rule",
    )


@pytest.mark.asyncio
async def test_cli_approve_y():
    """CLIApprovalHandler should return True on 'y' input."""
    handler = CLIApprovalHandler()
    decision = _make_decision()

    with patch("builtins.input", return_value="y"):
        result = await handler.request_approval(decision)
    assert result is True


@pytest.mark.asyncio
async def test_cli_approve_yes():
    """CLIApprovalHandler should return True on 'yes' input."""
    handler = CLIApprovalHandler()
    decision = _make_decision()

    with patch("builtins.input", return_value="yes"):
        result = await handler.request_approval(decision)
    assert result is True


@pytest.mark.asyncio
async def test_cli_deny_n():
    """CLIApprovalHandler should return False on 'n' input."""
    handler = CLIApprovalHandler()
    decision = _make_decision()

    with patch("builtins.input", return_value="n"):
        result = await handler.request_approval(decision)
    assert result is False


@pytest.mark.asyncio
async def test_cli_deny_no():
    """CLIApprovalHandler should return False on 'no' input."""
    handler = CLIApprovalHandler()
    decision = _make_decision()

    with patch("builtins.input", return_value="no"):
        result = await handler.request_approval(decision)
    assert result is False


@pytest.mark.asyncio
async def test_cli_retry_on_invalid_input(capsys):
    """CLIApprovalHandler should re-prompt on invalid input before accepting valid."""
    handler = CLIApprovalHandler()
    decision = _make_decision()

    with patch("builtins.input", side_effect=["maybe", "what", "y"]):
        result = await handler.request_approval(decision)

    assert result is True
    captured = capsys.readouterr()
    assert "Please enter 'y' or 'n'" in captured.out


@pytest.mark.asyncio
async def test_cli_displays_action_info(capsys):
    """CLIApprovalHandler should display action details."""
    handler = CLIApprovalHandler()
    decision = _make_decision(
        action_type="write",
        target="salesforce",
        risk=RiskLevel.HIGH,
        params={"field": "name", "value": "John"},
        description="Update contact name",
    )

    with patch("builtins.input", return_value="y"):
        await handler.request_approval(decision)

    captured = capsys.readouterr()
    assert "APPROVAL REQUIRED" in captured.out
    assert "write" in captured.out
    assert "salesforce" in captured.out
    assert "HIGH" in captured.out
    assert "test_rule" in captured.out
    assert "field" in captured.out
    assert "Update contact name" in captured.out


@pytest.mark.asyncio
async def test_cli_no_params_no_description(capsys):
    """CLIApprovalHandler should handle empty params and description."""
    handler = CLIApprovalHandler()
    decision = _make_decision(params={}, description="")

    with patch("builtins.input", return_value="n"):
        await handler.request_approval(decision)

    captured = capsys.readouterr()
    assert "APPROVAL REQUIRED" in captured.out
    # Should not print params line when empty
    # Should not print description line when empty
