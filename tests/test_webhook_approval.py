"""Tests for WebhookApprovalHandler."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aegis.core.action import Action
from aegis.core.policy import Approval, PolicyDecision
from aegis.core.risk import RiskLevel
from aegis.runtime.approval_webhook import WebhookApprovalHandler


@pytest.fixture()
def decision() -> PolicyDecision:
    return PolicyDecision(
        action=Action("delete", "production_db", params={"table": "users"}),
        risk_level=RiskLevel.CRITICAL,
        approval=Approval.APPROVE,
        matched_rule="delete_rule",
    )


async def test_webhook_approved(decision: PolicyDecision) -> None:
    handler = WebhookApprovalHandler(
        url="https://example.com/approve",
        headers={"Authorization": "Bearer test"},
    )

    mock_response = MagicMock()
    mock_response.json.return_value = {"approved": True}
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.request = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("aegis.runtime.approval_webhook._require_httpx") as mock_httpx:
        mock_httpx.return_value.AsyncClient.return_value = mock_client
        result = await handler.request_approval(decision)

    assert result is True


async def test_webhook_denied(decision: PolicyDecision) -> None:
    handler = WebhookApprovalHandler(url="https://example.com/approve")

    mock_response = MagicMock()
    mock_response.json.return_value = {"approved": False}
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.request = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("aegis.runtime.approval_webhook._require_httpx") as mock_httpx:
        mock_httpx.return_value.AsyncClient.return_value = mock_client
        result = await handler.request_approval(decision)

    assert result is False


async def test_webhook_payload_format(decision: PolicyDecision) -> None:
    handler = WebhookApprovalHandler(url="https://example.com/approve")

    mock_response = MagicMock()
    mock_response.json.return_value = {"approved": True}
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.request = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("aegis.runtime.approval_webhook._require_httpx") as mock_httpx:
        mock_httpx.return_value.AsyncClient.return_value = mock_client
        await handler.request_approval(decision)

    call_kwargs = mock_client.request.call_args
    payload = call_kwargs.kwargs["json"]
    assert payload["action_type"] == "delete"
    assert payload["action_target"] == "production_db"
    assert payload["risk_level"] == "CRITICAL"
    assert payload["matched_rule"] == "delete_rule"
    assert payload["action_params"] == {"table": "users"}


def test_webhook_missing_approved_field(decision: PolicyDecision) -> None:
    """Response without 'approved' field should default to False."""
    handler = WebhookApprovalHandler(url="https://example.com/approve")

    mock_response = MagicMock()
    mock_response.json.return_value = {}  # No 'approved' key
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.request = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    import asyncio

    with patch("aegis.runtime.approval_webhook._require_httpx") as mock_httpx:
        mock_httpx.return_value.AsyncClient.return_value = mock_client
        result = asyncio.run(handler.request_approval(decision))

    assert result is False
