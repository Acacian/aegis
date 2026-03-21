"""Webhook-based approval handler.

Sends approval requests to an HTTP endpoint (Slack, Discord, PagerDuty,
custom dashboard, etc.) and waits for a response.

Example::

    handler = WebhookApprovalHandler(
        url="https://your-app.com/api/approve",
        headers={"Authorization": "Bearer ..."},
    )
    runtime = Runtime(executor=..., policy=..., approval_handler=handler)
"""

from __future__ import annotations

from typing import Any

from aegis.core.policy import PolicyDecision
from aegis.runtime.approval import ApprovalHandler


def _require_httpx() -> Any:
    try:
        import httpx

        return httpx
    except ImportError:
        msg = "httpx is required for WebhookApprovalHandler: pip install 'agent-aegis[httpx]'"
        raise ImportError(msg) from None


class WebhookApprovalHandler(ApprovalHandler):
    """Send approval requests to an HTTP webhook endpoint.

    The handler POSTs a JSON payload describing the action and waits for
    a JSON response with an ``"approved"`` boolean field.

    Request payload::

        {
            "action_type": "delete",
            "action_target": "production_db",
            "action_params": {"table": "users"},
            "action_description": "Drop users table",
            "risk_level": "CRITICAL",
            "approval": "approve",
            "matched_rule": "delete_block"
        }

    Expected response::

        {"approved": true}   // or {"approved": false}

    Args:
        url: Webhook endpoint URL.
        headers: Optional HTTP headers (e.g. auth tokens).
        timeout: Request timeout in seconds.
        method: HTTP method (default POST).
    """

    def __init__(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float = 300.0,
        method: str = "POST",
    ) -> None:
        self._url = url
        self._headers = headers or {}
        self._timeout = timeout
        self._method = method.upper()

    async def request_approval(self, decision: PolicyDecision) -> bool:
        """Send approval request to webhook and return the response."""
        httpx = _require_httpx()

        payload = {
            "action_type": decision.action.type,
            "action_target": decision.action.target,
            "action_params": decision.action.params,
            "action_description": decision.action.description,
            "risk_level": decision.risk_level.name,
            "approval": decision.approval.value,
            "matched_rule": decision.matched_rule,
        }

        async with httpx.AsyncClient() as client:
            response = await client.request(
                self._method,
                self._url,
                json=payload,
                headers=self._headers,
                timeout=self._timeout,
            )
            response.raise_for_status()
            data = response.json()
            return bool(data.get("approved", False))
