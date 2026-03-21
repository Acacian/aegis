"""Webhook-based audit backend.

Sends audit events to an HTTP endpoint for integration with external
logging, monitoring, or SIEM systems.

Example::

    audit = WebhookAuditLogger(
        url="https://your-app.com/api/audit",
        headers={"Authorization": "Bearer ..."},
    )
    runtime = Runtime(executor=..., policy=..., audit_logger=audit)
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis.core.policy import PolicyDecision
from aegis.core.result import Result


def _require_httpx() -> Any:
    try:
        import httpx

        return httpx
    except ImportError:
        msg = "httpx is required for WebhookAuditLogger: pip install 'agent-aegis[httpx]'"
        raise ImportError(msg) from None


class WebhookAuditLogger:
    """Send audit events to an HTTP webhook endpoint.

    Each call to :meth:`log` POSTs a JSON payload to the configured URL.
    Also keeps an in-memory buffer for :meth:`get_log` queries.

    Payload::

        {
            "session_id": "abc123",
            "timestamp": "2026-03-21T12:00:00+00:00",
            "action_type": "delete",
            "action_target": "db",
            "risk_level": "CRITICAL",
            "approval": "block",
            "matched_rule": "no_deletes",
            "result_status": "blocked",
            "result_error": "Blocked by policy rule: no_deletes"
        }

    Args:
        url: Webhook endpoint URL.
        headers: Optional HTTP headers.
        timeout: Request timeout in seconds.
        buffer_size: Max entries to keep in memory for get_log().
    """

    def __init__(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
        buffer_size: int = 10000,
    ) -> None:
        self._url = url
        self._headers = headers or {}
        self._timeout = timeout
        self._buffer_size = buffer_size
        self._buffer: list[dict[str, Any]] = []
        self._counter = 0

    def log(
        self,
        session_id: str,
        decision: PolicyDecision,
        *,
        result: Result | None = None,
        human_decision: str | None = None,
    ) -> int:
        """Send an audit event to the webhook and buffer locally."""
        self._counter += 1
        entry = {
            "id": self._counter,
            "session_id": session_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "action_type": decision.action.type,
            "action_target": decision.action.target,
            "action_params": decision.action.params,
            "action_description": decision.action.description,
            "risk_level": decision.risk_level.name,
            "approval": decision.approval.value,
            "matched_rule": decision.matched_rule,
            "human_decision": human_decision,
            "result_status": result.status.value if result else None,
            "result_data": result.data if result else None,
            "result_error": result.error if result else None,
        }

        # Buffer for local queries
        self._buffer.append(entry)
        if len(self._buffer) > self._buffer_size:
            self._buffer = self._buffer[-self._buffer_size :]

        # Fire-and-forget POST (sync to match AuditLogger interface)
        self._send(entry)

        return self._counter

    def _send(self, payload: dict[str, Any]) -> None:
        """Send payload to webhook synchronously."""
        httpx = _require_httpx()
        try:
            with httpx.Client() as client:
                client.post(
                    self._url,
                    json=payload,
                    headers=self._headers,
                    timeout=self._timeout,
                )
        except Exception:
            pass  # Fire-and-forget: don't break the pipeline

    def get_log(
        self,
        session_id: str | None = None,
        **kwargs: Any,
    ) -> list[dict[str, object]]:
        """Query the in-memory buffer."""
        entries = self._buffer
        if session_id:
            entries = [e for e in entries if e["session_id"] == session_id]
        return entries

    def export_jsonl(self, path: str | Path, session_id: str | None = None) -> int:
        """Export buffered entries as JSON Lines."""
        entries = self.get_log(session_id=session_id)
        out = Path(path)
        with out.open("w") as f:
            for entry in entries:
                f.write(json.dumps(entry, default=str) + "\n")
        return len(entries)

    def close(self) -> None:
        """No-op for webhook logger."""
