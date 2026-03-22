"""Webhook & Notification System for real-time governance alerts.

Delivers alerts to Slack, PagerDuty, email gateways, and generic HTTP
endpoints when anomalies, blocks, or policy violations occur.

Supports per-webhook event-type and severity filtering, configurable
retry logic, and multiple payload formats (JSON, Slack Block Kit,
PagerDuty Events API v2).

Thread-safe: webhook list mutations are guarded by a lock.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict[str, int] = {"info": 0, "warning": 1, "critical": 2}

_VALID_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "action_blocked",
        "anomaly_detected",
        "rate_limited",
        "policy_violation",
        "chain_broken",
    }
)

_VALID_SEVERITIES: frozenset[str] = frozenset({"info", "warning", "critical"})

_VALID_FORMATS: frozenset[str] = frozenset({"json", "slack", "pagerduty"})

_SEVERITY_COLORS: dict[str, str] = {
    "info": "#36a64f",
    "warning": "#ff9900",
    "critical": "#ff0000",
}

_PAGERDUTY_SEVERITY: dict[str, str] = {
    "info": "info",
    "warning": "warning",
    "critical": "critical",
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WebhookEvent:
    """Immutable event payload representing a governance alert.

    Attributes:
        event_type: Category of the event.
        severity: Urgency level.
        timestamp: ISO 8601 timestamp string.
        agent_id: Identifier of the agent that triggered the event.
        action_type: The action type that caused this event.
        action_target: The target system involved.
        message: Human-readable summary.
        details: Arbitrary extra data.
    """

    event_type: str
    severity: str
    timestamp: str
    agent_id: str
    action_type: str
    action_target: str
    message: str
    details: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.event_type not in _VALID_EVENT_TYPES:
            raise ValueError(
                f"Invalid event_type {self.event_type!r}; "
                f"must be one of {sorted(_VALID_EVENT_TYPES)}"
            )
        if self.severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity {self.severity!r}; must be one of {sorted(_VALID_SEVERITIES)}"
            )


@dataclass(frozen=True)
class WebhookConfig:
    """Configuration for a single webhook endpoint.

    Attributes:
        url: HTTP(S) endpoint.
        name: Human-readable name (unique within a manager).
        events: Event types to forward; empty means all.
        min_severity: Minimum severity to forward.
        headers: Extra HTTP headers to include.
        format: Payload format — ``"json"``, ``"slack"``, or ``"pagerduty"``.
        enabled: Whether this webhook is active.
        retry_count: Maximum delivery attempts.
        timeout_seconds: Per-request timeout.
    """

    url: str
    name: str
    events: frozenset[str] = field(default_factory=frozenset)
    min_severity: str = "info"
    headers: dict[str, str] = field(default_factory=dict)
    format: str = "json"
    enabled: bool = True
    retry_count: int = 3
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        if self.min_severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid min_severity {self.min_severity!r}; "
                f"must be one of {sorted(_VALID_SEVERITIES)}"
            )
        if self.format not in _VALID_FORMATS:
            raise ValueError(
                f"Invalid format {self.format!r}; must be one of {sorted(_VALID_FORMATS)}"
            )
        for ev in self.events:
            if ev not in _VALID_EVENT_TYPES:
                raise ValueError(
                    f"Invalid event type {ev!r} in events; "
                    f"must be one of {sorted(_VALID_EVENT_TYPES)}"
                )


@dataclass(frozen=True)
class WebhookResult:
    """Outcome of a single webhook delivery attempt.

    Attributes:
        success: Whether the event was delivered successfully.
        webhook_name: Name of the target webhook.
        status_code: HTTP status code (``None`` on connection error).
        error: Error message, empty on success.
        attempts: Number of attempts made.
    """

    success: bool
    webhook_name: str
    status_code: int | None = None
    error: str = ""
    attempts: int = 1


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class WebhookManager:
    """Registry and dispatcher for webhook endpoints.

    Manages a set of :class:`WebhookConfig` entries, applies event-type and
    severity filters, formats payloads, and delivers them with configurable
    retries.

    Thread-safe: internal webhook list is protected by a lock.  The
    :meth:`_send` method may be overridden (e.g. in tests) to avoid real
    HTTP traffic.
    """

    def __init__(self, configs: list[WebhookConfig] | None = None) -> None:
        self._lock = threading.Lock()
        self._webhooks: dict[str, WebhookConfig] = {}
        for cfg in configs or []:
            self._webhooks[cfg.name] = cfg

    # -- public API ---------------------------------------------------------

    def add_webhook(self, config: WebhookConfig) -> None:
        """Register a webhook configuration."""
        with self._lock:
            self._webhooks[config.name] = config

    def remove_webhook(self, name: str) -> None:
        """Unregister a webhook by name.

        Raises :class:`KeyError` if *name* is not registered.
        """
        with self._lock:
            if name not in self._webhooks:
                raise KeyError(f"Webhook {name!r} not found")
            del self._webhooks[name]

    def get_webhooks(self) -> list[WebhookConfig]:
        """Return a snapshot of all registered webhooks."""
        with self._lock:
            return list(self._webhooks.values())

    def notify(self, event: WebhookEvent) -> list[WebhookResult]:
        """Deliver *event* to every matching & enabled webhook.

        Returns a :class:`WebhookResult` for each webhook that was
        attempted.
        """
        with self._lock:
            targets = list(self._webhooks.values())

        results: list[WebhookResult] = []
        for cfg in targets:
            if not self._should_send(cfg, event):
                continue
            result = self._deliver(cfg, event)
            results.append(result)
        return results

    def notify_async(self, event: WebhookEvent) -> None:
        """Fire-and-forget delivery in a background thread."""
        t = threading.Thread(target=self.notify, args=(event,), daemon=True)
        t.start()

    def format_payload(self, event: WebhookEvent, fmt: str) -> dict[str, object]:
        """Format *event* according to *fmt*.

        Supported formats: ``"json"``, ``"slack"``, ``"pagerduty"``.
        """
        if fmt == "json":
            return self._format_json(event)
        if fmt == "slack":
            return self._format_slack(event)
        if fmt == "pagerduty":
            return self._format_pagerduty(event)
        raise ValueError(f"Unknown format {fmt!r}")  # pragma: no cover

    @classmethod
    def from_config(cls, config_dict: dict[str, Any]) -> WebhookManager:
        """Create a :class:`WebhookManager` from a YAML-like dict.

        Expected shape::

            {
                "webhooks": [
                    {"name": "...", "url": "...", ...},
                    ...
                ]
            }
        """
        configs: list[WebhookConfig] = []
        for entry in config_dict.get("webhooks", []):
            events_raw = entry.get("events", [])
            events = frozenset(events_raw) if events_raw else frozenset()
            kwargs: dict[str, Any] = {
                "url": entry["url"],
                "name": entry["name"],
                "events": events,
            }
            if "min_severity" in entry:
                kwargs["min_severity"] = entry["min_severity"]
            if "headers" in entry:
                kwargs["headers"] = dict(entry["headers"])
            if "format" in entry:
                kwargs["format"] = entry["format"]
            if "enabled" in entry:
                kwargs["enabled"] = entry["enabled"]
            if "retry_count" in entry:
                kwargs["retry_count"] = entry["retry_count"]
            if "timeout_seconds" in entry:
                kwargs["timeout_seconds"] = entry["timeout_seconds"]
            configs.append(WebhookConfig(**kwargs))
        return cls(configs)

    # -- delivery internals -------------------------------------------------

    def _should_send(self, cfg: WebhookConfig, event: WebhookEvent) -> bool:
        """Return ``True`` if *cfg* should receive *event*."""
        if not cfg.enabled:
            return False
        if cfg.events and event.event_type not in cfg.events:
            return False
        return _SEVERITY_ORDER[event.severity] >= _SEVERITY_ORDER[cfg.min_severity]

    def _deliver(self, cfg: WebhookConfig, event: WebhookEvent) -> WebhookResult:
        """Attempt delivery with retries."""
        payload = self.format_payload(event, cfg.format)
        last_error = ""
        last_status: int | None = None

        for attempt in range(1, cfg.retry_count + 1):
            try:
                status = self._send(cfg, payload)
                if 200 <= status < 300:
                    return WebhookResult(
                        success=True,
                        webhook_name=cfg.name,
                        status_code=status,
                        attempts=attempt,
                    )
                last_status = status
                last_error = f"HTTP {status}"
            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)
                last_status = None

        return WebhookResult(
            success=False,
            webhook_name=cfg.name,
            status_code=last_status,
            error=last_error,
            attempts=cfg.retry_count,
        )

    def _send(self, cfg: WebhookConfig, payload: dict[str, object]) -> int:
        """Send *payload* to *cfg.url* via :mod:`urllib.request`.

        Override this method in tests to avoid real network traffic.
        Returns the HTTP status code.
        """
        data = json.dumps(payload, default=str).encode("utf-8")
        req = urllib.request.Request(
            cfg.url,
            data=data,
            headers={"Content-Type": "application/json", **cfg.headers},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=cfg.timeout_seconds) as resp:
                return int(resp.status)
        except urllib.error.HTTPError as exc:
            return int(exc.code)

    # -- payload formatters -------------------------------------------------

    @staticmethod
    def _format_json(event: WebhookEvent) -> dict[str, object]:
        return {
            "event_type": event.event_type,
            "severity": event.severity,
            "timestamp": event.timestamp,
            "agent_id": event.agent_id,
            "action_type": event.action_type,
            "action_target": event.action_target,
            "message": event.message,
            "details": event.details,
        }

    @staticmethod
    def _format_slack(event: WebhookEvent) -> dict[str, object]:
        color = _SEVERITY_COLORS.get(event.severity, "#cccccc")
        return {
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"Aegis Alert: {event.event_type}",
                            },
                        },
                        {
                            "type": "section",
                            "fields": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Severity:* {event.severity}",
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Agent:* {event.agent_id}",
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Action:* {event.action_type}",
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Target:* {event.action_target}",
                                },
                            ],
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": event.message,
                            },
                        },
                        {
                            "type": "context",
                            "elements": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"Timestamp: {event.timestamp}",
                                },
                            ],
                        },
                    ],
                }
            ],
        }

    @staticmethod
    def _format_pagerduty(event: WebhookEvent) -> dict[str, object]:
        return {
            "routing_key": "",
            "event_action": "trigger",
            "payload": {
                "summary": f"[{event.severity.upper()}] {event.event_type}: {event.message}",
                "source": f"aegis/{event.agent_id}",
                "severity": _PAGERDUTY_SEVERITY.get(event.severity, "info"),
                "timestamp": event.timestamp,
                "component": event.action_target,
                "group": event.action_type,
                "custom_details": {
                    "agent_id": event.agent_id,
                    "action_type": event.action_type,
                    "action_target": event.action_target,
                    "details": event.details,
                },
            },
        }


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------


def make_event(
    event_type: str,
    severity: str,
    agent_id: str,
    action_type: str,
    action_target: str,
    message: str,
    details: dict[str, object] | None = None,
) -> WebhookEvent:
    """Create a :class:`WebhookEvent` with an auto-generated timestamp."""
    return WebhookEvent(
        event_type=event_type,
        severity=severity,
        timestamp=datetime.now(UTC).isoformat(),
        agent_id=agent_id,
        action_type=action_type,
        action_target=action_target,
        message=message,
        details=details or {},
    )
