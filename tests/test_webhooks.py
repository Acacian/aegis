"""Tests for the Webhook & Notification System."""

from __future__ import annotations

import contextlib
import threading

import pytest

from aegis.core.webhooks import (
    WebhookConfig,
    WebhookEvent,
    WebhookManager,
    WebhookResult,
    make_event,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TS = "2026-03-23T12:00:00+00:00"


def _make_event(
    event_type: str = "action_blocked",
    severity: str = "warning",
    agent_id: str = "agent-1",
    action_type: str = "write",
    action_target: str = "salesforce",
    message: str = "Action was blocked",
    details: dict[str, object] | None = None,
) -> WebhookEvent:
    return WebhookEvent(
        event_type=event_type,
        severity=severity,
        timestamp=_TS,
        agent_id=agent_id,
        action_type=action_type,
        action_target=action_target,
        message=message,
        details=details or {},
    )


def _make_config(
    name: str = "test-hook",
    url: str = "https://example.com/hook",
    **kwargs: object,
) -> WebhookConfig:
    return WebhookConfig(name=name, url=url, **kwargs)  # type: ignore[arg-type]


class _MockManager(WebhookManager):
    """WebhookManager subclass that records _send calls instead of making HTTP requests."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self.send_log: list[tuple[WebhookConfig, dict[str, object]]] = []
        self._send_side_effect: list[int | Exception] | None = None

    def set_send_responses(self, responses: list[int | Exception]) -> None:
        self._send_side_effect = list(responses)

    def _send(self, cfg: WebhookConfig, payload: dict[str, object]) -> int:
        self.send_log.append((cfg, payload))
        if self._send_side_effect is not None:
            effect = self._send_side_effect.pop(0)
            if isinstance(effect, Exception):
                raise effect
            return effect
        return 200


# ---------------------------------------------------------------------------
# WebhookEvent
# ---------------------------------------------------------------------------


class TestWebhookEvent:
    def test_creation(self) -> None:
        ev = _make_event()
        assert ev.event_type == "action_blocked"
        assert ev.severity == "warning"
        assert ev.timestamp == _TS
        assert ev.agent_id == "agent-1"

    def test_frozen(self) -> None:
        ev = _make_event()
        with pytest.raises(AttributeError):
            ev.severity = "critical"  # type: ignore[misc]

    def test_default_details(self) -> None:
        ev = _make_event()
        assert ev.details == {}

    def test_custom_details(self) -> None:
        ev = _make_event(details={"key": "value"})
        assert ev.details == {"key": "value"}

    def test_invalid_event_type(self) -> None:
        with pytest.raises(ValueError, match="Invalid event_type"):
            _make_event(event_type="invalid")

    def test_invalid_severity(self) -> None:
        with pytest.raises(ValueError, match="Invalid severity"):
            _make_event(severity="extreme")

    def test_all_event_types(self) -> None:
        for et in (
            "action_blocked",
            "anomaly_detected",
            "rate_limited",
            "policy_violation",
            "chain_broken",
        ):
            ev = _make_event(event_type=et)
            assert ev.event_type == et

    def test_all_severities(self) -> None:
        for sev in ("info", "warning", "critical"):
            ev = _make_event(severity=sev)
            assert ev.severity == sev


# ---------------------------------------------------------------------------
# WebhookConfig
# ---------------------------------------------------------------------------


class TestWebhookConfig:
    def test_defaults(self) -> None:
        cfg = _make_config()
        assert cfg.enabled is True
        assert cfg.retry_count == 3
        assert cfg.timeout_seconds == 5.0
        assert cfg.min_severity == "info"
        assert cfg.format == "json"
        assert cfg.events == frozenset()
        assert cfg.headers == {}

    def test_frozen(self) -> None:
        cfg = _make_config()
        with pytest.raises(AttributeError):
            cfg.enabled = False  # type: ignore[misc]

    def test_invalid_min_severity(self) -> None:
        with pytest.raises(ValueError, match="Invalid min_severity"):
            _make_config(min_severity="extreme")

    def test_invalid_format(self) -> None:
        with pytest.raises(ValueError, match="Invalid format"):
            _make_config(format="xml")

    def test_invalid_event_in_events(self) -> None:
        with pytest.raises(ValueError, match="Invalid event type"):
            _make_config(events=frozenset({"bogus"}))

    def test_custom_headers(self) -> None:
        cfg = _make_config(headers={"Authorization": "Bearer tok"})
        assert cfg.headers["Authorization"] == "Bearer tok"


# ---------------------------------------------------------------------------
# WebhookResult
# ---------------------------------------------------------------------------


class TestWebhookResult:
    def test_success_result(self) -> None:
        r = WebhookResult(success=True, webhook_name="h", status_code=200)
        assert r.success is True
        assert r.status_code == 200

    def test_failure_result(self) -> None:
        r = WebhookResult(success=False, webhook_name="h", error="timeout", attempts=3)
        assert r.success is False
        assert r.error == "timeout"
        assert r.attempts == 3

    def test_defaults(self) -> None:
        r = WebhookResult(success=True, webhook_name="h")
        assert r.status_code is None
        assert r.error == ""
        assert r.attempts == 1


# ---------------------------------------------------------------------------
# Severity filtering
# ---------------------------------------------------------------------------


class TestSeverityFiltering:
    def test_info_event_reaches_info_webhook(self) -> None:
        mgr = _MockManager(configs=[_make_config(min_severity="info")])
        results = mgr.notify(_make_event(severity="info"))
        assert len(results) == 1
        assert results[0].success

    def test_info_event_blocked_by_warning_webhook(self) -> None:
        mgr = _MockManager(configs=[_make_config(min_severity="warning")])
        results = mgr.notify(_make_event(severity="info"))
        assert results == []

    def test_warning_event_reaches_warning_webhook(self) -> None:
        mgr = _MockManager(configs=[_make_config(min_severity="warning")])
        results = mgr.notify(_make_event(severity="warning"))
        assert len(results) == 1

    def test_critical_event_reaches_info_webhook(self) -> None:
        mgr = _MockManager(configs=[_make_config(min_severity="info")])
        results = mgr.notify(_make_event(severity="critical"))
        assert len(results) == 1

    def test_warning_event_blocked_by_critical_webhook(self) -> None:
        mgr = _MockManager(configs=[_make_config(min_severity="critical")])
        results = mgr.notify(_make_event(severity="warning"))
        assert results == []

    def test_critical_event_reaches_critical_webhook(self) -> None:
        mgr = _MockManager(configs=[_make_config(min_severity="critical")])
        results = mgr.notify(_make_event(severity="critical"))
        assert len(results) == 1


# ---------------------------------------------------------------------------
# Event type filtering
# ---------------------------------------------------------------------------


class TestEventTypeFiltering:
    def test_matching_event_type(self) -> None:
        mgr = _MockManager(configs=[_make_config(events=frozenset({"action_blocked"}))])
        results = mgr.notify(_make_event(event_type="action_blocked"))
        assert len(results) == 1

    def test_non_matching_event_type(self) -> None:
        mgr = _MockManager(configs=[_make_config(events=frozenset({"anomaly_detected"}))])
        results = mgr.notify(_make_event(event_type="action_blocked"))
        assert results == []

    def test_empty_events_matches_all(self) -> None:
        mgr = _MockManager(configs=[_make_config(events=frozenset())])
        results = mgr.notify(_make_event(event_type="chain_broken"))
        assert len(results) == 1


# ---------------------------------------------------------------------------
# Payload formats
# ---------------------------------------------------------------------------


class TestFormatPayload:
    def test_json_format(self) -> None:
        mgr = WebhookManager()
        ev = _make_event()
        p = mgr.format_payload(ev, "json")
        assert p["event_type"] == "action_blocked"
        assert p["severity"] == "warning"
        assert p["timestamp"] == _TS
        assert p["agent_id"] == "agent-1"
        assert p["action_type"] == "write"
        assert p["action_target"] == "salesforce"
        assert p["message"] == "Action was blocked"
        assert p["details"] == {}

    def test_slack_format_structure(self) -> None:
        mgr = WebhookManager()
        ev = _make_event()
        p = mgr.format_payload(ev, "slack")
        assert "attachments" in p
        attachments = p["attachments"]
        assert isinstance(attachments, list)
        assert len(attachments) == 1
        att = attachments[0]
        assert isinstance(att, dict)
        assert att["color"] == "#ff9900"  # warning color
        blocks = att["blocks"]
        assert isinstance(blocks, list)
        assert len(blocks) == 4

    def test_slack_format_header(self) -> None:
        mgr = WebhookManager()
        ev = _make_event()
        p = mgr.format_payload(ev, "slack")
        header = p["attachments"][0]["blocks"][0]  # type: ignore[index]
        assert header["type"] == "header"
        assert "action_blocked" in header["text"]["text"]

    def test_slack_format_severity_colors(self) -> None:
        mgr = WebhookManager()
        for sev, color in [("info", "#36a64f"), ("warning", "#ff9900"), ("critical", "#ff0000")]:
            ev = _make_event(severity=sev)
            p = mgr.format_payload(ev, "slack")
            assert p["attachments"][0]["color"] == color  # type: ignore[index]

    def test_pagerduty_format(self) -> None:
        mgr = WebhookManager()
        ev = _make_event(severity="critical")
        p = mgr.format_payload(ev, "pagerduty")
        assert p["event_action"] == "trigger"
        assert "routing_key" in p
        payload = p["payload"]
        assert isinstance(payload, dict)
        assert payload["severity"] == "critical"
        assert "agent-1" in str(payload["source"])
        assert payload["timestamp"] == _TS

    def test_pagerduty_summary_contains_event_info(self) -> None:
        mgr = WebhookManager()
        ev = _make_event(severity="critical", message="Oops")
        p = mgr.format_payload(ev, "pagerduty")
        summary = p["payload"]["summary"]  # type: ignore[index]
        assert "CRITICAL" in summary
        assert "action_blocked" in summary
        assert "Oops" in summary


# ---------------------------------------------------------------------------
# add_webhook / remove_webhook
# ---------------------------------------------------------------------------


class TestWebhookRegistration:
    def test_add_webhook(self) -> None:
        mgr = WebhookManager()
        mgr.add_webhook(_make_config(name="a"))
        assert len(mgr.get_webhooks()) == 1

    def test_remove_webhook(self) -> None:
        mgr = WebhookManager(configs=[_make_config(name="a")])
        mgr.remove_webhook("a")
        assert mgr.get_webhooks() == []

    def test_remove_missing_raises(self) -> None:
        mgr = WebhookManager()
        with pytest.raises(KeyError, match="not found"):
            mgr.remove_webhook("nope")

    def test_add_replaces_same_name(self) -> None:
        mgr = WebhookManager()
        mgr.add_webhook(_make_config(name="a", url="https://old.com"))
        mgr.add_webhook(_make_config(name="a", url="https://new.com"))
        hooks = mgr.get_webhooks()
        assert len(hooks) == 1
        assert hooks[0].url == "https://new.com"

    def test_get_webhooks_snapshot(self) -> None:
        mgr = WebhookManager(configs=[_make_config(name="a"), _make_config(name="b")])
        snap = mgr.get_webhooks()
        assert len(snap) == 2
        mgr.remove_webhook("a")
        assert len(snap) == 2  # snapshot unchanged


# ---------------------------------------------------------------------------
# notify with mock _send
# ---------------------------------------------------------------------------


class TestNotify:
    def test_basic_notify(self) -> None:
        mgr = _MockManager(configs=[_make_config()])
        results = mgr.notify(_make_event())
        assert len(results) == 1
        assert results[0].success

    def test_notify_passes_correct_payload(self) -> None:
        mgr = _MockManager(configs=[_make_config(format="slack")])
        mgr.notify(_make_event())
        _, payload = mgr.send_log[0]
        assert "attachments" in payload

    def test_notify_multiple_webhooks(self) -> None:
        mgr = _MockManager(
            configs=[
                _make_config(name="a"),
                _make_config(name="b"),
            ]
        )
        results = mgr.notify(_make_event())
        assert len(results) == 2
        assert all(r.success for r in results)

    def test_disabled_webhook_not_called(self) -> None:
        mgr = _MockManager(configs=[_make_config(enabled=False)])
        results = mgr.notify(_make_event())
        assert results == []
        assert len(mgr.send_log) == 0

    def test_notify_empty_webhooks(self) -> None:
        mgr = _MockManager()
        results = mgr.notify(_make_event())
        assert results == []


# ---------------------------------------------------------------------------
# notify_async
# ---------------------------------------------------------------------------


class TestNotifyAsync:
    def test_fires_without_blocking(self) -> None:
        barrier = threading.Event()

        class _SlowManager(_MockManager):
            def _send(self, cfg: WebhookConfig, payload: dict[str, object]) -> int:
                super()._send(cfg, payload)
                barrier.set()
                return 200

        mgr = _SlowManager(configs=[_make_config()])
        mgr.notify_async(_make_event())
        # Should return immediately; event delivered in background
        assert barrier.wait(timeout=2.0)
        assert len(mgr.send_log) == 1


# ---------------------------------------------------------------------------
# from_config
# ---------------------------------------------------------------------------


class TestFromConfig:
    def test_basic_parsing(self) -> None:
        raw = {
            "webhooks": [
                {
                    "name": "slack-alerts",
                    "url": "https://hooks.slack.com/services/xxx",
                    "format": "slack",
                    "events": ["action_blocked", "anomaly_detected"],
                    "min_severity": "warning",
                },
                {
                    "name": "pd-critical",
                    "url": "https://events.pagerduty.com/v2/enqueue",
                    "format": "pagerduty",
                    "min_severity": "critical",
                    "headers": {"Authorization": "Token token=xxx"},
                },
            ]
        }
        mgr = WebhookManager.from_config(raw)
        hooks = mgr.get_webhooks()
        assert len(hooks) == 2
        names = {h.name for h in hooks}
        assert names == {"slack-alerts", "pd-critical"}

    def test_slack_config_details(self) -> None:
        raw = {
            "webhooks": [
                {
                    "name": "s",
                    "url": "https://example.com",
                    "format": "slack",
                    "events": ["action_blocked"],
                    "min_severity": "warning",
                },
            ]
        }
        mgr = WebhookManager.from_config(raw)
        cfg = mgr.get_webhooks()[0]
        assert cfg.format == "slack"
        assert cfg.events == frozenset({"action_blocked"})
        assert cfg.min_severity == "warning"

    def test_pagerduty_headers(self) -> None:
        raw = {
            "webhooks": [
                {
                    "name": "pd",
                    "url": "https://pd.com",
                    "format": "pagerduty",
                    "headers": {"Authorization": "Bearer tok"},
                },
            ]
        }
        mgr = WebhookManager.from_config(raw)
        cfg = mgr.get_webhooks()[0]
        assert cfg.headers["Authorization"] == "Bearer tok"

    def test_empty_config(self) -> None:
        mgr = WebhookManager.from_config({})
        assert mgr.get_webhooks() == []

    def test_config_defaults_applied(self) -> None:
        raw = {"webhooks": [{"name": "x", "url": "https://x.com"}]}
        mgr = WebhookManager.from_config(raw)
        cfg = mgr.get_webhooks()[0]
        assert cfg.enabled is True
        assert cfg.retry_count == 3
        assert cfg.format == "json"


# ---------------------------------------------------------------------------
# Retry logic
# ---------------------------------------------------------------------------


class TestRetryLogic:
    def test_retry_on_failure_then_success(self) -> None:
        mgr = _MockManager(configs=[_make_config(retry_count=3)])
        mgr.set_send_responses([500, 500, 200])
        results = mgr.notify(_make_event())
        assert len(results) == 1
        assert results[0].success is True
        assert results[0].attempts == 3

    def test_retry_all_failures(self) -> None:
        mgr = _MockManager(configs=[_make_config(retry_count=2)])
        mgr.set_send_responses([500, 500])
        results = mgr.notify(_make_event())
        assert len(results) == 1
        assert results[0].success is False
        assert results[0].attempts == 2
        assert results[0].error == "HTTP 500"

    def test_retry_on_exception(self) -> None:
        mgr = _MockManager(configs=[_make_config(retry_count=3)])
        mgr.set_send_responses([ConnectionError("refused"), ConnectionError("refused"), 200])
        results = mgr.notify(_make_event())
        assert results[0].success is True
        assert results[0].attempts == 3

    def test_all_exceptions(self) -> None:
        mgr = _MockManager(configs=[_make_config(retry_count=2)])
        mgr.set_send_responses([TimeoutError("slow"), TimeoutError("slow")])
        results = mgr.notify(_make_event())
        assert results[0].success is False
        assert results[0].status_code is None
        assert "slow" in results[0].error

    def test_single_retry_success(self) -> None:
        mgr = _MockManager(configs=[_make_config(retry_count=1)])
        mgr.set_send_responses([200])
        results = mgr.notify(_make_event())
        assert results[0].success is True
        assert results[0].attempts == 1


# ---------------------------------------------------------------------------
# Multiple webhooks with mixed filters
# ---------------------------------------------------------------------------


class TestMixedFilters:
    def test_mixed_severity_and_event_filters(self) -> None:
        cfgs = [
            _make_config(name="info-all", min_severity="info"),
            _make_config(
                name="warning-blocked",
                min_severity="warning",
                events=frozenset({"action_blocked"}),
            ),
            _make_config(name="critical-only", min_severity="critical"),
        ]
        mgr = _MockManager(configs=cfgs)

        # warning action_blocked -> info-all, warning-blocked
        results = mgr.notify(_make_event(severity="warning", event_type="action_blocked"))
        names = {r.webhook_name for r in results}
        assert names == {"info-all", "warning-blocked"}

    def test_critical_event_reaches_all_severity_levels(self) -> None:
        cfgs = [
            _make_config(name="info", min_severity="info"),
            _make_config(name="warn", min_severity="warning"),
            _make_config(name="crit", min_severity="critical"),
        ]
        mgr = _MockManager(configs=cfgs)
        results = mgr.notify(_make_event(severity="critical"))
        assert len(results) == 3

    def test_info_event_only_reaches_info_level(self) -> None:
        cfgs = [
            _make_config(name="info", min_severity="info"),
            _make_config(name="warn", min_severity="warning"),
            _make_config(name="crit", min_severity="critical"),
        ]
        mgr = _MockManager(configs=cfgs)
        results = mgr.notify(_make_event(severity="info"))
        assert len(results) == 1
        assert results[0].webhook_name == "info"


# ---------------------------------------------------------------------------
# make_event helper
# ---------------------------------------------------------------------------


class TestMakeEvent:
    def test_auto_timestamp(self) -> None:
        ev = make_event(
            event_type="anomaly_detected",
            severity="info",
            agent_id="a",
            action_type="read",
            action_target="db",
            message="test",
        )
        assert ev.timestamp  # non-empty
        assert "T" in ev.timestamp  # ISO 8601

    def test_details_default(self) -> None:
        ev = make_event(
            event_type="rate_limited",
            severity="warning",
            agent_id="a",
            action_type="write",
            action_target="api",
            message="slow",
        )
        assert ev.details == {}


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_add_remove(self) -> None:
        mgr = WebhookManager()
        errors: list[Exception] = []

        def adder() -> None:
            try:
                for i in range(50):
                    mgr.add_webhook(_make_config(name=f"add-{i}", url="https://a.com"))
            except Exception as e:
                errors.append(e)

        def remover() -> None:
            try:
                for i in range(50):
                    with contextlib.suppress(KeyError):
                        mgr.remove_webhook(f"add-{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=adder), threading.Thread(target=remover)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        assert errors == []

    def test_concurrent_notify(self) -> None:
        mgr = _MockManager(configs=[_make_config()])
        ev = _make_event()
        errors: list[Exception] = []

        def notifier() -> None:
            try:
                for _ in range(20):
                    mgr.notify(ev)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=notifier) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        assert errors == []
        assert len(mgr.send_log) == 80
