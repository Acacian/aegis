"""Tests for server wiring — webhooks, rate limiting, and create_app_from_config."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from aegis.server.app import _build_rate_limiter, _build_webhook_manager
from aegis.server.config import (
    RateLimitRuleConfig,
    RateLimitSection,
    ServerConfig,
    WebhookEntry,
    WebhooksSection,
)

# ---- Webhook builder tests ----


def test_build_webhook_manager_disabled():
    cfg = WebhooksSection(enabled=False, endpoints=[])
    assert _build_webhook_manager(cfg) is None


def test_build_webhook_manager_no_endpoints():
    cfg = WebhooksSection(enabled=True, endpoints=[])
    assert _build_webhook_manager(cfg) is None


def test_build_webhook_manager_with_endpoints():
    cfg = WebhooksSection(
        enabled=True,
        endpoints=[
            WebhookEntry(
                url="https://hooks.example.com/alert",
                name="alerts",
                events=["action_blocked"],
                min_severity="critical",
                format="json",
            ),
        ],
    )
    mgr = _build_webhook_manager(cfg)
    assert mgr is not None
    assert len(mgr._webhooks) == 1
    assert "alerts" in mgr._webhooks


def test_build_webhook_manager_default_name():
    """When name is empty, URL is used as name."""
    cfg = WebhooksSection(
        enabled=True,
        endpoints=[WebhookEntry(url="https://hooks.example.com/x")],
    )
    mgr = _build_webhook_manager(cfg)
    assert "https://hooks.example.com/x" in mgr._webhooks


# ---- Rate limiter builder tests ----


def test_build_rate_limiter_disabled():
    cfg = RateLimitSection(enabled=False, rules=[])
    assert _build_rate_limiter(cfg) is None


def test_build_rate_limiter_no_rules():
    cfg = RateLimitSection(enabled=True, rules=[])
    assert _build_rate_limiter(cfg) is None


def test_build_rate_limiter_with_rules():
    cfg = RateLimitSection(
        enabled=True,
        rules=[
            RateLimitRuleConfig(
                name="api-limit",
                match_type="*",
                match_target="*",
                max_requests=10,
                window_seconds=60,
                per_agent=True,
                action_on_limit="block",
            ),
        ],
    )
    limiter = _build_rate_limiter(cfg)
    assert limiter is not None
    assert len(limiter._rules) == 1
    assert limiter._rules[0].name == "api-limit"
    assert limiter._rules[0].max_requests == 10


# ---- Config parsing for webhooks/rate_limit ----


def test_config_webhooks_from_dict():
    data = {
        "webhooks": {
            "enabled": True,
            "endpoints": [
                {
                    "url": "https://slack.example.com/hook",
                    "name": "slack-alerts",
                    "events": ["action_blocked", "anomaly_detected"],
                    "min_severity": "warning",
                    "format": "json",
                },
            ],
        },
    }
    cfg = ServerConfig.from_dict(data)
    assert cfg.webhooks.enabled is True
    assert len(cfg.webhooks.endpoints) == 1
    assert cfg.webhooks.endpoints[0].url == "https://slack.example.com/hook"
    assert cfg.webhooks.endpoints[0].events == ["action_blocked", "anomaly_detected"]


def test_config_rate_limit_from_dict():
    data = {
        "rate_limit": {
            "enabled": True,
            "rules": [
                {
                    "name": "global",
                    "match_type": "*",
                    "max_requests": 50,
                    "window_seconds": 30,
                    "per_agent": False,
                    "action_on_limit": "block",
                },
            ],
        },
    }
    cfg = ServerConfig.from_dict(data)
    assert cfg.rate_limit.enabled is True
    assert len(cfg.rate_limit.rules) == 1
    assert cfg.rate_limit.rules[0].max_requests == 50
    assert cfg.rate_limit.rules[0].per_agent is False


def test_config_webhooks_auto_enable():
    """Webhooks auto-enable when endpoints exist but enabled not set."""
    data = {
        "webhooks": {
            "endpoints": [{"url": "https://example.com/hook"}],
        },
    }
    cfg = ServerConfig.from_dict(data)
    assert cfg.webhooks.enabled is True


def test_config_rate_limit_auto_enable():
    """Rate limit auto-enables when rules exist but enabled not set."""
    data = {
        "rate_limit": {
            "rules": [{"name": "r", "match_type": "*", "max_requests": 10}],
        },
    }
    cfg = ServerConfig.from_dict(data)
    assert cfg.rate_limit.enabled is True


def test_config_from_yaml_full(tmp_path: Path):
    yaml_content = textwrap.dedent("""\
        server:
          port: 9000
        webhooks:
          enabled: true
          endpoints:
            - url: https://hooks.slack.com/services/abc
              name: slack
              events: [action_blocked]
              min_severity: critical
              format: json
        rate_limit:
          enabled: true
          rules:
            - name: default
              match_type: "*"
              max_requests: 100
              window_seconds: 60
    """)
    config_file = tmp_path / "aegis-server.yaml"
    config_file.write_text(yaml_content)

    cfg = ServerConfig.from_yaml(config_file)
    assert cfg.webhooks.enabled is True
    assert cfg.webhooks.endpoints[0].name == "slack"
    assert cfg.rate_limit.enabled is True
    assert cfg.rate_limit.rules[0].name == "default"


# ---- create_app_from_config integration ----


def test_create_app_from_config_with_webhooks_and_ratelimit(tmp_path: Path):
    """Full integration: create_app_from_config wires webhooks and rate limiter."""
    policy_yaml = tmp_path / "policy.yaml"
    policy_yaml.write_text("rules: []\n")

    data = {
        "policy": {"path": str(policy_yaml)},
        "dashboard": {"enabled": False},
        "guardrails": {"injection": False, "pii": False},
        "webhooks": {
            "enabled": True,
            "endpoints": [
                {"url": "https://example.com/hook", "name": "test-hook"},
            ],
        },
        "rate_limit": {
            "enabled": True,
            "rules": [
                {"name": "test-rule", "match_type": "*", "max_requests": 5},
            ],
        },
    }
    cfg = ServerConfig.from_dict(data)

    from aegis.server.app import create_app_from_config

    app = create_app_from_config(cfg)
    assert app is not None


# ---- Rate limiting in API ----


def test_rate_limit_blocks_request():
    """Rate limiter returns 429 when limit exceeded."""
    try:
        from starlette.testclient import TestClient
    except ImportError:
        pytest.skip("starlette not installed")

    from aegis.core.rate_limiter import RateLimiter, RateLimitRule

    limiter = RateLimiter(
        rules=[
            RateLimitRule(
                name="tight",
                match_type="*",
                max_requests=2,
                window_seconds=60.0,
            ),
        ],
    )

    from aegis.server.app import create_app

    app = create_app(enable_dashboard=False, rate_limiter=limiter)
    client = TestClient(app)

    # First two requests should succeed
    for _ in range(2):
        resp = client.post(
            "/api/v1/evaluate",
            json={"action_type": "read", "target": "data"},
        )
        assert resp.status_code == 200

    # Third should be rate limited
    resp = client.post(
        "/api/v1/evaluate",
        json={"action_type": "read", "target": "data"},
    )
    assert resp.status_code == 429
    assert "Rate limit exceeded" in resp.json()["error"]
