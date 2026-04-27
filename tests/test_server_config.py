"""Tests for aegis.server.config — ServerConfig YAML parsing."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from aegis.server.config import ServerConfig


def test_default_config():
    cfg = ServerConfig()
    assert cfg.server.host == "127.0.0.1"
    assert cfg.server.port == 8000
    assert cfg.audit.backend == "sqlite"
    assert cfg.dashboard.enabled is True
    assert cfg.agents.heartbeat_timeout == 60


def test_from_dict_minimal():
    cfg = ServerConfig.from_dict({})
    assert cfg.server.port == 8000
    assert cfg.policy.path == "policy.yaml"


def test_from_dict_full():
    data = {
        "server": {"host": "0.0.0.0", "port": 9000},
        "policy": {"path": "/etc/aegis/policy.yaml"},
        "audit": {
            "backend": "redis",
            "redis": {"url": "redis://redis:6379/1"},
        },
        "auth": {"api_key": "sk-test", "admin_key": "sk-admin"},
        "guardrails": {"injection": True, "pii": False, "toxicity": True},
        "dashboard": {"enabled": False},
        "agents": {"heartbeat_timeout": 120},
    }
    cfg = ServerConfig.from_dict(data)
    assert cfg.server.host == "0.0.0.0"
    assert cfg.server.port == 9000
    assert cfg.policy.path == "/etc/aegis/policy.yaml"
    assert cfg.audit.backend == "redis"
    assert cfg.audit.redis.url == "redis://redis:6379/1"
    assert cfg.auth.api_key == "sk-test"
    assert cfg.auth.admin_key == "sk-admin"
    assert cfg.guardrails.pii is False
    assert cfg.guardrails.toxicity is True
    assert cfg.dashboard.enabled is False
    assert cfg.agents.heartbeat_timeout == 120


def test_from_yaml(tmp_path: Path):
    yaml_content = textwrap.dedent("""\
        server:
          host: 0.0.0.0
          port: 7777
        policy:
          path: my-policy.yaml
        audit:
          backend: postgres
          postgres:
            dsn: postgresql://u:p@db/aegis
        dashboard:
          enabled: false
    """)
    config_file = tmp_path / "aegis-server.yaml"
    config_file.write_text(yaml_content)

    cfg = ServerConfig.from_yaml(config_file)
    assert cfg.server.host == "0.0.0.0"
    assert cfg.server.port == 7777
    assert cfg.audit.backend == "postgres"
    assert cfg.audit.postgres.dsn == "postgresql://u:p@db/aegis"
    assert cfg.dashboard.enabled is False


def test_env_var_resolution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("TEST_AEGIS_KEY", "my-secret-key")
    yaml_content = textwrap.dedent("""\
        auth:
          api_key: ${TEST_AEGIS_KEY}
    """)
    config_file = tmp_path / "test.yaml"
    config_file.write_text(yaml_content)

    cfg = ServerConfig.from_yaml(config_file)
    assert cfg.auth.api_key == "my-secret-key"


def test_env_var_missing_resolves_empty(tmp_path: Path):
    yaml_content = textwrap.dedent("""\
        auth:
          api_key: ${NONEXISTENT_VAR_12345}
    """)
    config_file = tmp_path / "test.yaml"
    config_file.write_text(yaml_content)

    cfg = ServerConfig.from_yaml(config_file)
    assert cfg.auth.api_key == ""


def test_create_audit_logger_sqlite():
    cfg = ServerConfig.from_dict({"audit": {"backend": "sqlite", "sqlite": {"path": ":memory:"}}})
    logger = cfg.create_audit_logger()
    from aegis.runtime.audit import AuditLogger

    assert isinstance(logger, AuditLogger)
    logger.close()
