"""Unified server configuration for Aegis governance framework.

Loads ``aegis-server.yaml`` and exposes typed configuration for
server, policy, audit backend, authentication, guardrails, and dashboard.

Example ``aegis-server.yaml``::

    server:
      host: 0.0.0.0
      port: 8000

    policy:
      path: policy.yaml

    audit:
      backend: sqlite          # sqlite | redis | postgres
      sqlite:
        path: aegis_audit.db
      redis:
        url: redis://localhost:6379/0
      postgres:
        dsn: postgresql://user:pass@localhost/aegis

    auth:
      api_key: ${AEGIS_API_KEY}
      admin_key: ${AEGIS_ADMIN_KEY}

    guardrails:
      injection: true
      pii: true
      toxicity: false

    dashboard:
      enabled: true

    agents:
      heartbeat_timeout: 60    # seconds
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


def _resolve_env(value: str) -> str:
    """Replace ``${VAR}`` placeholders with environment variable values."""

    def _sub(m: re.Match[str]) -> str:
        return os.environ.get(m.group(1), "")

    return re.sub(r"\$\{([^}]+)}", _sub, value)


@dataclass
class ServerSection:
    host: str = "127.0.0.1"
    port: int = 8000


@dataclass
class PolicySection:
    path: str = "policy.yaml"
    watch: bool = False


@dataclass
class SqliteAuditConfig:
    path: str = "aegis_audit.db"


@dataclass
class RedisAuditConfig:
    url: str = "redis://localhost:6379/0"


@dataclass
class PostgresAuditConfig:
    dsn: str = "postgresql://localhost/aegis"


@dataclass
class AuditSection:
    backend: str = "sqlite"
    sqlite: SqliteAuditConfig = field(default_factory=SqliteAuditConfig)
    redis: RedisAuditConfig = field(default_factory=RedisAuditConfig)
    postgres: PostgresAuditConfig = field(default_factory=PostgresAuditConfig)


@dataclass
class AuthSection:
    api_key: str = ""
    admin_key: str = ""


@dataclass
class GuardrailsSection:
    injection: bool = True
    pii: bool = True
    toxicity: bool = False
    prompt_leak: bool = False


@dataclass
class DashboardSection:
    enabled: bool = True


@dataclass
class AgentsSection:
    heartbeat_timeout: int = 60


@dataclass
class WebhookEntry:
    url: str
    name: str = ""
    events: list[str] = field(default_factory=list)
    min_severity: str = "warning"
    format: str = "json"


@dataclass
class WebhooksSection:
    enabled: bool = False
    endpoints: list[WebhookEntry] = field(default_factory=list)


@dataclass
class RateLimitRuleConfig:
    name: str = ""
    match_type: str = "*"
    match_target: str = "*"
    max_requests: int = 100
    window_seconds: int = 60
    per_agent: bool = True
    action_on_limit: str = "block"


@dataclass
class RateLimitSection:
    enabled: bool = False
    rules: list[RateLimitRuleConfig] = field(default_factory=list)


@dataclass
class CostSection:
    enabled: bool = False
    max_budget: float = 0.0


@dataclass
class ServerConfig:
    """Top-level server configuration."""

    server: ServerSection = field(default_factory=ServerSection)
    policy: PolicySection = field(default_factory=PolicySection)
    audit: AuditSection = field(default_factory=AuditSection)
    auth: AuthSection = field(default_factory=AuthSection)
    guardrails: GuardrailsSection = field(default_factory=GuardrailsSection)
    dashboard: DashboardSection = field(default_factory=DashboardSection)
    agents: AgentsSection = field(default_factory=AgentsSection)
    webhooks: WebhooksSection = field(default_factory=WebhooksSection)
    rate_limit: RateLimitSection = field(default_factory=RateLimitSection)
    cost: CostSection = field(default_factory=CostSection)

    @classmethod
    def from_yaml(cls, path: str | Path) -> ServerConfig:
        """Load configuration from a YAML file."""
        text = Path(path).read_text(encoding="utf-8")
        data = yaml.safe_load(text) or {}
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ServerConfig:
        """Build configuration from a raw dictionary."""
        cfg = cls()

        if "server" in data:
            s = data["server"]
            cfg.server = ServerSection(
                host=str(s.get("host", cfg.server.host)),
                port=int(s.get("port", cfg.server.port)),
            )

        if "policy" in data:
            p = data["policy"]
            cfg.policy = PolicySection(
                path=str(p.get("path", cfg.policy.path)),
                watch=bool(p.get("watch", cfg.policy.watch)),
            )

        if "audit" in data:
            a = data["audit"]
            cfg.audit.backend = str(a.get("backend", cfg.audit.backend))
            if "sqlite" in a:
                cfg.audit.sqlite = SqliteAuditConfig(
                    path=str(a["sqlite"].get("path", cfg.audit.sqlite.path)),
                )
            if "redis" in a:
                cfg.audit.redis = RedisAuditConfig(
                    url=_resolve_env(str(a["redis"].get("url", cfg.audit.redis.url))),
                )
            if "postgres" in a:
                cfg.audit.postgres = PostgresAuditConfig(
                    dsn=_resolve_env(str(a["postgres"].get("dsn", cfg.audit.postgres.dsn))),
                )

        if "auth" in data:
            au = data["auth"]
            cfg.auth = AuthSection(
                api_key=_resolve_env(str(au.get("api_key", ""))),
                admin_key=_resolve_env(str(au.get("admin_key", ""))),
            )

        if "guardrails" in data:
            g = data["guardrails"]
            cfg.guardrails = GuardrailsSection(
                injection=bool(g.get("injection", cfg.guardrails.injection)),
                pii=bool(g.get("pii", cfg.guardrails.pii)),
                toxicity=bool(g.get("toxicity", cfg.guardrails.toxicity)),
                prompt_leak=bool(g.get("prompt_leak", cfg.guardrails.prompt_leak)),
            )

        if "dashboard" in data:
            d = data["dashboard"]
            cfg.dashboard = DashboardSection(
                enabled=bool(d.get("enabled", cfg.dashboard.enabled)),
            )

        if "agents" in data:
            ag = data["agents"]
            cfg.agents = AgentsSection(
                heartbeat_timeout=int(ag.get("heartbeat_timeout", cfg.agents.heartbeat_timeout)),
            )

        if "webhooks" in data:
            w = data["webhooks"]
            endpoints = []
            for ep in w.get("endpoints", []):
                endpoints.append(
                    WebhookEntry(
                        url=str(ep.get("url", "")),
                        name=str(ep.get("name", "")),
                        events=ep.get("events", []),
                        min_severity=str(ep.get("min_severity", "warning")),
                        format=str(ep.get("format", "json")),
                    )
                )
            cfg.webhooks = WebhooksSection(
                enabled=bool(w.get("enabled", bool(endpoints))),
                endpoints=endpoints,
            )

        if "rate_limit" in data:
            rl = data["rate_limit"]
            rules = []
            for r in rl.get("rules", []):
                rules.append(
                    RateLimitRuleConfig(
                        name=str(r.get("name", "")),
                        match_type=str(r.get("match_type", "*")),
                        match_target=str(r.get("match_target", "*")),
                        max_requests=int(r.get("max_requests", 100)),
                        window_seconds=int(r.get("window_seconds", 60)),
                        per_agent=bool(r.get("per_agent", True)),
                        action_on_limit=str(r.get("action_on_limit", "block")),
                    )
                )
            cfg.rate_limit = RateLimitSection(
                enabled=bool(rl.get("enabled", bool(rules))),
                rules=rules,
            )

        if "cost" in data:
            c = data["cost"]
            cfg.cost = CostSection(
                enabled=bool(c.get("enabled", False)),
                max_budget=float(c.get("max_budget", 0.0)),
            )

        return cfg

    def create_audit_logger(self) -> Any:
        """Instantiate the appropriate audit logger based on config."""
        backend = self.audit.backend

        if backend == "redis":
            from aegis.runtime.audit_redis import RedisAuditLogger

            return RedisAuditLogger(url=self.audit.redis.url)

        if backend == "postgres":
            from aegis.runtime.audit_postgres import PostgresAuditLogger

            return PostgresAuditLogger(dsn=self.audit.postgres.dsn)

        # Default: SQLite
        from aegis.runtime.audit import AuditLogger

        return AuditLogger(db_path=self.audit.sqlite.path)
