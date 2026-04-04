"""Proxy configuration models."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class UpstreamConfig:
    """Configuration for a single upstream server."""

    name: str
    url: str
    protocol: str = "mcp-http"
    timeout_ms: int = 30000
    health_check: str = "/health"


@dataclass
class AuthConfig:
    """Agent authentication configuration."""

    mode: str = "none"  # bearer | mtls | none
    tokens: dict[str, str] = field(default_factory=dict)  # agent_id -> token


@dataclass
class ClaimsConfig:
    """ActionClaim assessment configuration."""

    enabled: bool = True
    gap_approve_threshold: float = 0.15
    gap_escalate_threshold: float = 0.40
    require_justification: bool = True


@dataclass
class CircuitBreakerConfig:
    """Proxy circuit breaker configuration."""

    enabled: bool = True
    failure_threshold: int = 5
    recovery_timeout_s: float = 60.0


@dataclass
class ProxyConfig:
    """Full proxy server configuration."""

    listen_host: str = "0.0.0.0"
    listen_port: int = 8080
    mode: str = "zero-trust"  # zero-trust | permissive
    policy_path: str = ""
    upstreams: list[UpstreamConfig] = field(default_factory=list)
    auth: AuthConfig = field(default_factory=AuthConfig)
    claims: ClaimsConfig = field(default_factory=ClaimsConfig)
    circuit_breaker: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)
    tls_cert: str = ""
    tls_key: str = ""

    @classmethod
    def from_yaml(cls, path: str | Path) -> ProxyConfig:
        """Load proxy configuration from YAML file."""
        import yaml

        raw = yaml.safe_load(Path(path).read_text())
        proxy = raw.get("proxy", raw)

        upstreams = [UpstreamConfig(**u) for u in proxy.get("upstreams", [])]

        auth_raw = proxy.get("auth", {})
        tokens = {}
        for t in auth_raw.get("tokens", []):
            tokens[t["agent"]] = t["token"]
        auth = AuthConfig(
            mode=auth_raw.get("mode", "none"),
            tokens=tokens,
        )

        claims_raw = proxy.get("claims", {})
        claims = ClaimsConfig(
            enabled=claims_raw.get("enabled", True),
            gap_approve_threshold=claims_raw.get("gap_approve_threshold", 0.15),
            gap_escalate_threshold=claims_raw.get("gap_escalate_threshold", 0.40),
            require_justification=claims_raw.get("require_justification", True),
        )

        cb_raw = proxy.get("circuit_breaker", {})
        cb = CircuitBreakerConfig(
            enabled=cb_raw.get("enabled", True),
            failure_threshold=cb_raw.get("failure_threshold", 5),
            recovery_timeout_s=cb_raw.get("recovery_timeout_s", 60.0),
        )

        return cls(
            listen_host=proxy.get("listen", {}).get("host", "0.0.0.0"),
            listen_port=proxy.get("listen", {}).get("port", 8080),
            mode=proxy.get("mode", "zero-trust"),
            policy_path=proxy.get("policy", ""),
            upstreams=upstreams,
            auth=auth,
            claims=claims,
            circuit_breaker=cb,
            tls_cert=proxy.get("listen", {}).get("tls_cert", ""),
            tls_key=proxy.get("listen", {}).get("tls_key", ""),
        )
