"""Tests for the Aegis Proxy server and configuration."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegis.proxy.config import (
    AuthConfig,
    CircuitBreakerConfig,
    ClaimsConfig,
    ProxyConfig,
    UpstreamConfig,
)
from aegis.proxy.server import AegisProxy, ProxyResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _upstream(
    name: str = "mcp-server",
    url: str = "http://localhost:9000",
    **kwargs,
) -> UpstreamConfig:
    return UpstreamConfig(name=name, url=url, **kwargs)


def _config(
    upstreams: list[UpstreamConfig] | None = None,
    mode: str = "permissive",
    auth: AuthConfig | None = None,
    claims_enabled: bool = False,
    cb_enabled: bool = False,
    **kwargs,
) -> ProxyConfig:
    return ProxyConfig(
        upstreams=upstreams or [_upstream()],
        mode=mode,
        auth=auth or AuthConfig(mode="none"),
        claims=ClaimsConfig(enabled=claims_enabled),
        circuit_breaker=CircuitBreakerConfig(enabled=cb_enabled),
        **kwargs,
    )


# ---------------------------------------------------------------------------
# UpstreamConfig
# ---------------------------------------------------------------------------


class TestUpstreamConfig:
    def test_creation(self) -> None:
        u = UpstreamConfig(name="srv", url="http://localhost:3000")
        assert u.name == "srv"
        assert u.url == "http://localhost:3000"
        assert u.protocol == "mcp-http"
        assert u.timeout_ms == 30000
        assert u.health_check == "/health"

    def test_custom_values(self) -> None:
        u = UpstreamConfig(
            name="fast",
            url="http://fast:8080",
            protocol="grpc",
            timeout_ms=5000,
            health_check="/ready",
        )
        assert u.protocol == "grpc"
        assert u.timeout_ms == 5000
        assert u.health_check == "/ready"


# ---------------------------------------------------------------------------
# AuthConfig
# ---------------------------------------------------------------------------


class TestAuthConfig:
    def test_defaults(self) -> None:
        a = AuthConfig()
        assert a.mode == "none"
        assert a.tokens == {}

    def test_bearer_tokens(self) -> None:
        a = AuthConfig(mode="bearer", tokens={"agent-1": "secret-1"})
        assert a.mode == "bearer"
        assert a.tokens["agent-1"] == "secret-1"


# ---------------------------------------------------------------------------
# ClaimsConfig
# ---------------------------------------------------------------------------


class TestClaimsConfig:
    def test_defaults(self) -> None:
        c = ClaimsConfig()
        assert c.enabled is True
        assert c.gap_approve_threshold == pytest.approx(0.15)
        assert c.gap_escalate_threshold == pytest.approx(0.40)
        assert c.require_justification is True


# ---------------------------------------------------------------------------
# ProxyConfig
# ---------------------------------------------------------------------------


class TestProxyConfig:
    def test_defaults(self) -> None:
        c = ProxyConfig()
        assert c.listen_host == "0.0.0.0"
        assert c.listen_port == 8080
        assert c.mode == "zero-trust"
        assert c.upstreams == []

    def test_from_yaml(self, tmp_path: Path) -> None:
        yaml_content = """\
proxy:
  listen:
    host: 127.0.0.1
    port: 9090
  mode: permissive
  policy: /tmp/policy.yaml
  upstreams:
    - name: server-a
      url: http://a:3000
      protocol: mcp-http
      timeout_ms: 5000
    - name: server-b
      url: http://b:3000
  auth:
    mode: bearer
    tokens:
      - agent: agent-1
        token: tok-111
      - agent: agent-2
        token: tok-222
  claims:
    enabled: true
    gap_approve_threshold: 0.10
    gap_escalate_threshold: 0.50
  circuit_breaker:
    enabled: false
    failure_threshold: 10
    recovery_timeout_s: 120.0
"""
        yaml_file = tmp_path / "proxy.yaml"
        yaml_file.write_text(yaml_content)

        cfg = ProxyConfig.from_yaml(yaml_file)
        assert cfg.listen_host == "127.0.0.1"
        assert cfg.listen_port == 9090
        assert cfg.mode == "permissive"
        assert cfg.policy_path == "/tmp/policy.yaml"
        assert len(cfg.upstreams) == 2
        assert cfg.upstreams[0].name == "server-a"
        assert cfg.upstreams[0].timeout_ms == 5000
        assert cfg.upstreams[1].name == "server-b"
        assert cfg.auth.mode == "bearer"
        assert cfg.auth.tokens["agent-1"] == "tok-111"
        assert cfg.auth.tokens["agent-2"] == "tok-222"
        assert cfg.claims.enabled is True
        assert cfg.claims.gap_approve_threshold == pytest.approx(0.10)
        assert cfg.claims.gap_escalate_threshold == pytest.approx(0.50)
        assert cfg.circuit_breaker.enabled is False
        assert cfg.circuit_breaker.failure_threshold == 10
        assert cfg.circuit_breaker.recovery_timeout_s == pytest.approx(120.0)

    def test_from_yaml_minimal(self, tmp_path: Path) -> None:
        yaml_content = "proxy:\n  mode: permissive\n"
        yaml_file = tmp_path / "minimal.yaml"
        yaml_file.write_text(yaml_content)

        cfg = ProxyConfig.from_yaml(yaml_file)
        assert cfg.mode == "permissive"
        assert cfg.upstreams == []
        assert cfg.auth.mode == "none"

    def test_from_yaml_tls(self, tmp_path: Path) -> None:
        yaml_content = """\
proxy:
  listen:
    host: 0.0.0.0
    port: 443
    tls_cert: /etc/ssl/cert.pem
    tls_key: /etc/ssl/key.pem
"""
        yaml_file = tmp_path / "tls.yaml"
        yaml_file.write_text(yaml_content)

        cfg = ProxyConfig.from_yaml(yaml_file)
        assert cfg.tls_cert == "/etc/ssl/cert.pem"
        assert cfg.tls_key == "/etc/ssl/key.pem"


# ---------------------------------------------------------------------------
# ProxyResult
# ---------------------------------------------------------------------------


class TestProxyResult:
    def test_allowed_result(self) -> None:
        r = ProxyResult(allowed=True)
        assert r.allowed is True
        assert r.reason == ""
        assert len(r.trace_id) == 16

    def test_blocked_result(self) -> None:
        r = ProxyResult(allowed=False, reason="policy blocked")
        assert r.allowed is False
        assert r.reason == "policy blocked"


# ---------------------------------------------------------------------------
# AegisProxy: authenticate
# ---------------------------------------------------------------------------


class TestAegisProxyAuthenticate:
    def test_auth_mode_none_always_passes(self) -> None:
        proxy = AegisProxy(config=_config(auth=AuthConfig(mode="none")))
        assert proxy.authenticate("anyone", "anything") is True

    def test_bearer_valid_token(self) -> None:
        auth = AuthConfig(mode="bearer", tokens={"agent-1": "secret"})
        proxy = AegisProxy(config=_config(auth=auth))
        assert proxy.authenticate("agent-1", "secret") is True

    def test_bearer_invalid_token(self) -> None:
        auth = AuthConfig(mode="bearer", tokens={"agent-1": "secret"})
        proxy = AegisProxy(config=_config(auth=auth))
        assert proxy.authenticate("agent-1", "wrong") is False

    def test_bearer_unknown_agent(self) -> None:
        auth = AuthConfig(mode="bearer", tokens={"agent-1": "secret"})
        proxy = AegisProxy(config=_config(auth=auth))
        assert proxy.authenticate("unknown-agent", "secret") is False

    def test_unsupported_auth_mode(self) -> None:
        auth = AuthConfig(mode="mtls", tokens={})
        proxy = AegisProxy(config=_config(auth=auth))
        assert proxy.authenticate("agent", "token") is False


# ---------------------------------------------------------------------------
# AegisProxy: handle_tool_call
# ---------------------------------------------------------------------------


class TestHandleToolCallUnknownUpstream:
    @pytest.mark.asyncio
    async def test_unknown_upstream_blocked(self) -> None:
        proxy = AegisProxy(config=_config())
        result = await proxy.handle_tool_call(
            tool_name="read_file",
            arguments={"path": "/etc/passwd"},
            server_name="nonexistent-server",
        )
        assert result.allowed is False
        assert "Unknown upstream" in result.reason


class TestHandleToolCallAllowed:
    @pytest.mark.asyncio
    async def test_allowed_in_permissive_mode(self) -> None:
        proxy = AegisProxy(config=_config(mode="permissive", claims_enabled=False))
        result = await proxy.handle_tool_call(
            tool_name="read_file",
            arguments={"path": "/tmp/test.txt"},
            server_name="mcp-server",
            agent_id="agent-1",
            justification="need to read config",
        )
        assert result.allowed is True
        assert result.claim is not None
        assert len(result.trace_id) == 16

    @pytest.mark.asyncio
    async def test_claim_fields_populated(self) -> None:
        proxy = AegisProxy(config=_config(mode="permissive", claims_enabled=False))
        result = await proxy.handle_tool_call(
            tool_name="write_file",
            arguments={"path": "/tmp/out.txt", "content": "hello"},
            server_name="mcp-server",
            agent_id="agent-1",
            justification="logging output",
            originating_goal="complete task",
        )
        assert result.allowed is True
        claim = result.claim
        assert claim.declared.proposed_transition == "write_file"
        assert claim.declared.target == "mcp-server"
        assert claim.declared.justification == "logging output"
        assert claim.declared.originating_goal == "complete task"
        assert claim.chain.principal == "agent-1"


class TestHandleToolCallMultipleUpstreams:
    @pytest.mark.asyncio
    async def test_routes_to_correct_upstream(self) -> None:
        upstreams = [
            _upstream("server-a", "http://a:3000"),
            _upstream("server-b", "http://b:3000"),
        ]
        proxy = AegisProxy(config=_config(upstreams=upstreams, claims_enabled=False))

        result_a = await proxy.handle_tool_call(
            tool_name="read",
            arguments={},
            server_name="server-a",
        )
        assert result_a.allowed is True

        result_b = await proxy.handle_tool_call(
            tool_name="read",
            arguments={},
            server_name="server-b",
        )
        assert result_b.allowed is True

        result_c = await proxy.handle_tool_call(
            tool_name="read",
            arguments={},
            server_name="server-c",
        )
        assert result_c.allowed is False


# ---------------------------------------------------------------------------
# AegisProxy: handle_tool_call with claims (gap assessment)
# ---------------------------------------------------------------------------


class TestHandleToolCallWithClaims:
    @pytest.mark.asyncio
    async def test_claims_pipeline_runs(self) -> None:
        """When claims are enabled, gap assessment is performed."""
        config = _config(mode="zero-trust", claims_enabled=True)
        proxy = AegisProxy(config=config)
        await proxy.start()

        result = await proxy.handle_tool_call(
            tool_name="read_file",
            arguments={"path": "/tmp/test.txt"},
            server_name="mcp-server",
            agent_id="agent-1",
            justification="need to read config",
            originating_goal="complete task",
        )
        # Result depends on gap computation; claim should be present
        assert result.claim is not None
        assert len(result.trace_id) == 16


# ---------------------------------------------------------------------------
# AegisProxy: proxy not started (no circuit breakers or claims)
# ---------------------------------------------------------------------------


class TestProxyNotStarted:
    @pytest.mark.asyncio
    async def test_works_without_start(self) -> None:
        """Proxy can handle calls even if start() was not called."""
        proxy = AegisProxy(config=_config(mode="permissive", claims_enabled=False))
        result = await proxy.handle_tool_call(
            tool_name="read",
            arguments={},
            server_name="mcp-server",
        )
        assert result.allowed is True


# ---------------------------------------------------------------------------
# AegisProxy: handle_tool_call with empty arguments
# ---------------------------------------------------------------------------


class TestHandleToolCallEdgeCases:
    @pytest.mark.asyncio
    async def test_empty_arguments(self) -> None:
        proxy = AegisProxy(config=_config(claims_enabled=False))
        result = await proxy.handle_tool_call(
            tool_name="list_files",
            arguments={},
            server_name="mcp-server",
        )
        assert result.allowed is True

    @pytest.mark.asyncio
    async def test_empty_agent_id(self) -> None:
        proxy = AegisProxy(config=_config(claims_enabled=False))
        result = await proxy.handle_tool_call(
            tool_name="read",
            arguments={},
            server_name="mcp-server",
            agent_id="",
        )
        assert result.allowed is True
        assert result.claim.chain.principal == ""

    @pytest.mark.asyncio
    async def test_each_call_gets_unique_trace_id(self) -> None:
        proxy = AegisProxy(config=_config(claims_enabled=False))
        r1 = await proxy.handle_tool_call(
            tool_name="read",
            arguments={},
            server_name="mcp-server",
        )
        r2 = await proxy.handle_tool_call(
            tool_name="read",
            arguments={},
            server_name="mcp-server",
        )
        assert r1.trace_id != r2.trace_id
