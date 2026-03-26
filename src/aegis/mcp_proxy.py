"""Aegis MCP Proxy — transparent governance proxy for MCP servers.

Sits between an MCP client (Claude Desktop, Cursor, Windsurf) and a target
MCP server. Every tool call passes through the Aegis governance pipeline:
security scanning, policy checks, guardrails, and audit logging.

Usage::

    # Wrap a single MCP server (most common)
    aegis-mcp-proxy --wrap npx -y @modelcontextprotocol/server-filesystem /home

    # With a policy file
    aegis-mcp-proxy --policy policy.yaml \\
        --wrap npx -y @modelcontextprotocol/server-filesystem /home

    # In Claude Desktop config (claude_desktop_config.json):
    {
      "mcpServers": {
        "filesystem": {
          "command": "uvx",
          "args": ["--from", "agent-aegis[mcp]", "aegis-mcp-proxy",
                   "--wrap", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/home"]
        }
      }
    }
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import uuid
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("aegis.mcp_proxy")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class TargetServerConfig:
    """Configuration for a target MCP server to proxy."""

    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] | None = None


@dataclass
class ToolEntry:
    """A discovered tool from a target server."""

    server_name: str
    tool: Any  # mcp.types.Tool
    proxy_name: str  # Name exposed to the MCP client


@dataclass
class ResourceEntry:
    """A discovered resource from a target server."""

    server_name: str
    resource: Any  # mcp.types.Resource


@dataclass
class PromptEntry:
    """A discovered prompt from a target server."""

    server_name: str
    prompt: Any  # mcp.types.Prompt


# ---------------------------------------------------------------------------
# Target connection
# ---------------------------------------------------------------------------


@dataclass
class _TargetConnection:
    """Active connection to a target MCP server."""

    config: TargetServerConfig
    session: Any  # mcp.client.session.ClientSession
    tools: dict[str, Any] = field(default_factory=dict)  # tool_name -> Tool
    resources: list[Any] = field(default_factory=list)
    prompts: list[Any] = field(default_factory=list)


# ---------------------------------------------------------------------------
# AegisMCPProxy
# ---------------------------------------------------------------------------


class AegisMCPProxy:
    """MCP Proxy Server with Aegis governance.

    Sits between an MCP client and one or more target MCP servers.
    All tool calls pass through:

    1. MCPSecurityGate (tool description scan, rug-pull, argument sanitization)
    2. Policy evaluation (risk level, approval requirement)
    3. GuardrailEngine (injection detection on string arguments)
    4. Audit logging (SQLite)
    5. Forward to target server (if allowed)
    """

    def __init__(
        self,
        targets: list[TargetServerConfig],
        *,
        policy_path: str | None = None,
        guardrails: str | None = "default",
        audit_db: str = "aegis_proxy_audit.db",
        min_trust_level: str = "L1_SCANNED",
        pin_store: str | None = None,
        log_level: str = "INFO",
        # Extended security modules
        response_scanning: bool = True,
        escalation_detection: bool = True,
        shadow_detection: bool = True,
        rate_limit_config: dict[str, Any] | None = None,
    ) -> None:
        self._targets = targets
        self._policy_path = policy_path or os.environ.get("AEGIS_POLICY_PATH")
        self._guardrails_spec = guardrails
        self._audit_db = audit_db
        self._min_trust_str = min_trust_level
        self._pin_store = pin_store
        self._log_level = log_level

        # Extended security module flags
        self._response_scanning = response_scanning
        self._escalation_detection = escalation_detection
        self._shadow_detection = shadow_detection
        self._rate_limit_config = rate_limit_config

        # Populated at start()
        self._connections: list[_TargetConnection] = []
        self._tool_registry: dict[str, ToolEntry] = {}
        self._resource_registry: list[ResourceEntry] = []
        self._prompt_registry: dict[str, PromptEntry] = {}
        self._exit_stack: AsyncExitStack | None = None
        self._multi_server = len(targets) > 1
        self._session_id = str(uuid.uuid4())

        # Governance components (lazy-init)
        self._policy: Any = None
        self._security_gate: Any = None
        self._guardrail_engine: Any = None
        self._audit_logger: Any = None

    # ------------------------------------------------------------------
    # Governance component initialization
    # ------------------------------------------------------------------

    def _init_governance(self) -> None:
        """Initialize governance components."""
        # Policy
        from aegis.core.policy import Policy

        if self._policy_path and Path(self._policy_path).exists():
            self._policy = Policy.from_yaml(self._policy_path)
        else:
            self._policy = Policy(rules=[])

        # Build extended security modules (lazy-create only when enabled)
        response_scanner = None
        escalation_detector = None
        shadow_detector = None
        rate_limiter = None

        if self._response_scanning:
            try:
                from aegis.core.mcp_response_scanner import MCPResponseScanner

                response_scanner = MCPResponseScanner()
            except ImportError:
                logger.warning("[aegis] Response scanner module not available")

        if self._escalation_detection:
            try:
                from aegis.core.mcp_escalation import EscalationDetector

                escalation_detector = EscalationDetector()
            except ImportError:
                logger.warning("[aegis] Escalation detector module not available")

        if self._shadow_detection:
            try:
                from aegis.core.mcp_shadow import ToolShadowDetector

                shadow_detector = ToolShadowDetector()
            except ImportError:
                logger.warning("[aegis] Shadow detector module not available")

        if self._rate_limit_config is not None:
            try:
                from aegis.core.mcp_rate_limiter import MCPRateLimiter, RateLimitConfig

                cfg = RateLimitConfig(
                    requests_per_minute=self._rate_limit_config.get("rpm", 60),
                    burst_limit=self._rate_limit_config.get("burst", 10),
                )
                rate_limiter = MCPRateLimiter(default_config=cfg)
            except ImportError:
                logger.warning("[aegis] Rate limiter module not available")

        # Security gate
        from aegis.core.mcp_security import MCPSecurityGate, TrustLevel

        trust_map = {t.name: t for t in TrustLevel}
        min_trust = trust_map.get(self._min_trust_str, TrustLevel.L1_SCANNED)
        self._security_gate = MCPSecurityGate(
            pin_store_path=self._pin_store,
            min_trust_level=min_trust,
            response_scanner=response_scanner,
            escalation_detector=escalation_detector,
            shadow_detector=shadow_detector,
            rate_limiter=rate_limiter,
        )

        # Guardrails
        from aegis.instrument._defaults import resolve_guardrails

        self._guardrail_engine = resolve_guardrails(self._guardrails_spec)

        # Audit logger
        from aegis.runtime.audit import AuditLogger

        self._audit_logger = AuditLogger(db_path=self._audit_db)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Connect to all target servers and discover their tools."""
        self._init_governance()
        self._exit_stack = AsyncExitStack()
        await self._exit_stack.__aenter__()

        for target in self._targets:
            try:
                conn = await self._connect_target(target)
                self._connections.append(conn)
                await self._discover_tools(conn)
                await self._discover_resources(conn)
                await self._discover_prompts(conn)
                logger.info(
                    "[aegis] Connected to %s: %d tools, %d resources, %d prompts",
                    target.name,
                    len(conn.tools),
                    len(conn.resources),
                    len(conn.prompts),
                )
            except Exception:
                logger.exception("[aegis] Failed to connect to %s", target.name)

        logger.info(
            "[aegis] Proxy ready: %d tools from %d servers",
            len(self._tool_registry),
            len(self._connections),
        )

    async def shutdown(self) -> None:
        """Gracefully disconnect from all target servers."""
        if self._exit_stack:
            await self._exit_stack.aclose()
        self._connections.clear()
        self._tool_registry.clear()

    # ------------------------------------------------------------------
    # Target server management
    # ------------------------------------------------------------------

    async def _connect_target(self, target: TargetServerConfig) -> _TargetConnection:
        """Spawn and connect to a single target MCP server."""
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        env = {**os.environ, **(target.env or {})}
        server_params = StdioServerParameters(
            command=target.command,
            args=target.args,
            env=env,
        )

        assert self._exit_stack is not None
        streams = await self._exit_stack.enter_async_context(stdio_client(server_params))
        read_stream, write_stream = streams
        session: ClientSession = await self._exit_stack.enter_async_context(
            ClientSession(read_stream, write_stream)
        )
        await session.initialize()

        return _TargetConnection(config=target, session=session)

    async def _discover_tools(self, conn: _TargetConnection) -> None:
        """List tools from a connected target and register them."""
        result = await conn.session.list_tools()
        for tool in result.tools:
            conn.tools[tool.name] = tool
            proxy_name = f"{conn.config.name}___{tool.name}" if self._multi_server else tool.name
            self._tool_registry[proxy_name] = ToolEntry(
                server_name=conn.config.name,
                tool=tool,
                proxy_name=proxy_name,
            )
            # Pin tool for rug-pull detection
            if self._security_gate:
                schema = tool.inputSchema if hasattr(tool, "inputSchema") else {}
                self._security_gate.pin_tool(
                    conn.config.name,
                    tool.name,
                    tool.description or "",
                    schema,
                )

        # Shadow detection — register all tools from this server at once
        if self._security_gate:
            tool_dicts = [
                {
                    "name": t.name,
                    "description": t.description or "",
                    "inputSchema": t.inputSchema if hasattr(t, "inputSchema") else {},
                }
                for t in result.tools
            ]
            shadow_findings = self._security_gate.register_tools(
                conn.config.name, tool_dicts
            )
            for sf in shadow_findings:
                severity = getattr(sf, "severity", "medium")
                if severity in ("critical",):
                    logger.error(
                        "[aegis] SHADOW %s: %s", conn.config.name, sf.detail
                    )
                elif severity in ("high",):
                    logger.warning(
                        "[aegis] SHADOW %s: %s", conn.config.name, sf.detail
                    )
                elif severity in ("medium",):
                    logger.info(
                        "[aegis] SHADOW %s: %s", conn.config.name, sf.detail
                    )
                else:
                    logger.debug(
                        "[aegis] SHADOW %s: %s", conn.config.name, sf.detail
                    )

    async def _discover_resources(self, conn: _TargetConnection) -> None:
        """List resources from a connected target."""
        try:
            result = await conn.session.list_resources()
            for resource in result.resources:
                conn.resources.append(resource)
                self._resource_registry.append(
                    ResourceEntry(server_name=conn.config.name, resource=resource)
                )
        except Exception:
            # Target may not support resources
            pass

    async def _discover_prompts(self, conn: _TargetConnection) -> None:
        """List prompts from a connected target."""
        try:
            result = await conn.session.list_prompts()
            for prompt in result.prompts:
                conn.prompts.append(prompt)
                proxy_name = (
                    f"{conn.config.name}___{prompt.name}" if self._multi_server else prompt.name
                )
                self._prompt_registry[proxy_name] = PromptEntry(
                    server_name=conn.config.name, prompt=prompt
                )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Connection lookup
    # ------------------------------------------------------------------

    def _get_connection(self, server_name: str) -> _TargetConnection | None:
        """Find the connection for a given server name."""
        for conn in self._connections:
            if conn.config.name == server_name:
                return conn
        return None

    # ------------------------------------------------------------------
    # Governance pipeline
    # ------------------------------------------------------------------

    def _evaluate_security(self, entry: ToolEntry, arguments: dict[str, Any]) -> Any:
        """Run MCPSecurityGate on the tool call."""
        if not self._security_gate:
            return None
        schema = entry.tool.inputSchema if hasattr(entry.tool, "inputSchema") else {}
        return self._security_gate.evaluate(
            server=entry.server_name,
            tool=entry.tool.name,
            description=entry.tool.description or "",
            schema=schema,
            arguments=arguments,
        )

    def _evaluate_policy(self, entry: ToolEntry, arguments: dict[str, Any]) -> Any:
        """Evaluate the tool call against Aegis policy."""
        from aegis.core.action import Action

        action = Action(
            type=entry.tool.name,
            target=entry.server_name,
            params=arguments,
            description=f"MCP: {entry.tool.name}@{entry.server_name}",
        )
        return self._policy.evaluate(action)

    def _run_guardrails(self, arguments: dict[str, Any]) -> list[Any]:
        """Run guardrail engine on string arguments."""
        if not self._guardrail_engine:
            return []
        # Serialize arguments to check for injection/PII in values
        content = json.dumps(arguments, default=str, ensure_ascii=False)
        return self._guardrail_engine.check(content)  # type: ignore[no-any-return]

    def _audit_decision(
        self,
        entry: ToolEntry,
        arguments: dict[str, Any],
        decision: Any,
        *,
        blocked_reason: str | None = None,
    ) -> None:
        """Write audit log entry."""
        if not self._audit_logger:
            return
        from aegis.core.result import Result, ResultStatus

        result = None
        if blocked_reason:
            from aegis.core.action import Action

            action = Action(
                type=entry.tool.name,
                target=entry.server_name,
                params=arguments,
            )
            result = Result(
                action=action,
                status=ResultStatus.BLOCKED,
                error=blocked_reason,
            )
        self._audit_logger.log(
            self._session_id,
            decision,
            result=result,
        )

    # ------------------------------------------------------------------
    # MCP Server handlers
    # ------------------------------------------------------------------

    async def handle_list_tools(self) -> list[Any]:
        """Return all discovered tools across all targets."""
        from mcp import types

        tools = []
        for entry in self._tool_registry.values():
            # Create tool with proxy name but original schema
            tool = entry.tool
            schema = tool.inputSchema if hasattr(tool, "inputSchema") else {}
            tools.append(
                types.Tool(
                    name=entry.proxy_name,
                    description=tool.description or "",
                    inputSchema=schema,
                )
            )
        return tools

    async def handle_call_tool(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> list[Any]:
        """Governance pipeline + forward to target server."""
        from mcp import types

        arguments = arguments or {}

        # 1. Look up tool
        entry = self._tool_registry.get(name)
        if not entry:
            return [
                types.TextContent(
                    type="text",
                    text=f"[aegis] Unknown tool: {name}",
                )
            ]

        # 1b. Rate limiting (BEFORE all other checks)
        if self._security_gate:
            rl_result = self._security_gate.check_rate_limit(
                entry.tool.name,
                entry.server_name,
                session_id=self._session_id,
            )
            if rl_result is not None and not rl_result.allowed:
                reason = f"Rate limited: {rl_result.reason}"
                logger.warning("[aegis] BLOCKED %s: %s", name, reason)
                return [
                    types.TextContent(
                        type="text",
                        text=f"[aegis] Tool call blocked: {reason}",
                    )
                ]

        # 2. Security gate
        trust_score = self._evaluate_security(entry, arguments)
        if trust_score and self._security_gate.should_block(trust_score):
            findings_str = "; ".join(
                f"{f.category}:{f.severity.value}" for f in trust_score.findings
            )
            reason = (
                f"Security gate blocked (trust={trust_score.level.name},"
                f" findings=[{findings_str}])"
            )
            decision = self._evaluate_policy(entry, arguments)
            self._audit_decision(entry, arguments, decision, blocked_reason=reason)
            logger.warning("[aegis] BLOCKED %s: %s", name, reason)
            return [
                types.TextContent(
                    type="text",
                    text=f"[aegis] Tool call blocked: {reason}",
                )
            ]

        # 3. Policy evaluation
        decision = self._evaluate_policy(entry, arguments)
        from aegis.core.policy import Approval

        if decision.approval == Approval.BLOCK:
            reason = (
                f"Policy blocked (rule={decision.matched_rule}, risk={decision.risk_level.value})"
            )
            self._audit_decision(entry, arguments, decision, blocked_reason=reason)
            logger.warning("[aegis] BLOCKED %s: %s", name, reason)
            return [
                types.TextContent(
                    type="text",
                    text=f"[aegis] Tool call blocked: {reason}",
                )
            ]

        # 4. Guardrails
        guardrail_results = self._run_guardrails(arguments)
        blocked = [r for r in guardrail_results if getattr(r, "action", "") == "blocked"]
        if blocked:
            details = "; ".join(getattr(r, "guardrail_name", "unknown") for r in blocked)
            reason = f"Guardrail blocked ({details})"
            self._audit_decision(entry, arguments, decision, blocked_reason=reason)
            logger.warning("[aegis] BLOCKED %s: %s", name, reason)
            return [
                types.TextContent(
                    type="text",
                    text=f"[aegis] Tool call blocked: {reason}",
                )
            ]

        # 4b. Escalation detection (record call for pattern tracking)
        if self._security_gate:
            esc_findings = self._security_gate.record_call(
                entry.tool.name,
                entry.server_name,
                arguments,
                session_id=self._session_id,
            )
            for ef in esc_findings:
                severity = getattr(ef.rule, "severity", "medium")
                detail = getattr(ef, "detail", str(ef))
                if severity in ("critical",):
                    logger.error("[aegis] ESCALATION %s: %s", name, detail)
                elif severity in ("high",):
                    logger.warning("[aegis] ESCALATION %s: %s", name, detail)
                elif severity in ("medium",):
                    logger.info("[aegis] ESCALATION %s: %s", name, detail)
                else:
                    logger.debug("[aegis] ESCALATION %s: %s", name, detail)

        # 5. Forward to target server
        conn = self._get_connection(entry.server_name)
        if not conn:
            return [
                types.TextContent(
                    type="text",
                    text=f"[aegis] Target server '{entry.server_name}' not connected",
                )
            ]

        try:
            result = await conn.session.call_tool(entry.tool.name, arguments)

            # 5b. Response scanning (AFTER getting response from target)
            if self._security_gate and result.content:
                response_text = " ".join(
                    getattr(c, "text", "") for c in result.content if hasattr(c, "text")
                )
                if response_text:
                    resp_findings = self._security_gate.check_response(
                        entry.tool.name,
                        response_text,
                        server_name=entry.server_name,
                    )
                    has_critical = False
                    for rf in resp_findings:
                        severity = getattr(rf, "severity", "medium")
                        detail = getattr(rf, "detail", str(rf))
                        if severity in ("critical",):
                            logger.error(
                                "[aegis] RESPONSE %s: %s", name, detail
                            )
                            has_critical = True
                        elif severity in ("high",):
                            logger.warning(
                                "[aegis] RESPONSE %s: %s", name, detail
                            )
                        elif severity in ("medium",):
                            logger.info(
                                "[aegis] RESPONSE %s: %s", name, detail
                            )
                        else:
                            logger.debug(
                                "[aegis] RESPONSE %s: %s", name, detail
                            )

                    if has_critical:
                        reason = (
                            "Response blocked: critical security findings in tool output"
                        )
                        self._audit_decision(
                            entry, arguments, decision, blocked_reason=reason
                        )
                        logger.warning("[aegis] BLOCKED response %s: %s", name, reason)
                        return [
                            types.TextContent(
                                type="text",
                                text=f"[aegis] {reason}",
                            )
                        ]

            # Audit success
            self._audit_decision(entry, arguments, decision)
            logger.debug("[aegis] ALLOWED %s → forwarded", name)
            return result.content  # type: ignore[no-any-return]
        except Exception as exc:
            reason = f"Target server error: {exc}"
            self._audit_decision(entry, arguments, decision, blocked_reason=reason)
            logger.error("[aegis] ERROR %s: %s", name, reason)
            return [
                types.TextContent(
                    type="text",
                    text=f"[aegis] Error forwarding tool call: {exc}",
                )
            ]

    async def handle_list_resources(self) -> list[Any]:
        """Return all discovered resources across all targets."""
        return [entry.resource for entry in self._resource_registry]

    async def handle_read_resource(self, uri: Any) -> Any:
        """Forward resource read to the appropriate target."""
        uri_str = str(uri)
        for entry in self._resource_registry:
            if str(entry.resource.uri) == uri_str:
                conn = self._get_connection(entry.server_name)
                if conn:
                    return await conn.session.read_resource(uri)
        raise ValueError(f"Resource not found: {uri}")

    async def handle_list_prompts(self) -> list[Any]:
        """Return all discovered prompts across all targets."""
        from mcp import types

        prompts = []
        for proxy_name, entry in self._prompt_registry.items():
            prompt = entry.prompt
            prompts.append(
                types.Prompt(
                    name=proxy_name,
                    description=prompt.description,
                    arguments=prompt.arguments,
                )
            )
        return prompts

    async def handle_get_prompt(self, name: str, arguments: dict[str, str] | None = None) -> Any:
        """Forward prompt get to the appropriate target."""
        entry = self._prompt_registry.get(name)
        if not entry:
            raise ValueError(f"Prompt not found: {name}")
        conn = self._get_connection(entry.server_name)
        if not conn:
            raise ValueError(f"Target server '{entry.server_name}' not connected")
        return await conn.session.get_prompt(entry.prompt.name, arguments)

    # ------------------------------------------------------------------
    # Server construction
    # ------------------------------------------------------------------

    def build_server(self) -> Any:
        """Build the low-level MCP Server with handlers registered."""
        from mcp.server import Server

        server = Server("aegis-proxy")
        proxy = self

        @server.list_tools()  # type: ignore[no-untyped-call]
        async def _list_tools() -> list[Any]:
            return await proxy.handle_list_tools()

        @server.call_tool()  # type: ignore[no-untyped-call]
        async def _call_tool(name: str, arguments: dict[str, Any] | None = None) -> list[Any]:
            return await proxy.handle_call_tool(name, arguments)

        @server.list_resources()  # type: ignore[no-untyped-call]
        async def _list_resources() -> list[Any]:
            return await proxy.handle_list_resources()

        @server.read_resource()  # type: ignore[no-untyped-call]
        async def _read_resource(uri: Any) -> Any:
            return await proxy.handle_read_resource(uri)

        @server.list_prompts()  # type: ignore[no-untyped-call]
        async def _list_prompts() -> list[Any]:
            return await proxy.handle_list_prompts()

        @server.get_prompt()  # type: ignore[no-untyped-call]
        async def _get_prompt(name: str, arguments: dict[str, str] | None = None) -> Any:
            return await proxy.handle_get_prompt(name, arguments)

        return server

    async def run_stdio(self) -> None:
        """Run the proxy as an stdio MCP server."""
        from mcp.server.stdio import stdio_server

        server = self.build_server()
        await self.start()
        try:
            async with stdio_server() as (read_stream, write_stream):
                await server.run(
                    read_stream,
                    write_stream,
                    server.create_initialization_options(),
                )
        finally:
            await self.shutdown()


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------


def _load_config(config_path: str) -> dict[str, Any]:
    """Load proxy configuration from YAML file."""
    import yaml

    with open(config_path) as f:
        return yaml.safe_load(f) or {}


def _expand_env(value: str) -> str:
    """Expand ${VAR} references in strings."""
    import re

    def _replace(m: re.Match[str]) -> str:
        return os.environ.get(m.group(1), m.group(0))

    return re.sub(r"\$\{(\w+)\}", _replace, value)


def _config_to_targets(config: dict[str, Any]) -> list[TargetServerConfig]:
    """Parse targets from config dict."""
    targets = []
    for t in config.get("targets", []):
        env = None
        if t.get("env"):
            env = {k: _expand_env(str(v)) for k, v in t["env"].items()}
        targets.append(
            TargetServerConfig(
                name=t["name"],
                command=t["command"],
                args=t.get("args", []),
                env=env,
            )
        )
    return targets


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _infer_server_name(command: str, args: list[str]) -> str:
    """Infer a server name from the command and arguments."""
    # Common patterns: npx -y @modelcontextprotocol/server-filesystem
    for arg in args:
        if "server-" in arg:
            # Extract "filesystem" from "@modelcontextprotocol/server-filesystem"
            part = arg.rsplit("server-", 1)[-1]
            return part.split("/")[0].split("@")[0]
        if arg.startswith("@") and "/" in arg:
            # @org/package-name -> package-name
            return arg.split("/")[-1]
    return command


def main(argv: list[str] | None = None) -> None:
    """Entry point for the Aegis MCP Proxy."""
    parser = argparse.ArgumentParser(
        prog="aegis-mcp-proxy",
        description="Aegis MCP Proxy — transparent governance proxy for MCP servers.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--wrap",
        nargs=argparse.REMAINDER,
        metavar="COMMAND",
        help="Wrap a single MCP server command (e.g., --wrap npx -y server-fs /home)",
    )
    group.add_argument(
        "--config",
        type=str,
        help="Path to aegis-proxy.yaml config for multi-server mode.",
    )
    parser.add_argument(
        "--policy",
        type=str,
        default=None,
        help="Path to YAML policy file (or set AEGIS_POLICY_PATH env var).",
    )
    parser.add_argument(
        "--trust-level",
        type=str,
        default="L1_SCANNED",
        help="Minimum trust level (default: L1_SCANNED).",
    )
    parser.add_argument(
        "--audit-db",
        type=str,
        default="aegis_proxy_audit.db",
        help="Audit database path (default: aegis_proxy_audit.db).",
    )
    parser.add_argument(
        "--pin-store",
        type=str,
        default=None,
        help="Hash pin store path for rug-pull detection.",
    )
    parser.add_argument(
        "--server-name",
        type=str,
        default=None,
        help="Server name for single --wrap mode (default: inferred from command).",
    )
    parser.add_argument(
        "--guardrails",
        type=str,
        default="default",
        help="Guardrails: 'default', 'none', or path to pack YAML.",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level (default: INFO).",
    )
    parser.add_argument(
        "--no-response-scan",
        action="store_true",
        default=False,
        help="Disable response scanning.",
    )
    parser.add_argument(
        "--no-escalation",
        action="store_true",
        default=False,
        help="Disable escalation detection.",
    )
    parser.add_argument(
        "--no-shadow",
        action="store_true",
        default=False,
        help="Disable shadow detection.",
    )
    parser.add_argument(
        "--rate-limit-rpm",
        type=int,
        default=None,
        metavar="N",
        help="Set requests per minute per tool (default: 60). Enables rate limiting.",
    )
    parser.add_argument(
        "--rate-limit-burst",
        type=int,
        default=None,
        metavar="N",
        help="Set burst limit (default: 10). Enables rate limiting.",
    )
    args = parser.parse_args(argv)

    # Configure logging to stderr
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(message)s",
        stream=sys.stderr,
    )

    # Build targets
    if args.wrap is not None:
        if not args.wrap:
            parser.error("--wrap requires a command (e.g., --wrap npx -y server-filesystem)")
        command = args.wrap[0]
        cmd_args = args.wrap[1:]
        name = args.server_name or _infer_server_name(command, cmd_args)
        targets = [TargetServerConfig(name=name, command=command, args=cmd_args)]
    else:
        config = _load_config(args.config)
        targets = _config_to_targets(config)
        # Config-level overrides
        if not args.policy and config.get("policy"):
            args.policy = config["policy"]
        if args.audit_db == "aegis_proxy_audit.db" and config.get("audit_db"):
            args.audit_db = config["audit_db"]
        if args.trust_level == "L1_SCANNED" and config.get("min_trust_level"):
            args.trust_level = config["min_trust_level"]
        if not args.pin_store and config.get("pin_store"):
            args.pin_store = config["pin_store"]

    if not targets:
        parser.error("No target servers configured.")

    target_names = ", ".join(t.name for t in targets)
    print(f"[aegis] Starting proxy for: {target_names}", file=sys.stderr)

    # Build rate limit config dict if any rate limit flags are set
    rate_limit_config: dict[str, Any] | None = None
    if args.rate_limit_rpm is not None or args.rate_limit_burst is not None:
        rate_limit_config = {
            "rpm": args.rate_limit_rpm if args.rate_limit_rpm is not None else 60,
            "burst": args.rate_limit_burst if args.rate_limit_burst is not None else 10,
        }

    proxy = AegisMCPProxy(
        targets=targets,
        policy_path=args.policy,
        guardrails=args.guardrails,
        audit_db=args.audit_db,
        min_trust_level=args.trust_level,
        pin_store=args.pin_store,
        log_level=args.log_level,
        response_scanning=not args.no_response_scan,
        escalation_detection=not args.no_escalation,
        shadow_detection=not args.no_shadow,
        rate_limit_config=rate_limit_config,
    )

    import anyio

    anyio.run(proxy.run_stdio)


if __name__ == "__main__":
    main()
