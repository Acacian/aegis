"""ASGI application for Aegis Proxy.

Exposes the governance proxy as an HTTP server using Starlette.
Handles JSON-RPC style tool call requests and returns governed responses.

Usage::

    aegis proxy --listen :8080 --upstream http://mcp-server:9090

Or programmatic::

    from aegis.proxy.app import create_app
    app = create_app(config)
    # Run with: uvicorn aegis.proxy.app:app
"""

from __future__ import annotations

import json
import logging
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from aegis.proxy.config import ProxyConfig
from aegis.proxy.server import AegisProxy

logger = logging.getLogger("aegis.proxy.app")


def create_app(config: ProxyConfig) -> Starlette:
    """Create the ASGI application for the proxy server."""
    proxy = AegisProxy(config)
    started = False

    async def _ensure_started() -> None:
        nonlocal started
        if not started:
            await proxy.start()
            started = True

    # -- Routes ----------------------------------------------------------------

    async def health(request: Request) -> JSONResponse:
        """Health check endpoint."""
        return JSONResponse({"status": "ok", "mode": config.mode})

    async def tool_call(request: Request) -> Response:
        """Handle a tool call through the governance pipeline.

        Accepts JSON body::

            {
                "tool_name": "read_file",
                "arguments": {"path": "/tmp/test.txt"},
                "server_name": "mcp-server",
                "agent_id": "agent-1",
                "justification": "need to read config",
                "originating_goal": "complete task",
                "token": "bearer-token-here"
            }
        """
        await _ensure_started()

        try:
            body: dict[str, Any] = await request.json()
        except (json.JSONDecodeError, ValueError):
            return JSONResponse(
                {"error": "Invalid JSON body"},
                status_code=400,
            )

        tool_name = body.get("tool_name", "")
        arguments = body.get("arguments", {})
        server_name = body.get("server_name", "")
        agent_id = body.get("agent_id", "")
        justification = body.get("justification", "")
        originating_goal = body.get("originating_goal", "")
        token = body.get("token", "")

        if not tool_name or not server_name:
            return JSONResponse(
                {"error": "tool_name and server_name are required"},
                status_code=400,
            )

        # Authenticate if configured
        if config.auth.mode != "none" and not proxy.authenticate(agent_id, token):
            return JSONResponse(
                {"error": "Authentication failed"},
                status_code=401,
            )

        result = await proxy.handle_tool_call(
            tool_name=tool_name,
            arguments=arguments,
            server_name=server_name,
            agent_id=agent_id,
            justification=justification,
            originating_goal=originating_goal,
        )

        response_body: dict[str, Any] = {
            "allowed": result.allowed,
            "trace_id": result.trace_id,
        }

        if not result.allowed:
            response_body["reason"] = result.reason
            if result.requires_escalation:
                response_body["requires_escalation"] = True
            status = 403
        else:
            response_body["data"] = result.data
            if result.forward_result:
                response_body["latency_ms"] = result.forward_result.latency_ms
                if not result.forward_result.success:
                    response_body["upstream_error"] = result.forward_result.error
            status = 200

        return JSONResponse(response_body, status_code=status)

    async def status(request: Request) -> JSONResponse:
        """Return proxy status and upstream health."""
        await _ensure_started()
        upstreams = [
            {"name": u.name, "url": u.url, "protocol": u.protocol} for u in config.upstreams
        ]
        return JSONResponse(
            {
                "mode": config.mode,
                "claims_enabled": config.claims.enabled,
                "circuit_breaker_enabled": config.circuit_breaker.enabled,
                "upstreams": upstreams,
            }
        )

    # -- MCP JSON-RPC compatibility endpoint -----------------------------------

    async def mcp_jsonrpc(request: Request) -> Response:
        """Handle MCP JSON-RPC 2.0 tool call requests.

        Compatible with MCP client libraries that POST JSON-RPC to the proxy.

        Expected body::

            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": {"path": "/tmp/test"}
                },
                "id": 1
            }
        """
        await _ensure_started()

        try:
            body: dict[str, Any] = await request.json()
        except (json.JSONDecodeError, ValueError):
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32700, "message": "Parse error"},
                    "id": None,
                },
                status_code=400,
            )

        method = body.get("method", "")
        params = body.get("params", {})
        req_id = body.get("id")

        if method != "tools/call":
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                    "id": req_id,
                }
            )

        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        # Extract server from X-Server-Name header or first upstream
        server_name = request.headers.get("x-server-name", "")
        if not server_name and config.upstreams:
            server_name = config.upstreams[0].name

        agent_id = request.headers.get("x-agent-id", "")
        token = request.headers.get("authorization", "").removeprefix("Bearer ").strip()

        # Authenticate
        if config.auth.mode != "none" and not proxy.authenticate(agent_id, token):
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32000, "message": "Authentication failed"},
                    "id": req_id,
                },
                status_code=401,
            )

        result = await proxy.handle_tool_call(
            tool_name=tool_name,
            arguments=arguments,
            server_name=server_name,
            agent_id=agent_id,
        )

        if not result.allowed:
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32000, "message": result.reason},
                    "id": req_id,
                }
            )

        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "result": result.data,
                "id": req_id,
            }
        )

    # -- App assembly ----------------------------------------------------------

    routes = [
        Route("/health", health, methods=["GET"]),
        Route("/v1/tool-call", tool_call, methods=["POST"]),
        Route("/v1/status", status, methods=["GET"]),
        Route("/mcp", mcp_jsonrpc, methods=["POST"]),
    ]

    return Starlette(routes=routes)
