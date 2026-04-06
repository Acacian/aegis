"""Protocol-specific upstream forwarders for Aegis Proxy.

Each forwarder translates governed tool calls into the upstream
server's native protocol and returns the response.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Protocol

logger = logging.getLogger("aegis.proxy.forwarder")


@dataclass(frozen=True)
class ForwardResult:
    """Result of forwarding a tool call to an upstream server."""

    success: bool
    status_code: int = 200
    data: Any = None
    error: str = ""
    latency_ms: float = 0.0


class Forwarder(Protocol):
    """Protocol for upstream forwarders."""

    async def forward(
        self,
        *,
        url: str,
        tool_name: str,
        arguments: dict[str, Any],
        timeout_ms: int = 30000,
        headers: dict[str, str] | None = None,
    ) -> ForwardResult: ...


class McpHttpForwarder:
    """Forwards tool calls via MCP-over-HTTP (JSON-RPC 2.0)."""

    async def forward(
        self,
        *,
        url: str,
        tool_name: str,
        arguments: dict[str, Any],
        timeout_ms: int = 30000,
        headers: dict[str, str] | None = None,
    ) -> ForwardResult:
        import time

        try:
            import httpx
        except ImportError:
            return ForwardResult(
                success=False,
                error="httpx not installed: pip install httpx",
            )

        payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
            "id": 1,
        }

        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=timeout_ms / 1000) as client:
                resp = await client.post(
                    url,
                    json=payload,
                    headers=headers or {},
                )
            latency = (time.monotonic() - t0) * 1000

            if resp.status_code != 200:
                return ForwardResult(
                    success=False,
                    status_code=resp.status_code,
                    error=f"HTTP {resp.status_code}: {resp.text[:200]}",
                    latency_ms=latency,
                )

            data = resp.json()
            if "error" in data:
                return ForwardResult(
                    success=False,
                    status_code=resp.status_code,
                    data=data,
                    error=data["error"].get("message", str(data["error"])),
                    latency_ms=latency,
                )

            return ForwardResult(
                success=True,
                status_code=resp.status_code,
                data=data.get("result"),
                latency_ms=latency,
            )
        except Exception as exc:
            latency = (time.monotonic() - t0) * 1000
            return ForwardResult(
                success=False,
                error=str(exc),
                latency_ms=latency,
            )


class McpSseForwarder:
    """Forwards tool calls via MCP-over-SSE (Server-Sent Events)."""

    async def forward(
        self,
        *,
        url: str,
        tool_name: str,
        arguments: dict[str, Any],
        timeout_ms: int = 30000,
        headers: dict[str, str] | None = None,
    ) -> ForwardResult:
        import time

        try:
            import httpx
        except ImportError:
            return ForwardResult(
                success=False,
                error="httpx not installed: pip install httpx",
            )

        payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
            "id": 1,
        }

        t0 = time.monotonic()
        try:
            # SSE: POST to the message endpoint, collect response
            message_url = url.rstrip("/") + "/message"
            async with httpx.AsyncClient(timeout=timeout_ms / 1000) as client:
                resp = await client.post(
                    message_url,
                    json=payload,
                    headers=headers or {},
                )
            latency = (time.monotonic() - t0) * 1000

            if resp.status_code != 200:
                return ForwardResult(
                    success=False,
                    status_code=resp.status_code,
                    error=f"HTTP {resp.status_code}",
                    latency_ms=latency,
                )

            # Parse SSE response — look for data lines
            result_data = None
            for line in resp.text.splitlines():
                if line.startswith("data: "):
                    try:
                        result_data = json.loads(line[6:])
                    except json.JSONDecodeError:
                        continue

            if result_data and "error" in result_data:
                return ForwardResult(
                    success=False,
                    data=result_data,
                    error=str(result_data["error"]),
                    latency_ms=latency,
                )

            return ForwardResult(
                success=True,
                status_code=resp.status_code,
                data=result_data.get("result") if result_data else resp.text,
                latency_ms=latency,
            )
        except Exception as exc:
            latency = (time.monotonic() - t0) * 1000
            return ForwardResult(
                success=False,
                error=str(exc),
                latency_ms=latency,
            )


class RestForwarder:
    """Forwards tool calls via REST API (POST)."""

    async def forward(
        self,
        *,
        url: str,
        tool_name: str,
        arguments: dict[str, Any],
        timeout_ms: int = 30000,
        headers: dict[str, str] | None = None,
    ) -> ForwardResult:
        import time

        try:
            import httpx
        except ImportError:
            return ForwardResult(
                success=False,
                error="httpx not installed: pip install httpx",
            )

        # REST: POST to url/tool_name
        target = f"{url.rstrip('/')}/{tool_name}"

        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=timeout_ms / 1000) as client:
                resp = await client.post(
                    target,
                    json=arguments,
                    headers=headers or {},
                )
            latency = (time.monotonic() - t0) * 1000

            if resp.status_code >= 400:
                return ForwardResult(
                    success=False,
                    status_code=resp.status_code,
                    error=f"HTTP {resp.status_code}: {resp.text[:200]}",
                    latency_ms=latency,
                )

            try:
                data = resp.json()
            except (json.JSONDecodeError, ValueError):
                data = resp.text

            return ForwardResult(
                success=True,
                status_code=resp.status_code,
                data=data,
                latency_ms=latency,
            )
        except Exception as exc:
            latency = (time.monotonic() - t0) * 1000
            return ForwardResult(
                success=False,
                error=str(exc),
                latency_ms=latency,
            )


def get_forwarder(protocol: str) -> Forwarder:
    """Get a forwarder for the given protocol."""
    _REGISTRY: dict[str, Forwarder] = {
        "mcp-http": McpHttpForwarder(),
        "mcp-sse": McpSseForwarder(),
        "rest": RestForwarder(),
    }
    forwarder = _REGISTRY.get(protocol)
    if forwarder is None:
        raise ValueError(f"Unknown protocol: {protocol!r}. Valid: {', '.join(_REGISTRY)}")
    return forwarder
