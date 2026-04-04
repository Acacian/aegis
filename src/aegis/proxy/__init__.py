"""Aegis Proxy -- external governance gateway for zero-trust environments.

Intercepts agent-to-MCP tool calls at the network level, applies
ActionClaim evaluation, and forwards governed calls to upstream servers.
"""

from __future__ import annotations

from aegis.proxy.config import ProxyConfig, UpstreamConfig
from aegis.proxy.server import AegisProxy, ProxyResult

__all__ = [
    "AegisProxy",
    "ProxyConfig",
    "ProxyResult",
    "UpstreamConfig",
]
