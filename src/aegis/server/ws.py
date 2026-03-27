"""WebSocket endpoint for real-time audit streaming."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
from typing import Any

from aegis.runtime.audit import AuditLogger


class AuditBroadcaster:
    """Bridges synchronous AuditLogger callbacks to async WebSocket clients."""

    def __init__(self) -> None:
        self._queues: set[asyncio.Queue[dict[str, Any]]] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    def attach(self, logger: AuditLogger) -> None:
        """Subscribe to an AuditLogger's entries."""
        logger.subscribe(self._on_entry)

    def detach(self, logger: AuditLogger) -> None:
        """Unsubscribe from an AuditLogger."""
        logger.unsubscribe(self._on_entry)

    def _on_entry(self, entry: dict[str, Any]) -> None:
        """Called synchronously from AuditLogger.log()."""
        if self._loop is None:
            with contextlib.suppress(RuntimeError):
                self._loop = asyncio.get_running_loop()
        if self._loop is None:
            return
        for q in list(self._queues):
            with contextlib.suppress(Exception):
                self._loop.call_soon_threadsafe(q.put_nowait, entry)

    def add_client(self) -> asyncio.Queue[dict[str, Any]]:
        """Register a new WebSocket client, returns its queue."""
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=256)
        self._queues.add(q)
        if self._loop is None:
            with contextlib.suppress(RuntimeError):
                self._loop = asyncio.get_running_loop()
        return q

    def remove_client(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        """Unregister a WebSocket client."""
        self._queues.discard(q)


def get_ws_route(broadcaster: AuditBroadcaster) -> Any:
    """Create a WebSocket route for real-time audit streaming."""
    from starlette.routing import WebSocketRoute
    from starlette.websockets import WebSocket, WebSocketDisconnect

    async def ws_audit(websocket: WebSocket) -> None:
        # Check API key authentication if AEGIS_API_KEY is set
        _api_key = os.environ.get("AEGIS_API_KEY")
        if _api_key:
            client_key = websocket.query_params.get("api_key", "")
            if client_key != _api_key:
                await websocket.close(code=4001, reason="Invalid or missing API key")
                return
        await websocket.accept()
        queue = broadcaster.add_client()
        try:
            while True:
                entry = await queue.get()
                await websocket.send_text(json.dumps(entry, default=str))
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            broadcaster.remove_client(queue)

    return WebSocketRoute("/ws/audit", ws_audit)
