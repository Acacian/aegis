"""Aegis governance client SDK.

Connects an AI agent to a running Aegis governance server for
policy evaluation, guardrail checks, and audit logging.

Usage::

    from aegis.client import AegisClient

    client = AegisClient(
        server_url="http://localhost:8000",
        agent_id="my-agent",
        name="My LangChain Agent",
        framework="langchain",
    )

    # Evaluate an action against server policy
    result = client.evaluate("read", "user_data")

    # Check content against server guardrails
    check = client.check_guardrails("some user input")

    # Disconnect (stops heartbeat)
    client.disconnect()

Requires ``httpx``::

    pip install agent-aegis[httpx]
"""

from __future__ import annotations

import atexit
import contextlib
import threading
from typing import Any


class AegisClient:
    """Client for communicating with an Aegis governance server.

    On creation, registers the agent with the server and starts
    a background heartbeat thread. Call :meth:`disconnect` to
    unregister and stop the heartbeat.
    """

    def __init__(
        self,
        server_url: str,
        *,
        agent_id: str,
        name: str = "",
        framework: str = "",
        version: str = "",
        api_key: str = "",
        heartbeat_interval: int = 30,
        auto_register: bool = True,
    ) -> None:
        try:
            import httpx
        except ImportError:
            msg = "httpx is required for AegisClient: pip install 'agent-aegis[httpx]'"
            raise ImportError(msg) from None

        self._base_url = server_url.rstrip("/")
        self._agent_id = agent_id
        self._name = name or agent_id
        self._framework = framework
        self._version = version
        self._heartbeat_interval = heartbeat_interval
        self._headers: dict[str, str] = {}
        if api_key:
            self._headers["X-API-Key"] = api_key

        self._http = httpx.Client(
            base_url=self._base_url,
            headers=self._headers,
            timeout=10.0,
        )
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None
        self._registered = False

        if auto_register:
            self.register()

        atexit.register(self._cleanup)

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def server_url(self) -> str:
        return self._base_url

    @property
    def is_registered(self) -> bool:
        return self._registered

    # ------------------------------------------------------------------
    # Registration & heartbeat
    # ------------------------------------------------------------------

    def register(self) -> dict[str, Any]:
        """Register this agent with the server."""
        resp = self._http.post(
            "/api/v1/agents",
            json={
                "agent_id": self._agent_id,
                "name": self._name,
                "framework": self._framework,
                "version": self._version,
            },
        )
        resp.raise_for_status()
        self._registered = True
        self._start_heartbeat()
        return resp.json()

    def _start_heartbeat(self) -> None:
        if self._heartbeat_thread is not None:
            return
        self._heartbeat_stop.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, daemon=True, name=f"aegis-hb-{self._agent_id}"
        )
        self._heartbeat_thread.start()

    def _heartbeat_loop(self) -> None:
        while not self._heartbeat_stop.is_set():
            self._heartbeat_stop.wait(self._heartbeat_interval)
            if self._heartbeat_stop.is_set():
                break
            with contextlib.suppress(Exception):
                self._http.post(f"/api/v1/agents/{self._agent_id}/heartbeat")

    def disconnect(self) -> None:
        """Unregister from the server and stop heartbeat."""
        self._heartbeat_stop.set()
        if self._heartbeat_thread is not None:
            self._heartbeat_thread.join(timeout=2)
            self._heartbeat_thread = None
        if self._registered:
            with contextlib.suppress(Exception):
                self._http.delete(f"/api/v1/agents/{self._agent_id}")
            self._registered = False

    def _cleanup(self) -> None:
        """Called at interpreter exit."""
        self.disconnect()
        self._http.close()

    # ------------------------------------------------------------------
    # Governance API
    # ------------------------------------------------------------------

    def evaluate(
        self,
        action_type: str,
        target: str = "",
        params: dict[str, Any] | None = None,
        description: str = "",
    ) -> dict[str, Any]:
        """Evaluate an action against the server's policy (dry-run).

        Returns the policy decision including risk level, approval status,
        and any guardrail results.
        """
        resp = self._http.post(
            "/api/v1/evaluate",
            json={
                "action_type": action_type,
                "target": target,
                "params": params or {},
                "description": description,
            },
        )
        resp.raise_for_status()
        return resp.json()

    def execute(
        self,
        action_type: str,
        target: str = "",
        params: dict[str, Any] | None = None,
        description: str = "",
    ) -> dict[str, Any]:
        """Execute an action through the full governance pipeline."""
        resp = self._http.post(
            "/api/v1/execute",
            json={
                "action_type": action_type,
                "target": target,
                "params": params or {},
                "description": description,
            },
        )
        resp.raise_for_status()
        return resp.json()

    def check_guardrails(self, content: str) -> dict[str, Any]:
        """Check content against the server's guardrail engine.

        Returns pass/fail status and individual guardrail results.
        """
        resp = self._http.post(
            "/api/v1/guardrails/check",
            json={"content": content},
        )
        resp.raise_for_status()
        return resp.json()

    def get_policy(self) -> dict[str, Any]:
        """Retrieve the current policy from the server."""
        resp = self._http.get("/api/v1/policy")
        resp.raise_for_status()
        return resp.json()

    def get_audit(self, **filters: Any) -> dict[str, Any] | list[dict[str, Any]]:
        """Query audit log from the server."""
        resp = self._http.get("/api/v1/audit", params=filters)
        resp.raise_for_status()
        return resp.json()

    def status(self) -> dict[str, Any]:
        """Get this agent's status from the server."""
        resp = self._http.get(f"/api/v1/agents/{self._agent_id}")
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> AegisClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.disconnect()
