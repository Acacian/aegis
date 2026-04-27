"""Agent registration and lifecycle management.

Tracks connected agents, their heartbeat status, and metadata.
Agents register via ``POST /api/v1/agents`` and send periodic
heartbeats via ``POST /api/v1/agents/{agent_id}/heartbeat``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentRecord:
    """Metadata for a registered agent."""

    agent_id: str
    name: str
    framework: str = ""
    version: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    registered_at: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)

    @property
    def is_alive(self) -> bool:
        """Check if last heartbeat was within timeout (checked externally)."""
        return True  # Caller checks against timeout

    def to_dict(self, *, timeout: int = 60) -> dict[str, Any]:
        elapsed = time.time() - self.last_heartbeat
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "framework": self.framework,
            "version": self.version,
            "metadata": self.metadata,
            "registered_at": self.registered_at,
            "last_heartbeat": self.last_heartbeat,
            "status": "alive" if elapsed < timeout else "stale",
            "uptime_seconds": round(time.time() - self.registered_at, 1),
        }


class AgentRegistry:
    """In-memory registry of connected agents."""

    def __init__(self, heartbeat_timeout: int = 60) -> None:
        self._agents: dict[str, AgentRecord] = {}
        self._heartbeat_timeout = heartbeat_timeout

    def register(
        self,
        agent_id: str,
        name: str,
        framework: str = "",
        version: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> AgentRecord:
        """Register or re-register an agent."""
        now = time.time()
        if agent_id in self._agents:
            rec = self._agents[agent_id]
            rec.name = name
            rec.framework = framework
            rec.version = version
            rec.metadata = metadata or {}
            rec.last_heartbeat = now
            return rec
        rec = AgentRecord(
            agent_id=agent_id,
            name=name,
            framework=framework,
            version=version,
            metadata=metadata or {},
            registered_at=now,
            last_heartbeat=now,
        )
        self._agents[agent_id] = rec
        return rec

    def heartbeat(self, agent_id: str) -> AgentRecord | None:
        """Update heartbeat timestamp. Returns None if not registered."""
        rec = self._agents.get(agent_id)
        if rec is not None:
            rec.last_heartbeat = time.time()
        return rec

    def unregister(self, agent_id: str) -> bool:
        """Remove an agent. Returns True if it existed."""
        return self._agents.pop(agent_id, None) is not None

    def get(self, agent_id: str) -> AgentRecord | None:
        return self._agents.get(agent_id)

    def list_all(self) -> list[AgentRecord]:
        return list(self._agents.values())

    def list_alive(self) -> list[AgentRecord]:
        now = time.time()
        return [
            r for r in self._agents.values() if (now - r.last_heartbeat) < self._heartbeat_timeout
        ]

    @property
    def count(self) -> int:
        return len(self._agents)

    @property
    def alive_count(self) -> int:
        return len(self.list_alive())
