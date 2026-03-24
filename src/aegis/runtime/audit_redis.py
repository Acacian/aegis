"""Redis-backed audit logger.

Uses Redis Sorted Sets for time-ordered entries per session,
a Hash for entry-by-ID lookup, INCR for row ID generation,
and Pub/Sub for the subscriber pattern.

Requires the ``redis`` package::

    pip install agent-aegis[redis]
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from threading import Thread
from typing import Any

from aegis.core.policy import PolicyDecision
from aegis.core.result import Result

# Redis key prefixes
_PREFIX = "aegis:audit"
_ID_SEQ = f"{_PREFIX}:id_seq"
_ENTRY_HASH = f"{_PREFIX}:entries"
_SESSION_ZSET = f"{_PREFIX}:session:"
_PUBSUB_CHANNEL = f"{_PREFIX}:notifications"


def _session_key(session_id: str) -> str:
    return f"{_SESSION_ZSET}{session_id}"


def _all_sessions_pattern() -> str:
    return f"{_SESSION_ZSET}*"


class RedisAuditLogger:
    """Audit logger backed by Redis.

    Each entry is stored as JSON in a Redis Hash keyed by entry ID.
    Session-scoped Sorted Sets provide time-ordered access, with the
    timestamp as the score and the entry ID as the member.

    Args:
        redis_url: Redis connection URL.
    """

    def __init__(self, redis_url: str = "redis://localhost:6379/0") -> None:
        import redis

        self._client: redis.Redis = redis.Redis.from_url(redis_url, decode_responses=True)
        self._subscribers: list[Callable[[dict[str, Any]], Any]] = []
        self._pubsub: Any | None = None
        self._pubsub_thread: Thread | None = None

    # ------------------------------------------------------------------
    # Core methods (AuditBackend protocol)
    # ------------------------------------------------------------------

    def log(
        self,
        session_id: str,
        decision: PolicyDecision,
        *,
        result: Result | None = None,
        human_decision: str | None = None,
    ) -> int:
        """Write one audit entry. Returns the integer entry ID."""
        row_id = int(self._client.incr(_ID_SEQ))  # type: ignore[arg-type]
        now = datetime.now(UTC)
        ts_iso = now.isoformat()
        ts_epoch = now.timestamp()

        entry: dict[str, Any] = {
            "id": row_id,
            "session_id": session_id,
            "timestamp": ts_iso,
            "action_type": decision.action.type,
            "action_target": decision.action.target,
            "action_params": json.dumps(decision.action.params, default=str),
            "action_desc": decision.action.description or None,
            "risk_level": decision.risk_level.name,
            "approval": decision.approval.value,
            "matched_rule": decision.matched_rule,
            "human_decision": human_decision,
            "result_status": result.status.value if result else None,
            "result_data": (
                json.dumps(result.data, default=str) if result and result.data else None
            ),
            "result_error": result.error if result else None,
            "agent_id": decision.action.agent_id or None,
            "parent_agent_id": decision.action.parent_agent_id or None,
            "chain_id": decision.action.chain_id or None,
            "chain_depth": decision.action.chain_depth,
        }

        pipe = self._client.pipeline()
        pipe.hset(_ENTRY_HASH, str(row_id), json.dumps(entry, default=str))
        pipe.zadd(_session_key(session_id), {str(row_id): ts_epoch})
        pipe.execute()

        # Notify in-process subscribers
        if self._subscribers:
            summary: dict[str, Any] = {
                "id": row_id,
                "session_id": session_id,
                "action_type": decision.action.type,
                "action_target": decision.action.target,
                "risk_level": decision.risk_level.name,
                "approval": decision.approval.value,
                "matched_rule": decision.matched_rule,
                "result_status": result.status.value if result else None,
                "agent_id": decision.action.agent_id or None,
            }
            for cb in self._subscribers:
                with contextlib.suppress(Exception):
                    cb(summary)

        # Publish to Redis Pub/Sub for cross-process subscribers
        self._client.publish(_PUBSUB_CHANNEL, json.dumps(entry, default=str))

        return row_id

    def get_log(
        self,
        session_id: str | None = None,
        *,
        action_type: str | None = None,
        risk_level: str | None = None,
        result_status: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int | None = None,
        agent_id: str | None = None,
        chain_id: str | None = None,
    ) -> list[dict[str, object]]:
        """Retrieve audit entries with flexible filtering."""
        entry_ids = self._collect_entry_ids(session_id, since, until)

        if not entry_ids:
            return []

        raw_entries: list[Any] = self._client.hmget(  # type: ignore[assignment]
            _ENTRY_HASH,
            *entry_ids,  # type: ignore[arg-type]
        )
        entries: list[dict[str, object]] = []

        for raw in raw_entries:
            if raw is None:
                continue
            entry: dict[str, object] = json.loads(raw)
            if not self._matches_filters(
                entry,
                action_type=action_type,
                risk_level=risk_level,
                result_status=result_status,
                since=since,
                until=until,
                agent_id=agent_id,
                chain_id=chain_id,
            ):
                continue
            entries.append(entry)

        # Sort by ID for consistent ordering
        entries.sort(key=lambda e: int(str(e.get("id", 0))))

        if limit is not None:
            entries = entries[:limit]

        return entries

    def count(
        self,
        *,
        session_id: str | None = None,
        action_type: str | None = None,
        risk_level: str | None = None,
        result_status: str | None = None,
    ) -> int:
        """Count audit entries matching the given filters."""
        entries = self.get_log(
            session_id=session_id,
            action_type=action_type,
            risk_level=risk_level,
            result_status=result_status,
        )
        return len(entries)

    def subscribe(self, callback: Callable[[dict[str, Any]], Any]) -> None:
        """Register a callback to receive new audit entries."""
        self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[dict[str, Any]], Any]) -> None:
        """Remove a previously registered callback."""
        with contextlib.suppress(ValueError):
            self._subscribers.remove(callback)

    def close(self) -> None:
        """Close the Redis connection and stop Pub/Sub listener."""
        if self._pubsub is not None:
            self._pubsub.unsubscribe()
            self._pubsub.close()
            self._pubsub = None
        if self._pubsub_thread is not None:
            self._pubsub_thread.join(timeout=2.0)
            self._pubsub_thread = None
        self._client.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _collect_entry_ids(
        self,
        session_id: str | None,
        since: datetime | None,
        until: datetime | None,
    ) -> list[str]:
        """Gather entry IDs from Sorted Sets, optionally filtered by time."""
        min_score: float | str = since.timestamp() if since else "-inf"
        max_score: float | str = until.timestamp() if until else "+inf"

        if session_id:
            ids: list[str] = self._client.zrangebyscore(  # type: ignore[assignment]
                _session_key(session_id), min_score, max_score
            )
            return ids

        # No session filter: scan all session keys
        all_ids: list[str] = []
        cursor: int = 0
        while True:
            cursor, keys = self._client.scan(  # type: ignore[misc]
                cursor=cursor, match=_all_sessions_pattern(), count=100
            )
            for key in keys:
                members: list[str] = self._client.zrangebyscore(  # type: ignore[assignment]
                    key, min_score, max_score
                )
                all_ids.extend(members)
            if cursor == 0:
                break

        return all_ids

    @staticmethod
    def _matches_filters(
        entry: dict[str, object],
        *,
        action_type: str | None = None,
        risk_level: str | None = None,
        result_status: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        agent_id: str | None = None,
        chain_id: str | None = None,
    ) -> bool:
        """Return True if *entry* passes all specified filters."""
        if action_type and entry.get("action_type") != action_type:
            return False
        if risk_level and entry.get("risk_level") != risk_level.upper():
            return False
        if result_status and entry.get("result_status") != result_status:
            return False
        if agent_id and entry.get("agent_id") != agent_id:
            return False
        if chain_id and entry.get("chain_id") != chain_id:
            return False

        ts_str = entry.get("timestamp")
        if ts_str and (since or until):
            ts = datetime.fromisoformat(str(ts_str))
            if since and ts < since:
                return False
            if until and ts > until:
                return False

        return True
