"""MCP consent protocol — human-in-the-loop for high-risk tool calls.

Structured consent flow for MCP tool calls that are too dangerous to
auto-approve: deletions, outbound messaging, financial operations,
code execution, system configuration changes, etc.

Components:
    - ConsentRequest: Immutable record of what needs approval
    - ConsentDecision: Immutable record of the human's decision
    - ConsentRule: Declarative rule for when consent is required
    - ConsentCallback: Protocol for pluggable consent handlers
    - AutoDenyHandler: Default handler that denies everything (safety)
    - CallbackConsentHandler: Delegates to a user-provided async callback
    - MCPConsentManager: Orchestrates rule matching, consent flow, audit

Example::

    manager = MCPConsentManager()
    decision = await manager.check_consent(
        tool_name="delete_table",
        server_name="postgres",
        arguments={"table": "users"},
        risk_level="critical",
    )
    if not decision.approved:
        # Block the tool call
        ...
"""

from __future__ import annotations

import asyncio
import fnmatch
import threading
import time
import uuid
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# Risk level ordering
# ---------------------------------------------------------------------------

_RISK_ORDER: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


def _risk_ge(level: str, threshold: str) -> bool:
    """Return True if *level* >= *threshold* in severity ordering."""
    return _RISK_ORDER.get(level, 0) >= _RISK_ORDER.get(threshold, 0)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConsentRequest:
    """A request for human consent on a tool call."""

    request_id: str
    tool_name: str
    server_name: str
    arguments: dict[str, Any]
    risk_level: str  # "low", "medium", "high", "critical"
    reason: str  # why consent is needed
    created_at: float
    timeout_seconds: float
    context: dict[str, Any]  # additional context (escalation findings, scan results, ...)


@dataclass(frozen=True)
class ConsentDecision:
    """The human's decision on a consent request."""

    request_id: str
    approved: bool
    decided_by: str  # identifier of the human
    decided_at: float
    reason: str  # optional reason for the decision
    conditions: dict[str, Any]  # optional conditions ("only once", "for this session", ...)


@dataclass
class ConsentRule:
    """Rule defining when consent is required.

    Both *tool_pattern* and *server_pattern* support ``|``-separated
    glob alternatives (e.g. ``"*delete*|*remove*|*drop*"``).
    """

    name: str
    tool_pattern: str  # glob pattern(s) for tool names
    server_pattern: str  # glob pattern(s) for server names
    min_risk_level: str  # minimum risk level to trigger consent
    reason_template: str  # template for the consent reason
    timeout_seconds: float = 30.0
    auto_deny: bool = True  # deny on timeout (vs auto-approve)


# ---------------------------------------------------------------------------
# Consent handlers (Protocol + implementations)
# ---------------------------------------------------------------------------


@runtime_checkable
class ConsentCallback(Protocol):
    """Protocol for consent handlers."""

    async def request_consent(self, request: ConsentRequest) -> ConsentDecision: ...


class AutoDenyHandler:
    """Default handler that auto-denies everything (for testing/safety)."""

    async def request_consent(self, request: ConsentRequest) -> ConsentDecision:
        return ConsentDecision(
            request_id=request.request_id,
            approved=False,
            decided_by="auto_deny",
            decided_at=time.time(),
            reason="Auto-denied by default safety handler",
            conditions={},
        )


class CallbackConsentHandler:
    """Handler that delegates to a user-provided async callback."""

    def __init__(
        self,
        callback: Callable[[ConsentRequest], Awaitable[ConsentDecision]],
    ) -> None:
        self._callback = callback

    async def request_consent(self, request: ConsentRequest) -> ConsentDecision:
        return await self._callback(request)


# ---------------------------------------------------------------------------
# Pattern matching helpers
# ---------------------------------------------------------------------------


def _matches_pattern(value: str, pattern: str) -> bool:
    """Check *value* against a ``|``-separated glob pattern string.

    Returns True if any alternative matches (case-insensitive).
    """
    value_lower = value.lower()
    for alt in pattern.split("|"):
        alt = alt.strip()
        if alt and fnmatch.fnmatch(value_lower, alt.lower()):
            return True
    return False


# ---------------------------------------------------------------------------
# MCPConsentManager
# ---------------------------------------------------------------------------


class MCPConsentManager:
    """Manages consent flow for MCP tool calls.

    Evaluates tool calls against consent rules, creates consent requests,
    delegates to the consent handler, and records all decisions for audit.
    """

    def __init__(
        self,
        *,
        rules: list[ConsentRule] | None = None,
        handler: ConsentCallback | None = None,
        history_size: int = 1000,
    ) -> None:
        self._rules: list[ConsentRule] = rules if rules is not None else self.builtin_rules()
        self._handler: ConsentCallback = handler or AutoDenyHandler()
        self._history: deque[ConsentDecision] = deque(maxlen=history_size)
        self._lock = threading.Lock()

    # -- public API ---------------------------------------------------------

    async def check_consent(
        self,
        tool_name: str,
        server_name: str,
        arguments: dict[str, Any],
        *,
        risk_level: str = "medium",
        context: dict[str, Any] | None = None,
    ) -> ConsentDecision:
        """Check if consent is needed and obtain it if so.

        If no rule matches, returns an auto-approved decision.
        If a rule matches, creates a :class:`ConsentRequest` and delegates
        to the configured handler.  Timeout produces an auto-deny (or
        auto-approve, depending on the rule's ``auto_deny`` flag).
        """
        rule = self.needs_consent(tool_name, server_name, risk_level=risk_level)

        if rule is None:
            # No consent required — auto-approve.
            decision = ConsentDecision(
                request_id=uuid.uuid4().hex,
                approved=True,
                decided_by="system",
                decided_at=time.time(),
                reason="No consent rule matched — auto-approved",
                conditions={},
            )
            self._record(decision)
            return decision

        # Build the consent request.
        request = ConsentRequest(
            request_id=uuid.uuid4().hex,
            tool_name=tool_name,
            server_name=server_name,
            arguments=arguments,
            risk_level=risk_level,
            reason=rule.reason_template.format(
                tool=tool_name,
                server=server_name,
            ),
            created_at=time.time(),
            timeout_seconds=rule.timeout_seconds,
            context=context or {},
        )

        # Delegate to handler with timeout.
        try:
            decision = await asyncio.wait_for(
                self._handler.request_consent(request),
                timeout=rule.timeout_seconds,
            )
        except (TimeoutError, Exception):
            # Timeout or handler failure → safe default.
            decision = ConsentDecision(
                request_id=request.request_id,
                approved=not rule.auto_deny,
                decided_by="timeout",
                decided_at=time.time(),
                reason="Consent timed out — applied default policy",
                conditions={},
            )

        self._record(decision)
        return decision

    def needs_consent(
        self,
        tool_name: str,
        server_name: str,
        *,
        risk_level: str = "medium",
    ) -> ConsentRule | None:
        """Check if a tool call requires consent.

        Returns the first matching rule, or ``None`` if no rule applies.
        """
        for rule in self._rules:
            if not _matches_pattern(tool_name, rule.tool_pattern):
                continue
            if not _matches_pattern(server_name, rule.server_pattern):
                continue
            if not _risk_ge(risk_level, rule.min_risk_level):
                continue
            return rule
        return None

    def get_history(self, *, limit: int = 100) -> list[ConsentDecision]:
        """Get recent consent decisions (newest first)."""
        with self._lock:
            items = list(self._history)
        # Newest first.
        items.reverse()
        return items[:limit]

    # -- built-in rules -----------------------------------------------------

    @staticmethod
    def builtin_rules() -> list[ConsentRule]:
        """Default consent rules covering common high-risk operations."""
        return [
            ConsentRule(
                name="delete_operations",
                tool_pattern="*delete*|*remove*|*drop*",
                server_pattern="*",
                min_risk_level="medium",
                reason_template="Destructive operation: {tool} on {server} requires human consent",
                timeout_seconds=30.0,
                auto_deny=True,
            ),
            ConsentRule(
                name="send_messages",
                tool_pattern="*send*|*post*|*publish*",
                server_pattern="*slack*|*email*|*discord*|*telegram*",
                min_risk_level="low",
                reason_template="Outbound message: {tool} via {server} requires human consent",
                timeout_seconds=30.0,
                auto_deny=True,
            ),
            ConsentRule(
                name="financial",
                tool_pattern="*pay*|*transfer*|*charge*",
                server_pattern="*",
                min_risk_level="low",
                reason_template="Financial operation: {tool} on {server} requires human consent",
                timeout_seconds=60.0,
                auto_deny=True,
            ),
            ConsentRule(
                name="code_execution",
                tool_pattern="*execute*|*eval*|*run*",
                server_pattern="*",
                min_risk_level="medium",
                reason_template="Code execution: {tool} on {server} requires human consent",
                timeout_seconds=30.0,
                auto_deny=True,
            ),
            ConsentRule(
                name="system_config",
                tool_pattern="*config*|*setting*|*permission*",
                server_pattern="*",
                min_risk_level="medium",
                reason_template="System configuration: {tool} on {server} requires human consent",
                timeout_seconds=30.0,
                auto_deny=True,
            ),
            ConsentRule(
                name="write_operations",
                tool_pattern="*write*|*update*|*modify*",
                server_pattern="*",
                min_risk_level="high",
                reason_template="Write operation: {tool} on {server} requires human consent",
                timeout_seconds=30.0,
                auto_deny=True,
            ),
            ConsentRule(
                name="bulk_operations",
                tool_pattern="*bulk*|*batch*|*all*",
                server_pattern="*",
                min_risk_level="medium",
                reason_template="Bulk operation: {tool} on {server} requires human consent",
                timeout_seconds=30.0,
                auto_deny=True,
            ),
            ConsentRule(
                name="external_api",
                tool_pattern="*fetch*|*request*|*curl*",
                server_pattern="*",
                min_risk_level="high",
                reason_template="External API call: {tool} on {server} requires human consent",
                timeout_seconds=30.0,
                auto_deny=True,
            ),
        ]

    # -- internal -----------------------------------------------------------

    def _record(self, decision: ConsentDecision) -> None:
        """Thread-safe history recording."""
        with self._lock:
            self._history.append(decision)
