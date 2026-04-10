"""Agent-to-Agent (A2A) communication governance.

Applies policy enforcement to inter-agent messages — ensuring agents
can only communicate within their authorized scope, with content
filtering and rate limiting.

Key capabilities:

- **Capability-gated messaging** — Agents must have matching
  capabilities to send messages of specific types.
- **Content filtering** — Scan message payloads for sensitive data
  patterns (PII, credentials, internal paths).
- **Rate limiting** — Per-sender and per-pair rate limits to prevent
  agent communication loops.
- **Trust-gated routing** — Minimum trust level requirements for
  different message types.
- **Full audit log** — Every message attempt is recorded with its
  governance decision.

Usage::

    from aegis.core.a2a_governance import A2AGovernor, A2AMessage
    from aegis.core.agent_identity import AgentIdentity, AgentRegistry

    registry = AgentRegistry()
    # ... register agents ...
    governor = A2AGovernor(registry=registry)

    msg = A2AMessage(
        sender_id="orchestrator",
        receiver_id="worker-1",
        message_type="task_request",
        payload={"action": "read_file", "path": "/tmp/data.csv"},
    )
    decision = governor.evaluate(msg)
    if decision.allowed:
        # deliver the message
        ...
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from aegis.core.agent_identity import AgentRegistry, has_capability

if TYPE_CHECKING:
    from aegis.core.agent_identity import AgentIdentity
    from aegis.core.mas_monitor import MASMonitor, TopologyAnomaly

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class A2AMessage:
    """A message between two agents.

    Attributes:
        sender_id: Agent ID of the sender.
        receiver_id: Agent ID of the receiver.
        message_type: Message category (e.g. ``"task_request"``,
            ``"task_response"``, ``"delegation"``, ``"notification"``).
        payload: Message content (arbitrary dict).
        correlation_id: Optional ID linking request/response pairs.
        timestamp: Unix timestamp (auto-filled if 0).
    """

    sender_id: str
    receiver_id: str
    message_type: str
    payload: dict[str, Any] = field(default_factory=dict)
    correlation_id: str = ""
    timestamp: float = 0.0
    envelope: GovernanceEnvelope | None = None

    def __post_init__(self) -> None:
        if self.timestamp == 0.0:
            object.__setattr__(self, "timestamp", time.time())


@dataclass(frozen=True)
class A2ADecision:
    """Result of evaluating an A2A message.

    Attributes:
        allowed: Whether the message is permitted.
        message: The evaluated message.
        reason: Human-readable explanation.
        filtered_payload: Modified payload (if content was redacted).
            ``None`` if no filtering was applied.
        violations: List of policy violations found.
        topology_anomalies: Immediate topological anomalies (flood,
            ghost) raised by a linked :class:`MASMonitor` when the
            message was recorded. Empty when no monitor is wired.
    """

    allowed: bool
    message: A2AMessage
    reason: str
    filtered_payload: dict[str, Any] | None = None
    violations: list[str] = field(default_factory=list)
    envelope: GovernanceEnvelope | None = None
    topology_anomalies: tuple[TopologyAnomaly, ...] = ()


@dataclass(frozen=True)
class GovernanceEnvelope:
    """Governance metadata attached to A2A messages.

    Analogous to a TLS certificate — carries the sender's governance
    credentials so the receiver can make informed trust decisions.

    Attributes:
        sender_ontology: Sender's constitutional role and domain.
        sender_capabilities: Sender's effective capability set.
        sender_constraints: Summary of sender's constraint names.
        trust_level: Sender's trust level (0–100).
        delegation_depth: Levels of delegation from the root agent.
        policy_version: Version identifier for the sender's active policy.
        timestamp: When the envelope was generated (Unix epoch).
        signature_hash: SHA-256 hash of canonical envelope contents.
    """

    sender_ontology: dict[str, str]
    sender_capabilities: frozenset[str]
    sender_constraints: frozenset[str]
    trust_level: int
    delegation_depth: int
    policy_version: str
    timestamp: float
    signature_hash: str


@dataclass(frozen=True)
class HandshakeResult:
    """Result of a governance handshake between two agents.

    Attributes:
        compatible: Whether the two agents' constitutions are compatible.
        reasons: List of compatibility/incompatibility reasons.
        negotiated_capabilities: Capabilities both agents share.
    """

    compatible: bool
    reasons: list[str] = field(default_factory=list)
    negotiated_capabilities: frozenset[str] = frozenset()


@dataclass
class A2ALogEntry:
    """Audit log entry for an A2A governance decision.

    Attributes:
        timestamp: When the decision was made.
        sender_id: Sender agent.
        receiver_id: Receiver agent.
        message_type: Message type.
        allowed: Whether the message was allowed.
        reason: Decision reason.
        violations: Policy violations found.
        has_envelope: Whether a governance envelope was attached.
    """

    timestamp: float
    sender_id: str
    receiver_id: str
    message_type: str
    allowed: bool
    reason: str
    violations: list[str] = field(default_factory=list)
    has_envelope: bool = False


# ---------------------------------------------------------------------------
# Content filtering
# ---------------------------------------------------------------------------

# Patterns that should be redacted from inter-agent messages
_SENSITIVE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "api_key",
        re.compile(
            r"(?:api[_-]?key|apikey|api[_-]?token)\s*[:=]\s*\S+",
            re.IGNORECASE,
        ),
    ),
    (
        "password",
        re.compile(
            r"(?:password|passwd|secret)\s*[:=]\s*\S+",
            re.IGNORECASE,
        ),
    ),
    (
        "bearer_token",
        re.compile(
            r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
        ),
    ),
    (
        "aws_key",
        re.compile(
            r"(?:AKIA|ASIA)[A-Z0-9]{16}",
        ),
    ),
    (
        "private_key",
        re.compile(
            r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
        ),
    ),
    (
        "email_address",
        re.compile(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        ),
    ),
    (
        "ssn",
        re.compile(
            r"\b\d{3}-\d{2}-\d{4}\b",
        ),
    ),
    (
        "credit_card",
        re.compile(
            r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))\d{8,12}\b",
        ),
    ),
    (
        "internal_path",
        re.compile(
            r"(?:/etc/(?:passwd|shadow|hosts)|/proc/|\.ssh/|\.aws/|\.env\b)",
        ),
    ),
]


def _flatten_payload(payload: dict[str, Any], depth: int = 0) -> str:
    """Flatten a payload dict to a single string for scanning."""
    if depth > 10:
        return ""
    parts: list[str] = []
    for v in payload.values():
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, dict):
            parts.append(_flatten_payload(v, depth + 1))
        elif isinstance(v, list | tuple):
            for item in v:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    parts.append(_flatten_payload(item, depth + 1))
    return " ".join(parts)


def scan_content(payload: dict[str, Any]) -> list[tuple[str, str]]:
    """Scan payload for sensitive content patterns.

    Returns list of (pattern_name, matched_text) tuples.
    """
    text = _flatten_payload(payload)
    findings: list[tuple[str, str]] = []
    for name, pattern in _SENSITIVE_PATTERNS:
        match = pattern.search(text)
        if match:
            findings.append((name, match.group(0)[:50]))
    return findings


def redact_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of payload with sensitive content redacted."""
    result: dict[str, Any] = _redact_recursive(payload, depth=0)
    return result


def _redact_recursive(obj: Any, depth: int) -> Any:
    """Recursively redact sensitive patterns in strings."""
    if depth > 10:
        return obj
    if isinstance(obj, str):
        result = obj
        for _name, pattern in _SENSITIVE_PATTERNS:
            result = pattern.sub("[REDACTED]", result)
        return result
    if isinstance(obj, dict):
        return {k: _redact_recursive(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_recursive(v, depth + 1) for v in obj]
    return obj


# ---------------------------------------------------------------------------
# Rate limiting (per-sender + per-pair)
# ---------------------------------------------------------------------------


class _RateWindow:
    """Sliding window rate counter."""

    def __init__(self, max_count: int, window_seconds: float) -> None:
        self.max_count = max_count
        self.window_seconds = window_seconds
        self._timestamps: list[float] = []

    def check_and_record(self, now: float | None = None) -> bool:
        """Return True if under limit, and record the event."""
        now = now or time.time()
        cutoff = now - self.window_seconds
        self._timestamps = [t for t in self._timestamps if t > cutoff]
        if len(self._timestamps) >= self.max_count:
            return False
        self._timestamps.append(now)
        return True

    @property
    def current_count(self) -> int:
        now = time.time()
        cutoff = now - self.window_seconds
        return sum(1 for t in self._timestamps if t > cutoff)


# ---------------------------------------------------------------------------
# Governance envelope builder
# ---------------------------------------------------------------------------


def _build_envelope(
    sender: AgentIdentity,
    registry: AgentRegistry,
    *,
    policy_version: str = "",
) -> GovernanceEnvelope:
    """Build a :class:`GovernanceEnvelope` from the sender's identity."""
    ontology: dict[str, str] = {"role": "", "domain": ""}
    constraints: frozenset[str] = frozenset()
    if sender.constitution is not None:
        ontology = {
            "role": sender.constitution.ontology.role,
            "domain": sender.constitution.ontology.domain,
        }
        constraints = frozenset(c.name for c in sender.constitution.constraints)

    try:
        chain = registry.get_trust_chain(sender.agent_id)
        delegation_depth = len(chain) - 1
    except (KeyError, RuntimeError):
        delegation_depth = 0

    now = time.time()
    canonical = (
        f"{sender.agent_id}\0"
        f"{ontology['role']}\0{ontology['domain']}\0"
        f"{','.join(sorted(sender.capabilities))}\0"
        f"{','.join(sorted(constraints))}\0"
        f"{sender.trust_level}\0"
        f"{delegation_depth}\0"
        f"{policy_version}\0"
        f"{now}"
    )
    sig = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    return GovernanceEnvelope(
        sender_ontology=ontology,
        sender_capabilities=sender.capabilities,
        sender_constraints=constraints,
        trust_level=sender.trust_level,
        delegation_depth=delegation_depth,
        policy_version=policy_version,
        timestamp=now,
        signature_hash=sig,
    )


# ---------------------------------------------------------------------------
# Governance handshake
# ---------------------------------------------------------------------------


class GovernanceHandshake:
    """Verify constitutional compatibility between two agents.

    Analogous to TLS negotiation — if constitutions conflict, the
    handshake fails and communication is blocked.

    Args:
        registry: Agent registry for identity/capability lookups.
        require_domain_match: If True, agents must share the same domain
            (or one must have no domain set).
        min_capability_overlap: Minimum overlapping capabilities required.
        min_trust_level: Minimum trust level for either party.
    """

    def __init__(
        self,
        registry: AgentRegistry,
        *,
        require_domain_match: bool = False,
        min_capability_overlap: int = 0,
        min_trust_level: int = 0,
    ) -> None:
        self._registry = registry
        self._require_domain_match = require_domain_match
        self._min_capability_overlap = min_capability_overlap
        self._min_trust_level = min_trust_level

    def negotiate(
        self,
        sender_id: str,
        receiver_id: str,
        *,
        message_type: str = "",
    ) -> HandshakeResult:
        """Negotiate governance compatibility between sender and receiver.

        Checks (in order):
        1. Both agents registered and retrievable.
        2. Domain compatibility (when ``require_domain_match`` is set).
        3. Capability overlap meets minimum.
        4. No constraint conflicts (forbidden targets/patterns).
        5. Trust level meets minimum for both parties.
        """
        reasons: list[str] = []
        compatible = True

        sender = self._registry.get(sender_id)
        receiver = self._registry.get(receiver_id)

        if sender is None:
            return HandshakeResult(compatible=False, reasons=["Sender not registered"])
        if receiver is None:
            return HandshakeResult(compatible=False, reasons=["Receiver not registered"])

        sender_const = sender.constitution
        receiver_const = receiver.constitution

        # 1. Domain compatibility
        if self._require_domain_match:
            s_domain = sender_const.ontology.domain if sender_const else ""
            r_domain = receiver_const.ontology.domain if receiver_const else ""
            if s_domain and r_domain and s_domain != r_domain:
                compatible = False
                reasons.append(f"Domain mismatch: sender='{s_domain}', receiver='{r_domain}'")

        # 2. Capability overlap (fnmatch-based)
        effective_overlap: set[str] = set(sender.capabilities & receiver.capabilities)
        for s_cap in sender.capabilities:
            for r_cap in receiver.capabilities:
                if fnmatch.fnmatch(s_cap, r_cap) or fnmatch.fnmatch(r_cap, s_cap):
                    effective_overlap.add(s_cap)
                    effective_overlap.add(r_cap)

        if len(effective_overlap) < self._min_capability_overlap:
            compatible = False
            reasons.append(
                f"Insufficient capability overlap: {len(effective_overlap)} "
                f"< required {self._min_capability_overlap}"
            )

        # 3. Constraint conflicts
        if sender_const:
            for constraint in sender_const.constraints:
                r_domain = receiver_const.ontology.domain if receiver_const else ""
                if r_domain:
                    for pattern in constraint.forbidden_targets:
                        if fnmatch.fnmatch(r_domain, pattern):
                            compatible = False
                            reasons.append(
                                f"Sender constraint '{constraint.name}' "
                                f"forbids target domain '{r_domain}'"
                            )
                if message_type:
                    for pattern in constraint.forbidden_patterns:
                        if fnmatch.fnmatch(message_type, pattern):
                            compatible = False
                            reasons.append(
                                f"Sender constraint '{constraint.name}' "
                                f"forbids message type '{message_type}'"
                            )

        if receiver_const:
            for constraint in receiver_const.constraints:
                if message_type:
                    for pattern in constraint.forbidden_patterns:
                        if fnmatch.fnmatch(message_type, pattern):
                            compatible = False
                            reasons.append(
                                f"Receiver constraint '{constraint.name}' "
                                f"forbids message type '{message_type}'"
                            )

        # 4. Trust level
        if sender.trust_level < self._min_trust_level:
            compatible = False
            reasons.append(f"Sender trust {sender.trust_level} < minimum {self._min_trust_level}")
        if receiver.trust_level < self._min_trust_level:
            compatible = False
            reasons.append(
                f"Receiver trust {receiver.trust_level} < minimum {self._min_trust_level}"
            )

        return HandshakeResult(
            compatible=compatible,
            reasons=reasons,
            negotiated_capabilities=frozenset(effective_overlap) if compatible else frozenset(),
        )


# ---------------------------------------------------------------------------
# A2A Governor
# ---------------------------------------------------------------------------

# Default capability requirements for message types
_DEFAULT_CAPABILITY_MAP: dict[str, str] = {
    "task_request": "a2a_send_task",
    "task_response": "a2a_respond_task",
    "delegation": "a2a_delegate",
    "notification": "a2a_notify",
    "data_share": "a2a_share_data",
}


class A2AGovernor:
    """Governance gate for agent-to-agent communication.

    Evaluates messages against:
    1. Agent registration (both sender and receiver must exist)
    2. Capability requirements (sender must have appropriate capability)
    3. Trust level requirements (sender must meet minimum trust)
    4. Content filtering (scan for sensitive data)
    5. Rate limiting (per-sender and per-pair)

    When a :class:`MASMonitor` is supplied, allowed messages are also
    recorded on the monitor so that topology-level anomalies (flood,
    domination, clique, isolation) are detected in the same pass. Any
    immediate anomalies from ``record_message()`` are attached to the
    returned :class:`A2ADecision` as ``topology_anomalies``.

    Args:
        registry: Agent registry for identity/capability lookups.
        capability_map: Message type → required capability mapping.
        min_trust_level: Minimum sender trust level for all messages.
        content_filter: Whether to scan/redact sensitive content.
        rate_limit_per_sender: Max messages per sender per window.
        rate_limit_per_pair: Max messages per sender-receiver pair.
        rate_window_seconds: Rate limit window duration.
        block_on_sensitive: If True, block messages with sensitive
            content. If False, redact and allow.
        mas_monitor: Optional :class:`MASMonitor` to receive allowed
            messages. Pairs A2A governance with topology anomaly
            detection (arXiv:2510.19420).
        topology_block_severities: Topology anomaly severities that, if
            observed in ``record_message()``, escalate the governed
            decision to ``blocked``. Default ``frozenset({"high"})`` —
            i.e. flood and ghost.
    """

    def __init__(
        self,
        registry: AgentRegistry,
        *,
        capability_map: dict[str, str] | None = None,
        min_trust_level: int = 0,
        content_filter: bool = True,
        rate_limit_per_sender: int = 100,
        rate_limit_per_pair: int = 50,
        rate_window_seconds: float = 60.0,
        block_on_sensitive: bool = False,
        attach_envelope: bool = False,
        policy_version: str = "",
        handshake: GovernanceHandshake | None = None,
        mas_monitor: MASMonitor | None = None,
        topology_block_severities: frozenset[str] = frozenset({"high"}),
    ) -> None:
        self._registry = registry
        self._capability_map = capability_map or dict(_DEFAULT_CAPABILITY_MAP)
        self._min_trust = min_trust_level
        self._content_filter = content_filter
        self._block_on_sensitive = block_on_sensitive
        self._rate_per_sender = rate_limit_per_sender
        self._rate_per_pair = rate_limit_per_pair
        self._rate_window = rate_window_seconds
        self._attach_envelope = attach_envelope
        self._policy_version = policy_version
        self._handshake = handshake
        self._mas_monitor = mas_monitor
        self._topology_block_severities = topology_block_severities
        self._sender_windows: dict[str, _RateWindow] = {}
        self._pair_windows: dict[str, _RateWindow] = {}
        self._log: list[A2ALogEntry] = []
        self._lock = threading.RLock()

    def evaluate(self, message: A2AMessage) -> A2ADecision:
        """Evaluate an A2A message against all governance rules.

        Returns an :class:`A2ADecision` with allow/block and details.
        """
        violations: list[str] = []

        # 1. Check sender exists
        sender = self._registry.get(message.sender_id)
        if sender is None:
            return self._decide(message, False, "Sender not registered", ["unknown_sender"])

        # 2. Check receiver exists
        receiver = self._registry.get(message.receiver_id)
        if receiver is None:
            return self._decide(message, False, "Receiver not registered", ["unknown_receiver"])

        # 3. Self-messaging blocked
        if message.sender_id == message.receiver_id:
            return self._decide(
                message,
                False,
                "Self-messaging not allowed",
                ["self_message"],
            )

        # 3.5 Optional governance handshake
        if self._handshake is not None:
            hs_result = self._handshake.negotiate(
                message.sender_id,
                message.receiver_id,
                message_type=message.message_type,
            )
            if not hs_result.compatible:
                return self._decide(
                    message,
                    False,
                    f"Governance handshake failed: {'; '.join(hs_result.reasons)}",
                    ["handshake_failed"],
                )

        # 4. Capability check
        required_cap = self._capability_map.get(message.message_type)
        if required_cap and not has_capability(sender.capabilities, required_cap):
            violations.append(f"missing_capability:{required_cap}")

        # 5. Trust level check
        if sender.trust_level < self._min_trust:
            violations.append(f"insufficient_trust:{sender.trust_level}<{self._min_trust}")

        # 6. If hard violations, block immediately
        if violations:
            return self._decide(
                message,
                False,
                f"Policy violations: {', '.join(violations)}",
                violations,
            )

        # 7. Rate limiting
        with self._lock:
            sender_key = message.sender_id
            if sender_key not in self._sender_windows:
                self._sender_windows[sender_key] = _RateWindow(
                    self._rate_per_sender, self._rate_window
                )
            if not self._sender_windows[sender_key].check_and_record(message.timestamp):
                return self._decide(
                    message,
                    False,
                    f"Rate limit exceeded for sender {message.sender_id}",
                    ["rate_limit_sender"],
                )

            pair_key = f"{message.sender_id}->{message.receiver_id}"
            if pair_key not in self._pair_windows:
                self._pair_windows[pair_key] = _RateWindow(self._rate_per_pair, self._rate_window)
            if not self._pair_windows[pair_key].check_and_record(message.timestamp):
                return self._decide(
                    message,
                    False,
                    f"Rate limit exceeded for pair {pair_key}",
                    ["rate_limit_pair"],
                )

        # 8. Content filtering
        filtered_payload: dict[str, Any] | None = None
        if self._content_filter and message.payload:
            findings = scan_content(message.payload)
            if findings:
                pattern_names = [name for name, _text in findings]
                if self._block_on_sensitive:
                    return self._decide(
                        message,
                        False,
                        f"Sensitive content detected: {', '.join(pattern_names)}",
                        [f"sensitive_content:{n}" for n in pattern_names],
                    )
                # Redact and allow
                filtered_payload = redact_payload(message.payload)
                violations_info = [f"redacted:{n}" for n in pattern_names]
                envelope = self._maybe_build_envelope(sender)
                return self._decide(
                    message,
                    True,
                    f"Allowed with redaction: {', '.join(pattern_names)}",
                    violations_info,
                    filtered_payload=filtered_payload,
                    envelope=envelope,
                )

        envelope = self._maybe_build_envelope(sender)
        return self._decide(message, True, "Allowed", envelope=envelope)

    def _maybe_build_envelope(
        self,
        sender: AgentIdentity | None,
    ) -> GovernanceEnvelope | None:
        """Build envelope if enabled and sender is known."""
        if not self._attach_envelope or sender is None:
            return None
        return _build_envelope(sender, self._registry, policy_version=self._policy_version)

    def _decide(
        self,
        message: A2AMessage,
        allowed: bool,
        reason: str,
        violations: list[str] | None = None,
        *,
        filtered_payload: dict[str, Any] | None = None,
        envelope: GovernanceEnvelope | None = None,
    ) -> A2ADecision:
        """Create a decision, log it, and optionally feed MASMonitor.

        When the decision is allowed and a :class:`MASMonitor` is
        attached, the message is recorded in the topology graph. Any
        immediate topology anomaly with a severity in
        ``self._topology_block_severities`` (default: ``{"high"}``)
        downgrades the decision to ``blocked`` and appends the reason to
        the violation list. This is the integration point the docs
        advertise as "A2A + topology anomaly detection wired by default"
        (arXiv:2510.19420).
        """
        violations = violations or []

        topology_anomalies: tuple[TopologyAnomaly, ...] = ()
        if allowed and self._mas_monitor is not None:
            anomalies = self._mas_monitor.record_message(
                source_id=message.sender_id,
                target_id=message.receiver_id,
                message_type=message.message_type,
                timestamp=message.timestamp,
            )
            if anomalies:
                topology_anomalies = tuple(anomalies)
                severe = [a for a in anomalies if a.severity in self._topology_block_severities]
                if severe:
                    allowed = False
                    severe_types = ", ".join(a.anomaly_type for a in severe)
                    reason = f"Topology anomaly: {severe_types}"
                    violations = list(violations) + [
                        f"topology_anomaly:{a.anomaly_type}" for a in severe
                    ]

        decision = A2ADecision(
            allowed=allowed,
            message=message,
            reason=reason,
            filtered_payload=filtered_payload,
            violations=violations,
            envelope=envelope,
            topology_anomalies=topology_anomalies,
        )
        entry = A2ALogEntry(
            timestamp=time.time(),
            sender_id=message.sender_id,
            receiver_id=message.receiver_id,
            message_type=message.message_type,
            allowed=allowed,
            reason=reason,
            violations=violations,
            has_envelope=envelope is not None,
        )
        with self._lock:
            self._log.append(entry)
        return decision

    @property
    def audit_log(self) -> list[A2ALogEntry]:
        """Return a snapshot of the audit log."""
        with self._lock:
            return list(self._log)

    def format_audit_log(self) -> str:
        """Format the audit log as human-readable text."""
        with self._lock:
            entries = list(self._log)

        if not entries:
            return "A2A Audit Log: No entries."

        lines: list[str] = []
        lines.append("A2A Communication Audit Log")
        lines.append("=" * 40)
        lines.append(f"Total messages: {len(entries)}")

        allowed = sum(1 for e in entries if e.allowed)
        blocked = len(entries) - allowed
        lines.append(f"Allowed: {allowed} | Blocked: {blocked}")
        lines.append("")

        for entry in entries:
            status = "ALLOW" if entry.allowed else "BLOCK"
            lines.append(
                f"  [{status}] {entry.sender_id} -> {entry.receiver_id} ({entry.message_type})"
            )
            lines.append(f"    Reason: {entry.reason}")
            if entry.violations:
                lines.append(f"    Violations: {', '.join(entry.violations)}")
            lines.append("")

        return "\n".join(lines)
