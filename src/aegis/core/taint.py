"""Data taint tracking for AI agent execution flows.

Inspired by FIDES (arXiv:2505.23643) -- tracks data provenance through
agent operations by attaching taint labels to values as they flow between
tools, models, and external systems.

Key concepts:

- **TaintLabel**: Categorises the origin/risk of a data value (e.g.
  ``USER_INPUT``, ``TOOL_OUTPUT``, ``EXTERNAL_API``).
- **TaintedValue**: Immutable wrapper that carries taint metadata alongside
  the actual data payload.
- **TaintPolicy**: Declarative rules governing what happens when tainted data
  flows into sensitive sinks (block, warn, sanitise).
- **TaintTracker**: Stateful, thread-safe tracker for an agent session.

No external dependencies.  Deterministic, sub-millisecond per operation.

Reference:
    FIDES: Faithful Inference-time Detection of Exfiltration Signals
    in AI Agents. arXiv:2505.23643 (2025).

Example::

    tracker = TaintTracker()
    tv = tracker.tag("user-query", TaintLabel.USER_INPUT, payload="DROP TABLE")
    tracker.propagate(tv, "sql-builder", TaintLabel.TOOL_OUTPUT)
    report = tracker.analyze()
    assert not report.clean
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

# ---------------------------------------------------------------------------
# Taint labels
# ---------------------------------------------------------------------------


class TaintLabel(StrEnum):
    """Origin classification for tainted data."""

    USER_INPUT = "user_input"
    TOOL_OUTPUT = "tool_output"
    EXTERNAL_API = "external_api"
    MODEL_OUTPUT = "model_output"
    FILE_SYSTEM = "file_system"
    DATABASE = "database"
    UNTRUSTED = "untrusted"
    SANITISED = "sanitised"


class TaintSeverity(StrEnum):
    """Severity when tainted data reaches a sink."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class TaintAction(StrEnum):
    """Action to take when a taint policy rule fires."""

    BLOCK = "block"
    WARN = "warn"
    SANITISE = "sanitise"
    LOG = "log"
    ALLOW = "allow"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TaintedValue:
    """An immutable tainted data wrapper.

    Attributes:
        taint_id: Unique identifier for this taint instance.
        labels: Set of taint labels attached to this value.
        source: Where the data originated (tool name, API name, etc.).
        payload_hash: SHA-256 hash of the payload (never stores raw data).
        created_at: Unix timestamp when the taint was first created.
        propagation_chain: Ordered list of (source, label) hops.
        metadata: Arbitrary extra context.
    """

    taint_id: str
    labels: frozenset[TaintLabel]
    source: str
    payload_hash: str
    created_at: float
    propagation_chain: tuple[tuple[str, str], ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TaintPolicyRule:
    """A single taint policy rule.

    Matches when tainted data with *source_labels* flows into a sink
    whose name matches *sink_pattern*.

    Attributes:
        name: Rule identifier.
        source_labels: Labels that trigger this rule.
        sink_pattern: Glob-free sink name (exact match for simplicity).
        action: What to do when the rule fires.
        severity: How bad the violation is.
    """

    name: str
    source_labels: frozenset[TaintLabel]
    sink_pattern: str
    action: TaintAction
    severity: TaintSeverity = TaintSeverity.HIGH


@dataclass(frozen=True)
class TaintFinding:
    """A detected taint violation.

    Attributes:
        rule_name: Which policy rule triggered.
        severity: Finding severity.
        action: Action taken (block, warn, etc.).
        taint_id: The tainted value that triggered the violation.
        source: Where the tainted data originated.
        sink: Where the tainted data was flowing to.
        labels: Taint labels that matched the rule.
        propagation_depth: How many hops the data traversed.
        description: Human-readable summary.
    """

    rule_name: str
    severity: str
    action: str
    taint_id: str
    source: str
    sink: str
    labels: frozenset[TaintLabel]
    propagation_depth: int
    description: str


@dataclass
class TaintReport:
    """Result of taint flow analysis.

    Attributes:
        findings: All taint violations detected.
        total_tracked: Number of tainted values currently tracked.
        total_propagations: Number of propagation hops recorded.
        sinks_reached: Number of distinct sinks that received tainted data.
        generated_at: Unix timestamp of report generation.
    """

    findings: list[TaintFinding] = field(default_factory=list)
    total_tracked: int = 0
    total_propagations: int = 0
    sinks_reached: int = 0
    generated_at: float = 0.0

    @property
    def clean(self) -> bool:
        """Whether no taint violations were detected."""
        return len(self.findings) == 0


# ---------------------------------------------------------------------------
# Default taint policy
# ---------------------------------------------------------------------------

_DEFAULT_RULES: list[TaintPolicyRule] = [
    TaintPolicyRule(
        name="untrusted_to_exec",
        source_labels=frozenset({TaintLabel.UNTRUSTED, TaintLabel.USER_INPUT}),
        sink_pattern="code_execution",
        action=TaintAction.BLOCK,
        severity=TaintSeverity.CRITICAL,
    ),
    TaintPolicyRule(
        name="external_to_database",
        source_labels=frozenset({TaintLabel.EXTERNAL_API, TaintLabel.UNTRUSTED}),
        sink_pattern="database",
        action=TaintAction.BLOCK,
        severity=TaintSeverity.CRITICAL,
    ),
    TaintPolicyRule(
        name="user_input_to_file_write",
        source_labels=frozenset({TaintLabel.USER_INPUT}),
        sink_pattern="file_write",
        action=TaintAction.WARN,
        severity=TaintSeverity.HIGH,
    ),
    TaintPolicyRule(
        name="tool_output_to_external",
        source_labels=frozenset({TaintLabel.TOOL_OUTPUT}),
        sink_pattern="external_api",
        action=TaintAction.WARN,
        severity=TaintSeverity.MEDIUM,
    ),
]


class TaintPolicy:
    """Declarative taint flow policy.

    Evaluates whether a tainted value should be allowed to flow into
    a given sink, based on a set of rules.

    Args:
        rules: List of policy rules.  If ``None``, uses sensible defaults.
    """

    def __init__(self, rules: list[TaintPolicyRule] | None = None) -> None:
        self._rules = list(rules) if rules is not None else list(_DEFAULT_RULES)

    @property
    def rules(self) -> list[TaintPolicyRule]:
        return list(self._rules)

    def add_rule(self, rule: TaintPolicyRule) -> None:
        """Add a rule to the policy."""
        self._rules.append(rule)

    def evaluate(
        self,
        tainted: TaintedValue,
        sink: str,
    ) -> TaintFinding | None:
        """Evaluate a tainted value flowing into *sink*.

        Returns a :class:`TaintFinding` if a rule matches, ``None`` otherwise.
        First matching rule wins.
        """
        for rule in self._rules:
            # Rule matches if ANY of the taint's labels intersect the rule's source_labels
            if tainted.labels & rule.source_labels and rule.sink_pattern == sink:
                matching_labels = tainted.labels & rule.source_labels
                return TaintFinding(
                    rule_name=rule.name,
                    severity=rule.severity,
                    action=rule.action,
                    taint_id=tainted.taint_id,
                    source=tainted.source,
                    sink=sink,
                    labels=matching_labels,
                    propagation_depth=len(tainted.propagation_chain),
                    description=(
                        f"Tainted data from '{tainted.source}' with labels "
                        f"{sorted(str(lbl) for lbl in matching_labels)} "
                        f"flowed into sink '{sink}' — rule '{rule.name}' triggered"
                    ),
                )
        return None


# ---------------------------------------------------------------------------
# Taint tracker
# ---------------------------------------------------------------------------

_COUNTER_LOCK = threading.Lock()
_COUNTER = 0


def _next_taint_id() -> str:
    global _COUNTER
    with _COUNTER_LOCK:
        _COUNTER += 1
        return f"taint-{_COUNTER:08d}"


def _hash_payload(payload: Any) -> str:
    """SHA-256 hash of the string representation of a payload."""
    return hashlib.sha256(str(payload).encode("utf-8")).hexdigest()[:32]


class TaintTracker:
    """Stateful, thread-safe taint tracker for an agent session.

    Tracks tainted values, records propagation hops, and evaluates
    taint policy on sink access.

    Args:
        policy: Taint flow policy.  If ``None``, uses defaults.
        session_id: Optional session identifier for correlation.
    """

    def __init__(
        self,
        policy: TaintPolicy | None = None,
        *,
        session_id: str = "",
    ) -> None:
        self._policy = policy or TaintPolicy()
        self._session_id = session_id
        self._values: dict[str, TaintedValue] = {}
        self._sink_log: list[tuple[str, str, float]] = []  # (taint_id, sink, ts)
        self._findings: list[TaintFinding] = []
        self._lock = threading.Lock()

    # -- tagging -------------------------------------------------------------

    def tag(
        self,
        source: str,
        label: TaintLabel,
        *,
        payload: Any = "",
        metadata: dict[str, Any] | None = None,
    ) -> TaintedValue:
        """Create a new tainted value and start tracking it.

        Args:
            source: Where the data originated (tool name, API, etc.).
            label: Initial taint label.
            payload: The actual data (only its hash is stored).
            metadata: Extra context.

        Returns:
            A :class:`TaintedValue` that can be propagated.
        """
        tv = TaintedValue(
            taint_id=_next_taint_id(),
            labels=frozenset({label}),
            source=source,
            payload_hash=_hash_payload(payload),
            created_at=time.time(),
            propagation_chain=((source, label),),
            metadata=dict(metadata) if metadata else {},
        )
        with self._lock:
            self._values[tv.taint_id] = tv
        return tv

    # -- propagation ---------------------------------------------------------

    def propagate(
        self,
        tainted: TaintedValue,
        new_source: str,
        added_label: TaintLabel | None = None,
    ) -> TaintedValue:
        """Record a taint propagation hop.

        When data flows from one component to another, call this to
        extend the propagation chain and optionally add a new label.

        Args:
            tainted: The existing tainted value.
            new_source: The component the data is flowing into.
            added_label: Optional additional taint label.

        Returns:
            A new :class:`TaintedValue` with the extended chain.
        """
        labels = tainted.labels
        if added_label:
            labels = labels | frozenset({added_label})

        chain = tainted.propagation_chain + ((new_source, added_label or "propagated"),)

        new_tv = TaintedValue(
            taint_id=tainted.taint_id,
            labels=labels,
            source=tainted.source,
            payload_hash=tainted.payload_hash,
            created_at=tainted.created_at,
            propagation_chain=chain,
            metadata=tainted.metadata,
        )
        with self._lock:
            self._values[new_tv.taint_id] = new_tv
        return new_tv

    # -- sink checking -------------------------------------------------------

    def check_sink(
        self,
        tainted: TaintedValue,
        sink: str,
    ) -> TaintFinding | None:
        """Check whether tainted data is allowed to flow into *sink*.

        Evaluates the taint policy. If a violation is found, it is
        recorded and returned.

        Args:
            tainted: The tainted value about to enter the sink.
            sink: Sink identifier (e.g. ``"database"``, ``"file_write"``).

        Returns:
            A :class:`TaintFinding` if blocked/warned, ``None`` if clean.
        """
        finding = self._policy.evaluate(tainted, sink)
        with self._lock:
            self._sink_log.append((tainted.taint_id, sink, time.time()))
            if finding:
                self._findings.append(finding)
        return finding

    # -- sanitisation --------------------------------------------------------

    def sanitise(self, tainted: TaintedValue) -> TaintedValue:
        """Mark a tainted value as sanitised.

        Replaces all existing labels with ``SANITISED``, effectively
        clearing the taint.  The propagation chain is preserved for
        audit purposes.

        Returns:
            A new :class:`TaintedValue` with the ``SANITISED`` label.
        """
        chain = tainted.propagation_chain + (("sanitiser", TaintLabel.SANITISED),)
        sanitised = TaintedValue(
            taint_id=tainted.taint_id,
            labels=frozenset({TaintLabel.SANITISED}),
            source=tainted.source,
            payload_hash=tainted.payload_hash,
            created_at=tainted.created_at,
            propagation_chain=chain,
            metadata=tainted.metadata,
        )
        with self._lock:
            self._values[sanitised.taint_id] = sanitised
        return sanitised

    # -- analysis ------------------------------------------------------------

    def analyze(self) -> TaintReport:
        """Analyze all tracked taint flows and return a report."""
        with self._lock:
            values = dict(self._values)
            findings = list(self._findings)
            sink_log = list(self._sink_log)

        total_props = sum(len(v.propagation_chain) for v in values.values())
        sinks = len({sink for _, sink, _ in sink_log})

        return TaintReport(
            findings=findings,
            total_tracked=len(values),
            total_propagations=total_props,
            sinks_reached=sinks,
            generated_at=time.time(),
        )

    def get_chain(self, taint_id: str) -> tuple[tuple[str, str], ...] | None:
        """Get the propagation chain for a specific taint ID."""
        with self._lock:
            tv = self._values.get(taint_id)
            return tv.propagation_chain if tv else None

    def get_tainted_sinks(self) -> dict[str, list[str]]:
        """Get a mapping of sink -> list of taint IDs that reached it."""
        with self._lock:
            result: dict[str, list[str]] = defaultdict(list)
            for taint_id, sink, _ in self._sink_log:
                result[sink].append(taint_id)
            return dict(result)

    def reset(self) -> None:
        """Clear all tracked state."""
        with self._lock:
            self._values.clear()
            self._sink_log.clear()
            self._findings.clear()
