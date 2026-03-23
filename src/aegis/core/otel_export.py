"""OpenTelemetry export for Aegis audit events.

Converts Aegis governance events (policy decisions, cost records,
anomaly alerts, MCP security findings) into OpenTelemetry spans and
events for integration with existing observability stacks (Datadog,
Grafana, Jaeger, etc.).

The module does **not** require ``opentelemetry-sdk`` at import time.
When the SDK is not installed, :class:`AegisOTelExporter` falls back
to an in-memory event buffer that can be consumed by tests or custom
exporters.

Usage with OpenTelemetry::

    from opentelemetry import trace
    from aegis.core.otel_export import AegisOTelExporter

    tracer = trace.get_tracer("aegis")
    exporter = AegisOTelExporter(tracer=tracer)
    exporter.record_decision(policy_decision, action)
    exporter.record_cost(cost_record)

Usage without OpenTelemetry (in-memory)::

    exporter = AegisOTelExporter()  # no tracer -> in-memory mode
    exporter.record_decision(policy_decision, action)
    print(exporter.events)  # list of dicts
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Event models (framework-agnostic)
# ---------------------------------------------------------------------------


@dataclass
class AegisEvent:
    """A single governance event suitable for export.

    Attributes:
        event_type: Category (e.g. ``"policy_decision"``, ``"cost_record"``).
        timestamp: Unix timestamp.
        attributes: Key-value pairs for the event.
    """

    event_type: str
    timestamp: float
    attributes: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Exporter
# ---------------------------------------------------------------------------


class AegisOTelExporter:
    """Exports Aegis governance events to OpenTelemetry or an in-memory buffer.

    When a ``tracer`` is provided (an OpenTelemetry ``Tracer`` instance),
    events are recorded as OTel span events. Otherwise, events are stored
    in the :attr:`events` list for testing or custom consumption.

    Args:
        tracer: Optional OpenTelemetry ``Tracer`` instance.
        service_name: Service name attribute for spans.
    """

    def __init__(
        self,
        tracer: Any | None = None,
        *,
        service_name: str = "aegis",
    ) -> None:
        self._tracer = tracer
        self._service_name = service_name
        self._events: list[AegisEvent] = []

    @property
    def events(self) -> list[AegisEvent]:
        """In-memory event buffer (populated when no tracer is set)."""
        return list(self._events)

    @property
    def event_count(self) -> int:
        """Total events recorded."""
        return len(self._events)

    # -- Public record methods -----------------------------------------------

    def record_decision(
        self,
        action_type: str,
        action_target: str,
        decision: str,
        *,
        risk_level: str = "",
        matched_rule: str = "",
        agent_id: str = "",
        session_id: str = "",
    ) -> AegisEvent:
        """Record a policy decision event.

        Args:
            action_type: The action type that was evaluated.
            action_target: The action target.
            decision: The policy decision (allow/block/approve).
            risk_level: The assessed risk level.
            matched_rule: The policy rule that matched.
            agent_id: Agent that performed the action.
            session_id: Session identifier.

        Returns:
            The created :class:`AegisEvent`.
        """
        attrs = {
            "aegis.action.type": action_type,
            "aegis.action.target": action_target,
            "aegis.decision": decision,
            "aegis.risk_level": risk_level,
            "aegis.matched_rule": matched_rule,
            "aegis.agent_id": agent_id,
            "aegis.session_id": session_id,
        }
        return self._emit("policy_decision", attrs)

    def record_cost(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cost: float,
        cumulative: float,
        *,
        agent_id: str = "",
        session_id: str = "",
    ) -> AegisEvent:
        """Record a cost tracking event.

        Args:
            model: LLM model identifier.
            input_tokens: Number of input tokens.
            output_tokens: Number of output tokens.
            cost: Cost of this call in dollars.
            cumulative: Cumulative spend in dollars.
            agent_id: Agent that made the call.
            session_id: Session identifier.

        Returns:
            The created :class:`AegisEvent`.
        """
        attrs = {
            "aegis.cost.model": model,
            "aegis.cost.input_tokens": input_tokens,
            "aegis.cost.output_tokens": output_tokens,
            "aegis.cost.amount": cost,
            "aegis.cost.cumulative": cumulative,
            "aegis.agent_id": agent_id,
            "aegis.session_id": session_id,
        }
        return self._emit("cost_record", attrs)

    def record_anomaly(
        self,
        agent_id: str,
        anomaly_type: str,
        action_type: str,
        *,
        severity: str = "warning",
        details: str = "",
    ) -> AegisEvent:
        """Record an anomaly detection event.

        Args:
            agent_id: Agent that triggered the anomaly.
            anomaly_type: Type of anomaly detected.
            action_type: The action that triggered the anomaly.
            severity: Severity level.
            details: Additional details.

        Returns:
            The created :class:`AegisEvent`.
        """
        attrs = {
            "aegis.anomaly.type": anomaly_type,
            "aegis.anomaly.action_type": action_type,
            "aegis.anomaly.severity": severity,
            "aegis.anomaly.details": details,
            "aegis.agent_id": agent_id,
        }
        return self._emit("anomaly_detected", attrs)

    def record_mcp_finding(
        self,
        tool_name: str,
        finding_type: str,
        severity: str,
        *,
        detail: str = "",
        trust_level: str = "",
    ) -> AegisEvent:
        """Record an MCP security finding event.

        Args:
            tool_name: Name of the MCP tool.
            finding_type: Category of finding (poisoning, rug_pull, etc.).
            severity: Finding severity.
            detail: Description of the finding.
            trust_level: Computed trust level.

        Returns:
            The created :class:`AegisEvent`.
        """
        attrs = {
            "aegis.mcp.tool_name": tool_name,
            "aegis.mcp.finding_type": finding_type,
            "aegis.mcp.severity": severity,
            "aegis.mcp.detail": detail,
            "aegis.mcp.trust_level": trust_level,
        }
        return self._emit("mcp_security_finding", attrs)

    def record_budget_alert(
        self,
        alert_type: str,
        spent: float,
        budget: float,
        utilization: float,
        *,
        session_id: str = "",
    ) -> AegisEvent:
        """Record a budget threshold alert.

        Args:
            alert_type: Type of alert (warn/soft_limit/hard_limit).
            spent: Current spend.
            budget: Maximum budget.
            utilization: Budget utilization as fraction.
            session_id: Session identifier.

        Returns:
            The created :class:`AegisEvent`.
        """
        attrs = {
            "aegis.budget.alert_type": alert_type,
            "aegis.budget.spent": spent,
            "aegis.budget.max": budget,
            "aegis.budget.utilization": utilization,
            "aegis.session_id": session_id,
        }
        return self._emit("budget_alert", attrs)

    # -- Internal ------------------------------------------------------------

    def _emit(self, event_type: str, attributes: dict[str, Any]) -> AegisEvent:
        """Create an event and optionally send to OTel tracer."""
        now = time.time()
        event = AegisEvent(
            event_type=event_type,
            timestamp=now,
            attributes=attributes,
        )
        self._events.append(event)

        # If tracer is available, create a span event
        if self._tracer is not None:
            self._emit_otel(event)

        return event

    def _emit_otel(self, event: AegisEvent) -> None:
        """Send an event to OpenTelemetry as a span event."""
        try:
            # Use the tracer to create a zero-duration span with the event
            with self._tracer.start_as_current_span(  # type: ignore[union-attr]
                f"aegis.{event.event_type}",
                attributes={
                    "service.name": self._service_name,
                    **{k: _otel_safe(v) for k, v in event.attributes.items()},
                },
            ) as span:
                span.add_event(
                    event.event_type,
                    attributes={k: _otel_safe(v) for k, v in event.attributes.items()},
                )
        except Exception:
            # Never let OTel errors break governance
            pass


def _otel_safe(value: Any) -> str | int | float | bool:
    """Coerce a value to an OTel-safe attribute type."""
    if isinstance(value, (str, int, float, bool)):
        return value
    return str(value)
