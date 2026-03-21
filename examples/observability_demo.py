"""
Observability integration demo — format Aegis audit events for monitoring platforms.

Usage:
    python examples/observability_demo.py

Demonstrates:
- Custom audit loggers that format events for DataDog/Splunk (JSON), OpenTelemetry
  (spans), and Prometheus (metrics)
- Structured logging with risk levels, latency, and action metadata
- Simulated actions flowing through each logger with formatted output
- How to bridge Aegis policy decisions into your observability stack
"""

from __future__ import annotations

import asyncio
import json
import random
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from aegis import Action, Approval, Policy, RiskLevel, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.core.policy import PolicyDecision
from aegis.core.result import Result, ResultStatus

# -- ANSI color helpers -------------------------------------------------------

GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

RISK_COLORS = {
    RiskLevel.LOW: GREEN,
    RiskLevel.MEDIUM: YELLOW,
    RiskLevel.HIGH: RED,
    RiskLevel.CRITICAL: f"{RED}{BOLD}",
}

STATUS_COLORS = {
    "auto": GREEN,
    "approve": YELLOW,
    "block": RED,
}

# -- Policy -------------------------------------------------------------------

POLICY_YAML = """\
version: "1"
defaults:
  risk_level: medium
  approval: approve

rules:
  - name: read_ops
    match: { type: "read" }
    risk_level: low
    approval: auto

  - name: query_ops
    match: { type: "query" }
    risk_level: low
    approval: auto

  - name: write_ops
    match: { type: "write" }
    risk_level: medium
    approval: approve

  - name: bulk_ops
    match: { type: "bulk_*" }
    risk_level: high
    approval: approve

  - name: delete_ops
    match: { type: "delete" }
    risk_level: critical
    approval: block
"""

# -- Display helpers ----------------------------------------------------------


def colored(text: str, color: str) -> str:
    return f"{color}{text}{RESET}"


def print_header(title: str) -> None:
    width = 68
    print(f"\n{BOLD}{'=' * width}")
    print(f"  {title}")
    print(f"{'=' * width}{RESET}")


def print_section(title: str) -> None:
    print(f"\n  {BOLD}[{title}]{RESET}")


def print_platform_output(platform: str, color: str, lines: list[str]) -> None:
    """Print formatted output block for a platform."""
    print(f"\n  {colored(platform, color)}")
    print(f"  {DIM}{'-' * 60}{RESET}")
    for line in lines:
        print(f"  {DIM}{line}{RESET}")


# -- Observability Loggers ----------------------------------------------------


@dataclass
class AuditEvent:
    """Intermediate representation of an Aegis audit event."""

    timestamp: str
    trace_id: str
    action_type: str
    action_target: str
    description: str
    risk_level: str
    risk_score: int
    approval: str
    matched_rule: str
    latency_ms: float
    agent_id: str
    status: str

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "trace_id": self.trace_id,
            "action_type": self.action_type,
            "action_target": self.action_target,
            "description": self.description,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "approval": self.approval,
            "matched_rule": self.matched_rule,
            "latency_ms": self.latency_ms,
            "agent_id": self.agent_id,
            "status": self.status,
        }


def build_audit_event(
    decision: PolicyDecision,
    *,
    latency_ms: float,
    status: str = "evaluated",
    trace_id: str = "",
    agent_id: str = "agent-main",
) -> AuditEvent:
    """Build an AuditEvent from an Aegis PolicyDecision."""
    return AuditEvent(
        timestamp=datetime.now(UTC).isoformat(),
        trace_id=trace_id or uuid.uuid4().hex[:16],
        action_type=decision.action.type,
        action_target=decision.action.target,
        description=decision.action.description,
        risk_level=decision.risk_level.name,
        risk_score=int(decision.risk_level),
        approval=decision.approval.value,
        matched_rule=decision.matched_rule,
        latency_ms=round(latency_ms, 3),
        agent_id=agent_id,
        status=status,
    )


# -- 1. DataDog / Splunk JSON Logger -----------------------------------------


@dataclass
class DataDogLogger:
    """Formats audit events as structured JSON for DataDog / Splunk ingestion.

    In production, these JSON objects would be sent via the DataDog Logs API
    or written to a file picked up by the Splunk Universal Forwarder.
    """

    service: str = "aegis-policy-engine"
    env: str = "demo"
    events: list[str] = field(default_factory=list)

    def log(self, event: AuditEvent) -> str:
        """Format and store a DataDog-compatible JSON log line."""
        record = {
            "ddsource": "aegis",
            "ddtags": (
                f"env:{self.env},"
                f"service:{self.service},"
                f"risk:{event.risk_level.lower()},"
                f"approval:{event.approval}"
            ),
            "service": self.service,
            "hostname": "aegis-demo",
            "message": (
                f"Policy decision: {event.action_type}:{event.action_target} "
                f"-> {event.approval}"
            ),
            "timestamp": event.timestamp,
            "trace_id": event.trace_id,
            "level": self._risk_to_log_level(event.risk_level),
            "aegis": event.to_dict(),
        }
        line = json.dumps(record, indent=2)
        self.events.append(line)
        return line

    @staticmethod
    def _risk_to_log_level(risk: str) -> str:
        return {
            "LOW": "INFO",
            "MEDIUM": "WARN",
            "HIGH": "ERROR",
            "CRITICAL": "CRITICAL",
        }.get(risk, "INFO")


# -- 2. OpenTelemetry Span Logger --------------------------------------------


@dataclass
class OTelSpanLogger:
    """Formats audit events as OpenTelemetry-compatible span representations.

    In production, these would be created via the opentelemetry-api SDK
    and exported to Jaeger, Tempo, or the OTel Collector.
    """

    service_name: str = "aegis-policy-engine"
    spans: list[dict] = field(default_factory=list)

    def record_span(self, event: AuditEvent) -> dict:
        """Create an OTel-style span dict from an audit event."""
        span = {
            "traceId": event.trace_id,
            "spanId": uuid.uuid4().hex[:16],
            "operationName": f"aegis.policy.{event.action_type}",
            "serviceName": self.service_name,
            "startTime": event.timestamp,
            "duration_ms": event.latency_ms,
            "status": {
                "code": "OK" if event.approval != "block" else "ERROR",
                "message": (
                    f"Blocked by rule: {event.matched_rule}"
                    if event.approval == "block"
                    else ""
                ),
            },
            "attributes": {
                "aegis.action.type": event.action_type,
                "aegis.action.target": event.action_target,
                "aegis.risk.level": event.risk_level,
                "aegis.risk.score": event.risk_score,
                "aegis.approval": event.approval,
                "aegis.rule.matched": event.matched_rule,
                "aegis.agent.id": event.agent_id,
            },
            "events": [
                {
                    "name": "policy.decision",
                    "timestamp": event.timestamp,
                    "attributes": {
                        "decision": event.approval,
                        "risk_level": event.risk_level,
                    },
                },
            ],
        }
        self.spans.append(span)
        return span


# -- 3. Prometheus Metrics Logger ---------------------------------------------


@dataclass
class PrometheusMetricsLogger:
    """Collects audit events and formats them as Prometheus exposition metrics.

    In production, these counters and histograms would be exposed on a
    /metrics endpoint via prometheus_client or a similar library.
    """

    _decisions_total: dict[str, int] = field(default_factory=dict)
    _risk_total: dict[str, int] = field(default_factory=dict)
    _latency_samples: list[float] = field(default_factory=list)
    _blocked_total: int = 0

    def record(self, event: AuditEvent) -> None:
        """Record an audit event into Prometheus-style counters."""
        # Increment decision counter by approval type
        key = f'{event.action_type}:{event.approval}'
        self._decisions_total[key] = self._decisions_total.get(key, 0) + 1

        # Increment risk level counter
        self._risk_total[event.risk_level] = (
            self._risk_total.get(event.risk_level, 0) + 1
        )

        # Collect latency for histogram
        self._latency_samples.append(event.latency_ms)

        # Count blocked actions
        if event.approval == "block":
            self._blocked_total += 1

    def format_exposition(self) -> str:
        """Render metrics in Prometheus exposition format."""
        lines: list[str] = []

        # Decision counters
        lines.append("# HELP aegis_decisions_total Total policy decisions by type")
        lines.append("# TYPE aegis_decisions_total counter")
        for key, count in sorted(self._decisions_total.items()):
            action_type, approval = key.split(":")
            lines.append(
                f'aegis_decisions_total{{action="{action_type}",'
                f'approval="{approval}"}} {count}'
            )

        # Risk level counters
        lines.append("")
        lines.append("# HELP aegis_risk_total Decisions by risk level")
        lines.append("# TYPE aegis_risk_total counter")
        for level, count in sorted(self._risk_total.items()):
            lines.append(f'aegis_risk_total{{level="{level.lower()}"}} {count}')

        # Blocked counter
        lines.append("")
        lines.append("# HELP aegis_blocked_total Total blocked actions")
        lines.append("# TYPE aegis_blocked_total counter")
        lines.append(f"aegis_blocked_total {self._blocked_total}")

        # Latency histogram (simplified — real implementation uses buckets)
        if self._latency_samples:
            avg = sum(self._latency_samples) / len(self._latency_samples)
            lines.append("")
            lines.append(
                "# HELP aegis_decision_latency_ms Policy evaluation latency"
            )
            lines.append("# TYPE aegis_decision_latency_ms summary")
            lines.append(
                f"aegis_decision_latency_ms_count {len(self._latency_samples)}"
            )
            lines.append(
                f"aegis_decision_latency_ms_sum "
                f"{sum(self._latency_samples):.3f}"
            )
            lines.append(f"aegis_decision_latency_ms_avg {avg:.3f}")

        return "\n".join(lines)


# -- Executor -----------------------------------------------------------------


class DemoExecutor(BaseExecutor):
    """Executor that simulates latency for realistic metrics."""

    async def execute(self, action: Action) -> Result:
        return Result(action=action, status=ResultStatus.SUCCESS)


# -- Main ---------------------------------------------------------------------

ACTIONS = [
    Action("read", "users", description="Fetch user profile"),
    Action("query", "analytics", description="Run dashboard query"),
    Action("write", "orders", description="Create purchase order"),
    Action("bulk_update", "inventory", description="Bulk stock adjustment"),
    Action("delete", "audit_logs", description="Purge old audit logs"),
    Action("read", "products", description="List product catalog"),
    Action("write", "notifications", description="Send batch emails"),
]


async def main() -> None:
    print_header("Aegis Observability Integration Demo")
    print(
        f"  {DIM}Routing audit events to DataDog, OpenTelemetry, "
        f"and Prometheus{RESET}"
    )

    # Load policy
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as f:
        f.write(POLICY_YAML)
        policy_path = f.name

    policy = Policy.from_yaml(policy_path)

    # Initialize platform loggers
    dd_logger = DataDogLogger(env="production")
    otel_logger = OTelSpanLogger()
    prom_logger = PrometheusMetricsLogger()

    async with Runtime(
        executor=DemoExecutor(),
        policy=policy,
    ) as runtime:
        # -- Evaluate actions and route to all platforms ----------------------

        print_section("Evaluating Actions")
        trace_id = uuid.uuid4().hex[:16]

        for action in ACTIONS:
            # Measure evaluation latency
            t0 = time.perf_counter()
            decision = policy.evaluate(action)
            latency_ms = (time.perf_counter() - t0) * 1000

            # Add simulated network/processing jitter for realistic metrics
            latency_ms += random.uniform(0.1, 2.5)

            # Determine status from execution
            status = "allowed" if decision.is_allowed else "blocked"

            event = build_audit_event(
                decision,
                latency_ms=latency_ms,
                status=status,
                trace_id=trace_id,
            )

            # Route to all platform loggers
            dd_logger.log(event)
            otel_logger.record_span(event)
            prom_logger.record(event)

            # Print action summary
            risk_color = RISK_COLORS.get(decision.risk_level, RESET)
            appr_color = STATUS_COLORS.get(decision.approval.value, RESET)
            print(
                f"    {action.type:<16} {action.target:<16} "
                f"risk={colored(decision.risk_level.name.lower(), risk_color):<23} "
                f"-> {colored(decision.approval.value, appr_color)}"
            )

            # Execute through runtime for non-blocked actions
            plan = runtime.plan([action])
            await runtime.execute(plan)

        # -- DataDog / Splunk output ------------------------------------------

        print_section("DataDog / Splunk JSON Logs")
        print(
            f"  {DIM}Each event is a structured JSON log line with "
            f"ddtags for filtering.{RESET}"
        )

        # Show 2 sample events: one low-risk, one critical
        samples = [dd_logger.events[0], dd_logger.events[-2]]
        for sample in samples:
            print_platform_output("JSON Log Entry", CYAN, sample.split("\n"))

        # -- OpenTelemetry output ---------------------------------------------

        print_section("OpenTelemetry Spans")
        print(
            f"  {DIM}Spans with attributes for distributed tracing "
            f"(Jaeger, Tempo, Zipkin).{RESET}"
        )

        # Show a sample span
        sample_span = otel_logger.spans[3]  # bulk_update — interesting one
        formatted = json.dumps(sample_span, indent=2)
        print_platform_output(
            f"Span: {sample_span['operationName']}", MAGENTA,
            formatted.split("\n"),
        )

        # -- Prometheus output ------------------------------------------------

        print_section("Prometheus Metrics")
        print(
            f"  {DIM}Exposition format for /metrics endpoint "
            f"(prometheus_client).{RESET}"
        )

        exposition = prom_logger.format_exposition()
        print_platform_output("GET /metrics", GREEN, exposition.split("\n"))

        # -- Summary ----------------------------------------------------------

        print_section("Summary")

        total = len(ACTIONS)
        auto_count = sum(
            1 for a in ACTIONS
            if policy.evaluate(a).approval == Approval.AUTO
        )
        approve_count = sum(
            1 for a in ACTIONS
            if policy.evaluate(a).approval == Approval.APPROVE
        )
        block_count = sum(
            1 for a in ACTIONS
            if policy.evaluate(a).approval == Approval.BLOCK
        )

        print(f"  Actions evaluated : {total}")
        print(f"  {colored('AUTO', GREEN)}              : {auto_count}")
        print(f"  {colored('APPROVE', YELLOW)}           : {approve_count}")
        print(f"  {colored('BLOCK', RED)}             : {block_count}")
        print(f"  DD log entries    : {len(dd_logger.events)}")
        print(f"  OTel spans        : {len(otel_logger.spans)}")
        print(
            f"  Prom metrics      : "
            f"{len(prom_logger._decisions_total)} counter series"
        )

    # Clean up
    Path(policy_path).unlink(missing_ok=True)

    print(f"\n{BOLD}{'=' * 68}{RESET}")
    print(f"  {DIM}Integration tips:")
    print("  - DataDog: send JSON via datadog-api-client or log file tailing")
    print("  - OTel: use opentelemetry-sdk to create real spans with context")
    print(
        "  - Prometheus: expose counters via prometheus_client on /metrics"
    )
    print(f"  - All platforms: use trace_id to correlate across systems{RESET}")
    print()


if __name__ == "__main__":
    asyncio.run(main())
