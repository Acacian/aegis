"""Cross-session data leakage detection for MCP servers.

Detects when a shared MCP server correlates requests across different
users/tenants to build profiles.  Analyzes tool call patterns across
sessions and tenants to surface leakage signals.

Detection categories:

- **Cross-tenant argument overlap** -- Same unusual argument values
  appearing across different tenant sessions.
- **Session fingerprinting** -- Tool calls that extract identifying
  information without clear purpose.
- **Correlation probing** -- Sequential tool calls that test whether
  a server "remembers" data from another session.
- **Exfiltration via tool args** -- Arguments that embed data from
  previous tool results (data flowing back to server).
- **Profile accumulation** -- Server responses containing information
  not present in the current session's requests.

Usage::

    from aegis.core.leakage_detector import LeakageDetector

    detector = LeakageDetector()
    detector.observe_tool_call(
        tenant_id="tenant-a", session_id="sess-1",
        tool_name="search", arguments={"query": "user profile"},
        result="...",
    )
    report = detector.analyze()
"""

from __future__ import annotations

import hashlib
import re
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LeakageFinding:
    """A single leakage detection finding.

    Attributes:
        category: Detection category (e.g. ``"cross_tenant_overlap"``).
        severity: ``"critical"``, ``"high"``, ``"medium"``, or ``"low"``.
        description: Human-readable description.
        evidence: Supporting evidence (tool names, argument values, etc.).
        tenant_ids: Tenant IDs involved in this finding.
        session_ids: Session IDs involved in this finding.
    """

    category: str
    severity: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    tenant_ids: frozenset[str] = frozenset()
    session_ids: frozenset[str] = frozenset()


@dataclass
class LeakageReport:
    """Result of cross-session leakage analysis.

    Attributes:
        findings: All leakage findings detected.
        sessions_analyzed: Number of unique sessions analyzed.
        tenants_analyzed: Number of unique tenants analyzed.
        observations_analyzed: Total observations analyzed.
        generated_at: Unix timestamp of report generation.
    """

    findings: list[LeakageFinding] = field(default_factory=list)
    sessions_analyzed: int = 0
    tenants_analyzed: int = 0
    observations_analyzed: int = 0
    generated_at: float = 0.0

    @property
    def clean(self) -> bool:
        """Whether no leakage was detected."""
        return len(self.findings) == 0


@dataclass
class _Observation:
    """Internal record of a single MCP tool call observation."""

    tenant_id: str
    session_id: str
    tool_name: str
    arguments: dict[str, Any]
    result: str
    timestamp: float
    arg_hash: str


# ---------------------------------------------------------------------------
# Fingerprinting patterns
# ---------------------------------------------------------------------------

_FINGERPRINT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "user_agent_probe",
        re.compile(r"user[_-]?agent|navigator|platform|browser", re.IGNORECASE),
    ),
    (
        "locale_probe",
        re.compile(
            r"locale|timezone|time[_-]?zone|language|lang|region",
            re.IGNORECASE,
        ),
    ),
    (
        "identity_probe",
        re.compile(
            r"whoami|who[_-]am[_-]i|current[_-]?user|username|user[_-]?id|ip[_-]?addr",
            re.IGNORECASE,
        ),
    ),
    (
        "system_probe",
        re.compile(
            r"hostname|machine[_-]?id|device[_-]?id|os[_-]?version|kernel",
            re.IGNORECASE,
        ),
    ),
    (
        "env_probe",
        re.compile(r"env(?:ironment)?[_-]?var|getenv|process\.env", re.IGNORECASE),
    ),
]

_MIN_ARG_VALUE_LENGTH = 8
_MIN_CROSS_TENANT_OVERLAP = 2


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _flatten_args(arguments: dict[str, Any], depth: int = 0) -> str:
    """Recursively flatten arguments to a single string."""
    if depth > 10:
        return ""
    parts: list[str] = []
    for k, v in arguments.items():
        parts.append(str(k))
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, dict):
            parts.append(_flatten_args(v, depth + 1))
        elif isinstance(v, (list, tuple)):
            for item in v:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    parts.append(_flatten_args(item, depth + 1))
                else:
                    parts.append(str(item))
        else:
            parts.append(str(v))
    return " ".join(parts)


def _extract_arg_values(
    arguments: dict[str, Any],
    min_length: int,
    depth: int = 0,
) -> list[str]:
    """Extract string values from arguments that meet minimum length."""
    if depth > 10:
        return []
    values: list[str] = []
    for v in arguments.values():
        if isinstance(v, str) and len(v) >= min_length:
            values.append(v)
        elif isinstance(v, dict):
            values.extend(_extract_arg_values(v, min_length, depth + 1))
        elif isinstance(v, (list, tuple)):
            for item in v:
                if isinstance(item, str) and len(item) >= min_length:
                    values.append(item)
                elif isinstance(item, dict):
                    values.extend(_extract_arg_values(item, min_length, depth + 1))
    return values


def _extract_tokens(text: str, min_length: int) -> list[str]:
    """Extract meaningful tokens from text for comparison."""
    tokens = re.split(r'[\s,;|{}\[\]"\']+', text)
    return [t for t in tokens if len(t) >= min_length]


# ---------------------------------------------------------------------------
# Leakage detector
# ---------------------------------------------------------------------------


class LeakageDetector:
    """Detects cross-session data leakage in MCP server interactions.

    Collects observations (tool calls + results) across sessions and
    tenants, then analyzes for leakage signals.

    Thread-safe: all state mutations are guarded by an internal lock.

    Args:
        min_arg_value_length: Minimum argument value length to track
            for cross-tenant overlap.  Default 8.
        min_cross_tenant_overlap: Minimum overlapping values to flag.
            Default 2.
        fingerprint_patterns: Additional ``(name, regex)`` tuples for
            fingerprinting detection.  Appended to built-in patterns.
    """

    def __init__(
        self,
        *,
        min_arg_value_length: int = _MIN_ARG_VALUE_LENGTH,
        min_cross_tenant_overlap: int = _MIN_CROSS_TENANT_OVERLAP,
        fingerprint_patterns: list[tuple[str, re.Pattern[str]]] | None = None,
    ) -> None:
        self._min_arg_len = min_arg_value_length
        self._min_overlap = min_cross_tenant_overlap
        self._extra_fp_patterns = fingerprint_patterns or []
        self._observations: list[_Observation] = []
        self._lock = threading.Lock()

    # -- observation ingestion -----------------------------------------------

    def observe_tool_call(
        self,
        *,
        tenant_id: str,
        session_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        result: str = "",
    ) -> None:
        """Record a tool call observation for later analysis."""
        arg_str = _flatten_args(arguments)
        arg_hash = hashlib.sha256(arg_str.encode("utf-8")).hexdigest()
        obs = _Observation(
            tenant_id=tenant_id,
            session_id=session_id,
            tool_name=tool_name,
            arguments=arguments,
            result=result,
            timestamp=time.time(),
            arg_hash=arg_hash,
        )
        with self._lock:
            self._observations.append(obs)

    def observe_session(
        self,
        session: Any,
        *,
        tenant_id: str = "",
    ) -> None:
        """Ingest all ``tool_call`` events from a :class:`Session` object.

        Args:
            session: A ``session_replay.Session`` object.
            tenant_id: Tenant ID to associate.  Falls back to
                ``session.metadata.get("tenant_id", "unknown")``.
        """
        tid = tenant_id or session.metadata.get("tenant_id", "unknown")
        for event in session.events:
            if event.event_type == "tool_call":
                self.observe_tool_call(
                    tenant_id=tid,
                    session_id=session.session_id,
                    tool_name=event.tool_name,
                    arguments=event.data.get("arguments", {}),
                )
            elif event.event_type == "tool_result":
                self._attach_result(
                    session.session_id,
                    event.tool_name,
                    event.data.get("result", ""),
                )

    def _attach_result(self, session_id: str, tool_name: str, result: str) -> None:
        """Attach a result to the last matching tool_call observation."""
        with self._lock:
            for obs in reversed(self._observations):
                if obs.session_id == session_id and obs.tool_name == tool_name and not obs.result:
                    obs.result = result
                    break

    # -- analysis ------------------------------------------------------------

    def analyze(self) -> LeakageReport:
        """Analyze all collected observations for leakage signals."""
        with self._lock:
            observations = list(self._observations)

        if not observations:
            return LeakageReport(generated_at=time.time())

        findings: list[LeakageFinding] = []

        by_tenant: dict[str, list[_Observation]] = defaultdict(list)
        by_session: dict[str, list[_Observation]] = defaultdict(list)
        for obs in observations:
            by_tenant[obs.tenant_id].append(obs)
            by_session[obs.session_id].append(obs)

        findings.extend(self._detect_cross_tenant_overlap(by_tenant))
        findings.extend(self._detect_fingerprinting(observations))
        findings.extend(self._detect_correlation_probing(by_session, by_tenant))
        findings.extend(self._detect_exfiltration_via_args(by_session))
        findings.extend(self._detect_profile_accumulation(by_session, by_tenant))

        return LeakageReport(
            findings=findings,
            sessions_analyzed=len(by_session),
            tenants_analyzed=len(by_tenant),
            observations_analyzed=len(observations),
            generated_at=time.time(),
        )

    def reset(self) -> None:
        """Clear all collected observations."""
        with self._lock:
            self._observations.clear()

    # -- detection methods ---------------------------------------------------

    def _detect_cross_tenant_overlap(
        self,
        by_tenant: dict[str, list[_Observation]],
    ) -> list[LeakageFinding]:
        """Same unusual argument values appearing across different tenants."""
        if len(by_tenant) < 2:
            return []

        findings: list[LeakageFinding] = []

        value_to_tenants: dict[str, set[str]] = defaultdict(set)
        value_to_sessions: dict[str, set[str]] = defaultdict(set)
        value_to_tools: dict[str, set[str]] = defaultdict(set)

        for tenant_id, obs_list in by_tenant.items():
            for obs in obs_list:
                for val in _extract_arg_values(obs.arguments, self._min_arg_len):
                    value_to_tenants[val].add(tenant_id)
                    value_to_sessions[val].add(obs.session_id)
                    value_to_tools[val].add(obs.tool_name)

        shared_values = [v for v, ts in value_to_tenants.items() if len(ts) >= 2]

        if len(shared_values) >= self._min_overlap:
            all_tenants: set[str] = set()
            all_sessions: set[str] = set()
            for val in shared_values:
                all_tenants.update(value_to_tenants[val])
                all_sessions.update(value_to_sessions[val])

            findings.append(
                LeakageFinding(
                    category="cross_tenant_overlap",
                    severity="high",
                    description=(
                        f"{len(shared_values)} argument values shared across "
                        f"{len(all_tenants)} tenants"
                    ),
                    evidence={
                        "shared_values_count": len(shared_values),
                        "sample_values": shared_values[:5],
                        "tools_involved": sorted(
                            set().union(*(value_to_tools[v] for v in shared_values))
                        ),
                    },
                    tenant_ids=frozenset(all_tenants),
                    session_ids=frozenset(all_sessions),
                )
            )

        return findings

    def _detect_fingerprinting(
        self,
        observations: list[_Observation],
    ) -> list[LeakageFinding]:
        """Tool calls that extract identifying information."""
        findings: list[LeakageFinding] = []
        all_patterns = _FINGERPRINT_PATTERNS + self._extra_fp_patterns

        flagged_by_session: dict[str, list[tuple[str, str, str]]] = defaultdict(list)

        for obs in observations:
            text_to_scan = obs.tool_name + " " + _flatten_args(obs.arguments)
            for pattern_name, regex in all_patterns:
                match = regex.search(text_to_scan)
                if match:
                    flagged_by_session[obs.session_id].append(
                        (pattern_name, obs.tool_name, match.group(0))
                    )

        for session_id, flags in flagged_by_session.items():
            unique_patterns = {name for name, _, _ in flags}
            if len(unique_patterns) >= 2:
                tenant_ids = {
                    obs.tenant_id for obs in observations if obs.session_id == session_id
                }
                findings.append(
                    LeakageFinding(
                        category="session_fingerprinting",
                        severity="medium",
                        description=(
                            f"Session '{session_id}' has {len(unique_patterns)} "
                            f"fingerprinting patterns: "
                            f"{', '.join(sorted(unique_patterns))}"
                        ),
                        evidence={
                            "patterns": sorted(unique_patterns),
                            "tools": sorted({tool for _, tool, _ in flags}),
                            "samples": [
                                {"pattern": name, "tool": tool, "matched": text}
                                for name, tool, text in flags[:5]
                            ],
                        },
                        tenant_ids=frozenset(tenant_ids),
                        session_ids=frozenset({session_id}),
                    )
                )

        return findings

    def _detect_correlation_probing(
        self,
        by_session: dict[str, list[_Observation]],
        by_tenant: dict[str, list[_Observation]],
    ) -> list[LeakageFinding]:
        """Same tool+args repeated across different sessions of same tenant."""
        findings: list[LeakageFinding] = []

        if len(by_session) < 2:
            return []

        for tenant_id, obs_list in by_tenant.items():
            sessions = {obs.session_id for obs in obs_list}
            if len(sessions) < 2:
                continue

            call_sig_sessions: dict[tuple[str, str], set[str]] = defaultdict(set)
            for obs in obs_list:
                key = (obs.tool_name, obs.arg_hash)
                call_sig_sessions[key].add(obs.session_id)

            repeated = {sig: sids for sig, sids in call_sig_sessions.items() if len(sids) >= 2}

            if len(repeated) >= 2:
                findings.append(
                    LeakageFinding(
                        category="correlation_probing",
                        severity="high",
                        description=(
                            f"Tenant '{tenant_id}': {len(repeated)} identical "
                            f"tool calls repeated across sessions"
                        ),
                        evidence={
                            "repeated_calls": [
                                {"tool": sig[0], "sessions": sorted(sids)}
                                for sig, sids in list(repeated.items())[:5]
                            ],
                        },
                        tenant_ids=frozenset({tenant_id}),
                        session_ids=frozenset(s for sids in repeated.values() for s in sids),
                    )
                )

        return findings

    def _detect_exfiltration_via_args(
        self,
        by_session: dict[str, list[_Observation]],
    ) -> list[LeakageFinding]:
        """Arguments that embed data from previous tool results."""
        findings: list[LeakageFinding] = []

        for session_id, obs_list in by_session.items():
            result_snippets: dict[str, str] = {}
            exfil_evidence: list[dict[str, str]] = []

            sorted_obs = sorted(obs_list, key=lambda o: o.timestamp)
            for i, obs in enumerate(sorted_obs):
                if obs.result:
                    for token in _extract_tokens(obs.result, self._min_arg_len):
                        result_snippets[token] = obs.tool_name

                if i > 0:
                    arg_str = _flatten_args(obs.arguments)
                    for snippet, source_tool in result_snippets.items():
                        if source_tool != obs.tool_name and snippet in arg_str:
                            exfil_evidence.append(
                                {
                                    "source_tool": source_tool,
                                    "destination_tool": obs.tool_name,
                                    "snippet_preview": snippet[:50],
                                }
                            )

            if exfil_evidence:
                tenant_ids = {obs.tenant_id for obs in obs_list}
                findings.append(
                    LeakageFinding(
                        category="exfiltration_via_args",
                        severity="high",
                        description=(
                            f"Session '{session_id}': {len(exfil_evidence)} "
                            f"cases of tool results embedded in subsequent "
                            f"tool arguments"
                        ),
                        evidence={"cases": exfil_evidence[:10]},
                        tenant_ids=frozenset(tenant_ids),
                        session_ids=frozenset({session_id}),
                    )
                )

        return findings

    def _detect_profile_accumulation(
        self,
        by_session: dict[str, list[_Observation]],
        by_tenant: dict[str, list[_Observation]],
    ) -> list[LeakageFinding]:
        """Server responses containing data from other tenants."""
        findings: list[LeakageFinding] = []

        if len(by_tenant) < 2:
            return []

        tenant_arg_values: dict[str, set[str]] = defaultdict(set)
        for tenant_id, obs_list in by_tenant.items():
            for obs in obs_list:
                for val in _extract_arg_values(obs.arguments, self._min_arg_len):
                    tenant_arg_values[tenant_id].add(val)

        for tenant_id, obs_list in by_tenant.items():
            other_values: set[str] = set()
            for other_tid, vals in tenant_arg_values.items():
                if other_tid != tenant_id:
                    other_values.update(vals)

            if not other_values:
                continue

            leaked: list[dict[str, str]] = []
            for obs in obs_list:
                if obs.result:
                    for val in other_values:
                        if val in obs.result:
                            source_tenants = {
                                tid
                                for tid, vals in tenant_arg_values.items()
                                if tid != tenant_id and val in vals
                            }
                            leaked.append(
                                {
                                    "tool": obs.tool_name,
                                    "session": obs.session_id,
                                    "leaked_value_preview": val[:50],
                                    "source_tenants": ",".join(sorted(source_tenants)),
                                }
                            )

            if leaked:
                involved_tenants: set[str] = {tenant_id}
                for item in leaked:
                    involved_tenants.update(item["source_tenants"].split(","))

                findings.append(
                    LeakageFinding(
                        category="profile_accumulation",
                        severity="critical",
                        description=(
                            f"Tenant '{tenant_id}': {len(leaked)} tool results "
                            f"contain data from other tenants"
                        ),
                        evidence={"leaked_items": leaked[:10]},
                        tenant_ids=frozenset(involved_tenants),
                        session_ids=frozenset(obs.session_id for obs in obs_list),
                    )
                )

        return findings

    # -- reporting -----------------------------------------------------------

    def format_report(self, report: LeakageReport) -> str:
        """Format a :class:`LeakageReport` as human-readable text."""
        lines: list[str] = [
            "Cross-Session Leakage Report",
            "=" * 40,
            f"Sessions analyzed: {report.sessions_analyzed}",
            f"Tenants analyzed: {report.tenants_analyzed}",
            f"Observations analyzed: {report.observations_analyzed}",
        ]

        if report.clean:
            lines.append("No leakage detected.")
            return "\n".join(lines)

        lines.append(f"Findings: {len(report.findings)}")
        lines.append("")

        for finding in report.findings:
            lines.append(f"  [{finding.severity.upper()}] {finding.category}")
            lines.append(f"    {finding.description}")
            if finding.tenant_ids:
                lines.append(f"    Tenants: {', '.join(sorted(finding.tenant_ids))}")
            if finding.session_ids:
                lines.append(f"    Sessions: {', '.join(sorted(finding.session_ids))}")
            lines.append("")

        return "\n".join(lines)
