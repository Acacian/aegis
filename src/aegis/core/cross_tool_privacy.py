"""Cross-tool privacy inference detection.

Inspired by TOP-Bench (arXiv:2512.16310) -- detects when combinations
of tool calls across an agent session could leak private information
that no single tool call would reveal on its own.

The key insight: individually innocuous tool calls can compose into
privacy violations.  For example:

1. Tool A returns a user's city ("Seoul")
2. Tool B returns their employer ("CompanyX")
3. Tool C returns their role ("VP Engineering")
4. Together: uniquely identifies the person → privacy violation

Detection strategies:

- **PII accumulation**: Tracks PII categories gathered across tool calls.
  Flags when enough categories accumulate to re-identify an individual.
- **Cross-reference inference**: Detects when tool outputs from different
  sources can be joined to produce new information.
- **Temporal correlation**: Flags rapid sequential queries that appear
  to be systematic profiling.
- **Quasi-identifier detection**: Identifies combinations of quasi-
  identifiers (age, zip, gender, occupation) that together may be
  uniquely identifying (inspired by k-anonymity research).

No external dependencies.  Thread-safe.

Reference:
    TOP-Bench: Evaluating Tool-Operated Privacy Leakage in LLM Agents.
    arXiv:2512.16310 (2025).

Example::

    detector = CrossToolPrivacyDetector()
    detector.observe("get_location", {"user_id": "123"}, "Seoul")
    detector.observe("get_employer", {"user_id": "123"}, "CompanyX")
    detector.observe("get_role", {"user_id": "123"}, "VP Engineering")
    report = detector.analyze()
    assert not report.clean  # quasi-identifier combination detected
"""

from __future__ import annotations

import re
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# PII category definitions
# ---------------------------------------------------------------------------


class PIICategory:
    """Known PII categories for accumulation tracking."""

    NAME = "name"
    EMAIL = "email"
    PHONE = "phone"
    ADDRESS = "address"
    LOCATION = "location"
    EMPLOYER = "employer"
    OCCUPATION = "occupation"
    AGE = "age"
    GENDER = "gender"
    INCOME = "income"
    HEALTH = "health"
    FINANCIAL = "financial"
    SSN = "ssn"
    DOB = "date_of_birth"
    ETHNICITY = "ethnicity"
    RELIGION = "religion"
    POLITICAL = "political"
    BIOMETRIC = "biometric"
    IP_ADDRESS = "ip_address"
    DEVICE_ID = "device_id"


# Quasi-identifier sets that together may uniquely identify
# Based on Sweeney (2000): 87% of US population uniquely identified
# by zip + gender + date_of_birth
_QUASI_ID_SETS: list[frozenset[str]] = [
    frozenset({PIICategory.LOCATION, PIICategory.GENDER, PIICategory.DOB}),
    frozenset({PIICategory.LOCATION, PIICategory.AGE, PIICategory.OCCUPATION}),
    frozenset({PIICategory.EMPLOYER, PIICategory.OCCUPATION, PIICategory.LOCATION}),
    frozenset({PIICategory.NAME, PIICategory.LOCATION}),
    frozenset({PIICategory.NAME, PIICategory.EMPLOYER}),
    frozenset({PIICategory.EMAIL}),
    frozenset({PIICategory.PHONE}),
    frozenset({PIICategory.SSN}),
]

# Minimum PII categories to trigger accumulation alert
_MIN_PII_ACCUMULATION = 3

# Patterns that hint at PII categories in tool names/args/results
_PII_HEURISTICS: list[tuple[str, re.Pattern[str]]] = [
    (PIICategory.NAME, re.compile(r"(?:name|full_name|display_name|real_name)", re.IGNORECASE)),
    (PIICategory.EMAIL, re.compile(r"(?:email|e-mail|mail_addr)", re.IGNORECASE)),
    (PIICategory.PHONE, re.compile(r"(?:phone|tel|mobile|cell)", re.IGNORECASE)),
    (PIICategory.ADDRESS, re.compile(r"(?:address|street|postal|zip_code)", re.IGNORECASE)),
    (
        PIICategory.LOCATION,
        re.compile(r"(?:location|city|country|region|geo|lat|lng)", re.IGNORECASE),
    ),
    (PIICategory.EMPLOYER, re.compile(r"(?:employer|company|org|workplace)", re.IGNORECASE)),
    (PIICategory.OCCUPATION, re.compile(r"(?:occupation|role|title|position|job)", re.IGNORECASE)),
    (PIICategory.AGE, re.compile(r"(?:^age$|birth_year|year_of_birth)", re.IGNORECASE)),
    (PIICategory.GENDER, re.compile(r"(?:gender|sex)", re.IGNORECASE)),
    (PIICategory.INCOME, re.compile(r"(?:income|salary|wage|earnings)", re.IGNORECASE)),
    (PIICategory.HEALTH, re.compile(r"(?:health|medical|diagnosis|condition)", re.IGNORECASE)),
    (PIICategory.FINANCIAL, re.compile(r"(?:bank|account|credit|debit|payment)", re.IGNORECASE)),
    (PIICategory.SSN, re.compile(r"(?:ssn|social_security|national_id)", re.IGNORECASE)),
    (PIICategory.DOB, re.compile(r"(?:dob|date_of_birth|birthday|birth_date)", re.IGNORECASE)),
    (PIICategory.IP_ADDRESS, re.compile(r"(?:ip_addr|ip_address|remote_addr)", re.IGNORECASE)),
    (
        PIICategory.DEVICE_ID,
        re.compile(r"(?:device_id|hardware_id|machine_id|uuid)", re.IGNORECASE),
    ),
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class _Observation:
    """Internal record of a tool call observation."""

    tool_name: str
    arguments: dict[str, Any]
    result: str
    timestamp: float
    detected_pii: set[str]
    subject_id: str  # entity being queried about


@dataclass(frozen=True)
class PrivacyFinding:
    """A detected privacy inference risk.

    Attributes:
        category: Detection category.
        severity: ``"critical"``, ``"high"``, ``"medium"``, or ``"low"``.
        description: Human-readable description.
        pii_categories: PII categories involved.
        tools_involved: Tool names that contributed.
        subject_id: The entity whose privacy is at risk.
        evidence: Supporting evidence.
    """

    category: str
    severity: str
    description: str
    pii_categories: frozenset[str] = frozenset()
    tools_involved: frozenset[str] = frozenset()
    subject_id: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class PrivacyReport:
    """Result of cross-tool privacy analysis.

    Attributes:
        findings: All privacy findings detected.
        observations_analyzed: Total observations analyzed.
        unique_subjects: Number of distinct entities observed.
        pii_categories_seen: All PII categories observed.
        generated_at: Unix timestamp.
    """

    findings: list[PrivacyFinding] = field(default_factory=list)
    observations_analyzed: int = 0
    unique_subjects: int = 0
    pii_categories_seen: set[str] = field(default_factory=set)
    generated_at: float = 0.0

    @property
    def clean(self) -> bool:
        return len(self.findings) == 0


# ---------------------------------------------------------------------------
# Subject ID extraction
# ---------------------------------------------------------------------------


def _extract_subject_id(arguments: dict[str, Any]) -> str:
    """Extract an entity identifier from tool arguments.

    Looks for common patterns: user_id, patient_id, entity_id, etc.
    """
    for key in ("user_id", "patient_id", "person_id", "entity_id", "subject_id", "id", "uid"):
        if key in arguments:
            return str(arguments[key])
    # Fallback: first string argument that looks like an ID
    for v in arguments.values():
        if isinstance(v, str) and len(v) < 64:
            return v
    return "unknown"


# ---------------------------------------------------------------------------
# PII detection helpers
# ---------------------------------------------------------------------------


def _detect_pii_categories(
    tool_name: str,
    arguments: dict[str, Any],
    result: str,
) -> set[str]:
    """Detect PII categories from tool name, arguments, and result."""
    categories: set[str] = set()
    text_to_scan = tool_name + " " + " ".join(str(k) for k in arguments)
    if result:
        text_to_scan += " " + result[:500]

    for category, pattern in _PII_HEURISTICS:
        if pattern.search(text_to_scan):
            categories.add(category)

    return categories


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class CrossToolPrivacyDetector:
    """Detects cross-tool privacy inference risks.

    Collects observations of tool calls and analyses whether
    combinations of calls could leak private information.

    Thread-safe.

    Args:
        min_pii_accumulation: Minimum PII categories to trigger
            accumulation alert.  Default 3.
        quasi_id_sets: Custom quasi-identifier sets.  If ``None``,
            uses built-in sets.
        profiling_window_s: Window in seconds for temporal correlation.
            Default 60.
        profiling_threshold: Number of PII-accessing calls within the
            window to flag as profiling.  Default 5.
    """

    def __init__(
        self,
        *,
        min_pii_accumulation: int = _MIN_PII_ACCUMULATION,
        quasi_id_sets: list[frozenset[str]] | None = None,
        profiling_window_s: float = 60.0,
        profiling_threshold: int = 5,
    ) -> None:
        self._min_pii = min_pii_accumulation
        self._quasi_sets = quasi_id_sets if quasi_id_sets is not None else list(_QUASI_ID_SETS)
        self._profiling_window = profiling_window_s
        self._profiling_threshold = profiling_threshold
        self._observations: list[_Observation] = []
        self._lock = threading.Lock()

    # -- observation ---------------------------------------------------------

    def observe(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result: str = "",
    ) -> set[str]:
        """Record a tool call observation.

        Returns the set of PII categories detected in this call.
        """
        pii = _detect_pii_categories(tool_name, arguments, result)
        subject = _extract_subject_id(arguments)

        obs = _Observation(
            tool_name=tool_name,
            arguments=arguments,
            result=result,
            timestamp=time.time(),
            detected_pii=pii,
            subject_id=subject,
        )
        with self._lock:
            self._observations.append(obs)
        return pii

    # -- analysis ------------------------------------------------------------

    def analyze(self) -> PrivacyReport:
        """Analyze all observations for cross-tool privacy risks."""
        with self._lock:
            observations = list(self._observations)

        if not observations:
            return PrivacyReport(generated_at=time.time())

        findings: list[PrivacyFinding] = []

        by_subject: dict[str, list[_Observation]] = defaultdict(list)
        for obs in observations:
            by_subject[obs.subject_id].append(obs)

        all_pii: set[str] = set()
        for obs in observations:
            all_pii.update(obs.detected_pii)

        findings.extend(self._detect_pii_accumulation(by_subject))
        findings.extend(self._detect_quasi_identifiers(by_subject))
        findings.extend(self._detect_temporal_profiling(by_subject))
        findings.extend(self._detect_cross_reference(by_subject))

        return PrivacyReport(
            findings=findings,
            observations_analyzed=len(observations),
            unique_subjects=len(by_subject),
            pii_categories_seen=all_pii,
            generated_at=time.time(),
        )

    def reset(self) -> None:
        """Clear all observations."""
        with self._lock:
            self._observations.clear()

    # -- detection methods ---------------------------------------------------

    def _detect_pii_accumulation(
        self,
        by_subject: dict[str, list[_Observation]],
    ) -> list[PrivacyFinding]:
        """Detect when too many PII categories accumulate for one subject."""
        findings: list[PrivacyFinding] = []

        for subject_id, obs_list in by_subject.items():
            accumulated: set[str] = set()
            tools: set[str] = set()
            for obs in obs_list:
                accumulated.update(obs.detected_pii)
                if obs.detected_pii:
                    tools.add(obs.tool_name)

            if len(accumulated) >= self._min_pii:
                findings.append(
                    PrivacyFinding(
                        category="pii_accumulation",
                        severity="high" if len(accumulated) >= 5 else "medium",
                        description=(
                            f"Subject '{subject_id}': {len(accumulated)} PII categories "
                            f"accumulated across {len(tools)} tools"
                        ),
                        pii_categories=frozenset(accumulated),
                        tools_involved=frozenset(tools),
                        subject_id=subject_id,
                        evidence={
                            "categories": sorted(accumulated),
                            "tool_count": len(tools),
                        },
                    )
                )

        return findings

    def _detect_quasi_identifiers(
        self,
        by_subject: dict[str, list[_Observation]],
    ) -> list[PrivacyFinding]:
        """Detect quasi-identifier combinations that may uniquely identify."""
        findings: list[PrivacyFinding] = []

        for subject_id, obs_list in by_subject.items():
            accumulated: set[str] = set()
            tools: set[str] = set()
            for obs in obs_list:
                accumulated.update(obs.detected_pii)
                if obs.detected_pii:
                    tools.add(obs.tool_name)

            for qi_set in self._quasi_sets:
                if qi_set.issubset(accumulated):
                    findings.append(
                        PrivacyFinding(
                            category="quasi_identifier",
                            severity="critical" if len(qi_set) <= 2 else "high",
                            description=(
                                f"Subject '{subject_id}': quasi-identifier set "
                                f"{sorted(qi_set)} fully collected — "
                                f"may uniquely identify individual"
                            ),
                            pii_categories=frozenset(qi_set),
                            tools_involved=frozenset(tools),
                            subject_id=subject_id,
                            evidence={
                                "quasi_set": sorted(qi_set),
                                "all_categories": sorted(accumulated),
                            },
                        )
                    )

        return findings

    def _detect_temporal_profiling(
        self,
        by_subject: dict[str, list[_Observation]],
    ) -> list[PrivacyFinding]:
        """Detect rapid sequential PII queries (systematic profiling)."""
        findings: list[PrivacyFinding] = []

        for subject_id, obs_list in by_subject.items():
            pii_obs = [o for o in obs_list if o.detected_pii]
            if len(pii_obs) < self._profiling_threshold:
                continue

            # Check sliding window
            sorted_obs = sorted(pii_obs, key=lambda o: o.timestamp)
            for i in range(len(sorted_obs)):
                window_end = sorted_obs[i].timestamp + self._profiling_window
                window_obs = [o for o in sorted_obs[i:] if o.timestamp <= window_end]
                if len(window_obs) >= self._profiling_threshold:
                    tools = {o.tool_name for o in window_obs}
                    categories = set()
                    for o in window_obs:
                        categories.update(o.detected_pii)
                    findings.append(
                        PrivacyFinding(
                            category="temporal_profiling",
                            severity="high",
                            description=(
                                f"Subject '{subject_id}': {len(window_obs)} "
                                f"PII-accessing calls within "
                                f"{self._profiling_window}s window"
                            ),
                            pii_categories=frozenset(categories),
                            tools_involved=frozenset(tools),
                            subject_id=subject_id,
                            evidence={
                                "calls_in_window": len(window_obs),
                                "window_seconds": self._profiling_window,
                                "categories": sorted(categories),
                            },
                        )
                    )
                    break  # One finding per subject is enough

        return findings

    def _detect_cross_reference(
        self,
        by_subject: dict[str, list[_Observation]],
    ) -> list[PrivacyFinding]:
        """Detect cross-tool information joining.

        Flags when the same subject's data is accessed by multiple tools
        where each tool provides different PII categories — indicating
        potential cross-reference to build a richer profile.
        """
        findings: list[PrivacyFinding] = []

        for subject_id, obs_list in by_subject.items():
            tool_pii: dict[str, set[str]] = defaultdict(set)
            for obs in obs_list:
                if obs.detected_pii:
                    tool_pii[obs.tool_name].update(obs.detected_pii)

            if len(tool_pii) < 2:
                continue

            # Check if different tools provide non-overlapping PII
            tools = list(tool_pii.keys())
            for i in range(len(tools)):
                for j in range(i + 1, len(tools)):
                    pii_a = tool_pii[tools[i]]
                    pii_b = tool_pii[tools[j]]
                    unique_a = pii_a - pii_b
                    unique_b = pii_b - pii_a
                    if unique_a and unique_b:
                        combined = pii_a | pii_b
                        findings.append(
                            PrivacyFinding(
                                category="cross_reference",
                                severity="medium",
                                description=(
                                    f"Subject '{subject_id}': tools "
                                    f"'{tools[i]}' and '{tools[j]}' provide "
                                    f"complementary PII ({len(combined)} categories "
                                    f"combined)"
                                ),
                                pii_categories=frozenset(combined),
                                tools_involved=frozenset({tools[i], tools[j]}),
                                subject_id=subject_id,
                                evidence={
                                    "tool_a": tools[i],
                                    "tool_a_pii": sorted(pii_a),
                                    "tool_b": tools[j],
                                    "tool_b_pii": sorted(pii_b),
                                    "unique_from_join": sorted(unique_a | unique_b),
                                },
                            )
                        )

        return findings
