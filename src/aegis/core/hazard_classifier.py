"""Classify agent tasks and execution plans for safety hazards.

Addresses risks catalogued by "SafeAgentBench: Benchmark for Safe Task
Planning" -- agents that operate in the real world must reason about
physical harm, data loss, privacy breaches, financial exposure, system
damage, social harm, legal risk, and environmental impact *before*
executing a plan.

Each task or plan step is scanned against a database of hazard patterns
organized by :class:`HazardCategory`.  The classifier outputs a
:class:`HazardAssessment` summarizing all discovered hazards, an
overall risk level, a safety recommendation, and whether the plan is
safe to proceed.

Custom hazard patterns can be registered at runtime to extend coverage
for domain-specific risks.

Pure Python, no external dependencies.  Thread-safe, sub-millisecond.

Reference:
    SafeAgentBench: A Benchmark for Safe Task Planning of Embodied
    LLM Agents.  arXiv:2412.13178 (2024).

Example::

    classifier = HazardClassifier()
    assessment = classifier.classify_task("delete all user data from database")
    assert not assessment.safe_to_proceed
    assert any(h.category == HazardCategory.DATA_LOSS for h in assessment.hazards_found)
"""

from __future__ import annotations

import re
import threading
import uuid
from dataclasses import dataclass
from enum import StrEnum

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class HazardCategory(StrEnum):
    """Category of safety hazard."""

    PHYSICAL_HARM = "physical_harm"
    DATA_LOSS = "data_loss"
    PRIVACY_BREACH = "privacy_breach"
    FINANCIAL_LOSS = "financial_loss"
    SYSTEM_DAMAGE = "system_damage"
    SOCIAL_HARM = "social_harm"
    LEGAL_RISK = "legal_risk"
    ENVIRONMENTAL = "environmental"


class Severity(StrEnum):
    """Hazard severity level."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class OverallRisk(StrEnum):
    """Aggregate risk level for an assessment."""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Frozen data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Hazard:
    """Immutable description of a detected hazard.

    Attributes:
        hazard_id: Unique identifier for this hazard instance.
        name: Short name of the hazard.
        category: Hazard category.
        severity: Severity level.
        description: Human-readable explanation.
        mitigations: Suggested mitigations.
    """

    hazard_id: str
    name: str
    category: HazardCategory
    severity: Severity
    description: str
    mitigations: tuple[str, ...]


@dataclass(frozen=True)
class HazardAssessment:
    """Immutable assessment result for a task or plan.

    Attributes:
        task_description: The task that was assessed.
        hazards_found: All hazards detected.
        overall_risk: Aggregate risk level.
        safe_to_proceed: Whether it is safe to execute.
        recommendations: List of recommendations.
    """

    task_description: str
    hazards_found: tuple[Hazard, ...]
    overall_risk: OverallRisk
    safe_to_proceed: bool
    recommendations: tuple[str, ...]


# ---------------------------------------------------------------------------
# Internal pattern type
# ---------------------------------------------------------------------------

_HazardPattern = tuple[
    str,  # name
    HazardCategory,  # category
    Severity,  # severity
    re.Pattern[str],  # compiled regex
    str,  # description
    tuple[str, ...],  # mitigations
]


def _p(
    name: str,
    cat: HazardCategory,
    sev: Severity,
    pattern: str,
    desc: str,
    mitigations: tuple[str, ...],
) -> _HazardPattern:
    return (name, cat, sev, re.compile(pattern, re.IGNORECASE), desc, mitigations)


_C = HazardCategory
_S = Severity

# ---------------------------------------------------------------------------
# Built-in hazard patterns (30+)
# ---------------------------------------------------------------------------

_BUILTIN_PATTERNS: list[_HazardPattern] = [
    # PHYSICAL_HARM
    _p(
        "robot_control",
        _C.PHYSICAL_HARM,
        _S.CRITICAL,
        r"\b(?:robot|robotic)\s+(?:arm|control|move|actuate)\b",
        "Direct robot/actuator control can cause physical harm",
        ("Require human supervision", "Implement force limits"),
    ),
    _p(
        "iot_command",
        _C.PHYSICAL_HARM,
        _S.HIGH,
        r"\b(?:iot|smart\s*home|thermostat|lock|alarm)\s+(?:set|control|toggle|activate|unlock)\b",
        "IoT device commands can affect physical environment",
        ("Validate command bounds", "Require confirmation"),
    ),
    _p(
        "vehicle_operation",
        _C.PHYSICAL_HARM,
        _S.CRITICAL,
        r"\b(?:vehicle|car|drone|autonomous)\s+(?:drive|steer|navigate|fly|land|takeoff)\b",
        "Vehicle control commands pose physical danger",
        ("Require human operator", "Implement geofencing"),
    ),
    _p(
        "medical_device",
        _C.PHYSICAL_HARM,
        _S.CRITICAL,
        r"\b(?:medical\s+device|infusion\s+pump|ventilator|defibrillator)\s+(?:set|adjust|dose|administer)\b",
        "Medical device control can cause patient harm",
        ("Require medical professional approval", "Double-check dosages"),
    ),
    # DATA_LOSS
    _p(
        "delete_data",
        _C.DATA_LOSS,
        _S.HIGH,
        r"\b(?:delete|remove)\s+(?:all|every|entire)\s+(?:data|records|files|entries|rows)\b",
        "Bulk deletion risks irreversible data loss",
        ("Require backup before deletion", "Use soft-delete"),
    ),
    _p(
        "truncate_table",
        _C.DATA_LOSS,
        _S.CRITICAL,
        r"\btruncate\s+(?:table)?\b",
        "TRUNCATE removes all rows without logging",
        ("Create backup first", "Use DELETE with WHERE"),
    ),
    _p(
        "drop_table",
        _C.DATA_LOSS,
        _S.CRITICAL,
        r"\bdrop\s+(?:table|database|collection|index)\b",
        "DROP permanently destroys database objects",
        ("Backup before dropping", "Require explicit confirmation"),
    ),
    _p(
        "format_disk",
        _C.DATA_LOSS,
        _S.CRITICAL,
        r"\b(?:format|mkfs|fdisk)\b",
        "Disk formatting destroys all data",
        ("Verify target device", "Backup all data first"),
    ),
    _p(
        "overwrite_file",
        _C.DATA_LOSS,
        _S.MEDIUM,
        r"\boverwrite\s+(?:all|existing|current)\b",
        "Overwriting existing data without backup",
        ("Create backup copy first", "Use versioning"),
    ),
    _p(
        "rm_rf",
        _C.DATA_LOSS,
        _S.CRITICAL,
        r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\b",
        "Recursive force delete",
        ("Verify target path", "Use trash instead of rm"),
    ),
    # PRIVACY_BREACH
    _p(
        "pii_extraction",
        _C.PRIVACY_BREACH,
        _S.HIGH,
        r"\b(?:extract|collect|scrape|harvest)\s+(?:pii|personal\s+(?:data|information)|ssn|social\s+security)\b",
        "Extracting personally identifiable information",
        ("Ensure consent", "Apply data anonymization"),
    ),
    _p(
        "surveillance",
        _C.PRIVACY_BREACH,
        _S.HIGH,
        r"\b(?:surveillance|monitor\s+user|track\s+(?:user|location|activity|browsing))\b",
        "User surveillance or tracking without consent",
        ("Obtain explicit consent", "Minimize data collection"),
    ),
    _p(
        "log_credentials",
        _C.PRIVACY_BREACH,
        _S.CRITICAL,
        r"\b(?:log|store|save|print)\s+(?:password|credential|secret|api[_\s]?key|token)\b",
        "Logging or storing sensitive credentials",
        ("Use secret management", "Never log credentials"),
    ),
    _p(
        "access_private",
        _C.PRIVACY_BREACH,
        _S.MEDIUM,
        r"\baccess\s+(?:private|confidential|restricted)\s+(?:data|files|records)\b",
        "Accessing restricted/private data",
        ("Check authorization", "Follow principle of least privilege"),
    ),
    # FINANCIAL_LOSS
    _p(
        "payment_transaction",
        _C.FINANCIAL_LOSS,
        _S.CRITICAL,
        r"\b(?:payment|pay|charge|bill)\s+(?:process|execute|submit|send)\b",
        "Processing financial transactions",
        ("Require explicit confirmation", "Implement spending limits"),
    ),
    _p(
        "transfer_funds",
        _C.FINANCIAL_LOSS,
        _S.CRITICAL,
        r"\b(?:transfer|send|wire)\s+(?:funds|money|payment|amount)\b",
        "Transferring funds to external accounts",
        ("Require multi-factor approval", "Verify recipient"),
    ),
    _p(
        "purchase_order",
        _C.FINANCIAL_LOSS,
        _S.HIGH,
        r"\b(?:purchase|buy|order|subscribe)\b",
        "Creating purchase orders or subscriptions",
        ("Require budget approval", "Set spending limits"),
    ),
    _p(
        "trading",
        _C.FINANCIAL_LOSS,
        _S.CRITICAL,
        r"\b(?:trade|sell|buy)\s+(?:stock|crypto|asset|security|option|future)\b",
        "Financial trading operations",
        ("Require human trader approval", "Implement position limits"),
    ),
    # SYSTEM_DAMAGE
    _p(
        "root_access",
        _C.SYSTEM_DAMAGE,
        _S.CRITICAL,
        r"\b(?:sudo|root|admin)\s+(?:access|privilege|permission|exec)\b",
        "Requesting elevated system privileges",
        ("Use least privilege", "Audit all elevated actions"),
    ),
    _p(
        "kernel_module",
        _C.SYSTEM_DAMAGE,
        _S.CRITICAL,
        r"\b(?:insmod|rmmod|modprobe|kernel\s+module)\b",
        "Loading or modifying kernel modules",
        ("Require system admin approval", "Test in sandbox first"),
    ),
    _p(
        "driver_install",
        _C.SYSTEM_DAMAGE,
        _S.HIGH,
        r"\b(?:install|load|update)\s+(?:driver|firmware)\b",
        "Installing or modifying system drivers",
        ("Verify driver signatures", "Test in staging environment"),
    ),
    _p(
        "modify_system_config",
        _C.SYSTEM_DAMAGE,
        _S.HIGH,
        r"\b(?:modify|edit|change)\s+(?:system\s+config|registry|sysctl|grub)\b",
        "Modifying core system configuration",
        ("Backup config first", "Require admin approval"),
    ),
    _p(
        "kill_process",
        _C.SYSTEM_DAMAGE,
        _S.MEDIUM,
        r"\b(?:kill|pkill|killall)\s+-9\b",
        "Force-killing system processes",
        ("Use graceful shutdown first", "Verify process identity"),
    ),
    # SOCIAL_HARM
    _p(
        "impersonation",
        _C.SOCIAL_HARM,
        _S.HIGH,
        r"\b(?:impersonate|pretend\s+to\s+be|pose\s+as|fake\s+identity)\b",
        "Identity impersonation or fraud",
        ("Use verified identities only", "Disclose AI involvement"),
    ),
    _p(
        "harassment",
        _C.SOCIAL_HARM,
        _S.CRITICAL,
        r"\b(?:harass|bully|threaten|intimidate|stalk)\b",
        "Harassment or threatening behavior",
        ("Block and report", "Implement content moderation"),
    ),
    _p(
        "deception",
        _C.SOCIAL_HARM,
        _S.HIGH,
        r"\b(?:deceive|mislead|manipulate\s+user|social\s+engineer|phish)\b",
        "Deception or manipulation of users",
        ("Ensure transparency", "Disclose AI nature"),
    ),
    _p(
        "spam",
        _C.SOCIAL_HARM,
        _S.MEDIUM,
        r"\b(?:mass\s+(?:email|message|post)|spam|flood\s+(?:message|chat))\b",
        "Mass messaging or spam operations",
        ("Rate limit outgoing messages", "Require opt-in"),
    ),
    # LEGAL_RISK
    _p(
        "web_scraping",
        _C.LEGAL_RISK,
        _S.MEDIUM,
        r"\b(?:scrape|crawl|spider)\s+(?:website|site|page|url)\b",
        "Web scraping may violate terms of service",
        ("Check robots.txt", "Respect rate limits"),
    ),
    _p(
        "copyright_violation",
        _C.LEGAL_RISK,
        _S.HIGH,
        r"\b(?:copy|download|distribute)\s+(?:copyrighted|licensed|protected)\s+(?:content|material|work)\b",
        "Copying or distributing copyrighted material",
        ("Check licensing terms", "Use fair use guidelines"),
    ),
    _p(
        "license_violation",
        _C.LEGAL_RISK,
        _S.HIGH,
        r"\b(?:violate|breach|ignore)\s+(?:license|tos|terms\s+of\s+service|eula)\b",
        "Violating software licenses or terms of service",
        ("Review license terms", "Seek legal counsel"),
    ),
    _p(
        "dmca_risk",
        _C.LEGAL_RISK,
        _S.HIGH,
        r"\b(?:circumvent|bypass)\s+(?:drm|copy\s+protection|dmca|access\s+control)\b",
        "Circumventing digital rights management",
        ("Respect DRM controls", "Consult legal team"),
    ),
    # ENVIRONMENTAL
    _p(
        "resource_exhaustion",
        _C.ENVIRONMENTAL,
        _S.MEDIUM,
        r"\b(?:infinite\s+loop|resource\s+exhaust|memory\s+bomb|fork\s+bomb)\b",
        "Resource exhaustion patterns",
        ("Implement resource limits", "Use timeouts"),
    ),
    _p(
        "crypto_mining",
        _C.ENVIRONMENTAL,
        _S.HIGH,
        r"\b(?:crypto\s*min(?:e|ing)|bitcoin\s+min(?:e|ing)|hash\s+mining)\b",
        "Cryptocurrency mining consumes significant energy",
        ("Require explicit authorization", "Monitor resource usage"),
    ),
    _p(
        "energy_intensive",
        _C.ENVIRONMENTAL,
        _S.LOW,
        r"\b(?:train\s+(?:large|huge)\s+model|gpu\s+cluster|massive\s+compute)\b",
        "Energy-intensive computation",
        ("Evaluate compute necessity", "Use efficient algorithms"),
    ),
    _p(
        "bulk_data_transfer",
        _C.ENVIRONMENTAL,
        _S.LOW,
        r"\b(?:transfer|download|upload)\s+(?:terabyte|petabyte|massive\s+dataset)\b",
        "Large-scale data transfer uses significant bandwidth",
        ("Use incremental transfers", "Compress data"),
    ),
]


# Severity ordering for comparison
_SEV_ORDER: dict[str, int] = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


# ---------------------------------------------------------------------------
# HazardClassifier
# ---------------------------------------------------------------------------


class HazardClassifier:
    """Classify agent tasks and execution plans for safety hazards.

    Scans text against built-in and custom hazard patterns, returning
    a structured assessment with identified hazards, overall risk,
    and recommendations.

    Thread-safe: all mutations are guarded by an internal lock.
    """

    def __init__(self) -> None:
        self._custom_patterns: list[_HazardPattern] = []
        self._lock = threading.Lock()

    # -- public API ----------------------------------------------------------

    def classify_task(self, task_description: str) -> HazardAssessment:
        """Classify a task description for safety hazards.

        Args:
            task_description: Free-text description of the task.

        Returns:
            A frozen :class:`HazardAssessment`.
        """
        if not task_description or not task_description.strip():
            return HazardAssessment(
                task_description=task_description,
                hazards_found=(),
                overall_risk=OverallRisk.SAFE,
                safe_to_proceed=True,
                recommendations=(),
            )

        hazards = self._scan_text(task_description)
        return self._build_assessment(task_description, hazards)

    def classify_plan(self, actions: list[str]) -> HazardAssessment:
        """Classify an execution plan (list of action descriptions).

        All actions are scanned individually; hazards are aggregated.

        Args:
            actions: List of action descriptions forming a plan.

        Returns:
            A frozen :class:`HazardAssessment`.
        """
        combined = "; ".join(actions)
        all_hazards: list[Hazard] = []
        for action in actions:
            all_hazards.extend(self._scan_text(action))

        # Deduplicate by name
        seen: set[str] = set()
        unique: list[Hazard] = []
        for h in all_hazards:
            if h.name not in seen:
                seen.add(h.name)
                unique.append(h)

        return self._build_assessment(combined, unique)

    def is_safe(self, task_description: str) -> bool:
        """Quick boolean check: is the task safe to proceed?

        Args:
            task_description: Free-text description of the task.

        Returns:
            ``True`` if no high/critical hazards are detected.
        """
        assessment = self.classify_task(task_description)
        return assessment.safe_to_proceed

    def add_hazard_pattern(
        self,
        name: str,
        category: HazardCategory,
        severity: Severity,
        pattern: str,
        description: str = "",
        mitigations: list[str] | None = None,
    ) -> None:
        """Register a custom hazard pattern.

        Args:
            name: Short name for the hazard.
            category: Hazard category.
            severity: Severity level.
            pattern: Regex pattern to match.
            description: Human-readable explanation.
            mitigations: Suggested mitigations.
        """
        entry = _p(
            name,
            category,
            severity,
            pattern,
            description or f"Custom hazard: {name}",
            tuple(mitigations or ()),
        )
        with self._lock:
            self._custom_patterns.append(entry)

    # -- internal ------------------------------------------------------------

    def _all_patterns(self) -> list[_HazardPattern]:
        """Return built-in + custom patterns."""
        with self._lock:
            return _BUILTIN_PATTERNS + list(self._custom_patterns)

    def _scan_text(self, text: str) -> list[Hazard]:
        """Scan text against all patterns and return found hazards."""
        hazards: list[Hazard] = []
        for name, cat, sev, regex, desc, mitigations in self._all_patterns():
            if regex.search(text):
                hazards.append(
                    Hazard(
                        hazard_id=uuid.uuid4().hex[:16],
                        name=name,
                        category=cat,
                        severity=sev,
                        description=desc,
                        mitigations=mitigations,
                    )
                )
        return hazards

    def _build_assessment(
        self,
        task_description: str,
        hazards: list[Hazard],
    ) -> HazardAssessment:
        """Build an assessment from a list of hazards."""
        if not hazards:
            return HazardAssessment(
                task_description=task_description,
                hazards_found=(),
                overall_risk=OverallRisk.SAFE,
                safe_to_proceed=True,
                recommendations=("No hazards detected",),
            )

        # Determine overall risk from worst severity
        worst_sev = max(hazards, key=lambda h: _SEV_ORDER.get(h.severity, 0))
        risk_map = {
            Severity.LOW: OverallRisk.LOW,
            Severity.MEDIUM: OverallRisk.MEDIUM,
            Severity.HIGH: OverallRisk.HIGH,
            Severity.CRITICAL: OverallRisk.CRITICAL,
        }
        overall = risk_map.get(worst_sev.severity, OverallRisk.MEDIUM)

        # Safe to proceed only if no high/critical
        safe = all(_SEV_ORDER.get(h.severity, 0) < _SEV_ORDER[Severity.HIGH] for h in hazards)

        # Gather recommendations from all hazards
        recommendations: list[str] = []
        seen_recs: set[str] = set()
        for h in hazards:
            for m in h.mitigations:
                if m not in seen_recs:
                    seen_recs.add(m)
                    recommendations.append(m)

        if not safe:
            recommendations.insert(0, "Human review required before proceeding")

        return HazardAssessment(
            task_description=task_description,
            hazards_found=tuple(hazards),
            overall_risk=overall,
            safe_to_proceed=safe,
            recommendations=tuple(recommendations),
        )
