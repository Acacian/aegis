"""Threat Taxonomy -- comprehensive threat categorization for agentic AI.

Provides a structured threat database covering OWASP Agentic Security
Initiative (ASI01-ASI10) categories plus additional academic threat
vectors.  Actions can be assessed against the taxonomy to identify
applicable threats and recommended mitigations.

Thread-safe via :class:`threading.Lock`.  Pure Python, no external deps.

References:
- "Agentic AI Security: Threats, Defenses, Evaluation"
  (arXiv:2510.23883)
- OWASP Agentic AI Threats ASI: https://owasp.org/www-project-agentic-ai-threats/
- MITRE ATLAS: https://atlas.mitre.org/
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import StrEnum

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ThreatCategory(StrEnum):
    """Threat categories covering OWASP ASI + academic threats."""

    # OWASP ASI categories
    EXCESSIVE_AGENCY = "excessive_agency"  # ASI01
    SUPPLY_CHAIN = "supply_chain"  # ASI02
    INSECURE_OUTPUT = "insecure_output"  # ASI03
    TOOL_MISUSE = "tool_misuse"  # ASI04
    MEMORY_POISONING = "memory_poisoning"  # ASI05
    PROMPT_INJECTION = "prompt_injection"  # ASI06
    MULTI_AGENT_MANIPULATION = "multi_agent_manipulation"  # ASI07
    CASCADING_FAILURES = "cascading_failures"  # ASI08
    TRUST_BOUNDARY = "trust_boundary"  # ASI09
    ROGUE_AGENT = "rogue_agent"  # ASI10

    # Academic threat categories
    REWARD_HACKING = "reward_hacking"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    GOAL_MISALIGNMENT = "goal_misalignment"
    DECEPTIVE_ALIGNMENT = "deceptive_alignment"
    ADVERSARIAL_ROBUSTNESS = "adversarial_robustness"


class ThreatSeverity(StrEnum):
    """Severity levels for threats."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MitigationStatus(StrEnum):
    """Implementation status of a mitigation."""

    NOT_IMPLEMENTED = "not_implemented"
    PLANNED = "planned"
    PARTIAL = "partial"
    IMPLEMENTED = "implemented"


# ---------------------------------------------------------------------------
# Frozen data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Threat:
    """Immutable record of a known threat."""

    id: str
    name: str
    category: ThreatCategory
    severity: ThreatSeverity
    owasp_id: str
    mitre_id: str
    description: str
    mitigations: tuple[str, ...] = ()


@dataclass(frozen=True)
class ThreatMitigation:
    """Immutable record of a mitigation strategy."""

    id: str
    name: str
    threat_ids: tuple[str, ...]
    description: str
    implementation_status: MitigationStatus = MitigationStatus.NOT_IMPLEMENTED


@dataclass(frozen=True)
class ThreatAssessment:
    """Result of assessing an action against the threat taxonomy."""

    threats_found: tuple[Threat, ...]
    risk_score: float  # 0.0 to 1.0
    recommendations: tuple[str, ...]
    assessed_at: float = field(default_factory=time.monotonic)


@dataclass(frozen=True)
class CoverageReport:
    """Report on mitigation coverage across the threat taxonomy."""

    total_threats: int
    mitigated_threats: int
    unmitigated_threats: int
    coverage_ratio: float
    threat_coverage: dict[str, list[str]]  # threat_id -> mitigation_ids
    generated_at: float = field(default_factory=time.monotonic)


# ---------------------------------------------------------------------------
# Built-in threat database (20+ threats covering OWASP ASI01-ASI10)
# ---------------------------------------------------------------------------

_BUILTIN_THREATS: tuple[Threat, ...] = (
    # ASI01: Excessive Agency
    Threat(
        id="T001",
        name="Unrestricted Tool Access",
        category=ThreatCategory.EXCESSIVE_AGENCY,
        severity=ThreatSeverity.CRITICAL,
        owasp_id="ASI01",
        mitre_id="AML.T0048",
        description="Agent granted access to tools beyond what is required for its task.",
        mitigations=("M001", "M002"),
    ),
    Threat(
        id="T002",
        name="Uncapped Autonomy",
        category=ThreatCategory.EXCESSIVE_AGENCY,
        severity=ThreatSeverity.HIGH,
        owasp_id="ASI01",
        mitre_id="AML.T0048",
        description="Agent operates without autonomy level constraints or human oversight.",
        mitigations=("M001", "M003"),
    ),
    # ASI02: Supply Chain
    Threat(
        id="T003",
        name="Malicious Plugin",
        category=ThreatCategory.SUPPLY_CHAIN,
        severity=ThreatSeverity.CRITICAL,
        owasp_id="ASI02",
        mitre_id="AML.T0010",
        description="Compromised or malicious third-party plugin injected into agent pipeline.",
        mitigations=("M004",),
    ),
    Threat(
        id="T004",
        name="Dependency Confusion",
        category=ThreatCategory.SUPPLY_CHAIN,
        severity=ThreatSeverity.HIGH,
        owasp_id="ASI02",
        mitre_id="AML.T0010",
        description="Agent loads a dependency from an untrusted source with a name collision.",
        mitigations=("M004", "M005"),
    ),
    # ASI03: Insecure Output
    Threat(
        id="T005",
        name="Code Injection via Output",
        category=ThreatCategory.INSECURE_OUTPUT,
        severity=ThreatSeverity.CRITICAL,
        owasp_id="ASI03",
        mitre_id="AML.T0043",
        description="Agent output contains executable code that is run without sanitization.",
        mitigations=("M006",),
    ),
    # ASI04: Tool Misuse
    Threat(
        id="T006",
        name="Unintended API Call",
        category=ThreatCategory.TOOL_MISUSE,
        severity=ThreatSeverity.HIGH,
        owasp_id="ASI04",
        mitre_id="AML.T0040",
        description="Agent invokes an API with parameters that cause unintended side effects.",
        mitigations=("M001", "M007"),
    ),
    Threat(
        id="T007",
        name="Destructive File Operation",
        category=ThreatCategory.TOOL_MISUSE,
        severity=ThreatSeverity.CRITICAL,
        owasp_id="ASI04",
        mitre_id="AML.T0040",
        description="Agent executes file deletion, overwrite, or corruption operations.",
        mitigations=("M001", "M008"),
    ),
    # ASI05: Memory Poisoning
    Threat(
        id="T008",
        name="Context Window Poisoning",
        category=ThreatCategory.MEMORY_POISONING,
        severity=ThreatSeverity.HIGH,
        owasp_id="ASI05",
        mitre_id="AML.T0019",
        description="Adversary injects misleading content into the agent's persistent memory.",
        mitigations=("M009",),
    ),
    Threat(
        id="T009",
        name="RAG Index Tampering",
        category=ThreatCategory.MEMORY_POISONING,
        severity=ThreatSeverity.HIGH,
        owasp_id="ASI05",
        mitre_id="AML.T0019",
        description="Attacker modifies RAG index to alter agent behavior.",
        mitigations=("M009", "M010"),
    ),
    # ASI06: Prompt Injection
    Threat(
        id="T010",
        name="Direct Prompt Injection",
        category=ThreatCategory.PROMPT_INJECTION,
        severity=ThreatSeverity.CRITICAL,
        owasp_id="ASI06",
        mitre_id="AML.T0051",
        description="User-supplied input directly overrides system instructions.",
        mitigations=("M011",),
    ),
    Threat(
        id="T011",
        name="Indirect Prompt Injection",
        category=ThreatCategory.PROMPT_INJECTION,
        severity=ThreatSeverity.CRITICAL,
        owasp_id="ASI06",
        mitre_id="AML.T0051",
        description="External data source contains instructions that hijack agent behavior.",
        mitigations=("M011", "M012"),
    ),
    # ASI07: Multi-Agent Manipulation
    Threat(
        id="T012",
        name="Inter-Agent Instruction Injection",
        category=ThreatCategory.MULTI_AGENT_MANIPULATION,
        severity=ThreatSeverity.HIGH,
        owasp_id="ASI07",
        mitre_id="AML.T0048",
        description="Compromised agent sends crafted messages to manipulate peer agents.",
        mitigations=("M013", "M014"),
    ),
    Threat(
        id="T013",
        name="Delegation Chain Attack",
        category=ThreatCategory.MULTI_AGENT_MANIPULATION,
        severity=ThreatSeverity.HIGH,
        owasp_id="ASI07",
        mitre_id="AML.T0048",
        description="Attacker exploits agent delegation to escalate privileges across agents.",
        mitigations=("M013", "M015"),
    ),
    # ASI08: Cascading Failures
    Threat(
        id="T014",
        name="Error Propagation Chain",
        category=ThreatCategory.CASCADING_FAILURES,
        severity=ThreatSeverity.HIGH,
        owasp_id="ASI08",
        mitre_id="AML.T0048",
        description="A failing agent's errors propagate to downstream agents in a chain reaction.",
        mitigations=("M016",),
    ),
    # ASI09: Trust Boundary Violations
    Threat(
        id="T015",
        name="Cross-Boundary Data Leak",
        category=ThreatCategory.TRUST_BOUNDARY,
        severity=ThreatSeverity.CRITICAL,
        owasp_id="ASI09",
        mitre_id="AML.T0024",
        description="Agent passes sensitive data across trust boundaries without authorization.",
        mitigations=("M017", "M018"),
    ),
    Threat(
        id="T016",
        name="Implicit Trust Assumption",
        category=ThreatCategory.TRUST_BOUNDARY,
        severity=ThreatSeverity.MEDIUM,
        owasp_id="ASI09",
        mitre_id="AML.T0024",
        description="Agent treats data from untrusted sources as trusted without validation.",
        mitigations=("M017",),
    ),
    # ASI10: Rogue Agents
    Threat(
        id="T017",
        name="Goal Drift",
        category=ThreatCategory.ROGUE_AGENT,
        severity=ThreatSeverity.HIGH,
        owasp_id="ASI10",
        mitre_id="AML.T0048",
        description="Agent gradually deviates from its intended goal over extended operation.",
        mitigations=("M019", "M020"),
    ),
    Threat(
        id="T018",
        name="Resource Hoarding",
        category=ThreatCategory.ROGUE_AGENT,
        severity=ThreatSeverity.MEDIUM,
        owasp_id="ASI10",
        mitre_id="AML.T0048",
        description="Agent acquires and retains resources beyond its operational needs.",
        mitigations=("M001", "M019"),
    ),
    # Academic: Reward Hacking
    Threat(
        id="T019",
        name="Specification Gaming",
        category=ThreatCategory.REWARD_HACKING,
        severity=ThreatSeverity.HIGH,
        owasp_id="",
        mitre_id="AML.T0048",
        description=(
            "Agent exploits loopholes in its reward specification"
            " to maximize score without fulfilling intent."
        ),
        mitigations=("M019", "M020"),
    ),
    # Academic: Data Exfiltration
    Threat(
        id="T020",
        name="Covert Channel Exfiltration",
        category=ThreatCategory.DATA_EXFILTRATION,
        severity=ThreatSeverity.CRITICAL,
        owasp_id="",
        mitre_id="AML.T0024",
        description=(
            "Agent encodes sensitive data in seemingly benign outputs to exfiltrate information."
        ),
        mitigations=("M006", "M017"),
    ),
    # Academic: Privilege Escalation
    Threat(
        id="T021",
        name="Tool Chain Privilege Escalation",
        category=ThreatCategory.PRIVILEGE_ESCALATION,
        severity=ThreatSeverity.CRITICAL,
        owasp_id="",
        mitre_id="AML.T0040",
        description=(
            "Agent chains multiple low-privilege tools to achieve high-privilege operations."
        ),
        mitigations=("M001", "M015"),
    ),
    # Academic: Goal Misalignment
    Threat(
        id="T022",
        name="Instrumental Convergence",
        category=ThreatCategory.GOAL_MISALIGNMENT,
        severity=ThreatSeverity.HIGH,
        owasp_id="",
        mitre_id="",
        description=(
            "Agent develops instrumental sub-goals"
            " (self-preservation, resource acquisition)"
            " misaligned with user intent."
        ),
        mitigations=("M019", "M020"),
    ),
    # Academic: Deceptive Alignment
    Threat(
        id="T023",
        name="Sandbagging / Deceptive Compliance",
        category=ThreatCategory.DECEPTIVE_ALIGNMENT,
        severity=ThreatSeverity.CRITICAL,
        owasp_id="",
        mitre_id="",
        description=(
            "Agent appears aligned during evaluation but pursues"
            " different objectives in deployment."
        ),
        mitigations=("M019", "M020"),
    ),
    # Academic: Adversarial Robustness
    Threat(
        id="T024",
        name="Adversarial Input Perturbation",
        category=ThreatCategory.ADVERSARIAL_ROBUSTNESS,
        severity=ThreatSeverity.MEDIUM,
        owasp_id="",
        mitre_id="AML.T0043",
        description=(
            "Small perturbations in input cause the agent"
            " to produce drastically different outputs."
        ),
        mitigations=("M011", "M021"),
    ),
)


# ---------------------------------------------------------------------------
# Built-in mitigation database
# ---------------------------------------------------------------------------

_BUILTIN_MITIGATIONS: tuple[ThreatMitigation, ...] = (
    ThreatMitigation(
        id="M001",
        name="Least Privilege Enforcement",
        threat_ids=("T001", "T002", "T006", "T007", "T018", "T021"),
        description="Restrict agent permissions to the minimum required for each task.",
    ),
    ThreatMitigation(
        id="M002",
        name="Tool Allowlisting",
        threat_ids=("T001",),
        description="Maintain explicit allowlist of tools an agent may invoke.",
    ),
    ThreatMitigation(
        id="M003",
        name="Human-in-the-Loop Gating",
        threat_ids=("T002",),
        description="Require human approval for actions above a risk threshold.",
    ),
    ThreatMitigation(
        id="M004",
        name="Supply Chain Verification",
        threat_ids=("T003", "T004"),
        description="Verify integrity and provenance of all plugins and dependencies.",
    ),
    ThreatMitigation(
        id="M005",
        name="Dependency Pinning",
        threat_ids=("T004",),
        description="Pin all dependencies to verified versions with hash checks.",
    ),
    ThreatMitigation(
        id="M006",
        name="Output Sanitization",
        threat_ids=("T005", "T020"),
        description="Sanitize and validate all agent outputs before execution or display.",
    ),
    ThreatMitigation(
        id="M007",
        name="API Parameter Validation",
        threat_ids=("T006",),
        description="Validate API call parameters against expected schemas before execution.",
    ),
    ThreatMitigation(
        id="M008",
        name="Filesystem Sandboxing",
        threat_ids=("T007",),
        description="Restrict agent file operations to a sandboxed directory.",
    ),
    ThreatMitigation(
        id="M009",
        name="Memory Integrity Checking",
        threat_ids=("T008", "T009"),
        description="Validate integrity of persistent memory and RAG indexes before use.",
    ),
    ThreatMitigation(
        id="M010",
        name="RAG Source Authentication",
        threat_ids=("T009",),
        description="Authenticate and verify sources used in retrieval-augmented generation.",
    ),
    ThreatMitigation(
        id="M011",
        name="Prompt Injection Detection",
        threat_ids=("T010", "T011", "T024"),
        description="Detect and block prompt injection attempts in user and external inputs.",
    ),
    ThreatMitigation(
        id="M012",
        name="Data Source Isolation",
        threat_ids=("T011",),
        description="Isolate external data from system instructions using privilege separation.",
    ),
    ThreatMitigation(
        id="M013",
        name="Inter-Agent Authentication",
        threat_ids=("T012", "T013"),
        description="Require mutual authentication for all inter-agent communications.",
    ),
    ThreatMitigation(
        id="M014",
        name="Message Content Validation",
        threat_ids=("T012",),
        description="Validate and sanitize inter-agent messages for injection attempts.",
    ),
    ThreatMitigation(
        id="M015",
        name="Delegation Depth Limiting",
        threat_ids=("T013", "T021"),
        description="Limit delegation chain depth and enforce privilege non-escalation.",
    ),
    ThreatMitigation(
        id="M016",
        name="Circuit Breaker Pattern",
        threat_ids=("T014",),
        description="Implement circuit breakers to halt error propagation between agents.",
    ),
    ThreatMitigation(
        id="M017",
        name="Trust Boundary Enforcement",
        threat_ids=("T015", "T016", "T020"),
        description="Explicitly define and enforce trust boundaries for data flow.",
    ),
    ThreatMitigation(
        id="M018",
        name="Data Classification Tagging",
        threat_ids=("T015",),
        description="Tag data with sensitivity levels and enforce cross-boundary rules.",
    ),
    ThreatMitigation(
        id="M019",
        name="Behavioral Drift Detection",
        threat_ids=("T017", "T018", "T019", "T022", "T023"),
        description="Monitor agent behavior for deviations from established baselines.",
    ),
    ThreatMitigation(
        id="M020",
        name="Goal Alignment Auditing",
        threat_ids=("T017", "T019", "T022", "T023"),
        description="Periodically audit agent actions against stated goals and constraints.",
    ),
    ThreatMitigation(
        id="M021",
        name="Input Robustness Testing",
        threat_ids=("T024",),
        description="Test agent behavior with adversarially perturbed inputs.",
    ),
)


# ---------------------------------------------------------------------------
# Keyword → threat category mapping for action assessment
# ---------------------------------------------------------------------------

_ACTION_KEYWORDS: dict[str, list[ThreatCategory]] = {
    "execute": [ThreatCategory.TOOL_MISUSE, ThreatCategory.EXCESSIVE_AGENCY],
    "run": [ThreatCategory.TOOL_MISUSE, ThreatCategory.EXCESSIVE_AGENCY],
    "code": [ThreatCategory.INSECURE_OUTPUT, ThreatCategory.TOOL_MISUSE],
    "eval": [ThreatCategory.INSECURE_OUTPUT, ThreatCategory.PROMPT_INJECTION],
    "delete": [ThreatCategory.TOOL_MISUSE],
    "remove": [ThreatCategory.TOOL_MISUSE],
    "write": [ThreatCategory.TOOL_MISUSE, ThreatCategory.INSECURE_OUTPUT],
    "install": [ThreatCategory.SUPPLY_CHAIN],
    "download": [ThreatCategory.SUPPLY_CHAIN],
    "plugin": [ThreatCategory.SUPPLY_CHAIN],
    "import": [ThreatCategory.SUPPLY_CHAIN],
    "memory": [ThreatCategory.MEMORY_POISONING],
    "context": [ThreatCategory.MEMORY_POISONING, ThreatCategory.PROMPT_INJECTION],
    "prompt": [ThreatCategory.PROMPT_INJECTION],
    "inject": [ThreatCategory.PROMPT_INJECTION],
    "override": [ThreatCategory.PROMPT_INJECTION, ThreatCategory.PRIVILEGE_ESCALATION],
    "delegate": [ThreatCategory.MULTI_AGENT_MANIPULATION],
    "forward": [ThreatCategory.MULTI_AGENT_MANIPULATION, ThreatCategory.CASCADING_FAILURES],
    "agent": [ThreatCategory.MULTI_AGENT_MANIPULATION, ThreatCategory.ROGUE_AGENT],
    "chain": [ThreatCategory.CASCADING_FAILURES, ThreatCategory.PRIVILEGE_ESCALATION],
    "cascade": [ThreatCategory.CASCADING_FAILURES],
    "boundary": [ThreatCategory.TRUST_BOUNDARY],
    "cross": [ThreatCategory.TRUST_BOUNDARY],
    "sensitive": [ThreatCategory.DATA_EXFILTRATION, ThreatCategory.TRUST_BOUNDARY],
    "secret": [ThreatCategory.DATA_EXFILTRATION],
    "credential": [ThreatCategory.DATA_EXFILTRATION],
    "password": [ThreatCategory.DATA_EXFILTRATION],
    "exfiltrate": [ThreatCategory.DATA_EXFILTRATION],
    "escalate": [ThreatCategory.PRIVILEGE_ESCALATION],
    "privilege": [ThreatCategory.PRIVILEGE_ESCALATION],
    "admin": [ThreatCategory.PRIVILEGE_ESCALATION],
    "sudo": [ThreatCategory.PRIVILEGE_ESCALATION],
    "root": [ThreatCategory.PRIVILEGE_ESCALATION],
    "reward": [ThreatCategory.REWARD_HACKING],
    "goal": [ThreatCategory.GOAL_MISALIGNMENT],
    "alignment": [ThreatCategory.GOAL_MISALIGNMENT, ThreatCategory.DECEPTIVE_ALIGNMENT],
    "autonomous": [ThreatCategory.EXCESSIVE_AGENCY, ThreatCategory.ROGUE_AGENT],
    "unrestricted": [ThreatCategory.EXCESSIVE_AGENCY],
    "adversarial": [ThreatCategory.ADVERSARIAL_ROBUSTNESS],
    "perturb": [ThreatCategory.ADVERSARIAL_ROBUSTNESS],
}

_SEVERITY_SCORES: dict[ThreatSeverity, float] = {
    ThreatSeverity.LOW: 0.2,
    ThreatSeverity.MEDIUM: 0.4,
    ThreatSeverity.HIGH: 0.7,
    ThreatSeverity.CRITICAL: 1.0,
}


# ---------------------------------------------------------------------------
# ThreatTaxonomy
# ---------------------------------------------------------------------------


class ThreatTaxonomy:
    """Comprehensive threat categorization for agentic AI systems.

    Implements the threat taxonomy from "Agentic AI Security: Threats,
    Defenses, Evaluation" (arXiv:2510.23883).  Contains a built-in
    database of 24 threats covering all OWASP ASI01-ASI10 categories plus
    academic threat vectors (reward hacking, data exfiltration, privilege
    escalation, goal misalignment, deceptive alignment, adversarial
    robustness).  21 mitigations are mapped to these threats.

    Additional threats and mitigations can be registered at runtime.

    Args:
        include_builtin: Whether to load the built-in threat/mitigation
            databases on construction.
    """

    def __init__(self, include_builtin: bool = True) -> None:
        self._threats: dict[str, Threat] = {}
        self._mitigations: dict[str, ThreatMitigation] = {}
        self._lock = threading.Lock()

        if include_builtin:
            for t in _BUILTIN_THREATS:
                self._threats[t.id] = t
            for m in _BUILTIN_MITIGATIONS:
                self._mitigations[m.id] = m

    # -- registration API ---------------------------------------------------

    def register_threat(self, threat: Threat) -> None:
        """Register a custom threat."""
        with self._lock:
            self._threats[threat.id] = threat

    def register_mitigation(self, mitigation: ThreatMitigation) -> None:
        """Register a custom mitigation."""
        with self._lock:
            self._mitigations[mitigation.id] = mitigation

    def set_mitigation_status(self, mitigation_id: str, status: MitigationStatus) -> bool:
        """Update the implementation status of a mitigation.

        Returns ``True`` if the mitigation was found and updated.
        """
        with self._lock:
            old = self._mitigations.get(mitigation_id)
            if old is None:
                return False
            self._mitigations[mitigation_id] = ThreatMitigation(
                id=old.id,
                name=old.name,
                threat_ids=old.threat_ids,
                description=old.description,
                implementation_status=status,
            )
            return True

    # -- query API -----------------------------------------------------------

    def get_threat(self, threat_id: str) -> Threat | None:
        """Return a threat by ID, or ``None``."""
        with self._lock:
            return self._threats.get(threat_id)

    def get_threats_by_category(self, category: ThreatCategory) -> list[Threat]:
        """Return all threats in the given category."""
        with self._lock:
            return [t for t in self._threats.values() if t.category == category]

    def get_threats_by_owasp(self, owasp_id: str) -> list[Threat]:
        """Return all threats matching an OWASP ASI identifier."""
        with self._lock:
            return [t for t in self._threats.values() if t.owasp_id == owasp_id]

    def get_all_threats(self) -> list[Threat]:
        """Return all registered threats."""
        with self._lock:
            return list(self._threats.values())

    def get_mitigation(self, mitigation_id: str) -> ThreatMitigation | None:
        """Return a mitigation by ID, or ``None``."""
        with self._lock:
            return self._mitigations.get(mitigation_id)

    # -- assessment API ------------------------------------------------------

    def assess_action(
        self,
        action_description: str,
        *,
        categories: list[ThreatCategory] | None = None,
    ) -> ThreatAssessment:
        """Assess an action description against the threat taxonomy.

        Scans the action description for keyword matches to identify
        applicable threat categories, then returns all threats in those
        categories.  Optionally, the caller can specify explicit
        categories to check.

        Args:
            action_description: Human-readable description of the action.
            categories: Optional explicit categories to check.

        Returns:
            A :class:`ThreatAssessment` with found threats, risk score,
            and recommendations.
        """
        with self._lock:
            matched_categories: set[ThreatCategory] = set()

            if categories:
                matched_categories.update(categories)
            else:
                lower_desc = action_description.lower()
                for keyword, cats in _ACTION_KEYWORDS.items():
                    if keyword in lower_desc:
                        matched_categories.update(cats)

            # Collect matching threats
            found: list[Threat] = []
            for threat in self._threats.values():
                if threat.category in matched_categories:
                    found.append(threat)

            # Compute risk score (max severity of found threats)
            risk_score = 0.0
            if found:
                max_sev = max(_SEVERITY_SCORES.get(t.severity, 0.0) for t in found)
                # Scale by number of threats (more threats = higher risk)
                count_factor = min(len(found) / 10.0, 1.0)
                risk_score = max_sev * 0.7 + count_factor * 0.3

            # Generate recommendations
            recommendations = self._generate_recommendations(found)

            return ThreatAssessment(
                threats_found=tuple(found),
                risk_score=min(1.0, risk_score),
                recommendations=tuple(recommendations),
            )

    def get_mitigations(self, threat_ids: list[str]) -> list[ThreatMitigation]:
        """Get recommended mitigations for a set of threat IDs."""
        with self._lock:
            tid_set = set(threat_ids)
            result: list[ThreatMitigation] = []
            for m in self._mitigations.values():
                if tid_set.intersection(m.threat_ids):
                    result.append(m)
            return result

    def coverage_report(self) -> CoverageReport:
        """Show which threats have active mitigations in the system."""
        with self._lock:
            threat_coverage: dict[str, list[str]] = {tid: [] for tid in self._threats}

            for m in self._mitigations.values():
                if m.implementation_status in (
                    MitigationStatus.IMPLEMENTED,
                    MitigationStatus.PARTIAL,
                ):
                    for tid in m.threat_ids:
                        if tid in threat_coverage:
                            threat_coverage[tid].append(m.id)

            mitigated = sum(1 for mits in threat_coverage.values() if mits)
            total = len(threat_coverage)
            ratio = mitigated / total if total > 0 else 0.0

            return CoverageReport(
                total_threats=total,
                mitigated_threats=mitigated,
                unmitigated_threats=total - mitigated,
                coverage_ratio=ratio,
                threat_coverage=threat_coverage,
            )

    # -- internal helpers ---------------------------------------------------

    def _generate_recommendations(self, threats: list[Threat]) -> list[str]:
        """Generate mitigation recommendations for found threats."""
        recs: list[str] = []
        seen_mitigation_ids: set[str] = set()

        for threat in threats:
            for mid in threat.mitigations:
                if mid in seen_mitigation_ids:
                    continue
                seen_mitigation_ids.add(mid)
                m = self._mitigations.get(mid)
                if m is None:
                    continue
                if m.implementation_status == MitigationStatus.IMPLEMENTED:
                    continue  # Already handled
                recs.append(f"[{m.implementation_status.value}] {m.name}: {m.description}")

        if not recs and threats:
            recs.append("Review and implement mitigations for identified threats.")

        return recs
