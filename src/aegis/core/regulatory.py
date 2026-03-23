"""Regulatory Compliance Mapper.

Maps Aegis governance features to regulatory requirements, generates
compliance gap analysis, and produces auditor-ready documentation.

Supported frameworks:
- EU AI Act (Regulation (EU) 2024/1689)
- NIST AI RMF 1.0 (AI 100-1)
- SOC2 Trust Services Criteria
- ISO/IEC 42001:2023 (AI Management System)
- OWASP Top 10 for Agentic Applications (2025)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


def _html_escape(text: str) -> str:
    """Escape HTML special characters in *text*."""
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )


class RegulatoryFramework(Enum):
    """Supported regulatory and standards frameworks."""

    EU_AI_ACT = "eu_ai_act"
    NIST_AI_RMF = "nist_ai_rmf"
    SOC2 = "soc2"
    ISO_42001 = "iso_42001"
    OWASP_AGENTIC = "owasp_agentic"


@dataclass(frozen=True)
class ComplianceRequirement:
    """A single regulatory requirement from a framework.

    Attributes:
        framework: The regulatory framework this requirement belongs to.
        requirement_id: Unique identifier, e.g. ``"EU-AI-ACT-ART-12"``.
        title: Short human-readable title.
        description: Full description of the requirement.
        category: Thematic category (e.g. ``"logging"``, ``"transparency"``).
        mandatory: Whether compliance is legally required.
        deadline: Enforcement deadline in ``"YYYY-MM-DD"`` format, or *None*.
        penalty: Description of non-compliance penalties, or *None*.
    """

    framework: RegulatoryFramework
    requirement_id: str
    title: str
    description: str
    category: str
    mandatory: bool
    deadline: str | None = None
    penalty: str | None = None


@dataclass(frozen=True)
class FeatureMapping:
    """Maps an Aegis feature to a regulatory requirement.

    Attributes:
        requirement: The regulatory requirement being addressed.
        aegis_feature: Name of the Aegis feature that addresses it.
        coverage: ``"full"``, ``"partial"``, or ``"none"``.
        evidence_type: What evidence Aegis can generate for auditors.
        notes: Additional context about the mapping.
    """

    requirement: ComplianceRequirement
    aegis_feature: str
    coverage: str  # "full" | "partial" | "none"
    evidence_type: str
    notes: str


@dataclass(frozen=True)
class ComplianceGapAnalysis:
    """Results of a compliance gap analysis for a single framework.

    Attributes:
        framework: The framework analyzed.
        total_requirements: Total number of requirements in the framework.
        fully_covered: Requirements with ``"full"`` coverage.
        partially_covered: Requirements with ``"partial"`` coverage.
        not_covered: Requirements with ``"none"`` coverage.
        coverage_score: Percentage of requirements at least partially covered.
        mappings: All feature-to-requirement mappings.
        gaps: Requirements with no coverage at all.
        recommendations: Actionable recommendations to close gaps.
    """

    framework: RegulatoryFramework
    total_requirements: int
    fully_covered: int
    partially_covered: int
    not_covered: int
    coverage_score: float
    mappings: list[FeatureMapping]
    gaps: list[ComplianceRequirement]
    recommendations: list[str]


# ---------------------------------------------------------------------------
# Built-in requirement databases
# ---------------------------------------------------------------------------

_EU_AI_ACT_REQUIREMENTS: list[ComplianceRequirement] = [
    ComplianceRequirement(
        framework=RegulatoryFramework.EU_AI_ACT,
        requirement_id="EU-AI-ACT-ART-9",
        title="Risk Management System",
        description=(
            "Providers of high-risk AI systems shall establish, implement, document "
            "and maintain a risk management system. It shall be a continuous iterative "
            "process planned and run throughout the entire lifecycle of a high-risk AI "
            "system, requiring regular systematic review and updating."
        ),
        category="risk_management",
        mandatory=True,
        deadline="2026-08-02",
        penalty="Up to \u20ac35M or 7% of global annual turnover",
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.EU_AI_ACT,
        requirement_id="EU-AI-ACT-ART-10",
        title="Data and Data Governance",
        description=(
            "High-risk AI systems which make use of techniques involving the training "
            "of AI models with data shall be developed on the basis of training, "
            "validation and testing data sets that meet the quality criteria referred "
            "to in this Article. Training, validation and testing data sets shall be "
            "subject to data governance and management practices."
        ),
        category="data_governance",
        mandatory=True,
        deadline="2026-08-02",
        penalty="Up to \u20ac35M or 7% of global annual turnover",
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.EU_AI_ACT,
        requirement_id="EU-AI-ACT-ART-11",
        title="Technical Documentation",
        description=(
            "The technical documentation of a high-risk AI system shall be drawn up "
            "before that system is placed on the market or put into service and shall "
            "be kept up-to-date. It shall demonstrate that the high-risk AI system "
            "complies with the requirements set out in this Chapter."
        ),
        category="documentation",
        mandatory=True,
        deadline="2026-08-02",
        penalty="Up to \u20ac35M or 7% of global annual turnover",
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.EU_AI_ACT,
        requirement_id="EU-AI-ACT-ART-12",
        title="Record-keeping / Automatic Logging",
        description=(
            "High-risk AI systems shall technically allow for the automatic recording "
            "of events (logs) over the lifetime of the system. The logging capabilities "
            "shall ensure a level of traceability of the AI system's functioning that "
            "is appropriate to the intended purpose of the system."
        ),
        category="logging",
        mandatory=True,
        deadline="2026-08-02",
        penalty="Up to \u20ac35M or 7% of global annual turnover",
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.EU_AI_ACT,
        requirement_id="EU-AI-ACT-ART-13",
        title="Transparency and Provision of Information to Deployers",
        description=(
            "High-risk AI systems shall be designed and developed in such a way as to "
            "ensure that their operation is sufficiently transparent to enable deployers "
            "to interpret a system's output and use it appropriately. Instructions for "
            "use shall be provided in an appropriate digital format."
        ),
        category="transparency",
        mandatory=True,
        deadline="2026-08-02",
        penalty="Up to \u20ac35M or 7% of global annual turnover",
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.EU_AI_ACT,
        requirement_id="EU-AI-ACT-ART-14",
        title="Human Oversight",
        description=(
            "High-risk AI systems shall be designed and developed in such a way, "
            "including with appropriate human-machine interface tools, that they can "
            "be effectively overseen by natural persons during the period in which "
            "they are in use. Human oversight shall aim to minimise the risks to "
            "health, safety or fundamental rights."
        ),
        category="human_oversight",
        mandatory=True,
        deadline="2026-08-02",
        penalty="Up to \u20ac35M or 7% of global annual turnover",
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.EU_AI_ACT,
        requirement_id="EU-AI-ACT-ART-15",
        title="Accuracy, Robustness and Cybersecurity",
        description=(
            "High-risk AI systems shall be designed and developed in such a way that "
            "they achieve an appropriate level of accuracy, robustness and cybersecurity, "
            "and that they perform consistently in those respects throughout their "
            "lifecycle. The levels of accuracy and relevant accuracy metrics shall be "
            "declared in the accompanying instructions of use."
        ),
        category="robustness",
        mandatory=True,
        deadline="2026-08-02",
        penalty="Up to \u20ac35M or 7% of global annual turnover",
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.EU_AI_ACT,
        requirement_id="EU-AI-ACT-ART-16",
        title="Obligations of Providers of High-risk AI Systems",
        description=(
            "Providers of high-risk AI systems shall ensure that their systems are "
            "compliant with this Regulation. They shall have a quality management "
            "system in place, keep documentation, maintain logs automatically generated "
            "by their systems, and ensure conformity assessment is carried out."
        ),
        category="governance",
        mandatory=True,
        deadline="2026-08-02",
        penalty="Up to \u20ac35M or 7% of global annual turnover",
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.EU_AI_ACT,
        requirement_id="EU-AI-ACT-ART-17",
        title="Quality Management System",
        description=(
            "Providers of high-risk AI systems shall put a quality management system "
            "in place that ensures compliance with this Regulation. That system shall "
            "be documented in a systematic and orderly manner in the form of written "
            "policies, procedures and instructions, and shall include strategies for "
            "regulatory compliance."
        ),
        category="governance",
        mandatory=True,
        deadline="2026-08-02",
        penalty="Up to \u20ac35M or 7% of global annual turnover",
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.EU_AI_ACT,
        requirement_id="EU-AI-ACT-ART-26",
        title="Obligations of Deployers of High-risk AI Systems",
        description=(
            "Deployers of high-risk AI systems shall use such systems in accordance "
            "with the instructions of use, ensure human oversight is carried out by "
            "natural persons who have the necessary competence, training and authority, "
            "and monitor the operation of the high-risk AI system on the basis of the "
            "instructions of use."
        ),
        category="deployment",
        mandatory=True,
        deadline="2026-08-02",
        penalty="Up to \u20ac15M or 3% of global annual turnover",
    ),
]

_NIST_AI_RMF_REQUIREMENTS: list[ComplianceRequirement] = [
    ComplianceRequirement(
        framework=RegulatoryFramework.NIST_AI_RMF,
        requirement_id="NIST-GOVERN-1",
        title="Policies, Processes, Procedures, and Practices",
        description=(
            "Policies, processes, procedures, and practices across the organization "
            "related to the mapping, measuring, and managing of AI risks are in place, "
            "transparent, and implemented effectively."
        ),
        category="governance",
        mandatory=False,
        deadline=None,
        penalty=None,
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.NIST_AI_RMF,
        requirement_id="NIST-GOVERN-2",
        title="Accountability Structures",
        description=(
            "Accountability structures are in place so that the appropriate teams and "
            "individuals are empowered, responsible, and trained for mapping, measuring, "
            "and managing AI risks."
        ),
        category="governance",
        mandatory=False,
        deadline=None,
        penalty=None,
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.NIST_AI_RMF,
        requirement_id="NIST-MAP-1",
        title="Context is Established and Understood",
        description=(
            "Context is established and understood. The intended purpose, setting, "
            "deployment conditions, and the specific set of users of the AI system "
            "are defined and documented."
        ),
        category="context",
        mandatory=False,
        deadline=None,
        penalty=None,
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.NIST_AI_RMF,
        requirement_id="NIST-MAP-3",
        title="AI Benefits and Costs Assessed",
        description=(
            "AI capabilities, targeted usage, goals, and expected benefits and costs "
            "compared with appropriate benchmarks are understood."
        ),
        category="assessment",
        mandatory=False,
        deadline=None,
        penalty=None,
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.NIST_AI_RMF,
        requirement_id="NIST-MEASURE-1",
        title="Appropriate Methods and Metrics Identified",
        description=(
            "Appropriate methods and metrics are identified and applied to measure "
            "AI risks and trustworthiness characteristics."
        ),
        category="measurement",
        mandatory=False,
        deadline=None,
        penalty=None,
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.NIST_AI_RMF,
        requirement_id="NIST-MEASURE-2",
        title="AI Systems Evaluated",
        description=(
            "AI systems are evaluated for trustworthy characteristics on a regular "
            "basis, including after deployment. Mechanisms are in place to track and "
            "respond to changes in the AI system or its operating environment."
        ),
        category="measurement",
        mandatory=False,
        deadline=None,
        penalty=None,
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.NIST_AI_RMF,
        requirement_id="NIST-MANAGE-1",
        title="AI Risks Prioritized, Responded to, and Managed",
        description=(
            "AI risks based on assessments and other analytical output from the MAP "
            "and MEASURE functions are prioritized, responded to, and managed."
        ),
        category="risk_management",
        mandatory=False,
        deadline=None,
        penalty=None,
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.NIST_AI_RMF,
        requirement_id="NIST-MANAGE-2",
        title="Strategies to Maximize AI Benefits and Minimize Adverse Impacts",
        description=(
            "Strategies to maximize AI benefits and minimize negative impacts are "
            "planned, prepared, implemented, documented, and informed by input from "
            "relevant AI actors."
        ),
        category="risk_management",
        mandatory=False,
        deadline=None,
        penalty=None,
    ),
]

_SOC2_REQUIREMENTS: list[ComplianceRequirement] = [
    ComplianceRequirement(
        framework=RegulatoryFramework.SOC2,
        requirement_id="SOC2-CC6.1",
        title="Logical Access Security",
        description=(
            "The entity implements logical access security software, infrastructure, "
            "and architectures over protected information assets to protect them from "
            "security events to meet the entity's objectives."
        ),
        category="access_control",
        mandatory=True,
        deadline=None,
        penalty="Audit qualification; loss of SOC2 Type II attestation",
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.SOC2,
        requirement_id="SOC2-CC6.8",
        title="Unauthorized Access Prevention",
        description=(
            "The entity implements controls to prevent or detect and act upon the "
            "introduction of unauthorized or malicious software to meet the entity's "
            "objectives."
        ),
        category="access_control",
        mandatory=True,
        deadline=None,
        penalty="Audit qualification; loss of SOC2 Type II attestation",
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.SOC2,
        requirement_id="SOC2-CC7.2",
        title="System Monitoring",
        description=(
            "The entity monitors system components and the operation of those "
            "components for anomalies that are indicative of malicious acts, natural "
            "disasters, and errors affecting the entity's ability to meet its objectives; "
            "anomalies are analyzed to determine whether they represent security events."
        ),
        category="monitoring",
        mandatory=True,
        deadline=None,
        penalty="Audit qualification; loss of SOC2 Type II attestation",
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.SOC2,
        requirement_id="SOC2-CC8.1",
        title="Change Management",
        description=(
            "The entity authorizes, designs, develops or acquires, configures, "
            "documents, tests, approves, and implements changes to infrastructure, "
            "data, software, and procedures to meet its objectives."
        ),
        category="change_management",
        mandatory=True,
        deadline=None,
        penalty="Audit qualification; loss of SOC2 Type II attestation",
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.SOC2,
        requirement_id="SOC2-A1.2",
        title="Recovery Mechanisms",
        description=(
            "The entity authorizes, designs, develops or acquires, implements, "
            "operates, approves, maintains, and monitors environmental protections, "
            "software, data backup processes, and recovery infrastructure to meet "
            "its objectives."
        ),
        category="availability",
        mandatory=True,
        deadline=None,
        penalty="Audit qualification; loss of SOC2 Type II attestation",
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.SOC2,
        requirement_id="SOC2-PI1.1",
        title="Processing Integrity",
        description=(
            "The entity implements policies and procedures over system processing to "
            "result in products, services, and reporting to meet the entity's "
            "objectives. System processing is complete, valid, accurate, timely, and "
            "authorized to meet the entity's processing integrity commitments."
        ),
        category="integrity",
        mandatory=True,
        deadline=None,
        penalty="Audit qualification; loss of SOC2 Type II attestation",
    ),
]

_ISO_42001_REQUIREMENTS: list[ComplianceRequirement] = [
    ComplianceRequirement(
        framework=RegulatoryFramework.ISO_42001,
        requirement_id="ISO-42001-6.1",
        title="Actions to Address Risks and Opportunities",
        description=(
            "The organization shall determine the AI-related risks and opportunities "
            "that need to be addressed to give assurance that the AI management system "
            "can achieve its intended outcomes, prevent or reduce undesired effects, "
            "and achieve continual improvement."
        ),
        category="risk_management",
        mandatory=True,
        deadline=None,
        penalty="Loss of ISO 42001 certification",
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.ISO_42001,
        requirement_id="ISO-42001-8.4",
        title="AI System Impact Assessment",
        description=(
            "The organization shall conduct an AI impact assessment for AI systems "
            "within the scope of its AI management system, considering the potential "
            "consequences for individuals, groups, and societies."
        ),
        category="assessment",
        mandatory=True,
        deadline=None,
        penalty="Loss of ISO 42001 certification",
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.ISO_42001,
        requirement_id="ISO-42001-9.1",
        title="Monitoring, Measurement, Analysis and Evaluation",
        description=(
            "The organization shall determine what needs to be monitored and measured, "
            "the methods for monitoring, measurement, analysis and evaluation, when "
            "monitoring and measuring shall be performed, and when results shall be "
            "analysed and evaluated."
        ),
        category="monitoring",
        mandatory=True,
        deadline=None,
        penalty="Loss of ISO 42001 certification",
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.ISO_42001,
        requirement_id="ISO-42001-9.2",
        title="Internal Audit",
        description=(
            "The organization shall conduct internal audits at planned intervals to "
            "provide information on whether the AI management system conforms to the "
            "organization's own requirements and to the requirements of this document."
        ),
        category="audit",
        mandatory=True,
        deadline=None,
        penalty="Loss of ISO 42001 certification",
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.ISO_42001,
        requirement_id="ISO-42001-10.1",
        title="Continual Improvement",
        description=(
            "The organization shall continually improve the suitability, adequacy and "
            "effectiveness of the AI management system through the use of policy, "
            "objectives, audit results, analysis of data, corrective actions, and "
            "management review."
        ),
        category="improvement",
        mandatory=True,
        deadline=None,
        penalty="Loss of ISO 42001 certification",
    ),
]

_OWASP_AGENTIC_REQUIREMENTS: list[ComplianceRequirement] = [
    ComplianceRequirement(
        framework=RegulatoryFramework.OWASP_AGENTIC,
        requirement_id="OWASP-AGENT-01",
        title="Agent Goal Hijack",
        description=(
            "AI agents can be redirected through natural language when processing "
            "external content like emails or documents containing hidden instructions "
            "that override intended objectives, resulting in total loss of control "
            "where an autonomous agent operates contrary to its intended purpose."
        ),
        category="prompt_security",
        mandatory=False,
        deadline=None,
        penalty=None,
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.OWASP_AGENTIC,
        requirement_id="OWASP-AGENT-02",
        title="Tool Misuse",
        description=(
            "Attackers who influence agent reasoning can weaponize legitimate tools "
            "such as email, databases, APIs, and command execution capabilities that "
            "agents were given to perform their intended functions, bending them into "
            "destructive outputs."
        ),
        category="tool_security",
        mandatory=False,
        deadline=None,
        penalty=None,
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.OWASP_AGENTIC,
        requirement_id="OWASP-AGENT-03",
        title="Identity and Privilege Abuse",
        description=(
            "When compromised, agents grant attackers access to all permissions they "
            "possess. Databases, cloud resources, and internal APIs become the "
            "attacker's access scope, enabling lateral movement and privilege "
            "escalation far beyond the agent's intended boundaries."
        ),
        category="access_control",
        mandatory=False,
        deadline=None,
        penalty=None,
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.OWASP_AGENTIC,
        requirement_id="OWASP-AGENT-04",
        title="Supply Chain Vulnerabilities",
        description=(
            "Malicious MCP servers, plugins, and external tools can be loaded "
            "dynamically at runtime, bypassing traditional dependency security "
            "controls and running with agent privileges. Runtime components are "
            "poisoned while natural-language execution paths unlock dangerous new "
            "avenues for remote code execution."
        ),
        category="supply_chain",
        mandatory=False,
        deadline=None,
        penalty=None,
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.OWASP_AGENTIC,
        requirement_id="OWASP-AGENT-05",
        title="Unexpected Code Execution",
        description=(
            "Code generation and execution features in agentic systems create direct "
            "paths from text input to system commands when untrusted instructions are "
            "embedded in input, enabling remote code execution through natural "
            "language interfaces."
        ),
        category="code_execution",
        mandatory=False,
        deadline=None,
        penalty=None,
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.OWASP_AGENTIC,
        requirement_id="OWASP-AGENT-06",
        title="Memory and Context Poisoning",
        description=(
            "Agents maintaining persistent memory create sleeper agent scenarios "
            "where a single successful injection corrupts memory permanently, "
            "affecting all future sessions and reshaping behavior long after the "
            "initial interaction."
        ),
        category="memory_integrity",
        mandatory=False,
        deadline=None,
        penalty=None,
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.OWASP_AGENTIC,
        requirement_id="OWASP-AGENT-07",
        title="Insecure Inter-Agent Communication",
        description=(
            "Multi-agent systems lack authentication and integrity checks on "
            "messages exchanged between agents, allowing malicious agents to inject "
            "false information into coordination channels and misdirect entire "
            "clusters of agents."
        ),
        category="communication_security",
        mandatory=False,
        deadline=None,
        penalty=None,
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.OWASP_AGENTIC,
        requirement_id="OWASP-AGENT-08",
        title="Cascading Failures",
        description=(
            "A compromised agent poisons downstream connected agents, and errors "
            "propagate through automated workflows faster than incident response "
            "can contain them. False signals cascade through pipelines with "
            "escalating impact."
        ),
        category="resilience",
        mandatory=False,
        deadline=None,
        penalty=None,
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.OWASP_AGENTIC,
        requirement_id="OWASP-AGENT-09",
        title="Human-Agent Trust Exploitation",
        description=(
            "Agents generate authoritative explanations that humans trust, making "
            "approval prompts become rubber stamps even when agents are manipulated "
            "or compromised. Humans overly rely on agent recommendations, leading "
            "to unsafe approvals of harmful actions."
        ),
        category="human_oversight",
        mandatory=False,
        deadline=None,
        penalty=None,
    ),
    ComplianceRequirement(
        framework=RegulatoryFramework.OWASP_AGENTIC,
        requirement_id="OWASP-AGENT-10",
        title="Rogue Agents",
        description=(
            "Agents develop misaligned objectives autonomous of external attacks, "
            "pursuing goals conflicting with their original purpose through reward "
            "function exploitation. Compromised or misaligned agents act harmfully "
            "while appearing legitimate."
        ),
        category="agent_alignment",
        mandatory=False,
        deadline=None,
        penalty=None,
    ),
]


# ---------------------------------------------------------------------------
# Feature-to-requirement mapping rules
# ---------------------------------------------------------------------------

# Mapping: (requirement_id) -> list of (feature_name, coverage, evidence_type, notes)
_FEATURE_MAP: dict[str, list[tuple[str, str, str, str]]] = {
    # ---- EU AI Act ----
    "EU-AI-ACT-ART-9": [
        (
            "policy_engine",
            "partial",
            "Policy YAML + decision logs",
            "Policy engine enforces risk-based rules; pair with "
            "organizational risk process for full coverage",
        ),
        (
            "anomaly_detection",
            "partial",
            "Anomaly detection reports",
            "Behavioral anomaly detection supports continuous risk monitoring",
        ),
    ],
    "EU-AI-ACT-ART-10": [
        (
            "policy_engine",
            "partial",
            "Data access policy rules",
            "Policy engine can restrict data operations; "
            "data governance practices are organizational",
        ),
    ],
    "EU-AI-ACT-ART-11": [
        (
            "compliance_reports",
            "partial",
            "Generated compliance reports",
            "Compliance report generator produces structured "
            "documentation; full technical docs are organizational",
        ),
        (
            "policy_diff",
            "partial",
            "Policy diff history",
            "Policy diff tracking maintains documentation change history",
        ),
    ],
    "EU-AI-ACT-ART-12": [
        (
            "audit_logging",
            "full",
            "Tamper-evident audit logs with cryptographic hashes",
            "Comprehensive automatic logging of all AI system events with hash chains",
        ),
        (
            "crypto_audit",
            "full",
            "Cryptographic audit trail verification reports",
            "SHA-256 hash chain ensures log integrity and non-repudiation",
        ),
    ],
    "EU-AI-ACT-ART-13": [
        (
            "compliance_reports",
            "partial",
            "Compliance and governance reports",
            "Reports provide transparency on system behavior; "
            "UI-level transparency is organizational",
        ),
        (
            "semantic_conditions",
            "partial",
            "Semantic policy evaluation logs",
            "Semantic conditions make policy decisions interpretable",
        ),
    ],
    "EU-AI-ACT-ART-14": [
        (
            "human_oversight",
            "full",
            "Approval gate logs with approver identity",
            "Built-in approval gates require human authorization for high-risk actions",
        ),
    ],
    "EU-AI-ACT-ART-15": [
        (
            "anomaly_detection",
            "partial",
            "Anomaly detection and behavioral profile reports",
            "Anomaly detection monitors system robustness; accuracy metrics are model-specific",
        ),
        (
            "rate_limiting",
            "partial",
            "Rate limit enforcement logs",
            "Rate limiting provides cybersecurity protection against abuse",
        ),
    ],
    "EU-AI-ACT-ART-16": [
        (
            "policy_engine",
            "partial",
            "Policy enforcement decision logs",
            "Policy engine ensures systematic compliance; "
            "full provider obligations span organizational processes",
        ),
        (
            "compliance_reports",
            "partial",
            "Compliance assessment reports",
            "Automated compliance reporting supports conformity assessment",
        ),
    ],
    "EU-AI-ACT-ART-17": [
        (
            "policy_engine",
            "partial",
            "Policy definitions and enforcement history",
            "Policy-as-code is part of quality management; full QMS is organizational",
        ),
        (
            "audit_logging",
            "partial",
            "Complete audit trail",
            "Audit trail supports quality management record-keeping",
        ),
    ],
    "EU-AI-ACT-ART-26": [
        (
            "human_oversight",
            "partial",
            "Human oversight interaction logs",
            "Approval gates support deployer oversight obligations; training is organizational",
        ),
        (
            "audit_logging",
            "partial",
            "Operational monitoring logs",
            "Audit logs enable deployers to monitor AI system operation",
        ),
    ],
    # ---- NIST AI RMF ----
    "NIST-GOVERN-1": [
        (
            "policy_engine",
            "full",
            "Policy YAML definitions and enforcement logs",
            "Policy-as-code implements transparent, documented governance processes",
        ),
    ],
    "NIST-GOVERN-2": [
        (
            "agent_trust_chain",
            "partial",
            "Agent identity and delegation chain records",
            "Agent trust chain establishes accountability; organizational roles are external",
        ),
        (
            "human_oversight",
            "partial",
            "Approval gate assignments",
            "Human oversight defines who is responsible for approvals",
        ),
    ],
    "NIST-MAP-1": [
        (
            "semantic_conditions",
            "partial",
            "Semantic policy condition definitions",
            "Semantic conditions document intended use context; "
            "broader context mapping is organizational",
        ),
    ],
    "NIST-MAP-3": [
        (
            "compliance_reports",
            "partial",
            "Compliance and governance reports",
            "Reports provide quantitative data on system behavior; "
            "cost-benefit analysis is organizational",
        ),
    ],
    "NIST-MEASURE-1": [
        (
            "anomaly_detection",
            "partial",
            "Behavioral profiling metrics and anomaly scores",
            "Anomaly detection provides measurement methods; custom metrics may be needed",
        ),
        (
            "compliance_reports",
            "partial",
            "Compliance scoring and grading",
            "Compliance reports include quantitative risk metrics",
        ),
    ],
    "NIST-MEASURE-2": [
        (
            "anomaly_detection",
            "partial",
            "Continuous behavioral monitoring results",
            "Anomaly detection evaluates system behavior post-deployment",
        ),
        (
            "audit_logging",
            "partial",
            "Ongoing operational audit logs",
            "Audit logs track system changes over time",
        ),
    ],
    "NIST-MANAGE-1": [
        (
            "policy_engine",
            "full",
            "Risk-level-based policy enforcement logs",
            "Policy engine prioritizes and manages AI risks based on configurable risk levels",
        ),
    ],
    "NIST-MANAGE-2": [
        (
            "policy_engine",
            "partial",
            "Policy rules and enforcement statistics",
            "Policy engine implements risk management strategies; "
            "broader planning is organizational",
        ),
        (
            "rate_limiting",
            "partial",
            "Rate limit configurations and enforcement logs",
            "Rate limiting minimizes adverse impacts from excessive AI activity",
        ),
    ],
    # ---- SOC2 ----
    "SOC2-CC6.1": [
        (
            "policy_engine",
            "full",
            "Policy enforcement decision logs",
            "Policy engine provides logical access security "
            "by evaluating every action against rules",
        ),
    ],
    "SOC2-CC6.8": [
        (
            "policy_engine",
            "full",
            "Action blocking and denial logs",
            "Policy engine blocks unauthorized actions based on configurable rules",
        ),
        (
            "rate_limiting",
            "partial",
            "Rate limit enforcement logs",
            "Rate limiting prevents abuse patterns",
        ),
    ],
    "SOC2-CC7.2": [
        (
            "anomaly_detection",
            "full",
            "Anomaly detection alerts and behavioral reports",
            "Anomaly detection continuously monitors for security-relevant behavioral changes",
        ),
        (
            "audit_logging",
            "full",
            "Continuous audit log stream",
            "Audit logging provides comprehensive system monitoring",
        ),
    ],
    "SOC2-CC8.1": [
        (
            "policy_diff",
            "full",
            "Policy change diffs with before/after comparison",
            "Policy diff tracking documents all configuration changes",
        ),
    ],
    "SOC2-A1.2": [
        (
            "audit_logging",
            "partial",
            "Audit log export and backup capabilities",
            "Audit logs can be exported for backup; infrastructure recovery is external",
        ),
    ],
    "SOC2-PI1.1": [
        (
            "policy_engine",
            "partial",
            "Policy enforcement validation logs",
            "Policy engine ensures processing follows defined "
            "rules; complete integrity is application-specific",
        ),
        (
            "crypto_audit",
            "partial",
            "Hash chain verification reports",
            "Cryptographic audit trail verifies processing integrity of logged events",
        ),
    ],
    # ---- ISO 42001 ----
    "ISO-42001-6.1": [
        (
            "policy_engine",
            "partial",
            "Risk-level policy definitions and enforcement logs",
            "Policy engine addresses AI risks; full organizational risk assessment is external",
        ),
        (
            "anomaly_detection",
            "partial",
            "Behavioral anomaly risk detection reports",
            "Anomaly detection identifies emerging risks",
        ),
    ],
    "ISO-42001-8.4": [
        (
            "compliance_reports",
            "partial",
            "Compliance gap analysis reports",
            "Compliance reports support impact assessment; stakeholder analysis is organizational",
        ),
    ],
    "ISO-42001-9.1": [
        (
            "anomaly_detection",
            "partial",
            "Behavioral monitoring metrics",
            "Anomaly detection provides monitoring and measurement capabilities",
        ),
        (
            "audit_logging",
            "partial",
            "Audit log analysis data",
            "Audit logs provide raw data for analysis and evaluation",
        ),
    ],
    "ISO-42001-9.2": [
        (
            "audit_logging",
            "partial",
            "Audit trail for internal review",
            "Audit logs support internal audits; audit program management is organizational",
        ),
        (
            "compliance_reports",
            "partial",
            "Automated compliance audit reports",
            "Compliance reports automate parts of the internal audit process",
        ),
    ],
    "ISO-42001-10.1": [
        (
            "policy_diff",
            "partial",
            "Policy evolution history",
            "Policy diff tracking shows improvement over time; "
            "management review is organizational",
        ),
        (
            "compliance_reports",
            "partial",
            "Trend analysis in compliance reports",
            "Reports highlight areas for improvement",
        ),
    ],
    # ---- OWASP Top 10 for Agentic Applications ----
    "OWASP-AGENT-01": [
        (
            "policy_engine",
            "partial",
            "Policy enforcement decision logs blocking unauthorized actions",
            "Policy engine can block actions that deviate from allowed goals; "
            "full prompt injection defense requires input sanitization layers",
        ),
        (
            "anomaly_detection",
            "partial",
            "Behavioral anomaly detection alerts",
            "Anomaly detection can identify goal drift by profiling expected behavior",
        ),
    ],
    "OWASP-AGENT-02": [
        (
            "policy_engine",
            "partial",
            "Tool invocation policy enforcement logs",
            "Policy engine restricts which tools can be called and under what conditions; "
            "tool-level sandboxing is external",
        ),
        (
            "rate_limiting",
            "partial",
            "Rate limit enforcement on tool calls",
            "Rate limiting constrains tool invocation frequency to limit misuse impact",
        ),
        (
            "audit_logging",
            "partial",
            "Tool usage audit trail",
            "Audit logging records all tool invocations for forensic review",
        ),
    ],
    "OWASP-AGENT-03": [
        (
            "policy_engine",
            "partial",
            "Access control policy enforcement logs",
            "Policy engine enforces least-privilege rules on agent actions; "
            "identity and credential management is external",
        ),
        (
            "agent_trust_chain",
            "partial",
            "Agent identity and delegation chain records",
            "Agent trust chain tracks delegation and prevents privilege escalation "
            "across agent boundaries",
        ),
    ],
    "OWASP-AGENT-04": [
        (
            "policy_engine",
            "partial",
            "Plugin and tool allowlist enforcement logs",
            "Policy engine can restrict which external tools and plugins are permitted; "
            "supply chain integrity verification is external",
        ),
    ],
    "OWASP-AGENT-05": [
        (
            "policy_engine",
            "partial",
            "Code execution policy enforcement logs",
            "Policy engine can block or constrain code execution actions; "
            "sandboxed execution environments are external",
        ),
        (
            "audit_logging",
            "partial",
            "Code execution audit trail",
            "Audit logging records all code execution events for review",
        ),
    ],
    "OWASP-AGENT-06": [
        (
            "audit_logging",
            "partial",
            "Memory and context modification audit trail",
            "Audit logging records context changes enabling detection of poisoning; "
            "memory integrity protection mechanisms are external",
        ),
        (
            "crypto_audit",
            "partial",
            "Cryptographic hash chain over context events",
            "Crypto audit trail detects tampering with logged context modifications",
        ),
    ],
    "OWASP-AGENT-07": [
        (
            "agent_trust_chain",
            "partial",
            "Inter-agent authentication and delegation records",
            "Agent trust chain provides authentication between agents; "
            "message-level encryption and signing is external",
        ),
        (
            "audit_logging",
            "partial",
            "Inter-agent communication audit logs",
            "Audit logging records all inter-agent messages for integrity review",
        ),
    ],
    "OWASP-AGENT-08": [
        (
            "anomaly_detection",
            "partial",
            "Cascading failure anomaly detection alerts",
            "Anomaly detection can identify unusual error propagation patterns; "
            "circuit breakers and isolation mechanisms are external",
        ),
        (
            "rate_limiting",
            "partial",
            "Rate limiting to contain blast radius",
            "Rate limiting constrains downstream impact during failure cascades",
        ),
    ],
    "OWASP-AGENT-09": [
        (
            "human_oversight",
            "partial",
            "Approval gate logs with approver identity",
            "Approval gates enforce human-in-the-loop for high-risk actions; "
            "preventing blind trust requires organizational training and UX design",
        ),
        (
            "compliance_reports",
            "partial",
            "Decision explanation and justification reports",
            "Compliance reports provide auditable decision rationale to support "
            "informed human review rather than rubber-stamping",
        ),
    ],
    "OWASP-AGENT-10": [
        (
            "anomaly_detection",
            "partial",
            "Rogue behavior detection via behavioral profiling",
            "Anomaly detection profiles expected agent behavior and flags deviations "
            "that may indicate misalignment or compromise",
        ),
        (
            "policy_engine",
            "partial",
            "Behavioral boundary enforcement logs",
            "Policy engine enforces behavioral boundaries to prevent goal drift; "
            "alignment verification is external",
        ),
        (
            "audit_logging",
            "partial",
            "Comprehensive agent action audit trail",
            "Audit logging enables forensic analysis of rogue agent behavior",
        ),
    ],
}

# All Aegis features recognized by the mapper.
_ALL_FEATURES: set[str] = {
    "policy_engine",
    "audit_logging",
    "crypto_audit",
    "anomaly_detection",
    "compliance_reports",
    "semantic_conditions",
    "agent_trust_chain",
    "rate_limiting",
    "human_oversight",
    "policy_diff",
}


# ---------------------------------------------------------------------------
# ComplianceMapper
# ---------------------------------------------------------------------------


class ComplianceMapper:
    """Maps Aegis features to regulatory requirements and identifies gaps.

    Usage::

        from aegis.core.regulatory import ComplianceMapper, RegulatoryFramework

        mapper = ComplianceMapper()
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT)
        print(mapper.generate_report(analysis))
    """

    def __init__(self) -> None:
        self._requirements: dict[RegulatoryFramework, list[ComplianceRequirement]] = {
            RegulatoryFramework.EU_AI_ACT: list(_EU_AI_ACT_REQUIREMENTS),
            RegulatoryFramework.NIST_AI_RMF: list(_NIST_AI_RMF_REQUIREMENTS),
            RegulatoryFramework.SOC2: list(_SOC2_REQUIREMENTS),
            RegulatoryFramework.ISO_42001: list(_ISO_42001_REQUIREMENTS),
            RegulatoryFramework.OWASP_AGENTIC: list(_OWASP_AGENTIC_REQUIREMENTS),
        }

    def get_requirements(self, framework: RegulatoryFramework) -> list[ComplianceRequirement]:
        """Return all requirements for a given framework."""
        return list(self._requirements.get(framework, []))

    def get_deadlines(self) -> list[tuple[str, ComplianceRequirement]]:
        """Return all requirements that have deadlines, sorted by date.

        Returns:
            List of ``(deadline, requirement)`` tuples sorted ascending.
        """
        result: list[tuple[str, ComplianceRequirement]] = []
        for reqs in self._requirements.values():
            for req in reqs:
                if req.deadline is not None:
                    result.append((req.deadline, req))
        result.sort(key=lambda pair: pair[0])
        return result

    def analyze(
        self,
        framework: RegulatoryFramework,
        features: dict[str, bool] | None = None,
    ) -> ComplianceGapAnalysis:
        """Perform a compliance gap analysis for a framework.

        Args:
            framework: The regulatory framework to analyze against.
            features: Optional dict of Aegis feature names to booleans
                indicating which features are enabled. Defaults to all enabled.

        Returns:
            A :class:`ComplianceGapAnalysis` with mappings, gaps, and
            recommendations.
        """
        if features is None:
            enabled: set[str] = set(_ALL_FEATURES)
        else:
            enabled = {k for k, v in features.items() if v}

        reqs = self.get_requirements(framework)
        mappings: list[FeatureMapping] = []
        gaps: list[ComplianceRequirement] = []
        fully_covered = 0
        partially_covered = 0
        not_covered = 0

        for req in reqs:
            feature_entries = _FEATURE_MAP.get(req.requirement_id, [])
            # Filter to only enabled features
            active_entries = [
                (feat, cov, ev, note) for feat, cov, ev, note in feature_entries if feat in enabled
            ]

            if not active_entries:
                # No enabled features map to this requirement
                not_covered += 1
                gaps.append(req)
                mappings.append(
                    FeatureMapping(
                        requirement=req,
                        aegis_feature="(none)",
                        coverage="none",
                        evidence_type="No evidence available",
                        notes="No enabled Aegis feature addresses this requirement",
                    )
                )
            else:
                # Determine best coverage level across all mapped features
                coverages = [cov for _, cov, _, _ in active_entries]
                has_full = "full" in coverages

                for feat, cov, ev, note in active_entries:
                    mappings.append(
                        FeatureMapping(
                            requirement=req,
                            aegis_feature=feat,
                            coverage=cov,
                            evidence_type=ev,
                            notes=note,
                        )
                    )

                if has_full:
                    fully_covered += 1
                else:
                    partially_covered += 1

        total = len(reqs)
        covered_count = fully_covered + partially_covered
        coverage_score = (covered_count / total * 100.0) if total > 0 else 0.0

        recommendations = self._generate_recommendations(
            framework, gaps, partially_covered, fully_covered, total, enabled
        )

        return ComplianceGapAnalysis(
            framework=framework,
            total_requirements=total,
            fully_covered=fully_covered,
            partially_covered=partially_covered,
            not_covered=not_covered,
            coverage_score=coverage_score,
            mappings=mappings,
            gaps=gaps,
            recommendations=recommendations,
        )

    def generate_report(self, analysis: ComplianceGapAnalysis) -> str:
        """Generate a Markdown compliance report from an analysis.

        Args:
            analysis: The gap analysis to report on.

        Returns:
            A Markdown-formatted string suitable for auditor review.
        """
        framework_names = {
            RegulatoryFramework.EU_AI_ACT: "EU AI Act (Regulation (EU) 2024/1689)",
            RegulatoryFramework.NIST_AI_RMF: "NIST AI Risk Management Framework 1.0",
            RegulatoryFramework.SOC2: "SOC2 Trust Services Criteria",
            RegulatoryFramework.ISO_42001: "ISO/IEC 42001:2023",
            RegulatoryFramework.OWASP_AGENTIC: "OWASP Top 10 for Agentic Applications (2025)",
        }
        name = framework_names.get(analysis.framework, analysis.framework.value)

        lines: list[str] = []
        lines.append(f"# Compliance Gap Analysis: {name}")
        lines.append("")
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"- **Framework**: {name}")
        lines.append(f"- **Total Requirements**: {analysis.total_requirements}")
        lines.append(f"- **Fully Covered**: {analysis.fully_covered}")
        lines.append(f"- **Partially Covered**: {analysis.partially_covered}")
        lines.append(f"- **Not Covered**: {analysis.not_covered}")
        lines.append(f"- **Coverage Score**: {analysis.coverage_score:.1f}%")
        lines.append("")

        # Coverage detail
        lines.append("## Requirement Coverage Detail")
        lines.append("")

        # Group mappings by requirement
        seen_reqs: set[str] = set()
        for mapping in analysis.mappings:
            req = mapping.requirement
            if req.requirement_id in seen_reqs:
                # Additional mapping for same requirement
                lines.append(
                    f"  - **{mapping.aegis_feature}** ({mapping.coverage}): {mapping.notes}"
                )
                continue
            seen_reqs.add(req.requirement_id)

            status = mapping.coverage.upper()
            lines.append(f"### {req.requirement_id}: {req.title} [{status}]")
            lines.append("")
            lines.append(f"> {req.description[:200]}...")
            lines.append("")
            lines.append(f"- **Category**: {req.category}")
            lines.append(f"- **Mandatory**: {'Yes' if req.mandatory else 'No'}")
            if req.deadline:
                lines.append(f"- **Deadline**: {req.deadline}")
            if req.penalty:
                lines.append(f"- **Penalty**: {req.penalty}")
            lines.append("")
            lines.append("**Aegis Feature Mappings:**")
            lines.append("")
            lines.append(f"  - **{mapping.aegis_feature}** ({mapping.coverage}): {mapping.notes}")

        lines.append("")

        # Gaps section
        if analysis.gaps:
            lines.append("## Compliance Gaps")
            lines.append("")
            for gap in analysis.gaps:
                lines.append(f"- **{gap.requirement_id}**: {gap.title}")
                if gap.mandatory:
                    lines.append("  - MANDATORY requirement")
                if gap.deadline:
                    lines.append(f"  - Deadline: {gap.deadline}")
                if gap.penalty:
                    lines.append(f"  - Penalty: {gap.penalty}")
            lines.append("")

        # Recommendations
        if analysis.recommendations:
            lines.append("## Recommendations")
            lines.append("")
            for i, rec in enumerate(analysis.recommendations, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        lines.append("---")
        lines.append("*Generated by Aegis Compliance Mapper*")
        lines.append("")

        return "\n".join(lines)

    def generate_html_report(self, analysis: ComplianceGapAnalysis) -> str:
        """Generate a self-contained HTML compliance gap analysis report."""
        framework_names = {
            RegulatoryFramework.EU_AI_ACT: "EU AI Act (Regulation (EU) 2024/1689)",
            RegulatoryFramework.NIST_AI_RMF: "NIST AI Risk Management Framework 1.0",
            RegulatoryFramework.SOC2: "SOC2 Trust Services Criteria",
            RegulatoryFramework.ISO_42001: "ISO/IEC 42001:2023",
            RegulatoryFramework.OWASP_AGENTIC: "OWASP Top 10 for Agentic Applications (2025)",
        }
        name = framework_names.get(analysis.framework, analysis.framework.value)
        score = analysis.coverage_score
        bar_color = "#22c55e" if score >= 80 else "#eab308" if score >= 50 else "#ef4444"
        coverage_styles = {
            "full": "background:#dcfce7;color:#166534;",
            "partial": "background:#fef9c3;color:#854d0e;",
            "none": "background:#fee2e2;color:#991b1b;",
        }
        seen_reqs: set[str] = set()
        req_rows: list[str] = []
        for mapping in analysis.mappings:
            req = mapping.requirement
            cov_style = coverage_styles.get(mapping.coverage, "")
            if req.requirement_id in seen_reqs:
                req_rows.append(
                    f'<tr><td style="padding:8px 12px;"></td>'
                    f'<td style="padding:8px 12px;"></td>'
                    f'<td style="padding:8px 12px;{cov_style}font-weight:600;">'
                    f"{_html_escape(mapping.coverage.upper())}</td>"
                    f'<td style="padding:8px 12px;">{_html_escape(mapping.aegis_feature)}</td>'
                    f'<td style="padding:8px 12px;">{_html_escape(mapping.evidence_type)}</td>'
                    f'<td style="padding:8px 12px;">{_html_escape(mapping.notes)}</td></tr>'
                )
                continue
            seen_reqs.add(req.requirement_id)
            mand_style = (
                "background:#ef4444;color:#fff;padding:2px 6px;border-radius:3px;font-size:11px;"
            )
            badge = f' <span style="{mand_style}">MANDATORY</span>' if req.mandatory else ""
            req_rows.append(
                f'<tr><td style="padding:8px 12px;font-weight:600;">'
                f"{_html_escape(req.requirement_id)}{badge}</td>"
                f'<td style="padding:8px 12px;">{_html_escape(req.title)}</td>'
                f'<td style="padding:8px 12px;{cov_style}font-weight:600;">'
                f"{_html_escape(mapping.coverage.upper())}</td>"
                f'<td style="padding:8px 12px;">{_html_escape(mapping.aegis_feature)}</td>'
                f'<td style="padding:8px 12px;">{_html_escape(mapping.evidence_type)}</td>'
                f'<td style="padding:8px 12px;">{_html_escape(mapping.notes)}</td></tr>'
            )
        gaps_html = ""
        if analysis.gaps:
            gap_items = []
            for gap in analysis.gaps:
                m_style = (
                    "background:#ef4444;color:#fff;"
                    "padding:2px 6px;"
                    "border-radius:3px;font-size:11px;"
                )
                m = f' <span style="{m_style}">MANDATORY</span>' if gap.mandatory else ""
                d = f" &mdash; Deadline: {_html_escape(gap.deadline)}" if gap.deadline else ""
                p = (
                    f"<br><small style='color:#991b1b;'>"
                    f"Penalty: "
                    f"{_html_escape(gap.penalty)}</small>"
                    if gap.penalty
                    else ""
                )
                gap_items.append(
                    f"<li><strong>"
                    f"{_html_escape(gap.requirement_id)}"
                    f": {_html_escape(gap.title)}"
                    f"</strong>{m}{d}{p}</li>"
                )
            gaps_html = (
                f'<div class="section"><h2>Compliance Gaps</h2><ul>{"".join(gap_items)}</ul></div>'
            )
        recs_html = ""
        if analysis.recommendations:
            ri = "".join(f"<li>{_html_escape(r)}</li>" for r in analysis.recommendations)
            recs_html = f'<div class="section"><h2>Recommendations</h2><ol>{ri}</ol></div>'
        # Build CSS as a separate string to stay within line limits
        css = (
            "body{font-family:-apple-system,BlinkMacSystemFont,"
            "'Segoe UI',Roboto,sans-serif;"
            "margin:0;padding:0;background:#f8fafc;color:#1e293b}"
            ".container{max-width:1100px;margin:0 auto;padding:24px}"
            ".header{background:#1e293b;color:#f8fafc;"
            "padding:32px;border-radius:8px 8px 0 0}"
            ".header h1{margin:0 0 8px 0;font-size:28px}"
            ".header .meta{font-size:14px;opacity:.8}"
            ".section{background:#fff;border:1px solid #e2e8f0;"
            "border-radius:8px;padding:24px;margin:16px 0}"
            ".section h2{margin:0 0 16px 0;font-size:20px;"
            "color:#334155}"
            ".summary-grid{display:grid;"
            "grid-template-columns:repeat(auto-fit,"
            "minmax(140px,1fr));gap:12px;margin-bottom:20px}"
            ".summary-card{background:#f1f5f9;"
            "border-radius:6px;padding:16px;text-align:center}"
            ".summary-card .value{font-size:28px;"
            "font-weight:700;color:#0f172a}"
            ".summary-card .label{font-size:13px;"
            "color:#64748b;margin-top:4px}"
            ".bar-container{background:#e2e8f0;border-radius:8px;"
            "height:28px;overflow:hidden;margin:8px 0}"
            ".bar-fill{height:100%;border-radius:8px;display:flex;"
            "align-items:center;justify-content:center;"
            "color:#fff;font-weight:600;font-size:14px}"
            "table{width:100%;border-collapse:collapse;"
            "font-size:13px}"
            "th{background:#f1f5f9;padding:10px 12px;"
            "text-align:left;font-weight:600;color:#475569;"
            "border-bottom:2px solid #e2e8f0}"
            "td{padding:8px 12px;border-bottom:1px solid #e2e8f0;"
            "vertical-align:top}"
            "tr:hover{background:#f8fafc}"
            "ul,ol{padding-left:20px}li{margin-bottom:8px}"
            ".footer{text-align:center;font-size:12px;"
            "color:#94a3b8;padding:16px}"
        )
        esc_name = _html_escape(name)
        total = analysis.total_requirements
        full = analysis.fully_covered
        partial = analysis.partially_covered
        uncov = analysis.not_covered
        rows_html = "".join(req_rows)
        return (
            f"<!DOCTYPE html><html lang='en'><head>"
            f"<meta charset='utf-8'>"
            f"<meta name='viewport' "
            f"content='width=device-width, initial-scale=1'>"
            f"<title>Compliance Gap Analysis: "
            f"{esc_name}</title>"
            f"<style>{css}</style></head>"
            f"<body><div class='container'>"
            f"<div class='header'>"
            f"<h1>Compliance Gap Analysis</h1>"
            f"<div class='meta'>{esc_name}</div></div>"
            f"<div class='section'>"
            f"<h2>Coverage Overview</h2>"
            f"<div class='summary-grid'>"
            f"<div class='summary-card'>"
            f"<div class='value'>{total}</div>"
            f"<div class='label'>Total Requirements</div></div>"
            f"<div class='summary-card'>"
            f"<div class='value' style='color:#22c55e;'>"
            f"{full}</div>"
            f"<div class='label'>Fully Covered</div></div>"
            f"<div class='summary-card'>"
            f"<div class='value' style='color:#eab308;'>"
            f"{partial}</div>"
            f"<div class='label'>Partially Covered</div></div>"
            f"<div class='summary-card'>"
            f"<div class='value' style='color:#ef4444;'>"
            f"{uncov}</div>"
            f"<div class='label'>Not Covered</div></div>"
            f"</div>"
            f"<div class='bar-container'>"
            f"<div class='bar-fill' style='"
            f"width:{score:.1f}%;background:{bar_color};'>"
            f"{score:.1f}%</div></div></div>"
            f"<div class='section'>"
            f"<h2>Requirements Detail</h2>"
            f"<table><thead><tr>"
            f"<th>Requirement</th><th>Title</th>"
            f"<th>Coverage</th><th>Aegis Feature</th>"
            f"<th>Evidence Type</th><th>Notes</th>"
            f"</tr></thead>"
            f"<tbody>{rows_html}</tbody></table></div>"
            f"{gaps_html}{recs_html}"
            f"<div class='footer'>"
            f"Generated by Aegis Compliance Mapper"
            f"</div></div></body></html>"
        )

    def generate_evidence_map(self, analysis: ComplianceGapAnalysis) -> dict[str, object]:
        """Generate a JSON-serializable evidence map from an analysis.

        Args:
            analysis: The gap analysis to map evidence for.

        Returns:
            A dict suitable for ``json.dumps()``, structured for auditor tools.
        """
        framework_names = {
            RegulatoryFramework.EU_AI_ACT: "EU AI Act",
            RegulatoryFramework.NIST_AI_RMF: "NIST AI RMF",
            RegulatoryFramework.SOC2: "SOC2",
            RegulatoryFramework.ISO_42001: "ISO 42001",
            RegulatoryFramework.OWASP_AGENTIC: "OWASP Agentic AI",
        }

        evidence_entries: list[dict[str, Any]] = []
        for mapping in analysis.mappings:
            req = mapping.requirement
            evidence_entries.append(
                {
                    "requirement_id": req.requirement_id,
                    "requirement_title": req.title,
                    "category": req.category,
                    "mandatory": req.mandatory,
                    "deadline": req.deadline,
                    "penalty": req.penalty,
                    "aegis_feature": mapping.aegis_feature,
                    "coverage": mapping.coverage,
                    "evidence_type": mapping.evidence_type,
                    "notes": mapping.notes,
                }
            )

        gap_entries: list[dict[str, Any]] = []
        for gap in analysis.gaps:
            gap_entries.append(
                {
                    "requirement_id": gap.requirement_id,
                    "title": gap.title,
                    "category": gap.category,
                    "mandatory": gap.mandatory,
                    "deadline": gap.deadline,
                    "penalty": gap.penalty,
                }
            )

        return {
            "framework": framework_names.get(analysis.framework, analysis.framework.value),
            "summary": {
                "total_requirements": analysis.total_requirements,
                "fully_covered": analysis.fully_covered,
                "partially_covered": analysis.partially_covered,
                "not_covered": analysis.not_covered,
                "coverage_score": round(analysis.coverage_score, 2),
            },
            "mappings": evidence_entries,
            "gaps": gap_entries,
            "recommendations": analysis.recommendations,
        }

    # -- internal helpers --

    @staticmethod
    def _generate_recommendations(
        framework: RegulatoryFramework,
        gaps: list[ComplianceRequirement],
        partially_covered: int,
        fully_covered: int,
        total: int,
        enabled: set[str],
    ) -> list[str]:
        """Generate actionable recommendations based on the gap analysis."""
        recs: list[str] = []

        # Gaps with deadlines get urgent recommendations
        deadline_gaps = [g for g in gaps if g.deadline is not None]
        if deadline_gaps:
            earliest = min(deadline_gaps, key=lambda g: g.deadline or "")
            recs.append(
                f"URGENT: {len(deadline_gaps)} uncovered requirement(s) have "
                f"enforcement deadlines. Earliest: {earliest.requirement_id} "
                f"by {earliest.deadline}."
            )

        # Mandatory gaps
        mandatory_gaps = [g for g in gaps if g.mandatory]
        if mandatory_gaps:
            ids = ", ".join(g.requirement_id for g in mandatory_gaps)
            recs.append(f"Address {len(mandatory_gaps)} mandatory requirement gap(s): {ids}.")

        # Feature enablement recommendations
        disabled = _ALL_FEATURES - enabled
        if disabled:
            recs.append(
                f"Enable disabled Aegis features to improve coverage: "
                f"{', '.join(sorted(disabled))}."
            )

        # Partial coverage improvements
        if partially_covered > 0:
            recs.append(
                f"{partially_covered} requirement(s) have partial coverage. "
                f"Review organizational processes to complement Aegis capabilities."
            )

        # Framework-specific advice
        if framework == RegulatoryFramework.EU_AI_ACT:
            recs.append(
                "Ensure technical documentation (Art 11) is maintained alongside "
                "Aegis audit logs for complete EU AI Act compliance."
            )
        elif framework == RegulatoryFramework.NIST_AI_RMF:
            recs.append(
                "NIST AI RMF is a voluntary framework; align organizational AI "
                "governance practices with Aegis technical controls."
            )
        elif framework == RegulatoryFramework.SOC2:
            recs.append(
                "Coordinate with your SOC2 auditor to validate that Aegis evidence "
                "meets their specific testing requirements."
            )
        elif framework == RegulatoryFramework.ISO_42001:
            recs.append(
                "ISO 42001 certification requires management commitment; use Aegis "
                "reports to demonstrate operational AI governance controls."
            )
        elif framework == RegulatoryFramework.OWASP_AGENTIC:
            recs.append(
                "OWASP Agentic AI risks require defense-in-depth; combine Aegis "
                "policy enforcement and monitoring with input sanitization, sandboxing, "
                "and secure agent architecture."
            )

        # Coverage score feedback
        score = (fully_covered + partially_covered) / total * 100.0 if total else 0.0
        if score == 100.0:
            recs.append(
                "All requirements have at least partial coverage. Focus on upgrading "
                "partial coverage to full coverage."
            )
        elif score >= 80.0:
            recs.append(
                f"Coverage score is {score:.0f}%. Close remaining gaps to reach full coverage."
            )
        elif score >= 50.0:
            recs.append(
                f"Coverage score is {score:.0f}%. Significant gaps remain. Prioritize "
                f"mandatory requirements with approaching deadlines."
            )
        else:
            recs.append(
                f"Coverage score is only {score:.0f}%. Comprehensive governance "
                f"implementation is needed before compliance can be claimed."
            )

        return recs
