"""Core models and policy engine.

Import from the top-level ``aegis`` package for convenience::

    from aegis import Action, Policy, Runtime

All public symbols are lazy-loaded on first access so that
``import aegis`` stays fast regardless of how many modules exist here.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

_LAZY_IMPORTS: dict[str, str] = {
    # a2a_governance
    "A2ADecision": "aegis.core.a2a_governance",
    "A2AGovernor": "aegis.core.a2a_governance",
    "A2AMessage": "aegis.core.a2a_governance",
    "GovernanceEnvelope": "aegis.core.a2a_governance",
    "GovernanceHandshake": "aegis.core.a2a_governance",
    "HandshakeResult": "aegis.core.a2a_governance",
    # action
    "Action": "aegis.core.action",
    # agent_identity
    "AgentIdentity": "aegis.core.agent_identity",
    "AgentRegistry": "aegis.core.agent_identity",
    "DelegationEvent": "aegis.core.agent_identity",
    # constitution
    "AgentConstitution": "aegis.core.constitution",
    "AgentOntology": "aegis.core.constitution",
    "Constraint": "aegis.core.constitution",
    "Obligation": "aegis.core.constitution",
    # anomaly
    "AnomalyDetector": "aegis.core.anomaly",
    "AnomalyResult": "aegis.core.anomaly",
    "BehaviorProfile": "aegis.core.anomaly",
    # budget
    "BudgetAction": "aegis.core.budget",
    "BudgetExhausted": "aegis.core.budget",
    "CostRecord": "aegis.core.budget",
    "CostTracker": "aegis.core.budget",
    "ModelPricing": "aegis.core.budget",
    "TokenUsage": "aegis.core.budget",
    # builder
    "PolicyBuilder": "aegis.core.builder",
    "RuleBuilder": "aegis.core.builder",
    # compliance
    "ComplianceFinding": "aegis.core.compliance",
    "ComplianceReport": "aegis.core.compliance",
    "ReportGenerator": "aegis.core.compliance",
    # cost_attribution
    "AgentCostNode": "aegis.core.cost_attribution",
    "CostAttributionTree": "aegis.core.cost_attribution",
    # cost_callbacks
    "AnthropicCostExtractor": "aegis.core.cost_callbacks",
    "GoogleCostExtractor": "aegis.core.cost_callbacks",
    "LangChainCostCallback": "aegis.core.cost_callbacks",
    "OpenAICostExtractor": "aegis.core.cost_callbacks",
    # crypto_audit
    "AuditEntry": "aegis.core.crypto_audit",
    "CryptoAuditChain": "aegis.core.crypto_audit",
    "EvidencePackage": "aegis.core.crypto_audit",
    "VerificationResult": "aegis.core.crypto_audit",
    # leakage_detector
    "LeakageDetector": "aegis.core.leakage_detector",
    "LeakageFinding": "aegis.core.leakage_detector",
    "LeakageReport": "aegis.core.leakage_detector",
    # mcp_audit_dashboard
    "Alert": "aegis.core.mcp_audit_dashboard",
    "CallRecord": "aegis.core.mcp_audit_dashboard",
    "DashboardState": "aegis.core.mcp_audit_dashboard",
    "DashboardStats": "aegis.core.mcp_audit_dashboard",
    "MCPAuditDashboard": "aegis.core.mcp_audit_dashboard",
    "ServerStatus": "aegis.core.mcp_audit_dashboard",
    # mcp_consent
    "AutoDenyHandler": "aegis.core.mcp_consent",
    "CallbackConsentHandler": "aegis.core.mcp_consent",
    "ConsentDecision": "aegis.core.mcp_consent",
    "ConsentRequest": "aegis.core.mcp_consent",
    "ConsentRule": "aegis.core.mcp_consent",
    "MCPConsentManager": "aegis.core.mcp_consent",
    # mcp_escalation
    "EscalationDetector": "aegis.core.mcp_escalation",
    "EscalationFinding": "aegis.core.mcp_escalation",
    "EscalationRule": "aegis.core.mcp_escalation",
    "ToolCallRecord": "aegis.core.mcp_escalation",
    # mcp_rate_limiter
    "MCPRateLimiter": "aegis.core.mcp_rate_limiter",
    "MCPRateLimitResult": "aegis.core.mcp_rate_limiter",
    "RateLimitConfig": "aegis.core.mcp_rate_limiter",
    # mcp_response_scanner
    "MCPResponseScanner": "aegis.core.mcp_response_scanner",
    "ResponseFinding": "aegis.core.mcp_response_scanner",
    "ResponsePattern": "aegis.core.mcp_response_scanner",
    # mcp_sbom
    "MCPServerInfo": "aegis.core.mcp_sbom",
    "MCPToolInfo": "aegis.core.mcp_sbom",
    "SBOM": "aegis.core.mcp_sbom",
    "SBOMGenerator": "aegis.core.mcp_sbom",
    # mcp_shadow
    "ShadowFinding": "aegis.core.mcp_shadow",
    "ToolRegistration": "aegis.core.mcp_shadow",
    "ToolShadowDetector": "aegis.core.mcp_shadow",
    # mcp_transport
    "MCPTransportValidator": "aegis.core.mcp_transport",
    "NetworkConfig": "aegis.core.mcp_transport",
    "StdioConfig": "aegis.core.mcp_transport",
    "TransportFinding": "aegis.core.mcp_transport",
    "TransportProfile": "aegis.core.mcp_transport",
    # mcp_security_report
    "MCPSecurityReport": "aegis.core.mcp_security_report",
    "MCPSecurityReportGenerator": "aegis.core.mcp_security_report",
    "ServerSecurityProfile": "aegis.core.mcp_security_report",
    # mcp_security
    "ArgumentSanitizer": "aegis.core.mcp_security",
    "MCPFinding": "aegis.core.mcp_security",
    "MCPSecurityGate": "aegis.core.mcp_security",
    "RugPullDetector": "aegis.core.mcp_security",
    "ToolDescriptionScanner": "aegis.core.mcp_security",
    "ToolTrustScorer": "aegis.core.mcp_security",
    "TrustLevel": "aegis.core.mcp_security",
    "TrustScore": "aegis.core.mcp_security",
    # mcp_vuln_db
    "MCPVulnDB": "aegis.core.mcp_vuln_db",
    "VulnEntry": "aegis.core.mcp_vuln_db",
    "VulnFinding": "aegis.core.mcp_vuln_db",
    # otel_export
    "AegisEvent": "aegis.core.otel_export",
    "AegisOTelExporter": "aegis.core.otel_export",
    # plan
    "ExecutionPlan": "aegis.core.plan",
    # plan_rules
    "CumulativeRiskThreshold": "aegis.core.plan_rules",
    "PlanRules": "aegis.core.plan_rules",
    "PlanViolation": "aegis.core.plan_rules",
    "SequencePattern": "aegis.core.plan_rules",
    # policy
    "Approval": "aegis.core.policy",
    "Policy": "aegis.core.policy",
    "PolicyDecision": "aegis.core.policy",
    "PolicyRule": "aegis.core.policy",
    # policy_git
    "PolicyDiffFormatter": "aegis.core.policy_git",
    "PolicyDriftDetector": "aegis.core.policy_git",
    "PolicyImpactAnalyzer": "aegis.core.policy_git",
    "export_policy_yaml": "aegis.core.policy_git",
    # rate_limiter
    "RateLimiter": "aegis.core.rate_limiter",
    "RateLimitResult": "aegis.core.rate_limiter",
    "RateLimitRule": "aegis.core.rate_limiter",
    # result
    "Result": "aegis.core.result",
    "ResultStatus": "aegis.core.result",
    # retry
    "RetryPolicy": "aegis.core.retry",
    # risk
    "RiskLevel": "aegis.core.risk",
    # semantic
    "KeywordSemanticEvaluator": "aegis.core.semantic",
    "SEMANTIC_CATEGORIES": "aegis.core.semantic",
    "SemanticEvaluator": "aegis.core.semantic",
    "evaluate_semantic_condition": "aegis.core.semantic",
    # session_replay
    "ReplayReport": "aegis.core.session_replay",
    "SessionRecorder": "aegis.core.session_replay",
    "SessionReplayer": "aegis.core.session_replay",
}

__all__ = list(_LAZY_IMPORTS.keys())


def __getattr__(name: str) -> object:
    if name in _LAZY_IMPORTS:
        module = importlib.import_module(_LAZY_IMPORTS[name])
        value = getattr(module, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


if TYPE_CHECKING:
    from aegis.core.a2a_governance import (
        A2ADecision as A2ADecision,
    )
    from aegis.core.a2a_governance import (
        A2AGovernor as A2AGovernor,
    )
    from aegis.core.a2a_governance import (
        A2AMessage as A2AMessage,
    )
    from aegis.core.a2a_governance import (
        GovernanceEnvelope as GovernanceEnvelope,
    )
    from aegis.core.a2a_governance import (
        GovernanceHandshake as GovernanceHandshake,
    )
    from aegis.core.a2a_governance import (
        HandshakeResult as HandshakeResult,
    )
    from aegis.core.action import Action as Action
    from aegis.core.agent_identity import (
        AgentIdentity as AgentIdentity,
    )
    from aegis.core.agent_identity import (
        AgentRegistry as AgentRegistry,
    )
    from aegis.core.agent_identity import (
        DelegationEvent as DelegationEvent,
    )
    from aegis.core.anomaly import (
        AnomalyDetector as AnomalyDetector,
    )
    from aegis.core.anomaly import (
        AnomalyResult as AnomalyResult,
    )
    from aegis.core.anomaly import (
        BehaviorProfile as BehaviorProfile,
    )
    from aegis.core.budget import (
        BudgetAction as BudgetAction,
    )
    from aegis.core.budget import (
        BudgetExhausted as BudgetExhausted,
    )
    from aegis.core.budget import (
        CostRecord as CostRecord,
    )
    from aegis.core.budget import (
        CostTracker as CostTracker,
    )
    from aegis.core.budget import (
        ModelPricing as ModelPricing,
    )
    from aegis.core.budget import (
        TokenUsage as TokenUsage,
    )
    from aegis.core.builder import (
        PolicyBuilder as PolicyBuilder,
    )
    from aegis.core.builder import (
        RuleBuilder as RuleBuilder,
    )
    from aegis.core.compliance import (
        ComplianceFinding as ComplianceFinding,
    )
    from aegis.core.compliance import (
        ComplianceReport as ComplianceReport,
    )
    from aegis.core.compliance import (
        ReportGenerator as ReportGenerator,
    )
    from aegis.core.constitution import (
        AgentConstitution as AgentConstitution,
    )
    from aegis.core.constitution import (
        AgentOntology as AgentOntology,
    )
    from aegis.core.constitution import (
        Constraint as Constraint,
    )
    from aegis.core.constitution import (
        Obligation as Obligation,
    )
    from aegis.core.cost_attribution import (
        AgentCostNode as AgentCostNode,
    )
    from aegis.core.cost_attribution import (
        CostAttributionTree as CostAttributionTree,
    )
    from aegis.core.cost_callbacks import (
        AnthropicCostExtractor as AnthropicCostExtractor,
    )
    from aegis.core.cost_callbacks import (
        GoogleCostExtractor as GoogleCostExtractor,
    )
    from aegis.core.cost_callbacks import (
        LangChainCostCallback as LangChainCostCallback,
    )
    from aegis.core.cost_callbacks import (
        OpenAICostExtractor as OpenAICostExtractor,
    )
    from aegis.core.crypto_audit import (
        AuditEntry as AuditEntry,
    )
    from aegis.core.crypto_audit import (
        CryptoAuditChain as CryptoAuditChain,
    )
    from aegis.core.crypto_audit import (
        EvidencePackage as EvidencePackage,
    )
    from aegis.core.crypto_audit import (
        VerificationResult as VerificationResult,
    )
    from aegis.core.leakage_detector import (
        LeakageDetector as LeakageDetector,
    )
    from aegis.core.leakage_detector import (
        LeakageFinding as LeakageFinding,
    )
    from aegis.core.leakage_detector import (
        LeakageReport as LeakageReport,
    )
    from aegis.core.mcp_audit_dashboard import (
        Alert as Alert,
    )
    from aegis.core.mcp_audit_dashboard import (
        CallRecord as CallRecord,
    )
    from aegis.core.mcp_audit_dashboard import (
        DashboardState as DashboardState,
    )
    from aegis.core.mcp_audit_dashboard import (
        DashboardStats as DashboardStats,
    )
    from aegis.core.mcp_audit_dashboard import (
        MCPAuditDashboard as MCPAuditDashboard,
    )
    from aegis.core.mcp_audit_dashboard import (
        ServerStatus as ServerStatus,
    )
    from aegis.core.mcp_consent import (
        AutoDenyHandler as AutoDenyHandler,
    )
    from aegis.core.mcp_consent import (
        CallbackConsentHandler as CallbackConsentHandler,
    )
    from aegis.core.mcp_consent import (
        ConsentDecision as ConsentDecision,
    )
    from aegis.core.mcp_consent import (
        ConsentRequest as ConsentRequest,
    )
    from aegis.core.mcp_consent import (
        ConsentRule as ConsentRule,
    )
    from aegis.core.mcp_consent import (
        MCPConsentManager as MCPConsentManager,
    )
    from aegis.core.mcp_escalation import (
        EscalationDetector as EscalationDetector,
    )
    from aegis.core.mcp_escalation import (
        EscalationFinding as EscalationFinding,
    )
    from aegis.core.mcp_escalation import (
        EscalationRule as EscalationRule,
    )
    from aegis.core.mcp_escalation import (
        ToolCallRecord as ToolCallRecord,
    )
    from aegis.core.mcp_rate_limiter import (
        MCPRateLimiter as MCPRateLimiter,
    )
    from aegis.core.mcp_rate_limiter import (
        MCPRateLimitResult as MCPRateLimitResult,
    )
    from aegis.core.mcp_rate_limiter import (
        RateLimitConfig as RateLimitConfig,
    )
    from aegis.core.mcp_response_scanner import (
        MCPResponseScanner as MCPResponseScanner,
    )
    from aegis.core.mcp_response_scanner import (
        ResponseFinding as ResponseFinding,
    )
    from aegis.core.mcp_response_scanner import (
        ResponsePattern as ResponsePattern,
    )
    from aegis.core.mcp_sbom import (
        SBOM as SBOM,
    )
    from aegis.core.mcp_sbom import (
        MCPServerInfo as MCPServerInfo,
    )
    from aegis.core.mcp_sbom import (
        MCPToolInfo as MCPToolInfo,
    )
    from aegis.core.mcp_sbom import (
        SBOMGenerator as SBOMGenerator,
    )
    from aegis.core.mcp_security import (
        ArgumentSanitizer as ArgumentSanitizer,
    )
    from aegis.core.mcp_security import (
        MCPFinding as MCPFinding,
    )
    from aegis.core.mcp_security import (
        MCPSecurityGate as MCPSecurityGate,
    )
    from aegis.core.mcp_security import (
        RugPullDetector as RugPullDetector,
    )
    from aegis.core.mcp_security import (
        ToolDescriptionScanner as ToolDescriptionScanner,
    )
    from aegis.core.mcp_security import (
        ToolTrustScorer as ToolTrustScorer,
    )
    from aegis.core.mcp_security import (
        TrustLevel as TrustLevel,
    )
    from aegis.core.mcp_security import (
        TrustScore as TrustScore,
    )
    from aegis.core.mcp_security_report import (
        MCPSecurityReport as MCPSecurityReport,
    )
    from aegis.core.mcp_security_report import (
        MCPSecurityReportGenerator as MCPSecurityReportGenerator,
    )
    from aegis.core.mcp_security_report import (
        ServerSecurityProfile as ServerSecurityProfile,
    )
    from aegis.core.mcp_shadow import (
        ShadowFinding as ShadowFinding,
    )
    from aegis.core.mcp_shadow import (
        ToolRegistration as ToolRegistration,
    )
    from aegis.core.mcp_shadow import (
        ToolShadowDetector as ToolShadowDetector,
    )
    from aegis.core.mcp_transport import (
        MCPTransportValidator as MCPTransportValidator,
    )
    from aegis.core.mcp_transport import (
        NetworkConfig as NetworkConfig,
    )
    from aegis.core.mcp_transport import (
        StdioConfig as StdioConfig,
    )
    from aegis.core.mcp_transport import (
        TransportFinding as TransportFinding,
    )
    from aegis.core.mcp_transport import (
        TransportProfile as TransportProfile,
    )
    from aegis.core.mcp_vuln_db import (
        MCPVulnDB as MCPVulnDB,
    )
    from aegis.core.mcp_vuln_db import (
        VulnEntry as VulnEntry,
    )
    from aegis.core.mcp_vuln_db import (
        VulnFinding as VulnFinding,
    )
    from aegis.core.otel_export import (
        AegisEvent as AegisEvent,
    )
    from aegis.core.otel_export import (
        AegisOTelExporter as AegisOTelExporter,
    )
    from aegis.core.plan import ExecutionPlan as ExecutionPlan
    from aegis.core.plan_rules import (
        CumulativeRiskThreshold as CumulativeRiskThreshold,
    )
    from aegis.core.plan_rules import (
        PlanRules as PlanRules,
    )
    from aegis.core.plan_rules import (
        PlanViolation as PlanViolation,
    )
    from aegis.core.plan_rules import (
        SequencePattern as SequencePattern,
    )
    from aegis.core.policy import (
        Approval as Approval,
    )
    from aegis.core.policy import (
        Policy as Policy,
    )
    from aegis.core.policy import (
        PolicyDecision as PolicyDecision,
    )
    from aegis.core.policy import (
        PolicyRule as PolicyRule,
    )
    from aegis.core.policy_git import (
        PolicyDiffFormatter as PolicyDiffFormatter,
    )
    from aegis.core.policy_git import (
        PolicyDriftDetector as PolicyDriftDetector,
    )
    from aegis.core.policy_git import (
        PolicyImpactAnalyzer as PolicyImpactAnalyzer,
    )
    from aegis.core.policy_git import (
        export_policy_yaml as export_policy_yaml,
    )
    from aegis.core.rate_limiter import (
        RateLimiter as RateLimiter,
    )
    from aegis.core.rate_limiter import (
        RateLimitResult as RateLimitResult,
    )
    from aegis.core.rate_limiter import (
        RateLimitRule as RateLimitRule,
    )
    from aegis.core.result import Result as Result
    from aegis.core.result import ResultStatus as ResultStatus
    from aegis.core.retry import RetryPolicy as RetryPolicy
    from aegis.core.risk import RiskLevel as RiskLevel
    from aegis.core.semantic import (
        SEMANTIC_CATEGORIES as SEMANTIC_CATEGORIES,
    )
    from aegis.core.semantic import (
        KeywordSemanticEvaluator as KeywordSemanticEvaluator,
    )
    from aegis.core.semantic import (
        SemanticEvaluator as SemanticEvaluator,
    )
    from aegis.core.semantic import (
        evaluate_semantic_condition as evaluate_semantic_condition,
    )
    from aegis.core.session_replay import (
        ReplayReport as ReplayReport,
    )
    from aegis.core.session_replay import (
        SessionRecorder as SessionRecorder,
    )
    from aegis.core.session_replay import (
        SessionReplayer as SessionReplayer,
    )
