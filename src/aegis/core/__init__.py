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
    # action_claim
    "ActionClaim": "aegis.core.action_claim",
    "AssessedFields": "aegis.core.action_claim",
    "ChainFields": "aegis.core.action_claim",
    "ClaimVerdict": "aegis.core.action_claim",
    "DeclaredFields": "aegis.core.action_claim",
    "DelegationChainEntry": "aegis.core.action_claim",
    "ImpactVector": "aegis.core.action_claim",
    "validate_monotone_constraint": "aegis.core.action_claim",
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
    # drift
    "DriftAction": "aegis.core.drift",
    "DriftBaseline": "aegis.core.drift",
    "DriftDetector": "aegis.core.drift",
    "DriftMetricConfig": "aegis.core.drift",
    "DriftResult": "aegis.core.drift",
    "DriftSeverity": "aegis.core.drift",
    "DriftType": "aegis.core.drift",
    "HistoricalSnapshot": "aegis.core.drift",
    # drift_policy
    "DriftPolicyDecision": "aegis.core.drift_policy",
    "DriftPolicyEvaluator": "aegis.core.drift_policy",
    "DriftPolicyRule": "aegis.core.drift_policy",
    # budget
    "BudgetAction": "aegis.core.budget",
    "BudgetExhausted": "aegis.core.budget",
    "CostRecord": "aegis.core.budget",
    "CostTracker": "aegis.core.budget",
    "ModelPricing": "aegis.core.budget",
    "TokenUsage": "aegis.core.budget",
    # cascade_guard (OWASP ASI08: Cascading Failures)
    "AgentHealth": "aegis.core.cascade_guard",
    "AgentState": "aegis.core.cascade_guard",
    "CascadeDecision": "aegis.core.cascade_guard",
    "CascadeEvent": "aegis.core.cascade_guard",
    "CascadeEventType": "aegis.core.cascade_guard",
    "CascadeGuard": "aegis.core.cascade_guard",
    "CascadeReport": "aegis.core.cascade_guard",
    # circuit_breaker
    "AnomalyCircuitBridge": "aegis.core.circuit_breaker",
    "CircuitBreaker": "aegis.core.circuit_breaker",
    "CircuitBreakerConfig": "aegis.core.circuit_breaker",
    "CircuitBreakerRegistry": "aegis.core.circuit_breaker",
    "CircuitOpenError": "aegis.core.circuit_breaker",
    "CircuitState": "aegis.core.circuit_breaker",
    "QDVMetric": "aegis.core.circuit_breaker",
    "QualityLevel": "aegis.core.circuit_breaker",
    # builder
    "PolicyBuilder": "aegis.core.builder",
    "RuleBuilder": "aegis.core.builder",
    # code_exec_safety (OWASP Agentic ASI05)
    "Category": "aegis.core.code_exec_safety",
    "CodeExecFinding": "aegis.core.code_exec_safety",
    "CodeExecResult": "aegis.core.code_exec_safety",
    "CodeExecSafetyGate": "aegis.core.code_exec_safety",
    "ExecAction": "aegis.core.code_exec_safety",
    "Severity": "aegis.core.code_exec_safety",
    # compliance
    "ComplianceFinding": "aegis.core.compliance",
    "ComplianceReport": "aegis.core.compliance",
    "ReportGenerator": "aegis.core.compliance",
    # cost_attribution
    "AgentCostNode": "aegis.core.cost_attribution",
    "CostAttributionTree": "aegis.core.cost_attribution",
    # cost_policy
    "CostAction": "aegis.core.cost_policy",
    "CostDecision": "aegis.core.cost_policy",
    "CostPolicyEnforcer": "aegis.core.cost_policy",
    # model_pricing
    "estimate_call_cost": "aegis.core.model_pricing",
    "get_pricing": "aegis.core.model_pricing",
    "list_models": "aegis.core.model_pricing",
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
    # justification_gap
    "ClaimAssessor": "aegis.core.justification_gap",
    "CongruenceChecker": "aegis.core.justification_gap",
    "ImpactRule": "aegis.core.justification_gap",
    "ImpactScorer": "aegis.core.justification_gap",
    "JustificationGapComputer": "aegis.core.justification_gap",
    "JustificationGapResult": "aegis.core.justification_gap",
    "RuleBasedImpactScorer": "aegis.core.justification_gap",
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
    # selection_audit
    "CommitRevealSelection": "aegis.core.selection_audit",
    "EliminatedOption": "aegis.core.selection_audit",
    "EliminationReason": "aegis.core.selection_audit",
    "SelectionAuditor": "aegis.core.selection_audit",
    "SelectionAuditResult": "aegis.core.selection_audit",
    "SelectionFinding": "aegis.core.selection_audit",
    "SelectionOption": "aegis.core.selection_audit",
    "SelectionSet": "aegis.core.selection_audit",
    "audit_selection": "aegis.core.selection_audit",
    # session_replay
    "ReplayReport": "aegis.core.session_replay",
    "SessionRecorder": "aegis.core.session_replay",
    "SessionReplayer": "aegis.core.session_replay",
    # taint (arXiv:2505.23643 FIDES)
    "TaintAction": "aegis.core.taint",
    "TaintFinding": "aegis.core.taint",
    "TaintLabel": "aegis.core.taint",
    "TaintPolicy": "aegis.core.taint",
    "TaintPolicyRule": "aegis.core.taint",
    "TaintReport": "aegis.core.taint",
    "TaintSeverity": "aegis.core.taint",
    "TaintTracker": "aegis.core.taint",
    "TaintedValue": "aegis.core.taint",
    # contracts (arXiv:2601.08815 Agent Contracts)
    "ContractMonitor": "aegis.core.contracts",
    "ContractStatus": "aegis.core.contracts",
    "ContractViolation": "aegis.core.contracts",
    "ResourceContract": "aegis.core.contracts",
    "resource_contract": "aegis.core.contracts",
    # merkle_audit (arXiv:2602.20214 Right to History)
    "BatchProofResult": "aegis.core.merkle_audit",
    "MerkleAuditTree": "aegis.core.merkle_audit",
    "MerkleLeaf": "aegis.core.merkle_audit",
    "MerkleProof": "aegis.core.merkle_audit",
    # cross_tool_privacy (arXiv:2512.16310 TOP-Bench)
    "CrossToolPrivacyDetector": "aegis.core.cross_tool_privacy",
    "PIICategory": "aegis.core.cross_tool_privacy",
    "PrivacyFinding": "aegis.core.cross_tool_privacy",
    "PrivacyReport": "aegis.core.cross_tool_privacy",
    # memory_integrity (OWASP ASI06: Memory & Context Poisoning)
    "InjectionSignal": "aegis.core.memory_integrity",
    "IntegrityViolation": "aegis.core.memory_integrity",
    "MemoryEntry": "aegis.core.memory_integrity",
    "MemoryIntegrityVerifier": "aegis.core.memory_integrity",
    "MemoryStats": "aegis.core.memory_integrity",
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
    from aegis.core.action_claim import (
        ActionClaim as ActionClaim,
    )
    from aegis.core.action_claim import (
        AssessedFields as AssessedFields,
    )
    from aegis.core.action_claim import (
        ChainFields as ChainFields,
    )
    from aegis.core.action_claim import (
        ClaimVerdict as ClaimVerdict,
    )
    from aegis.core.action_claim import (
        DeclaredFields as DeclaredFields,
    )
    from aegis.core.action_claim import (
        DelegationChainEntry as DelegationChainEntry,
    )
    from aegis.core.action_claim import (
        ImpactVector as ImpactVector,
    )
    from aegis.core.action_claim import (
        validate_monotone_constraint as validate_monotone_constraint,
    )
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
    from aegis.core.cascade_guard import (
        AgentHealth as AgentHealth,
    )
    from aegis.core.cascade_guard import (
        AgentState as AgentState,
    )
    from aegis.core.cascade_guard import (
        CascadeDecision as CascadeDecision,
    )
    from aegis.core.cascade_guard import (
        CascadeEvent as CascadeEvent,
    )
    from aegis.core.cascade_guard import (
        CascadeEventType as CascadeEventType,
    )
    from aegis.core.cascade_guard import (
        CascadeGuard as CascadeGuard,
    )
    from aegis.core.cascade_guard import (
        CascadeReport as CascadeReport,
    )
    from aegis.core.circuit_breaker import (
        AnomalyCircuitBridge as AnomalyCircuitBridge,
    )
    from aegis.core.circuit_breaker import (
        CircuitBreaker as CircuitBreaker,
    )
    from aegis.core.circuit_breaker import (
        CircuitBreakerConfig as CircuitBreakerConfig,
    )
    from aegis.core.circuit_breaker import (
        CircuitBreakerRegistry as CircuitBreakerRegistry,
    )
    from aegis.core.circuit_breaker import (
        CircuitOpenError as CircuitOpenError,
    )
    from aegis.core.circuit_breaker import (
        CircuitState as CircuitState,
    )
    from aegis.core.circuit_breaker import (
        QDVMetric as QDVMetric,
    )
    from aegis.core.circuit_breaker import (
        QualityLevel as QualityLevel,
    )
    from aegis.core.code_exec_safety import (
        Category as Category,
    )
    from aegis.core.code_exec_safety import (
        CodeExecFinding as CodeExecFinding,
    )
    from aegis.core.code_exec_safety import (
        CodeExecResult as CodeExecResult,
    )
    from aegis.core.code_exec_safety import (
        CodeExecSafetyGate as CodeExecSafetyGate,
    )
    from aegis.core.code_exec_safety import (
        ExecAction as ExecAction,
    )
    from aegis.core.code_exec_safety import (
        Severity as Severity,
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
    from aegis.core.contracts import (
        ContractMonitor as ContractMonitor,
    )
    from aegis.core.contracts import (
        ContractStatus as ContractStatus,
    )
    from aegis.core.contracts import (
        ContractViolation as ContractViolation,
    )
    from aegis.core.contracts import (
        ResourceContract as ResourceContract,
    )
    from aegis.core.contracts import (
        resource_contract as resource_contract,
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
    from aegis.core.cost_policy import (
        CostAction as CostAction,
    )
    from aegis.core.cost_policy import (
        CostDecision as CostDecision,
    )
    from aegis.core.cost_policy import (
        CostPolicyEnforcer as CostPolicyEnforcer,
    )
    from aegis.core.cross_tool_privacy import (
        CrossToolPrivacyDetector as CrossToolPrivacyDetector,
    )
    from aegis.core.cross_tool_privacy import (
        PIICategory as PIICategory,
    )
    from aegis.core.cross_tool_privacy import (
        PrivacyFinding as PrivacyFinding,
    )
    from aegis.core.cross_tool_privacy import (
        PrivacyReport as PrivacyReport,
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
    from aegis.core.drift import (
        DriftAction as DriftAction,
    )
    from aegis.core.drift import (
        DriftBaseline as DriftBaseline,
    )
    from aegis.core.drift import (
        DriftDetector as DriftDetector,
    )
    from aegis.core.drift import (
        DriftMetricConfig as DriftMetricConfig,
    )
    from aegis.core.drift import (
        DriftResult as DriftResult,
    )
    from aegis.core.drift import (
        DriftSeverity as DriftSeverity,
    )
    from aegis.core.drift import (
        DriftType as DriftType,
    )
    from aegis.core.drift import (
        HistoricalSnapshot as HistoricalSnapshot,
    )
    from aegis.core.drift_policy import (
        DriftPolicyDecision as DriftPolicyDecision,
    )
    from aegis.core.drift_policy import (
        DriftPolicyEvaluator as DriftPolicyEvaluator,
    )
    from aegis.core.drift_policy import (
        DriftPolicyRule as DriftPolicyRule,
    )
    from aegis.core.justification_gap import (
        ClaimAssessor as ClaimAssessor,
    )
    from aegis.core.justification_gap import (
        CongruenceChecker as CongruenceChecker,
    )
    from aegis.core.justification_gap import (
        ImpactRule as ImpactRule,
    )
    from aegis.core.justification_gap import (
        ImpactScorer as ImpactScorer,
    )
    from aegis.core.justification_gap import (
        JustificationGapComputer as JustificationGapComputer,
    )
    from aegis.core.justification_gap import (
        JustificationGapResult as JustificationGapResult,
    )
    from aegis.core.justification_gap import (
        RuleBasedImpactScorer as RuleBasedImpactScorer,
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
    from aegis.core.memory_integrity import (
        InjectionSignal as InjectionSignal,
    )
    from aegis.core.memory_integrity import (
        IntegrityViolation as IntegrityViolation,
    )
    from aegis.core.memory_integrity import (
        MemoryEntry as MemoryEntry,
    )
    from aegis.core.memory_integrity import (
        MemoryIntegrityVerifier as MemoryIntegrityVerifier,
    )
    from aegis.core.memory_integrity import (
        MemoryStats as MemoryStats,
    )
    from aegis.core.merkle_audit import (
        BatchProofResult as BatchProofResult,
    )
    from aegis.core.merkle_audit import (
        MerkleAuditTree as MerkleAuditTree,
    )
    from aegis.core.merkle_audit import (
        MerkleLeaf as MerkleLeaf,
    )
    from aegis.core.merkle_audit import (
        MerkleProof as MerkleProof,
    )
    from aegis.core.model_pricing import (
        estimate_call_cost as estimate_call_cost,
    )
    from aegis.core.model_pricing import (
        get_pricing as get_pricing,
    )
    from aegis.core.model_pricing import (
        list_models as list_models,
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
    from aegis.core.selection_audit import (
        CommitRevealSelection as CommitRevealSelection,
    )
    from aegis.core.selection_audit import (
        EliminatedOption as EliminatedOption,
    )
    from aegis.core.selection_audit import (
        EliminationReason as EliminationReason,
    )
    from aegis.core.selection_audit import (
        SelectionAuditor as SelectionAuditor,
    )
    from aegis.core.selection_audit import (
        SelectionAuditResult as SelectionAuditResult,
    )
    from aegis.core.selection_audit import (
        SelectionFinding as SelectionFinding,
    )
    from aegis.core.selection_audit import (
        SelectionOption as SelectionOption,
    )
    from aegis.core.selection_audit import (
        SelectionSet as SelectionSet,
    )
    from aegis.core.selection_audit import (
        audit_selection as audit_selection,
    )
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
    from aegis.core.taint import (
        TaintAction as TaintAction,
    )
    from aegis.core.taint import (
        TaintedValue as TaintedValue,
    )
    from aegis.core.taint import (
        TaintFinding as TaintFinding,
    )
    from aegis.core.taint import (
        TaintLabel as TaintLabel,
    )
    from aegis.core.taint import (
        TaintPolicy as TaintPolicy,
    )
    from aegis.core.taint import (
        TaintPolicyRule as TaintPolicyRule,
    )
    from aegis.core.taint import (
        TaintReport as TaintReport,
    )
    from aegis.core.taint import (
        TaintSeverity as TaintSeverity,
    )
    from aegis.core.taint import (
        TaintTracker as TaintTracker,
    )
