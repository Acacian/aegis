"""Aegis: Policy & approval runtime for AI agents.

All public symbols are lazy-loaded on first access so that
``import aegis`` is fast (~30ms) regardless of which features you use.
Only ``Aegis``, ``init``, ``shutdown``, ``get``, and ``auto_instrument``
are loaded eagerly — everything else is imported when first accessed.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

# ---- Eager: the minimal set for aegis.init() / aegis.auto_instrument() ----
from aegis.init import Aegis
from aegis.instrument import auto_instrument

init = Aegis.init
shutdown = Aegis.shutdown
get = Aegis.get

__version__ = "0.9.5"

# ---- Lazy imports ----------------------------------------------------------

_LAZY_IMPORTS: dict[str, str] = {
    # Config
    "AegisConfig": "aegis.config",
    "AuditConfig": "aegis.config",
    "CostConfig": "aegis.config",
    "GuardrailsConfig": "aegis.config",
    "InjectionConfig": "aegis.config",
    "IntegrationsConfig": "aegis.config",
    "PIIConfig": "aegis.config",
    "PolicyConfig": "aegis.config",
    # -- v0.9 selection-governance & tripartite ActionClaim (academic features) --
    "ActionClaim": "aegis.core.action_claim",
    "DeclaredFields": "aegis.core.action_claim",
    "AssessedFields": "aegis.core.action_claim",
    "ChainFields": "aegis.core.action_claim",
    "ClaimVerdict": "aegis.core.action_claim",
    "ImpactVector": "aegis.core.action_claim",
    "DelegationChainEntry": "aegis.core.action_claim",
    "ClaimPolicy": "aegis.core.claim_policy",
    "ClaimPolicyDecision": "aegis.core.claim_policy",
    "ClaimAssessor": "aegis.core.justification_gap",
    "ImpactScorer": "aegis.core.justification_gap",
    "RuleBasedImpactScorer": "aegis.core.justification_gap",
    "SelectionAuditor": "aegis.core.selection_audit",
    "SelectionSet": "aegis.core.selection_audit",
    "SelectionOption": "aegis.core.selection_audit",
    "EliminatedOption": "aegis.core.selection_audit",
    "EliminationReason": "aegis.core.selection_audit",
    "SelectionAuditResult": "aegis.core.selection_audit",
    "SelectionFinding": "aegis.core.selection_audit",
    "FindingType": "aegis.core.selection_audit",
    "CommitRevealSelection": "aegis.core.selection_audit",
    "audit_selection": "aegis.core.selection_audit",
    "set_global_auditor": "aegis.core.selection_audit",
    "A2AGovernor": "aegis.core.a2a_governance",
    "A2AMessage": "aegis.core.a2a_governance",
    "A2ADecision": "aegis.core.a2a_governance",
    "GovernanceHandshake": "aegis.core.a2a_governance",
    "GovernanceEnvelope": "aegis.core.a2a_governance",
    "HandshakeResult": "aegis.core.a2a_governance",
    # Core types
    "Action": "aegis.core.action",
    "AgentConstitution": "aegis.core.constitution",
    "AgentIdentity": "aegis.core.agent_identity",
    "AgentRegistry": "aegis.core.agent_identity",
    "AnomalyDetector": "aegis.core.anomaly",
    "AnomalyResult": "aegis.core.anomaly",
    "Approval": "aegis.core.policy",
    "AccessController": "aegis.core.rbac",
    "BatchAuditLogger": "aegis.runtime.batch_audit",
    "BehaviorProfile": "aegis.core.anomaly",
    "ComplianceMapper": "aegis.core.regulatory",
    "CryptoAuditChain": "aegis.core.crypto_audit",
    "DelegationEvent": "aegis.core.agent_identity",
    "ExecutionPlan": "aegis.core.plan",
    "LeakageDetector": "aegis.core.leakage_detector",
    "Permission": "aegis.core.rbac",
    "PlanRules": "aegis.core.plan_rules",
    "PlanViolation": "aegis.core.plan_rules",
    "Policy": "aegis.core.policy",
    "PolicyBuilder": "aegis.core.builder",
    "PolicyConflict": "aegis.core.hierarchy",
    "PolicyDecision": "aegis.core.policy",
    "PolicyHierarchy": "aegis.core.hierarchy",
    "PolicyStore": "aegis.core.versioning",
    "PolicyVersion": "aegis.core.versioning",
    "PolicyWatcher": "aegis.runtime.watcher",
    "RateLimiter": "aegis.core.rate_limiter",
    "RegulatoryFramework": "aegis.core.regulatory",
    "ReplayEngine": "aegis.core.replay",
    "Result": "aegis.core.result",
    "ResultStatus": "aegis.core.result",
    "RetryPolicy": "aegis.core.retry",
    "RiskLevel": "aegis.core.risk",
    "Role": "aegis.core.rbac",
    "Runtime": "aegis.runtime.engine",
    "RuntimeHooks": "aegis.runtime.engine",
    "User": "aegis.core.rbac",
    "WebhookManager": "aegis.core.webhooks",
    # Integrations
    "AegisBlockedError": "aegis.integrations.errors",
    "AegisGuardrailError": "aegis.integrations.errors",
    "guard": "aegis.integrations.decorators",
    "patch_anthropic": "aegis.integrations.patch_anthropic",
    "patch_openai": "aegis.integrations.patch_openai",
    "unpatch_anthropic": "aegis.integrations.patch_anthropic",
    "unpatch_openai": "aegis.integrations.patch_openai",
    # -- Paper-based features (v0.10+) --
    # Taint tracking (arXiv:2505.23643)
    "TaintTracker": "aegis.core.taint",
    "TaintLabel": "aegis.core.taint",
    "TaintPolicy": "aegis.core.taint",
    "TaintFinding": "aegis.core.taint",
    # Resource contracts (arXiv:2601.08815)
    "ResourceContract": "aegis.core.contracts",
    "ContractMonitor": "aegis.core.contracts",
    "ContractViolation": "aegis.core.contracts",
    "resource_contract": "aegis.core.contracts",
    # Merkle audit (arXiv:2602.20214)
    "MerkleAuditTree": "aegis.core.merkle_audit",
    "MerkleProof": "aegis.core.merkle_audit",
    # Cross-tool privacy (arXiv:2512.16310)
    "CrossToolPrivacyDetector": "aegis.core.cross_tool_privacy",
    "PrivacyFinding": "aegis.core.cross_tool_privacy",
    # Tool output guard (arXiv:2602.22724)
    "ToolOutputGuardrail": "aegis.guardrails.tool_output",
    # -- OWASP Agentic modules --
    # Code execution safety (ASI05)
    "CodeExecSafetyGate": "aegis.core.code_exec_safety",
    "CodeExecResult": "aegis.core.code_exec_safety",
    # Memory integrity (ASI06)
    "MemoryIntegrityVerifier": "aegis.core.memory_integrity",
    "IntegrityViolation": "aegis.core.memory_integrity",
    # Cascade guard (ASI08)
    "CascadeGuard": "aegis.core.cascade_guard",
    "CascadeDecision": "aegis.core.cascade_guard",
    # Behavioral drift (ASI10)
    "DriftDetector": "aegis.core.behavioral_drift",
    "DriftFinding": "aegis.core.behavioral_drift",
    # -- Paper-based modules (v0.11+) --
    # MCP STDIO injection guard (OX Security advisory 2026-04-15)
    "StdioGuard": "aegis.core.mcp_stdio_guard",
    "StdioInjectionScanner": "aegis.core.mcp_stdio_guard",
    "StdioFrameValidator": "aegis.core.mcp_stdio_guard",
    "StdioScanResult": "aegis.core.mcp_stdio_guard",
    # MCP manifest signing (arXiv:2512.06556)
    "ManifestSigner": "aegis.core.mcp_manifest",
    "ManifestVerifier": "aegis.core.mcp_manifest",
    # ETDI tool verification (arXiv:2506.01333)
    "ETDIVerifier": "aegis.core.etdi",
    "ETDIViolation": "aegis.core.etdi",
    # MCP vulnerability scanner (arXiv:2510.23673)
    "MCPVulnScanner": "aegis.core.mcp_vuln_scanner",
    "VulnFinding": "aegis.core.mcp_vuln_scanner",
    # MCP threat intelligence (arXiv:2508.14925)
    "MCPThreatIntel": "aegis.core.mcp_threat_intel",
    "ThreatMatch": "aegis.core.mcp_threat_intel",
    # Trust scoring (arXiv:2508.18765)
    "TrustScorer": "aegis.core.trust_score",
    "TrustScore": "aegis.core.trust_score",
    # Autonomy levels (arXiv:2506.12469)
    "AutonomyManager": "aegis.core.autonomy_level",
    "AutonomyLevel": "aegis.core.autonomy_level",
    # Trust calibration (arXiv:2509.23497)
    "TrustCalibrator": "aegis.core.trust_calibration",
    "CalibrationDecision": "aegis.core.trust_calibration",
    # Threat taxonomy (arXiv:2510.23883)
    "ThreatTaxonomy": "aegis.core.threat_taxonomy",
    "ThreatAssessment": "aegis.core.threat_taxonomy",
    # Tool poisoning graph (arXiv:2508.20412)
    "DecisionDependenceGraph": "aegis.core.tool_poisoning_graph",
    "PoisoningReport": "aegis.core.tool_poisoning_graph",
    # Temporal monitor (arXiv:2509.20364)
    "TemporalMonitor": "aegis.core.temporal_monitor",
    "TemporalViolation": "aegis.core.temporal_monitor",
    # RAG guard (arXiv:2510.25025)
    "RAGGuard": "aegis.guardrails.rag_guard",
    "RAGScanResult": "aegis.guardrails.rag_guard",
    # MAS monitor (arXiv:2510.19420)
    "MASMonitor": "aegis.core.mas_monitor",
    "MASReport": "aegis.core.mas_monitor",
    # Reversibility (arXiv:2510.14503)
    "ReversibilityScorer": "aegis.core.reversibility",
    "ReversibilityScore": "aegis.core.reversibility",
    # Sandbox policy (arXiv:2512.12806)
    "SandboxPolicy": "aegis.core.sandbox_policy",
    "SandboxDecision": "aegis.core.sandbox_policy",
    # Execution trace (arXiv:2512.15892)
    "ExecutionTracer": "aegis.core.exec_trace",
    "TraceVerification": "aegis.core.exec_trace",
    # Hazard classifier (arXiv:2412.13178)
    "HazardClassifier": "aegis.core.hazard_classifier",
    "HazardAssessment": "aegis.core.hazard_classifier",
    # Zero-trust agent (arXiv:2505.19301)
    "ZeroTrustAgent": "aegis.core.zero_trust_agent",
    "AgentCredential": "aegis.core.zero_trust_agent",
    # Identity binding (arXiv:2512.17538)
    "IdentityBinder": "aegis.core.identity_binding",
    "IdentityBinding": "aegis.core.identity_binding",
    # Audit lifecycle (arXiv:2601.20727)
    "AuditLifecycle": "aegis.core.audit_lifecycle",
    "LifecycleEvent": "aegis.core.audit_lifecycle",
    # Data isolation (arXiv:2403.04960)
    "DataIsolator": "aegis.core.data_isolation",
    "IsolationViolation": "aegis.core.data_isolation",
}

__all__ = [
    # Eager
    "Aegis",
    "auto_instrument",
    "get",
    "init",
    "shutdown",
    # Lazy (sorted)
    *sorted(_LAZY_IMPORTS.keys()),
]


def __getattr__(name: str) -> object:
    if name in _LAZY_IMPORTS:
        module = importlib.import_module(_LAZY_IMPORTS[name])
        value = getattr(module, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


if TYPE_CHECKING:
    from aegis.config import (
        AegisConfig as AegisConfig,
    )
    from aegis.config import (
        AuditConfig as AuditConfig,
    )
    from aegis.config import (
        CostConfig as CostConfig,
    )
    from aegis.config import (
        GuardrailsConfig as GuardrailsConfig,
    )
    from aegis.config import (
        InjectionConfig as InjectionConfig,
    )
    from aegis.config import (
        IntegrationsConfig as IntegrationsConfig,
    )
    from aegis.config import (
        PIIConfig as PIIConfig,
    )
    from aegis.config import (
        PolicyConfig as PolicyConfig,
    )
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

    # Paper-based modules (v0.11+)
    from aegis.core.audit_lifecycle import (
        AuditLifecycle as AuditLifecycle,
    )
    from aegis.core.audit_lifecycle import (
        LifecycleEvent as LifecycleEvent,
    )
    from aegis.core.autonomy_level import (
        AutonomyLevel as AutonomyLevel,
    )
    from aegis.core.autonomy_level import (
        AutonomyManager as AutonomyManager,
    )

    # OWASP Agentic modules
    from aegis.core.behavioral_drift import (
        DriftDetector as DriftDetector,
    )
    from aegis.core.behavioral_drift import (
        DriftFinding as DriftFinding,
    )
    from aegis.core.builder import PolicyBuilder as PolicyBuilder
    from aegis.core.cascade_guard import (
        CascadeDecision as CascadeDecision,
    )
    from aegis.core.cascade_guard import (
        CascadeGuard as CascadeGuard,
    )
    from aegis.core.claim_policy import (
        ClaimPolicy as ClaimPolicy,
    )
    from aegis.core.claim_policy import (
        ClaimPolicyDecision as ClaimPolicyDecision,
    )
    from aegis.core.code_exec_safety import (
        CodeExecResult as CodeExecResult,
    )
    from aegis.core.code_exec_safety import (
        CodeExecSafetyGate as CodeExecSafetyGate,
    )
    from aegis.core.constitution import AgentConstitution as AgentConstitution

    # Paper-based features
    from aegis.core.contracts import (
        ContractMonitor as ContractMonitor,
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
    from aegis.core.cross_tool_privacy import (
        CrossToolPrivacyDetector as CrossToolPrivacyDetector,
    )
    from aegis.core.cross_tool_privacy import (
        PrivacyFinding as PrivacyFinding,
    )
    from aegis.core.crypto_audit import CryptoAuditChain as CryptoAuditChain
    from aegis.core.data_isolation import (
        DataIsolator as DataIsolator,
    )
    from aegis.core.data_isolation import (
        IsolationViolation as IsolationViolation,
    )
    from aegis.core.etdi import ETDIVerifier as ETDIVerifier
    from aegis.core.etdi import ETDIViolation as ETDIViolation
    from aegis.core.exec_trace import (
        ExecutionTracer as ExecutionTracer,
    )
    from aegis.core.exec_trace import (
        TraceVerification as TraceVerification,
    )
    from aegis.core.hazard_classifier import (
        HazardAssessment as HazardAssessment,
    )
    from aegis.core.hazard_classifier import (
        HazardClassifier as HazardClassifier,
    )
    from aegis.core.hierarchy import (
        PolicyConflict as PolicyConflict,
    )
    from aegis.core.hierarchy import (
        PolicyHierarchy as PolicyHierarchy,
    )
    from aegis.core.identity_binding import (
        IdentityBinder as IdentityBinder,
    )
    from aegis.core.identity_binding import (
        IdentityBinding as IdentityBinding,
    )
    from aegis.core.justification_gap import (
        ClaimAssessor as ClaimAssessor,
    )
    from aegis.core.justification_gap import (
        ImpactScorer as ImpactScorer,
    )
    from aegis.core.justification_gap import (
        RuleBasedImpactScorer as RuleBasedImpactScorer,
    )
    from aegis.core.leakage_detector import LeakageDetector as LeakageDetector
    from aegis.core.mas_monitor import MASMonitor as MASMonitor
    from aegis.core.mas_monitor import MASReport as MASReport
    from aegis.core.mcp_manifest import (
        ManifestSigner as ManifestSigner,
    )
    from aegis.core.mcp_manifest import (
        ManifestVerifier as ManifestVerifier,
    )
    from aegis.core.mcp_threat_intel import (
        MCPThreatIntel as MCPThreatIntel,
    )
    from aegis.core.mcp_threat_intel import (
        ThreatMatch as ThreatMatch,
    )
    from aegis.core.mcp_vuln_scanner import (
        MCPVulnScanner as MCPVulnScanner,
    )
    from aegis.core.mcp_vuln_scanner import (
        VulnFinding as VulnFinding,
    )
    from aegis.core.memory_integrity import (
        IntegrityViolation as IntegrityViolation,
    )
    from aegis.core.memory_integrity import (
        MemoryIntegrityVerifier as MemoryIntegrityVerifier,
    )
    from aegis.core.merkle_audit import (
        MerkleAuditTree as MerkleAuditTree,
    )
    from aegis.core.merkle_audit import (
        MerkleProof as MerkleProof,
    )
    from aegis.core.plan import ExecutionPlan as ExecutionPlan
    from aegis.core.plan_rules import (
        PlanRules as PlanRules,
    )
    from aegis.core.plan_rules import (
        PlanViolation as PlanViolation,
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
    from aegis.core.rate_limiter import RateLimiter as RateLimiter
    from aegis.core.rbac import (
        AccessController as AccessController,
    )
    from aegis.core.rbac import (
        Permission as Permission,
    )
    from aegis.core.rbac import (
        Role as Role,
    )
    from aegis.core.rbac import (
        User as User,
    )
    from aegis.core.regulatory import (
        ComplianceMapper as ComplianceMapper,
    )
    from aegis.core.regulatory import (
        RegulatoryFramework as RegulatoryFramework,
    )
    from aegis.core.replay import ReplayEngine as ReplayEngine
    from aegis.core.result import Result as Result
    from aegis.core.result import ResultStatus as ResultStatus
    from aegis.core.retry import RetryPolicy as RetryPolicy
    from aegis.core.reversibility import (
        ReversibilityScore as ReversibilityScore,
    )
    from aegis.core.reversibility import (
        ReversibilityScorer as ReversibilityScorer,
    )
    from aegis.core.risk import RiskLevel as RiskLevel
    from aegis.core.sandbox_policy import (
        SandboxDecision as SandboxDecision,
    )
    from aegis.core.sandbox_policy import (
        SandboxPolicy as SandboxPolicy,
    )
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
        FindingType as FindingType,
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
    from aegis.core.selection_audit import (
        set_global_auditor as set_global_auditor,
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
        TaintTracker as TaintTracker,
    )
    from aegis.core.temporal_monitor import (
        TemporalMonitor as TemporalMonitor,
    )
    from aegis.core.temporal_monitor import (
        TemporalViolation as TemporalViolation,
    )
    from aegis.core.threat_taxonomy import (
        ThreatAssessment as ThreatAssessment,
    )
    from aegis.core.threat_taxonomy import (
        ThreatTaxonomy as ThreatTaxonomy,
    )
    from aegis.core.tool_poisoning_graph import (
        DecisionDependenceGraph as DecisionDependenceGraph,
    )
    from aegis.core.tool_poisoning_graph import (
        PoisoningReport as PoisoningReport,
    )
    from aegis.core.trust_calibration import (
        CalibrationDecision as CalibrationDecision,
    )
    from aegis.core.trust_calibration import (
        TrustCalibrator as TrustCalibrator,
    )
    from aegis.core.trust_score import TrustScore as TrustScore
    from aegis.core.trust_score import TrustScorer as TrustScorer
    from aegis.core.versioning import (
        PolicyStore as PolicyStore,
    )
    from aegis.core.versioning import (
        PolicyVersion as PolicyVersion,
    )
    from aegis.core.webhooks import WebhookManager as WebhookManager
    from aegis.core.zero_trust_agent import (
        AgentCredential as AgentCredential,
    )
    from aegis.core.zero_trust_agent import (
        ZeroTrustAgent as ZeroTrustAgent,
    )
    from aegis.guardrails.rag_guard import RAGGuard as RAGGuard
    from aegis.guardrails.rag_guard import (
        RAGScanResult as RAGScanResult,
    )
    from aegis.guardrails.tool_output import (
        ToolOutputGuardrail as ToolOutputGuardrail,
    )
    from aegis.integrations.decorators import guard as guard
    from aegis.integrations.errors import (
        AegisBlockedError as AegisBlockedError,
    )
    from aegis.integrations.errors import (
        AegisGuardrailError as AegisGuardrailError,
    )
    from aegis.integrations.patch_anthropic import (
        patch_anthropic as patch_anthropic,
    )
    from aegis.integrations.patch_anthropic import (
        unpatch_anthropic as unpatch_anthropic,
    )
    from aegis.integrations.patch_openai import (
        patch_openai as patch_openai,
    )
    from aegis.integrations.patch_openai import (
        unpatch_openai as unpatch_openai,
    )
    from aegis.runtime.batch_audit import BatchAuditLogger as BatchAuditLogger
    from aegis.runtime.engine import (
        Runtime as Runtime,
    )
    from aegis.runtime.engine import (
        RuntimeHooks as RuntimeHooks,
    )
    from aegis.runtime.watcher import PolicyWatcher as PolicyWatcher
