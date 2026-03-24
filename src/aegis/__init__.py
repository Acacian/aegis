"""Aegis: Policy & approval runtime for AI agents."""

from aegis.config import (
    AegisConfig,
    AuditConfig,
    CostConfig,
    GuardrailsConfig,
    InjectionConfig,
    IntegrationsConfig,
    PIIConfig,
    PolicyConfig,
)
from aegis.core.action import Action
from aegis.core.agent_identity import AgentIdentity, AgentRegistry, DelegationEvent
from aegis.core.anomaly import AnomalyDetector, AnomalyResult, BehaviorProfile
from aegis.core.builder import PolicyBuilder
from aegis.core.crypto_audit import CryptoAuditChain
from aegis.core.hierarchy import PolicyConflict, PolicyHierarchy
from aegis.core.plan import ExecutionPlan
from aegis.core.policy import Approval, Policy, PolicyDecision
from aegis.core.rate_limiter import RateLimiter
from aegis.core.rbac import AccessController, Permission, Role, User
from aegis.core.regulatory import ComplianceMapper, RegulatoryFramework
from aegis.core.replay import ReplayEngine
from aegis.core.result import Result, ResultStatus
from aegis.core.retry import RetryPolicy
from aegis.core.risk import RiskLevel
from aegis.core.versioning import PolicyStore, PolicyVersion
from aegis.core.webhooks import WebhookManager
from aegis.init import Aegis
from aegis.integrations.decorators import guard
from aegis.integrations.errors import AegisBlockedError, AegisGuardrailError
from aegis.integrations.patch_anthropic import patch_anthropic, unpatch_anthropic
from aegis.integrations.patch_openai import patch_openai, unpatch_openai
from aegis.runtime.batch_audit import BatchAuditLogger
from aegis.runtime.engine import Runtime, RuntimeHooks
from aegis.runtime.watcher import PolicyWatcher

# ---- Unified entry point ------------------------------------------------
# These top-level functions delegate to the Aegis singleton so that
# ``import aegis; aegis.init()`` works.

init = Aegis.init
shutdown = Aegis.shutdown
get = Aegis.get

__all__ = [
    # Unified init API
    "Aegis",
    "AegisConfig",
    "AuditConfig",
    "CostConfig",
    "get",
    "GuardrailsConfig",
    "init",
    "InjectionConfig",
    "IntegrationsConfig",
    "PIIConfig",
    "PolicyConfig",
    "shutdown",
    # Core
    "Action",
    "AegisBlockedError",
    "AegisGuardrailError",
    "AgentIdentity",
    "AgentRegistry",
    "AnomalyDetector",
    "AnomalyResult",
    "Approval",
    "AccessController",
    "BatchAuditLogger",
    "BehaviorProfile",
    "ComplianceMapper",
    "CryptoAuditChain",
    "DelegationEvent",
    "ExecutionPlan",
    "guard",
    "patch_anthropic",
    "patch_openai",
    "Permission",
    "Policy",
    "PolicyBuilder",
    "PolicyConflict",
    "PolicyDecision",
    "PolicyHierarchy",
    "PolicyStore",
    "PolicyVersion",
    "PolicyWatcher",
    "RateLimiter",
    "RegulatoryFramework",
    "ReplayEngine",
    "Result",
    "ResultStatus",
    "RetryPolicy",
    "RiskLevel",
    "Role",
    "Runtime",
    "RuntimeHooks",
    "unpatch_anthropic",
    "unpatch_openai",
    "User",
    "WebhookManager",
]

__version__ = "0.3.0"
