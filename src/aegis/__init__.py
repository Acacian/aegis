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

__version__ = "0.9.0"

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
    from aegis.core.builder import PolicyBuilder as PolicyBuilder
    from aegis.core.constitution import AgentConstitution as AgentConstitution
    from aegis.core.crypto_audit import CryptoAuditChain as CryptoAuditChain
    from aegis.core.hierarchy import (
        PolicyConflict as PolicyConflict,
    )
    from aegis.core.hierarchy import (
        PolicyHierarchy as PolicyHierarchy,
    )
    from aegis.core.leakage_detector import LeakageDetector as LeakageDetector
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
    from aegis.core.risk import RiskLevel as RiskLevel
    from aegis.core.versioning import (
        PolicyStore as PolicyStore,
    )
    from aegis.core.versioning import (
        PolicyVersion as PolicyVersion,
    )
    from aegis.core.webhooks import WebhookManager as WebhookManager
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
