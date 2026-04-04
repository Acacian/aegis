"""Aegis Proxy server -- external governance gateway.

Intercepts tool calls, constructs ActionClaims, evaluates
justification gap, and forwards governed calls to upstreams.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

from aegis.proxy.config import ProxyConfig, UpstreamConfig

logger = logging.getLogger("aegis.proxy")


@dataclass
class ProxyResult:
    """Result of proxy tool call evaluation."""

    allowed: bool
    reason: str = ""
    data: Any = None
    requires_escalation: bool = False
    claim: Any = None
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])


class AegisProxy:
    """External governance gateway for AI agent tool calls.

    Pipeline:
    1. Authenticate agent
    2. Construct ActionClaim from tool call
    3. Assess impact (JustificationGapComputer)
    4. Evaluate policy
    5. Check circuit breaker
    6. Forward or block
    7. Audit log
    """

    def __init__(self, config: ProxyConfig) -> None:
        self._config = config
        self._upstreams: dict[str, UpstreamConfig] = {u.name: u for u in config.upstreams}
        self._policy: Any = None
        self._gap_computer: Any = None
        self._impact_scorer: Any = None
        self._congruence_checker: Any = None
        self._circuit_breakers: dict[str, Any] = {}
        self._started = False

    async def start(self) -> None:
        """Initialize proxy components."""
        if self._config.policy_path:
            from aegis.core.policy import Policy

            self._policy = Policy.from_yaml(self._config.policy_path)

        if self._config.claims.enabled:
            from aegis.core.justification_gap import (
                CongruenceChecker,
                JustificationGapComputer,
                RuleBasedImpactScorer,
            )

            self._gap_computer = JustificationGapComputer(
                approve_threshold=self._config.claims.gap_approve_threshold,
                escalate_threshold=self._config.claims.gap_escalate_threshold,
            )
            self._impact_scorer = RuleBasedImpactScorer()
            self._congruence_checker = CongruenceChecker()

        if self._config.circuit_breaker.enabled:
            from aegis.core.circuit_breaker import (
                CircuitBreaker,
            )
            from aegis.core.circuit_breaker import (
                CircuitBreakerConfig as CBConfig,
            )

            cb_cfg = CBConfig(
                failure_threshold=self._config.circuit_breaker.failure_threshold,
                recovery_timeout_s=self._config.circuit_breaker.recovery_timeout_s,
            )
            for name in self._upstreams:
                self._circuit_breakers[name] = CircuitBreaker(
                    name=f"proxy-{name}",
                    config=cb_cfg,
                )

        self._started = True
        logger.info(
            "Aegis Proxy started on %s:%d (mode=%s, upstreams=%d)",
            self._config.listen_host,
            self._config.listen_port,
            self._config.mode,
            len(self._upstreams),
        )

    def authenticate(self, agent_id: str, token: str) -> bool:
        """Authenticate an agent via bearer token."""
        if self._config.auth.mode == "none":
            return True
        if self._config.auth.mode == "bearer":
            expected = self._config.auth.tokens.get(agent_id)
            return expected is not None and expected == token
        return False

    async def handle_tool_call(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        server_name: str,
        agent_id: str = "",
        justification: str = "",
        originating_goal: str = "",
    ) -> ProxyResult:
        """Process a tool call through the governance pipeline."""
        from aegis.core.action_claim import (
            ActionClaim,
            ChainFields,
            ClaimVerdict,
            DeclaredFields,
        )

        trace_id = uuid.uuid4().hex[:16]

        # 1. Check upstream exists
        upstream = self._upstreams.get(server_name)
        if upstream is None:
            return ProxyResult(
                allowed=False,
                reason=f"Unknown upstream: {server_name}",
                trace_id=trace_id,
            )

        # 2. Check circuit breaker
        cb = self._circuit_breakers.get(server_name)
        if cb is not None:
            try:
                cb.check_allowed()
            except Exception:
                return ProxyResult(
                    allowed=False,
                    reason=f"Circuit breaker open for {server_name}",
                    trace_id=trace_id,
                )

        # 3. Construct ActionClaim
        claim = ActionClaim(
            declared=DeclaredFields(
                proposed_transition=tool_name,
                target=server_name,
                justification=justification,
                originating_goal=originating_goal,
                preconditions=arguments,
            ),
            chain=ChainFields(
                principal=agent_id,
                chain_depth=0,
            ),
        )

        # 4. Assess impact
        if self._config.claims.enabled and self._impact_scorer and self._gap_computer:
            assessed_impact = self._impact_scorer.score(claim)
            gap_result = self._gap_computer.compute(
                claim.declared.declared_impact,
                assessed_impact,
            )
            claim.verdict = gap_result.verdict

            if self._config.mode == "zero-trust":
                if gap_result.verdict == ClaimVerdict.BLOCK:
                    return ProxyResult(
                        allowed=False,
                        reason=gap_result.explanation,
                        claim=claim,
                        trace_id=trace_id,
                    )
                if gap_result.verdict == ClaimVerdict.ESCALATE:
                    return ProxyResult(
                        allowed=False,
                        reason=f"Escalation required: {gap_result.explanation}",
                        requires_escalation=True,
                        claim=claim,
                        trace_id=trace_id,
                    )

        # 5. Policy evaluation
        if self._policy:
            action = claim.to_action()
            decision = self._policy.evaluate(action)
            if not decision.is_allowed:
                return ProxyResult(
                    allowed=False,
                    reason=f"Policy blocked: {decision.matched_rule}",
                    claim=claim,
                    trace_id=trace_id,
                )

        # 6. Forward (actual forwarding deferred -- returns placeholder)
        return ProxyResult(
            allowed=True,
            claim=claim,
            trace_id=trace_id,
        )
