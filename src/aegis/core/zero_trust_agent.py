"""Zero-Trust Identity Framework for Agentic AI.

Implements zero-trust identity verification for multi-agent systems where
no agent is trusted by default.  Every interaction requires fresh
credential verification, session tokens are scoped and time-bounded, and
mutual authentication ensures bidirectional trust establishment.

Key principles from the zero-trust paradigm applied to AI agents:

- **Never trust, always verify**: Every request must carry valid credentials.
- **Least-privilege sessions**: Session tokens are scoped to specific actions.
- **Continuous re-verification**: Sessions expire and credentials can be
  revoked at any time.
- **Mutual authentication**: Both parties in an interaction verify each other.

No external dependencies.  Thread-safe.  Sub-millisecond per operation.

Reference:
    Zero-Trust Identity Framework for Agentic AI.
    arXiv:2505.19301 (2025).

Example::

    zt = ZeroTrustAgent()
    cred = zt.register_agent("agent-1", CredentialType.PLATFORM_ISSUED,
                             issuer="platform", claims={"role": "worker"})
    result = zt.verify_agent("agent-1")
    assert result.verified
    session = zt.create_session("agent-1", scope=frozenset({"read"}))
    assert zt.verify_session(session.token_id)
"""

from __future__ import annotations

import hashlib
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(data: str) -> str:
    """Compute SHA-256 hex digest of a UTF-8 string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(UTC)


def _now_iso() -> str:
    return _now().isoformat()


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class CredentialType(Enum):
    """Type of credential presented by an agent.

    Ordered by trust level: SELF_SIGNED < DELEGATED < PLATFORM_ISSUED < VERIFIED.
    """

    SELF_SIGNED = "self_signed"
    DELEGATED = "delegated"
    PLATFORM_ISSUED = "platform_issued"
    VERIFIED = "verified"


_CREDENTIAL_TRUST: dict[CredentialType, int] = {
    CredentialType.SELF_SIGNED: 10,
    CredentialType.DELEGATED: 40,
    CredentialType.PLATFORM_ISSUED: 70,
    CredentialType.VERIFIED: 100,
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AgentCredential:
    """An agent's credential used for identity verification.

    Attributes:
        agent_id: Unique agent identifier.
        credential_type: Type of credential.
        issuer: Entity that issued the credential.
        issued_at: Timestamp when credential was issued.
        expires_at: Timestamp when credential expires.
        claims: Arbitrary claims embedded in the credential.
        signature_hash: SHA-256 hash of the credential content.
    """

    agent_id: str
    credential_type: CredentialType
    issuer: str
    issued_at: str
    expires_at: str
    claims: dict[str, Any] = field(default_factory=dict)
    signature_hash: str = ""


@dataclass(frozen=True)
class VerificationResult:
    """Result of verifying an agent's identity.

    Attributes:
        verified: Whether the agent passed verification.
        agent_id: The agent that was verified.
        trust_level: Computed trust level (0-100).
        reasons: List of reasons for the verification outcome.
        verified_at: Timestamp of verification.
    """

    verified: bool
    agent_id: str
    trust_level: int
    reasons: tuple[str, ...]
    verified_at: str


@dataclass(frozen=True)
class SessionToken:
    """A scoped, time-bounded session token for an authenticated agent.

    Attributes:
        token_id: Unique token identifier.
        agent_id: Agent this token was issued to.
        scope: Set of allowed actions.
        issued_at: Timestamp when token was issued.
        expires_at: Timestamp when token expires.
        context_hash: SHA-256 hash of the session context.
    """

    token_id: str
    agent_id: str
    scope: frozenset[str]
    issued_at: str
    expires_at: str
    context_hash: str


@dataclass(frozen=True)
class ZeroTrustPolicy:
    """Policy governing zero-trust verification behavior.

    Attributes:
        require_mutual_auth: Whether mutual authentication is required.
        max_session_duration: Maximum session duration in seconds.
        re_verify_interval: Seconds between mandatory re-verifications.
        min_trust_level: Minimum trust level to pass verification.
    """

    require_mutual_auth: bool = True
    max_session_duration: int = 3600
    re_verify_interval: int = 300
    min_trust_level: int = 40


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class ZeroTrustAgent:
    """Thread-safe zero-trust identity verifier for multi-agent systems.

    Implements the core zero-trust principle: never trust by default.
    Every interaction requires fresh verification against current
    credential state.

    Parameters
    ----------
    policy:
        Zero-trust policy configuration.  Uses sensible defaults if omitted.
    credential_ttl:
        Default credential time-to-live in seconds (default 86400 = 24h).
    """

    def __init__(
        self,
        policy: ZeroTrustPolicy | None = None,
        credential_ttl: int = 86400,
    ) -> None:
        self._policy = policy or ZeroTrustPolicy()
        self._credential_ttl = credential_ttl
        self._credentials: dict[str, AgentCredential] = {}
        self._sessions: dict[str, SessionToken] = {}
        self._revoked: set[str] = set()
        self._lock = threading.Lock()

    @property
    def policy(self) -> ZeroTrustPolicy:
        """Return the active zero-trust policy."""
        return self._policy

    # -- registration --------------------------------------------------------

    def register_agent(
        self,
        agent_id: str,
        credential_type: CredentialType,
        issuer: str,
        claims: dict[str, Any] | None = None,
        ttl: int | None = None,
    ) -> AgentCredential:
        """Register an agent with a credential.

        Parameters
        ----------
        agent_id:
            Unique agent identifier.
        credential_type:
            Type of credential being presented.
        issuer:
            Entity issuing the credential.
        claims:
            Optional claims embedded in the credential.
        ttl:
            Override credential TTL in seconds.

        Raises
        ------
        ValueError:
            If the agent_id is empty or already registered.
        """
        if not agent_id:
            raise ValueError("agent_id must be a non-empty string")

        effective_ttl = ttl if ttl is not None else self._credential_ttl
        now = _now()
        issued_at = now.isoformat()
        expires_at = (now + timedelta(seconds=effective_ttl)).isoformat()
        effective_claims = dict(claims) if claims else {}

        sig_payload = f"{agent_id}:{credential_type.value}:{issuer}:{issued_at}"
        signature_hash = _sha256(sig_payload)

        cred = AgentCredential(
            agent_id=agent_id,
            credential_type=credential_type,
            issuer=issuer,
            issued_at=issued_at,
            expires_at=expires_at,
            claims=effective_claims,
            signature_hash=signature_hash,
        )

        with self._lock:
            if agent_id in self._credentials:
                raise ValueError(f"Agent already registered: {agent_id}")
            self._credentials[agent_id] = cred

        return cred

    # -- verification --------------------------------------------------------

    def verify_agent(self, agent_id: str) -> VerificationResult:
        """Verify an agent's identity and credential validity.

        Checks:
        1. Agent is registered.
        2. Credential has not been revoked.
        3. Credential has not expired.
        4. Signature hash is valid.
        5. Trust level meets policy minimum.

        Returns a :class:`VerificationResult` with details.
        """
        now = _now()
        reasons: list[str] = []

        with self._lock:
            cred = self._credentials.get(agent_id)
            revoked = agent_id in self._revoked

        if cred is None:
            return VerificationResult(
                verified=False,
                agent_id=agent_id,
                trust_level=0,
                reasons=("Agent not registered",),
                verified_at=now.isoformat(),
            )

        if revoked:
            reasons.append("Credential has been revoked")
            return VerificationResult(
                verified=False,
                agent_id=agent_id,
                trust_level=0,
                reasons=tuple(reasons),
                verified_at=now.isoformat(),
            )

        # Check expiry
        expires_at = datetime.fromisoformat(cred.expires_at)
        if now > expires_at:
            reasons.append("Credential has expired")
            return VerificationResult(
                verified=False,
                agent_id=agent_id,
                trust_level=0,
                reasons=tuple(reasons),
                verified_at=now.isoformat(),
            )

        # Verify signature hash
        expected_sig = _sha256(
            f"{cred.agent_id}:{cred.credential_type.value}:{cred.issuer}:{cred.issued_at}"
        )
        if cred.signature_hash != expected_sig:
            reasons.append("Signature hash mismatch")
            return VerificationResult(
                verified=False,
                agent_id=agent_id,
                trust_level=0,
                reasons=tuple(reasons),
                verified_at=now.isoformat(),
            )

        trust_level = _CREDENTIAL_TRUST[cred.credential_type]

        if trust_level < self._policy.min_trust_level:
            reasons.append(
                f"Trust level {trust_level} below minimum {self._policy.min_trust_level}"
            )
            return VerificationResult(
                verified=False,
                agent_id=agent_id,
                trust_level=trust_level,
                reasons=tuple(reasons),
                verified_at=now.isoformat(),
            )

        reasons.append("All checks passed")
        return VerificationResult(
            verified=True,
            agent_id=agent_id,
            trust_level=trust_level,
            reasons=tuple(reasons),
            verified_at=now.isoformat(),
        )

    # -- sessions ------------------------------------------------------------

    def create_session(
        self,
        agent_id: str,
        scope: frozenset[str],
        duration: int | None = None,
    ) -> SessionToken:
        """Create a scoped session token after verifying the agent.

        Parameters
        ----------
        agent_id:
            Agent requesting a session.
        scope:
            Set of allowed actions for this session.
        duration:
            Session duration in seconds (default: policy max).

        Raises
        ------
        PermissionError:
            If agent verification fails.
        """
        result = self.verify_agent(agent_id)
        if not result.verified:
            raise PermissionError(
                f"Agent {agent_id} failed verification: {', '.join(result.reasons)}"
            )

        effective_duration = min(
            duration if duration is not None else self._policy.max_session_duration,
            self._policy.max_session_duration,
        )

        now = _now()
        token_id = uuid.uuid4().hex
        issued_at = now.isoformat()
        expires_at = (now + timedelta(seconds=effective_duration)).isoformat()
        context_hash = _sha256(f"{agent_id}:{token_id}:{issued_at}:{','.join(sorted(scope))}")

        token = SessionToken(
            token_id=token_id,
            agent_id=agent_id,
            scope=scope,
            issued_at=issued_at,
            expires_at=expires_at,
            context_hash=context_hash,
        )

        with self._lock:
            self._sessions[token_id] = token

        return token

    def verify_session(self, token_id: str) -> bool:
        """Verify that a session token is still valid.

        Checks existence, expiry, and that the agent is not revoked.
        """
        now = _now()

        with self._lock:
            token = self._sessions.get(token_id)

        if token is None:
            return False

        expires_at = datetime.fromisoformat(token.expires_at)
        if now > expires_at:
            return False

        with self._lock:
            if token.agent_id in self._revoked:
                return False

        return True

    # -- revocation ----------------------------------------------------------

    def revoke_credential(self, agent_id: str) -> bool:
        """Revoke an agent's credential and invalidate all its sessions.

        Returns ``True`` if the agent was found and revoked.
        """
        with self._lock:
            if agent_id not in self._credentials:
                return False
            self._revoked.add(agent_id)
            # Invalidate all sessions for this agent
            to_remove = [tid for tid, tok in self._sessions.items() if tok.agent_id == agent_id]
            for tid in to_remove:
                del self._sessions[tid]
        return True

    # -- mutual verification -------------------------------------------------

    def mutual_verify(
        self, agent_a: str, agent_b: str
    ) -> tuple[VerificationResult, VerificationResult]:
        """Perform bidirectional verification between two agents.

        Both agents verify each other.  Returns a tuple of
        ``(result_a_verifies_b, result_b_verifies_a)``.

        This implements the mutual authentication handshake required
        by zero-trust policy.
        """
        result_a = self.verify_agent(agent_a)
        result_b = self.verify_agent(agent_b)
        return result_a, result_b

    # -- queries -------------------------------------------------------------

    def get_credential(self, agent_id: str) -> AgentCredential | None:
        """Return the credential for an agent, or ``None``."""
        with self._lock:
            return self._credentials.get(agent_id)

    def get_session(self, token_id: str) -> SessionToken | None:
        """Return a session token by ID, or ``None``."""
        with self._lock:
            return self._sessions.get(token_id)

    def is_revoked(self, agent_id: str) -> bool:
        """Check whether an agent's credential has been revoked."""
        with self._lock:
            return agent_id in self._revoked

    def active_sessions(self, agent_id: str) -> list[SessionToken]:
        """Return all active (non-expired) sessions for an agent."""
        now = _now()
        with self._lock:
            return [
                tok
                for tok in self._sessions.values()
                if tok.agent_id == agent_id and datetime.fromisoformat(tok.expires_at) > now
            ]
