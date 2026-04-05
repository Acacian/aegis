"""Tests for Zero-Trust Identity Framework for Agentic AI.

Covers:
- Agent registration and credential creation
- Credential verification (valid, expired, revoked, low trust)
- Session token creation and verification
- Session expiry and revocation cascading
- Mutual verification handshake
- Credential type trust levels
- Policy enforcement
- Thread safety under concurrent operations
- Edge cases (empty IDs, duplicate registration, unknown agents)

Reference: arXiv:2505.19301
"""

from __future__ import annotations

import threading
import time
from datetime import datetime

import pytest

from aegis.core.zero_trust_agent import (
    _CREDENTIAL_TRUST,
    AgentCredential,
    CredentialType,
    ZeroTrustAgent,
    ZeroTrustPolicy,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def zt() -> ZeroTrustAgent:
    return ZeroTrustAgent()


@pytest.fixture()
def zt_strict() -> ZeroTrustAgent:
    policy = ZeroTrustPolicy(
        require_mutual_auth=True,
        max_session_duration=60,
        re_verify_interval=10,
        min_trust_level=70,
    )
    return ZeroTrustAgent(policy=policy)


def _register_default(
    zt: ZeroTrustAgent,
    agent_id: str = "agent-1",
    cred_type: CredentialType = CredentialType.PLATFORM_ISSUED,
    issuer: str = "platform",
) -> AgentCredential:
    return zt.register_agent(agent_id, cred_type, issuer)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_register_creates_credential(self, zt: ZeroTrustAgent) -> None:
        cred = _register_default(zt)
        assert cred.agent_id == "agent-1"
        assert cred.credential_type == CredentialType.PLATFORM_ISSUED
        assert cred.issuer == "platform"

    def test_register_sets_signature_hash(self, zt: ZeroTrustAgent) -> None:
        cred = _register_default(zt)
        assert len(cred.signature_hash) == 64  # SHA-256 hex digest

    def test_register_sets_expiry(self, zt: ZeroTrustAgent) -> None:
        cred = _register_default(zt)
        issued = datetime.fromisoformat(cred.issued_at)
        expires = datetime.fromisoformat(cred.expires_at)
        assert expires > issued

    def test_register_with_claims(self, zt: ZeroTrustAgent) -> None:
        cred = zt.register_agent(
            "agent-1",
            CredentialType.VERIFIED,
            "authority",
            claims={"role": "admin", "org": "acme"},
        )
        assert cred.claims["role"] == "admin"
        assert cred.claims["org"] == "acme"

    def test_register_duplicate_raises(self, zt: ZeroTrustAgent) -> None:
        _register_default(zt)
        with pytest.raises(ValueError, match="already registered"):
            _register_default(zt)

    def test_register_empty_id_raises(self, zt: ZeroTrustAgent) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            zt.register_agent("", CredentialType.SELF_SIGNED, "self")

    def test_register_custom_ttl(self, zt: ZeroTrustAgent) -> None:
        cred = zt.register_agent("agent-1", CredentialType.SELF_SIGNED, "self", ttl=60)
        issued = datetime.fromisoformat(cred.issued_at)
        expires = datetime.fromisoformat(cred.expires_at)
        diff = (expires - issued).total_seconds()
        assert 59 <= diff <= 61  # Allow 1s rounding


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


class TestVerification:
    def test_verify_valid_agent(self, zt: ZeroTrustAgent) -> None:
        _register_default(zt)
        result = zt.verify_agent("agent-1")
        assert result.verified is True
        assert result.agent_id == "agent-1"
        assert result.trust_level == _CREDENTIAL_TRUST[CredentialType.PLATFORM_ISSUED]

    def test_verify_unregistered_agent(self, zt: ZeroTrustAgent) -> None:
        result = zt.verify_agent("unknown")
        assert result.verified is False
        assert "not registered" in result.reasons[0].lower()

    def test_verify_revoked_agent(self, zt: ZeroTrustAgent) -> None:
        _register_default(zt)
        zt.revoke_credential("agent-1")
        result = zt.verify_agent("agent-1")
        assert result.verified is False
        assert any("revoked" in r.lower() for r in result.reasons)

    def test_verify_expired_credential(self) -> None:
        zt = ZeroTrustAgent(credential_ttl=0)
        zt.register_agent("agent-1", CredentialType.PLATFORM_ISSUED, "platform", ttl=0)
        # TTL=0 means it expires immediately
        time.sleep(0.01)
        result = zt.verify_agent("agent-1")
        assert result.verified is False
        assert any("expired" in r.lower() for r in result.reasons)

    def test_verify_self_signed_below_default_policy(self, zt: ZeroTrustAgent) -> None:
        # Default min_trust_level is 40, self_signed gives 10
        zt.register_agent("agent-low", CredentialType.SELF_SIGNED, "self")
        result = zt.verify_agent("agent-low")
        assert result.verified is False
        assert any("below minimum" in r.lower() for r in result.reasons)

    def test_verify_self_signed_with_low_policy(self) -> None:
        policy = ZeroTrustPolicy(min_trust_level=5)
        zt = ZeroTrustAgent(policy=policy)
        zt.register_agent("agent-low", CredentialType.SELF_SIGNED, "self")
        result = zt.verify_agent("agent-low")
        assert result.verified is True

    def test_verify_sets_timestamp(self, zt: ZeroTrustAgent) -> None:
        _register_default(zt)
        result = zt.verify_agent("agent-1")
        assert result.verified_at != ""
        datetime.fromisoformat(result.verified_at)  # Should not raise

    def test_credential_trust_levels(self) -> None:
        assert (
            _CREDENTIAL_TRUST[CredentialType.SELF_SIGNED]
            < _CREDENTIAL_TRUST[CredentialType.DELEGATED]
        )
        assert (
            _CREDENTIAL_TRUST[CredentialType.DELEGATED]
            < _CREDENTIAL_TRUST[CredentialType.PLATFORM_ISSUED]
        )
        assert (
            _CREDENTIAL_TRUST[CredentialType.PLATFORM_ISSUED]
            < _CREDENTIAL_TRUST[CredentialType.VERIFIED]
        )


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


class TestSessions:
    def test_create_session(self, zt: ZeroTrustAgent) -> None:
        _register_default(zt)
        session = zt.create_session("agent-1", scope=frozenset({"read", "write"}))
        assert session.agent_id == "agent-1"
        assert session.scope == frozenset({"read", "write"})
        assert len(session.token_id) == 32  # UUID hex

    def test_session_has_context_hash(self, zt: ZeroTrustAgent) -> None:
        _register_default(zt)
        session = zt.create_session("agent-1", scope=frozenset({"read"}))
        assert len(session.context_hash) == 64

    def test_verify_valid_session(self, zt: ZeroTrustAgent) -> None:
        _register_default(zt)
        session = zt.create_session("agent-1", scope=frozenset({"read"}))
        assert zt.verify_session(session.token_id) is True

    def test_verify_unknown_session(self, zt: ZeroTrustAgent) -> None:
        assert zt.verify_session("nonexistent") is False

    def test_session_respects_max_duration(self) -> None:
        policy = ZeroTrustPolicy(max_session_duration=30)
        zt = ZeroTrustAgent(policy=policy)
        zt.register_agent("agent-1", CredentialType.PLATFORM_ISSUED, "p")
        session = zt.create_session("agent-1", scope=frozenset({"read"}), duration=9999)
        issued = datetime.fromisoformat(session.issued_at)
        expires = datetime.fromisoformat(session.expires_at)
        diff = (expires - issued).total_seconds()
        assert diff <= 31  # Capped at policy max

    def test_create_session_for_unverified_raises(self, zt: ZeroTrustAgent) -> None:
        with pytest.raises(PermissionError):
            zt.create_session("unknown", scope=frozenset({"read"}))

    def test_session_invalidated_on_revoke(self, zt: ZeroTrustAgent) -> None:
        _register_default(zt)
        session = zt.create_session("agent-1", scope=frozenset({"read"}))
        zt.revoke_credential("agent-1")
        assert zt.verify_session(session.token_id) is False

    def test_active_sessions(self, zt: ZeroTrustAgent) -> None:
        _register_default(zt)
        zt.create_session("agent-1", scope=frozenset({"read"}))
        zt.create_session("agent-1", scope=frozenset({"write"}))
        sessions = zt.active_sessions("agent-1")
        assert len(sessions) == 2


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


class TestRevocation:
    def test_revoke_existing(self, zt: ZeroTrustAgent) -> None:
        _register_default(zt)
        assert zt.revoke_credential("agent-1") is True
        assert zt.is_revoked("agent-1") is True

    def test_revoke_nonexistent(self, zt: ZeroTrustAgent) -> None:
        assert zt.revoke_credential("unknown") is False

    def test_revoked_agent_cannot_create_session(self, zt: ZeroTrustAgent) -> None:
        _register_default(zt)
        zt.revoke_credential("agent-1")
        with pytest.raises(PermissionError):
            zt.create_session("agent-1", scope=frozenset({"read"}))


# ---------------------------------------------------------------------------
# Mutual verification
# ---------------------------------------------------------------------------


class TestMutualVerification:
    def test_mutual_verify_both_valid(self, zt: ZeroTrustAgent) -> None:
        zt.register_agent("agent-a", CredentialType.PLATFORM_ISSUED, "p")
        zt.register_agent("agent-b", CredentialType.VERIFIED, "authority")
        result_a, result_b = zt.mutual_verify("agent-a", "agent-b")
        assert result_a.verified is True
        assert result_b.verified is True

    def test_mutual_verify_one_invalid(self, zt: ZeroTrustAgent) -> None:
        zt.register_agent("agent-a", CredentialType.PLATFORM_ISSUED, "p")
        result_a, result_b = zt.mutual_verify("agent-a", "unknown")
        assert result_a.verified is True
        assert result_b.verified is False

    def test_mutual_verify_both_invalid(self, zt: ZeroTrustAgent) -> None:
        result_a, result_b = zt.mutual_verify("x", "y")
        assert result_a.verified is False
        assert result_b.verified is False


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


class TestPolicy:
    def test_default_policy(self, zt: ZeroTrustAgent) -> None:
        p = zt.policy
        assert p.require_mutual_auth is True
        assert p.max_session_duration == 3600
        assert p.min_trust_level == 40

    def test_strict_policy_rejects_delegated(self, zt_strict: ZeroTrustAgent) -> None:
        zt_strict.register_agent("agent-d", CredentialType.DELEGATED, "parent")
        result = zt_strict.verify_agent("agent-d")
        # DELEGATED trust is 40, strict policy requires 70
        assert result.verified is False

    def test_strict_policy_accepts_platform(self, zt_strict: ZeroTrustAgent) -> None:
        zt_strict.register_agent("agent-p", CredentialType.PLATFORM_ISSUED, "platform")
        result = zt_strict.verify_agent("agent-p")
        assert result.verified is True


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------


class TestQueries:
    def test_get_credential(self, zt: ZeroTrustAgent) -> None:
        _register_default(zt)
        cred = zt.get_credential("agent-1")
        assert cred is not None
        assert cred.agent_id == "agent-1"

    def test_get_credential_unknown(self, zt: ZeroTrustAgent) -> None:
        assert zt.get_credential("unknown") is None

    def test_get_session(self, zt: ZeroTrustAgent) -> None:
        _register_default(zt)
        session = zt.create_session("agent-1", scope=frozenset({"read"}))
        fetched = zt.get_session(session.token_id)
        assert fetched is not None
        assert fetched.token_id == session.token_id

    def test_get_session_unknown(self, zt: ZeroTrustAgent) -> None:
        assert zt.get_session("nonexistent") is None


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_registrations(self) -> None:
        zt = ZeroTrustAgent()
        errors: list[str] = []

        def register(i: int) -> None:
            try:
                zt.register_agent(f"agent-{i}", CredentialType.PLATFORM_ISSUED, "p")
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=register, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        for i in range(50):
            assert zt.get_credential(f"agent-{i}") is not None

    def test_concurrent_verify_and_revoke(self) -> None:
        zt = ZeroTrustAgent()
        for i in range(20):
            zt.register_agent(f"agent-{i}", CredentialType.PLATFORM_ISSUED, "p")

        errors: list[str] = []

        def verify_agents() -> None:
            try:
                for i in range(20):
                    zt.verify_agent(f"agent-{i}")
            except Exception as e:
                errors.append(str(e))

        def revoke_agents() -> None:
            try:
                for i in range(10):
                    zt.revoke_credential(f"agent-{i}")
            except Exception as e:
                errors.append(str(e))

        t1 = threading.Thread(target=verify_agents)
        t2 = threading.Thread(target=revoke_agents)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert len(errors) == 0


# ---------------------------------------------------------------------------
# Frozen dataclass immutability
# ---------------------------------------------------------------------------


class TestImmutability:
    def test_credential_is_frozen(self, zt: ZeroTrustAgent) -> None:
        cred = _register_default(zt)
        with pytest.raises(AttributeError):
            cred.agent_id = "tampered"  # type: ignore[misc]

    def test_verification_result_is_frozen(self, zt: ZeroTrustAgent) -> None:
        _register_default(zt)
        result = zt.verify_agent("agent-1")
        with pytest.raises(AttributeError):
            result.verified = False  # type: ignore[misc]

    def test_session_token_is_frozen(self, zt: ZeroTrustAgent) -> None:
        _register_default(zt)
        session = zt.create_session("agent-1", scope=frozenset({"read"}))
        with pytest.raises(AttributeError):
            session.agent_id = "tampered"  # type: ignore[misc]

    def test_policy_is_frozen(self) -> None:
        policy = ZeroTrustPolicy()
        with pytest.raises(AttributeError):
            policy.min_trust_level = 0  # type: ignore[misc]
