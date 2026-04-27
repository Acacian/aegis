"""Tests for aegis.server.extended_api — extended governance endpoints."""

from __future__ import annotations

import pytest


@pytest.fixture
def client():
    """Starlette TestClient with all extended features enabled."""
    try:
        from starlette.testclient import TestClient
    except ImportError:
        pytest.skip("starlette not installed")

    from aegis.core.behavioral_drift import DriftDetector
    from aegis.core.budget import CostTracker
    from aegis.core.crypto_audit import CryptoAuditChain
    from aegis.core.trust_score import TrustScorer
    from aegis.core.versioning import PolicyStore
    from aegis.server.app import create_app

    app = create_app(
        enable_dashboard=False,
        policy_store=PolicyStore(),
        crypto_chain=CryptoAuditChain(),
        drift_detector=DriftDetector(),
        trust_scorer=TrustScorer(),
        cost_tracker=CostTracker(max_budget=10.0),
    )
    return TestClient(app)


@pytest.fixture
def bare_client():
    """TestClient with no extended features (all 501)."""
    try:
        from starlette.testclient import TestClient
    except ImportError:
        pytest.skip("starlette not installed")

    from aegis.server.app import create_app

    app = create_app(enable_dashboard=False)
    return TestClient(app)


# ---- Policy Versioning ----


class TestPolicyVersioning:
    def test_version_list_empty(self, client):
        resp = client.get("/api/v1/policy/versions")
        assert resp.status_code == 200
        data = resp.json()
        assert data["versions"] == []
        assert data["total"] == 0

    def test_commit_and_list(self, client):
        resp = client.post(
            "/api/v1/policy/commit",
            json={"author": "test", "message": "initial commit"},
        )
        assert resp.status_code == 201
        v = resp.json()
        assert v["author"] == "test"
        assert v["message"] == "initial commit"
        assert v["version_number"] == 1

        # List should contain one version
        resp = client.get("/api/v1/policy/versions")
        assert len(resp.json()["versions"]) == 1

    def test_get_version(self, client):
        resp = client.post(
            "/api/v1/policy/commit",
            json={"author": "a", "message": "v1"},
        )
        vid = resp.json()["version_id"]
        resp = client.get(f"/api/v1/policy/versions/{vid}")
        assert resp.status_code == 200
        assert resp.json()["version_id"] == vid

    def test_get_version_not_found(self, client):
        resp = client.get("/api/v1/policy/versions/nonexistent")
        assert resp.status_code == 404

    def test_tag_and_get_by_tag(self, client):
        resp = client.post(
            "/api/v1/policy/commit",
            json={"author": "a", "message": "v1"},
        )
        vid = resp.json()["version_id"]
        resp = client.post(
            "/api/v1/policy/tag",
            json={"version_id": vid, "tag": "stable"},
        )
        assert resp.status_code == 200

        resp = client.get("/api/v1/policy/versions/stable")
        assert resp.status_code == 200
        assert resp.json()["version_id"] == vid

    def test_diff(self, client):
        r1 = client.post(
            "/api/v1/policy/commit",
            json={"author": "a", "message": "v1"},
        )
        r2 = client.post(
            "/api/v1/policy/commit",
            json={"author": "a", "message": "v2"},
        )
        resp = client.post(
            "/api/v1/policy/diff",
            json={
                "version_a": r1.json()["version_id"],
                "version_b": r2.json()["version_id"],
            },
        )
        assert resp.status_code == 200
        assert "version_from" in resp.json()

    def test_rollback(self, client):
        r1 = client.post(
            "/api/v1/policy/commit",
            json={"author": "a", "message": "v1"},
        )
        client.post(
            "/api/v1/policy/commit",
            json={"author": "a", "message": "v2"},
        )
        resp = client.post(
            "/api/v1/policy/rollback",
            json={"version_id": r1.json()["version_id"]},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "rolled_back"

    def test_not_configured(self, bare_client):
        resp = bare_client.get("/api/v1/policy/versions")
        assert resp.status_code == 501


# ---- Crypto Audit ----


class TestCryptoAudit:
    def test_verify_empty_chain(self, client):
        resp = client.get("/api/v1/audit/crypto/verify")
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

    def test_entries_empty(self, client):
        resp = client.get("/api/v1/audit/crypto/entries")
        assert resp.status_code == 200
        assert resp.json()["entries"] == []

    def test_evidence(self, client):
        resp = client.get("/api/v1/audit/crypto/evidence")
        assert resp.status_code == 200
        data = resp.json()
        assert "algorithm" in data
        assert data["verified"] is True

    def test_not_configured(self, bare_client):
        resp = bare_client.get("/api/v1/audit/crypto/verify")
        assert resp.status_code == 501


# ---- Behavioral Drift ----


class TestDrift:
    def test_drift_report(self, client):
        resp = client.get("/api/v1/drift")
        assert resp.status_code == 200

    def test_drift_agent(self, client):
        resp = client.get("/api/v1/drift/test-agent")
        assert resp.status_code == 200
        data = resp.json()
        assert data["agent_id"] == "test-agent"
        assert isinstance(data["findings"], list)

    def test_not_configured(self, bare_client):
        resp = bare_client.get("/api/v1/drift")
        assert resp.status_code == 501


# ---- Trust Score ----


class TestTrustScore:
    def test_trust_report(self, client):
        resp = client.get("/api/v1/trust")
        assert resp.status_code == 200

    def test_trust_agent(self, client):
        resp = client.get("/api/v1/trust/test-agent")
        assert resp.status_code == 200
        data = resp.json()
        assert data["agent_id"] == "test-agent"
        assert "score" in data

    def test_trust_check(self, client):
        resp = client.get("/api/v1/trust/test-agent/check?risk_level=MEDIUM")
        assert resp.status_code == 200
        data = resp.json()
        assert "allowed" in data

    def test_not_configured(self, bare_client):
        resp = bare_client.get("/api/v1/trust")
        assert resp.status_code == 501


# ---- Cost Governance ----


class TestCost:
    def test_cost_status(self, client):
        resp = client.get("/api/v1/cost")
        assert resp.status_code == 200
        data = resp.json()
        assert data["max_budget"] == 10.0
        assert data["spent"] == 0.0

    def test_cost_report(self, client):
        resp = client.get("/api/v1/cost/report")
        assert resp.status_code == 200

    def test_cost_check(self, client):
        resp = client.post(
            "/api/v1/cost/check",
            json={"estimated_cost": 1.0},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "action" in data
        assert data["remaining"] == 10.0

    def test_not_configured(self, bare_client):
        resp = bare_client.get("/api/v1/cost")
        assert resp.status_code == 501


# ---- Session Replay ----


class TestSessionReplay:
    def test_session_list_empty(self, client):
        resp = client.get("/api/v1/sessions")
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    def test_session_not_found(self, client):
        resp = client.get("/api/v1/sessions/nonexistent")
        assert resp.status_code == 404

    def test_replay_not_found(self, client):
        resp = client.post("/api/v1/sessions/nonexistent/replay")
        assert resp.status_code == 404


# ---- Compliance ----


class TestCompliance:
    def test_compliance_report(self, client):
        resp = client.get("/api/v1/compliance/report")
        assert resp.status_code == 200

    def test_compliance_report_type(self, client):
        resp = client.get("/api/v1/compliance/report?type=soc2")
        assert resp.status_code == 200

    def test_regulatory_gaps(self, client):
        resp = client.get("/api/v1/compliance/gaps?framework=eu_ai_act")
        assert resp.status_code == 200


# ---- Config sections ----


class TestConfigSections:
    def test_cost_config_from_dict(self):
        from aegis.server.config import ServerConfig

        cfg = ServerConfig.from_dict(
            {
                "cost": {"enabled": True, "max_budget": 50.0},
            }
        )
        assert cfg.cost.enabled is True
        assert cfg.cost.max_budget == 50.0

    def test_policy_watch_config(self):
        from aegis.server.config import ServerConfig

        cfg = ServerConfig.from_dict(
            {
                "policy": {"path": "p.yaml", "watch": True},
            }
        )
        assert cfg.policy.watch is True

    def test_cost_default_disabled(self):
        from aegis.server.config import ServerConfig

        cfg = ServerConfig()
        assert cfg.cost.enabled is False
