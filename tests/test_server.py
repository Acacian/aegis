"""Tests for Aegis REST API server."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.risk import RiskLevel


@pytest.fixture()
def policy() -> Policy:
    return Policy(
        rules=[
            PolicyRule(
                match_type="read*",
                risk_level=RiskLevel.LOW,
                approval=Approval.AUTO,
                name="read_auto",
            ),
            PolicyRule(
                match_type="delete*",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
                name="delete_block",
            ),
        ],
    )


@pytest.fixture()
def app(policy: Policy, tmp_path: Path):
    """Create a test app. Skip if starlette not installed."""
    try:
        from aegis.server.app import create_app

        return create_app(policy=policy, audit_db_path=tmp_path / "test.db")
    except ImportError:
        pytest.skip("starlette not installed")


@pytest.fixture()
def client(app):
    """Create a test client. Skip if starlette/httpx not installed."""
    try:
        from starlette.testclient import TestClient

        return TestClient(app)
    except ImportError:
        pytest.skip("starlette test dependencies not installed")


def test_health(client) -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_evaluate_allowed(client) -> None:
    resp = client.post(
        "/api/v1/evaluate",
        json={"action_type": "read_file", "target": "crm"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] == "LOW"
    assert data["approval"] == "auto"
    assert data["is_allowed"] is True
    assert data["matched_rule"] == "read_auto"


def test_evaluate_blocked(client) -> None:
    resp = client.post(
        "/api/v1/evaluate",
        json={"action_type": "delete_file", "target": "db"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] == "CRITICAL"
    assert data["approval"] == "block"
    assert data["is_allowed"] is False


def test_evaluate_batch(client) -> None:
    resp = client.post(
        "/api/v1/evaluate",
        json={
            "actions": [
                {"action_type": "read_data", "target": "crm"},
                {"action_type": "delete_record", "target": "db"},
            ]
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    assert data[0]["is_allowed"] is True
    assert data[1]["is_allowed"] is False


def test_execute_allowed(client) -> None:
    resp = client.post(
        "/api/v1/execute",
        json={"action_type": "read_data", "target": "crm"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"


def test_execute_blocked(client) -> None:
    resp = client.post(
        "/api/v1/execute",
        json={"action_type": "delete_data", "target": "db"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "blocked"
    assert "error" in data


def test_get_policy(client) -> None:
    resp = client.get("/api/v1/policy")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["rules"]) == 2
    assert data["rules"][0]["name"] == "read_auto"
    assert data["rules"][1]["name"] == "delete_block"


def test_update_policy(client) -> None:
    new_policy = {
        "rules": [
            {
                "name": "all_block",
                "match": {"type": "*"},
                "risk_level": "critical",
                "approval": "block",
            }
        ]
    }
    resp = client.put("/api/v1/policy", json=new_policy)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "updated"
    assert data["rule_count"] == 1

    # Verify the new policy is active
    resp = client.post(
        "/api/v1/evaluate",
        json={"action_type": "read_data", "target": "crm"},
    )
    assert resp.json()["is_allowed"] is False


def test_update_policy_yaml(client) -> None:
    yaml_str = """
rules:
  - name: all_auto
    match:
      type: "*"
    risk_level: low
    approval: auto
"""
    resp = client.put("/api/v1/policy", json={"yaml": yaml_str})
    assert resp.status_code == 200
    assert resp.json()["rule_count"] == 1


def test_update_policy_bad_request(client) -> None:
    resp = client.put("/api/v1/policy", json={"invalid": True})
    assert resp.status_code == 400


def test_audit_empty(client) -> None:
    resp = client.get("/api/v1/audit")
    assert resp.status_code == 200
    assert resp.json() == []


def test_audit_after_execute(client) -> None:
    client.post(
        "/api/v1/execute",
        json={"action_type": "read_data", "target": "crm"},
    )
    resp = client.get("/api/v1/audit")
    assert resp.status_code == 200
    entries = resp.json()
    assert len(entries) >= 1


def test_create_app_from_yaml(tmp_path: Path) -> None:
    try:
        from aegis.server.app import create_app
    except ImportError:
        pytest.skip("starlette not installed")

    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("""
version: "1"
defaults:
  risk_level: low
  approval: auto
rules:
  - name: block_delete
    match:
      type: "delete*"
    risk_level: critical
    approval: block
""")
    app = create_app(policy_path=policy_file)
    assert app is not None
