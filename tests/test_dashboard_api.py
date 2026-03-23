"""Tests for the Aegis dashboard API endpoints."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegis.core.action import Action
from aegis.core.anomaly import AnomalyDetector
from aegis.core.policy import Approval, Policy, PolicyDecision, PolicyRule
from aegis.core.result import Result, ResultStatus
from aegis.core.risk import RiskLevel
from aegis.runtime.audit import AuditLogger


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
                match_type="write*",
                risk_level=RiskLevel.MEDIUM,
                approval=Approval.APPROVE,
                name="write_approve",
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
def audit_db(tmp_path: Path) -> Path:
    return tmp_path / "test_dashboard.db"


@pytest.fixture()
def populated_audit(audit_db: Path, policy: Policy) -> AuditLogger:
    """Create an audit log with sample data."""
    logger = AuditLogger(db_path=audit_db)
    actions = [
        ("read", "crm", RiskLevel.LOW, Approval.AUTO, "read_auto", ResultStatus.SUCCESS),
        ("read", "db", RiskLevel.LOW, Approval.AUTO, "read_auto", ResultStatus.SUCCESS),
        (
            "write",
            "crm",
            RiskLevel.MEDIUM,
            Approval.APPROVE,
            "write_approve",
            ResultStatus.SUCCESS,
        ),
        ("delete", "db", RiskLevel.CRITICAL, Approval.BLOCK, "delete_block", ResultStatus.BLOCKED),
        ("read", "api", RiskLevel.LOW, Approval.AUTO, "read_auto", ResultStatus.SUCCESS),
    ]
    for atype, target, risk, approval, rule, status in actions:
        decision = PolicyDecision(
            action=Action(atype, target),
            risk_level=risk,
            approval=approval,
            matched_rule=rule,
        )
        logger.log(
            "s1",
            decision,
            result=Result(action=decision.action, status=status),
        )
    return logger


@pytest.fixture()
def app_with_data(policy: Policy, audit_db: Path, populated_audit: AuditLogger):
    try:
        from aegis.server.app import create_app

        populated_audit.close()
        return create_app(
            policy=policy,
            audit_db_path=audit_db,
            enable_dashboard=True,
        )
    except ImportError:
        pytest.skip("starlette not installed")


@pytest.fixture()
def app_empty(policy: Policy, tmp_path: Path):
    try:
        from aegis.server.app import create_app

        return create_app(
            policy=policy,
            audit_db_path=tmp_path / "empty.db",
            enable_dashboard=True,
        )
    except ImportError:
        pytest.skip("starlette not installed")


@pytest.fixture()
def app_with_anomaly(policy: Policy, audit_db: Path, populated_audit: AuditLogger):
    try:
        from aegis.server.app import create_app

        populated_audit.close()
        detector = AnomalyDetector()
        detector.record(Action("read", "crm"), "agent-1")
        detector.record(Action("read", "crm"), "agent-1")
        detector.record(Action("write", "crm"), "agent-1")
        return create_app(
            policy=policy,
            audit_db_path=audit_db,
            enable_dashboard=True,
            anomaly_detector=detector,
        )
    except ImportError:
        pytest.skip("starlette not installed")


def _client(app):
    from starlette.testclient import TestClient

    return TestClient(app)


# -- Overview ---------------------------------------------------------------


class TestOverview:
    def test_overview_returns_kpis(self, app_with_data):
        resp = _client(app_with_data).get("/api/v1/dashboard/overview")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_actions"] == 5
        assert data["approval_distribution"]["block"] == 1
        assert data["approval_distribution"]["auto"] == 3
        assert data["policy_rule_count"] == 3
        assert "compliance_grade" in data
        assert "compliance_score" in data

    def test_overview_empty(self, app_empty):
        resp = _client(app_empty).get("/api/v1/dashboard/overview")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_actions"] == 0


# -- Timeline ---------------------------------------------------------------


class TestTimeline:
    def test_timeline_24h(self, app_with_data):
        resp = _client(app_with_data).get("/api/v1/dashboard/stats/timeline?period=24h")
        assert resp.status_code == 200
        data = resp.json()
        assert data["period"] == "24h"
        assert isinstance(data["buckets"], list)

    def test_timeline_7d(self, app_with_data):
        resp = _client(app_with_data).get("/api/v1/dashboard/stats/timeline?period=7d")
        assert resp.status_code == 200
        assert resp.json()["period"] == "7d"

    def test_timeline_empty(self, app_empty):
        resp = _client(app_empty).get("/api/v1/dashboard/stats/timeline")
        assert resp.status_code == 200
        assert resp.json()["buckets"] == []


# -- Audit ------------------------------------------------------------------


class TestAuditRecent:
    def test_returns_entries(self, app_with_data):
        resp = _client(app_with_data).get("/api/v1/dashboard/audit/recent")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 5
        assert len(data["entries"]) == 5

    def test_pagination(self, app_with_data):
        resp = _client(app_with_data).get("/api/v1/dashboard/audit/recent?limit=2&offset=0")
        data = resp.json()
        assert len(data["entries"]) == 2
        assert data["total"] == 5

    def test_filter_by_risk(self, app_with_data):
        resp = _client(app_with_data).get("/api/v1/dashboard/audit/recent?risk_level=CRITICAL")
        data = resp.json()
        assert data["total"] == 1
        assert data["entries"][0]["risk_level"] == "CRITICAL"

    def test_filter_by_action_type(self, app_with_data):
        resp = _client(app_with_data).get("/api/v1/dashboard/audit/recent?action_type=read")
        data = resp.json()
        assert data["total"] == 3

    def test_empty_db(self, app_empty):
        resp = _client(app_empty).get("/api/v1/dashboard/audit/recent")
        data = resp.json()
        assert data["total"] == 0
        assert data["entries"] == []


class TestAuditStats:
    def test_returns_stats(self, app_with_data):
        resp = _client(app_with_data).get("/api/v1/dashboard/audit/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 5
        assert "by_risk_level" in data
        assert "by_approval" in data
        assert "by_action_type" in data


# -- Policy -----------------------------------------------------------------


class TestPolicySummary:
    def test_returns_rules(self, app_with_data):
        resp = _client(app_with_data).get("/api/v1/dashboard/policy/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["rule_count"] == 3
        assert len(data["rules"]) == 3
        assert data["has_destructive_blocks"] is True
        assert data["has_approval_gates"] is True


class TestPolicyScore:
    def test_returns_score(self, app_with_data):
        resp = _client(app_with_data).get("/api/v1/dashboard/policy/score")
        assert resp.status_code == 200
        data = resp.json()
        assert 0 <= data["score"] <= 100
        assert "grade" in data
        assert isinstance(data["checks"], list)
        assert len(data["checks"]) > 0
        # Our test policy should have rules, blocks, and approvals
        assert data["score"] >= 50


# -- Compliance -------------------------------------------------------------


class TestComplianceReport:
    def test_governance_report(self, app_with_data):
        resp = _client(app_with_data).get("/api/v1/dashboard/compliance/report?type=governance")
        assert resp.status_code == 200
        data = resp.json()
        assert data["report_type"] == "governance"
        assert 0 <= data["score"] <= 100
        assert "findings" in data

    def test_soc2_report(self, app_with_data):
        resp = _client(app_with_data).get("/api/v1/dashboard/compliance/report?type=soc2")
        assert resp.status_code == 200
        assert resp.json()["report_type"] == "soc2"

    def test_gdpr_report(self, app_with_data):
        resp = _client(app_with_data).get("/api/v1/dashboard/compliance/report?type=gdpr")
        assert resp.status_code == 200
        assert resp.json()["report_type"] == "gdpr"

    def test_invalid_report_type(self, app_with_data):
        resp = _client(app_with_data).get("/api/v1/dashboard/compliance/report?type=invalid")
        assert resp.status_code == 400

    def test_empty_db_report(self, app_empty):
        resp = _client(app_empty).get("/api/v1/dashboard/compliance/report?type=governance")
        assert resp.status_code == 200
        assert resp.json()["total_actions"] == 0


class TestComplianceRegulatory:
    def test_eu_ai_act(self, app_with_data):
        resp = _client(app_with_data).get(
            "/api/v1/dashboard/compliance/regulatory?framework=eu_ai_act"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["framework"] == "eu_ai_act"
        assert "coverage_score" in data
        assert "gaps" in data

    def test_nist(self, app_with_data):
        resp = _client(app_with_data).get(
            "/api/v1/dashboard/compliance/regulatory?framework=nist_ai_rmf"
        )
        assert resp.status_code == 200

    def test_soc2(self, app_with_data):
        resp = _client(app_with_data).get("/api/v1/dashboard/compliance/regulatory?framework=soc2")
        assert resp.status_code == 200

    def test_iso_42001(self, app_with_data):
        resp = _client(app_with_data).get(
            "/api/v1/dashboard/compliance/regulatory?framework=iso_42001"
        )
        assert resp.status_code == 200

    def test_invalid_framework(self, app_with_data):
        resp = _client(app_with_data).get(
            "/api/v1/dashboard/compliance/regulatory?framework=invalid"
        )
        assert resp.status_code == 400


# -- Anomalies --------------------------------------------------------------


class TestAnomalyProfiles:
    def test_not_configured(self, app_with_data):
        resp = _client(app_with_data).get("/api/v1/dashboard/anomalies/profiles")
        assert resp.status_code == 200
        data = resp.json()
        assert data["configured"] is False

    def test_with_detector(self, app_with_anomaly):
        resp = _client(app_with_anomaly).get("/api/v1/dashboard/anomalies/profiles")
        assert resp.status_code == 200
        data = resp.json()
        assert data["configured"] is True
        assert len(data["profiles"]) == 1
        profile = data["profiles"][0]
        assert profile["agent_id"] == "agent-1"
        assert profile["total_actions"] == 3


class TestAnomalyAlerts:
    def test_not_configured(self, app_with_data):
        resp = _client(app_with_data).get("/api/v1/dashboard/anomalies/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["configured"] is False

    def test_with_detector(self, app_with_anomaly):
        resp = _client(app_with_anomaly).get("/api/v1/dashboard/anomalies/alerts")
        assert resp.status_code == 200
        assert resp.json()["configured"] is True


# -- System -----------------------------------------------------------------


class TestSystemHealth:
    def test_returns_health(self, app_with_data):
        resp = _client(app_with_data).get("/api/v1/dashboard/system/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "version" in data
        assert data["audit_entries"] == 5
        assert data["policy_rules"] == 3


# -- Dashboard HTML ---------------------------------------------------------


class TestDashboardServing:
    def test_root_serves_html(self, app_with_data):
        resp = _client(app_with_data).get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "AEGIS" in resp.text

    def test_dashboard_route(self, app_with_data):
        resp = _client(app_with_data).get("/dashboard")
        assert resp.status_code == 200
        assert "AEGIS" in resp.text

    def test_static_css(self, app_with_data):
        resp = _client(app_with_data).get("/static/app.css")
        assert resp.status_code == 200

    def test_static_js(self, app_with_data):
        resp = _client(app_with_data).get("/static/app.js")
        assert resp.status_code == 200


# -- Policy YAML export -----------------------------------------------------


class TestPolicyYaml:
    def test_returns_yaml_string(self, app_with_data):
        resp = _client(app_with_data).get("/api/v1/dashboard/policy/yaml")
        assert resp.status_code == 200
        data = resp.json()
        assert "yaml" in data
        assert "read_auto" in data["yaml"]
        assert "delete_block" in data["yaml"]


# -- Badge endpoint ---------------------------------------------------------


class TestBadgeScore:
    def test_returns_shields_io_format(self, app_with_data):
        resp = _client(app_with_data).get("/api/v1/badge/score")
        assert resp.status_code == 200
        data = resp.json()
        assert data["schemaVersion"] == 1
        assert data["label"] == "aegis score"
        assert "/100)" in data["message"]
        assert data["color"] in ("brightgreen", "yellow", "orange", "red")

    def test_score_value_in_message(self, app_with_data):
        resp = _client(app_with_data).get("/api/v1/badge/score")
        data = resp.json()
        # Our test policy has 3 rules, blocks, approves, all named, non-auto default
        # Should score: 15 + 20 + 15 + 10 + 0 + 0 + 10 + 10 = 80
        assert "80/100" in data["message"]
        assert data["color"] == "brightgreen"


# -- WebSocket audit stream -------------------------------------------------


class TestWebSocketAudit:
    def test_ws_connects(self, app_with_data):
        client = _client(app_with_data)
        with client.websocket_connect("/ws/audit"):
            pass  # Connection opens without error

    def test_ws_receives_entry(self, policy, tmp_path):
        try:
            from starlette.testclient import TestClient

            from aegis.server.app import create_app
        except ImportError:
            pytest.skip("starlette not installed")

        db_path = tmp_path / "ws_test.db"
        app = create_app(policy=policy, audit_db_path=db_path, enable_dashboard=True)
        client = TestClient(app)

        # We need access to the audit_logger used by the app.
        # The simplest way: call /api/v1/execute to trigger an audit write
        # while a WS connection is open.
        import threading

        received = []

        def ws_listener():
            with client.websocket_connect("/ws/audit") as ws:
                data = ws.receive_text()
                received.append(data)

        t = threading.Thread(target=ws_listener, daemon=True)
        t.start()

        import time

        time.sleep(0.3)  # Let WS connect

        # Trigger an action that gets logged
        client.post(
            "/api/v1/execute",
            json={"action_type": "read_test", "target": "ws"},
        )
        t.join(timeout=3)

        assert len(received) == 1
        import json

        entry = json.loads(received[0])
        assert entry["action_type"] == "read_test"


# -- Dashboard disabled -----------------------------------------------------


class TestDashboardDisabled:
    def test_no_dashboard_routes(self, policy, tmp_path):
        try:
            from starlette.testclient import TestClient

            from aegis.server.app import create_app
        except ImportError:
            pytest.skip("starlette not installed")

        app = create_app(
            policy=policy,
            audit_db_path=tmp_path / "no_dash.db",
            enable_dashboard=False,
        )
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/dashboard/overview")
        assert resp.status_code in (404, 405)
