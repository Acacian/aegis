"""Dashboard demo — populate sample data and launch the Aegis governance dashboard.

Usage::

    pip install 'agent-aegis[server]'
    python examples/dashboard_demo.py

Then open http://localhost:8000 in your browser.
"""

from __future__ import annotations

import random
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Ensure src/ is importable when running from repo root
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aegis.core.action import Action
from aegis.core.anomaly import AnomalyDetector
from aegis.core.policy import Approval, Policy, PolicyDecision, PolicyRule
from aegis.core.result import Result, ResultStatus
from aegis.core.risk import RiskLevel
from aegis.runtime.audit import AuditLogger

# ---------------------------------------------------------------------------
# 1. Define a realistic policy
# ---------------------------------------------------------------------------

policy = Policy(
    rules=[
        PolicyRule(
            name="read_auto",
            match_type="read*",
            risk_level=RiskLevel.LOW,
            approval=Approval.AUTO,
        ),
        PolicyRule(
            name="search_auto",
            match_type="search*",
            risk_level=RiskLevel.LOW,
            approval=Approval.AUTO,
        ),
        PolicyRule(
            name="write_approve",
            match_type="write*",
            risk_level=RiskLevel.MEDIUM,
            approval=Approval.APPROVE,
        ),
        PolicyRule(
            name="update_approve",
            match_type="update*",
            risk_level=RiskLevel.MEDIUM,
            approval=Approval.APPROVE,
        ),
        PolicyRule(
            name="send_approve",
            match_type="send*",
            risk_level=RiskLevel.MEDIUM,
            approval=Approval.APPROVE,
        ),
        PolicyRule(
            name="deploy_approve",
            match_type="deploy*",
            risk_level=RiskLevel.HIGH,
            approval=Approval.APPROVE,
        ),
        PolicyRule(
            name="export_approve",
            match_type="export*",
            risk_level=RiskLevel.HIGH,
            approval=Approval.APPROVE,
        ),
        PolicyRule(
            name="delete_block",
            match_type="delete*",
            risk_level=RiskLevel.CRITICAL,
            approval=Approval.BLOCK,
        ),
        PolicyRule(
            name="drop_block",
            match_type="drop*",
            risk_level=RiskLevel.CRITICAL,
            approval=Approval.BLOCK,
        ),
    ],
    default_risk_level=RiskLevel.MEDIUM,
    default_approval=Approval.APPROVE,
)

# ---------------------------------------------------------------------------
# 2. Generate realistic audit data
# ---------------------------------------------------------------------------

AGENTS = ["crm-agent", "data-pipeline", "email-bot", "analytics-agent", "admin-bot"]
TARGETS = ["crm", "database", "email", "api", "storage", "users", "payments", "analytics"]

SCENARIOS = [
    # (action_type, target_pool, risk, approval, rule, status, weight)
    ("read", TARGETS, RiskLevel.LOW, Approval.AUTO, "read_auto", ResultStatus.SUCCESS, 40),
    ("search", TARGETS, RiskLevel.LOW, Approval.AUTO, "search_auto", ResultStatus.SUCCESS, 15),
    ("write", TARGETS, RiskLevel.MEDIUM, Approval.APPROVE, "write_approve", ResultStatus.SUCCESS, 12),
    ("update", TARGETS, RiskLevel.MEDIUM, Approval.APPROVE, "update_approve", ResultStatus.SUCCESS, 8),
    ("send_email", ["email"], RiskLevel.MEDIUM, Approval.APPROVE, "send_approve", ResultStatus.SUCCESS, 5),
    ("deploy", ["api", "storage"], RiskLevel.HIGH, Approval.APPROVE, "deploy_approve", ResultStatus.SUCCESS, 3),
    ("export", ["database", "analytics"], RiskLevel.HIGH, Approval.APPROVE, "export_approve", ResultStatus.SUCCESS, 4),
    ("delete", TARGETS, RiskLevel.CRITICAL, Approval.BLOCK, "delete_block", ResultStatus.BLOCKED, 8),
    ("drop", ["database"], RiskLevel.CRITICAL, Approval.BLOCK, "drop_block", ResultStatus.BLOCKED, 2),
    ("write", TARGETS, RiskLevel.MEDIUM, Approval.APPROVE, "write_approve", ResultStatus.FAILED, 3),
]

DB_PATH = Path("demo_audit.db")


def populate_data() -> tuple[AuditLogger, AnomalyDetector]:
    """Generate ~200 realistic audit entries spanning the last 48 hours."""
    if DB_PATH.exists():
        DB_PATH.unlink()

    logger = AuditLogger(db_path=DB_PATH)
    detector = AnomalyDetector()

    now = datetime.now(UTC)
    weights = [s[6] for s in SCENARIOS]

    for i in range(250):
        scenario = random.choices(SCENARIOS, weights=weights, k=1)[0]
        action_type, target_pool, risk, approval, rule, status, _ = scenario

        agent = random.choice(AGENTS)
        target = random.choice(target_pool)
        ts_offset = random.uniform(0, 48 * 3600)
        _ts = now - timedelta(seconds=ts_offset)

        action = Action(
            type=action_type,
            target=target,
            agent_id=agent,
            description=f"Demo action #{i}",
        )

        decision = PolicyDecision(
            action=action,
            risk_level=risk,
            approval=approval,
            matched_rule=rule,
        )

        result = Result(action=action, status=status)

        logger.log(
            f"session-{agent}",
            decision,
            result=result,
        )

        # Feed anomaly detector
        detector.record(
            action,
            agent,
            blocked=(status == ResultStatus.BLOCKED),
        )

    print(f"Generated 250 audit entries in {DB_PATH}")
    return logger, detector


# ---------------------------------------------------------------------------
# 3. Launch the dashboard
# ---------------------------------------------------------------------------


def main() -> None:
    logger, detector = populate_data()
    logger.close()

    try:
        import uvicorn
    except ImportError:
        print("uvicorn not installed. Install with: pip install 'agent-aegis[server]'")
        sys.exit(1)

    from aegis.server.app import create_app

    app = create_app(
        policy=policy,
        audit_db_path=DB_PATH,
        enable_dashboard=True,
        anomaly_detector=detector,
    )

    print("\n  Aegis Dashboard: http://localhost:8000")
    print("  Press Ctrl+C to stop.\n")

    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")


if __name__ == "__main__":
    main()
