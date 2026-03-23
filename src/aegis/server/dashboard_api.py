"""Dashboard API endpoints for the Aegis governance dashboard.

Provides REST endpoints for the SPA dashboard: overview KPIs, audit log
queries, policy inspection, compliance reports, anomaly profiles,
and regulatory gap analysis.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from aegis.core.anomaly import AnomalyDetector
from aegis.core.compliance import ReportGenerator
from aegis.core.policy import Policy
from aegis.core.regulatory import ComplianceMapper, RegulatoryFramework
from aegis.runtime.audit import AuditLogger


def _json_response(data: Any, status_code: int = 200) -> Any:
    from starlette.responses import JSONResponse

    return JSONResponse(data, status_code=status_code)


def _parse_timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        ts = value.replace("Z", "+00:00") if value.endswith("Z") else value
        return datetime.fromisoformat(ts)
    except (ValueError, AttributeError):
        return None


def _bucket_by_time(entries: list[dict[str, Any]], period: str) -> list[dict[str, Any]]:
    """Group audit entries into time buckets for charting."""
    now = datetime.now(UTC)

    if period == "7d":
        bucket_seconds = 6 * 3600  # 6-hour buckets
        lookback_hours = 7 * 24
    elif period == "30d":
        bucket_seconds = 24 * 3600  # daily buckets
        lookback_hours = 30 * 24
    else:  # default 24h
        bucket_seconds = 3600  # hourly buckets
        lookback_hours = 24

    cutoff = now.timestamp() - lookback_hours * 3600
    buckets: dict[int, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "blocked": 0, "approved": 0, "auto": 0}
    )

    for entry in entries:
        ts = _parse_timestamp(str(entry.get("timestamp", "")))
        if ts is None:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        epoch = ts.timestamp()
        if epoch < cutoff:
            continue
        bucket_key = int(epoch // bucket_seconds) * bucket_seconds
        buckets[bucket_key]["total"] += 1
        approval = str(entry.get("approval", "")).lower()
        if approval == "block":
            buckets[bucket_key]["blocked"] += 1
        elif approval == "approve":
            buckets[bucket_key]["approved"] += 1
        elif approval == "auto":
            buckets[bucket_key]["auto"] += 1

    result = []
    for ts_key in sorted(buckets):
        bucket = buckets[ts_key]
        result.append(
            {
                "timestamp": datetime.fromtimestamp(ts_key, tz=UTC).isoformat(),
                **bucket,
            }
        )
    return result


def get_dashboard_routes(
    *,
    policy: Policy,
    audit_logger: AuditLogger,
    anomaly_detector: AnomalyDetector | None = None,
) -> list[Any]:
    """Create dashboard API routes.

    Returns a list of Starlette Route objects.
    """
    from starlette.requests import Request
    from starlette.routing import Route

    async def overview(request: Request) -> Any:
        entries = audit_logger.get_log()
        total = len(entries)

        risk_counts: dict[str, int] = {}
        approval_counts: dict[str, int] = {"auto": 0, "approve": 0, "block": 0}
        status_counts: dict[str, int] = {}
        for e in entries:
            risk = str(e.get("risk_level", "UNKNOWN")).upper()
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
            approval = str(e.get("approval", "")).lower()
            if approval in approval_counts:
                approval_counts[approval] += 1
            status = str(e.get("result_status", "unknown"))
            status_counts[status] = status_counts.get(status, 0) + 1

        report_gen = ReportGenerator(policy)
        report = report_gen.generate(entries, report_type="governance")

        return _json_response(
            {
                "total_actions": total,
                "risk_distribution": risk_counts,
                "approval_distribution": approval_counts,
                "status_distribution": status_counts,
                "compliance_score": report.score,
                "compliance_grade": report.grade,
                "policy_rule_count": len(policy.rules),
                "active_agents": len(
                    {str(e.get("agent_id", "")) for e in entries if e.get("agent_id")}
                ),
            }
        )

    async def timeline(request: Request) -> Any:
        period = request.query_params.get("period", "24h")
        entries = audit_logger.get_log()
        buckets = _bucket_by_time(entries, period)
        return _json_response({"period": period, "buckets": buckets})

    async def audit_recent(request: Request) -> Any:
        limit = int(request.query_params.get("limit", "50"))
        offset = int(request.query_params.get("offset", "0"))

        filters: dict[str, Any] = {}
        if risk := request.query_params.get("risk_level"):
            filters["risk_level"] = risk
        if action_type := request.query_params.get("action_type"):
            filters["action_type"] = action_type
        if agent_id := request.query_params.get("agent_id"):
            filters["agent_id"] = agent_id
        if result_status := request.query_params.get("result_status"):
            filters["result_status"] = result_status

        entries = audit_logger.get_log(**filters)
        # Reverse to show newest first
        entries.reverse()
        page = entries[offset : offset + limit]
        content = json.loads(json.dumps(page, default=str))
        return _json_response(
            {
                "entries": content,
                "total": len(entries),
                "offset": offset,
                "limit": limit,
            }
        )

    async def audit_stats(request: Request) -> Any:
        entries = audit_logger.get_log()
        total = len(entries)

        risk_counts: dict[str, int] = {}
        approval_counts: dict[str, int] = {"auto": 0, "approve": 0, "block": 0}
        action_type_counts: dict[str, int] = {}
        agent_counts: dict[str, int] = {}

        for e in entries:
            risk = str(e.get("risk_level", "UNKNOWN")).upper()
            risk_counts[risk] = risk_counts.get(risk, 0) + 1

            approval = str(e.get("approval", "")).lower()
            if approval in approval_counts:
                approval_counts[approval] += 1

            atype = str(e.get("action_type", "unknown"))
            action_type_counts[atype] = action_type_counts.get(atype, 0) + 1

            agent = str(e.get("agent_id") or "default")
            agent_counts[agent] = agent_counts.get(agent, 0) + 1

        return _json_response(
            {
                "total": total,
                "by_risk_level": risk_counts,
                "by_approval": approval_counts,
                "by_action_type": dict(
                    sorted(action_type_counts.items(), key=lambda x: x[1], reverse=True)[:20]
                ),
                "by_agent": agent_counts,
            }
        )

    async def policy_summary(request: Request) -> Any:
        rules = []
        for rule in policy.rules:
            rules.append(
                {
                    "name": rule.name,
                    "match_type": rule.match_type,
                    "match_target": rule.match_target,
                    "risk_level": rule.risk_level.name,
                    "approval": rule.approval.value,
                    "conditions": rule.conditions,
                }
            )

        # Coverage assessment
        has_destructive = any(r.approval.value == "block" for r in policy.rules)
        has_approval = any(r.approval.value == "approve" for r in policy.rules)

        return _json_response(
            {
                "default_risk_level": policy.default_risk_level.name,
                "default_approval": policy.default_approval.value,
                "rule_count": len(policy.rules),
                "rules": rules,
                "has_destructive_blocks": has_destructive,
                "has_approval_gates": has_approval,
            }
        )

    async def policy_yaml(request: Request) -> Any:
        """Export current policy as YAML string."""
        import yaml

        data: dict[str, Any] = {
            "version": "1",
            "defaults": {
                "risk_level": policy.default_risk_level.name.lower(),
                "approval": policy.default_approval.value,
            },
            "rules": [],
        }
        for rule in policy.rules:
            r: dict[str, Any] = {}
            if rule.name:
                r["name"] = rule.name
            match: dict[str, str] = {}
            if rule.match_type and rule.match_type != "*":
                match["type"] = rule.match_type
            if rule.match_target and rule.match_target != "*":
                match["target"] = rule.match_target
            if match:
                r["match"] = match
            if rule.conditions:
                r["conditions"] = rule.conditions
            r["risk_level"] = rule.risk_level.name.lower()
            r["approval"] = rule.approval.value
            data["rules"].append(r)

        yaml_str: str = yaml.dump(
            data, default_flow_style=False, sort_keys=False, allow_unicode=True
        )
        return _json_response({"yaml": yaml_str})

    async def policy_score(request: Request) -> Any:
        """Calculate governance score (adapted from cli/score.py logic)."""
        score = 0
        checks: list[dict[str, Any]] = []

        # 1. Has rules at all
        has_rules = len(policy.rules) > 0
        score += 15 if has_rules else 0
        checks.append({"name": "Has policy rules", "passed": has_rules, "points": 15})

        # 2. Blocks destructive actions
        has_blocks = any(r.approval.value == "block" for r in policy.rules)
        score += 20 if has_blocks else 0
        checks.append({"name": "Blocks destructive actions", "passed": has_blocks, "points": 20})

        # 3. Approval gates for writes
        has_approval = any(r.approval.value == "approve" for r in policy.rules)
        score += 15 if has_approval else 0
        checks.append(
            {
                "name": "Approval gates for sensitive ops",
                "passed": has_approval,
                "points": 15,
            }
        )

        # 4. Multiple rules (breadth)
        multi_rules = len(policy.rules) >= 3
        score += 10 if multi_rules else 0
        checks.append({"name": "3+ policy rules", "passed": multi_rules, "points": 10})

        # 5. Target-specific rules
        has_target_rules = any(r.match_target and r.match_target != "*" for r in policy.rules)
        score += 10 if has_target_rules else 0
        checks.append({"name": "Target-specific rules", "passed": has_target_rules, "points": 10})

        # 6. Condition-based rules
        has_conditions = any(r.conditions for r in policy.rules)
        score += 10 if has_conditions else 0
        checks.append({"name": "Conditional rules", "passed": has_conditions, "points": 10})

        # 7. Non-permissive defaults
        safe_defaults = policy.default_approval.value != "auto"
        score += 10 if safe_defaults else 0
        checks.append({"name": "Non-permissive defaults", "passed": safe_defaults, "points": 10})

        # 8. Named rules
        all_named = all(r.name for r in policy.rules) if policy.rules else False
        score += 10 if all_named else 0
        checks.append({"name": "All rules named", "passed": all_named, "points": 10})

        grade = _score_to_grade(score)
        return _json_response({"score": score, "grade": grade, "checks": checks})

    async def compliance_report(request: Request) -> Any:
        report_type = request.query_params.get("type", "governance")
        entries = audit_logger.get_log()
        report_gen = ReportGenerator(policy)
        try:
            report = report_gen.generate(entries, report_type=report_type)
        except ValueError as e:
            return _json_response({"error": str(e)}, status_code=400)
        return _json_response(report_gen.to_dict(report))

    async def compliance_regulatory(request: Request) -> Any:
        framework_str = request.query_params.get("framework", "eu_ai_act")
        try:
            framework = RegulatoryFramework(framework_str)
        except ValueError:
            valid = [f.value for f in RegulatoryFramework]
            return _json_response(
                {"error": f"Unknown framework. Valid: {valid}"},
                status_code=400,
            )
        mapper = ComplianceMapper()
        analysis = mapper.analyze(framework)
        return _json_response(
            {
                "framework": analysis.framework.value,
                "total_requirements": analysis.total_requirements,
                "fully_covered": analysis.fully_covered,
                "partially_covered": analysis.partially_covered,
                "not_covered": analysis.not_covered,
                "coverage_score": analysis.coverage_score,
                "gaps": [
                    {
                        "requirement_id": g.requirement_id,
                        "title": g.title,
                        "description": g.description,
                        "category": g.category,
                        "mandatory": g.mandatory,
                        "deadline": g.deadline,
                        "penalty": g.penalty,
                    }
                    for g in analysis.gaps
                ],
                "recommendations": analysis.recommendations,
            }
        )

    async def anomaly_profiles(request: Request) -> Any:
        if anomaly_detector is None:
            return _json_response({"profiles": [], "configured": False})

        profiles = []
        for agent_id in list(anomaly_detector._profiles.keys()):
            p = anomaly_detector.get_profile(agent_id)
            if p is None:
                continue
            block_rate = p.blocked_count / p.total_actions if p.total_actions > 0 else 0.0
            profiles.append(
                {
                    "agent_id": p.agent_id,
                    "total_actions": p.total_actions,
                    "blocked_count": p.blocked_count,
                    "block_rate": round(block_rate, 3),
                    "action_types": dict(p.action_counts),
                    "targets": dict(p.target_counts),
                    "first_seen": p.first_seen.isoformat(),
                    "last_seen": p.last_seen.isoformat(),
                }
            )
        return _json_response({"profiles": profiles, "configured": True})

    async def anomaly_alerts(request: Request) -> Any:
        if anomaly_detector is None:
            return _json_response({"alerts": [], "configured": False})

        # Build alerts from audit log by replaying through detector
        entries = audit_logger.get_log()
        alerts: list[dict[str, Any]] = []
        seen_agents: set[str] = set()

        for e in reversed(entries[-200:]):
            agent_id = str(e.get("agent_id") or "default")
            if agent_id in seen_agents:
                continue
            p = anomaly_detector.get_profile(agent_id)
            if p is None:
                continue
            if p.total_actions >= 5:
                block_rate = p.blocked_count / p.total_actions
                if block_rate > 0.5:
                    alerts.append(
                        {
                            "type": "high_block_rate",
                            "severity": min(1.0, block_rate),
                            "agent_id": agent_id,
                            "message": (
                                f"Agent '{agent_id}' blocked "
                                f"{p.blocked_count}/{p.total_actions} times"
                            ),
                            "timestamp": p.last_seen.isoformat(),
                        }
                    )
            seen_agents.add(agent_id)

        return _json_response({"alerts": alerts, "configured": True})

    async def system_health(request: Request) -> Any:
        from aegis import __version__

        total_entries = audit_logger.count()

        return _json_response(
            {
                "status": "ok",
                "version": __version__,
                "audit_entries": total_entries,
                "policy_rules": len(policy.rules),
                "anomaly_detector": anomaly_detector is not None,
            }
        )

    async def badge_score(request: Request) -> Any:
        """Shields.io endpoint badge for governance score."""
        score = 0
        score += 15 if policy.rules else 0
        score += 20 if any(r.approval.value == "block" for r in policy.rules) else 0
        score += 15 if any(r.approval.value == "approve" for r in policy.rules) else 0
        score += 10 if len(policy.rules) >= 3 else 0
        score += 10 if any(r.match_target and r.match_target != "*" for r in policy.rules) else 0
        score += 10 if any(r.conditions for r in policy.rules) else 0
        score += 10 if policy.default_approval.value != "auto" else 0
        score += 10 if (policy.rules and all(r.name for r in policy.rules)) else 0

        grade = _score_to_grade(score)
        if score >= 80:
            color = "brightgreen"
        elif score >= 60:
            color = "yellow"
        elif score >= 40:
            color = "orange"
        else:
            color = "red"

        return _json_response(
            {
                "schemaVersion": 1,
                "label": "aegis score",
                "message": f"{grade} ({score}/100)",
                "color": color,
            }
        )

    return [
        Route("/api/v1/badge/score", badge_score, methods=["GET"]),
        Route("/api/v1/dashboard/overview", overview, methods=["GET"]),
        Route("/api/v1/dashboard/stats/timeline", timeline, methods=["GET"]),
        Route("/api/v1/dashboard/audit/recent", audit_recent, methods=["GET"]),
        Route("/api/v1/dashboard/audit/stats", audit_stats, methods=["GET"]),
        Route("/api/v1/dashboard/policy/summary", policy_summary, methods=["GET"]),
        Route("/api/v1/dashboard/policy/yaml", policy_yaml, methods=["GET"]),
        Route("/api/v1/dashboard/policy/score", policy_score, methods=["GET"]),
        Route("/api/v1/dashboard/compliance/report", compliance_report, methods=["GET"]),
        Route(
            "/api/v1/dashboard/compliance/regulatory",
            compliance_regulatory,
            methods=["GET"],
        ),
        Route(
            "/api/v1/dashboard/anomalies/profiles",
            anomaly_profiles,
            methods=["GET"],
        ),
        Route("/api/v1/dashboard/anomalies/alerts", anomaly_alerts, methods=["GET"]),
        Route("/api/v1/dashboard/system/health", system_health, methods=["GET"]),
    ]


def _score_to_grade(score: int) -> str:
    if score >= 97:
        return "A+"
    if score >= 93:
        return "A"
    if score >= 90:
        return "A-"
    if score >= 87:
        return "B+"
    if score >= 83:
        return "B"
    if score >= 80:
        return "B-"
    if score >= 77:
        return "C+"
    if score >= 73:
        return "C"
    if score >= 70:
        return "C-"
    if score >= 60:
        return "D"
    return "F"
