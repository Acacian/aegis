"""Extended API endpoints for advanced governance features.

Adds REST endpoints for policy versioning, RBAC, crypto audit verification,
behavioral drift, trust scoring, cost governance, session replay, compliance
reports, and SIEM export configuration.

All endpoints are mounted under ``/api/v1/`` by :func:`get_extended_routes`.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any


def _safe_dict(obj: Any) -> Any:
    """Convert dataclass to dict with datetime serialization."""
    d = asdict(obj)
    return json.loads(json.dumps(d, default=str))


def _json(data: Any, status: int = 200) -> Any:
    from starlette.responses import JSONResponse

    content = json.loads(json.dumps(data, default=str))
    return JSONResponse(content, status_code=status)


_MAX_BODY = 1_048_576


async def _body(request: Any) -> Any:
    from starlette.responses import JSONResponse

    raw = await request.body()
    if len(raw) > _MAX_BODY:
        return JSONResponse({"error": "Request body too large"}, status_code=413)
    return json.loads(raw)


def get_extended_routes(
    *,
    policy_store: Any | None = None,
    crypto_chain: Any | None = None,
    drift_detector: Any | None = None,
    trust_scorer: Any | None = None,
    cost_tracker: Any | None = None,
    session_store: dict[str, Any] | None = None,
    runtime: Any | None = None,
) -> list[Any]:
    """Build Route list for extended governance API.

    Each feature degrades gracefully — if the backing object is ``None``,
    endpoints return 501 Not Implemented.
    """
    from starlette.requests import Request
    from starlette.routing import Route

    # Mutable session store (in-memory)
    _sessions: dict[str, Any] = session_store if session_store is not None else {}

    # ------------------------------------------------------------------ #
    # Policy Versioning
    # ------------------------------------------------------------------ #

    async def version_list(request: Request) -> Any:
        if policy_store is None:
            return _json({"error": "Policy versioning not configured"}, 501)
        limit = int(request.query_params.get("limit", "50"))
        versions = policy_store.get_history(limit=limit)
        return _json(
            {
                "versions": [_safe_dict(v) for v in versions],
                "total": len(policy_store._versions),
            }
        )

    async def version_get(request: Request) -> Any:
        if policy_store is None:
            return _json({"error": "Policy versioning not configured"}, 501)
        vid = request.path_params["version_id"]
        v = policy_store.get_version(vid)
        if v is None:
            v = policy_store.get_by_tag(vid)
        if v is None:
            return _json({"error": "Version not found"}, 404)
        return _json(_safe_dict(v))

    async def version_commit(request: Request) -> Any:
        if policy_store is None:
            return _json({"error": "Policy versioning not configured"}, 501)
        if runtime is None:
            return _json({"error": "Runtime not available"}, 501)
        body = await _body(request)
        if not isinstance(body, dict):
            return body
        author = body.get("author", "api")
        message = body.get("message", "API commit")
        v = policy_store.commit(runtime.policy, author=author, message=message)
        return _json(_safe_dict(v), 201)

    async def version_diff(request: Request) -> Any:
        if policy_store is None:
            return _json({"error": "Policy versioning not configured"}, 501)
        body = await _body(request)
        if not isinstance(body, dict):
            return body
        va = body.get("version_a", "")
        vb = body.get("version_b", "")
        if not va or not vb:
            return _json({"error": "version_a and version_b required"}, 400)
        delta = policy_store.diff(va, vb)
        return _json(_safe_dict(delta))

    async def version_rollback(request: Request) -> Any:
        if policy_store is None:
            return _json({"error": "Policy versioning not configured"}, 501)
        body = await _body(request)
        if not isinstance(body, dict):
            return body
        vid = body.get("version_id", "")
        if not vid:
            return _json({"error": "version_id required"}, 400)
        v = policy_store.rollback(vid)
        # Apply to runtime if available
        if runtime is not None:
            from aegis.core.policy import Policy

            new_policy = Policy.from_dict(v.policy_dict)
            runtime.update_policy(new_policy)
        return _json({"status": "rolled_back", "version": _safe_dict(v)})

    async def version_tag(request: Request) -> Any:
        if policy_store is None:
            return _json({"error": "Policy versioning not configured"}, 501)
        body = await _body(request)
        if not isinstance(body, dict):
            return body
        vid = body.get("version_id", "")
        tag = body.get("tag", "")
        if not vid or not tag:
            return _json({"error": "version_id and tag required"}, 400)
        policy_store.tag(vid, tag)
        return _json({"status": "tagged", "version_id": vid, "tag": tag})

    # ------------------------------------------------------------------ #
    # Crypto Audit Chain
    # ------------------------------------------------------------------ #

    async def crypto_verify(request: Request) -> Any:
        if crypto_chain is None:
            return _json({"error": "Crypto audit not configured"}, 501)
        result = crypto_chain.verify()
        return _json(_safe_dict(result))

    async def crypto_entries(request: Request) -> Any:
        if crypto_chain is None:
            return _json({"error": "Crypto audit not configured"}, 501)
        start = int(request.query_params.get("start", "0"))
        end_param = request.query_params.get("end")
        end = int(end_param) if end_param else None
        entries = crypto_chain.get_entries(start=start, end=end)
        return _json(
            {
                "entries": [_safe_dict(e) for e in entries],
                "total": len(crypto_chain._chain),
            }
        )

    async def crypto_evidence(request: Request) -> Any:
        if crypto_chain is None:
            return _json({"error": "Crypto audit not configured"}, 501)
        result = crypto_chain.verify()
        return _json(
            {
                "chain_length": len(crypto_chain._chain),
                "algorithm": crypto_chain._algorithm,
                "verified": result.valid,
                "broken_links": result.broken_links if hasattr(result, "broken_links") else [],
            }
        )

    # ------------------------------------------------------------------ #
    # Behavioral Drift
    # ------------------------------------------------------------------ #

    async def drift_report(request: Request) -> Any:
        if drift_detector is None:
            return _json({"error": "Drift detection not configured"}, 501)
        report = drift_detector.report()
        return _json(_safe_dict(report))

    async def drift_agent(request: Request) -> Any:
        if drift_detector is None:
            return _json({"error": "Drift detection not configured"}, 501)
        agent_id = request.path_params["agent_id"]
        findings = drift_detector.check_drift(agent_id)
        baseline = drift_detector.get_baseline(agent_id)
        return _json(
            {
                "agent_id": agent_id,
                "findings": [_safe_dict(f) for f in findings],
                "baseline": _safe_dict(baseline) if baseline else None,
            }
        )

    # ------------------------------------------------------------------ #
    # Trust Score
    # ------------------------------------------------------------------ #

    async def trust_report(request: Request) -> Any:
        if trust_scorer is None:
            return _json({"error": "Trust scoring not configured"}, 501)
        report = trust_scorer.report()
        return _json(_safe_dict(report))

    async def trust_agent(request: Request) -> Any:
        if trust_scorer is None:
            return _json({"error": "Trust scoring not configured"}, 501)
        agent_id = request.path_params["agent_id"]
        score = trust_scorer.get_score(agent_id)
        events = trust_scorer.get_events(agent_id)
        return _json(
            {
                "agent_id": agent_id,
                "score": _safe_dict(score),
                "recent_events": [_safe_dict(e) for e in events[-20:]],
            }
        )

    async def trust_check(request: Request) -> Any:
        if trust_scorer is None:
            return _json({"error": "Trust scoring not configured"}, 501)
        agent_id = request.path_params["agent_id"]
        risk = request.query_params.get("risk_level", "MEDIUM")
        allowed = trust_scorer.check_threshold(agent_id, risk)
        score = trust_scorer.get_score(agent_id)
        return _json(
            {
                "agent_id": agent_id,
                "risk_level": risk,
                "allowed": allowed,
                "current_score": _safe_dict(score),
            }
        )

    # ------------------------------------------------------------------ #
    # Cost Governance
    # ------------------------------------------------------------------ #

    async def cost_report(request: Request) -> Any:
        if cost_tracker is None:
            return _json({"error": "Cost tracking not configured"}, 501)
        return _json(cost_tracker.get_report())

    async def cost_check(request: Request) -> Any:
        if cost_tracker is None:
            return _json({"error": "Cost tracking not configured"}, 501)
        body = await _body(request)
        if not isinstance(body, dict):
            return body
        estimated = float(body.get("estimated_cost", 0))
        action = cost_tracker.check_budget(estimated)
        return _json(
            {
                "action": action.value if hasattr(action, "value") else str(action),
                "spent": cost_tracker.spent,
                "remaining": cost_tracker.remaining,
                "utilization": cost_tracker.utilization,
            }
        )

    async def cost_status(request: Request) -> Any:
        if cost_tracker is None:
            return _json({"error": "Cost tracking not configured"}, 501)
        return _json(
            {
                "max_budget": cost_tracker.max_budget,
                "spent": cost_tracker.spent,
                "remaining": cost_tracker.remaining,
                "utilization": cost_tracker.utilization,
                "record_count": len(cost_tracker.records),
            }
        )

    # ------------------------------------------------------------------ #
    # Session Replay
    # ------------------------------------------------------------------ #

    async def session_list(request: Request) -> Any:
        return _json(
            {
                "sessions": [
                    {
                        "session_id": s.session_id,
                        "agent_id": s.agent_id,
                        "event_count": len(s.events),
                    }
                    for s in _sessions.values()
                ],
                "total": len(_sessions),
            }
        )

    async def session_get(request: Request) -> Any:
        sid = request.path_params["session_id"]
        session = _sessions.get(sid)
        if session is None:
            return _json({"error": "Session not found"}, 404)
        return _json(
            {
                "session_id": session.session_id,
                "agent_id": session.agent_id,
                "event_count": len(session.events),
                "events": [_safe_dict(e) for e in session.events],
            }
        )

    async def session_replay(request: Request) -> Any:
        sid = request.path_params["session_id"]
        session = _sessions.get(sid)
        if session is None:
            return _json({"error": "Session not found"}, 404)
        from aegis.core.session_replay import SessionReplayer

        replayer = SessionReplayer()
        report = replayer.replay(session)
        return _json(
            {
                "session_id": sid,
                "clean": report.clean,
                "findings": [_safe_dict(f) for f in report.findings],
                "summary": {
                    "total_events": report.events_scanned,
                    "scanned_events": report.events_scanned,
                    "finding_count": len(report.findings),
                },
            }
        )

    # ------------------------------------------------------------------ #
    # Compliance & Regulatory
    # ------------------------------------------------------------------ #

    async def compliance_report(request: Request) -> Any:
        report_type = request.query_params.get("type", "governance")
        if runtime is None:
            return _json({"error": "Runtime not available"}, 501)

        from aegis.core.compliance import ReportGenerator

        generator = ReportGenerator(runtime.policy)
        audit_entries = runtime.audit.get_log(limit=1000)
        report = generator.generate(
            audit_entries=audit_entries,
            report_type=report_type,
        )
        return _json(_safe_dict(report))

    async def regulatory_gaps(request: Request) -> Any:
        framework = request.query_params.get("framework", "eu_ai_act")

        from aegis.core.regulatory import ComplianceMapper, RegulatoryFramework

        framework_enum = RegulatoryFramework(framework)
        mapper = ComplianceMapper()
        result = mapper.analyze(framework=framework_enum)
        return _json(_safe_dict(result))

    # ------------------------------------------------------------------ #
    # Route list
    # ------------------------------------------------------------------ #

    routes = [
        # Policy versioning
        Route("/api/v1/policy/versions", version_list, methods=["GET"]),
        Route("/api/v1/policy/versions/{version_id}", version_get, methods=["GET"]),
        Route("/api/v1/policy/commit", version_commit, methods=["POST"]),
        Route("/api/v1/policy/diff", version_diff, methods=["POST"]),
        Route("/api/v1/policy/rollback", version_rollback, methods=["POST"]),
        Route("/api/v1/policy/tag", version_tag, methods=["POST"]),
        # Crypto audit
        Route("/api/v1/audit/crypto/verify", crypto_verify, methods=["GET"]),
        Route("/api/v1/audit/crypto/entries", crypto_entries, methods=["GET"]),
        Route("/api/v1/audit/crypto/evidence", crypto_evidence, methods=["GET"]),
        # Behavioral drift
        Route("/api/v1/drift", drift_report, methods=["GET"]),
        Route("/api/v1/drift/{agent_id}", drift_agent, methods=["GET"]),
        # Trust score
        Route("/api/v1/trust", trust_report, methods=["GET"]),
        Route("/api/v1/trust/{agent_id}", trust_agent, methods=["GET"]),
        Route("/api/v1/trust/{agent_id}/check", trust_check, methods=["GET"]),
        # Cost governance
        Route("/api/v1/cost", cost_status, methods=["GET"]),
        Route("/api/v1/cost/report", cost_report, methods=["GET"]),
        Route("/api/v1/cost/check", cost_check, methods=["POST"]),
        # Session replay
        Route("/api/v1/sessions", session_list, methods=["GET"]),
        Route("/api/v1/sessions/{session_id}", session_get, methods=["GET"]),
        Route("/api/v1/sessions/{session_id}/replay", session_replay, methods=["POST"]),
        # Compliance & regulatory
        Route("/api/v1/compliance/report", compliance_report, methods=["GET"]),
        Route("/api/v1/compliance/gaps", regulatory_gaps, methods=["GET"]),
    ]

    return routes
