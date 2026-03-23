"""ASGI application for Aegis governance API.

Provides REST endpoints for policy evaluation, action execution,
and audit log queries. Built on Starlette for minimal overhead.

Endpoints::

    POST /api/v1/evaluate   - Evaluate action(s) against policy (dry-run)
    POST /api/v1/execute     - Execute action through full governance pipeline
    GET  /api/v1/audit       - Query audit log
    GET  /api/v1/policy      - Inspect current policy rules
    PUT  /api/v1/policy      - Hot-reload policy from YAML string
    GET  /health             - Health check

Example usage with curl::

    curl -X POST http://localhost:8000/api/v1/evaluate \\
        -H "Content-Type: application/json" \\
        -d '{"action_type": "read", "target": "crm", "params": {}}'
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aegis.adapters.base import BaseExecutor
from aegis.core.action import Action
from aegis.core.policy import Policy
from aegis.core.result import Result, ResultStatus
from aegis.runtime.approval import AutoApprovalHandler
from aegis.runtime.audit import AuditLogger
from aegis.runtime.engine import Runtime


def _require_starlette() -> Any:
    try:
        import starlette

        return starlette
    except ImportError:
        msg = "starlette is required for the API server: pip install 'agent-aegis[server]'"
        raise ImportError(msg) from None


class _NoOpExecutor(BaseExecutor):
    """Executor that does nothing — used for evaluate-only mode."""

    async def execute(self, action: Action) -> Result:
        return Result(action=action, status=ResultStatus.SUCCESS, data={"executed": True})


def create_app(
    *,
    policy_path: str | Path | None = None,
    policy: Policy | None = None,
    executor: Any | None = None,
    audit_db_path: str | Path | None = None,
    enable_dashboard: bool = True,
    anomaly_detector: Any | None = None,
) -> Any:
    """Create the Aegis ASGI application.

    Args:
        policy_path: Path to a YAML policy file.
        policy: A pre-built Policy instance (takes precedence over policy_path).
        executor: Optional executor for /execute endpoint. Defaults to no-op.
        audit_db_path: Path for SQLite audit DB. Defaults to in-memory.
        enable_dashboard: Serve the web dashboard at ``/``. Default ``True``.
        anomaly_detector: Optional :class:`AnomalyDetector` for dashboard anomaly pages.

    Returns:
        A Starlette ASGI application.
    """
    _require_starlette()
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import FileResponse, JSONResponse
    from starlette.routing import Mount, Route, WebSocketRoute
    from starlette.staticfiles import StaticFiles

    if policy is None and policy_path is not None:
        policy = Policy.from_yaml(policy_path)
    elif policy is None:
        policy = Policy()

    audit_logger = AuditLogger(db_path=audit_db_path) if audit_db_path else AuditLogger()
    import logging as _logging

    _server_logger = _logging.getLogger("aegis.server")
    _server_logger.warning(
        "Aegis REST server uses AutoApprovalHandler by default. "
        "All approval-required actions will be auto-approved. "
        "Deploy behind an authenticating reverse proxy for production use."
    )

    runtime = Runtime(
        executor=executor or _NoOpExecutor(),
        policy=policy,
        approval_handler=AutoApprovalHandler(),
        audit_logger=audit_logger,
    )

    async def health(request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "version": _get_version()})

    _MAX_BODY_BYTES = 1_048_576  # 1 MB

    async def _read_json(request: Request) -> Any:
        """Read JSON body with size limit."""
        body_bytes = await request.body()
        if len(body_bytes) > _MAX_BODY_BYTES:
            return JSONResponse({"error": "Request body too large (max 1MB)"}, status_code=413)
        return json.loads(body_bytes)

    async def evaluate(request: Request) -> JSONResponse:
        """Evaluate action(s) against policy without executing."""
        body = await _read_json(request)
        if isinstance(body, JSONResponse):
            return body
        actions = _parse_actions(body)

        results = []
        for action in actions:
            decision = runtime.policy.evaluate(action)
            results.append(
                {
                    "action_type": action.type,
                    "target": action.target,
                    "risk_level": decision.risk_level.name,
                    "approval": decision.approval.value,
                    "is_allowed": decision.is_allowed,
                    "matched_rule": decision.matched_rule,
                }
            )

        if len(results) == 1:
            return JSONResponse(results[0])
        return JSONResponse(results)

    async def execute_action(request: Request) -> JSONResponse:
        """Execute action through full governance pipeline."""
        body = await _read_json(request)
        if isinstance(body, JSONResponse):
            return body
        actions = _parse_actions(body)

        results = []
        for action in actions:
            result = await runtime.run_one(action)
            results.append(
                {
                    "action_type": result.action.type,
                    "target": result.action.target,
                    "status": result.status.value,
                    "data": result.data,
                    "error": result.error,
                }
            )

        if len(results) == 1:
            return JSONResponse(results[0])
        return JSONResponse(results)

    async def get_audit(request: Request) -> JSONResponse:
        """Query audit log with optional filters."""
        filters: dict[str, Any] = {}
        if session_id := request.query_params.get("session_id"):
            filters["session_id"] = session_id
        if action_type := request.query_params.get("action_type"):
            filters["action_type"] = action_type
        if risk_level := request.query_params.get("risk_level"):
            filters["risk_level"] = risk_level
        if result_status := request.query_params.get("result_status"):
            filters["result_status"] = result_status
        if limit := request.query_params.get("limit"):
            try:
                limit_int = int(limit)
                if limit_int < 0:
                    return JSONResponse(
                        {"error": "limit must be a non-negative integer"}, status_code=400
                    )
                filters["limit"] = limit_int
            except ValueError:
                return JSONResponse({"error": "limit must be a valid integer"}, status_code=400)

        entries = runtime.audit.get_log(**filters)
        # Serialize with default=str to handle datetime objects
        content = json.loads(json.dumps(entries, default=str))
        return JSONResponse(content)

    async def get_policy(request: Request) -> JSONResponse:
        """Inspect current policy rules."""
        rules = []
        for rule in runtime.policy.rules:
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
        return JSONResponse(
            {
                "default_risk_level": runtime.policy.default_risk_level.name,
                "default_approval": runtime.policy.default_approval.value,
                "rules": rules,
            }
        )

    async def update_policy(request: Request) -> JSONResponse:
        """Hot-reload policy from YAML string or dict."""
        body = await _read_json(request)
        if isinstance(body, JSONResponse):
            return body

        if "yaml" in body:
            import yaml

            data = yaml.safe_load(body["yaml"])
            new_policy = Policy.from_dict(data)
        elif "rules" in body or "defaults" in body:
            new_policy = Policy.from_dict(body)
        else:
            return JSONResponse(
                {"error": "Provide 'yaml' string or policy dict with 'rules'"},
                status_code=400,
            )

        runtime.update_policy(new_policy)
        return JSONResponse({"status": "updated", "rule_count": len(new_policy.rules)})

    async def handle_error(request: Request, exc: Exception) -> JSONResponse:
        if isinstance(exc, json.JSONDecodeError):
            return JSONResponse({"error": "Invalid JSON"}, status_code=400)
        if isinstance(exc, (KeyError, ValueError, TypeError)):
            return JSONResponse({"error": "Bad request"}, status_code=400)
        # Do not leak internal exception details to clients
        return JSONResponse({"error": "Internal server error"}, status_code=500)

    routes: list[Route | Mount | WebSocketRoute] = [
        Route("/health", health, methods=["GET"]),
        Route("/api/v1/evaluate", evaluate, methods=["POST"]),
        Route("/api/v1/execute", execute_action, methods=["POST"]),
        Route("/api/v1/audit", get_audit, methods=["GET"]),
        Route("/api/v1/policy", get_policy, methods=["GET"]),
        Route("/api/v1/policy", update_policy, methods=["PUT"]),
    ]

    # WebSocket for real-time audit streaming
    from aegis.server.ws import AuditBroadcaster, get_ws_route

    broadcaster = AuditBroadcaster()
    broadcaster.attach(audit_logger)
    routes.append(get_ws_route(broadcaster))

    if enable_dashboard:
        from aegis.server.dashboard_api import get_dashboard_routes

        dashboard_routes = get_dashboard_routes(
            policy=policy,
            audit_logger=audit_logger,
            anomaly_detector=anomaly_detector,
        )
        routes.extend(dashboard_routes)

        # Serve the SPA frontend
        _static_dir = Path(__file__).parent / "static"
        _index_html = _static_dir / "index.html"

        async def serve_index(request: Request) -> FileResponse:
            return FileResponse(str(_index_html), media_type="text/html")

        routes.append(Route("/", serve_index, methods=["GET"]))
        routes.append(Route("/dashboard", serve_index, methods=["GET"]))
        routes.append(Mount("/static", app=StaticFiles(directory=str(_static_dir)), name="static"))

    exception_handlers = {
        400: handle_error,
        500: handle_error,
    }

    return Starlette(routes=routes, exception_handlers=exception_handlers)


def _parse_actions(body: dict[str, Any] | list[dict[str, Any]]) -> list[Action]:
    """Parse one or more actions from request body."""
    if isinstance(body, list):
        items = body
    elif "actions" in body:
        items = body["actions"]
    else:
        items = [body]

    actions = []
    for item in items:
        action_type = item.get("action_type", item.get("type", ""))
        if not action_type:
            raise ValueError("action_type is required and cannot be empty")
        actions.append(
            Action(
                type=action_type,
                target=item.get("target", ""),
                params=item.get("params", {}),
                description=item.get("description", ""),
            )
        )
    return actions


def _get_version() -> str:
    try:
        from aegis import __version__

        return __version__
    except ImportError:
        return "unknown"
