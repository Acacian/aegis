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
import os
from datetime import UTC, datetime
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
    audit_logger: Any | None = None,
    agent_heartbeat_timeout: int = 60,
    guardrail_engine: Any | None = None,
    webhook_manager: Any | None = None,
    rate_limiter: Any | None = None,
    policy_store: Any | None = None,
    crypto_chain: Any | None = None,
    drift_detector: Any | None = None,
    trust_scorer: Any | None = None,
    cost_tracker: Any | None = None,
    enable_policy_watcher: bool = False,
) -> Any:
    """Create the Aegis ASGI application.

    Args:
        policy_path: Path to a YAML policy file.
        policy: A pre-built Policy instance (takes precedence over policy_path).
        executor: Optional executor for /execute endpoint. Defaults to no-op.
        audit_db_path: Path for SQLite audit DB. Defaults to in-memory.
        enable_dashboard: Serve the web dashboard at ``/``. Default ``True``.
        anomaly_detector: Optional :class:`AnomalyDetector` for dashboard anomaly pages.
        audit_logger: Pre-configured audit logger instance (overrides audit_db_path).
        agent_heartbeat_timeout: Seconds before an agent is considered stale.
        guardrail_engine: Pre-configured :class:`GuardrailEngine` for content checks.

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

    if audit_logger is None:
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
        data: dict[str, Any] = {
            "status": "ok",
            "version": _get_version(),
            "agents": {
                "total": agent_registry.count,
                "alive": agent_registry.alive_count,
            },
            "guardrails": {
                "enabled": guardrail_engine is not None,
                "active": [g.name for g in guardrail_engine._guardrails]
                if guardrail_engine is not None
                else [],
            },
        }
        return JSONResponse(data)

    _MAX_BODY_BYTES = 1_048_576  # 1 MB

    async def _read_json(request: Request) -> Any:
        """Read JSON body with size limit."""
        body_bytes = await request.body()
        if len(body_bytes) > _MAX_BODY_BYTES:
            return JSONResponse({"error": "Request body too large (max 1MB)"}, status_code=413)
        return json.loads(body_bytes)

    def _check_rate_limit(action: Action) -> JSONResponse | None:
        """Check rate limit for an action. Returns 429 response if exceeded."""
        if rate_limiter is None:
            return None
        agent_id = action.agent_id or "anonymous"
        result = rate_limiter.check(action, agent_id=agent_id)
        if not result.allowed:
            if webhook_manager is not None:
                from aegis.core.webhooks import WebhookEvent

                webhook_manager.notify_async(
                    WebhookEvent(
                        event_type="rate_limited",
                        severity="warning",
                        timestamp=datetime.now(UTC).isoformat(),
                        agent_id=agent_id,
                        action_type=action.type,
                        action_target=action.target,
                        message=f"Rate limited: {result.rule_name}",
                    )
                )
            return JSONResponse(
                {
                    "error": "Rate limit exceeded",
                    "rule": result.rule_name,
                    "retry_after_seconds": result.retry_after_seconds,
                },
                status_code=429,
            )
        rate_limiter.record(action, agent_id=agent_id)
        return None

    def _fire_block_webhook(action: Action, reason: str) -> None:
        """Fire a webhook notification when an action is blocked."""
        if webhook_manager is None:
            return
        from aegis.core.webhooks import WebhookEvent

        webhook_manager.notify_async(
            WebhookEvent(
                event_type="action_blocked",
                severity="critical",
                timestamp=datetime.now(UTC).isoformat(),
                agent_id=action.agent_id or "unknown",
                action_type=action.type,
                action_target=action.target,
                message=reason,
            )
        )

    async def evaluate(request: Request) -> JSONResponse:
        """Evaluate action(s) against policy without executing."""
        body = await _read_json(request)
        if isinstance(body, JSONResponse):
            return body
        actions = _parse_actions(body)

        # Rate limit check (first action only for batch)
        if actions:
            rl_resp = _check_rate_limit(actions[0])
            if rl_resp is not None:
                return rl_resp

        results = []
        for action in actions:
            decision = runtime.policy.evaluate(action)
            entry: dict[str, Any] = {
                "action_type": action.type,
                "target": action.target,
                "risk_level": decision.risk_level.name,
                "approval": decision.approval.value,
                "is_allowed": decision.is_allowed,
                "matched_rule": decision.matched_rule,
            }

            # Run guardrails on action description/params if engine is available
            if guardrail_engine is not None and action.description:
                gr_results = guardrail_engine.check(action.description)
                entry["guardrails"] = [
                    {
                        "name": r.guardrail_name,
                        "passed": r.passed,
                        "severity": getattr(r, "severity", "medium"),
                        "details": r.details,
                    }
                    for r in gr_results
                ]
                if any(not r.passed for r in gr_results):
                    entry["is_allowed"] = False
                    entry["blocked_by_guardrail"] = True

            results.append(entry)

        if len(results) == 1:
            return JSONResponse(results[0])
        return JSONResponse(results)

    async def check_guardrails(request: Request) -> JSONResponse:
        """Run guardrail checks on arbitrary content."""
        if guardrail_engine is None:
            return JSONResponse({"error": "No guardrails configured"}, status_code=501)
        body = await _read_json(request)
        if isinstance(body, JSONResponse):
            return body
        content = body.get("content", "")
        if not content:
            return JSONResponse({"error": "content is required"}, status_code=400)

        gr_results = guardrail_engine.check(content)
        return JSONResponse(
            {
                "content_length": len(content),
                "passed": all(r.passed for r in gr_results),
                "results": [
                    {
                        "name": r.guardrail_name,
                        "passed": r.passed,
                        "severity": getattr(r, "severity", "medium"),
                        "details": r.details,
                    }
                    for r in gr_results
                ],
            }
        )

    async def list_guardrails(request: Request) -> JSONResponse:
        """List active guardrails and their configuration."""
        if guardrail_engine is None:
            return JSONResponse({"enabled": False, "guardrails": []})
        return JSONResponse(
            {
                "enabled": True,
                "guardrails": [
                    {
                        "name": g.name,
                        "description": getattr(g, "description", ""),
                    }
                    for g in guardrail_engine._guardrails
                ],
            }
        )

    async def execute_action(request: Request) -> JSONResponse:
        """Execute action through full governance pipeline."""
        body = await _read_json(request)
        if isinstance(body, JSONResponse):
            return body
        actions = _parse_actions(body)

        # Rate limit check
        if actions:
            rl_resp = _check_rate_limit(actions[0])
            if rl_resp is not None:
                return rl_resp

        results = []
        for action in actions:
            # Pre-execution guardrail check
            if guardrail_engine is not None and action.description:
                gr_results = guardrail_engine.check(action.description)
                if any(not r.passed for r in gr_results):
                    _fire_block_webhook(action, "Blocked by guardrail")
                    results.append(
                        {
                            "action_type": action.type,
                            "target": action.target,
                            "status": "blocked",
                            "data": None,
                            "error": "Blocked by guardrail",
                            "guardrails": [
                                {
                                    "name": r.guardrail_name,
                                    "passed": r.passed,
                                    "severity": getattr(r, "severity", "medium"),
                                    "details": r.details,
                                }
                                for r in gr_results
                            ],
                        }
                    )
                    continue

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
        if isinstance(exc, KeyError | ValueError | TypeError):
            return JSONResponse({"error": "Bad request"}, status_code=400)
        # Do not leak internal exception details to clients
        return JSONResponse({"error": "Internal server error"}, status_code=500)

    # --- Agent registry ---
    from aegis.server.agents import AgentRegistry

    agent_registry = AgentRegistry(heartbeat_timeout=agent_heartbeat_timeout)

    async def register_agent(request: Request) -> JSONResponse:
        """Register or re-register an agent."""
        body = await _read_json(request)
        if isinstance(body, JSONResponse):
            return body
        agent_id = body.get("agent_id", "")
        if not agent_id:
            return JSONResponse({"error": "agent_id is required"}, status_code=400)
        rec = agent_registry.register(
            agent_id=agent_id,
            name=body.get("name", agent_id),
            framework=body.get("framework", ""),
            version=body.get("version", ""),
            metadata=body.get("metadata"),
        )
        timeout = agent_registry._heartbeat_timeout
        return JSONResponse(rec.to_dict(timeout=timeout), status_code=201)

    async def list_agents(request: Request) -> JSONResponse:
        """List all registered agents."""
        alive_only = request.query_params.get("alive", "").lower() in ("1", "true")
        agents = agent_registry.list_alive() if alive_only else agent_registry.list_all()
        timeout = agent_registry._heartbeat_timeout
        return JSONResponse(
            {
                "agents": [a.to_dict(timeout=timeout) for a in agents],
                "total": agent_registry.count,
                "alive": agent_registry.alive_count,
            }
        )

    async def get_agent(request: Request) -> JSONResponse:
        """Get a single agent's status."""
        agent_id = request.path_params["agent_id"]
        rec = agent_registry.get(agent_id)
        if rec is None:
            return JSONResponse({"error": "Agent not found"}, status_code=404)
        return JSONResponse(rec.to_dict(timeout=agent_registry._heartbeat_timeout))

    async def agent_heartbeat(request: Request) -> JSONResponse:
        """Update agent heartbeat."""
        agent_id = request.path_params["agent_id"]
        rec = agent_registry.heartbeat(agent_id)
        if rec is None:
            return JSONResponse({"error": "Agent not found"}, status_code=404)
        return JSONResponse({"status": "ok", "agent_id": agent_id})

    async def unregister_agent(request: Request) -> JSONResponse:
        """Unregister an agent."""
        agent_id = request.path_params["agent_id"]
        if agent_registry.unregister(agent_id):
            return JSONResponse({"status": "removed", "agent_id": agent_id})
        return JSONResponse({"error": "Agent not found"}, status_code=404)

    routes: list[Route | Mount | WebSocketRoute] = [
        Route("/health", health, methods=["GET"]),
        Route("/api/v1/evaluate", evaluate, methods=["POST"]),
        Route("/api/v1/execute", execute_action, methods=["POST"]),
        Route("/api/v1/audit", get_audit, methods=["GET"]),
        Route("/api/v1/policy", get_policy, methods=["GET"]),
        Route("/api/v1/policy", update_policy, methods=["PUT"]),
        # Agent management
        Route("/api/v1/agents", register_agent, methods=["POST"]),
        Route("/api/v1/agents", list_agents, methods=["GET"]),
        Route("/api/v1/agents/{agent_id}", get_agent, methods=["GET"]),
        Route("/api/v1/agents/{agent_id}", unregister_agent, methods=["DELETE"]),
        Route("/api/v1/agents/{agent_id}/heartbeat", agent_heartbeat, methods=["POST"]),
        # Guardrail checks
        Route("/api/v1/guardrails", list_guardrails, methods=["GET"]),
        Route("/api/v1/guardrails/check", check_guardrails, methods=["POST"]),
    ]

    # Extended API endpoints (versioning, crypto, drift, trust, cost, sessions, compliance)
    from aegis.server.extended_api import get_extended_routes

    routes.extend(
        get_extended_routes(
            policy_store=policy_store,
            crypto_chain=crypto_chain,
            drift_detector=drift_detector,
            trust_scorer=trust_scorer,
            cost_tracker=cost_tracker,
            runtime=runtime,
        )
    )

    # Policy watcher (auto-reload on file change)
    if enable_policy_watcher and policy_path is not None:
        from aegis.runtime.watcher import PolicyWatcher

        _watcher = PolicyWatcher(runtime, str(policy_path))

        async def _on_startup() -> None:
            await _watcher.start()

        async def _on_shutdown() -> None:
            await _watcher.stop()

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

    # API key authentication middleware
    # SECURITY: Without AEGIS_API_KEY, server binds to localhost only.
    # The policy PUT endpoint requires a separate admin key or the main key.
    _api_key = os.environ.get("AEGIS_API_KEY")
    _admin_key = os.environ.get("AEGIS_ADMIN_KEY", _api_key)
    middleware: list[Any] = []

    from starlette.middleware import Middleware
    from starlette.middleware.base import BaseHTTPMiddleware

    class ApiKeyAuthMiddleware(BaseHTTPMiddleware):
        """Require X-API-Key header for all mutating endpoints."""

        async def dispatch(self, request: Request, call_next: Any) -> Any:
            import hmac as _hmac

            if request.url.path == "/health":
                return await call_next(request)

            key = request.headers.get("X-API-Key", "")

            # Policy update requires admin key
            if request.url.path == "/api/v1/policy" and request.method == "PUT":
                if not _admin_key:
                    return JSONResponse(
                        {"error": "Policy updates require AEGIS_ADMIN_KEY"},
                        status_code=403,
                    )
                if not _hmac.compare_digest(key, _admin_key):
                    return JSONResponse(
                        {"error": "Invalid admin API key"},
                        status_code=401,
                    )
                return await call_next(request)

            # All other endpoints require the standard API key (if set)
            if _api_key and not _hmac.compare_digest(key, _api_key):
                return JSONResponse(
                    {"error": "Invalid or missing API key"},
                    status_code=401,
                )

            return await call_next(request)

    middleware.append(Middleware(ApiKeyAuthMiddleware))
    if _api_key:
        _server_logger.info("API key authentication enabled via AEGIS_API_KEY")
    else:
        _server_logger.warning(
            "AEGIS_API_KEY not set — server will only accept connections "
            "from localhost. Set AEGIS_API_KEY for remote access."
        )

    lifecycle_handlers: dict[str, Any] = {}
    if enable_policy_watcher and policy_path is not None:
        lifecycle_handlers["on_startup"] = [_on_startup]
        lifecycle_handlers["on_shutdown"] = [_on_shutdown]

    return Starlette(
        routes=routes,
        exception_handlers=exception_handlers,
        middleware=middleware,
        **lifecycle_handlers,
    )


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


def create_app_from_config(config: Any) -> Any:
    """Create an ASGI app from a :class:`ServerConfig` instance.

    This is the primary entry point for the Aegis governance framework.

    Args:
        config: A :class:`~aegis.server.config.ServerConfig` instance.

    Returns:
        A Starlette ASGI application.
    """
    from aegis.server.config import ServerConfig

    if not isinstance(config, ServerConfig):
        msg = f"Expected ServerConfig, got {type(config).__name__}"
        raise TypeError(msg)

    policy_path = config.policy.path
    audit_logger = config.create_audit_logger()

    # Override env vars for auth middleware if config provides them
    if config.auth.api_key:
        os.environ.setdefault("AEGIS_API_KEY", config.auth.api_key)
    if config.auth.admin_key:
        os.environ.setdefault("AEGIS_ADMIN_KEY", config.auth.admin_key)

    # Build guardrail engine from config
    guardrail_engine = _build_guardrail_engine(config.guardrails)

    # Build webhook manager from config
    webhook_manager = _build_webhook_manager(config.webhooks)

    # Build rate limiter from config
    rate_limiter = _build_rate_limiter(config.rate_limit)

    # Build extended feature objects
    policy_store = _build_policy_store(config)
    crypto_chain = _build_crypto_chain(config)
    drift_detector = _build_drift_detector(config)
    trust_scorer = _build_trust_scorer(config)
    cost_tracker = _build_cost_tracker(config)

    return create_app(
        policy_path=policy_path,
        audit_logger=audit_logger,
        enable_dashboard=config.dashboard.enabled,
        agent_heartbeat_timeout=config.agents.heartbeat_timeout,
        guardrail_engine=guardrail_engine,
        webhook_manager=webhook_manager,
        rate_limiter=rate_limiter,
        policy_store=policy_store,
        crypto_chain=crypto_chain,
        drift_detector=drift_detector,
        trust_scorer=trust_scorer,
        cost_tracker=cost_tracker,
        enable_policy_watcher=config.policy.watch,
    )


def _build_guardrail_engine(cfg: Any) -> Any:
    """Build a GuardrailEngine from guardrails config section."""
    from aegis.guardrails.engine import GuardrailEngine

    guardrails: list[Any] = []

    if cfg.injection:
        from aegis.guardrails.injection import InjectionGuardrail

        guardrails.append(InjectionGuardrail())

    if cfg.pii:
        from aegis.guardrails.pii import PIIGuardrail

        guardrails.append(PIIGuardrail())

    if cfg.toxicity:
        from aegis.guardrails.toxicity import ToxicityGuardrail

        guardrails.append(ToxicityGuardrail())

    if cfg.prompt_leak:
        from aegis.guardrails.prompt_leak import PromptLeakGuardrail

        guardrails.append(PromptLeakGuardrail())

    if not guardrails:
        return None

    return GuardrailEngine(guardrails=guardrails)


def _build_webhook_manager(cfg: Any) -> Any:
    """Build a WebhookManager from webhooks config section."""
    if not cfg.enabled or not cfg.endpoints:
        return None

    from aegis.core.webhooks import WebhookConfig, WebhookManager

    configs = []
    for ep in cfg.endpoints:
        configs.append(
            WebhookConfig(
                url=ep.url,
                name=ep.name or ep.url,
                events=frozenset(ep.events) if ep.events else frozenset(),
                min_severity=ep.min_severity,
                format=ep.format,
            )
        )
    return WebhookManager(configs=configs)


def _build_rate_limiter(cfg: Any) -> Any:
    """Build a RateLimiter from rate_limit config section."""
    if not cfg.enabled or not cfg.rules:
        return None

    from aegis.core.rate_limiter import RateLimiter, RateLimitRule

    rules: list[RateLimitRule] = []
    for r in cfg.rules:
        rules.append(
            RateLimitRule(
                name=r.name or f"rule_{len(rules)}",
                match_type=r.match_type,
                match_target=r.match_target,
                max_requests=r.max_requests,
                window_seconds=float(r.window_seconds),
                per_agent=r.per_agent,
                action_on_limit=r.action_on_limit,
            )
        )
    return RateLimiter(rules=rules)


def _build_policy_store(config: Any) -> Any:
    """Build PolicyStore for versioning if enabled."""
    if not getattr(config, "_versioning_enabled", True):
        return None
    from aegis.core.versioning import PolicyStore

    return PolicyStore()


def _build_crypto_chain(config: Any) -> Any:
    """Build CryptoAuditChain if enabled."""
    if not getattr(config, "_crypto_enabled", True):
        return None
    from aegis.core.crypto_audit import CryptoAuditChain

    return CryptoAuditChain()


def _build_drift_detector(config: Any) -> Any:
    """Build DriftDetector if enabled."""
    if not getattr(config, "_drift_enabled", True):
        return None
    from aegis.core.behavioral_drift import DriftDetector

    return DriftDetector()


def _build_trust_scorer(config: Any) -> Any:
    """Build TrustScorer if enabled."""
    if not getattr(config, "_trust_enabled", True):
        return None
    from aegis.core.trust_score import TrustScorer

    return TrustScorer()


def _build_cost_tracker(config: Any) -> Any:
    """Build CostTracker if enabled in config."""
    cost_cfg = getattr(config, "cost", None)
    if cost_cfg is None or not cost_cfg.enabled:
        return None
    from aegis.core.budget import CostTracker

    return CostTracker(max_budget=cost_cfg.max_budget)


def _get_version() -> str:
    try:
        from aegis import __version__

        return __version__
    except ImportError:
        return "unknown"
