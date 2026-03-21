"""
FastAPI middleware demo — Aegis as API endpoint governance layer.

Usage:
    python examples/fastapi_middleware_demo.py

Demonstrates:
- Mapping HTTP methods to Aegis risk levels (GET=auto, POST=approve, DELETE=block)
- Middleware-style request interception and policy evaluation
- Per-endpoint governance with full audit trail
- Simulated FastAPI request/response cycle without requiring FastAPI installed
"""

from __future__ import annotations

import asyncio
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegis import Action, Approval, Policy, PolicyDecision, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.core.result import Result, ResultStatus
from aegis.runtime.approval import AutoApprovalHandler
from aegis.runtime.audit import AuditLogger


# ANSI colors
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"


POLICY_YAML = """\
version: "1"
defaults:
  risk_level: medium
  approval: approve

rules:
  - name: get_auto
    match: { type: "GET" }
    risk_level: low
    approval: auto

  - name: post_approve
    match: { type: "POST" }
    risk_level: medium
    approval: approve

  - name: put_approve
    match: { type: "PUT" }
    risk_level: medium
    approval: approve

  - name: delete_block
    match: { type: "DELETE" }
    risk_level: critical
    approval: block
"""


# ---------------------------------------------------------------------------
# Simulated FastAPI request/response (no FastAPI import needed)
# ---------------------------------------------------------------------------

@dataclass
class Request:
    """Simulated HTTP request."""

    method: str
    path: str
    body: dict[str, Any] | None = None

    def __str__(self) -> str:
        return f"{self.method} {self.path}"


@dataclass
class Response:
    """Simulated HTTP response."""

    status_code: int
    body: dict[str, Any]


# ---------------------------------------------------------------------------
# Aegis middleware
# ---------------------------------------------------------------------------

class AegisMiddleware:
    """Middleware that evaluates every request against Aegis policy.

    In a real FastAPI app this would be an ASGI middleware or a dependency.
    The pattern is the same:

        @app.middleware("http")
        async def aegis_gate(request: Request, call_next):
            decision = policy.evaluate(
                Action(request.method, request.url.path)
            )
            if decision.approval == Approval.BLOCK:
                return JSONResponse(status_code=403, ...)
            response = await call_next(request)
            return response
    """

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def evaluate(self, request: Request) -> PolicyDecision:
        """Map an HTTP request to an Aegis action and evaluate it."""
        action = Action(
            type=request.method,
            target=request.path,
            description=f"{request.method} {request.path}",
        )
        return self.policy.evaluate(action)


# ---------------------------------------------------------------------------
# Simulated endpoint executor
# ---------------------------------------------------------------------------

class EndpointExecutor(BaseExecutor):
    """Simulates FastAPI endpoint handlers."""

    USERS_DB: list[dict[str, Any]] = [
        {"id": 1, "name": "Alice", "role": "admin"},
        {"id": 2, "name": "Bob", "role": "viewer"},
        {"id": 3, "name": "Charlie", "role": "editor"},
    ]

    async def execute(self, action: Action) -> Result:
        method = action.type
        path = action.target

        if method == "GET" and path == "/users":
            return Result(
                action=action,
                status=ResultStatus.SUCCESS,
                data={"users": self.USERS_DB},
            )
        if method == "POST" and path == "/users":
            new_user = action.params.get("body", {})
            return Result(
                action=action,
                status=ResultStatus.SUCCESS,
                data={"created": new_user},
            )
        if method == "DELETE" and path.startswith("/users/"):
            user_id = path.split("/")[-1]
            return Result(
                action=action,
                status=ResultStatus.SUCCESS,
                data={"deleted_id": user_id},
            )
        return Result(action=action, status=ResultStatus.SUCCESS)


# ---------------------------------------------------------------------------
# Simulated request dispatcher
# ---------------------------------------------------------------------------

def _color_for_decision(decision: PolicyDecision) -> str:
    if decision.approval == Approval.AUTO:
        return C.GREEN
    if decision.approval == Approval.APPROVE:
        return C.YELLOW
    return C.RED


def _label_for_decision(decision: PolicyDecision) -> str:
    if decision.approval == Approval.AUTO:
        return "AUTO-APPROVED"
    if decision.approval == Approval.APPROVE:
        return "NEEDS APPROVAL"
    return "BLOCKED"


async def dispatch(
    request: Request,
    middleware: AegisMiddleware,
    runtime: Runtime,
) -> Response:
    """Simulate the middleware + endpoint flow for one request."""
    decision = middleware.evaluate(request)
    color = _color_for_decision(decision)
    label = _label_for_decision(decision)

    print(f"  {C.CYAN}{C.BOLD}{request}{C.RESET}")
    print(
        f"    Rule:     {C.DIM}{decision.matched_rule}{C.RESET}"
    )
    print(
        f"    Risk:     {color}{decision.risk_level.name}{C.RESET}"
    )
    print(
        f"    Decision: {color}{C.BOLD}{label}{C.RESET}"
    )

    if decision.approval == Approval.BLOCK:
        print(
            f"    Response: {C.RED}403 Forbidden "
            f"- policy blocks {request.method} requests{C.RESET}"
        )
        print()
        return Response(
            status_code=403,
            body={"error": f"Blocked by policy rule: {decision.matched_rule}"},
        )

    # Build action and run through the governed runtime
    action = Action(
        type=request.method,
        target=request.path,
        params={"body": request.body} if request.body else {},
        description=f"{request.method} {request.path}",
    )
    plan = runtime.plan([action])
    results = await runtime.execute(plan)
    result = results[0]

    if result.status == ResultStatus.SUCCESS:
        print(f"    Response: {C.GREEN}200 OK{C.RESET}")
        if result.data:
            preview = str(result.data)
            if len(preview) > 60:
                preview = preview[:57] + "..."
            print(f"    Body:     {C.DIM}{preview}{C.RESET}")
    else:
        print(f"    Response: {C.YELLOW}500 Error{C.RESET}")

    print()
    return Response(
        status_code=200 if result.status == ResultStatus.SUCCESS else 500,
        body=result.data or {},
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main() -> None:
    print()
    print(f"{C.CYAN}{C.BOLD}{'=' * 60}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  FastAPI Middleware Demo{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  Aegis as API Endpoint Governance Layer{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{'=' * 60}{C.RESET}")

    # Load policy from YAML
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as f:
        f.write(POLICY_YAML)
        policy_path = f.name

    policy = Policy.from_yaml(policy_path)
    middleware = AegisMiddleware(policy)

    runtime = Runtime(
        executor=EndpointExecutor(),
        policy=policy,
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=":memory:"),
    )

    # -- Show the policy mapping --
    print(f"\n{C.MAGENTA}{C.BOLD}  Policy Mapping:{C.RESET}")
    print(f"    {C.GREEN}GET{C.RESET}    -> risk=low      approval=auto")
    print(f"    {C.YELLOW}POST{C.RESET}   -> risk=medium   approval=approve")
    print(f"    {C.RED}DELETE{C.RESET} -> risk=critical  approval=block")

    # -- Simulate requests --
    requests = [
        Request("GET", "/users"),
        Request("POST", "/users", body={"name": "Dave", "role": "viewer"}),
        Request("DELETE", "/users/3"),
    ]

    print(f"\n{C.MAGENTA}{C.BOLD}{'=' * 60}{C.RESET}")
    print(f"{C.MAGENTA}{C.BOLD}  Simulated Requests{C.RESET}")
    print(f"{C.MAGENTA}{C.BOLD}{'=' * 60}{C.RESET}\n")

    responses: list[tuple[Request, Response]] = []
    for req in requests:
        resp = await dispatch(req, middleware, runtime)
        responses.append((req, resp))

    # -- Summary table --
    print(f"{C.MAGENTA}{C.BOLD}{'=' * 60}{C.RESET}")
    print(f"{C.MAGENTA}{C.BOLD}  Summary{C.RESET}")
    print(f"{C.MAGENTA}{C.BOLD}{'=' * 60}{C.RESET}\n")

    header = f"  {'Request':<22} {'Status':<8} {'Decision':<16}"
    print(f"{C.BOLD}{header}{C.RESET}")
    print(f"  {'-' * 46}")
    for req, resp in responses:
        decision = middleware.evaluate(req)
        color = _color_for_decision(decision)
        label = _label_for_decision(decision)
        print(
            f"  {str(req):<22} "
            f"{color}{resp.status_code:<8}{C.RESET} "
            f"{color}{label}{C.RESET}"
        )

    # -- Audit trail --
    print(f"\n{C.MAGENTA}{C.BOLD}{'=' * 60}{C.RESET}")
    print(f"{C.MAGENTA}{C.BOLD}  Audit Trail{C.RESET}")
    print(f"{C.MAGENTA}{C.BOLD}{'=' * 60}{C.RESET}\n")

    for entry in runtime.audit.get_log():
        risk = entry.get("risk_level", "")
        action_type = entry.get("action_type", "")
        target = entry.get("action_target", "")
        result_status = entry.get("result_status", "-")
        print(
            f"  {action_type:>6} {target:<14} "
            f"risk={risk:<8} result={result_status}"
        )

    # -- Integration hint --
    hint = (
        '    @app.middleware("http")\n'
        "    async def aegis_gate(request, call_next):\n"
        "        decision = policy.evaluate(\n"
        "            Action(request.method, request.url.path)\n"
        "        )\n"
        "        if decision.approval == Approval.BLOCK:\n"
        "            return JSONResponse(status_code=403, ...)\n"
        "        return await call_next(request)"
    )
    print(f"\n{C.DIM}  Integration pattern for a real FastAPI app:\n")
    print(f"{hint}{C.RESET}")
    print()

    Path(policy_path).unlink(missing_ok=True)


if __name__ == "__main__":
    asyncio.run(main())
