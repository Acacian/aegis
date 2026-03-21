"""
Enterprise SSO / RBAC demo.

Usage:
    python examples/enterprise_sso_demo.py

Demonstrates:
- Role-based access control (admin, developer, viewer)
- Policy conditions enforcing per-role governance
- Different approval outcomes per role for the same actions
- ANSI-colored result matrix
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime

from aegis import Action, Policy, Result, ResultStatus, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.runtime.approval import ApprovalHandler
from aegis.runtime.audit import AuditLogger

# ── ANSI colors ──────────────────────────────────────────────

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


# ── User / role model ───────────────────────────────────────


@dataclass(frozen=True)
class User:
    name: str
    role: str  # admin | developer | viewer


USERS = [
    User("alice", "admin"),
    User("bob", "developer"),
    User("carol", "viewer"),
]

# ── Actions every user will attempt ─────────────────────────

ACTIONS = [
    ("read", "dashboard", "View analytics dashboard"),
    ("write", "config", "Update service config"),
    ("delete", "records", "Delete customer records"),
    ("deploy", "production", "Deploy to production"),
]


# ── Policy per role ─────────────────────────────────────────
# Each role gets its own policy with param_eq conditions on the
# "role" param, so a single merged policy resolves differently
# depending on the caller's role.

POLICY_DICT: dict = {
    "version": "1",
    "defaults": {"risk_level": "high", "approval": "block"},
    "rules": [
        # ── Admin rules (matched first) ─────────────────────
        {
            "name": "admin_read",
            "match": {"type": "read"},
            "conditions": {"param_eq": {"role": "admin"}},
            "risk_level": "low",
            "approval": "auto",
        },
        {
            "name": "admin_write",
            "match": {"type": "write"},
            "conditions": {"param_eq": {"role": "admin"}},
            "risk_level": "medium",
            "approval": "auto",
        },
        {
            "name": "admin_delete",
            "match": {"type": "delete"},
            "conditions": {"param_eq": {"role": "admin"}},
            "risk_level": "high",
            "approval": "auto",
        },
        {
            "name": "admin_deploy",
            "match": {"type": "deploy"},
            "conditions": {"param_eq": {"role": "admin"}},
            "risk_level": "high",
            "approval": "auto",
        },
        # ── Developer rules ──────────────────────────────────
        {
            "name": "dev_read",
            "match": {"type": "read"},
            "conditions": {"param_eq": {"role": "developer"}},
            "risk_level": "low",
            "approval": "auto",
        },
        {
            "name": "dev_write",
            "match": {"type": "write"},
            "conditions": {"param_eq": {"role": "developer"}},
            "risk_level": "medium",
            "approval": "auto",
        },
        {
            "name": "dev_delete",
            "match": {"type": "delete"},
            "conditions": {"param_eq": {"role": "developer"}},
            "risk_level": "critical",
            "approval": "approve",
        },
        {
            "name": "dev_deploy",
            "match": {"type": "deploy"},
            "conditions": {"param_eq": {"role": "developer"}},
            "risk_level": "high",
            "approval": "approve",
        },
        # ── Viewer rules (read-only) ────────────────────────
        {
            "name": "viewer_read",
            "match": {"type": "read"},
            "conditions": {"param_eq": {"role": "viewer"}},
            "risk_level": "low",
            "approval": "auto",
        },
        {
            "name": "viewer_write",
            "match": {"type": "write"},
            "conditions": {"param_eq": {"role": "viewer"}},
            "risk_level": "high",
            "approval": "block",
        },
        {
            "name": "viewer_delete",
            "match": {"type": "delete"},
            "conditions": {"param_eq": {"role": "viewer"}},
            "risk_level": "critical",
            "approval": "block",
        },
        {
            "name": "viewer_deploy",
            "match": {"type": "deploy"},
            "conditions": {"param_eq": {"role": "viewer"}},
            "risk_level": "critical",
            "approval": "block",
        },
    ],
}


# ── Executor & approval handler ─────────────────────────────


class NoOpExecutor(BaseExecutor):
    """Executor that always succeeds (actions are simulated)."""

    async def execute(self, action: Action) -> Result:
        return Result(
            action=action,
            status=ResultStatus.SUCCESS,
            data={"simulated": True},
            completed_at=datetime.now(UTC),
        )


class DenyApprovalHandler(ApprovalHandler):
    """Simulates a human reviewer who denies every pending request."""

    async def request_approval(self, decision) -> bool:
        return False


# ── Display helpers ──────────────────────────────────────────


def _color_for_outcome(outcome: str) -> str:
    if outcome in ("SUCCESS", "AUTO"):
        return GREEN
    if outcome in ("PENDING", "APPROVE"):
        return YELLOW
    return RED


def _print_header() -> None:
    print()
    print(f"{BOLD}{'=' * 68}{RESET}")
    print(f"{BOLD}  Enterprise SSO / RBAC Demo{RESET}")
    print(f"{BOLD}{'=' * 68}{RESET}")
    print()
    print(f"  {DIM}Roles:{RESET}")
    print(f"    {CYAN}admin{RESET}     — auto-approve all actions")
    print(f"    {CYAN}developer{RESET} — auto for read/write, needs approval for destructive")
    print(f"    {CYAN}viewer{RESET}    — read-only, everything else blocked")
    print()


def _print_matrix(matrix: dict[str, dict[str, str]]) -> None:
    # Column headers: the action labels
    action_labels = [desc for _, _, desc in ACTIONS]
    col_width = 22

    # Header row
    print(f"  {'User':<18}", end="")
    for label in action_labels:
        short = label[:col_width - 2]
        print(f"{short:<{col_width}}", end="")
    print()
    print(f"  {'─' * 18}", end="")
    for _ in action_labels:
        print(f"{'─' * col_width}", end="")
    print()

    # Data rows
    for user in USERS:
        role_color = CYAN
        print(f"  {role_color}{user.name:<10}{RESET}{DIM}({user.role}){RESET}  ", end="")
        for label in action_labels:
            outcome = matrix[user.name][label]
            color = _color_for_outcome(outcome)
            print(f"{color}{outcome:<{col_width}}{RESET}", end="")
        print()

    print()


# ── Main ─────────────────────────────────────────────────────


async def main() -> None:
    _print_header()

    policy = Policy.from_dict(POLICY_DICT)

    # Phase 1: Policy evaluation (no execution yet)
    print(f"{BOLD}  Phase 1: Policy evaluation{RESET}")
    print(f"  {DIM}Show how the same action resolves differently per role.{RESET}")
    print()

    eval_matrix: dict[str, dict[str, str]] = {}
    for user in USERS:
        eval_matrix[user.name] = {}
        for action_type, target, desc in ACTIONS:
            action = Action(
                action_type, target,
                params={"role": user.role},
                description=desc,
            )
            decision = policy.evaluate(action)
            eval_matrix[user.name][desc] = decision.approval.value.upper()

    _print_matrix(eval_matrix)

    # Phase 2: Runtime execution (approval handler denies pending)
    print(f"{BOLD}  Phase 2: Runtime execution{RESET}")
    print(
        f"  {DIM}Actions marked APPROVE are sent to a reviewer who denies them.{RESET}"
    )
    print()

    runtime = Runtime(
        executor=NoOpExecutor(),
        policy=policy,
        approval_handler=DenyApprovalHandler(),
        audit_logger=AuditLogger(db_path=":memory:"),
    )

    exec_matrix: dict[str, dict[str, str]] = {}
    for user in USERS:
        exec_matrix[user.name] = {}
        for action_type, target, desc in ACTIONS:
            action = Action(
                action_type, target,
                params={"role": user.role},
                description=desc,
            )
            plan = runtime.plan([action])
            results = await runtime.execute(plan)
            result = results[0]
            exec_matrix[user.name][desc] = result.status.value.upper()

    _print_matrix(exec_matrix)

    # Phase 3: Audit summary
    print(f"{BOLD}  Phase 3: Audit trail{RESET}")
    print(f"  {DIM}All decisions are recorded regardless of outcome.{RESET}")
    print()

    entries = runtime.audit.get_log()
    for entry in entries:
        status = entry.get("result_status") or "-"
        color = _color_for_outcome(status.upper() if status != "-" else "")
        print(
            f"  {entry['action_type']:>8} -> {entry['action_target']:<12} "
            f"| rule={entry['matched_rule']:<16} "
            f"| risk={entry['risk_level']:<8} "
            f"| {color}{status}{RESET}"
        )

    print()
    print(f"{BOLD}{'=' * 68}{RESET}")
    print(
        f"  {DIM}Aegis enforces RBAC at the policy layer — no executor changes needed.{RESET}"
    )
    print(f"{BOLD}{'=' * 68}{RESET}")
    print()


if __name__ == "__main__":
    asyncio.run(main())
