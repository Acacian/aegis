"""
Multi-executor governance demo.

Usage:
    python examples/multi_executor_demo.py

Demonstrates:
- Multiple domain executors (CRM, Code, Browser) under one policy
- A single YAML policy that governs all domains with domain-specific rules
- Centralized audit trail across all executors
- Unified governance regardless of execution backend
"""

from __future__ import annotations

import asyncio
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from aegis import Action, Policy, Result, ResultStatus, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.runtime.approval import AutoApprovalHandler
from aegis.runtime.audit import AuditLogger

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
BLUE = "\033[34m"

STATUS_COLOUR = {
    ResultStatus.SUCCESS: GREEN,
    ResultStatus.BLOCKED: RED,
    ResultStatus.DENIED: YELLOW,
    ResultStatus.FAILED: RED,
    ResultStatus.SKIPPED: DIM,
}

# ---------------------------------------------------------------------------
# Unified policy for all domains
# ---------------------------------------------------------------------------
POLICY_YAML = """\
version: "1"
defaults:
  risk_level: medium
  approval: approve

rules:
  # --- CRM domain ---
  - name: crm_read
    match: { type: "read", target: "crm" }
    risk_level: low
    approval: auto
  - name: crm_update
    match: { type: "update", target: "crm" }
    risk_level: medium
    approval: auto
  - name: crm_bulk_delete
    match: { type: "bulk_delete", target: "crm" }
    risk_level: critical
    approval: block

  # --- Code domain ---
  - name: code_lint
    match: { type: "lint", target: "code" }
    risk_level: low
    approval: auto
  - name: code_generate
    match: { type: "generate", target: "code" }
    risk_level: medium
    approval: auto
  - name: code_deploy
    match: { type: "deploy", target: "code" }
    risk_level: high
    approval: approve

  # --- Browser domain ---
  - name: browser_navigate
    match: { type: "navigate", target: "browser" }
    risk_level: low
    approval: auto
  - name: browser_fill_form
    match: { type: "fill_form", target: "browser" }
    risk_level: medium
    approval: auto
  - name: browser_submit_payment
    match: { type: "submit_payment", target: "browser" }
    risk_level: critical
    approval: block
"""


# ---------------------------------------------------------------------------
# Domain executors
# ---------------------------------------------------------------------------
class CRMExecutor(BaseExecutor):
    """Simulates CRM operations (Salesforce, HubSpot, etc.)."""

    async def execute(self, action: Action) -> Result:
        detail = action.params.get("detail", "")
        print(
            f"    {CYAN}[CRM]{RESET}  {action.type} "
            f"{DIM}{detail}{RESET}"
        )
        return Result(
            action=action,
            status=ResultStatus.SUCCESS,
            data={"executor": "crm", "records_affected": 42},
            completed_at=datetime.now(UTC),
        )


class CodeExecutor(BaseExecutor):
    """Simulates code-related operations (lint, generate, deploy)."""

    async def execute(self, action: Action) -> Result:
        detail = action.params.get("detail", "")
        print(
            f"    {MAGENTA}[CODE]{RESET} {action.type} "
            f"{DIM}{detail}{RESET}"
        )
        return Result(
            action=action,
            status=ResultStatus.SUCCESS,
            data={"executor": "code", "files_processed": 17},
            completed_at=datetime.now(UTC),
        )


class BrowserExecutor(BaseExecutor):
    """Simulates browser automation (Playwright, Selenium, etc.)."""

    async def execute(self, action: Action) -> Result:
        detail = action.params.get("detail", "")
        print(
            f"    {BLUE}[BROWSER]{RESET} {action.type} "
            f"{DIM}{detail}{RESET}"
        )
        return Result(
            action=action,
            status=ResultStatus.SUCCESS,
            data={"executor": "browser", "page_loaded": True},
            completed_at=datetime.now(UTC),
        )


# ---------------------------------------------------------------------------
# Dispatcher: routes actions to the correct executor
# ---------------------------------------------------------------------------
class MultiDomainExecutor(BaseExecutor):
    """Routes actions to domain-specific executors based on target."""

    def __init__(self) -> None:
        self._executors: dict[str, BaseExecutor] = {
            "crm": CRMExecutor(),
            "code": CodeExecutor(),
            "browser": BrowserExecutor(),
        }

    async def setup(self) -> None:
        for executor in self._executors.values():
            await executor.setup()

    async def teardown(self) -> None:
        for executor in self._executors.values():
            await executor.teardown()

    async def execute(self, action: Action) -> Result:
        executor = self._executors.get(action.target)
        if executor is None:
            return Result(
                action=action,
                status=ResultStatus.FAILED,
                error=f"No executor registered for target: {action.target}",
                completed_at=datetime.now(UTC),
            )
        return await executor.execute(action)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _status_label(status: ResultStatus) -> str:
    colour = STATUS_COLOUR.get(status, RESET)
    return f"{colour}{status.value.upper()}{RESET}"


def _print_header(title: str) -> None:
    width = 62
    print(f"\n{BOLD}{'=' * width}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'=' * width}{RESET}")


def _print_section(title: str) -> None:
    print(f"\n  {BOLD}{title}{RESET}")
    print(f"  {'-' * 56}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
async def main() -> None:
    _print_header("Multi-Executor Governance Demo")
    print(
        f"  {DIM}One policy, three domains: CRM + Code + Browser{RESET}"
    )

    # Write policy to temp file and load
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as f:
        f.write(POLICY_YAML)
        policy_path = f.name

    policy = Policy.from_yaml(policy_path)
    audit = AuditLogger(db_path=":memory:")

    # Define actions from each domain
    actions = [
        # CRM actions
        Action(
            "read", "crm",
            params={"detail": "list active contacts"},
            description="Read CRM contacts",
        ),
        Action(
            "update", "crm",
            params={"detail": "set status=active for lead #42"},
            description="Update CRM lead",
        ),
        Action(
            "bulk_delete", "crm",
            params={"detail": "purge 10k inactive records"},
            description="Bulk-delete inactive CRM records",
        ),
        # Code actions
        Action(
            "lint", "code",
            params={"detail": "ruff check src/"},
            description="Lint source code",
        ),
        Action(
            "generate", "code",
            params={"detail": "scaffold REST endpoint"},
            description="Generate boilerplate code",
        ),
        Action(
            "deploy", "code",
            params={"detail": "push to production"},
            description="Deploy to production",
        ),
        # Browser actions
        Action(
            "navigate", "browser",
            params={"detail": "https://dashboard.example.com"},
            description="Navigate to dashboard",
        ),
        Action(
            "fill_form", "browser",
            params={"detail": "expense report form"},
            description="Fill expense report",
        ),
        Action(
            "submit_payment", "browser",
            params={"detail": "$5,000 wire transfer"},
            description="Submit wire payment",
        ),
    ]

    # Run all actions through a single Runtime
    async with Runtime(
        executor=MultiDomainExecutor(),
        policy=policy,
        approval_handler=AutoApprovalHandler(),
        audit_logger=audit,
    ) as runtime:
        _print_section("Executing Actions")

        results: list[Result] = []
        for action in actions:
            result = await runtime.run_one(action)
            results.append(result)
            print(f"      -> {_status_label(result.status)}")
            if result.error:
                print(f"         {DIM}{result.error}{RESET}")

        # --- Summary table ---
        _print_section("Results Summary")
        print(
            f"  {'Domain':<10} {'Action':<16} {'Risk':<10} "
            f"{'Rule':<22} {'Status'}"
        )
        print(f"  {'------':<10} {'------':<16} {'----':<10} "
              f"{'----':<22} {'------'}")

        for action, result in zip(actions, results, strict=True):
            decision = policy.evaluate(action)
            colour = STATUS_COLOUR.get(result.status, RESET)
            print(
                f"  {action.target:<10} {action.type:<16} "
                f"{decision.risk_level.name:<10} "
                f"{decision.matched_rule:<22} "
                f"{colour}{result.status.value:<8}{RESET}"
            )

        # --- Unified audit trail ---
        _print_section("Unified Audit Trail")

        entries = audit.get_log(session_id=runtime.session_id)
        for entry in entries:
            ts = str(entry.get("timestamp", ""))[:19]
            a_type = entry.get("action_type", "")
            a_target = entry.get("action_target", "")
            risk = entry.get("risk_level", "")
            status = entry.get("result_status", "")
            rule = entry.get("matched_rule", "")
            print(
                f"  {DIM}{ts}{RESET}  "
                f"{a_target:<10} {a_type:<16} "
                f"risk={risk:<8} rule={rule:<22} "
                f"status={status}"
            )

        # --- Stats ---
        _print_section("Governance Stats")
        total = len(results)
        allowed = sum(1 for r in results if r.ok)
        blocked = sum(
            1 for r in results if r.status == ResultStatus.BLOCKED
        )
        print(f"  Total actions : {total}")
        print(f"  Allowed       : {GREEN}{allowed}{RESET}")
        print(f"  Blocked       : {RED}{blocked}{RESET}")
        print(
            f"\n  {DIM}All {total} actions governed by a single "
            f"policy across 3 executor domains.{RESET}"
        )

    # Clean up
    Path(policy_path).unlink(missing_ok=True)


if __name__ == "__main__":
    asyncio.run(main())
