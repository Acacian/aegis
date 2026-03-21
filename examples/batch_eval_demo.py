"""
Batch evaluation demo — evaluate many actions at once and measure performance.

Usage:
    python examples/batch_eval_demo.py

Demonstrates:
- Evaluating 10+ diverse actions in a single plan() call
- Batch audit logging with BatchAuditLogger
- Policy evaluation caching for repeated action patterns
- Timing / performance measurement
- Filtering results by approval status
- ANSI-colored summary table
"""

from __future__ import annotations

import asyncio
import tempfile
import time
from pathlib import Path

from aegis import Action, Approval, BatchAuditLogger, Policy, RiskLevel, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.core.result import Result, ResultStatus

# -- ANSI color helpers -------------------------------------------------------

GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

STATUS_COLORS = {
    "auto": GREEN,
    "approve": YELLOW,
    "block": RED,
}

RISK_COLORS = {
    RiskLevel.LOW: GREEN,
    RiskLevel.MEDIUM: YELLOW,
    RiskLevel.HIGH: RED,
    RiskLevel.CRITICAL: f"{RED}{BOLD}",
}

# -- Policy -------------------------------------------------------------------

POLICY_YAML = """\
version: "1"
defaults:
  risk_level: medium
  approval: approve

rules:
  # Safe read operations — auto-approved
  - name: read_ops
    match: { type: "read" }
    risk_level: low
    approval: auto

  - name: list_ops
    match: { type: "list" }
    risk_level: low
    approval: auto

  - name: search_ops
    match: { type: "search" }
    risk_level: low
    approval: auto

  # Write operations — require approval
  - name: write_ops
    match: { type: "write" }
    risk_level: medium
    approval: approve

  - name: update_ops
    match: { type: "update" }
    risk_level: medium
    approval: approve

  # Dangerous operations — blocked
  - name: delete_ops
    match: { type: "delete" }
    risk_level: critical
    approval: block

  - name: drop_ops
    match: { type: "drop_table" }
    risk_level: critical
    approval: block

  # Bulk operations — high risk, require approval
  - name: bulk_ops
    match: { type: "bulk_*" }
    risk_level: high
    approval: approve

  # Export — high risk, require approval
  - name: export_ops
    match: { type: "export" }
    risk_level: high
    approval: approve
"""

# -- Actions ------------------------------------------------------------------

ACTIONS = [
    # Auto-approved (low risk reads)
    Action("read", "users", description="Fetch user profile"),
    Action("read", "orders", description="Lookup order details"),
    Action("list", "products", description="List product catalog"),
    Action("search", "inventory", description="Search stock levels"),
    # Require approval (medium/high risk writes)
    Action("write", "orders", description="Create new order"),
    Action("update", "users", params={"field": "email"}, description="Update email"),
    Action("export", "analytics", description="Export monthly report"),
    Action("bulk_update", "pricing", description="Bulk price adjustment"),
    # Blocked (critical / destructive)
    Action("delete", "users", description="Delete user account"),
    Action("drop_table", "logs", description="Drop audit log table"),
    Action("delete", "orders", description="Purge order history"),
    # Additional auto-approved to demonstrate caching benefit
    Action("read", "users", description="Fetch user profile (cached)"),
    Action("read", "orders", description="Lookup order details (cached)"),
]

# -- Executor -----------------------------------------------------------------


class NoOpExecutor(BaseExecutor):
    """Executor that immediately succeeds (evaluation-only demo)."""

    async def execute(self, action: Action) -> Result:
        return Result(action=action, status=ResultStatus.SUCCESS)


# -- Display helpers ----------------------------------------------------------


def colored(text: str, color: str) -> str:
    return f"{color}{text}{RESET}"


def print_header(title: str) -> None:
    width = 68
    print(f"\n{BOLD}{'=' * width}")
    print(f"  {title}")
    print(f"{'=' * width}{RESET}")


def print_summary_table(decisions: list[tuple[Action, str, str, str]]) -> None:
    """Print a formatted table of evaluation results."""
    hdr_fmt = f"  {BOLD}{'#':<4}{'Action':<22}{'Target':<14}{'Risk':<12}{'Approval':<10}{RESET}"
    print(hdr_fmt)
    print(f"  {DIM}{'-' * 62}{RESET}")

    for i, (action, risk_name, approval_val, _rule) in enumerate(decisions, 1):
        risk_color = RISK_COLORS.get(RiskLevel[risk_name.upper()], RESET)
        appr_color = STATUS_COLORS.get(approval_val, RESET)

        row = (
            f"  {i:<4}"
            f"{action.type:<22}"
            f"{action.target:<14}"
            f"{colored(risk_name, risk_color):<23}"
            f"{colored(approval_val, appr_color)}"
        )
        print(row)


# -- Main ---------------------------------------------------------------------


async def main() -> None:
    print_header("Aegis Batch Evaluation Demo")
    print(f"  {DIM}Evaluate {len(ACTIONS)} actions at once, measure performance{RESET}")

    # Load policy from temp file
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as f:
        f.write(POLICY_YAML)
        policy_path = f.name

    policy = Policy.from_yaml(policy_path).with_cache(maxsize=128)
    audit = BatchAuditLogger(db_path=":memory:", batch_size=20)

    # -- 1. Batch evaluate with timing ----------------------------------------

    print(f"\n  {BOLD}[1] Batch Policy Evaluation{RESET}")
    print(f"  {DIM}Evaluating {len(ACTIONS)} actions via runtime.plan()...{RESET}\n")

    async with Runtime(
        executor=NoOpExecutor(),
        policy=policy,
        audit_logger=audit,
    ) as runtime:
        t0 = time.perf_counter()
        plan = runtime.plan(ACTIONS)
        t_eval = time.perf_counter() - t0

        # Collect decision info for display
        rows: list[tuple[Action, str, str, str]] = []
        for decision in plan.decisions:
            rows.append((
                decision.action,
                decision.risk_level.name.lower(),
                decision.approval.value,
                decision.matched_rule,
            ))

        print_summary_table(rows)

        # -- 2. Timing report -------------------------------------------------

        print(f"\n  {BOLD}[2] Performance{RESET}")
        us_total = t_eval * 1_000_000
        us_per = us_total / len(ACTIONS) if ACTIONS else 0
        print(f"  Actions evaluated : {len(ACTIONS)}")
        print(f"  Total time        : {colored(f'{us_total:,.0f} us', CYAN)}")
        print(f"  Per action        : {colored(f'{us_per:,.1f} us', CYAN)}")
        print(f"  Cache enabled     : {colored('yes (128 slots)', GREEN)}")

        # -- 3. Filter by approval status -------------------------------------

        print(f"\n  {BOLD}[3] Filter by Approval Status{RESET}")

        auto = [d for d in plan.decisions if d.approval == Approval.AUTO]
        approve = [d for d in plan.decisions if d.approval == Approval.APPROVE]
        blocked = [d for d in plan.decisions if d.approval == Approval.BLOCK]

        print(
            f"  {colored('AUTO', GREEN)}    : {len(auto):>2} actions  "
            f"(safe, no human needed)"
        )
        print(
            f"  {colored('APPROVE', YELLOW)} : {len(approve):>2} actions  "
            f"(human-in-the-loop required)"
        )
        print(
            f"  {colored('BLOCK', RED)}   : {len(blocked):>2} actions  "
            f"(denied by policy)"
        )

        # Show each group
        for label, color, group in [
            ("Auto-approved", GREEN, auto),
            ("Needs approval", YELLOW, approve),
            ("Blocked", RED, blocked),
        ]:
            if group:
                names = ", ".join(
                    f"{d.action.type}:{d.action.target}" for d in group
                )
                print(f"    {colored(label, color)}: {DIM}{names}{RESET}")

        # -- 4. Dry-run execution (batch) -------------------------------------

        print(f"\n  {BOLD}[4] Dry-Run Execution{RESET}")
        print(f"  {DIM}Execute the plan in dry-run mode (no side effects)...{RESET}\n")

        t0 = time.perf_counter()
        results = await runtime.execute(plan, dry_run=True)
        t_exec = time.perf_counter() - t0

        success = sum(1 for r in results if r.status == ResultStatus.SUCCESS)
        blocked_r = sum(1 for r in results if r.status == ResultStatus.BLOCKED)

        print("  Dry-run results:")
        print(f"    {colored('SUCCESS', GREEN)} : {success}")
        print(f"    {colored('BLOCKED', RED)} : {blocked_r}")
        print(
            f"  Dry-run time      : "
            f"{colored(f'{t_exec * 1_000_000:,.0f} us', CYAN)}"
        )

        # -- 5. Batch audit summary -------------------------------------------

        print(f"\n  {BOLD}[5] Batch Audit Logger{RESET}")
        pending = audit.pending
        flushed = audit.flush()
        print(f"  Buffered entries  : {pending}")
        print(f"  Flushed to DB     : {flushed}")
        print(
            f"  {DIM}BatchAuditLogger reduces SQLite write overhead "
            f"by batching inserts.{RESET}"
        )

    # Clean up
    Path(policy_path).unlink(missing_ok=True)

    print(f"\n{BOLD}{'=' * 68}{RESET}")
    print(f"  {DIM}Tip: Enable policy caching with policy.with_cache() for repeated")
    print("  action patterns. Combine with BatchAuditLogger for high-throughput")
    print(f"  scenarios.{RESET}")
    print()


if __name__ == "__main__":
    asyncio.run(main())
