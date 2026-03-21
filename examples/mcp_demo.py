"""Demo: Governing MCP (Model Context Protocol) tool calls with Aegis.

Shows how to wrap MCP server tool invocations with Aegis policy,
approval gates, and audit logging. Demonstrates:

1. govern_mcp_tool_call() for individual tool governance
2. AegisMCPToolFilter for check-only (dry-run) and full governance
3. Per-server policy rules (filesystem vs database)
4. Blocked, auto-approved, and approval-required outcomes
5. Audit trail query at the end

No external MCP server needed — tool calls are governed but not
actually dispatched, which is the typical integration pattern:
Aegis decides, your MCP client executes.

Run:
    python examples/mcp_demo.py
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from aegis import Action, Policy, Result, ResultStatus, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.adapters.mcp import AegisMCPToolFilter, govern_mcp_tool_call
from aegis.runtime.approval import AutoApprovalHandler
from aegis.runtime.audit import AuditLogger


# ---------------------------------------------------------------------------
# Mock executor — Aegis governs the decision; actual MCP dispatch is yours
# ---------------------------------------------------------------------------

class MCPMockExecutor(BaseExecutor):
    """Simulates executing an MCP tool call after Aegis approves it."""

    async def execute(self, action: Action) -> Result:
        print(f"    [mcp-mock] Dispatching {action.type} to server '{action.target}'")
        return Result(
            action=action,
            status=ResultStatus.SUCCESS,
            data={"server": action.target, "tool": action.type, "mock": True},
            completed_at=datetime.now(UTC),
        )


# ---------------------------------------------------------------------------
# Policy: different rules for different MCP servers
# ---------------------------------------------------------------------------

POLICY = {
    "version": "1",
    "defaults": {"risk_level": "medium", "approval": "approve"},
    "rules": [
        # --- Filesystem server ---
        {
            "name": "fs_read_auto",
            "match": {"type": "read_file", "target": "filesystem"},
            "risk_level": "low",
            "approval": "auto",
        },
        {
            "name": "fs_list_auto",
            "match": {"type": "list_directory", "target": "filesystem"},
            "risk_level": "low",
            "approval": "auto",
        },
        {
            "name": "fs_write_approve",
            "match": {"type": "write_file", "target": "filesystem"},
            "risk_level": "medium",
            "approval": "approve",
        },
        {
            "name": "fs_delete_block",
            "match": {"type": "delete_file", "target": "filesystem"},
            "risk_level": "critical",
            "approval": "block",
        },
        # --- Database server ---
        {
            "name": "db_query_auto",
            "match": {"type": "query", "target": "database"},
            "risk_level": "low",
            "approval": "auto",
        },
        {
            "name": "db_insert_approve",
            "match": {"type": "insert", "target": "database"},
            "risk_level": "medium",
            "approval": "approve",
        },
        {
            "name": "db_drop_block",
            "match": {"type": "drop_table", "target": "database"},
            "risk_level": "critical",
            "approval": "block",
        },
    ],
}


# ---------------------------------------------------------------------------
# Demo 1: govern_mcp_tool_call() — govern individual calls
# ---------------------------------------------------------------------------

async def demo_govern_tool_call(runtime: Runtime) -> None:
    """Use govern_mcp_tool_call() to govern one tool at a time."""
    print("=" * 60)
    print("  DEMO 1: govern_mcp_tool_call()")
    print("=" * 60)
    print()

    tool_calls = [
        ("filesystem", "read_file", {"path": "/data/report.csv"}),
        ("filesystem", "write_file", {"path": "/data/output.txt", "content": "hello"}),
        ("filesystem", "delete_file", {"path": "/etc/passwd"}),
        ("database", "query", {"sql": "SELECT * FROM users LIMIT 10"}),
        ("database", "drop_table", {"table": "users"}),
    ]

    for server, tool, args in tool_calls:
        result = await govern_mcp_tool_call(
            runtime=runtime,
            tool_name=tool,
            arguments=args,
            server_name=server,
        )
        status_label = result.status.value.upper()
        print(f"  {tool:>16} @ {server:<12}  ->  [{status_label}]")
        if result.error:
            print(f"                   Reason: {result.error}")

    print()


# ---------------------------------------------------------------------------
# Demo 2: AegisMCPToolFilter — check-only vs full governance
# ---------------------------------------------------------------------------

async def demo_tool_filter(runtime: Runtime) -> None:
    """Use AegisMCPToolFilter for dry-run checks and governed calls."""
    print("=" * 60)
    print("  DEMO 2: AegisMCPToolFilter")
    print("=" * 60)
    print()

    tool_filter = AegisMCPToolFilter(runtime=runtime)

    # --- Check-only mode (dry-run) ---
    print("  [check-only / dry-run]")
    checks = [
        ("filesystem", "read_file", {"path": "/data/config.yaml"}),
        ("filesystem", "delete_file", {"path": "/data/secrets.env"}),
        ("database", "insert", {"table": "logs", "data": {"msg": "test"}}),
    ]

    for server, tool, args in checks:
        result = await tool_filter.check(server=server, tool=tool, arguments=args)
        allowed = "ALLOWED" if result.ok else "DENIED"
        print(f"    {tool:>16} @ {server:<12}  ->  {allowed}")
        if result.data and result.data.get("approval_required"):
            print(f"                     (would require human approval)")

    print()

    # --- Full governance via call_tool() ---
    print("  [full governance via call_tool()]")
    calls = [
        ("filesystem", "list_directory", {"path": "/data"}),
        ("database", "query", {"sql": "SELECT count(*) FROM orders"}),
        ("database", "drop_table", {"table": "orders"}),
    ]

    for server, tool, args in calls:
        result = await tool_filter.call_tool(server=server, tool=tool, arguments=args)
        status_label = result.status.value.upper()
        print(f"    {tool:>16} @ {server:<12}  ->  [{status_label}]")

    print()


# ---------------------------------------------------------------------------
# Demo 3: Audit trail
# ---------------------------------------------------------------------------

def show_audit_trail(runtime: Runtime) -> None:
    """Query and display the audit log."""
    print("=" * 60)
    print("  AUDIT TRAIL")
    print("=" * 60)

    entries = runtime.audit.get_log(session_id=runtime.session_id)
    if not entries:
        print("  (no entries)")
        return

    for entry in entries:
        print(
            f"  {entry['action_type']:>16} @ {entry['action_target']:<12} | "
            f"risk={entry['risk_level']:<8} | "
            f"rule={entry.get('matched_rule') or '-':<20} | "
            f"result={entry.get('result_status') or '-'}"
        )

    print()

    # Summary counts
    total = len(entries)
    blocked = sum(1 for e in entries if e.get("result_status") == "blocked")
    succeeded = sum(1 for e in entries if e.get("result_status") == "success")
    print(f"  Summary: {total} actions logged, {succeeded} succeeded, {blocked} blocked")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main() -> None:
    runtime = Runtime(
        executor=MCPMockExecutor(),
        policy=Policy.from_dict(POLICY),
        approval_handler=AutoApprovalHandler(),
        audit_logger=AuditLogger(db_path=":memory:"),
    )

    await demo_govern_tool_call(runtime)
    await demo_tool_filter(runtime)
    show_audit_trail(runtime)


if __name__ == "__main__":
    asyncio.run(main())
