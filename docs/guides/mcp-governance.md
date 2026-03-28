---
description: "Add policy enforcement, approval gates, and audit trails to MCP tool calls. Govern Model Context Protocol servers with YAML rules."
---

# Governing MCP Tool Calls

Add policy checks, approval gates, and a full audit trail to every MCP tool call -- in under 5 minutes.

---

**MCP (Model Context Protocol)** gives AI agents standardized access to filesystems, databases, APIs, browsers, email, and more. That power is exactly the problem: without governance, every MCP tool call executes immediately with no policy check, no human approval, and no audit trail.

Aegis sits between the AI agent and the MCP server, enforcing YAML-defined policies on every tool call before it reaches the target system.

```
AI Agent ─── MCP tool call ──→ Aegis ──→ Policy check ──→ MCP Server
                                │
                                ├─ ALLOW → forward to server
                                ├─ APPROVE → pause for human
                                └─ BLOCK → reject immediately
                                │
                                └─ Audit log (every decision)
```

## Why Govern MCP?

MCP servers expose real-world capabilities. Without governance, an AI agent can:

| MCP Server | Ungoverned Risk |
|---|---|
| **Filesystem** | Delete files, overwrite configs, read secrets |
| **Database** | DROP tables, bulk DELETE, exfiltrate data |
| **Email / Slack** | Send messages to anyone, impersonate users |
| **Browser** | Submit forms, make purchases, leak credentials |
| **Git** | Force-push, delete branches, rewrite history |

A single prompt injection or hallucinated tool call can trigger any of these. Aegis makes every MCP tool call go through policy evaluation first.

## Quick Start (5 Minutes)

### 1. Install

```bash
pip install agent-aegis
```

### 2. Define a policy

Create `mcp-policy.yaml`:

```yaml
version: "1"

defaults:
  risk_level: high
  approval: approve         # Default: require human approval

rules:
  # Allow all read operations across MCP servers
  - name: allow_reads
    match:
      type: "read_*"
    risk_level: low
    approval: auto

  # Block destructive filesystem operations
  - name: block_file_deletes
    match:
      type: "delete_file"
      target: "filesystem"
    risk_level: critical
    approval: block

  # Require approval for file writes
  - name: approve_file_writes
    match:
      type: "write_file"
      target: "filesystem"
    risk_level: medium
    approval: approve
```

### 3. Govern MCP tool calls (3 lines of integration)

```python
import asyncio
from aegis import Policy, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.adapters.mcp import govern_mcp_tool_call
from aegis.core.result import Result, ResultStatus


class NoOpExecutor(BaseExecutor):
    """Pass-through executor -- governance only, no execution."""
    async def execute(self, action):
        return Result(action=action, status=ResultStatus.SUCCESS)


async def main():
    runtime = Runtime(
        executor=NoOpExecutor(),
        policy=Policy.from_yaml("mcp-policy.yaml"),
    )

    # Govern an MCP tool call -- this is the integration point
    result = await govern_mcp_tool_call(
        runtime=runtime,
        tool_name="read_file",
        arguments={"path": "/data/report.csv"},
        server_name="filesystem",
    )

    if result.ok:
        print("Allowed -- forward to MCP server")
        # mcp_result = await mcp_client.call_tool("read_file", {"path": "/data/report.csv"})
    else:
        print(f"Blocked: {result.status}")


asyncio.run(main())
```

That is it. Every MCP tool call is now policy-checked and audit-logged.

## Policy Examples for Common MCP Servers

### Filesystem Server

```yaml
version: "1"

defaults:
  risk_level: high
  approval: approve

rules:
  # Auto-allow reading files and listing directories
  - name: allow_reads
    match:
      type: "read_file"
      target: "filesystem"
    risk_level: low
    approval: auto

  - name: allow_list
    match:
      type: "list_directory"
      target: "filesystem"
    risk_level: low
    approval: auto

  # Require approval for writes
  - name: approve_writes
    match:
      type: "write_file"
      target: "filesystem"
    risk_level: medium
    approval: approve

  # Block all deletes
  - name: block_deletes
    match:
      type: "delete_*"
      target: "filesystem"
    risk_level: critical
    approval: block

  # Block moves outside safe directories
  - name: block_moves
    match:
      type: "move_file"
      target: "filesystem"
    risk_level: high
    approval: approve
```

### Database Server

```yaml
version: "1"

defaults:
  risk_level: high
  approval: approve

rules:
  # Auto-allow SELECT queries
  - name: allow_select
    match:
      type: "query"
      target: "database"
    conditions:
      param_matches: { sql: "^SELECT " }
    risk_level: low
    approval: auto

  # Approve INSERT and UPDATE
  - name: approve_mutations
    match:
      type: "query"
      target: "database"
    conditions:
      param_matches: { sql: "^(INSERT|UPDATE) " }
    risk_level: medium
    approval: approve

  # Block DROP, TRUNCATE, DELETE without WHERE
  - name: block_destructive
    match:
      type: "query"
      target: "database"
    conditions:
      param_matches: { sql: "^(DROP|TRUNCATE) " }
    risk_level: critical
    approval: block

  # Block large batch operations
  - name: block_bulk_delete
    match:
      type: "query"
      target: "database"
    conditions:
      param_matches: { sql: "^DELETE " }
    risk_level: critical
    approval: approve  # Require manual review
```

### Email / Slack Server

```yaml
version: "1"

defaults:
  risk_level: medium
  approval: approve

rules:
  # Auto-allow reading messages
  - name: allow_read_messages
    match:
      type: "read_*"
      target: "slack"
    risk_level: low
    approval: auto

  - name: allow_read_email
    match:
      type: "read_*"
      target: "email"
    risk_level: low
    approval: auto

  # Require approval for sending messages
  - name: approve_slack_send
    match:
      type: "send_message"
      target: "slack"
    risk_level: medium
    approval: approve

  - name: approve_email_send
    match:
      type: "send_email"
      target: "email"
    risk_level: high
    approval: approve

  # Block bulk operations
  - name: block_bulk_send
    match:
      type: "bulk_*"
      target: "email"
    risk_level: critical
    approval: block
```

### Browser Server

```yaml
version: "1"

defaults:
  risk_level: medium
  approval: approve

rules:
  # Auto-allow navigation and reading
  - name: allow_navigation
    match:
      type: "navigate"
      target: "browser"
    risk_level: low
    approval: auto

  - name: allow_screenshot
    match:
      type: "screenshot"
      target: "browser"
    risk_level: low
    approval: auto

  - name: allow_read_page
    match:
      type: "read_*"
      target: "browser"
    risk_level: low
    approval: auto

  # Require approval for form interactions
  - name: approve_form_fill
    match:
      type: "fill"
      target: "browser"
    risk_level: medium
    approval: approve

  # Block form submissions (purchases, logins, etc.)
  - name: block_submit
    match:
      type: "click"
      target: "browser"
    risk_level: high
    approval: approve

  # Block JavaScript execution
  - name: block_js_eval
    match:
      type: "evaluate"
      target: "browser"
    risk_level: critical
    approval: block
```

## Using AegisMCPToolFilter

The `AegisMCPToolFilter` class provides a filter-based approach for pre-checking MCP tool calls before forwarding them to the MCP server. This is the recommended pattern when you want to intercept tool calls at the client level.

### Check-Only Mode

Use `check()` for dry-run policy evaluation without going through the full execution pipeline:

```python
from aegis import Policy, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.adapters.mcp import AegisMCPToolFilter
from aegis.core.result import Result, ResultStatus


class PassthroughExecutor(BaseExecutor):
    async def execute(self, action):
        return Result(action=action, status=ResultStatus.SUCCESS)


runtime = Runtime(
    executor=PassthroughExecutor(),
    policy=Policy.from_yaml("mcp-policy.yaml"),
)

tool_filter = AegisMCPToolFilter(runtime=runtime)

# Pre-check before calling the MCP server
result = await tool_filter.check(
    server="filesystem",
    tool="delete_file",
    arguments={"path": "/important/data.db"},
)

if result.ok:
    # Policy allows it -- forward to the actual MCP server
    mcp_result = await mcp_client.call_tool(
        "delete_file", {"path": "/important/data.db"}
    )
else:
    print(f"Policy denied: {result.status}")
    # result.status is BLOCKED or DENIED
```

### Full Governance Pipeline

Use `call_tool()` for the full governance pipeline including approval gates and audit logging:

```python
tool_filter = AegisMCPToolFilter(runtime=runtime)

# Full governance: policy check + approval gate + audit log
result = await tool_filter.call_tool(
    server="database",
    tool="query",
    arguments={"sql": "SELECT * FROM users"},
)

if result.ok:
    # Forward the approved action to MCP
    mcp_result = await mcp_client.call_tool("query", {"sql": "SELECT * FROM users"})
```

### Integration Pattern: MCP Client Wrapper

Here is a complete pattern for wrapping an MCP client with Aegis governance:

```python
from aegis import Policy, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.adapters.mcp import AegisMCPToolFilter
from aegis.core.result import Result, ResultStatus
from aegis.runtime.audit import AuditLogger


class MCPPassthrough(BaseExecutor):
    async def execute(self, action):
        return Result(action=action, status=ResultStatus.SUCCESS)


class GovernedMCPClient:
    """MCP client with Aegis governance built in."""

    def __init__(self, mcp_client, policy_path: str):
        self._mcp = mcp_client
        self._runtime = Runtime(
            executor=MCPPassthrough(),
            policy=Policy.from_yaml(policy_path),
            audit_logger=AuditLogger(db_path="mcp_audit.db"),
        )
        self._filter = AegisMCPToolFilter(runtime=self._runtime)

    async def call_tool(self, server: str, tool: str, arguments: dict = None):
        """Call an MCP tool with governance."""
        # Step 1: Policy check + approval + audit
        result = await self._filter.call_tool(
            server=server,
            tool=tool,
            arguments=arguments,
        )

        # Step 2: Only forward to MCP if governance passes
        if not result.ok:
            return {"error": f"Governance denied: {result.status}", "ok": False}

        # Step 3: Execute via actual MCP client
        mcp_result = await self._mcp.call_tool(tool, arguments or {})
        return {"data": mcp_result, "ok": True}


# Usage
governed = GovernedMCPClient(mcp_client, "mcp-policy.yaml")
result = await governed.call_tool("filesystem", "read_file", {"path": "/data.csv"})
```

## Audit Trail for MCP

Every MCP tool call governed by Aegis is automatically recorded in the audit trail. Each entry captures the full context of the governance decision.

### What Gets Logged

| Field | MCP Mapping | Example |
|---|---|---|
| `action_type` | MCP tool name | `read_file`, `query`, `send_email` |
| `action_target` | MCP server name | `filesystem`, `database`, `slack` |
| `action_params` | Tool arguments (JSON) | `{"path": "/data.csv"}` |
| `risk_level` | From matched policy rule | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `approval` | From matched policy rule | `auto`, `approve`, `block` |
| `matched_rule` | Which policy rule fired | `allow_reads`, `block_deletes` |
| `human_decision` | Approval outcome (if any) | `approved`, `denied`, `null` |
| `result_status` | Final outcome | `success`, `blocked`, `denied` |
| `timestamp` | ISO 8601 UTC | `2026-03-22T10:30:00Z` |

### Viewing the Audit Trail

```bash
# Table view
aegis audit

# JSON output for programmatic use
aegis audit --format json

# Export to JSONL for log aggregators
aegis audit --format jsonl -o mcp_audit.jsonl

# Filter by session
aegis audit --session mcp-session-001
```

### Programmatic Access

```python
from aegis.runtime.audit import AuditLogger

logger = AuditLogger(db_path="mcp_audit.db")

# Query all entries
entries = logger.get_log()
for entry in entries:
    print(f"{entry['timestamp']} | {entry['action_type']}@{entry['action_target']} | {entry['result_status']}")

# Filter by session
session_entries = logger.get_log(session_id="mcp-session-001")

# Export for compliance
count = logger.export_jsonl("compliance_export.jsonl")
print(f"Exported {count} audit entries")
```

### Cloud-Native Logging

For production deployments, use `LoggingAuditLogger` to pipe MCP audit data to your log aggregator (DataDog, CloudWatch, ELK):

```python
import logging
from aegis.runtime.audit_logging import LoggingAuditLogger

logging.basicConfig(level=logging.DEBUG)

runtime = Runtime(
    executor=MCPPassthrough(),
    policy=Policy.from_yaml("mcp-policy.yaml"),
    audit_logger=LoggingAuditLogger(),  # Emits structured JSON to "aegis.audit" logger
)
```

Risk levels map to log levels: LOW=DEBUG, MEDIUM=INFO, HIGH=WARNING, CRITICAL=ERROR.

## Advanced: Per-Server Policies

Real deployments use multiple MCP servers. Aegis supports layered policies so you can define a base policy for all servers and override per server.

### Policy Merge

Use `Policy.merge()` to combine a base policy with server-specific overrides. Base rules are evaluated first (first-match-wins), then the merged rules.

```python
from aegis import Policy

# Base policy: conservative defaults for all MCP servers
base = Policy.from_yaml("policies/mcp-base.yaml")

# Server-specific overrides
fs_policy = Policy.from_yaml("policies/mcp-filesystem.yaml")
db_policy = Policy.from_yaml("policies/mcp-database.yaml")

# Merge: base rules take priority (evaluated first)
filesystem_combined = base.merge(fs_policy)
database_combined = base.merge(db_policy)
```

**`policies/mcp-base.yaml`** -- shared rules across all MCP servers:

```yaml
version: "1"

defaults:
  risk_level: high
  approval: approve

rules:
  # Universal: block anything matching destructive patterns
  - name: block_destructive_everywhere
    match:
      type: "drop_*"
    risk_level: critical
    approval: block

  # Universal: auto-allow list/read operations
  - name: allow_reads_everywhere
    match:
      type: "read_*"
    risk_level: low
    approval: auto

  - name: allow_list_everywhere
    match:
      type: "list_*"
    risk_level: low
    approval: auto
```

**`policies/mcp-filesystem.yaml`** -- filesystem-specific rules:

```yaml
version: "1"

defaults:
  risk_level: medium
  approval: approve

rules:
  - name: fs_approve_writes
    match:
      type: "write_file"
      target: "filesystem"
    risk_level: medium
    approval: approve

  - name: fs_block_deletes
    match:
      type: "delete_*"
      target: "filesystem"
    risk_level: critical
    approval: block
```

### Policy Hierarchy (Org / Team / Agent)

For enterprise deployments, use `PolicyHierarchy` to enforce organizational policies that individual teams or agents cannot override:

```python
from aegis.core.hierarchy import PolicyHierarchy

hierarchy = PolicyHierarchy(
    org=Policy.from_yaml("policies/org-mcp.yaml"),      # Cannot be overridden
    team=Policy.from_yaml("policies/team-mcp.yaml"),     # Can tighten, not loosen
    agent=Policy.from_yaml("policies/agent-mcp.yaml"),   # Most specific
)

# Evaluate: most restrictive decision wins
decision, conflicts = hierarchy.evaluate(action)

# Or flatten into a single policy for use with Runtime
combined_policy = hierarchy.flatten()
runtime = Runtime(executor=executor, policy=combined_policy)
```

If the org policy blocks `DROP` operations, no team or agent policy can override that -- the most restrictive decision always wins.

### Hot-Reload for MCP Policies

Update MCP policies without restarting your application using `PolicyWatcher`:

```python
from aegis.runtime.watcher import PolicyWatcher

runtime = Runtime(
    executor=MCPPassthrough(),
    policy=Policy.from_yaml("mcp-policy.yaml"),
)

# Watch for policy file changes and reload automatically
async with PolicyWatcher(runtime, "mcp-policy.yaml", interval=2.0):
    # Policy changes are picked up automatically
    # No restart needed -- edit mcp-policy.yaml and it takes effect
    while True:
        result = await govern_mcp_tool_call(
            runtime=runtime,
            tool_name=incoming_tool,
            arguments=incoming_args,
            server_name=incoming_server,
        )
        # ... handle result ...
```

You can also use `PolicyWatcher` with a callback to log reloads or notify external systems:

```python
async def on_policy_reload(new_policy):
    print(f"MCP policy reloaded: {len(new_policy.rules)} rules active")

watcher = PolicyWatcher(
    runtime,
    "mcp-policy.yaml",
    interval=1.0,
    on_reload=on_policy_reload,
)
await watcher.start()
```

Call `runtime.update_policy(new_policy)` directly if you load policies from a source other than local files (API, database, config service).

## How Aegis Maps MCP Concepts

Understanding the mapping between MCP and Aegis helps you write precise policies:

| MCP Concept | Aegis Concept | Policy Field |
|---|---|---|
| Tool name (`read_file`, `query`) | `Action.type` | `match.type` |
| Server name (`filesystem`, `database`) | `Action.target` | `match.target` |
| Tool arguments (`{"path": "..."}`) | `Action.params` | `conditions.param_*` |
| Tool result | `Result.data` | Stored in audit trail |

This mapping means you can write policies that match on any combination of tool name, server name, and argument values.

## Next Steps

- [Writing Policies](policies.md) -- full policy syntax, conditions, and glob patterns
- [Approval Handlers](approval-handlers.md) -- custom approval flows (Slack, webhooks, UI)
- [Security Model](security-model.md) -- defense-in-depth with Aegis + containers
- [API Reference: Adapters](../api/adapters.md) -- complete MCP adapter API
- [API Reference: Audit](../api/audit.md) -- audit logger and export formats
