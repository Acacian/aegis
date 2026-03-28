---
description: "Govern MCP tool calls with per-server, per-tool policies. Add approval gates and audit trails to Model Context Protocol in 5 minutes."
---

# Govern MCP Tool Calls in 5 Minutes

The Model Context Protocol (MCP) lets AI models call tools across servers. Aegis adds policy enforcement to every MCP tool call — per-server, per-tool granularity.

**What you will build:** MCP governance where file reads are auto-approved, file writes need review, and file deletion is blocked — with per-server audit trails.

**Time:** 5 minutes.

---

## Prerequisites

```bash
pip install agent-aegis  # MCP adapter is included in core
```

---

## Step 1: Write Your Policy

```yaml
# policy.yaml
version: "1"
defaults:
  risk_level: medium
  approval: approve

rules:
  - name: mcp_read
    match: { type: "read_file" }
    risk_level: low
    approval: auto

  - name: mcp_list
    match: { type: "list_*" }
    risk_level: low
    approval: auto

  - name: mcp_write
    match: { type: "write_file" }
    risk_level: medium
    approval: approve

  - name: mcp_delete
    match: { type: "delete_file" }
    risk_level: critical
    approval: block

  # Per-server rules: stricter for production filesystem
  - name: prod_fs_block
    match: { type: "*", target: "prod-filesystem" }
    risk_level: critical
    approval: block
```

## Step 2: Govern MCP Tool Calls

```python
from aegis import Policy, Runtime
from aegis.adapters.mcp import govern_mcp_tool_call, AegisMCPToolFilter
from aegis.adapters.base import BaseExecutor
from aegis.core.result import Result, ResultStatus
from aegis.core.action import Action


class MCPToolExecutor(BaseExecutor):
    async def execute(self, action: Action) -> Result:
        print(f"  MCP: {action.type} on {action.target}")
        return Result(action=action, status=ResultStatus.SUCCESS)


async def main():
    policy = Policy.from_yaml("policy.yaml")
    async with Runtime(
        executor=MCPToolExecutor(), policy=policy
    ) as runtime:
        # Option 1: Govern individual tool calls
        result = await govern_mcp_tool_call(
            runtime=runtime,
            tool_name="read_file",
            arguments={"path": "/data/report.csv"},
            server_name="dev-filesystem",
        )
        print(f"  read_file: {'ALLOWED' if result.ok else 'BLOCKED'}")

        result = await govern_mcp_tool_call(
            runtime=runtime,
            tool_name="delete_file",
            arguments={"path": "/data/report.csv"},
            server_name="dev-filesystem",
        )
        print(f"  delete_file: {'ALLOWED' if result.ok else 'BLOCKED'}")

        # Option 2: Filter-based (pre-check before actual MCP call)
        tool_filter = AegisMCPToolFilter(runtime=runtime)
        check = await tool_filter.check(
            server="prod-filesystem", tool="write_file"
        )
        print(f"  prod write_file: {'ALLOWED' if check.ok else 'BLOCKED'}")


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
```

## What Happens

| Tool Call | Server | Result | Reason |
|-----------|--------|--------|--------|
| `read_file` | dev-filesystem | AUTO-APPROVED | Low risk, matches `mcp_read` |
| `delete_file` | dev-filesystem | BLOCKED | Critical risk, matches `mcp_delete` |
| `write_file` | prod-filesystem | BLOCKED | All prod-filesystem ops blocked |

## Per-Server Policies

MCP typically involves multiple servers (filesystem, database, API). You can create per-server rules:

```yaml
rules:
  # Dev server: permissive
  - name: dev_auto
    match: { target: "dev-*" }
    risk_level: low
    approval: auto

  # Staging: moderate
  - name: staging_approve
    match: { target: "staging-*" }
    risk_level: medium
    approval: approve

  # Production: locked down
  - name: prod_block
    match: { target: "prod-*" }
    risk_level: critical
    approval: block
```

## Next Steps

- [MCP Governance Guide](../guides/mcp-governance.md) — detailed MCP integration patterns
- [Writing Policies](../guides/policies.md) — full YAML policy syntax
- [Try the Playground](../playground/) — experiment in your browser
