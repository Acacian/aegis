---
description: "Add policy governance to OpenAI Agents SDK in 5 minutes. Control function tool calls, enforce approvals, and audit every action."
---

# Add Governance to OpenAI Agents in 5 Minutes

The OpenAI Agents SDK lets you build agents that call function tools
autonomously. That is powerful -- and dangerous. A single hallucinated
function call can delete production data, send an email to the wrong person,
or charge a credit card twice.

**Aegis** adds a policy layer between your agent's decisions and the actual
tool calls. You define rules in YAML; Aegis enforces them at runtime. Every
action is evaluated, gated, and logged -- with zero changes to your existing
function tools.

**What you will build:** An OpenAI agent where search tools run freely,
write operations require approval, delete operations are hard-blocked, and
everything is recorded in an audit trail.

**Time:** 5 minutes.

---

## Prerequisites

```bash
pip install 'agent-aegis[openai-agents]' openai-agents
```

> Aegis works with any OpenAI Agents SDK setup. The `@governed_tool`
> decorator wraps your existing function tools transparently.

---

## Step 1: Define Your Policy

Create `policy.yaml` in your project root:

```yaml
version: "1"

defaults:
  risk_level: medium
  approval: approve        # Anything without an explicit rule needs human approval

rules:
  # --- Safe: auto-approve ---
  - name: search_tools
    match:
      type: "search*"
      target: "web"
    risk_level: low
    approval: auto

  - name: retrieval_tools
    match:
      type: "retriev*"
      target: "*"
    risk_level: low
    approval: auto

  # --- Needs approval: write operations ---
  - name: write_ops
    match:
      type: "write_*"
      target: "*"
    risk_level: high
    approval: approve

  # --- Hard block: no writes after hours (6 PM - 8 AM UTC) ---
  - name: after_hours_write_block
    match:
      type: "write_*"
      target: "*"
    conditions:
      time_after: "18:00"
    risk_level: critical
    approval: block

  - name: early_morning_write_block
    match:
      type: "write_*"
      target: "*"
    conditions:
      time_before: "08:00"
    risk_level: critical
    approval: block

  # --- Hard block: deletes never run ---
  - name: block_deletes
    match:
      type: "delete_*"
      target: "*"
    risk_level: critical
    approval: block
```

**How rules work:**

- Rules are evaluated top to bottom. The **first match wins**.
- `match.type` maps to the `action_type` you pass to `@governed_tool`. Glob patterns (`*`, `?`) are supported.
- `match.target` is the system being acted on (e.g., `"web"`, `"database"`, `"crm"`).
- `conditions` add time-based and parameter-based guards.
- `approval: auto` means execute immediately. `approve` means ask a human. `block` means reject unconditionally.

---

## Step 2: Wrap Function Tools with `@governed_tool`

The `@governed_tool` decorator wraps any function tool with Aegis governance.
The function's parameters are automatically captured and passed to the policy
engine for evaluation.

```python
from agents import Agent, Runner
from aegis import Action, Policy, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.adapters.openai_agents import governed_tool
from aegis.runtime.approval import AutoApprovalHandler

# A simple executor (replace with your real logic)
class MyExecutor(BaseExecutor):
    async def execute(self, action):
        from aegis import Result, ResultStatus
        return Result(action=action, status=ResultStatus.SUCCESS, data={"ok": True})

# 1. Build the governed runtime
runtime = Runtime(
    executor=MyExecutor(),
    policy=Policy.from_yaml("policy.yaml"),
    approval_handler=AutoApprovalHandler(),
)

# 2. Decorate your function tools
@governed_tool(runtime=runtime, action_type="search", action_target="web")
async def web_search(query: str) -> str:
    """Search the web for information."""
    return f"Results for: {query}"

@governed_tool(runtime=runtime, action_type="write_record", action_target="database")
async def write_record(table: str, data: str) -> str:
    """Write a record to the database."""
    return f"Written to {table}: {data}"

@governed_tool(runtime=runtime, action_type="delete_record", action_target="database")
async def delete_record(record_id: str) -> str:
    """Delete a record from the database."""
    return f"Deleted record {record_id}"
```

**What each decorator parameter does:**

| Parameter | Description |
|-----------|-------------|
| `runtime` | An Aegis `Runtime` instance with your policy |
| `action_type` | The Aegis action type for policy matching |
| `action_target` | The Aegis action target (default: `"default"`) |
| `description` | Override the function's docstring for the action description |

When the agent calls `delete_record`, the function body never executes. Aegis
evaluates the policy, finds `block_deletes`, and returns:

```
[AEGIS BLOCKED] Action blocked by policy rule: block_deletes
```

The agent sees this as a tool response and can explain to the user why the
action was not performed.

---

## Step 3: Full Example -- Governed OpenAI Agent

Here is a complete, runnable example. Copy it, set your API key, and run it.

```python
"""governed_agent.py -- OpenAI Agents SDK agent with Aegis governance."""

import asyncio

from agents import Agent, Runner

from aegis import Action, Policy, Result, ResultStatus, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.adapters.openai_agents import governed_tool
from aegis.runtime.approval import AutoApprovalHandler


# -- Executor (simulated for demo; replace with real API calls) --

class SimulatedExecutor(BaseExecutor):
    async def execute(self, action: Action) -> Result:
        responses = {
            "search": {"results": ["AI safety paper", "Governance framework"]},
            "write_report": {"written": True},
            "delete_document": {"deleted": True},
        }
        data = responses.get(action.type, {"result": "ok"})
        return Result(action=action, status=ResultStatus.SUCCESS, data=data)


# -- Define the policy inline (or load from policy.yaml) --

POLICY = Policy.from_dict({
    "version": "1",
    "defaults": {
        "risk_level": "medium",
        "approval": "approve",
    },
    "rules": [
        {
            "name": "search_auto",
            "match": {"type": "search*", "target": "web"},
            "risk_level": "low",
            "approval": "auto",
        },
        {
            "name": "write_needs_approval",
            "match": {"type": "write_*", "target": "*"},
            "risk_level": "high",
            "approval": "approve",
        },
        {
            "name": "block_deletes",
            "match": {"type": "delete_*", "target": "*"},
            "risk_level": "critical",
            "approval": "block",
        },
    ],
})


# -- Build the governed runtime --

runtime = Runtime(
    executor=SimulatedExecutor(),
    policy=POLICY,
    approval_handler=AutoApprovalHandler(),  # Auto-approve for demo; use CLIApprovalHandler() for interactive
)


# -- Create governed tools --

@governed_tool(runtime=runtime, action_type="search", action_target="web")
async def web_search(query: str) -> str:
    """Search the web for information."""
    return f"Search results for '{query}': AI governance frameworks, NIST AI RMF, EU AI Act..."


@governed_tool(runtime=runtime, action_type="write_report", action_target="storage")
async def write_report(title: str, content: str) -> str:
    """Write a report to storage."""
    return f"Report '{title}' saved successfully."


@governed_tool(runtime=runtime, action_type="delete_document", action_target="storage")
async def delete_document(document_id: str) -> str:
    """Delete a document from storage."""
    return f"Deleted document {document_id}"


# -- Build the agent --

agent = Agent(
    name="Research Assistant",
    instructions=(
        "You are a research assistant. Use web_search to find information, "
        "write_report to save findings, and delete_document to clean up. "
        "If a tool call is blocked, explain why to the user."
    ),
    tools=[web_search, write_report, delete_document],
)


# -- Run it --

async def main():
    # This will auto-approve (search is low risk)
    result = await Runner.run(agent, "Search for 'AI governance best practices'.")
    print("\n--- Agent Output ---")
    print(result.final_output)

    print("\n\n--- Now try a blocked action ---\n")

    # This will be blocked by policy
    result = await Runner.run(agent, "Delete document ID 42 from storage.")
    print("\n--- Agent Output ---")
    print(result.final_output)

    # -- Check the audit trail --
    print("\n--- Audit Trail ---")
    for entry in runtime.audit.get_log():
        print(
            f"  {entry['action_type']:>15} | risk={entry['risk_level']:<8} | "
            f"rule={entry.get('matched_rule', '-'):<20} | "
            f"result={entry.get('result_status') or '-'}"
        )


asyncio.run(main())
```

**What happens when you run this:**

1. The agent calls `web_search`. Aegis evaluates the policy, matches
   `search_auto` (low risk, auto-approve), and executes the function.

2. The agent calls `delete_document`. Aegis matches `block_deletes` (critical
   risk, block). The function returns
   `[AEGIS BLOCKED] Action blocked by policy rule: block_deletes`.
   The agent sees this and reports to the user that the action was not allowed.

3. Every decision is recorded in `aegis_audit.db`.

---

## Step 4: Check the Audit Trail

Aegis logs every action to a local SQLite database (`aegis_audit.db` by default).

### From the CLI

```bash
# View all audit entries
aegis audit

# Filter by risk level
aegis audit --risk high

# Filter by result status
aegis audit --status blocked

# Export to JSON Lines for external analysis
aegis audit --export audit_export.jsonl
```

### From Python

```python
from aegis.runtime.audit import AuditLogger

logger = AuditLogger(db_path="aegis_audit.db")

# Get all blocked actions
blocked = logger.get_log(result_status="blocked")
for entry in blocked:
    print(f"[{entry['timestamp']}] {entry['action_type']} -> {entry['action_target']}: "
          f"{entry['result_error']}")

# Count high-risk actions in this session
count = logger.count(risk_level="HIGH")
print(f"High-risk actions: {count}")

# Export everything to JSON Lines
logger.export_jsonl("audit_export.jsonl")
```

### What the audit log captures

Each entry records the full lifecycle of one tool call:

| Field | Example |
|-------|---------|
| `session_id` | `a3f1b2c4d5e6` |
| `timestamp` | `2024-11-15T14:32:01+00:00` |
| `action_type` | `delete_document` |
| `action_target` | `storage` |
| `action_params` | `{"document_id": "42"}` |
| `risk_level` | `CRITICAL` |
| `approval` | `block` |
| `matched_rule` | `block_deletes` |
| `result_status` | `blocked` |
| `result_error` | `Action blocked by policy rule: block_deletes` |
| `human_decision` | `null` (no human involved) |

---

## Advanced Patterns

### Policy Merge: Base + Production Overrides

Maintain a base policy for development and layer production-specific rules on top:

```yaml
# base-policy.yaml
version: "1"
defaults:
  risk_level: medium
  approval: approve

rules:
  - name: search_auto
    match: { type: "search*" }
    risk_level: low
    approval: auto
```

```yaml
# prod-overrides.yaml
version: "1"
rules:
  - name: prod_block_deletes
    match: { type: "delete_*" }
    risk_level: critical
    approval: block

  - name: prod_require_approval_writes
    match: { type: "write_*" }
    risk_level: high
    approval: approve
```

```python
# Rules from prod-overrides are appended after base rules.
# First-match-wins, so put higher-priority overrides in the first file.
policy = Policy.from_yaml_files("prod-overrides.yaml", "base-policy.yaml")
```

Or merge programmatically:

```python
base = Policy.from_yaml("base-policy.yaml")
prod = Policy.from_yaml("prod-overrides.yaml")
combined = prod.merge(base)  # prod rules checked first, then base rules
```

### Hot-Reload: Update Policy Without Restarting

`PolicyWatcher` monitors your YAML file and swaps the policy atomically
whenever the file changes. In-flight executions are not affected.

```python
from aegis import Runtime, PolicyWatcher

runtime = Runtime(
    executor=SimulatedExecutor(),
    policy=Policy.from_yaml("policy.yaml"),
)

# Start watching -- policy reloads automatically on file change
async with PolicyWatcher(runtime, "policy.yaml", interval=2.0):
    # Your agent runs here. Edit policy.yaml and changes take effect
    # within 2 seconds -- no restart needed.
    result = await Runner.run(agent, "Do something")
```

### Runtime Hooks: Custom Logging and Alerting

Attach callbacks to observe every policy decision, approval gate, and execution
result without modifying the core pipeline:

```python
from aegis import Runtime, RuntimeHooks, PolicyDecision, Result

async def log_decision(decision: PolicyDecision) -> None:
    """Called after every policy evaluation."""
    if decision.risk_level.name in ("HIGH", "CRITICAL"):
        print(f"[ALERT] High-risk action: {decision.action.type} "
              f"-> {decision.action.target} (rule: {decision.matched_rule})")

async def log_approval(decision: PolicyDecision, approved: bool) -> None:
    """Called after every approval gate."""
    status = "APPROVED" if approved else "DENIED"
    print(f"[APPROVAL] {decision.action.type}: {status}")

async def log_execution(result: Result) -> None:
    """Called after every action execution."""
    print(f"[EXEC] {result.action.type}: {result.status.value}")

hooks = RuntimeHooks(
    on_decision=log_decision,
    on_approval=log_approval,
    on_execute=log_execution,
)

runtime = Runtime(
    executor=SimulatedExecutor(),
    policy=Policy.from_yaml("policy.yaml"),
    hooks=hooks,
)
```

### Governing Both Sync and Async Tools

The `@governed_tool` decorator works with both sync and async functions. Aegis
detects the function type automatically:

```python
# Async tool -- runs natively
@governed_tool(runtime=runtime, action_type="search", action_target="web")
async def async_search(query: str) -> str:
    """Async search tool."""
    result = await some_async_client.search(query)
    return str(result)

# Sync tool -- also works
@governed_tool(runtime=runtime, action_type="lookup", action_target="cache")
def sync_lookup(key: str) -> str:
    """Sync lookup tool."""
    return cache.get(key)
```

### Multiple Agents with Shared Policy

Use one runtime across multiple agents for consistent governance:

```python
runtime = Runtime(
    executor=SimulatedExecutor(),
    policy=Policy.from_yaml("policy.yaml"),
    approval_handler=AutoApprovalHandler(),
)

@governed_tool(runtime=runtime, action_type="search", action_target="web")
async def shared_search(query: str) -> str:
    """Shared search tool."""
    return f"Results for: {query}"

@governed_tool(runtime=runtime, action_type="write_email", action_target="email")
async def send_email(to: str, subject: str, body: str) -> str:
    """Send an email (governed)."""
    return f"Email sent to {to}"

researcher = Agent(
    name="Researcher",
    instructions="You research topics.",
    tools=[shared_search],
)

communicator = Agent(
    name="Communicator",
    instructions="You draft and send emails based on research.",
    tools=[shared_search, send_email],
)

# Both agents share the same policy and audit trail
result = await Runner.run(researcher, "Find info about AI safety")
result = await Runner.run(communicator, "Email a summary to team@example.com")
```

### Dry Run: Test Policies Without Executing

Validate your policy against a set of actions without running any tools:

```python
plan = runtime.plan([
    Action("search", target="web", params={"query": "test"}),
    Action("write_record", target="database", params={"table": "users"}),
    Action("delete_record", target="database", params={"id": "42"}),
])

# Print what would happen
print(plan.summary())
#   1. [   AUTO] Action(search -> web)              (risk=LOW, rule=search_auto)
#   2. [APPROVE] Action(write_record -> database)   (risk=HIGH, rule=write_needs_approval)
#   3. [ BLOCK] Action(delete_record -> database)   (risk=CRITICAL, rule=block_deletes)
```

---

## Quick Reference

| Concept | Code |
|---------|------|
| Load policy from YAML | `Policy.from_yaml("policy.yaml")` |
| Load + merge policies | `Policy.from_yaml_files("overrides.yaml", "base.yaml")` |
| Govern a function tool | `@governed_tool(runtime=rt, action_type=..., action_target=...)` |
| Plan actions | `plan = runtime.plan([Action(...)])` |
| Execute with governance | `results = await runtime.execute(plan)` |
| Dry run | `await runtime.execute(plan, dry_run=True)` |
| Hot-reload policy | `async with PolicyWatcher(runtime, "policy.yaml"): ...` |
| Manual policy update | `runtime.update_policy(new_policy)` |
| Query audit log | `AuditLogger().get_log(result_status="blocked")` |
| Export audit log | `AuditLogger().export_jsonl("out.jsonl")` |

---

## Next Steps

- [Policy syntax reference](../guides/policies.md) -- all match patterns, conditions, and operators
- [Approval handlers](../guides/approval-handlers.md) -- CLI, webhook, callback, and custom handlers
- [Audit log](../api/audit.md) -- filtering, export, and programmatic access
- [Custom adapters](../guides/custom-adapters.md) -- build an executor for any system
- [Full API docs](../api/runtime.md) -- Runtime, ExecutionPlan, PolicyDecision
