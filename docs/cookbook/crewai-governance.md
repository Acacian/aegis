---
description: "Add policy governance to CrewAI multi-agent crews in 5 minutes. Control tool calls, enforce approval gates, and audit every action."
---

# Add Governance to CrewAI Agents in 5 Minutes

CrewAI agents collaborate as a crew, delegating tasks and calling tools
autonomously. That multi-agent autonomy is powerful -- and risky. A single
tool call from any crew member can delete data, overwrite records, or hit a
paid API with no guardrails.

**Aegis** adds a policy layer between your crew's tool calls and actual
execution. You define rules in YAML; Aegis enforces them at runtime. Every
tool invocation is evaluated, gated, and logged -- with zero changes to your
existing CrewAI workflow.

**What you will build:** A CrewAI crew where search tools run freely, write
operations require approval, delete operations are hard-blocked, and
everything is recorded in an audit trail.

**Time:** 5 minutes.

---

## Prerequisites

```bash
pip install 'agent-aegis[crewai]' crewai crewai-tools
```

> Aegis works with any CrewAI setup. The examples below use inline functions
> for simplicity, but you can wrap any existing CrewAI tool or API client.

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

  # --- Hard block: deletes never run ---
  - name: block_deletes
    match:
      type: "delete_*"
      target: "*"
    risk_level: critical
    approval: block

  # --- Block bulk operations over 100 records ---
  - name: block_bulk_writes
    match:
      type: "write_*"
      target: "*"
    conditions:
      param_gt: { count: 100 }
    risk_level: critical
    approval: block
```

**How rules work:**

- Rules are evaluated top to bottom. The **first match wins**.
- `match.type` maps to the `action_type` you assign to each `AegisCrewAITool`. Glob patterns (`*`, `?`) are supported.
- `match.target` is the system being acted on (e.g., `"web"`, `"database"`, `"crm"`).
- `conditions` add time-based and parameter-based guards.
- `approval: auto` means execute immediately. `approve` means ask a human. `block` means reject unconditionally.

---

## Step 2: Create Governed Tools with `AegisCrewAITool`

`AegisCrewAITool` is a CrewAI-compatible tool that routes every call through
the Aegis policy engine before executing your function.

```python
from aegis import Policy, Runtime
from aegis.adapters.crewai import AegisCrewAITool
from aegis.adapters.base import BaseExecutor
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
    approval_handler=AutoApprovalHandler(),  # Use CLIApprovalHandler() for interactive
)

# 2. Create governed tools
governed_search = AegisCrewAITool(
    runtime=runtime,
    name="web_search",
    description="Search the web for information. Input: a search query.",
    action_type="search",
    action_target="web",
    fn=lambda query: f"Results for: {query}",
)

governed_write = AegisCrewAITool(
    runtime=runtime,
    name="write_record",
    description="Write a record to the database.",
    action_type="write_record",
    action_target="database",
    fn=lambda **kwargs: f"Written: {kwargs}",
)

governed_delete = AegisCrewAITool(
    runtime=runtime,
    name="delete_record",
    description="Delete a record from the database.",
    action_type="delete_record",
    action_target="database",
    fn=lambda record_id: f"Deleted: {record_id}",
)
```

**What each parameter does:**

| Parameter | Description |
|-----------|-------------|
| `runtime` | An Aegis `Runtime` instance with your policy |
| `name` | Tool name visible to the CrewAI agent |
| `description` | Tool description the agent uses to decide when to call it |
| `action_type` | The Aegis action type for policy matching |
| `action_target` | The Aegis action target (e.g., `"web"`, `"database"`) |
| `fn` | The actual function to execute after governance checks pass |

When the agent calls `delete_record`, it never reaches your function. Aegis
evaluates the policy, finds `block_deletes`, and returns:

```
[AEGIS BLOCKED] Blocked by policy rule: block_deletes
```

The agent sees this as a tool response and can explain to the user why the
action was not performed.

---

## Step 3: Full Example -- Governed CrewAI Crew

Here is a complete, runnable example. Copy it, set your API key, and run it.

```python
"""governed_crew.py -- CrewAI crew with Aegis governance."""

import asyncio
from crewai import Agent, Task, Crew, Process

from aegis import Action, Policy, Result, ResultStatus, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.adapters.crewai import AegisCrewAITool
from aegis.runtime.approval import AutoApprovalHandler


# -- Executor (simulated for demo; replace with real API calls) --

class SimulatedExecutor(BaseExecutor):
    async def execute(self, action: Action) -> Result:
        return Result(action=action, status=ResultStatus.SUCCESS, data={"mock": True})


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
    approval_handler=AutoApprovalHandler(),
)


# -- Create governed tools --

search_tool = AegisCrewAITool(
    runtime=runtime,
    name="web_search",
    description="Search the web for information. Input: a search query string.",
    action_type="search",
    action_target="web",
    fn=lambda query: f"Search results for '{query}': AI governance frameworks, NIST guidelines...",
)

write_tool = AegisCrewAITool(
    runtime=runtime,
    name="write_report",
    description="Write a report to storage. Input: report content.",
    action_type="write_report",
    action_target="storage",
    fn=lambda content: f"Report saved: {content[:50]}...",
)

delete_tool = AegisCrewAITool(
    runtime=runtime,
    name="delete_document",
    description="Delete a document from storage. Input: document ID.",
    action_type="delete_document",
    action_target="storage",
    fn=lambda doc_id: f"Deleted document {doc_id}",
)


# -- Build the crew --

researcher = Agent(
    role="Senior Research Analyst",
    goal="Find and summarize information about AI governance best practices",
    backstory="You are an expert researcher skilled at finding relevant information.",
    tools=[search_tool],
    verbose=True,
)

writer = Agent(
    role="Technical Writer",
    goal="Write clear, concise reports based on research findings",
    backstory="You are a skilled writer who creates well-structured documents.",
    tools=[write_tool, delete_tool],
    verbose=True,
)

research_task = Task(
    description="Research AI governance best practices and summarize the key findings.",
    expected_output="A summary of AI governance best practices.",
    agent=researcher,
)

write_task = Task(
    description=(
        "Write a report based on the research. "
        "Then try to delete document ID 42 (this should be blocked by policy)."
    ),
    expected_output="A written report and an explanation of any blocked actions.",
    agent=writer,
)

crew = Crew(
    agents=[researcher, writer],
    tasks=[research_task, write_task],
    process=Process.sequential,
    verbose=True,
)


# -- Run it --

result = crew.kickoff()
print("\n--- Crew Output ---")
print(result)

# -- Check the audit trail --
print("\n--- Audit Trail ---")
for entry in runtime.audit.get_log():
    print(
        f"  {entry['action_type']:>15} | risk={entry['risk_level']:<8} | "
        f"rule={entry.get('matched_rule', '-'):<20} | "
        f"result={entry.get('result_status') or '-'}"
    )
```

**What happens when you run this:**

1. The researcher agent calls `web_search`. Aegis evaluates the policy, matches
   `search_auto` (low risk, auto-approve), and executes the tool.

2. The writer agent calls `write_report`. Aegis matches `write_needs_approval`
   (high risk, approve). With `AutoApprovalHandler`, it auto-approves for the
   demo. In production, use `CLIApprovalHandler()` for interactive approval.

3. The writer agent calls `delete_document`. Aegis matches `block_deletes`
   (critical risk, block). The tool returns
   `[AEGIS BLOCKED] Blocked by policy rule: block_deletes`. The agent sees this
   and reports that the action was not allowed.

4. Every decision is recorded in `aegis_audit.db`.

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
| `action_params` | `{"doc_id": "42"}` |
| `risk_level` | `CRITICAL` |
| `approval` | `block` |
| `matched_rule` | `block_deletes` |
| `result_status` | `blocked` |
| `result_error` | `Blocked by policy rule: block_deletes` |
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
    # Your crew runs here. Edit policy.yaml and changes take effect
    # within 2 seconds -- no restart needed.
    result = crew.kickoff()
```

### Runtime Hooks: Custom Logging and Alerting

Attach callbacks to observe every policy decision and execution result:

```python
from aegis import Runtime, RuntimeHooks, PolicyDecision, Result

async def alert_on_block(decision: PolicyDecision) -> None:
    """Called after every policy evaluation."""
    if decision.risk_level.name in ("HIGH", "CRITICAL"):
        print(f"[ALERT] High-risk action from crew: {decision.action.type} "
              f"-> {decision.action.target} (rule: {decision.matched_rule})")

async def log_execution(result: Result) -> None:
    """Called after every action execution."""
    print(f"[EXEC] {result.action.type}: {result.status.value}")

hooks = RuntimeHooks(
    on_decision=alert_on_block,
    on_execute=log_execution,
)

runtime = Runtime(
    executor=SimulatedExecutor(),
    policy=Policy.from_yaml("policy.yaml"),
    hooks=hooks,
)
```

### Per-Agent Policies: Different Rules for Different Crew Members

Create separate runtimes with different policies per agent role:

```python
# Researcher: can search freely, nothing else
researcher_policy = Policy.from_dict({
    "version": "1",
    "defaults": {"risk_level": "critical", "approval": "block"},
    "rules": [
        {"name": "search_only", "match": {"type": "search*"}, "risk_level": "low", "approval": "auto"},
    ],
})
researcher_runtime = Runtime(executor=MyExecutor(), policy=researcher_policy)

# Writer: can search and write, but not delete
writer_policy = Policy.from_dict({
    "version": "1",
    "defaults": {"risk_level": "critical", "approval": "block"},
    "rules": [
        {"name": "search_ok", "match": {"type": "search*"}, "risk_level": "low", "approval": "auto"},
        {"name": "write_ok", "match": {"type": "write_*"}, "risk_level": "medium", "approval": "approve"},
    ],
})
writer_runtime = Runtime(executor=MyExecutor(), policy=writer_policy)

# Build tools with role-specific runtimes
researcher_search = AegisCrewAITool(
    runtime=researcher_runtime, name="web_search",
    description="Search the web.", action_type="search",
    action_target="web", fn=my_search_fn,
)

writer_write = AegisCrewAITool(
    runtime=writer_runtime, name="write_report",
    description="Write a report.", action_type="write_report",
    action_target="storage", fn=my_write_fn,
)
```

### Dry Run: Test Policies Without Executing

Validate your policy against a set of actions before deploying:

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
| Create governed CrewAI tool | `AegisCrewAITool(runtime=rt, name=..., action_type=..., fn=...)` |
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
