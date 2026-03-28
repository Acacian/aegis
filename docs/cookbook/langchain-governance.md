---
description: "Add policy governance to LangChain agents in 5 minutes. Block dangerous tool calls, require approval, and log every action."
---

# Add Governance to LangChain Agents in 5 Minutes

LangChain agents can call tools autonomously. That is powerful -- and dangerous.
A single hallucinated function call can delete production data, send an email to
the wrong person, or charge a credit card twice.

**Aegis** adds a policy layer between your agent's decisions and the actual tool
calls. You define rules in YAML; Aegis enforces them at runtime. Every action is
evaluated, gated, and logged -- with zero changes to your existing LangChain code.

**What you will build:** A ReAct agent where search and retrieval run freely,
write operations require approval, delete operations are hard-blocked, and
everything is recorded in an audit trail.

**Time:** 5 minutes.

---

## Prerequisites

```bash
pip install 'agent-aegis[langchain]' langchain-core langchain-openai
```

> Aegis works with any LangChain-compatible model. The examples use
> `langchain-openai`, but swap in `langchain-anthropic`, `langchain-google-genai`,
> or any other provider.

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
      type: "duckduckgo_search"
      target: "web"
    risk_level: low
    approval: auto

  - name: retrieval_tools
    match:
      type: "retriever"
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
- `match.type` maps to the LangChain tool name. Glob patterns (`*`, `?`) are supported.
- `match.target` is the system being acted on (e.g., `"web"`, `"database"`, `"crm"`).
- `conditions` add time-based and parameter-based guards.
- `approval: auto` means execute immediately. `approve` means ask a human. `block` means reject unconditionally.

---

## Step 2: Wrap Existing LangChain Tools with Governance

`LangChainExecutor` takes your existing LangChain tools and runs them through
the Aegis policy engine. The tool name becomes the action type.

```python
from langchain_community.tools import DuckDuckGoSearchRun
from aegis import Action, Policy, Runtime
from aegis.adapters.langchain import LangChainExecutor

# 1. Your existing LangChain tools -- no changes needed
search = DuckDuckGoSearchRun()

# 2. Wrap them in a governed executor
executor = LangChainExecutor(tools=[search])

# 3. Create the runtime with your policy
runtime = Runtime(
    executor=executor,
    policy=Policy.from_yaml("policy.yaml"),
)

# 4. Plan and execute -- policy is checked before every tool call
plan = runtime.plan([
    Action("duckduckgo_search", target="web", params={"query": "LangChain governance"}),
])

# plan.summary() shows what will happen:
#   1. [   AUTO] Action(duckduckgo_search -> web)  (risk=LOW, rule=search_tools)
print(plan.summary())

results = await runtime.execute(plan)
print(results[0].data)  # Search results
```

**What happened:** The search tool matched `search_tools` (low risk, auto-approve),
so it ran immediately with no human intervention. The action, decision, and result
were all recorded in the audit log.

You can also register tools dynamically:

```python
from langchain_community.tools import WikipediaQueryRun
from langchain_community.utilities import WikipediaAPIWrapper

executor.register_tool(WikipediaQueryRun(api_wrapper=WikipediaAPIWrapper()))
```

---

## Step 3: Expose Governed Actions as LangChain Tools

What if you want to go the other direction -- let a LangChain agent call
Aegis-governed actions as if they were regular tools?

`AegisTool.from_runtime()` creates a standard LangChain `StructuredTool` that
routes every call through the Aegis policy engine:

```python
from aegis import Policy, Runtime
from aegis.adapters.langchain import AegisTool, LangChainExecutor

runtime = Runtime(
    executor=LangChainExecutor(tools=[]),
    policy=Policy.from_yaml("policy.yaml"),
)

# Create governed LangChain tools
governed_search = AegisTool.from_runtime(
    runtime=runtime,
    name="web_search",
    description="Search the web. Input: a search query string.",
    action_type="duckduckgo_search",
    action_target="web",
)

governed_write = AegisTool.from_runtime(
    runtime=runtime,
    name="write_record",
    description="Write a record to the database. Input: record fields as key-value pairs.",
    action_type="write_record",
    action_target="database",
)

governed_delete = AegisTool.from_runtime(
    runtime=runtime,
    name="delete_record",
    description="Delete a record from the database. Input: record ID.",
    action_type="delete_record",
    action_target="database",
)

# These are standard LangChain tools -- plug them into any agent
tools = [governed_search, governed_write, governed_delete]
```

When the agent calls `delete_record`, it does not reach the database. Aegis
evaluates the policy, finds `block_deletes`, and returns:

```
[AEGIS BLOCKED] Blocked by policy rule: block_deletes
```

The agent sees this as a tool response and can explain to the user why the
action was not performed.

---

## Step 4: Full Example -- Governed ReAct Agent

Here is a complete, runnable example. Copy it, set your API key, and run it.

```python
"""governed_agent.py -- LangChain ReAct agent with Aegis governance."""

import asyncio
from langchain_openai import ChatOpenAI
from langchain_core.tools import StructuredTool
from langchain.agents import create_react_agent, AgentExecutor
from langchain_core.prompts import PromptTemplate

from aegis import Action, Policy, Runtime
from aegis.adapters.langchain import AegisTool, LangChainExecutor
from aegis.runtime.approval import AutoApprovalHandler


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
            "match": {"type": "web_search", "target": "web"},
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
    executor=LangChainExecutor(tools=[]),
    policy=POLICY,
    approval_handler=AutoApprovalHandler(),  # Auto-approve for demo; use CLIApprovalHandler() for interactive
)


# -- Create governed tools --

search_tool = AegisTool.from_runtime(
    runtime=runtime,
    name="web_search",
    description="Search the web for information. Input: a search query.",
    action_type="web_search",
    action_target="web",
)

write_tool = AegisTool.from_runtime(
    runtime=runtime,
    name="write_document",
    description="Write a document to storage. Input: title and content.",
    action_type="write_document",
    action_target="storage",
)

delete_tool = AegisTool.from_runtime(
    runtime=runtime,
    name="delete_document",
    description="Delete a document from storage. Input: document ID.",
    action_type="delete_document",
    action_target="storage",
)

tools = [search_tool, write_tool, delete_tool]


# -- Build the agent --

llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)

PROMPT = PromptTemplate.from_template(
    """Answer the following questions as best you can. You have access to the following tools:

{tools}

Use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I know the final answer
Final Answer: the final answer to the original input question

Begin!

Question: {input}
Thought:{agent_scratchpad}"""
)

agent = create_react_agent(llm, tools, PROMPT)
agent_executor = AgentExecutor(
    agent=agent,
    tools=tools,
    verbose=True,
    handle_parsing_errors=True,
)


# -- Run it --

async def main():
    # This will auto-approve (search is low risk)
    result = await agent_executor.ainvoke(
        {"input": "Search for 'AI governance best practices' and summarize what you find."}
    )
    print("\n--- Agent Output ---")
    print(result["output"])

    print("\n\n--- Now try a blocked action ---\n")

    # This will be blocked by policy
    result = await agent_executor.ainvoke(
        {"input": "Delete document ID 42 from storage."}
    )
    print("\n--- Agent Output ---")
    print(result["output"])


asyncio.run(main())
```

**What happens when you run this:**

1. The agent calls `web_search`. Aegis evaluates the policy, matches `search_auto`
   (low risk, auto-approve), and executes the tool.

2. The agent calls `delete_document`. Aegis matches `block_deletes` (critical risk,
   block). The tool returns `[AEGIS BLOCKED] Blocked by policy rule: block_deletes`.
   The agent sees this and reports to the user that the action was not allowed.

3. Every decision is recorded in `aegis_audit.db`.

---

## Step 5: Check the Audit Trail

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

Each entry records the full lifecycle of one action:

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
    match: { type: "web_search" }
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
    executor=LangChainExecutor(tools=my_tools),
    policy=Policy.from_yaml("policy.yaml"),
)

# Start watching -- policy reloads automatically on file change
async with PolicyWatcher(runtime, "policy.yaml", interval=2.0):
    # Your agent runs here. Edit policy.yaml and changes take effect
    # within 2 seconds -- no restart needed.
    result = await agent_executor.ainvoke({"input": "Do something"})
```

You can also hook into reload events:

```python
async def on_policy_reload(new_policy):
    print(f"Policy reloaded: {len(new_policy.rules)} rules active")

watcher = PolicyWatcher(
    runtime,
    "policy.yaml",
    interval=1.0,
    on_reload=on_policy_reload,
)
await watcher.start()
# ... later ...
await watcher.stop()
```

Or update the policy manually at any time:

```python
runtime.update_policy(Policy.from_yaml("new-policy.yaml"))
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
    executor=LangChainExecutor(tools=my_tools),
    policy=Policy.from_yaml("policy.yaml"),
    hooks=hooks,
)
```

### Webhook Approval: Slack, Discord, PagerDuty

Replace the CLI approval prompt with a webhook that posts to Slack (or any HTTP
endpoint) and waits for a response:

```python
from aegis.runtime.approval_webhook import WebhookApprovalHandler

handler = WebhookApprovalHandler(
    url="https://your-app.com/api/approve",
    headers={"Authorization": "Bearer your-token"},
    timeout=300.0,  # Wait up to 5 minutes for human response
)

runtime = Runtime(
    executor=LangChainExecutor(tools=my_tools),
    policy=Policy.from_yaml("policy.yaml"),
    approval_handler=handler,
)
```

The webhook receives a JSON payload:

```json
{
    "action_type": "write_record",
    "action_target": "database",
    "action_params": {"table": "users", "data": {"name": "Alice"}},
    "risk_level": "HIGH",
    "approval": "approve",
    "matched_rule": "write_needs_approval"
}
```

Your endpoint responds with:

```json
{"approved": true}
```

### Callback Approval: Custom Logic

For full control, use `CallbackApprovalHandler` with any sync or async function:

```python
from aegis.runtime.approval_callback import CallbackApprovalHandler
from aegis.core.risk import RiskLevel

async def smart_approval(decision):
    """Auto-approve medium risk; send high/critical to Slack."""
    if decision.risk_level <= RiskLevel.MEDIUM:
        return True
    return await slack_bot.request_approval(decision)

runtime = Runtime(
    executor=LangChainExecutor(tools=my_tools),
    policy=Policy.from_yaml("policy.yaml"),
    approval_handler=CallbackApprovalHandler(smart_approval),
)
```

### Dry Run: Test Policies Without Executing

Validate your policy against a set of actions without running any tools:

```python
plan = runtime.plan([
    Action("web_search", target="web", params={"query": "test"}),
    Action("write_record", target="database", params={"table": "users"}),
    Action("delete_record", target="database", params={"id": "42"}),
])

# Print what would happen
print(plan.summary())
#   1. [   AUTO] Action(web_search -> web)            (risk=LOW, rule=search_auto)
#   2. [APPROVE] Action(write_record -> database)     (risk=HIGH, rule=write_needs_approval)
#   3. [ BLOCK] Action(delete_record -> database)     (risk=CRITICAL, rule=block_deletes)

# dry_run=True evaluates policy and approval requirements but skips execution
results = await runtime.execute(plan, dry_run=True)
for r in results:
    print(f"{r.action.type}: {r.status.value} {r.data}")
```

### Plan Filtering: Execute Only Safe Actions

```python
# Get the full plan
plan = runtime.plan(actions)

# Filter to only auto-approved actions
from aegis import Approval
safe_plan = plan.filter(allowed_only=True)

# Or filter by approval mode
auto_plan = plan.filter(approval=Approval.AUTO)

results = await runtime.execute(auto_plan)
```

---

## Quick Reference

| Concept | Code |
|---------|------|
| Load policy from YAML | `Policy.from_yaml("policy.yaml")` |
| Load + merge policies | `Policy.from_yaml_files("overrides.yaml", "base.yaml")` |
| Wrap LangChain tools | `LangChainExecutor(tools=[tool1, tool2])` |
| Create governed LangChain tool | `AegisTool.from_runtime(runtime=rt, name=..., action_type=..., action_target=...)` |
| Plan actions | `plan = runtime.plan([Action(...)])` |
| Execute with governance | `results = await runtime.execute(plan)` |
| Execute single action | `result = await runtime.run_one(Action(...))` |
| Dry run | `await runtime.execute(plan, dry_run=True)` |
| Hot-reload policy | `async with PolicyWatcher(runtime, "policy.yaml"): ...` |
| Manual policy update | `runtime.update_policy(new_policy)` |
| Webhook approval | `WebhookApprovalHandler(url="https://...")` |
| Callback approval | `CallbackApprovalHandler(my_func)` |
| Query audit log | `AuditLogger().get_log(result_status="blocked")` |
| Export audit log | `AuditLogger().export_jsonl("out.jsonl")` |

---

## Next Steps

- [Policy syntax reference](../guides/policies.md) -- all match patterns, conditions, and operators
- [Approval handlers](../guides/approval-handlers.md) -- CLI, webhook, callback, and custom handlers
- [Audit log](../api/audit.md) -- filtering, export, and programmatic access
- [Custom adapters](../guides/custom-adapters.md) -- build an executor for any system
- [Full API docs](../api/runtime.md) -- Runtime, ExecutionPlan, PolicyDecision
