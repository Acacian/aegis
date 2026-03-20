# Aegis

[![CI](https://github.com/Acacian/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/Acacian/aegis/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/agent-aegis)](https://pypi.org/project/agent-aegis/)
[![Python](https://img.shields.io/pypi/pyversions/agent-aegis)](https://pypi.org/project/agent-aegis/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-acacian.github.io%2Faegis-blue)](https://acacian.github.io/aegis/)

**Your AI agent can browse the web, call APIs, and modify SaaS data. Aegis makes sure it asks permission first.**

> Policy engine + approval gate + audit log for AI agents acting on systems you don't own.

```
Agent action  →  Policy check  →  Approval gate  →  Execute  →  Verify  →  Audit log
  (read CRM)      (auto: low)      (skip)            (run)      (ok)       (logged)
  (bulk update)   (approve: high)  (human y/n)       (run)      (ok)       (logged)
  (delete all)    (block: critical) —                  —          —         (logged)
```

### Works with your stack

**LangChain** | **CrewAI** | **OpenAI Agents SDK** | **Anthropic Claude** | **Playwright** | **httpx** | **Custom adapters**

### Why?

AI agents are getting real-world access — but without governance, a hallucinating agent can bulk-delete your CRM, submit wrong forms, or trigger irreversible API calls. Aegis gives you:

- **YAML policy rules** — classify actions by risk, set approval requirements per action pattern
- **Human-in-the-loop** — approval gates that pause for confirmation on sensitive ops
- **Full audit trail** — every decision and result logged to SQLite
- **5-minute integration** — add 3 lines to your existing agent code

## Quick start

```bash
pip install agent-aegis  # PyPI package name; import as "aegis"
```

### 1. Define a policy

```yaml
# policy.yaml
version: "1"
defaults:
  risk_level: medium
  approval: approve

rules:
  - name: read_operations
    match:
      type: read
    risk_level: low
    approval: auto

  - name: bulk_update
    match:
      type: bulk_update
    risk_level: high
    approval: approve

  - name: delete_blocked
    match:
      type: delete
    risk_level: critical
    approval: block
```

### 2. Use the runtime

```python
from aegis import Action, Policy, Runtime
from aegis.adapters.playwright import PlaywrightExecutor

runtime = Runtime(
    executor=PlaywrightExecutor(),
    policy=Policy.from_yaml("policy.yaml"),
)

# Plan: evaluate actions against the policy
plan = runtime.plan([
    Action("read", target="salesforce", params={"selector": ".contacts"}),
    Action("bulk_update", target="salesforce", params={"field": "status", "value": "active"}),
    Action("delete", target="salesforce", params={"selector": "#nuke"}),
])

print(plan.summary())
#   1. [   AUTO] Action(read -> salesforce)        (risk=LOW, rule=read_operations)
#   2. [APPROVE] Action(bulk_update -> salesforce)  (risk=HIGH, rule=bulk_update)
#   3. [  BLOCK] Action(delete -> salesforce)       (risk=CRITICAL, rule=delete_blocked)

# Execute: auto-runs reads, prompts for bulk_update, blocks delete
results = await runtime.execute(plan)
```

### 3. Review the audit log

```bash
aegis audit
#   ID      Session          Action          Target     Risk   Decision     Result
# ----  -----------  ---------------  ---------------  ------  ----------  ----------
#    1  a1b2c3d4e5f6            read       salesforce     LOW       auto     success
#    2  a1b2c3d4e5f6     bulk_update       salesforce    HIGH   approved     success
#    3  a1b2c3d4e5f6          delete       salesforce CRITICAL      block     blocked
```

## Architecture

```
aegis/
  core/        Action, RiskLevel, Policy engine, JSON Schema, Result, ExecutionPlan
  adapters/    BaseExecutor, Playwright, httpx, LangChain, CrewAI, OpenAI, Anthropic
  runtime/     Runtime engine, ApprovalHandler, AuditLogger (SQLite + JSONL)
  cli/         CLI (aegis audit, aegis validate, aegis schema)
```

### Key concepts

| Concept | Description |
|---------|-------------|
| **Action** | A single operation an agent wants to perform (type + target + params) |
| **Policy** | YAML rules mapping action patterns to risk levels and approval requirements |
| **ExecutionPlan** | Actions evaluated against policy, ready for execution |
| **Runtime** | Orchestrator: plan -> approve -> execute -> verify -> audit |
| **Adapter** | Pluggable executor (Playwright for browsers, custom for APIs) |

### Policy rules

Rules are evaluated in order — first match wins. Each rule specifies:

- **match**: Glob patterns for `type` and `target`
- **risk_level**: `low`, `medium`, `high`, `critical`
- **approval**: `auto` (no human needed), `approve` (human must confirm), `block` (never execute)

## CLI

```bash
# Validate a policy file
aegis validate policy.yaml

# View the audit log
aegis audit
aegis audit --session abc123 --format json
aegis audit --format jsonl -o audit_export.jsonl

# Print the policy JSON Schema (for editor integration)
aegis schema
```

## Integrations

Aegis plugs into the agent frameworks you already use. Install only what you need:

```bash
pip install 'agent-aegis[langchain]'      # LangChain
pip install 'agent-aegis[crewai]'         # CrewAI
pip install 'agent-aegis[openai-agents]'  # OpenAI Agents SDK
pip install 'agent-aegis[playwright]'     # Playwright browser
pip install 'agent-aegis[httpx]'          # REST APIs (httpx)
pip install 'agent-aegis[all]'            # Everything
```

### LangChain

```python
from langchain_community.tools import DuckDuckGoSearchRun
from aegis import Policy, Runtime
from aegis.adapters.langchain import LangChainExecutor

executor = LangChainExecutor(tools=[DuckDuckGoSearchRun()])
runtime = Runtime(executor=executor, policy=Policy.from_yaml("policy.yaml"))
```

Or expose Aegis-governed actions *as* LangChain tools:

```python
from aegis.adapters.langchain import AegisTool

tool = AegisTool.from_runtime(
    runtime=runtime,
    name="governed_search",
    description="Policy-governed web search",
    action_type="search",
    action_target="web",
)
# Use `tool` in any LangChain agent
```

### OpenAI Agents SDK

```python
from aegis.adapters.openai_agents import governed_tool

@governed_tool(runtime=runtime, action_type="write", action_target="crm")
async def update_contact(name: str, email: str) -> str:
    """Update a CRM contact — governed by Aegis policy."""
    return await crm.update(name=name, email=email)
```

### CrewAI

```python
from aegis.adapters.crewai import AegisCrewAITool

tool = AegisCrewAITool(
    runtime=runtime,
    name="governed_search",
    description="Search with governance",
    action_type="search", action_target="web",
    fn=lambda query: do_search(query),
)
# Use `tool` in any CrewAI Agent
```

### httpx (REST APIs)

```python
from aegis.adapters.httpx_adapter import HttpxExecutor

executor = HttpxExecutor(
    base_url="https://api.example.com",
    default_headers={"Authorization": "Bearer ..."},
)
runtime = Runtime(executor=executor, policy=Policy.from_yaml("policy.yaml"))

plan = runtime.plan([
    Action("get", "/users"),
    Action("post", "/users", params={"json": {"name": "Alice"}}),
    Action("delete", "/users/1"),
])
```

Maps action types to HTTP methods: `get`, `post`, `put`, `patch`, `delete`

### Playwright (browser automation)

```python
from aegis.adapters.playwright import PlaywrightExecutor

executor = PlaywrightExecutor(headless=True, browser_type="chromium")
```

Supports: `navigate`, `click`, `fill`, `read`, `screenshot`

### Custom adapters

```python
from aegis.adapters.base import BaseExecutor
from aegis.core.action import Action
from aegis.core.result import Result, ResultStatus

class MyAPIExecutor(BaseExecutor):
    async def execute(self, action: Action) -> Result:
        # Your execution logic here
        return Result(action=action, status=ResultStatus.SUCCESS, data={...})
```

## Demo

Run the quickstart example (no browser required):

```bash
python examples/quickstart.py
```

```
============================================================
  EXECUTION PLAN
============================================================
  1. [   AUTO] Action(navigate -> crm)              (risk=LOW, rule=navigate_auto)
  2. [   AUTO] Action(read -> crm - Read contact list)  (risk=LOW, rule=read_auto)
  3. [APPROVE] Action(write -> crm - Update contact)    (risk=MEDIUM, rule=write_approve)
  4. [APPROVE] Action(bulk_update -> crm - Bulk status change)  (risk=HIGH, rule=bulk_approve)
  5. [  BLOCK] Action(delete -> crm - Delete all records)  (risk=CRITICAL, rule=delete_block)

    [dry-run] Would execute: Action(navigate -> crm)
    [dry-run] Would execute: Action(read -> crm - Read contact list)

============================================================
  APPROVAL REQUIRED
============================================================
  Action:  write
  Target:  crm
  Risk:    MEDIUM
  Approve? [y/n]: y
    [dry-run] Would execute: Action(write -> crm - Update contact)

============================================================
  RESULTS
============================================================
  [OK] navigate -> crm
  [OK] read -> crm
  [OK] write -> crm
  [OK] bulk_update -> crm
  [BLOCK] delete -> crm

============================================================
  AUDIT LOG
============================================================
      navigate | risk=LOW      | decision=auto     | result=success
          read | risk=LOW      | decision=auto     | result=success
         write | risk=MEDIUM   | decision=approved | result=success
   bulk_update | risk=HIGH     | decision=approved | result=success
        delete | risk=CRITICAL | decision=block    | result=blocked
```

## Why Not Build Your Own?

| | DIY Governance | Aegis |
|---|---|---|
| **Policy engine** | Custom if/else per action | YAML rules, glob matching, hot-reloadable |
| **Risk classification** | Hardcoded | 4-tier model with per-rule overrides |
| **Human approval** | Build your own UI/CLI | Pluggable handlers (CLI, Slack, custom) |
| **Audit trail** | printf / custom logging | SQLite + JSONL export with session tracking |
| **Framework support** | Rewrite per framework | LangChain, CrewAI, OpenAI SDK, Playwright, httpx |
| **Verification** | Hope it worked | Post-execution verification hooks |
| **Time to integrate** | Days to weeks | Minutes |

## Roadmap

| Version | Features |
|---------|----------|
| **0.1** | Policy engine, Playwright/httpx adapters, CLI approval, SQLite + JSONL audit, JSON Schema, LangChain/CrewAI/OpenAI/Anthropic integrations |
| **0.2** | Dashboard (React), Slack/Discord approval handlers, policy inheritance |
| **0.3** | MCP server adapter, rollback support, webhook notifications |
| **0.4** | Multi-tenant policies, team-based approvals, cloud audit storage |

See [CHANGELOG.md](CHANGELOG.md) for release history.

## Development

```bash
git clone https://github.com/Acacian/aegis.git
cd aegis
pip install -e ".[dev]"
pytest
```

## License

MIT
