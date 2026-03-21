<p align="center">
  <h1 align="center">Aegis</h1>
  <p align="center">
    <strong>The simplest way to govern AI agent actions. No infra. No lock-in. Just Python.</strong>
  </p>
  <p align="center">
    <code>pip install agent-aegis</code> &#8594; YAML policy &#8594; governance in 5 minutes.<br/>
    <strong>Works with LangChain, CrewAI, OpenAI, Anthropic, MCP, and more.</strong>
  </p>
</p>

<p align="center">
  <a href="https://github.com/Acacian/aegis/actions/workflows/ci.yml"><img src="https://github.com/Acacian/aegis/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/agent-aegis/"><img src="https://img.shields.io/pypi/v/agent-aegis?color=blue&cacheSeconds=3600" alt="PyPI"></a>
  <a href="https://pypi.org/project/agent-aegis/"><img src="https://img.shields.io/pypi/pyversions/agent-aegis?cacheSeconds=3600" alt="Python"></a>
  <a href="https://github.com/Acacian/aegis/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
  <a href="https://acacian.github.io/aegis/"><img src="https://img.shields.io/badge/docs-acacian.github.io%2Faegis-blue" alt="Docs"></a>
  <a href="https://github.com/Acacian/aegis"><img src="https://img.shields.io/github/stars/Acacian/aegis?style=social" alt="GitHub stars"></a>
  <br/>
  <a href="https://github.com/Acacian/aegis/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/tests-420_passed-brightgreen" alt="Tests"></a>
  <a href="https://github.com/Acacian/aegis/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/coverage-92%25-brightgreen" alt="Coverage"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#how-it-works">How It Works</a> &bull;
  <a href="https://acacian.github.io/aegis/">Documentation</a> &bull;
  <a href="#integrations">Integrations</a> &bull;
  <a href="https://github.com/Acacian/aegis/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22">Contributing</a>
</p>

<p align="center">
  <b>English</b> &bull;
  <a href="./README.ko.md">한국어</a>
</p>

---

## The Problem

AI agents are getting real-world access. Without governance, a hallucinating agent can:

- Bulk-delete your CRM contacts
- Submit wrong forms to government portals
- Trigger irreversible API calls at 3am
- Run up cloud bills with infinite loops

**There's no `sudo` for AI agents. Until now.**

## The Solution

Aegis is a **Python middleware** that sits between your AI agent and the actions it takes. It's not a separate server you have to run -- you import it directly into your agent code and it wraps every action with policy checks, approval gates, and audit logging.

```
Your Agent                    Aegis                         Real World
    |                           |                               |
    |-- "delete all users" ---> |                               |
    |                      [Policy check]                       |
    |                      risk=CRITICAL                        |
    |                      approval=BLOCK                       |
    |                           |--- X (blocked, logged) -----> |
    |                           |                               |
    |-- "read contacts" ------> |                               |
    |                      [Policy check]                       |
    |                      risk=LOW                             |
    |                      approval=AUTO                        |
    |                           |--- execute (logged) --------> |
    |                           |                               |
    |-- "bulk update 500" ----> |                               |
    |                      [Policy check]                       |
    |                      risk=HIGH                            |
    |                      approval=APPROVE                     |
    |                           |--- ask human (Slack/CLI) ---> |
    |                           |<-- "approved" --------------- |
    |                           |--- execute (logged) --------> |
```

**3 lines to add governance:**

```python
from aegis import Action, Policy, Runtime

runtime = Runtime(executor=your_executor, policy=Policy.from_yaml("policy.yaml"))
results = await runtime.run_one(Action("write", "salesforce", params={...}))
```

**No servers to deploy. No Kubernetes. No vendor lock-in.** One `pip install`, one YAML file, and your agent has policy checks, human approval gates, and a full audit trail — across any AI provider.

## How It Works

### Core Concepts

Aegis has 3 key components. You need to understand these to use it:

| Concept | What it is | Your responsibility |
|---------|-----------|-------------------|
| **Policy** | YAML rules that define what's allowed, what needs approval, and what's blocked. | Write the rules. |
| **Executor** | The adapter that actually does things (calls APIs, clicks buttons, runs queries). | Provide one, or use a built-in adapter. |
| **Runtime** | The engine that connects Policy + Executor. Evaluates rules, gates approval, executes, logs. | Create it. Call `run_one()` or `plan()` + `execute()`. |

### The Pipeline

Every action goes through 5 stages. This happens automatically -- you just call `runtime.run_one(action)`:

```
1. EVALUATE    Your action is matched against policy rules (glob patterns).
               → PolicyDecision: risk level + approval requirement + matched rule

2. APPROVE     Based on the decision:
               - auto:    proceed immediately (low-risk actions)
               - approve: ask a human via CLI, Slack, Discord, Telegram, webhook, or email
               - block:   reject immediately (dangerous actions)

3. EXECUTE     The Executor carries out the action.
               Built-in: Playwright (browser), httpx (HTTP), LangChain, CrewAI, OpenAI, Anthropic, MCP
               Custom: extend BaseExecutor (10 lines)

4. VERIFY      Optional post-execution check (override executor.verify()).

5. AUDIT       Every decision and result is logged to SQLite automatically.
               Export: JSONL, webhook, or query via CLI/API.
```

### Two Ways to Use

**Option A: Python library (most common)** -- no server needed.

Import Aegis into your agent code. Everything runs in the same process.

```python
runtime = Runtime(executor=MyExecutor(), policy=Policy.from_yaml("policy.yaml"))
result = await runtime.run_one(Action("read", "crm"))
```

**Option B: REST API server** -- for non-Python agents (Go, TypeScript, etc.).

```bash
pip install 'agent-aegis[server]'
aegis serve policy.yaml --port 8000
```

```bash
curl -X POST localhost:8000/api/v1/evaluate \
  -d '{"action_type": "delete", "target": "db"}'
# => {"risk_level": "CRITICAL", "approval": "block", "is_allowed": false}
```

### Approval Handlers

When a policy rule requires `approval: approve`, Aegis asks a human. You choose how:

| Handler | How it works | Status |
|---------|-------------|--------|
| **CLI** (default) | Terminal Y/N prompt | Stable |
| **Slack** | Posts Block Kit message, polls thread replies | Stable |
| **Discord** | Sends rich embed, polls callback | Stable |
| **Telegram** | Inline keyboard buttons, polls getUpdates | Stable |
| **Webhook** | POSTs to any URL, reads response | Stable |
| **Email** | Sends approval request via SMTP, polls mailbox | Beta |
| **Auto** | Approves everything (for testing / server mode) | Stable |
| **Custom** | Extend `ApprovalHandler` with your own logic | Stable |

### Audit Trail

Every action is automatically logged to a local SQLite database. No setup required.

```bash
aegis audit                              # View all entries
aegis audit --risk-level HIGH            # Filter by risk
aegis audit --tail                       # Live monitoring (1s poll)
aegis stats                              # Statistics per rule
aegis audit --format jsonl -o export.jsonl  # Export
```

---

## Quick Start

```bash
pip install agent-aegis
```

### 1. Generate a policy

```bash
aegis init  # Creates policy.yaml with sensible defaults
```

```yaml
# policy.yaml
version: "1"
defaults:
  risk_level: medium
  approval: approve

rules:
  - name: read_safe
    match: { type: "read*" }
    risk_level: low
    approval: auto

  - name: bulk_ops_need_approval
    match: { type: "bulk_*" }
    conditions:
      param_gt: { count: 100 }  # Only when count > 100
    risk_level: high
    approval: approve

  - name: no_deletes
    match: { type: "delete*" }
    risk_level: critical
    approval: block
```

### 2. Add to your agent

```python
import asyncio
from aegis import Action, Policy, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.core.result import Result, ResultStatus

class MyExecutor(BaseExecutor):
    async def execute(self, action):
        print(f"  Executing: {action.type} -> {action.target}")
        return Result(action=action, status=ResultStatus.SUCCESS)

async def main():
    async with Runtime(
        executor=MyExecutor(),
        policy=Policy.from_yaml("policy.yaml"),
    ) as runtime:
        plan = runtime.plan([
            Action("read", "crm", description="Fetch contacts"),
            Action("bulk_update", "crm", params={"count": 150}),
            Action("delete", "crm", description="Drop table"),
        ])
        print(plan.summary())
        results = await runtime.execute(plan)

asyncio.run(main())
```

### 3. See what happened

```bash
aegis audit
```
```
  ID  Session       Action        Target   Risk      Decision    Result
  1   a1b2c3d4...   read          crm      LOW       auto        success
  2   a1b2c3d4...   bulk_update   crm      HIGH      approved    success
  3   a1b2c3d4...   delete        crm      CRITICAL  block       blocked
```

## Features

| Feature | Description |
|---------|-------------|
| **YAML policies** | Glob matching, first-match-wins, JSON Schema for validation |
| **Smart conditions** | `time_after`, `time_before`, `weekdays`, `param_gt/lt/eq/contains/matches` |
| **4-tier risk model** | `low` / `medium` / `high` / `critical` with per-rule overrides |
| **Approval gates** | CLI, Slack, Discord, Telegram, email, webhook, or custom |
| **Audit trail** | SQLite, JSONL export, Python `logging`, or webhook to external SIEM |
| **REST API server** | `aegis serve policy.yaml` -- govern from any language via HTTP |
| **MCP adapter** | Govern Model Context Protocol tool calls |
| **Retry & rollback** | Exponential backoff, error filters, automatic rollback on failure |
| **Dry-run & simulate** | Test policies without executing: `aegis simulate policy.yaml read:crm` |
| **Hot-reload** | `runtime.update_policy(...)` -- swap policies without restart |
| **Policy merge** | `Policy.from_yaml_files("base.yaml", "prod.yaml")` -- layer configs |
| **Runtime hooks** | Async callbacks for `on_decision`, `on_approval`, `on_execute` |
| **Type-safe** | Full `mypy --strict` compliance, `py.typed` marker |

## Real-World Use Cases

| Scenario | Policy | Outcome |
|----------|--------|---------|
| **Finance** | Block bulk transfers > $10K without CFO approval | Agents can process invoices safely; large amounts trigger Slack approval |
| **SaaS Ops** | Auto-approve reads; require approval for account mutations | Support agents handle tickets without accidentally deleting accounts |
| **DevOps** | Allow deploys Mon-Fri 9-5; block after hours | CI/CD agents can't push to prod at 3am |
| **Data Pipeline** | Block DELETE on production tables; auto-approve staging | ETL agents can't drop prod data, even if the LLM hallucinates |
| **Compliance** | Log every external API call with full context | Auditors get a complete trail for SOC2 / GDPR evidence |

## Production Ready

| Aspect | Detail |
|--------|--------|
| **420 tests, 92% coverage** | Every adapter, handler, and edge case tested |
| **Type-safe** | `mypy --strict` with zero errors, `py.typed` marker |
| **Performance** | Policy evaluation < 1ms; auto-approved actions add < 5ms overhead |
| **Fail-safe** | Blocked actions never execute; can't be bypassed without policy change |
| **Audit immutability** | Results are frozen dataclasses; audit writes happen before returning |
| **No magic** | Pure Python, no monkey-patching, no global state |

## Compliance & Audit

Aegis audit trails provide evidence for regulatory and internal compliance:

| Standard | What Aegis provides |
|----------|-------------------|
| **SOC2** | Immutable audit log of every agent action, decision, and approval |
| **GDPR** | Data access documentation -- who/what accessed which system and when |
| **HIPAA** | PHI access trail with full action context and approval chain |
| **Internal** | Change management evidence, risk assessment per action |

Export as JSONL, query via CLI/API, or stream to external SIEM via webhook. For defense-in-depth with container isolation, see the [Security Model](https://acacian.github.io/aegis/guides/security-model/) guide.

## Integrations

Works with the agent frameworks you already use:

```bash
pip install 'agent-aegis[langchain]'      # LangChain
pip install 'agent-aegis[crewai]'         # CrewAI
pip install 'agent-aegis[openai-agents]'  # OpenAI Agents SDK
pip install 'agent-aegis[anthropic]'      # Anthropic Claude
pip install 'agent-aegis[httpx]'          # Webhook approval/audit
pip install 'agent-aegis[playwright]'     # Browser automation
pip install 'agent-aegis[server]'         # REST API server
pip install 'agent-aegis[all]'            # Everything
```

<details>
<summary><b>LangChain</b> -- wrap tools or expose governed actions</summary>

```python
from aegis.adapters.langchain import LangChainExecutor, AegisTool

# Wrap existing LangChain tools with governance
executor = LangChainExecutor(tools=[DuckDuckGoSearchRun()])
runtime = Runtime(executor=executor, policy=Policy.from_yaml("policy.yaml"))

# Or expose governed actions AS LangChain tools
tool = AegisTool.from_runtime(runtime, name="governed_search",
    description="Policy-governed search", action_type="search", action_target="web")
```
</details>

<details>
<summary><b>OpenAI Agents SDK</b> -- decorator-based governance</summary>

```python
from aegis.adapters.openai_agents import governed_tool

@governed_tool(runtime=runtime, action_type="write", action_target="crm")
async def update_contact(name: str, email: str) -> str:
    """Update a CRM contact -- governed by Aegis policy."""
    return await crm.update(name=name, email=email)
```
</details>

<details>
<summary><b>CrewAI</b> -- governed tools for crews</summary>

```python
from aegis.adapters.crewai import AegisCrewAITool

tool = AegisCrewAITool(runtime=runtime, name="governed_search",
    description="Search with governance", action_type="search",
    action_target="web", fn=lambda query: do_search(query))
```
</details>

<details>
<summary><b>Anthropic Claude</b> -- govern tool_use calls</summary>

```python
from aegis.adapters.anthropic import govern_tool_call

for block in response.content:
    if block.type == "tool_use":
        result = await govern_tool_call(
            runtime=runtime, tool_name=block.name,
            tool_input=block.input, target="my_system")
```
</details>

<details>
<summary><b>httpx</b> -- governed REST API calls</summary>

```python
from aegis.adapters.httpx_adapter import HttpxExecutor

executor = HttpxExecutor(base_url="https://api.example.com",
    default_headers={"Authorization": "Bearer ..."})
runtime = Runtime(executor=executor, policy=Policy.from_yaml("policy.yaml"))

# Action types map to HTTP methods: get, post, put, patch, delete
plan = runtime.plan([Action("get", "/users"), Action("delete", "/users/1")])
```
</details>

<details>
<summary><b>MCP (Model Context Protocol)</b> -- govern any MCP tool call</summary>

```python
from aegis.adapters.mcp import govern_mcp_tool_call, AegisMCPToolFilter

# Option 1: Govern individual tool calls
result = await govern_mcp_tool_call(
    runtime=runtime, tool_name="read_file",
    arguments={"path": "/data.csv"}, server_name="filesystem")

# Option 2: Filter-based governance
tool_filter = AegisMCPToolFilter(runtime=runtime)
result = await tool_filter.check(server="filesystem", tool="delete_file")
if result.ok:
    # Proceed with actual MCP call
    pass
```
</details>

<details>
<summary><b>REST API</b> -- govern from any language</summary>

```bash
pip install 'agent-aegis[server]'
aegis serve policy.yaml --port 8000
```

```bash
# Evaluate an action (dry-run)
curl -X POST http://localhost:8000/api/v1/evaluate \
    -H "Content-Type: application/json" \
    -d '{"action_type": "delete", "target": "db"}'
# => {"risk_level": "CRITICAL", "approval": "block", "is_allowed": false}

# Execute through full governance pipeline
curl -X POST http://localhost:8000/api/v1/execute \
    -H "Content-Type: application/json" \
    -d '{"action_type": "read", "target": "crm"}'

# Query audit log
curl http://localhost:8000/api/v1/audit?action_type=delete

# Hot-reload policy
curl -X PUT http://localhost:8000/api/v1/policy \
    -H "Content-Type: application/json" \
    -d '{"yaml": "rules:\n  - name: block_all\n    match: {type: \"*\"}\n    approval: block"}'
```
</details>

<details>
<summary><b>Custom adapters</b> -- 10 lines to integrate anything</summary>

```python
from aegis.adapters.base import BaseExecutor
from aegis.core.action import Action
from aegis.core.result import Result, ResultStatus

class MyAPIExecutor(BaseExecutor):
    async def execute(self, action: Action) -> Result:
        response = await my_api.call(action.type, action.target, **action.params)
        return Result(action=action, status=ResultStatus.SUCCESS, data=response)

    async def verify(self, action: Action, result: Result) -> bool:
        return result.data.get("status") == "ok"
```
</details>

## Policy Conditions

Go beyond glob matching with smart conditions:

```yaml
rules:
  # Block writes after business hours
  - name: after_hours_block
    match: { type: "write*" }
    conditions:
      time_after: "18:00"
    risk_level: critical
    approval: block

  # Escalate bulk operations over threshold
  - name: large_bulk_ops
    match: { type: "update*" }
    conditions:
      param_gt: { count: 100 }
    risk_level: high
    approval: approve

  # Only allow deploys on weekdays
  - name: weekday_deploys
    match: { type: "deploy*" }
    conditions:
      weekdays: [1, 2, 3, 4, 5]
    risk_level: medium
    approval: approve
```

Available: `time_after`, `time_before`, `weekdays`, `param_eq`, `param_gt`, `param_lt`, `param_gte`, `param_lte`, `param_contains`, `param_matches` (regex).

## Architecture

```
aegis/
  core/        Action, Policy engine, Conditions, Risk levels, Retry, JSON Schema
  adapters/    BaseExecutor, Playwright, httpx, LangChain, CrewAI, OpenAI, Anthropic, MCP
  runtime/     Runtime engine, ApprovalHandler, AuditLogger (SQLite/JSONL/webhook/logging)
  server/      REST API (Starlette ASGI) -- evaluate, execute, audit, policy endpoints
  cli/         aegis validate | audit | schema | init | simulate | serve | stats
```

## Why Aegis?

There are many ways to add governance to AI agents. Here's how they compare:

### vs. Writing Your Own

| | DIY | Aegis |
|---|---|---|
| **Policy engine** | Custom if/else per action | YAML rules + glob + conditions |
| **Risk model** | Hardcoded | 4-tier with per-rule overrides |
| **Human approval** | Build your own | Pluggable (CLI, Slack, Discord, Telegram, email, webhook) |
| **Audit trail** | printf debugging | SQLite + JSONL + session tracking |
| **Framework support** | Rewrite per framework | 7 adapters out of the box |
| **Retry & rollback** | DIY error handling | Exponential backoff + automatic rollback |
| **Type safety** | Maybe | mypy strict, py.typed |
| **Time to integrate** | Days | Minutes |

### vs. Platform-Native Guardrails

OpenAI, Google, and Anthropic each ship built-in guardrails — but they only govern their own ecosystem. If your agent calls OpenAI **and** Anthropic, or uses LangChain **and** MCP tools, you need one governance layer that works across all of them. That's Aegis.

### vs. Enterprise Governance Platforms

Enterprise platforms like centralized control planes need Kubernetes clusters, cloud infrastructure, and procurement cycles. Aegis is a **library** — `pip install` and you have governance in 5 minutes. Start with a library, graduate to a platform when you need to.

## CLI

```bash
aegis init                              # Generate starter policy
aegis validate policy.yaml              # Validate policy syntax
aegis schema                            # Print JSON Schema (for editor autocomplete)
aegis simulate policy.yaml read:crm delete:db  # Test policies without executing
aegis audit                             # View audit log
aegis audit --session abc --format json # Filter + format
aegis audit --tail                      # Live monitoring
aegis audit --format jsonl -o export.jsonl  # Export
aegis stats                             # Policy rule statistics
aegis serve policy.yaml --port 8000     # Start REST API server
```

## Roadmap

| Version | Status | Features |
|---------|--------|----------|
| **0.1** | **Released** | Policy engine, 7 adapters (incl. MCP), CLI, audit (SQLite + JSONL + webhook), conditions, JSON Schema |
| **0.1.3** | **Released** | REST API server, retry/rollback, dry-run, hot-reload, policy merge, webhook approval/audit, Slack/Discord/Telegram/email approval, simulate CLI, runtime hooks, color-coded CLI, stats, live tail |
| **0.2** | Q2 2026 | Dashboard UI, rate limiting, queue-based async execution |
| **0.3** | Q3 2026 | Agent identity (`agent_id` in actions), policy hierarchy (org → team → agent), conflict detection |
| **0.4** | Q4 2026 | Multi-agent governance (delegation, chain tracing), centralized policy server, cross-agent audit correlation |
| **1.0** | 2027 | Distributed governance, policy versioning & rollback, multi-tenant REST API |

## Contributing

We welcome contributions! Check out:

- [**Good First Issues**](https://github.com/Acacian/aegis/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) -- great starting points
- [**Contributing Guide**](CONTRIBUTING.md) -- setup, code style, PR process
- [**Architecture**](ARCHITECTURE.md) -- how the codebase is structured

```bash
git clone https://github.com/Acacian/aegis.git && cd aegis
make dev      # Install deps + hooks
make test     # Run tests
make lint     # Lint + format check
make coverage # Coverage report
```

Or jump straight into a cloud environment:

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/Acacian/aegis)

## License

MIT -- see [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built for the era of autonomous AI agents.</sub><br/>
  <sub>If Aegis helps you, consider giving it a star -- it helps others find it too.</sub>
</p>
