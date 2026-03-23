<!-- mcp-name: io.github.Acacian/aegis -->
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
  <a href="https://pypi.org/project/langchain-aegis/"><img src="https://img.shields.io/pypi/v/langchain-aegis?label=langchain-aegis&color=blue&cacheSeconds=3600" alt="langchain-aegis"></a>
  <a href="https://pypi.org/project/agent-aegis/"><img src="https://img.shields.io/pypi/pyversions/agent-aegis?cacheSeconds=3600" alt="Python"></a>
  <a href="https://github.com/Acacian/aegis/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
  <a href="https://acacian.github.io/aegis/"><img src="https://img.shields.io/badge/docs-acacian.github.io%2Faegis-blue" alt="Docs"></a>
  <a href="https://pypi.org/project/agent-aegis/"><img src="https://img.shields.io/pypi/dm/agent-aegis?label=downloads&color=brightgreen" alt="Downloads"></a>
  <a href="https://github.com/Acacian/aegis"><img src="https://img.shields.io/github/stars/Acacian/aegis?style=social" alt="GitHub stars"></a>
  <br/>
  <a href="https://github.com/Acacian/aegis/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/tests-1642_passed-brightgreen" alt="Tests"></a>
  <a href="https://github.com/Acacian/aegis/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/coverage-92%25-brightgreen" alt="Coverage"></a>
  <a href="https://acacian.github.io/aegis/playground/"><img src="https://img.shields.io/badge/playground-Try_it_Live-ff6b6b" alt="Playground"></a>
</p>

<p align="center">
  <a href="https://acacian.github.io/aegis/playground/"><strong>Try it Live in Your Browser</strong></a> &bull;
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

**Copy, paste, run — zero config needed:**

```python
from aegis import Action, Policy

policy = Policy.from_dict({
    "version": "1",
    "defaults": {"risk_level": "low", "approval": "auto"},
    "rules": [{"name": "block_delete", "match": {"type": "delete_*"},
               "risk_level": "critical", "approval": "block"}]
})

safe = policy.evaluate(Action(type="read_users", target="db"))
print(safe.approval)   # Approval.AUTO  ✅

danger = policy.evaluate(Action(type="delete_users", target="db"))
print(danger.approval)  # Approval.BLOCK 🚫
```

Or with a YAML file — **3 lines:**

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
| **Semantic conditions** | Two-tier architecture: built-in keyword matching + pluggable LLM evaluator protocol |
| **4-tier risk model** | `low` / `medium` / `high` / `critical` with per-rule overrides |
| **Approval gates** | CLI, Slack, Discord, Telegram, email, webhook, or custom |
| **Audit trail** | SQLite, JSONL export, Python `logging`, or webhook to external SIEM |
| **Behavioral anomaly detection** | Learns per-agent behavior profiles; detects rate spikes, bursts, new actions, unusual targets |
| **Compliance reports** | Generate SOC2/GDPR/governance reports from audit logs with scoring |
| **Policy diff & impact** | Compare policies, replay actions, analyze impact of rule changes |
| **Agent trust chain** | Hierarchical identity, delegation with intersection semantics, cascade revocation |
| **`aegis scan`** | AST-based static analysis detecting ungoverned AI tool calls in your codebase |
| **`aegis score`** | Governance scoring (0-100) with shields.io badge generation |
| **REST API server** | `aegis serve policy.yaml` -- govern from any language via HTTP |
| **Web Dashboard** | Real-time governance dashboard with KPIs, audit log, compliance reports, anomaly detection |
| **MCP adapter** | Govern Model Context Protocol tool calls |
| **Retry & rollback** | Exponential backoff, error filters, automatic rollback on failure |
| **Dry-run & simulate** | Test policies without executing: `aegis simulate policy.yaml read:crm` |
| **Hot-reload** | `runtime.update_policy(...)` -- swap policies without restart |
| **Policy merge** | `Policy.from_yaml_files("base.yaml", "prod.yaml")` -- layer configs |
| **Runtime hooks** | Async callbacks for `on_decision`, `on_approval`, `on_execute` |
| **Rate limiter** | Per-agent and global sliding-window rate limits with glob matching |
| **RBAC** | 12 granular permissions, 5 hierarchical roles (viewer → super_admin), thread-safe |
| **Policy versioning** | Git-like commit, diff, rollback, tagging with JSON persistence |
| **Multi-tenant isolation** | `TenantContext` (contextvars), tenant registry, quota enforcement, data isolation |
| **Cryptographic audit chain** | SHA-256/SHA3-256 hash-linked tamper-evident audit trail for EU AI Act Art.12 |
| **Regulatory mapper** | EU AI Act, NIST AI RMF, SOC2, ISO 42001 gap analysis with evidence generation |
| **Webhook notifications** | Slack, PagerDuty, generic JSON with severity filtering |
| **Action replay** | What-if policy analysis by replaying historical actions against new rules |
| **Policy-as-Code SDK** | Fluent `PolicyBuilder` API for programmatic policy construction |
| **Policy testing framework** | Automated rule testing, regression detection, test auto-generation |
| **GitHub Action** | CI/CD governance gates: `aegis validate`, `aegis scan`, `aegis score` in your pipeline |
| **Natural language policies** | `aegis autopolicy "block deletes, allow reads"` -- generates YAML from English (Tier 1: keyword, Tier 2: LLM) |
| **Adversarial probe** | `aegis probe policy.yaml` -- automated gap detection: glob bypass, escalation, missing coverage |
| **Real-time monitor** | Terminal dashboard for live governance activity |
| **Type-safe** | Full `mypy --strict` compliance, `py.typed` marker |
| **9 policy templates** | Pre-built for CRM, code, finance, browser, DevOps, healthcare, and more |
| **Interactive playground** | [Try in browser](https://acacian.github.io/aegis/playground/) -- no install needed |
| **Docker ready** | [`examples/docker/`](examples/docker/) -- deploy REST API in one command |

## Real-World Use Cases

| Scenario | Policy | Outcome |
|----------|--------|---------|
| **Finance** | Block bulk transfers > $10K without CFO approval | Agents can process invoices safely; large amounts trigger Slack approval |
| **SaaS Ops** | Auto-approve reads; require approval for account mutations | Support agents handle tickets without accidentally deleting accounts |
| **DevOps** | Allow deploys Mon-Fri 9-5; block after hours | CI/CD agents can't push to prod at 3am |
| **Data Pipeline** | Block DELETE on production tables; auto-approve staging | ETL agents can't drop prod data, even if the LLM hallucinates |
| **Compliance** | Log every external API call with full context | Auditors get a complete trail for SOC2 / GDPR evidence |

## Policy Templates

Pre-built YAML policies for common industries. Copy one, customize it, deploy:

| Template | Use Case | Key Rules |
|----------|----------|-----------|
| [`crm-agent.yaml`](policies/crm-agent.yaml) | Salesforce, HubSpot, CRM | Read=auto, Write=approve, Delete=block |
| [`code-agent.yaml`](policies/code-agent.yaml) | Cursor, Copilot, Aider | Read=auto, Shell=high, Deploy=block |
| [`financial-agent.yaml`](policies/financial-agent.yaml) | Payments, invoicing | View=auto, Payments=approve, Transfers=critical |
| [`browser-agent.yaml`](policies/browser-agent.yaml) | Playwright, Selenium | Navigate=auto, Click=approve, JS eval=block |
| [`data-pipeline.yaml`](policies/data-pipeline.yaml) | ETL, database ops | SELECT=auto, INSERT=approve, DROP=block |
| [`devops-agent.yaml`](policies/devops-agent.yaml) | CI/CD, infrastructure | Monitor=auto, Deploy=approve, Destroy=block |
| [`healthcare-agent.yaml`](policies/healthcare-agent.yaml) | Healthcare, HIPAA | Search=auto, PHI=approve, Delete=block |
| [`ecommerce-agent.yaml`](policies/ecommerce-agent.yaml) | Online stores | View=auto, Refund=approve, Delete=block |
| [`support-agent.yaml`](policies/support-agent.yaml) | Customer support | Read=auto, Respond=approve, Delete=block |

```python
policy = Policy.from_yaml("policies/crm-agent.yaml")
```

## Production Ready

| Aspect | Detail |
|--------|--------|
| **1,642+ tests, 92% coverage** | Every adapter, handler, and edge case tested |
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
pip install langchain-aegis               # LangChain (standalone integration)
pip install 'agent-aegis[langchain]'      # LangChain (adapter)
pip install 'agent-aegis[crewai]'         # CrewAI
pip install 'agent-aegis[openai-agents]'  # OpenAI Agents SDK
pip install 'agent-aegis[anthropic]'      # Anthropic Claude
pip install 'agent-aegis[httpx]'          # Webhook approval/audit
pip install 'agent-aegis[playwright]'     # Browser automation
pip install 'agent-aegis[server]'         # REST API server
pip install 'agent-aegis[all]'            # Everything
```

<details>
<summary><b>LangChain</b> -- govern any LangChain tool with one function call</summary>

**Option A: `langchain-aegis` (recommended)** — standalone integration package

```bash
pip install langchain-aegis
```

```python
from langchain_aegis import govern_tools

# Add governance to existing tools — no other code changes
governed = govern_tools(tools, policy="policy.yaml")
agent = create_react_agent(model, governed)
```

**Option B: `agent-aegis[langchain]`** — adapter-based

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
<summary><b>MCP Server</b> -- one-click governance for Claude, Cursor, VS Code, Windsurf</summary>

```bash
pip install 'agent-aegis[mcp]'
aegis-mcp-server --policy policy.yaml
```

**Claude Desktop** — add to `~/Library/Application Support/Claude/claude_desktop_config.json`:
```json
{ "mcpServers": { "aegis": { "command": "uvx", "args": ["--from", "agent-aegis[mcp]", "aegis-mcp-server"] }}}
```

**Cursor** — add to `.cursor/mcp.json`:
```json
{ "mcpServers": { "aegis": { "command": "uvx", "args": ["--from", "agent-aegis[mcp]", "aegis-mcp-server"] }}}
```

**VS Code Copilot** — add to `.vscode/mcp.json`:
```json
{ "servers": { "aegis": { "command": "uvx", "args": ["--from", "agent-aegis[mcp]", "aegis-mcp-server"] }}}
```

**Windsurf** — add to `~/.codeium/windsurf/mcp_config.json`:
```json
{ "mcpServers": { "aegis": { "command": "uvx", "args": ["--from", "agent-aegis[mcp]", "aegis-mcp-server"] }}}
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

### Semantic Conditions

Go beyond keyword matching with the two-tier semantic conditions engine:

```yaml
rules:
  - name: block_harmful_content
    match: { type: "generate*" }
    conditions:
      semantic: "contains harmful, violent, or illegal content"
    risk_level: critical
    approval: block
```

Tier 1 uses fast built-in keyword matching. Tier 2 plugs in any LLM evaluator via the `SemanticEvaluator` protocol -- bring your own model for nuanced content analysis.

## Governance Dashboard

Built-in web dashboard for real-time agent governance monitoring. No separate frontend build needed.

```bash
# Quick start
pip install 'agent-aegis[server]'
aegis serve policy.yaml

# Open http://localhost:8000
```

**7 dashboard pages:**

| Page | What it shows |
|------|---------------|
| **Overview** | KPI cards, action volume chart, risk distribution, compliance grade |
| **Audit Log** | Filterable/paginated history of all agent actions and decisions |
| **Policy** | Current rules, governance score (0-100), score breakdown |
| **Anomalies** | Agent behavior profiles, block rates, anomaly alerts |
| **Compliance** | SOC2/GDPR/governance reports with findings and letter grades |
| **Regulatory** | EU AI Act, NIST, SOC2, ISO 42001 gap analysis |
| **System** | Health status, version, API endpoints |

**11 REST API endpoints** under `/api/v1/dashboard/` -- use programmatically or through the UI.

```python
# Programmatic access
from aegis.server.app import create_app

app = create_app(
    policy_path="policy.yaml",
    audit_db_path="audit.db",
    enable_dashboard=True,
    anomaly_detector=detector,  # optional
)
```

## Deep Features

Advanced capabilities for production-grade agent governance.

### Behavioral Anomaly Detection

Aegis learns per-agent behavior profiles and automatically detects anomalies -- no manual threshold tuning required.

```python
from aegis.core.anomaly import AnomalyDetector

detector = AnomalyDetector()

# Feed observed actions to build per-agent behavior profiles
detector.observe(agent_id="agent-1", action_type="read", target="crm")
detector.observe(agent_id="agent-1", action_type="read", target="crm")
detector.observe(agent_id="agent-1", action_type="read", target="crm")

# Detect anomalies: rate spikes, bursts, new actions, unusual targets, high block rates
alerts = detector.check(agent_id="agent-1", action_type="delete", target="prod_db")
# => [Anomaly(type=NEW_ACTION, detail="action 'delete' never seen for agent-1")]

# Auto-generate a policy from observed behavior
learned_policy = detector.generate_policy(agent_id="agent-1")
```

Detects: **rate spikes** | **burst patterns** | **never-seen actions** | **unusual targets** | **high block rates**

### Compliance Report Generator

Generate audit-ready compliance reports from your existing audit logs. No additional tooling needed.

```bash
aegis compliance --type soc2 --output report.json
aegis compliance --type gdpr --output gdpr-report.json
aegis compliance --type governance --days 30
```

```python
from aegis.core.compliance import ComplianceReporter

reporter = ComplianceReporter(audit_store=runtime.audit_store)
report = await reporter.generate(report_type="soc2", days=90)

print(report.score)        # 87.5
print(report.findings)     # List of findings with severity
print(report.evidence)     # Linked audit log entries
```

Supported report types: **SOC2** | **GDPR** | **Governance** -- each with scoring, findings, and evidence links.

### Policy Diff & Impact Analysis

Compare two policy files and understand exactly what changed and what impact it will have.

```bash
# Show added/removed/modified rules between two policies
aegis diff policy-v1.yaml policy-v2.yaml

# Replay historical actions against the new policy to see impact
aegis diff policy-v1.yaml policy-v2.yaml --replay audit.db
```

```
 Rules: 2 added, 1 removed, 3 modified

 + bulk_write_block     CRITICAL/block   (new)
 + pii_access_approve   HIGH/approve     (new)
 - legacy_allow_all     LOW/auto         (removed)
 ~ read_safe            LOW/auto → LOW/auto  conditions changed
 ~ deploy_prod          HIGH/approve → CRITICAL/block  risk escalated
 ~ bulk_ops             MEDIUM/approve   param_gt.count: 100 → 50

 Impact (replayed 1,247 actions):
   23 actions would change from AUTO → BLOCK
    7 actions would change from APPROVE → BLOCK
```

### Agent Trust Chain

Hierarchical agent identity with delegation and capability-scoped trust.

```python
from aegis.core.trust import TrustChain, AgentIdentity, Capability

# Create a root agent with full capabilities
root = AgentIdentity(
    agent_id="orchestrator",
    capabilities=[Capability("*")],  # glob matching
)

# Delegate a subset of capabilities (intersection semantics)
worker = root.delegate(
    agent_id="data-worker",
    capabilities=[Capability("read:*"), Capability("write:staging_*")],
)

# Worker can only do what both root AND delegation allow
chain = TrustChain()
chain.register(root)
chain.register(worker, parent=root)

# Verify capability at runtime
chain.can(worker, "read:crm")           # True
chain.can(worker, "delete:prod_db")     # False -- not in delegation

# Cascade revocation: revoking parent revokes all children
chain.revoke(root)
chain.can(worker, "read:crm")           # False
```

### Rate Limiter

Per-agent and global sliding-window rate limiting with glob-pattern matching on agent IDs.

```python
from aegis.core.rate_limiter import RateLimiter

limiter = RateLimiter()
limiter.add_rule("agent-*", max_requests=100, window_seconds=60)
limiter.add_rule("agent-untrusted", max_requests=10, window_seconds=60)

limiter.check("agent-untrusted", action_type="write")  # True (allowed)
# After 10 calls in 60s:
limiter.check("agent-untrusted", action_type="write")  # False (rate limited)
```

### RBAC (Role-Based Access Control)

12 granular permissions across 5 hierarchical roles. Thread-safe `AccessController` for multi-agent environments.

```python
from aegis.core.rbac import AccessController, Role

ac = AccessController()
ac.assign_role("alice", Role.ADMIN)
ac.assign_role("bot-1", Role.OPERATOR)

ac.check("alice", "policy:write")   # True
ac.check("bot-1", "policy:write")   # False -- operators can execute, not configure
ac.check("bot-1", "action:execute") # True
```

Roles: `viewer` < `operator` < `admin` < `policy_admin` < `super_admin`

### Policy Versioning

Git-like policy version control with commit, diff, rollback, and tagging.

```python
from aegis.core.versioning import PolicyVersionStore

store = PolicyVersionStore("./policy-versions.json")
store.commit(policy, message="Initial production policy")
store.tag("v1.0")

# Later...
store.commit(updated_policy, message="Relax read rules")
diff = store.diff("v1.0", "HEAD")   # See what changed
store.rollback("v1.0")               # Revert to tagged version
```

### Multi-Tenant Isolation

Context-based tenant isolation with quota enforcement and data separation.

```python
from aegis.core.tenant import TenantContext, TenantRegistry, TenantIsolation

registry = TenantRegistry()
registry.register("acme-corp", quota={"max_actions_per_hour": 1000})

with TenantContext("acme-corp"):
    # All policy evaluations, audit writes, and rate limits
    # are automatically scoped to this tenant
    result = await runtime.run_one(action)
```

### Cryptographic Audit Chain

Tamper-evident audit trail with hash-linked entries. Meets EU AI Act Article 12 and SOC2 CC7.2 requirements.

```bash
aegis audit --verify              # Verify chain integrity
aegis audit --export-chain        # Export full hash chain
aegis audit --evidence soc2       # Generate compliance evidence package
```

```python
from aegis.core.crypto_audit import CryptoAuditLogger

logger = CryptoAuditLogger(algorithm="sha3-256")
# Each entry is hash-linked to the previous -- any tampering breaks the chain
logger.log(action, decision, result)
assert logger.verify_chain()  # True if untampered
```

### Regulatory Compliance Mapper

Maps your governance posture against EU AI Act, NIST AI RMF, SOC2, and ISO 42001. Identifies gaps and generates evidence.

```bash
aegis regulatory --framework eu-ai-act    # Gap analysis
aegis regulatory --framework nist-ai-rmf  # NIST mapping
aegis regulatory --all --output report.json
```

29 regulatory requirements mapped across 4 frameworks with automatic evidence collection from audit logs.

### Natural Language Policy Generation

Generate YAML policies from plain English. Two tiers: built-in keyword parser (no dependencies) and pluggable LLM evaluator (bring your own API key).

```bash
aegis autopolicy "block all deletes on production, allow reads, require approval for writes over $10K"
```
```yaml
# Generated output:
version: '1'
defaults:
  risk_level: medium
  approval: approve
rules:
- name: delete_block
  match: { type: "delete*", target: "prod*" }
  risk_level: critical
  approval: block
- name: read_auto
  match: { type: "read*" }
  risk_level: low
  approval: auto
```

Tier 2 (LLM-backed): implement the `PolicyGenerator` protocol with your preferred provider (OpenAI, Anthropic, etc.) -- same pattern as `SemanticEvaluator`.

### Adversarial Policy Probe

Automated testing for governance gaps. Probes for glob bypasses, missing coverage, escalation patterns, and overly permissive defaults.

```bash
aegis probe policy.yaml

# Aegis Policy Probe — 205 probes
# ==================================================
#   Robustness score: 72/100
#   Findings: 8
#
#   CRITICAL [missing_coverage]
#     Destructive action 'drop' on 'production' is auto-approved
#     -> Add a rule to block or require approval for 'drop' actions
#
#   HIGH [glob_bypass]
#     'bulk_delete' bypasses block rule 'no_deletes' (pattern: 'delete')
#     -> Broaden the glob pattern to 'delete*' or add a rule for 'bulk_delete'
```

Probe categories: **missing coverage** | **glob bypass** | **default fallthrough** | **escalation patterns** | **target gaps** | **wildcard rules**

### `aegis scan` -- Static Analysis

AST-based scanner that detects ungoverned AI tool calls in your Python codebase.

```bash
aegis scan ./src/

# Output:
# src/agents/mailer.py:42  openai.ChatCompletion.create()  -- ungoverned
# src/agents/writer.py:18  anthropic.messages.create()     -- ungoverned
# src/tools/search.py:7    langchain tool "web_search"     -- ungoverned
#
# 3 ungoverned calls found. Run `aegis score` for governance coverage.
```

### `aegis score` -- Governance Score

Quantify your governance coverage with a 0-100 score and generate a shields.io badge.

```bash
aegis score ./src/ --policy policy.yaml

# Governance Score: 84/100
#   Governed calls:   21/25 (84%)
#   Policy coverage:  18 rules covering 6 action types
#   Anomaly detection: enabled
#   Audit trail:       enabled
#
# Badge: https://img.shields.io/badge/aegis_score-84-brightgreen
```

Add the badge to your repo:
```markdown
![Aegis Score](https://img.shields.io/badge/aegis_score-84-brightgreen)
```

## Architecture

```
aegis/
  core/              Action, Policy engine, Conditions, Risk levels, Retry, JSON Schema
  core/anomaly       Behavioral anomaly detection -- per-agent profiling, auto-policy generation
  core/compliance    Compliance report generator -- SOC2, GDPR, governance scoring
  core/trust         Agent trust chain -- hierarchical identity, delegation, revocation
  core/semantic      Semantic conditions engine -- keyword matching + LLM evaluator protocol
  core/diff          Policy diff & impact analysis -- rule comparison, action replay
  core/rate_limiter  Per-agent/global sliding-window rate limiting
  core/rbac          Role-based access control -- 12 permissions, 5 roles, AccessController
  core/versioning    Policy version control -- commit, diff, rollback, tagging
  core/tenant        Multi-tenant isolation -- context, registry, quota enforcement
  core/crypto_audit  Cryptographic audit chain -- hash-linked tamper-evident logs
  core/replay        Action replay engine -- what-if policy analysis
  core/regulatory    EU AI Act / NIST / SOC2 / ISO 42001 compliance mapper
  core/webhooks      Webhook notifications -- Slack, PagerDuty, JSON
  core/builder       Policy-as-Code SDK -- fluent PolicyBuilder API
  core/autopolicy    Natural language -> YAML policy generation (keyword + LLM)
  core/probe         Adversarial policy testing -- gap detection, bypass attempts
  core/tiers         Enterprise tier system -- feature gating with soft nudge
  adapters/          BaseExecutor, Playwright, httpx, LangChain, CrewAI, OpenAI, Anthropic, MCP
  runtime/           Runtime engine, ApprovalHandler, AuditLogger (SQLite/JSONL/webhook/logging)
  server/            REST API (Starlette ASGI) -- evaluate, execute, audit, policy endpoints
  cli/               aegis validate | audit | schema | init | simulate | serve | stats |
                     scan | score | diff | compliance | regulatory | monitor
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
aegis serve policy.yaml --port 8000     # Start REST API + dashboard (http://localhost:8000)
aegis scan ./src/                       # Detect ungoverned AI tool calls (AST-based)
aegis score ./src/ --policy policy.yaml # Governance score (0-100) + badge
aegis diff policy-v1.yaml policy-v2.yaml           # Compare policies
aegis diff policy-v1.yaml policy-v2.yaml --replay  # Impact analysis with action replay
aegis compliance --type soc2 --output report.json  # Generate compliance report
aegis autopolicy "block deletes, allow reads"      # Generate policy from English
aegis probe policy.yaml                            # Adversarial policy testing
```

## Roadmap

| Version | Status | Features |
|---------|--------|----------|
| **0.1** | **Released** | Policy engine, 7 adapters (incl. MCP), CLI, audit (SQLite + JSONL + webhook), conditions, JSON Schema |
| **0.1.3** | **Released** | REST API server, retry/rollback, dry-run, hot-reload, policy merge, Slack/Discord/Telegram/email approval, simulate CLI, runtime hooks, stats, live tail |
| **0.1.4** | **Released** | Multi-agent foundations (agent_id, PolicyHierarchy, conflict detection), performance optimizations (compiled globs, batch audit, eval cache), security hardening, MCP/LangChain/CrewAI/OpenAI cookbooks |
| **0.1.5** | **Released** | Behavioral anomaly detection, compliance report generator (SOC2/GDPR), policy diff & impact analysis, semantic conditions engine, agent trust chain, `aegis scan` (static analysis), `aegis score` (governance scoring + badge) |
| **0.1.7** | **Released** | Cryptographic audit chain, rate limiter, RBAC, policy versioning, multi-tenant isolation, regulatory mapper (EU AI Act/NIST/SOC2/ISO 42001), webhook notifications, action replay, PolicyBuilder SDK, policy testing framework, real-time monitor, GitHub Action |
| **0.1.9** | **Released** | Web governance dashboard (7 pages, 11 API endpoints), `aegis serve` with dashboard, natural language autopolicy, adversarial probe |
| **0.2** | Q2 2026 | Queue-based async execution, WebSocket real-time updates |
| **0.3** | Q3 2026 | Centralized policy server, cross-agent audit correlation |
| **1.0** | 2027 | Distributed governance, hosted SaaS, SSO/SCIM |

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

## Badge

Using Aegis? Add a badge to your project:

```markdown
[![Governed by Aegis](https://img.shields.io/badge/governed%20by-aegis-blue?logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIj48dGV4dCB5PSIuOWVtIiBmb250LXNpemU9IjkwIj7wn5uh77iPPC90ZXh0Pjwvc3ZnPg==)](https://github.com/Acacian/aegis)
```

[![Governed by Aegis](https://img.shields.io/badge/governed%20by-aegis-blue?logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIj48dGV4dCB5PSIuOWVtIiBmb250LXNpemU9IjkwIj7wn5uh77iPPC90ZXh0Pjwvc3ZnPg==)](https://github.com/Acacian/aegis)

## License

MIT -- see [LICENSE](LICENSE) for details.

Copyright (c) 2026 구동하 (Dongha Koo, [@Acacian](https://github.com/Acacian)). Created March 21, 2026.

---

<p align="center">
  <sub>Built for the era of autonomous AI agents.</sub><br/>
  <sub>If Aegis helps you, consider giving it a star -- it helps others find it too.</sub>
</p>
