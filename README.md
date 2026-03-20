<p align="center">
  <h1 align="center">Aegis</h1>
  <p align="center">
    <strong>Governance layer for AI agents. Policy engine + approval gate + audit log.</strong>
  </p>
  <p align="center">
    Your AI agent can browse the web, call APIs, and modify SaaS data.<br/>
    <strong>Aegis makes sure it asks permission first.</strong>
  </p>
</p>

<p align="center">
  <a href="https://github.com/Acacian/aegis/actions/workflows/ci.yml"><img src="https://github.com/Acacian/aegis/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/agent-aegis/"><img src="https://img.shields.io/pypi/v/agent-aegis?color=blue" alt="PyPI"></a>
  <a href="https://pypi.org/project/agent-aegis/"><img src="https://img.shields.io/pypi/dm/agent-aegis?color=green" alt="Downloads"></a>
  <a href="https://pypi.org/project/agent-aegis/"><img src="https://img.shields.io/pypi/pyversions/agent-aegis" alt="Python"></a>
  <a href="https://codecov.io/gh/Acacian/aegis"><img src="https://codecov.io/gh/Acacian/aegis/graph/badge.svg" alt="Coverage"></a>
  <a href="https://github.com/Acacian/aegis/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
  <a href="https://acacian.github.io/aegis/"><img src="https://img.shields.io/badge/docs-acacian.github.io%2Faegis-blue" alt="Docs"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
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

```
Action      Policy        Approval       Execute     Audit
  |            |              |              |           |
read CRM  --> auto (low)  --> skip -------> run ------> logged
bulk edit --> approve (high) --> human y/n -> run ------> logged
delete *  --> block (critical) ------------> X --------> logged
```

Aegis sits between your agent and the real world. **3 lines to add governance:**

```python
from aegis import Action, Policy, Runtime

runtime = Runtime(executor=your_executor, policy=Policy.from_yaml("policy.yaml"))
results = await runtime.run_one(Action("write", "salesforce", params={...}))
```

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
| **Approval gates** | CLI prompt, callback functions, or build your own (Slack, Discord, etc.) |
| **Audit trail** | SQLite (default), JSONL export, or Python `logging` backend |
| **Context manager** | `async with Runtime(...) as rt:` — auto setup/teardown |
| **Single-action mode** | `await runtime.run_one(action)` for simple cases |
| **JSON Schema** | `aegis schema` — auto-complete in VS Code / JetBrains |
| **Policy generator** | `aegis init` — starter policy in seconds |
| **Type-safe** | Full `mypy --strict` compliance, `py.typed` marker |

## Integrations

Works with the agent frameworks you already use:

```bash
pip install 'agent-aegis[langchain]'      # LangChain
pip install 'agent-aegis[crewai]'         # CrewAI
pip install 'agent-aegis[openai-agents]'  # OpenAI Agents SDK
pip install 'agent-aegis[httpx]'          # REST APIs
pip install 'agent-aegis[playwright]'     # Browser automation
pip install 'agent-aegis[all]'            # Everything
```

<details>
<summary><b>LangChain</b> — wrap tools or expose governed actions</summary>

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
<summary><b>OpenAI Agents SDK</b> — decorator-based governance</summary>

```python
from aegis.adapters.openai_agents import governed_tool

@governed_tool(runtime=runtime, action_type="write", action_target="crm")
async def update_contact(name: str, email: str) -> str:
    """Update a CRM contact — governed by Aegis policy."""
    return await crm.update(name=name, email=email)
```
</details>

<details>
<summary><b>CrewAI</b> — governed tools for crews</summary>

```python
from aegis.adapters.crewai import AegisCrewAITool

tool = AegisCrewAITool(runtime=runtime, name="governed_search",
    description="Search with governance", action_type="search",
    action_target="web", fn=lambda query: do_search(query))
```
</details>

<details>
<summary><b>Anthropic Claude</b> — govern tool_use calls</summary>

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
<summary><b>httpx</b> — governed REST API calls</summary>

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
<summary><b>Custom adapters</b> — 10 lines to integrate anything</summary>

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
  core/        Action, Policy engine, Conditions, Risk levels, JSON Schema
  adapters/    BaseExecutor, Playwright, httpx, LangChain, CrewAI, OpenAI, Anthropic
  runtime/     Runtime engine, ApprovalHandler, AuditLogger (SQLite/JSONL/logging)
  cli/         aegis validate | audit | schema | init
```

```
                    +----------------+
                    |   Your Agent   |
                    +-------+--------+
                            |
                     Action(type, target, params)
                            |
                    +-------v--------+
                    |  Policy Engine |  <-- policy.yaml (YAML rules + conditions)
                    +-------+--------+
                            |
                   PolicyDecision(risk, approval, rule)
                            |
              +-------------+-------------+
              |             |             |
         auto: LOW    approve: HIGH   block: CRITICAL
              |             |             |
              v      +------v------+      v
           execute   | Approval    |   blocked
              |      | Handler     |      |
              |      +------+------+      |
              |             |             |
              v             v             |
         +---------+   +---------+        |
         | Adapter |   | Adapter |        |
         +---------+   +---------+        |
              |             |             |
              v             v             v
         +------------------------------------+
         |          Audit Logger              |
         |   (SQLite / JSONL / logging)       |
         +------------------------------------+
```

## Why Not Build Your Own?

| | DIY | Aegis |
|---|---|---|
| **Policy engine** | Custom if/else per action | YAML rules + glob + conditions |
| **Risk model** | Hardcoded | 4-tier with per-rule overrides |
| **Human approval** | Build your own | Pluggable (CLI, Slack, custom) |
| **Audit trail** | printf debugging | SQLite + JSONL + session tracking |
| **Framework support** | Rewrite per framework | 6 adapters out of the box |
| **Verification** | Hope it worked | Post-execution verification hooks |
| **Type safety** | Maybe | mypy strict, py.typed |
| **Time to integrate** | Days | Minutes |

## CLI

```bash
aegis init                              # Generate starter policy
aegis validate policy.yaml              # Validate policy syntax
aegis schema                            # Print JSON Schema (for editor autocomplete)
aegis audit                             # View audit log
aegis audit --session abc --format json # Filter + format
aegis audit --format jsonl -o export.jsonl  # Export
```

## Roadmap

| Version | Status | Features |
|---------|--------|----------|
| **0.1** | **Released** | Policy engine, 6 adapters, CLI, audit (SQLite + JSONL), conditions, JSON Schema |
| **0.2** | Planned | Dashboard UI, Slack/Discord approval, policy inheritance, hot-reload |
| **0.3** | Planned | MCP server adapter, rollback support, webhook notifications |
| **0.4** | Planned | Multi-tenant policies, team approvals, cloud audit storage |

## Contributing

We welcome contributions! Check out:

- [**Good First Issues**](https://github.com/Acacian/aegis/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) — great starting points
- [**Contributing Guide**](CONTRIBUTING.md) — setup, code style, PR process
- [**Architecture**](ARCHITECTURE.md) — how the codebase is structured

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
