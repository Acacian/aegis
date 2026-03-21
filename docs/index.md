# Aegis

**Open-source policy & approval runtime for AI agents acting on systems you don't own.**

Your AI agent can browse the web, call APIs, and modify SaaS data. **Aegis makes sure it asks permission first.**

## What is Aegis?

AI agents are getting access to external systems -- Salesforce, Stripe, your internal tools -- via browsers and APIs. Aegis is the governance layer that sits between the agent and those systems:

```
Action      Policy        Approval       Execute     Audit
  |            |              |              |           |
read CRM  --> auto (low)  --> skip -------> run ------> logged
bulk edit --> approve (high) --> human y/n -> run ------> logged
delete *  --> block (critical) ------------> X --------> logged
```

## Key Features

| Feature | Description |
|---------|-------------|
| **YAML policies** | Glob matching, first-match-wins, JSON Schema for validation |
| **Smart conditions** | `time_after`, `time_before`, `weekdays`, `param_gt/lt/eq/contains/matches` |
| **4-tier risk model** | `low` / `medium` / `high` / `critical` with per-rule overrides |
| **Approval gates** | CLI prompt, callbacks, or build your own (Slack, Discord, etc.) |
| **Audit trail** | SQLite (default), JSONL export, or Python `logging` backend |
| **6 framework adapters** | LangChain, CrewAI, OpenAI Agents SDK, Anthropic Claude, Playwright, httpx |
| **CLI tools** | `aegis init`, `aegis validate`, `aegis audit`, `aegis schema` |
| **Type-safe** | Full `mypy --strict`, `py.typed` marker |

## Quick Example

```python
from aegis import Action, Policy, Runtime
from aegis.adapters.httpx_adapter import HttpxExecutor

async with Runtime(
    executor=HttpxExecutor(base_url="https://api.example.com"),
    policy=Policy.from_yaml("policy.yaml"),
) as runtime:
    # Single action
    result = await runtime.run_one(Action("get", "/users"))

    # Multiple actions
    plan = runtime.plan([
        Action("get", "/users"),              # auto-execute (low risk)
        Action("post", "/users", params={"json": {"name": "Alice"}}),  # approve
        Action("delete", "/users/all"),       # blocked (critical risk)
    ])
    results = await runtime.execute(plan)
```

## Install

```bash
pip install agent-aegis
aegis init  # Generate a starter policy
```

With integrations:

```bash
pip install 'agent-aegis[langchain]'      # LangChain
pip install 'agent-aegis[crewai]'         # CrewAI
pip install 'agent-aegis[openai-agents]'  # OpenAI Agents SDK
pip install 'agent-aegis[httpx]'          # REST APIs
pip install 'agent-aegis[playwright]'     # Browser automation
pip install 'agent-aegis[all]'            # Everything
```

## Roadmap

| Version | Status | Features |
|---------|--------|----------|
| **0.1** | **Released** | Policy engine, 6 adapters, CLI, audit, conditions, JSON Schema |
| **0.2** | Planned | Dashboard UI, Slack/Discord approval, policy inheritance |
| **0.3** | Planned | MCP server adapter, rollback support, webhooks |
| **0.4** | Planned | Multi-tenant policies, team approvals, cloud audit |

## Links

- [GitHub](https://github.com/Acacian/aegis) -- source code, issues, discussions
- [PyPI](https://pypi.org/project/agent-aegis/) -- package page
- [Contributing](https://github.com/Acacian/aegis/blob/main/CONTRIBUTING.md) -- get involved
- [Changelog](https://github.com/Acacian/aegis/blob/main/CHANGELOG.md) -- release history
- [Architecture](https://github.com/Acacian/aegis/blob/main/ARCHITECTURE.md) -- design decisions
