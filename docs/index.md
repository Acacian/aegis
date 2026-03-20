# Aegis

**Open-source policy & approval runtime for AI agents acting on systems you don't own.**

## What is Aegis?

AI agents are getting access to external systems — Salesforce, Stripe, your internal tools — via browsers and APIs. Aegis is the governance layer that sits between the agent and those systems, ensuring every action goes through:

```
Policy check → Approval gate → Execute → Verify → Audit log
```

## Key Features

- **Policy Engine**: YAML rules with glob matching and smart conditions (time, params, weekday)
- **Approval Gates**: Human-in-the-loop confirmation for sensitive operations
- **Audit Trail**: SQLite, Python logging, or JSONL backends
- **Framework Integrations**: LangChain, CrewAI, OpenAI Agents SDK, Anthropic, Playwright, httpx
- **Pluggable**: Bring your own executor for any system
- **CLI**: `aegis init`, `aegis validate`, `aegis audit`, `aegis schema`
- **Type-safe**: Full type hints, `py.typed` marker, mypy-checked

## Quick Example

```python
from aegis import Action, Policy, Runtime
from aegis.adapters.httpx_adapter import HttpxExecutor

async with Runtime(
    executor=HttpxExecutor(base_url="https://api.example.com"),
    policy=Policy.from_yaml("policy.yaml"),
) as runtime:
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

## Links

- [GitHub](https://github.com/Acacian/aegis) — source code, issues, discussions
- [PyPI](https://pypi.org/project/agent-aegis/) — package page
- [CHANGELOG](https://github.com/Acacian/aegis/blob/main/CHANGELOG.md) — release history
- [ARCHITECTURE](https://github.com/Acacian/aegis/blob/main/ARCHITECTURE.md) — design decisions
