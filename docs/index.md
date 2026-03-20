# Aegis

**Open-source policy & approval runtime for AI agents acting on systems you don't own.**

## What is Aegis?

AI agents are getting access to external systems — Salesforce, Stripe, your internal tools — via browsers and APIs. Aegis is the governance layer that sits between the agent and those systems, ensuring every action goes through:

```
Policy check → Approval gate → Execute → Verify → Audit log
```

## Key Features

- **Policy Engine**: YAML-based rules that classify actions by risk level and set approval requirements
- **Approval Gates**: Human-in-the-loop confirmation for sensitive operations
- **Audit Trail**: Every decision and result logged to SQLite
- **Framework Integrations**: LangChain, CrewAI, OpenAI Agents SDK, Playwright
- **Pluggable**: Bring your own executor for any system

## Quick Example

```python
from aegis import Action, Policy, Runtime
from aegis.adapters.playwright import PlaywrightExecutor

runtime = Runtime(
    executor=PlaywrightExecutor(),
    policy=Policy.from_yaml("policy.yaml"),
)

plan = runtime.plan([
    Action("read", target="salesforce", params={"selector": ".contacts"}),
    Action("delete", target="salesforce", params={"id": "all"}),
])

# read → auto-executes (low risk)
# delete → blocked by policy (critical risk)
results = await runtime.execute(plan)
```

## Install

```bash
pip install agent-aegis
```

With integrations:

```bash
pip install 'agent-aegis[langchain]'      # LangChain
pip install 'agent-aegis[crewai]'         # CrewAI
pip install 'agent-aegis[openai-agents]'  # OpenAI Agents SDK
pip install 'agent-aegis[all]'            # Everything
```
