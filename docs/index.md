# Aegis

**The simplest way to govern AI agent actions. No infra. No lock-in. Just Python.**

`pip install agent-aegis` → YAML policy → governance in 5 minutes. Works with LangChain, CrewAI, OpenAI, Anthropic, MCP, and more.

[**Try it live in your browser**](playground/){ .md-button .md-button--primary } — no install needed.

---

## The Problem

AI agents are getting real-world access — calling APIs, modifying databases, running shell commands, browsing the web. Without governance, a single hallucination can:

- **Bulk-delete** your CRM contacts
- **Submit wrong forms** to government portals
- **Trigger irreversible API calls** at 3am
- **Run up cloud bills** with infinite loops

There's no `sudo` for AI agents. **Until now.**

## What is Aegis?

Aegis is a **Python library** (not a platform, not a server) that wraps every AI agent action with policy checks, approval gates, and audit logging:

```
Action      Policy        Approval       Execute     Audit
  |            |              |              |           |
read CRM  --> auto (low)  --> skip -------> run ------> logged
bulk edit --> approve (high) --> human y/n -> run ------> logged
delete *  --> block (critical) ------------> X --------> logged
```

**3 lines to add governance** to any Python AI agent:

```python
from aegis import Action, Policy, Runtime

runtime = Runtime(executor=your_executor, policy=Policy.from_yaml("policy.yaml"))
result = await runtime.run_one(Action("delete", "crm", params={"id": "all"}))
# Policy checked. Approval gated. Audit logged. Done.
```

## Key Features

| Feature | Description |
|---------|-------------|
| **YAML policies** | Glob matching, first-match-wins, JSON Schema for validation |
| **Smart conditions** | `time_after`, `time_before`, `weekdays`, `param_gt/lt/eq/contains/matches` |
| **4-tier risk model** | `low` / `medium` / `high` / `critical` with per-rule overrides |
| **7 approval handlers** | CLI, Slack, Discord, Telegram, email, webhook, or custom |
| **Audit trail** | SQLite + JSONL + webhook + Python `logging` — compliance-ready |
| **7 framework adapters** | LangChain, CrewAI, OpenAI Agents SDK, Anthropic Claude, Playwright, httpx, MCP |
| **REST API server** | `aegis serve policy.yaml` — govern from any language |
| **CLI tools** | `aegis init`, `validate`, `simulate`, `audit`, `stats`, `serve` |
| **Type-safe** | Full `mypy --strict`, `py.typed` marker |
| **< 1ms overhead** | Policy evaluation adds minimal latency to your agent |

## Real-World Use Cases

| Scenario | How Aegis Helps |
|----------|-----------------|
| **CRM Agent** | Read contacts freely, review updates, block mass deletes |
| **Code Agent** | Read files safely, review edits, block deploys to production |
| **Financial Agent** | View accounts, approve payments over threshold, block after-hours transfers |
| **Browser Agent** | Navigate freely, review form fills, block JavaScript execution |
| **Data Pipeline** | SELECT freely, review INSERTs to production, block DROP TABLE |
| **Compliance** | Every action logged with full context for SOC2/GDPR/HIPAA evidence |

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
pip install 'agent-aegis[anthropic]'      # Anthropic Claude
pip install 'agent-aegis[httpx]'          # REST APIs
pip install 'agent-aegis[playwright]'     # Browser automation
pip install 'agent-aegis[server]'         # REST API server
pip install 'agent-aegis[all]'            # Everything
```

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

    # Multiple actions with plan
    plan = runtime.plan([
        Action("get", "/users"),              # auto-execute (low risk)
        Action("post", "/users", params={"json": {"name": "Alice"}}),  # approve
        Action("delete", "/users/all"),       # blocked (critical risk)
    ])
    results = await runtime.execute(plan)
```

## Production Ready

| Aspect | Detail |
|--------|--------|
| **486 tests, 92% coverage** | Every adapter, handler, and edge case tested |
| **Type-safe** | `mypy --strict` with zero errors |
| **< 1ms evaluation** | Policy check adds negligible overhead |
| **Fail-safe** | Blocked actions never execute, period |
| **Audit immutability** | Results are frozen; audit writes happen before returning |
| **Zero external deps** | Core has no required infrastructure |

## Roadmap

| Version | Status | Features |
|---------|--------|----------|
| **0.1** | **Released** | Policy engine, 7 adapters (incl. MCP), CLI, audit, conditions, JSON Schema |
| **0.1.3** | **Released** | REST API server, retry/rollback, dry-run, hot-reload, policy merge, 7 approval handlers, runtime hooks |
| **0.1.4** | **Released** | Multi-agent foundations, PolicyHierarchy, performance optimizations, security hardening |
| **0.2** | Q2 2026 | Dashboard UI, rate limiting, queue-based async execution |
| **0.3** | Q3 2026 | Agent identity, cross-agent audit correlation |
| **0.4** | Q4 2026 | Multi-agent governance, centralized policy server |
| **1.0** | 2027 | Distributed governance, policy versioning, multi-tenant API |

## Links

- [GitHub](https://github.com/Acacian/aegis) — source code, issues, discussions
- [PyPI](https://pypi.org/project/agent-aegis/) — package page
- [Playground](playground/) — try Aegis in your browser
- [Contributing](https://github.com/Acacian/aegis/blob/main/CONTRIBUTING.md) — get involved
- [Changelog](https://github.com/Acacian/aegis/blob/main/CHANGELOG.md) — release history
- [Architecture](https://github.com/Acacian/aegis/blob/main/ARCHITECTURE.md) — design decisions
