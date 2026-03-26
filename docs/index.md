# Aegis

**OpenTelemetry for AI agent security. Auto-instrument any AI framework with guardrails -- zero code changes.**

`pip install agent-aegis` and add one line. Aegis monkey-patches LangChain, CrewAI, OpenAI Agents SDK, OpenAI, and Anthropic at runtime -- every LLM call and tool invocation passes through prompt-injection detection, PII masking, toxicity filtering, and a full audit trail.

[**Try it live in your browser**](playground/){ .md-button .md-button--primary } -- no install needed.

---

## The Fastest Way to Add AI Agent Security

```python
import aegis
aegis.auto_instrument()

# That's it. Every AI call in your app is now governed.
# Prompt injection detection, PII masking, toxicity filtering, audit trail -- all active.
```

Or zero code changes -- just set an environment variable:

```bash
AEGIS_INSTRUMENT=1 python my_agent.py
```

Aegis detects which AI frameworks are installed and monkey-patches them at runtime, the same approach used by OpenTelemetry for observability and Sentry for error tracking. Your existing code stays untouched.

## Supported Frameworks

| Framework | What gets patched | Status |
|-----------|------------------|--------|
| **LangChain** | `BaseChatModel.invoke/ainvoke`, `BaseTool.invoke/ainvoke` | Stable |
| **CrewAI** | `Crew.kickoff/kickoff_async`, global `BeforeToolCallHook` | Stable |
| **OpenAI Agents SDK** | `Runner.run`, `Runner.run_sync` | Stable |
| **OpenAI API** | `Completions.create` (chat & completions) | Stable |
| **Anthropic API** | `Messages.create` | Stable |

Default guardrails (all deterministic, no LLM calls, sub-millisecond):

- **Prompt injection detection** -- 10 attack categories, 85+ patterns, multi-language (block)
- **Toxicity detection** -- harmful/abusive content (block)
- **PII detection** -- 12 categories including credit cards, SSN, API keys (warn)
- **Prompt leak detection** -- system prompt extraction attempts (warn)

## Beyond Auto-Instrumentation

Aegis is also a full security framework with YAML policy engine, approval gates, audit trail, and compliance reporting:

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
| **Auto-instrumentation** | `aegis.auto_instrument()` -- one line governs LangChain, CrewAI, OpenAI, Anthropic |
| **Runtime guardrails** | PII detection (12 categories), prompt injection (85+ patterns), toxicity, prompt leak |
| **YAML policies** | Glob matching, first-match-wins, JSON Schema for validation |
| **Smart conditions** | `time_after`, `time_before`, `weekdays`, `param_gt/lt/eq/contains/matches` |
| **4-tier risk model** | `low` / `medium` / `high` / `critical` with per-rule overrides |
| **7 approval handlers** | CLI, Slack, Discord, Telegram, email, webhook, or custom |
| **Audit trail** | SQLite + JSONL + webhook + Python `logging` -- auditor-ready evidence export |
| **7 framework adapters** | LangChain, CrewAI, OpenAI Agents SDK, Anthropic Claude, Playwright, httpx, MCP |
| **REST API server** | `aegis serve policy.yaml` -- govern from any language |
| **Web dashboard** | Real-time security dashboard with compliance reports and anomaly detection |
| **CLI tools** | `aegis init`, `validate`, `simulate`, `audit`, `serve`, `scan`, `score`, `probe` |
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
```

The fastest path -- auto-instrument everything:

```python
import aegis
aegis.auto_instrument()
```

For manual control, install specific integrations:

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
| **3,860+ tests** | Every adapter, handler, and edge case tested |
| **Type-safe** | `mypy --strict` with zero errors |
| **< 1ms evaluation** | Policy check adds negligible overhead |
| **Fail-safe** | Blocked actions never execute, period |
| **Audit immutability** | Results are frozen; audit writes happen before returning |
| **Clean patching** | Auto-instrumentation is fully reversible via `reset()`, idempotent, skip-if-missing |

## Roadmap

| Version | Status | Features |
|---------|--------|----------|
| **0.1** | **Released** | Policy engine, 7 adapters, CLI, audit, conditions, JSON Schema |
| **0.1.3** | **Released** | REST API, retry/rollback, dry-run, hot-reload, 7 approval handlers |
| **0.1.7** | **Released** | Crypto audit chain, RBAC, rate limiter, regulatory mapper, anomaly detection, policy versioning |
| **0.1.9** | **Released** | Web dashboard, autopolicy (NL to YAML), adversarial probe, multi-tenant isolation |
| **0.2** | **Released** | WebSocket real-time streaming, interactive playground, policy editor, shields.io badge |
| **0.4** | **Released** | `aegis.init()`, runtime guardrails, AGEF/AGP open governance specs |
| **0.4.2** | **Released** | **Auto-instrumentation** -- `aegis.auto_instrument()` for LangChain, CrewAI, OpenAI Agents SDK, OpenAI, Anthropic |
| **0.5** | **Released** | Auto-instrumentation for LiteLLM, Google GenAI, Pydantic AI, LlamaIndex. Centralized policy server |
| **1.0** | 2027 | Distributed security, hosted SaaS, SSO/SCIM |

## Links

- [GitHub](https://github.com/Acacian/aegis) -- source code, issues, discussions
- [PyPI](https://pypi.org/project/agent-aegis/) -- package page
- [Playground](playground/) -- try Aegis in your browser
- [Contributing](https://github.com/Acacian/aegis/blob/main/CONTRIBUTING.md) -- get involved
- [Changelog](https://github.com/Acacian/aegis/blob/main/CHANGELOG.md) -- release history
- [Architecture](https://github.com/Acacian/aegis/blob/main/ARCHITECTURE.md) -- design decisions
