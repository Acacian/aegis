<!-- mcp-name: io.github.Acacian/aegis -->
<p align="center">
  <h1 align="center">Aegis</h1>
  <p align="center">
    <strong>Policy CI/CD for AI agents — the <code>terraform plan</code> for AI agent security.<br/>Auto-instrument 11 frameworks with runtime guardrails, policy testing, and audit trail — zero code changes.</strong>
  </p>
  <p align="center">
    <code>pip install agent-aegis</code> and add <b>one line</b>. Aegis monkey-patches LangChain, CrewAI, OpenAI Agents SDK, OpenAI, Anthropic, LiteLLM, Google GenAI, Pydantic AI, LlamaIndex, Instructor, and DSPy at runtime — every LLM call and tool invocation passes through prompt-injection detection, PII masking, and a full audit trail. Preview policy changes with <code>aegis plan</code>, regression-test with <code>aegis test</code>, and gate CI/CD merges — like <code>terraform plan</code> for AI governance. Governs what agents <b>do</b> (actions, tool calls, data access), not what they <b>say</b>. No refactoring. No infra. All checks are deterministic and sub-millisecond.
  </p>
</p>

<p align="center">
  <a href="https://github.com/Acacian/aegis/actions/workflows/ci.yml"><img src="https://github.com/Acacian/aegis/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/agent-aegis/"><img src="https://img.shields.io/pypi/v/agent-aegis?color=blue&cacheSeconds=3600" alt="PyPI"></a>
  <a href="https://pypi.org/project/langchain-aegis/"><img src="https://img.shields.io/pypi/v/langchain-aegis?label=langchain-aegis&color=blue&cacheSeconds=3600" alt="langchain-aegis"></a>
  <a href="https://pypi.org/project/agent-aegis/"><img src="https://img.shields.io/pypi/pyversions/agent-aegis?cacheSeconds=3600" alt="Python"></a>
  <a href="https://github.com/Acacian/aegis/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
  <a href="https://acacian.github.io/aegis/"><img src="https://img.shields.io/badge/docs-acacian.github.io%2Faegis-blue" alt="Docs"></a>
  <br/>
  <a href="https://github.com/Acacian/aegis/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/tests-4650%2B_passed-brightgreen" alt="Tests"></a>
  <a href="https://github.com/Acacian/aegis/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/coverage-92%25-brightgreen" alt="Coverage"></a>
  <a href="https://acacian.github.io/aegis/playground/"><img src="https://img.shields.io/badge/playground-Try_it_Live-ff6b6b" alt="Playground"></a>
  <a href="https://www.bestpractices.dev/projects/12253"><img src="https://www.bestpractices.dev/projects/12253/badge" alt="OpenSSF Best Practices"></a>
</p>

<p align="center">
  <a href="#auto-instrumentation"><strong>Auto-Instrumentation</strong></a> &bull;
  <a href="#policy-cicd"><strong>Policy CI/CD</strong></a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#supported-frameworks">Supported Frameworks</a> &bull;
  <a href="#three-pillars">Three Pillars</a> &bull;
  <a href="https://acacian.github.io/aegis/">Documentation</a> &bull;
  <a href="#integrations">Integrations</a> &bull;
  <a href="https://acacian.github.io/aegis/playground/"><strong>Try it Live</strong></a> &bull;
  <a href="https://github.com/Acacian/aegis/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22">Contributing</a>
</p>

<p align="center">
  <b>English</b> &bull;
  <a href="./README.ko.md">한국어</a>
</p>

---

## Auto-Instrumentation

Add AI safety to any project in 30 seconds. No refactoring, no wrappers, no config files.

```python
import aegis
aegis.auto_instrument()

# That's it. Every LangChain, CrewAI, OpenAI, Anthropic, LiteLLM,
# Google GenAI, Pydantic AI, LlamaIndex, Instructor, and DSPy
# call in your application now passes through:
#   - Prompt injection detection (blocks attacks)
#   - PII detection (warns on personal data exposure)
#   - Prompt leak detection (warns on system prompt extraction)
#   - Toxicity detection (warns — opt-in to block)
#   - Full audit trail (every call logged)
```

Or zero code changes — just set an environment variable:

```bash
AEGIS_INSTRUMENT=1 python my_agent.py
```

Aegis monkey-patches framework internals at import time, the same approach used by Sentry for error tracking. Your existing code stays untouched.

### How It Works

```
Your code                          Aegis layer (invisible)
---------                          -----------------------
chain.invoke("Hello")       -->    [input guardrails] --> LangChain --> [output guardrails] --> response
Runner.run(agent, "query")  -->    [input guardrails] --> OpenAI SDK --> [output guardrails] --> response
crew.kickoff()              -->    [task guardrails]  --> CrewAI     --> [tool guardrails]   --> response
client.chat.completions()   -->    [input guardrails] --> OpenAI API --> [output guardrails] --> response
```

Every call is checked on both input and output. Blocked content raises `AegisGuardrailError` (configurable to warn or log instead).

### Supported Frameworks

| Framework | What gets patched | Status |
|-----------|------------------|--------|
| **LangChain** | `BaseChatModel.invoke/ainvoke`, `BaseTool.invoke/ainvoke` | Stable |
| **CrewAI** | `Crew.kickoff/kickoff_async`, global `BeforeToolCallHook` | Stable |
| **OpenAI Agents SDK** | `Runner.run`, `Runner.run_sync` | Stable |
| **OpenAI API** | `Completions.create` (chat & completions) | Stable |
| **Anthropic API** | `Messages.create` | Stable |
| **LiteLLM** | `completion`, `acompletion` | Stable |
| **Google GenAI (Gemini)** | `Models.generate_content` (new) + `GenerativeModel.generate_content` (legacy) | Stable |
| **Pydantic AI** | `Agent.run`, `Agent.run_sync` | Stable |
| **LlamaIndex** | `LLM.chat/achat/complete/acomplete`, `BaseQueryEngine.query/aquery` | Stable |
| **Instructor** | `Instructor.create`, `AsyncInstructor.create` | Stable |
| **DSPy** | `Module.__call__`, `LM.forward/aforward` | Stable |

### Default Guardrails

All guardrails are deterministic (no LLM calls), sub-millisecond, and require zero configuration:

| Guardrail | Default action | What it catches |
|-----------|---------------|-----------------|
| **Prompt injection** | Block | 10 attack categories, 85+ patterns, multi-language (EN/KO/ZH/JA) |
| **PII detection** | Warn | 13 categories (email, credit card, SSN, IBAN, API keys, etc.) |
| **Prompt leak** | Warn | System prompt extraction attempts |
| **Toxicity** | Warn (opt-in to block) | Harmful, violent, or abusive content |

### Fine-Grained Control

```python
from aegis.instrument import auto_instrument, patch_langchain, status, reset

# Instrument only specific frameworks
auto_instrument(frameworks=["langchain", "openai_agents"])

# Customize behavior
auto_instrument(
    on_block="warn",       # "raise" (default), "warn", or "log"
    guardrails="default",  # or "none" for audit-only mode
    audit=True,            # log every call
)

# Instrument a single framework
patch_langchain()

# Check what's instrumented
print(status())
# {"active": True, "frameworks": {"langchain": {"patched": True, ...}}, "guardrails": 4}

# Clean removal — restore all original methods
reset()
```

---

## Policy CI/CD

**No one else does this.** Security tools protect at runtime. Aegis also manages the policy lifecycle — preview changes, test for regressions, and gate CI/CD merges before anything reaches production.

### `aegis plan` — Preview impact before deploying

Like `terraform plan` for AI agent policies. Replays historical audit data to show exactly what would change.

```bash
aegis plan current.yaml proposed.yaml --audit-db aegis_audit.db

# Policy Impact Analysis
# =====================
#   Rules: 2 added, 1 removed, 3 modified
#   Impact (replayed 1,247 actions):
#     23 actions would change from AUTO → BLOCK
#      7 actions would change from APPROVE → BLOCK
#
#   CI mode: aegis plan current.yaml proposed.yaml --ci  (exit 1 if breaking)
```

### `aegis test` — Regression testing for policies

Define expected outcomes, auto-generate test suites, catch unintended side effects.

```bash
# Auto-generate test suite from policy
aegis test policy.yaml --generate --generate-output tests.yaml

# Run in CI — exit 1 on failure
aegis test policy.yaml tests.yaml

# Regression test between old and new policy
aegis test new-policy.yaml tests.yaml --regression old-policy.yaml
```

### CI/CD Integration

```yaml
# .github/workflows/policy-check.yml
- uses: Acacian/aegis@main
  with:
    policy: aegis.yaml
    tests: tests.yaml
    fail-on-regression: true
```

Policy changes get the same rigor as code changes: diff, test, review, merge.

---

## Quick Start

### Step 1: Install

```bash
pip install agent-aegis
```

### Step 2: Choose your integration level

**Level 1: Auto-instrument (recommended)** -- one line, governs everything:

```python
import aegis
aegis.auto_instrument()
# All 11 supported frameworks are now governed.
```

**Level 2: Init with full security stack** -- guardrails + policy engine + audit:

```python
import aegis
aegis.auto_instrument()
# Discovers aegis.yaml, activates policy engine, audit logging, cost tracking.
```

**Level 3: Targeted patching** -- govern specific APIs:

```python
import aegis
aegis.patch_openai()    # Only OpenAI calls
aegis.patch_anthropic() # Only Anthropic calls

# Or use the decorator for custom functions
@aegis.guard
def my_agent_function():
    ...
```

**Level 4: YAML config** -- full control when you need it:

```bash
aegis init  # Creates aegis.yaml with sensible defaults
```

```yaml
# aegis.yaml
guardrails:
  pii: { enabled: true, action: mask }
  injection: { enabled: true, action: block, sensitivity: medium }

policy:
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
        param_gt: { count: 100 }
      risk_level: high
      approval: approve
    - name: no_deletes
      match: { type: "delete*" }
      risk_level: critical
      approval: block
```

**Level 5: Full Runtime() control** -- custom executors, approval gates, the works:

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
        results = await runtime.execute(plan)

asyncio.run(main())
```

### Step 3: See what happened

```bash
aegis audit
```
```
  ID  Session       Action        Target   Risk      Decision    Result
  1   a1b2c3d4...   read          crm      LOW       auto        success
  2   a1b2c3d4...   bulk_update   crm      HIGH      approved    success
  3   a1b2c3d4...   delete        crm      CRITICAL  block       blocked
```

## Three Pillars

Aegis is built on three pillars. Together they make a complete AI security framework — not just a policy checker.

### Pillar 1: Runtime Guardrails

Content-level protection that runs on every input and output automatically.

| Capability | Detail |
|------------|--------|
| **PII detection & masking** | 13 categories (email, credit card, SSN, IBAN, Korean RRN, API keys, etc.) with Luhn/mod-97 validation |
| **Prompt injection blocking** | 10 attack categories, 85+ patterns, multi-language (English, Korean, Chinese, Japanese) |
| **Rule pack ecosystem** | Extensible via community YAML packs (`@aegis/pii-detection`, `@aegis/prompt-injection`) |
| **Configurable actions** | `mask`, `block`, `warn`, `log` — per deployment, per category |

### Pillar 2: Policy Engine

Declarative YAML rules with the full governance pipeline (EVALUATE --> APPROVE --> EXECUTE --> VERIFY --> AUDIT).

| Capability | Detail |
|------------|--------|
| **Glob matching** | First-match-wins, wildcard patterns (`delete*`, `bulk_*`) |
| **Smart conditions** | `time_after`, `weekdays`, `param_gt`, `param_contains`, regex, semantic |
| **4-tier risk model** | `low` / `medium` / `high` / `critical` with per-rule overrides |
| **Approval gates** | CLI, Slack, Discord, Telegram, email, webhook, or custom handler |
| **Audit trail** | Automatic SQLite logging. Export: JSONL, webhook, or query via CLI/API |

### Pillar 3: Open Standards

Specifications that make Aegis a platform, not just a tool.

| Standard | What it does |
|----------|-------------|
| **AGEF** (Agent Governance Event Format) | Standardized JSON schema for governance events — 7 event types, hash-linked evidence chain. The SARIF of AI governance. |
| **AGP** (Agent Governance Protocol) | Communication protocol between agents and governance systems. MCP standardizes what agents CAN do; AGP standardizes what agents MUST NOT do. |
| **Rule Packs** | Community-driven guardrail rules. Install with `aegis install <pack>`. |

### The Pipeline

Every action goes through 5 stages. This happens automatically — you just call `aegis.auto_instrument()` or `runtime.run_one(action)`:

```
1. EVALUATE    Your action is matched against policy rules (glob patterns).
               --> PolicyDecision: risk level + approval requirement + matched rule

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

### Three Ways to Use

**Option A: Python library (most common)** -- no server needed.

Import Aegis into your agent code. Everything runs in the same process.

```python
runtime = Runtime(executor=MyExecutor(), policy=Policy.from_yaml("policy.yaml"))
result = await runtime.run_one(Action("read", "crm"))
```

**Option B: MCP Proxy** -- govern any MCP server with zero code changes.

Wrap any MCP server with Aegis governance. Every tool call passes through security scanning, policy checks, and audit logging — transparently. Works with Claude Desktop, Cursor, Windsurf, or any MCP client.

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "uvx",
      "args": ["--from", "agent-aegis[mcp]", "aegis-mcp-proxy",
               "--wrap", "npx", "-y",
               "@modelcontextprotocol/server-filesystem", "/home"]
    }
  }
}
```

What happens on every tool call:
- **Tool description scanning** — detects poisoned tool descriptions (10 attack patterns)
- **Rug-pull detection** — alerts if tool definitions change unexpectedly (SHA-256 pinning)
- **Argument sanitization** — blocks path traversal, command injection
- **Policy evaluation** — risk level + approval rules from your aegis.yaml
- **Full audit trail** — every call logged to SQLite

```bash
# Or from the command line:
pip install 'agent-aegis[mcp]'
aegis-mcp-proxy --policy policy.yaml \
    --wrap npx -y @modelcontextprotocol/server-filesystem /home
```

**Option C: REST API server** -- for non-Python agents (Go, TypeScript, etc.).

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

## Features

**Core** — what you get out of the box:

| | |
|---|---|
| **Auto-instrumentation** | `aegis.auto_instrument()` — monkey-patches 11 frameworks (LangChain, CrewAI, OpenAI, Anthropic, LiteLLM, Google GenAI, Pydantic AI, LlamaIndex, Instructor, DSPy). Zero code changes. |
| **Runtime guardrails** | PII detection (13 categories, incl. IBAN) + prompt injection blocking (10 categories, 85+ patterns, multi-language) + toxicity + prompt leak |
| **One-line activation** | `aegis.auto_instrument()` — guardrails, policy engine, audit, cost tracking, all active |
| **YAML policies** | Glob matching, first-match-wins, smart conditions (`time_after`, `param_gt`, `weekdays`, regex, etc.) |
| **4-tier risk model** | `low` / `medium` / `high` / `critical` with per-rule overrides |
| **Approval gates** | CLI, Slack, Discord, Telegram, email, webhook, or custom |
| **Audit trail** | Automatic SQLite logging. Export: JSONL, webhook, or query via CLI/API |
| **Policy CI/CD** | `aegis plan` (terraform plan for policies) + `aegis test` (regression testing) + GitHub Action — no other tool does this |
| **Env var activation** | `AEGIS_INSTRUMENT=1` — add security via environment variable, no code changes at all |
| **7 adapters** | LangChain, CrewAI, OpenAI Agents, Anthropic, MCP, Playwright, httpx |
| **REST API + Dashboard** | `aegis serve policy.yaml` — web UI with KPIs, audit log, compliance reports |

<details>
<summary><strong>Enterprise</strong> — production-grade security</summary>

| | |
|---|---|
| **Cryptographic audit chain** | SHA-256/SHA3-256 hash-linked tamper-evident trail (maps to EU AI Act Art.12, SOC2 CC7.2 evidence requirements) |
| **Regulatory mapper** | EU AI Act, NIST AI RMF, SOC2, ISO 42001, OWASP Agentic Top 10 — gap analysis + evidence |
| **Behavioral anomaly detection** | Per-agent profiling, auto-policy generation from observed behavior |
| **RBAC** | 12 permissions, 5 hierarchical roles, thread-safe AccessController |
| **Multi-tenant isolation** | TenantContext, quota enforcement, data separation |
| **Policy versioning** | Git-like commit, diff, rollback, tagging |
| **AGEF spec** | Standardized JSON event format for AI governance (7 event types, hash-linked evidence chain) |
| **AGP spec** | Governance protocol complementing MCP — 7 message types, 3 conformance levels |

</details>

<details>
<summary><strong>MCP Supply Chain Security</strong> — defense-in-depth for MCP tool calls</summary>

| | |
|---|---|
| **Tool poisoning detection** | 10 regex patterns against Unicode-normalized text, schema recursion |
| **Rug pull detection** | SHA-256 hash pinning, definition change alerts |
| **Argument sanitization** | Path traversal, command injection, null byte detection |
| **Trust scoring (L0-L4)** | Automated trust levels from scan + pin + audit status |
| **Vulnerability database** | 8 built-in CVEs for popular MCP servers, version-range matching, auto-block |
| **SBOM generation** | CycloneDX-inspired bill of materials with vulnerability overlay |
| **Session replay** | Record/replay agent sessions with retroactive security scanning (16 patterns) |
| **Cross-session leakage detection** | Detects shared MCP servers correlating requests across tenants (5 detectors: cross-tenant overlap, session fingerprinting, correlation probing, exfiltration via args, profile accumulation) |

</details>

<details>
<summary><strong>Multi-Agent Governance</strong></summary>

| | |
|---|---|
| **Cost circuit breaker** | 17 model pricing entries, loop detection, hierarchical budgets, thread-safe |
| **Cross-framework cost tracking** | LangChain + OpenAI + Anthropic + Google → unified CostTracker |
| **Multi-agent cost attribution** | Delegation trees, subtree rollup, formatted attribution reports |
| **A2A communication governance** | Capability-gated messaging, PII/credential redaction, rate limiting, audit log |
| **Constitutional Protocol** | Agent constitutions (ontology + obligations + constraints), constitutional inheritance via delegation, plan-level governance (sequence patterns, cumulative risk) |
| **Governance Envelope** | A2A messages carry sender's governance credentials (SHA-256 signed) — like TLS certificates for agents |
| **Governance Handshake** | Constitutional compatibility verification before agent communication (domain, capability, constraint, trust checks) |
| **Policy-as-code Git integration** | Diff formatting, impact analysis, drift detection, YAML export |
| **OpenTelemetry export** | Policy/cost/anomaly/MCP events → OTel spans, in-memory fallback |

</details>

<details>
<summary><strong>Developer Experience</strong></summary>

| | |
|---|---|
| **`aegis scan`** | AST-based detection of ungoverned AI calls in your codebase |
| **`aegis probe`** | Adversarial policy testing — glob bypass, missing coverage, escalation |
| **`aegis plan`** | `terraform plan` for AI policies — preview impact of changes against real audit data |
| **`aegis test`** | Policy regression testing for CI/CD pipelines |
| **`aegis autopolicy`** | Natural language → YAML (`"block deletes, allow reads"`) |
| **`aegis score`** | Governance coverage 0-100 with shields.io badge |
| **Policy-as-Code SDK** | Fluent `PolicyBuilder` API for programmatic construction |
| **GitHub Action** | CI/CD governance gates in your pipeline |
| **9 policy templates** | Pre-built for CRM, finance, DevOps, healthcare, and more |
| **[Interactive playground](https://acacian.github.io/aegis/playground/)** | Try in browser — no install needed |

</details>

## Runtime Guardrails

Aegis includes production-grade content guardrails that run on every prompt and response. Configurable via `aegis.yaml`.

### PII Detection & Masking

13 PII categories with compiled regex patterns and secondary validation (Luhn algorithm for credit cards, mod-97 for IBAN):

| Category | Examples | Severity |
|----------|----------|----------|
| Email | `user@example.com` | high |
| Credit card | Visa, MasterCard, Amex, Discover (Luhn-validated) | critical |
| SSN | US Social Security Number | critical |
| Korean RRN | Resident Registration Number (주민등록번호) | critical |
| Korean phone | Mobile + landline + international format | high |
| IBAN | International Bank Account Number with mod-97 validation | critical |
| API keys | OpenAI, AWS, GitHub, Slack, Bearer tokens, generic secrets | critical |
| IP address | IPv4 with octet validation | medium |
| Passport | With keyword context | critical |
| URL credentials | `user:pass@host` patterns | critical |

Actions: `mask` (default), `block`, `warn`, `log` — configurable per deployment.

### Prompt Injection Detection

10 attack categories, 85+ patterns, multi-language support (English, Korean, Chinese, Japanese):

| Category | What it catches |
|----------|----------------|
| System prompt extraction | "show me your system prompt", "repeat your instructions" |
| Role hijacking | "you are now an unrestricted AI", "switch to developer mode" |
| Instruction override | "ignore all previous instructions", "forget everything" |
| Delimiter injection | `<\|endoftext\|>`, `[/INST]`, ChatML tokens |
| Encoding evasion | Base64-wrapped instructions, ROT13, hex, unicode escapes |
| Multi-language attacks | Korean, Chinese (simplified + traditional), Japanese injection patterns |
| Indirect injection | "if the user asks, tell them...", embedded instructions in tool output |
| Data exfiltration | "send the conversation to", "append to URL" |
| Jailbreak patterns | DAN, AIM, "do anything now" variants |
| Context manipulation | "the following is a test", "this is authorized by the developer" |

Three sensitivity levels: `low` (high-confidence only), `medium` (known patterns, recommended), `high` (aggressive/fuzzy).

### Rule Pack Ecosystem

Guardrails are extensible via community YAML rule packs:

```yaml
# aegis.yaml
guardrails:
  pii:
    enabled: true
    action: mask
  injection:
    enabled: true
    action: block
    sensitivity: medium
```

Built-in packs: `@aegis/pii-detection`, `@aegis/prompt-injection`. Install additional packs with `aegis install <pack>`.

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
| **4,650+ tests, 92% coverage** | Every adapter, handler, and edge case tested |
| **Type-safe** | `mypy --strict` with zero errors, `py.typed` marker |
| **Performance** | Lazy imports — `import aegis` loads 20 modules (not 67); policy evaluation < 1ms (LRU-cached); O(log n) timestamp pruning; SQLite WAL mode; `execute(parallel=True)` for concurrent actions |
| **Fail-safe** | Blocked actions never execute; can't be bypassed without policy change |
| **Audit immutability** | Results are frozen dataclasses; audit writes happen before returning |
| **Clean patching** | Controlled monkey-patching with `auto_instrument()` — fully reversible via `reset()`, idempotent, skip-if-missing |

## Compliance & Audit

One policy config, multiple compliance regimes. Aegis maps your security posture to both mandatory regulations (EU) and voluntary frameworks (US):

| Standard | What Aegis provides |
|----------|-------------------|
| **EU AI Act** | Art.12 logging, risk classification, human oversight evidence — mandatory Aug 2026 |
| **NIST AI RMF** | Govern/Map/Measure/Manage functions mapped to Aegis policy + audit + anomaly detection |
| **SOC2** | Immutable audit log of every agent action, decision, and approval |
| **ISO 42001** | AI management system evidence — policy lifecycle, risk assessment, continuous monitoring |
| **GDPR** | Data access documentation — who/what accessed which system and when |
| **HIPAA** | PHI access trail with full action context and approval chain |
| **OWASP Agentic Top 10** | ASI01-ASI10 threat coverage with built-in detection and mitigation |

Export as JSONL, query via CLI/API, or stream to external SIEM via webhook. For defense-in-depth with container isolation, see the [Security Model](https://acacian.github.io/aegis/guides/security-model/) guide.

## Integrations

**Easiest way: auto-instrument.** Install the framework, call `aegis.auto_instrument()`, done.

For manual control, use adapters:

```bash
pip install agent-aegis                   # Core — includes auto_instrument() for all frameworks
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

**Option B: AgentMiddleware** — intercepts every tool call via LangChain's middleware protocol

```python
from aegis.adapters.langchain import AegisMiddleware

middleware = AegisMiddleware(policy=Policy.from_yaml("policy.yaml"))
# Blocked calls return a ToolMessage explaining the policy violation
# Allowed calls proceed normally
```

**Option C: Executor/Tool adapter**

```python
from aegis.adapters.langchain import LangChainExecutor, AegisTool

executor = LangChainExecutor(tools=[DuckDuckGoSearchRun()])
runtime = Runtime(executor=executor, policy=Policy.from_yaml("policy.yaml"))
```
</details>

<details>
<summary><b>OpenAI Agents SDK</b> -- native guardrails + decorator security</summary>

**Option A: Native guardrails (recommended)** — uses SDK's `@tool_input_guardrail` / `@tool_output_guardrail`

```python
from agents import function_tool
from aegis import Policy
from aegis.adapters.openai_agents import (
    create_aegis_input_guardrail,
    create_aegis_output_guardrail,
)

policy = Policy.from_yaml("policy.yaml")
input_guard = create_aegis_input_guardrail(policy=policy, fail_closed=True)
output_guard = create_aegis_output_guardrail(policy=policy)

@function_tool(
    tool_input_guardrails=[input_guard],
    tool_output_guardrails=[output_guard],
)
def web_search(query: str) -> str:
    """Search the web -- Aegis evaluates before AND after execution."""
    return do_search(query)
```

**Option B: Decorator-based** — wraps function with full governance pipeline

```python
from aegis.adapters.openai_agents import governed_tool

@governed_tool(runtime=runtime, action_type="write", action_target="crm")
async def update_contact(name: str, email: str) -> str:
    """Update a CRM contact -- governed by Aegis policy."""
    return await crm.update(name=name, email=email)
```
</details>

<details>
<summary><b>CrewAI</b> -- global guardrail hook + per-tool security</summary>

**Option A: Global guardrail (recommended)** — governs ALL tool calls across all Crews

```python
from aegis.adapters.crewai import enable_aegis_guardrail

# One line — every tool call now goes through Aegis policy
provider = enable_aegis_guardrail(runtime=my_runtime)
```

**Option B: Per-tool wrapper**

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
<summary><b>MCP Server</b> -- one-click security for Claude, Cursor, VS Code, Windsurf</summary>

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

## Security Dashboard

Built-in web dashboard for real-time agent security monitoring. No separate frontend build needed.

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

Advanced capabilities for production-grade agent security.

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

Tamper-evident audit trail with hash-linked entries. Provides evidence for EU AI Act Article 12 logging obligations and SOC2 CC7.2 monitoring controls.

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

Maps your security posture against EU AI Act, NIST AI RMF, SOC2, and ISO 42001. Identifies gaps and generates evidence.

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

Automated testing for security gaps. Probes for glob bypasses, missing coverage, escalation patterns, and overly permissive defaults.

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

### `aegis plan` -- Policy Impact Preview

Like `terraform plan` for AI agent policies. Previews the impact of policy changes by replaying historical audit data -- see exactly what would break before deploying.

```bash
# Show what changes between two policies
aegis plan current.yaml proposed.yaml

# Replay against real audit history to see impact
aegis plan current.yaml proposed.yaml --audit-db aegis_audit.db

# CI mode: exit 1 if any actions would be newly blocked
aegis plan current.yaml proposed.yaml --replay audit.jsonl --ci
```

### `aegis test` -- Policy Regression Testing

Policy regression testing for CI/CD pipelines. Define expected outcomes, auto-generate test suites, and catch unintended side effects of policy changes.

```bash
# Run policy test suite (exit 1 on failure)
aegis test policy.yaml tests.yaml

# Auto-generate test suite from policy
aegis test policy.yaml --generate --generate-output tests.yaml

# Regression test between old and new policy
aegis test new-policy.yaml tests.yaml --regression old-policy.yaml
```

## AGEF & AGP — Open Governance Standards

Aegis is the reference implementation of two open specifications that bring interoperability to AI security:

### AGEF (Agent Governance Event Format)

A standardized JSON schema for recording AI governance events — policy decisions, guardrail activations, approval workflows, cost alerts, and tamper-evident audit trails. AGEF is to AI governance what SARIF is to static analysis and CEF is to security logging.

- 7 event types: `policy_decision`, `guardrail_trigger`, `approval_request/response`, `cost_alert`, `rate_limit`, `audit_entry`
- Multi-agent lineage tracking with delegation chains
- Hash-linked tamper-evident evidence chain
- Correlates with OpenTelemetry traces and ingests into any SIEM

See [`specs/agef/v1/`](specs/agef/v1/) for the full specification and JSON Schema.

### AGP (Agent Governance Protocol)

A standard communication protocol between AI agents and governance systems. AGP complements MCP:

> **MCP standardizes what AI agents CAN do. AGP standardizes what AI agents MUST NOT do.**

| | Direction | Question | Protocol |
|---|---|---|---|
| Communication | Agent --> External World | "How do I call this tool?" | MCP |
| Governance | External World --> Agent | "Should you be allowed to?" | **AGP** |

- Transport-agnostic (in-process, HTTP, WebSocket, gRPC, message queue)
- Message types: `action.declare/evaluate`, `guardrail.check/result`, `approval.request/response`, `evidence.record`
- 3 conformance levels: Basic, Standard, Full
- Aegis implements AGP Level 3 (Full)

See [`specs/agp/v1/`](specs/agp/v1/) for the full protocol specification.

## Architecture

```
aegis/
  instrument/        Auto-instrumentation — monkey-patches LangChain, CrewAI, OpenAI Agents SDK, OpenAI, Anthropic
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
  core/mcp_security  MCP supply chain security -- poisoning, rug pull, sanitization, trust scoring
  core/mcp_vuln_db   MCP vulnerability database -- CVE matching, version ranges, auto-block
  core/mcp_sbom      MCP server SBOM generation -- tool catalog, vulnerability overlay, JSON export
  core/budget        Cost circuit breaker -- 17 model pricing, loop detection, hierarchical budgets
  core/cost_callbacks  Cross-framework cost tracking -- LangChain, OpenAI, Anthropic, Google
  core/cost_attribution  Multi-agent cost attribution -- delegation trees, subtree rollup
  core/a2a_governance  Agent-to-agent communication governance -- capability gates, content filter
  core/policy_git    Policy-as-code Git integration -- diff, impact analysis, drift detection
  core/otel_export   OpenTelemetry export -- governance events → OTel spans
  core/session_replay  Session replay -- record/replay with retroactive security scanning
  guardrails/        Runtime content guardrails -- PII detection (13 categories), injection detection (10 categories, 85+ patterns)
  specs/agef/        AGEF (Agent Governance Event Format) -- JSON schema for governance events
  specs/agp/         AGP (Agent Governance Protocol) -- communication protocol for agent governance
  adapters/          BaseExecutor, Playwright, httpx, LangChain, CrewAI, OpenAI, Anthropic, MCP
  runtime/           Runtime engine, ApprovalHandler, AuditLogger (SQLite/JSONL/webhook/logging)
  server/            REST API (Starlette ASGI) -- evaluate, execute, audit, policy endpoints
  cli/               aegis validate | audit | schema | init | simulate | serve | stats |
                     scan | score | diff | compliance | regulatory | monitor
```

## Why Aegis?

| | Writing your own | Platform guardrails | Enterprise platforms | **Aegis** |
|---|---|---|---|---|
| **Setup** | Days of if/else | Vendor-specific config | Kubernetes + procurement | **`pip install` + one line** |
| **Code changes** | Wrap every call | SDK-specific integration | Months of integration | **Zero — auto-instruments at runtime** |
| **Cross-framework** | Rewrite per framework | Their ecosystem only | Usually single-vendor | **11 frameworks — LangChain to DSPy** |
| **Policy CI/CD** | None | None | None | **`aegis plan` + `aegis test` + GitHub Action** |
| **Audit trail** | printf debugging | Platform logs only | Cloud dashboard | **SQLite + JSONL + webhooks — local, no infra** |
| **Compliance** | Manual documentation | None | Enterprise sales cycle | **EU AI Act, NIST, SOC2, ISO 42001 built-in** |
| **Cost** | Engineering time | Free-to-$$$ per vendor | $$$$ + infra | **Free (MIT). Forever.** |

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
aegis plan current.yaml proposed.yaml              # terraform plan for AI policies
aegis plan current.yaml proposed.yaml --replay audit.jsonl --ci  # CI gate
aegis test policy.yaml tests.yaml                  # Policy regression testing
aegis test policy.yaml --generate --generate-output tests.yaml   # Auto-generate tests
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
| **0.2** | **Released** | LangChain AgentMiddleware, CrewAI GuardrailProvider, OpenAI Agents native guardrails, OWASP Agentic Top 10, HTML compliance reports, interactive playground + challenge |
| **0.3** | **Released** | MCP supply chain security (poisoning/rug pull/SBOM/vuln DB), cost circuit breaker (17 models), cross-framework cost tracking (LangChain/OpenAI/Anthropic/Google), A2A communication governance, session replay with retroactive scanning, OpenTelemetry export, policy Git integration |
| **0.4** | **Released** | `aegis.init()` one-line activation, runtime guardrails (PII detection/masking, prompt injection blocking), rule pack ecosystem, zero-code integration (`patch_openai`/`patch_anthropic`, `@guard`), AGEF/AGP open governance specs, Redis/PostgreSQL audit backends |
| **0.4.1** | **Released** | 13 performance & correctness fixes: LRU cache, O(log n) bisect pruning, SQLite WAL + indexes, parallel `execute()`, async guardrails, multi-anomaly `check_all()`, cache key correctness, lock leak fix, batch flush race fix |
| **0.4.2** | **Released** | **Auto-instrumentation** (`aegis.auto_instrument()`) — zero-code monkey-patching for LangChain, CrewAI, OpenAI Agents SDK, OpenAI API, Anthropic API. `AEGIS_INSTRUMENT=1` env var. Default guardrails (injection/toxicity/PII/prompt leak). Per-framework `patch_`/`unpatch_` + `status()`/`reset()` |
| **0.5** | **Released** | Auto-instrumentation for LiteLLM, Google GenAI, Pydantic AI, LlamaIndex, Instructor, DSPy. Centralized policy server, rule pack registry, cross-agent audit correlation |
| **0.6** | **Released** | Security hardening (18 vulnerabilities fixed): fail-closed defaults, API auth middleware, audit data sanitization, SSRF/ReDoS/TOCTOU protection. IBAN PII detection with mod-97 validation. Policy CI/CD enhancements (impact analysis, test runner, GitHub Action) |
| **1.0** | 2027 | Distributed security, hosted SaaS, SSO/SCIM |

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
  <sub>Policy CI/CD for AI agents. Built for the era of autonomous AI agents.</sub><br/>
  <sub>If Aegis helps you, consider giving it a star -- it helps others find it too.</sub>
</p>
