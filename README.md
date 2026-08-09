<!-- mcp-name: io.github.Acacian/aegis -->
<p align="center">
  <h1 align="center">Agent-Aegis</h1>
  <p align="center">
    <strong>The governance layer for AI agents. One API, 12 frameworks, every governance primitive.</strong>
  </p>
  <p align="center">
    Aegis is to agent governance what Redis is to data structures — one runtime that unifies prompt-injection blocking, PII masking, policy enforcement, trust delegation, and tamper-evident audit across every agent framework. No code changes.<br/>
    <code>pip install agent-aegis</code> → <code>aegis.auto_instrument()</code> → 12 frameworks are now governed.
  </p>
</p>

<p align="center">
  <a href="https://www.bestpractices.dev/projects/12253"><img src="https://www.bestpractices.dev/projects/12253/badge" alt="OpenSSF Best Practices"></a>
  <a href="https://github.com/Acacian/aegis/actions/workflows/ci.yml"><img src="https://github.com/Acacian/aegis/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/agent-aegis/"><img src="https://img.shields.io/pypi/v/agent-aegis?color=blue&cacheSeconds=3600" alt="PyPI"></a>
  <a href="https://pypi.org/project/agent-aegis/"><img src="https://img.shields.io/pypi/pyversions/agent-aegis?cacheSeconds=3600" alt="Python"></a>
  <a href="https://github.com/Acacian/aegis/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
  <br/>
  <a href="https://github.com/Acacian/aegis/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/tests-6400%2B_passed-brightgreen" alt="Tests"></a>
  <a href="https://github.com/Acacian/aegis/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/coverage-92%25-brightgreen" alt="Coverage"></a>
  <a href="https://acacian.github.io/aegis/playground/"><img src="https://img.shields.io/badge/playground-Try_it_Live-ff6b6b" alt="Playground"></a>
</p>

<p align="center">
  <a href="#what-is-aegis"><strong>What is Aegis</strong></a> &bull;
  <a href="#primitives">Primitives</a> &bull;
  <a href="#frameworks">Frameworks</a> &bull;
  <a href="#use-cases">Use Cases</a> &bull;
  <a href="#30-second-start"><strong>30-Second Start</strong></a> &bull;
  <a href="#research">Research</a> &bull;
  <a href="https://acacian.github.io/aegis/">Docs</a> &bull;
  <a href="https://acacian.github.io/aegis/playground/"><strong>Playground</strong></a>
</p>

<p align="center">
  <b>English</b> &bull;
  <a href="./README.ko.md">한국어</a>
</p>

---

<p align="center">
  <img src="docs/assets/demo.gif?v=2" alt="Aegis Demo" width="880">
</p>

---

## What is Aegis

Every AI agent framework reinvents the same governance primitives — and each one does it slightly differently. Aegis is the abstraction layer that unifies them.

| Layer | What it does | Examples |
|-------|-------------|----------|
| **1. Primitives** | A universal contract for every tool call | `Action`, `ActionClaim`, `Policy`, `Result`, `DelegationChain`, `AuditEvent` |
| **2. Adapters** | Auto-instrument any framework through its own hooks | LangChain callbacks, CrewAI `BeforeToolCallHook`, OpenAI Agents tracing, Google ADK `BasePlugin`, MCP transport, DSPy modules, httpx middleware, Playwright context |
| **3. Governance** | Declarative primitives you compose into policy | Prompt injection / PII / leak / toxicity guardrails, RBAC, rate limit, cost budget, drift detection, anomaly scoring, trust delegation, justification gap, selection audit, Merkle audit chain |
| **4. Lifecycle** | One runtime, every stage of agent ops | Scan → Instrument → Policy CI/CD → Runtime → Proxy → Audit |

```python
import aegis
aegis.auto_instrument()    # 12 frameworks governed. No other code changes.
```

You don't write a LangChain guardrail and a CrewAI guardrail and an OpenAI guardrail — you write one `Policy` and every framework inherits it.

### How this differs from the guardrail libraries

They solve a different problem, and mostly a text-shaped one. [Guardrails AI](https://github.com/guardrails-ai/guardrails) validates model output against a hub of validators; [NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) scripts conversational and tool policy in the Colang DSL; [Snyk Agent Scan](https://github.com/snyk/agent-scan) — Invariant Labs' `mcp-scan`, since the Snyk acquisition — scans MCP servers and agent skills for known risk patterns and can proxy them at runtime; [LLM Guard](https://github.com/protectai/llm-guard) chained input/output scanners until it was archived in July 2026. Each one you wire in yourself, at a call site you choose. Aegis starts from the other end: `auto_instrument()` finds the frameworks already installed and instruments them in place, so one `Policy` covers all of them without a line of agent code changing. What it enforces is agent-shaped rather than prompt-shaped — delegation chains under a monotone trust constraint, audits of what an agent *excluded* rather than what it picked, the distance between an agent's declared intent and its measured impact, and a tamper-evident audit chain. All of it is deterministic, so there is no second model sitting in the request path. These are not exclusive choices: a semantic or model-based detector drops into `GuardrailEngine.add()` alongside the built-ins.

---

## Primitives

The contract every adapter maps into. Framework-agnostic by design.

| Primitive | Purpose | Module |
|-----------|---------|--------|
| **`Action`** | Unified representation of any tool / LLM / HTTP / MCP call across all frameworks | `aegis.core.action` |
| **`ActionClaim`** | Tripartite structure — Declared (agent-authored) / Assessed (Aegis-computed) / Chain (delegation) | `aegis.core.action_claim` |
| **`Policy`** | Declarative YAML rules: match → risk → approval (`auto` / `approve` / `block`) | `aegis.core.policy` |
| **`ClaimPolicy`** | Policy layer that evaluates 6-dimensional impact vectors, not just tool names | `aegis.core.claim_policy` |
| **`Guardrails`** | Deterministic regex checks for injection, PII, prompt leak, toxicity — 2.65ms cold / <1µs warm | `aegis.guardrails` |
| **`DelegationChain`** | Multi-agent hand-off tracking with monotone trust constraint (non-increasing) | `aegis.core.agent_identity` |
| **`AuditEvent`** | Tamper-evident append-only log, Merkle-chained, SQLite + JSONL + webhook sinks | `aegis.core.merkle_audit` |
| **`SelectionAudit`** | Audits what an agent *excludes*, not just what it picks — detects cosmetic alignment | `aegis.core.selection_audit` |
| **`JustificationGap`** | 6D asymmetric scoring: agents declare impact, Aegis independently assesses, gap triggers escalation | `aegis.core.justification_gap` |
| **`CryptoAuditChain`** | Ed25519-signed chain for long-term compliance evidence | `aegis.core.crypto_audit` |

Every governance feature in Aegis — anomaly detection, cost budgets, drift, cascade guards, kill switches — is a **composition** of these primitives. Read the [Concepts guide](https://acacian.github.io/aegis/getting-started/concepts/) to see how they fit together.

---

## Frameworks

One API. 12 agent frameworks + 3 protocol-level adapters.

| Framework | Hook | Status |
|-----------|------|--------|
| **LangChain** | `BaseChatModel.invoke/ainvoke`, `BaseTool.invoke/ainvoke` | Stable |
| **CrewAI** | `Crew.kickoff/kickoff_async`, global `BeforeToolCallHook` | Stable |
| **OpenAI Agents SDK** | `Runner.run`, `Runner.run_sync` | Stable |
| **OpenAI API** | `Completions.create` (chat & completions) | Stable |
| **Anthropic API** | `Messages.create` | Stable |
| **LiteLLM** | `completion`, `acompletion` | Stable |
| **Google GenAI** | `Models.generate_content` (new + legacy) | Stable |
| **Google ADK** | `BasePlugin` lifecycle (tool calls, agent routing, sessions) | Stable |
| **Pydantic AI** | `Agent.run`, `Agent.run_sync` | Stable |
| **LlamaIndex** | `LLM.chat/achat/complete/acomplete`, `BaseQueryEngine.query/aquery` | Stable |
| **Instructor** | `Instructor.create`, `AsyncInstructor.create` | Stable |
| **DSPy** | `Module.__call__`, `LM.forward/aforward` | Stable |
| **MCP** | Transport-layer proxy for any MCP server (stdio / HTTP) | Stable |
| **httpx** | Middleware for raw HTTP egress (REST agents, webhooks) | Stable |
| **Playwright** | Browser context instrumentation for browsing agents | Stable |

`auto_instrument()` detects what's installed and patches only those — no hard dependencies. [Custom adapters](https://acacian.github.io/aegis/guides/custom-adapters/) use the same `BaseAdapter` interface. Every adapter above is exercised against the current upstream release daily by the [integration workflow](.github/workflows/integration.yml), which drives each framework's real entrypoint and asserts a guardrail fires — the unit suite fakes these frameworks, so it cannot see upstream drift on its own.

Where a framework offers a native extension point, Aegis uses it instead of patching. The Pydantic AI integration was monkey-patched until core maintainer DouweM reviewed it — *"It doesn't look like those features are actually exposed as Pydantic AI capabilities?"* — and it was rebuilt on the native extension API in response. It ships today as an `AbstractCapability` subclass ([`src/aegis/contrib/pydantic_ai.py`](src/aegis/contrib/pydantic_ai.py)); the review is [pydantic-ai#4888](https://github.com/pydantic/pydantic-ai/pull/4888).

### Default Guardrails

| Guardrail | Default | What it catches |
|-----------|---------|-----------------|
| **Prompt injection** | Block | 10 attack categories, 85+ patterns, multi-language (EN/KO/ZH/JA) |
| **PII detection** | Warn | 13 categories (email, credit card, SSN, IBAN, API keys, etc.) |
| **Prompt leak** | Warn | System prompt extraction attempts |
| **Toxicity** | Warn | Harmful, violent, or abusive content |
| **MCP STDIO injection** | Block | JSON-RPC injection, frame concatenation, unicode escape bypass ([OX Security advisory](https://www.oxsecurity.io/blog/mcp-security-research)) |

Deterministic regex — no LLM calls, no network. **2.65ms cold / <1µs warm** per check.

---

## Use Cases

The same primitives, five different entry points. Pick whichever matches your workflow.

### 1. Runtime protection (most common)

One line. Any framework.

```python
import aegis
aegis.auto_instrument()
```

Or zero code changes — `AEGIS_INSTRUMENT=1 python my_agent.py`. Injection blocking, PII masking, prompt-leak warnings, audit trail, and policy enforcement become active for every LangChain / CrewAI / OpenAI / Anthropic / LiteLLM / ADK / DSPy / LlamaIndex / Pydantic AI call.

**Pydantic AI native capability** — no monkey-patching, explicit per-agent control:

```python
from pydantic_ai import Agent
from aegis.contrib.pydantic_ai import AegisCapability

agent = Agent(
    "openai:gpt-4o-mini",
    capabilities=[AegisCapability.default()],  # injection, PII, toxicity, prompt-leak, hallucination
)
result = await agent.run("What is AI governance?")
```

[Full Pydantic AI integration guide →](https://acacian.github.io/aegis/cookbook/pydantic-ai-governance/)

### 2. Pre-production scanning

Find ungoverned AI calls before they ship.

```bash
pip install agent-aegis
aegis scan .
```

```
Aegis Governance Scan
=====================
Scanned: 47 files in ./src

Found 5 ungoverned tool call(s):
  agent.py:12   OpenAI        function call with tools= — no governance wrapper  [ASI02]
  tools.py:8    LangChain     @tool "search_db" — no policy check  [ASI02]
  llm.py:21     LiteLLM       litellm.completion() — no governance wrapper  [ASI02]
  run.py:5      subprocess    subprocess.run — direct shell execution  [ASI08]
  api.py:14     HTTP          requests.post — raw HTTP in agent code  [ASI07]

Governance Score: D (5 ungoverned call(s))
```

Supports `--format json|sarif|suggest`, `--threshold A-F`, `.aegisscanignore`, and inline `# aegis: ignore` pragmas. Auto-fix with `aegis scan --fix`.

### 3. Policy CI/CD

Security tools protect at runtime. Aegis *also* manages the policy lifecycle — the same way you test and ship code.

```bash
aegis plan current.yaml proposed.yaml --audit-db aegis_audit.db

# Policy Impact Analysis
#   Rules: 2 added, 1 removed, 3 modified
#   Impact (replayed 1,247 actions):
#     23 actions would change from AUTO → BLOCK
```

```bash
aegis test policy.yaml tests.yaml                      # Run in CI
aegis test policy.yaml --generate                      # Auto-generate test suite
aegis test new.yaml tests.yaml --regression old.yaml   # Regression check
```

```yaml
# .github/workflows/policy-check.yml
- uses: Acacian/aegis@main
  with:
    policy: aegis.yaml
    tests: tests.yaml
    fail-on-regression: true
```

Or block ungoverned calls at PR time:

```yaml
- uses: Acacian/aegis@v1.0.0
  with:
    command: scan
    fail-on-ungoverned: true
```

### 4. Audit & compliance

Every call is logged to a tamper-evident Merkle chain, with mappings to EU AI Act / NIST AI RMF / SOC2 built in.

```bash
aegis audit
```

```
  ID  Session       Action        Target   Risk      Decision    Result
  1   a1b2c3d4...   read          crm      LOW       auto        success
  2   a1b2c3d4...   bulk_update   crm      HIGH      approved    success
  3   a1b2c3d4...   delete        crm      CRITICAL  block       blocked
```

SQLite + JSONL + webhook sinks. Ed25519 signing for long-term evidence. See the [Compliance guide](https://acacian.github.io/aegis/api/compliance/).

### 5. Governance server (multi-agent)

Centralized governance for multiple agents. Each agent connects via SDK, server handles policy, guardrails, audit, and compliance.

```bash
pip install 'agent-aegis[server]'
aegis-server
```

37 REST endpoints + WebSocket audit streaming + web dashboard. Agents auto-register, send heartbeats, and query policy over HTTP. See [Governance Framework Server](#governance-framework-server).

---

## 30-Second Start

```bash
pip install agent-aegis
```

```python
import aegis
aegis.auto_instrument()
# All 12 frameworks now governed with default guardrails.
```

Or use a YAML policy for full control:

```bash
aegis init  # Creates aegis.yaml
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
    - name: no_deletes
      match: { type: "delete*" }
      risk_level: critical
      approval: block
```

---

## Install Options

```bash
pip install agent-aegis                   # Core (includes auto_instrument for all frameworks)
pip install langchain-aegis               # LangChain standalone integration
pip install 'agent-aegis[mcp]'            # MCP server + proxy
pip install 'agent-aegis[server]'         # REST API + dashboard
pip install 'agent-aegis[all]'            # Everything
```

### MCP Proxy — govern any MCP server with zero code changes

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

Works with Claude Desktop, Cursor, VS Code, Windsurf. STDIO injection protection, tool poisoning detection, rug-pull detection, argument sanitization, policy evaluation, full audit trail.

### Governance Framework Server

Run Aegis as a dedicated governance server with REST API, WebSocket streaming, and web dashboard.

```bash
pip install 'agent-aegis[server]'
aegis-server --init          # Generate aegis-server.yaml
aegis-server                 # Start server on :8000
```

**37 REST endpoints** covering the full governance lifecycle:

| API Group | Endpoints | Purpose |
|-----------|-----------|---------|
| **Core** | evaluate, execute, audit, policy | Policy evaluation + execution pipeline |
| **Agents** | register, heartbeat, list, status | Agent lifecycle management |
| **Guardrails** | check, list | Content safety checks |
| **Policy Versioning** | commit, diff, rollback, tag | Git-like policy change management |
| **Crypto Audit** | verify, entries, evidence | Tamper-proof audit chain verification |
| **Trust & Drift** | trust score, drift detection | Per-agent behavioral analysis |
| **Cost** | budget check, reports | LLM cost governance |
| **Compliance** | reports, regulatory gaps | SOC2 / GDPR / EU AI Act reports |
| **Sessions** | list, replay | Session recording + forensic replay |

Connect with the Python SDK (sync or async):

```python
from aegis import AegisClient

with AegisClient("http://localhost:8000", agent_id="my-agent") as client:
    result = client.evaluate("delete", "user_data")
    # result["risk_level"] == "CRITICAL", result["is_allowed"] == False
```

```python
from aegis import AsyncAegisClient

async with AsyncAegisClient("http://localhost:8000", agent_id="my-agent") as client:
    result = await client.evaluate("read", "reports")
```

Config-driven via `aegis-server.yaml` — guardrails, webhooks (Slack/PagerDuty), rate limiting, cost budgets, and auth all declarative. See [`aegis-server.example.yaml`](aegis-server.example.yaml).

---

## Why Aegis?

| | Writing your own | Platform guardrails | Enterprise platforms | **Aegis** |
|---|---|---|---|---|
| **Abstraction level** | Per-framework if/else | Single-vendor SDK | Proprietary gateway | **Universal primitives across 12 frameworks** |
| **Setup** | Days of if/else | Vendor-specific config | Kubernetes + procurement | **`pip install` + one line** |
| **Code changes** | Wrap every call | SDK-specific | Months of integration | **Zero — auto-instruments** |
| **Policy portability** | Rewrite per framework | Locked to ecosystem | Usually single-vendor | **One YAML policy, every framework** |
| **Governance primitives** | Build from scratch | Subset, vendor-defined | Proprietary | **10+ composable primitives** |
| **Policy CI/CD** | None | None | None | **`aegis plan` + `aegis test`** |
| **Audit trail** | printf debugging | Platform logs only | Cloud dashboard | **SQLite + JSONL + webhooks + Merkle chain** |
| **Compliance** | Manual docs | None | Enterprise sales cycle | **EU AI Act, NIST, SOC2 built-in** |
| **Cost** | Engineering time | Free-to-$$$ | $$$$ + infra | **Free (MIT). Forever.** |

### What Only Aegis Does

Other tools check inputs and outputs. Aegis governs the *decision itself* — with primitives no other governance runtime exposes.

| Capability | What it means | Based on |
|---|---|---|
| **Tripartite ActionClaim** | Every tool call splits into Declared (agent-authored, untrusted), Assessed (Aegis-computed), and Chain (delegation) fields. The structural separation is what makes cosmetic alignment detectable. | [Justification Gap measurement on 14,285 tau-bench calls](https://acacian.github.io/aegis/research/tripartite-action-claim/) |
| **Justification Gap** | 6-dimensional asymmetric scoring: agents declare impact, Aegis independently assesses it, and `per_dim = max(0, assessed − declared)`. Under-reporting triggers escalate (>0.15) or block (>0.40). | Name "ActionClaim" from [COA-MAS (Carvalho)](https://arxiv.org/abs/2401.05064); 6D metric + runtime form original |
| **Selection Governance** | Audits what agents *exclude*, not just what they choose. A model that "helpfully" omits risky options is exerting selection power — Aegis detects this. | [Santander et al., arXiv:2602.14606](https://arxiv.org/abs/2602.14606) |
| **Monotone Trust Constraint** | Delegated agents cannot escalate their own authority. Trust levels must be non-increasing along the chain — violations auto-block. | Lattice-based access control |
| **Full Lifecycle** | Scan (detect) → Instrument (protect) → Policy CI/CD (test) → Runtime (govern) → Proxy (gateway) → Audit (trace). One library, one `pip install`. | — |

---

## CLI

```bash
aegis scan ./src/                       # Detect ungoverned AI calls
aegis score ./src/ --policy policy.yaml # Governance score (0-100)
aegis init                              # Generate starter policy
aegis validate policy.yaml              # Validate syntax
aegis plan current.yaml proposed.yaml   # Preview policy changes
aegis test policy.yaml tests.yaml       # Policy regression testing
aegis audit                             # View audit log
aegis serve policy.yaml                 # REST API + dashboard
aegis probe policy.yaml                 # Adversarial policy testing
aegis autopolicy "block deletes"        # Natural language → YAML
```

## Research

Original measurements on public agent trace datasets. Stdlib-only, reproducible in 30 seconds.

- [**The Justification Gap in 14,285 Tau-Bench Tool Calls**](https://acacian.github.io/aegis/research/tripartite-action-claim/) — Formal definition of the Tripartite ActionClaim with a silent-baseline empirical study. 90.3% approve / 9.7% escalate / 0% block across four model:domain groups. Airline domain exposes ~2× the mean gap of retail. Includes soundness sketches for the three structural invariants and an honest note on the `max`-only override limitation discovered during the study.
- [**Tool Distribution Drift in 1,960 Tau-Bench Trajectories**](https://acacian.github.io/aegis/research/tau-bench-tool-distribution-drift/) — Shannon entropy on tool name sequences across GPT-4o and Sonnet 3.5 New. 39.8% of scored trajectories collapse onto one or two tools by the end. Bimodal distribution, 1.7× cross-model gap. All scripts and raw data included.

Run the same signal on your own trace:

```bash
aegis check drift --trace path/to/trace.jsonl
```

The CLI reads only the `tool_name` field — never args, CoT, or prompts — so enterprise users can score prod traces without exfiltrating PII.

We also ran `aegis scan` across 39 public agent repositories and graded their governance posture: [92% scored an F](https://acacian.github.io/aegis/playground/scan-report.html). That is a finding about the ecosystem, not about any one project — most agent code has no tool-call policy at all.

## Documentation

Full documentation at **[acacian.github.io/aegis](https://acacian.github.io/aegis/)**:

- [Integration guides](https://acacian.github.io/aegis/) — LangChain, CrewAI, OpenAI, MCP, and more
- [Policy reference](https://acacian.github.io/aegis/) — conditions, templates, best practices
- [Security features](https://acacian.github.io/aegis/) — guardrails, anomaly detection, compliance
- [API stability](https://acacian.github.io/aegis/api/stability/) — what 1.x guarantees, and what counts as a breaking change
- [Architecture](ARCHITECTURE.md) — how the codebase is structured
- [Interactive playground](https://acacian.github.io/aegis/playground/) — try in browser, no install

## Contributing

```bash
git clone https://github.com/Acacian/aegis.git && cd aegis
make dev      # Install deps + hooks
make test     # Run tests
make lint     # Lint + format check
```

[Contributing Guide](CONTRIBUTING.md) &bull; [Good First Issues](https://github.com/Acacian/aegis/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) &bull; [![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/Acacian/aegis)

## License

MIT -- see [LICENSE](LICENSE) for details.

Copyright (c) 2026 구동하 (Dongha Koo, [@Acacian](https://github.com/Acacian)). Created March 21, 2026.

---

<p align="center">
  <sub>The governance layer for AI agents. One API, 12 frameworks, every governance primitive.</sub><br/>
  <sub>If Aegis helps you, consider giving it a star -- it helps others find it too.</sub>
</p>
