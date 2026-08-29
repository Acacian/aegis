---
title: "Agent-Aegis — The Governance Layer for AI Agents"
description: "One API, 12 frameworks, every governance primitive. Redis is to in-memory data structures what Aegis is to AI agent governance — prompt injection blocking, PII masking, policy enforcement, trust delegation, tamper-evident audit."
---

<style>
.md-typeset h1 { font-size: 2.2em; font-weight: 700; margin-bottom: 0.2em; }
.hero-sub { font-size: 1.25em; color: var(--md-default-fg-color--light); margin-bottom: 1.5em; }
.stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1em; margin: 1.5em 0; }
.stat-box { text-align: center; padding: 1em; border-radius: 8px; background: var(--md-code-bg-color); }
.stat-box strong { display: block; font-size: 1.8em; color: var(--md-accent-fg-color); }
.stat-box span { font-size: 0.85em; color: var(--md-default-fg-color--light); }
.cta-row { display: flex; gap: 0.8em; flex-wrap: wrap; margin: 1.5em 0; }
</style>

# Agent-Aegis

<p class="hero-sub">The governance layer for AI agents. One API, 12 frameworks, every governance primitive.</p>

<div class="stat-grid">
<div class="stat-box"><strong>12</strong><span>Frameworks</span></div>
<div class="stat-box"><strong>10+</strong><span>Primitives</span></div>
<div class="stat-box"><strong>85+</strong><span>Injection Patterns</span></div>
<div class="stat-box"><strong>&lt;1ms</strong><span>Per Check</span></div>
</div>

<div class="cta-row">
<a href="playground/" class="md-button md-button--primary">Try in Browser</a>
<a href="getting-started/quickstart/" class="md-button">Quick Start</a>
<a href="https://github.com/Acacian/aegis" class="md-button">GitHub</a>
</div>

---

![Aegis Demo](assets/demo.svg)

---

## What is Aegis

Every AI agent framework reinvents the same governance primitives — and each one does it slightly differently. Aegis is the abstraction layer that unifies them. **Redis is to in-memory data structures what Aegis is to agent governance**: one library, every primitive, every framework, one API.

| Layer | What it does | Examples |
|-------|-------------|----------|
| **1. Primitives** | A universal contract for every tool call | `Action`, `ActionClaim`, `Policy`, `Result`, `DelegationChain`, `AuditEvent` |
| **2. Adapters** | Auto-instrument any framework through its own hooks | LangChain callbacks, CrewAI `BeforeToolCallHook`, OpenAI Agents tracing, Google ADK `BasePlugin`, MCP transport, DSPy modules, httpx middleware, Playwright context |
| **3. Governance** | Declarative primitives you compose into policy | Injection / PII / leak / toxicity guardrails, RBAC, rate limit, cost budget, drift, anomaly, trust delegation, justification gap, selection audit, Merkle audit |
| **4. Lifecycle** | One runtime, every stage of agent ops | Scan → Instrument → Policy CI/CD → Runtime → Proxy → Audit |

```python
import aegis
aegis.auto_instrument()    # 12 frameworks governed. No other code changes.
```

You don't write a LangChain guardrail and a CrewAI guardrail and an OpenAI guardrail — you write one `Policy` and every framework inherits it.

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
| **`DelegationChain`** | Multi-agent hand-off tracking with monotone trust constraint | `aegis.core.agent_identity` |
| **`AuditEvent`** | Tamper-evident append-only log, Merkle-chained, SQLite + JSONL + webhook sinks | `aegis.core.merkle_audit` |
| **`SelectionAudit`** | Audits what an agent *excludes*, not just what it picks — detects cosmetic alignment | `aegis.core.selection_audit` |
| **`JustificationGap`** | 6D asymmetric scoring: agents declare impact, Aegis independently assesses, gap triggers escalation | `aegis.core.justification_gap` |
| **`CryptoAuditChain`** | Ed25519-signed chain for long-term compliance evidence | `aegis.core.crypto_audit` |

Every governance feature in Aegis is a composition of these primitives. Read the [Concepts guide](getting-started/concepts.md) to see how they fit together.

---

## Frameworks

One API. 12 agent frameworks + 3 protocol-level adapters. `auto_instrument()` detects what's installed and patches only those — no hard dependencies.

| Framework | Hook |
|-----------|------|
| **LangChain** | `BaseChatModel.invoke/ainvoke`, `BaseTool.invoke/ainvoke` |
| **CrewAI** | `Crew.kickoff/kickoff_async`, global `BeforeToolCallHook` |
| **OpenAI Agents SDK** | `Runner.run`, `Runner.run_sync` |
| **OpenAI API** | `Completions.create` (chat & completions) |
| **Anthropic API** | `Messages.create` |
| **LiteLLM** | `completion`, `acompletion` |
| **Google GenAI** | `Models.generate_content` (new + legacy) |
| **Google ADK** | `BasePlugin` lifecycle (tool calls, agent routing, sessions) |
| **Pydantic AI** | `Agent.run`, `Agent.run_sync` |
| **LlamaIndex** | `LLM.chat/achat/complete/acomplete`, `BaseQueryEngine.query/aquery` |
| **Instructor** | `Instructor.create`, `AsyncInstructor.create` |
| **DSPy** | `Module.__call__`, `LM.forward/aforward` |
| **MCP** | Transport-layer proxy for any MCP server (stdio / HTTP) |
| **httpx** | Middleware for raw HTTP egress (REST agents, webhooks) |
| **Playwright** | Browser context instrumentation for browsing agents |

### Default Guardrails

All deterministic regex. No LLM calls. No network. Sub-millisecond.

| Guardrail | Default | Coverage |
|-----------|---------|----------|
| **Prompt injection** | Block | 109 patterns, 13 categories, 9 languages (EN/KO/ZH/JA/ES/DE/FR/TH/VI) |
| **PII detection** | Warn | 13 categories — email, credit card, SSN, API keys, IBAN |
| **Toxicity** | Warn | Harmful, violent, abusive content |
| **Prompt leak** | Warn | System prompt extraction attempts |

---

## Use Cases

The same primitives, four different entry points.

### 1. Runtime protection

```python
import aegis
aegis.auto_instrument()
```

One line. Any framework. Or zero code changes: `AEGIS_INSTRUMENT=1 python my_agent.py`.

### 2. Pre-production scanning

```bash
pip install agent-aegis
aegis scan .
```

```
Found 5 ungoverned tool call(s):
  agent.py:12   OpenAI      function call with tools= — no governance wrapper  [ASI02]
  tools.py:8    LangChain   @tool "search_db" — no policy check               [ASI02]
  run.py:5      subprocess  subprocess.run — direct shell execution            [ASI08]

Governance Score: D
```

Maps to [OWASP Agentic Top 10](solutions/ai-agent-vulnerability-scanner.md). Supports `--format json|sarif`, `--threshold A-F`, `--fix`.

### 3. Policy CI/CD

```yaml
# aegis.yaml
guardrails:
  injection: { enabled: true, action: block }
  pii: { enabled: true, action: mask }

policy:
  version: "1"
  rules:
    - name: allow_reads
      match: { type: "read*" }
      approval: auto
    - name: block_deletes
      match: { type: "delete*" }
      approval: block
```

```bash
aegis plan current.yaml proposed.yaml    # Preview impact
aegis test policy.yaml tests.yaml        # Regression testing
```

### 4. Audit & compliance

```bash
aegis audit
```
```
  ID  Action        Target   Risk      Decision    Result
  1   read          crm      LOW       auto        success
  2   bulk_update   crm      HIGH      approved    success
  3   delete        crm      CRITICAL  block       blocked
```

Tamper-evident Merkle chain. SQLite + JSONL + webhooks. EU AI Act / NIST AI RMF / SOC2 mappings built in.

---

## Why Aegis

| | Writing your own | Platform guardrails | Enterprise platforms | **Aegis** |
|---|---|---|---|---|
| **Abstraction level** | Per-framework if/else | Single-vendor SDK | Proprietary gateway | **Universal primitives across 12 frameworks** |
| **Setup** | Days of if/else | Vendor-specific | Procurement + infra | **`pip install` + 1 line** |
| **Code changes** | Wrap every call | SDK-specific | Months | **Zero** |
| **Policy portability** | Per-framework | Locked to ecosystem | Single-vendor | **One YAML, every framework** |
| **Governance primitives** | Build from scratch | Subset, vendor-defined | Proprietary | **10+ composable primitives** |
| **Policy testing** | None | None | None | **`aegis plan` + `aegis test`** |
| **Cost per check** | $0 | $0-$$$  | $$$$ | **$0 (deterministic)** |
| **License** | -- | Varies | Enterprise | **MIT** |

### What Only Aegis Does

Other tools check inputs and outputs. Aegis governs the *decision itself* — with primitives no other governance runtime exposes.

| Capability | What it means | Based on |
|---|---|---|
| **Tripartite ActionClaim** | Every tool call splits into Declared (agent-authored, untrusted), Assessed (Aegis-computed), Chain (delegation). Structural separation makes cosmetic alignment detectable. | [Justification Gap measurement on 14,285 tau-bench calls](research/tripartite-action-claim.md) |
| **Justification Gap** | 6D asymmetric scoring: agents declare impact, Aegis independently assesses, gap triggers escalation or block. | Name from [COA-MAS (Carvalho)](https://arxiv.org/abs/2401.05064); 6D metric original |
| **Selection Governance** | Audits what agents *exclude*, not just what they choose. Detects cosmetic alignment. | [Santander et al., arXiv:2602.14606](https://arxiv.org/abs/2602.14606) |
| **Monotone Trust Constraint** | Delegated agents cannot escalate their own authority. Trust must be non-increasing along the chain. | Lattice-based access control |
| **Full Lifecycle** | Scan → Instrument → Policy CI/CD → Runtime → Proxy → Audit. One `pip install`. | — |

---

## Install

```bash
pip install agent-aegis                   # Core
pip install 'agent-aegis[mcp]'            # MCP server + proxy
pip install 'agent-aegis[server]'         # REST API + dashboard
pip install 'agent-aegis[all]'            # Everything
```

---

## Solutions by Use Case

Framework and problem-specific guides. Each page is a drop-in recipe for one concrete task.

### By Framework

- [**LangChain Security**](solutions/langchain-security.md) — add guardrails to `BaseChatModel` and `BaseTool` in 2 lines
- [**CrewAI Security**](solutions/crewai-security.md) — govern every crew task and tool call with one hook
- [**OpenAI Agents SDK Security**](solutions/openai-agents-security.md) — wrap `Runner.run` with injection/PII checks
- [**LiteLLM Security**](solutions/litellm-security.md) — governance for `completion`/`acompletion`
- [**MCP Security**](solutions/mcp-security.md) — protect MCP servers from tool poisoning and rug-pulls
- [**LLM Guardrails for Python**](solutions/llm-guardrails-python.md) — framework-agnostic guardrails overview

### By Problem

- [**Prompt Injection Detection**](solutions/prompt-injection-detection.md) — 109 patterns, 13 categories, 9 languages
- [**PII Detection for AI Agents**](solutions/pii-detection-ai-agent.md) — Luhn-validated cards, SSN, API keys, 12 categories
- [**AI Agent Vulnerability Scanner**](solutions/ai-agent-vulnerability-scanner.md) — find ungoverned calls in any Python codebase
- [**AI Agent Permission Control**](solutions/ai-agent-permission-control.md) — declarative allow/deny/approve rules
- [**AI Agent Cost Governance**](solutions/ai-agent-cost-governance.md) — per-call/session/daily LLM budget caps
- [**AI Agent Audit Trail**](solutions/ai-agent-audit-trail.md) — SHA-256 hash-chained tamper-evident logging
- [**Policy as Code for AI**](solutions/policy-as-code-ai.md) — Terraform plan for AI agent policies
- [**EU AI Act Compliance**](solutions/eu-ai-act-compliance.md) — automatic evidence packages for Article 16+

## Compare Aegis

Side-by-side comparisons with the closest alternatives. Use these to decide between tools or combine them.

- [**vs Microsoft Agent Governance Toolkit**](comparisons/vs-ms-agt.md) — library vs enterprise platform
- [**vs NeMo Guardrails**](comparisons/vs-nemo-guardrails.md) — deterministic regex vs LLM-based dialog rails
- [**vs Guardrails AI**](comparisons/vs-guardrails-ai.md) — action security vs output validation (complementary)
- [**vs mcp-scan**](comparisons/vs-mcp-scan.md) — runtime MCP governance vs static configuration scanning
- [**vs DIY (if/else)**](comparisons/vs-diy.md) — 30+ lines per framework vs 2 lines total

## Framework Cookbook

End-to-end recipes for every supported framework:

- [LangChain](cookbook/langchain-governance.md) · [CrewAI](cookbook/crewai-governance.md) · [OpenAI Agents](cookbook/openai-agents-governance.md) · [Anthropic](cookbook/anthropic-governance.md) · [MCP](cookbook/mcp-governance.md)
- [LlamaIndex](cookbook/llamaindex-governance.md) · [Pydantic AI](cookbook/pydantic-ai-governance.md) · [DSPy](cookbook/dspy-governance.md) · [LiteLLM](cookbook/litellm-governance.md)
- [httpx REST API](cookbook/httpx-governance.md) · [Playwright Browser](cookbook/playwright-governance.md) · [CI/CD Integration](cookbook/ci-governance.md) · [Gradio Playground](cookbook/gradio-playground.md) · [Docker REST API](cookbook/docker-rest-api.md)

## Research

Original measurements on public agent trace datasets. Stdlib-only, reproducible in 30 seconds.

- [**The Justification Gap in 14,285 Tau-Bench Tool Calls**](research/tripartite-action-claim.md) — Formal definition of the Tripartite ActionClaim with a silent-baseline empirical study. 90.3% approve / 9.7% escalate / 0% block across four model:domain groups. Airline domain exposes ~2× the mean gap of retail. Includes soundness sketches for three structural invariants and an honest note on the `max`-only override limitation discovered during the study.
- [**Tool Distribution Drift in 1,960 Tau-Bench Trajectories**](research/tau-bench-tool-distribution-drift.md) — Shannon entropy on tool name sequences across GPT-4o and Sonnet 3.5 New. 39.8% of scored trajectories collapse onto one or two tools by the end. Bimodal distribution, 1.7× cross-model gap. All scripts and raw data included.

---

## Links

- [Getting Started](getting-started/quickstart.md) — install and configure in 5 minutes
- [API Reference](api/runtime.md) — full API docs
- [Playground](playground/) — try in browser, no install
- [GitHub](https://github.com/Acacian/aegis) — source, issues, contributions
- [PyPI](https://pypi.org/project/agent-aegis/) — package page
