---
description: "NeMo Guardrails vs Aegis: LLM conversation control vs deterministic agent action security. Compare setup, latency, LLM dependency, and audit trails."
---

# NeMo Guardrails vs Aegis: Conversation Control vs Action Security

## TL;DR

NeMo Guardrails controls what an LLM *says* during a conversation -- topic steering, dialogue safety, and flow control. Aegis controls what an agent *does* -- tool calls, API requests, database writes, and file operations. They operate at different layers and work well together.

## What NeMo Guardrails Does

[NVIDIA NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) is a conversation-level safety framework. It uses **Colang**, a domain-specific language, to define rails that govern how an LLM-powered application interacts with users.

Key strengths:

- **Conversation flow control** -- define allowed and disallowed dialogue paths
- **Topic steering** -- keep the LLM focused on permitted subjects
- **Input/output rails** -- check what goes into and comes out of the LLM
- **Hallucination detection** -- fact-checking rails that verify LLM claims
- **Jailbreak prevention** -- detect attempts to bypass system instructions
- **Colang 2.0** -- a purpose-built language for modeling conversational interactions

NeMo Guardrails is particularly strong for customer-facing chatbots, virtual assistants, and any application where controlling the *conversation* is the primary concern.

**Trade-offs:**

- Requires an LLM call for rail evaluation (adds latency and cost)
- Colang has a learning curve beyond standard YAML/Python configuration
- Heavier setup -- requires defining flows, actions, and knowledge bases
- Primarily designed for dialogue-oriented applications

## What Aegis Does

Aegis is an action-layer security framework. It governs the concrete operations an AI agent performs, regardless of what conversation led to those operations.

Key strengths:

- **Deterministic evaluation** -- pattern matching, no LLM calls during policy checks
- **Sub-millisecond latency** -- policy evaluation adds < 1ms overhead
- **Auto-instrumentation** -- `pip install agent-aegis` and add one line of code
- **YAML policies** -- readable by developers and auditors, no DSL to learn
- **Approval workflows** -- built-in human-in-the-loop via CLI, Slack, Discord, Telegram, email, webhook
- **Audit trail** -- every action logged with full context (SQLite, JSONL, webhook, Python logging)
- **Runtime guardrails** -- prompt injection detection (109 patterns), PII masking (13 categories), toxicity filtering

**Trade-offs:**

- Does not control conversation flow or topic steering
- Does not perform hallucination detection
- Pattern-based guardrails are less flexible than LLM-based content analysis

## Side-by-Side Comparison

| Aspect | NeMo Guardrails | Aegis |
|--------|----------------|-------|
| **Primary focus** | Conversation flow and LLM behavior | Agent action security and governance |
| **What it checks** | Dialogue topics, input/output content, conversation flow | Tool calls, API requests, DB writes, file operations |
| **Configuration** | Colang DSL + YAML + Python actions | YAML policies |
| **Setup time** | Hours (Colang flows, knowledge bases, LLM config) | Minutes (`pip install` + 2 lines of code) |
| **Evaluation method** | LLM-in-the-loop (calls LLM to evaluate rails) | Deterministic pattern matching |
| **Latency per check** | 100ms--2s+ (depends on LLM provider) | < 1ms |
| **LLM dependency** | Required (for rail evaluation) | None (for policy evaluation) |
| **Cost per check** | LLM API cost per evaluation | Zero (no external API calls) |
| **Human approval** | Not built-in | 7 handlers (CLI, Slack, Discord, Telegram, email, webhook, custom) |
| **Audit trail** | Conversation logs | Action-level audit (SQLite, JSONL, webhook, logging) |
| **Framework support** | LangChain, LlamaIndex | LangChain, CrewAI, OpenAI Agents SDK, OpenAI, Anthropic, MCP, httpx, Playwright |
| **Hallucination detection** | Yes (via fact-checking rails) | No |
| **Topic steering** | Yes (core feature) | No |
| **Runtime guardrails** | Input/output content rails | Prompt injection, PII, toxicity, prompt leak detection |
| **License** | Apache 2.0 | MIT |

## When to Use What

**Use NeMo Guardrails when:**

- You are building a conversational AI (chatbot, virtual assistant, customer support)
- You need to control what topics the LLM discusses
- Hallucination detection is critical for your use case
- You need complex dialogue flow management
- The added latency and LLM cost per check is acceptable

**Use Aegis when:**

- Your agent performs real-world actions (API calls, database writes, file operations)
- You need sub-millisecond policy evaluation without LLM dependency
- You need human approval workflows for sensitive operations
- You need a compliance-ready audit trail
- You want to govern multiple frameworks with one policy
- You need to get governance running in minutes, not hours

**Use both when:**

- Your agent has conversations *and* takes actions based on those conversations
- NeMo Guardrails ensures the LLM stays on topic and behaves safely in dialogue
- Aegis ensures the resulting actions are authorized, approved, and audited

```
User request
    |
    v
NeMo Guardrails  -- Is this a valid conversation topic? Is the response safe?
    |
    v
Agent reasoning  -- LLM decides what action to take
    |
    v
Aegis            -- Is this action allowed? Does it need approval? Log it.
    |
    v
Execution        -- Tool call, API request, DB write
```

## Try Aegis

```bash
pip install agent-aegis
```

```python
import aegis
aegis.auto_instrument()

# Every AI call is now governed with prompt injection detection,
# PII masking, toxicity filtering, and full audit trail.
```

[Try it live in your browser](../playground/) -- no install needed.
