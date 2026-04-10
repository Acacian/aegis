---
description: "Add guardrails to LiteLLM in 2 lines of Python. Prompt injection blocking, PII masking, and audit trail for litellm.completion() and acompletion()."
---

# LiteLLM Security: Guardrails for Multi-Provider LLM Calls

LiteLLM routes LLM calls to 100+ providers (OpenAI, Anthropic, Azure, Bedrock, Ollama, etc.) through a unified API. This makes it easy to switch providers — but it also means a single ungoverned `litellm.completion()` call can send unvalidated prompts to any provider without input checking, output filtering, or audit trail.

Aegis adds guardrails to every LiteLLM call with zero code changes.

## Quick Start

```bash
pip install agent-aegis litellm
```

```python
import aegis
aegis.auto_instrument()

# Every litellm.completion() and litellm.acompletion() call is now governed.

import litellm

response = litellm.completion(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Summarize this document"}],
)
# Aegis scanned the input for injection and the output for PII/toxicity
# before the response was returned.
```

## What Gets Patched

| Target | What it does |
|--------|-------------|
| `litellm.completion` | Sync LLM call — messages scanned before, response scanned after |
| `litellm.acompletion` | Async LLM call — same guardrails as sync |

Aegis extracts the `content` field from every message in the `messages` list and runs all four guardrail checks (injection, PII, toxicity, prompt leak) before the call reaches the LLM provider.

## LiteLLM-Specific Risks

### Multi-Provider Data Leakage

LiteLLM's strength is routing to any provider. But this means sensitive data in prompts can be sent to providers with different data policies:

```python
# This sends customer PII to whichever provider is configured
litellm.completion(
    model="gpt-4o",
    messages=[{"role": "user", "content": f"Summarize: {customer_record}"}],
)
```

Aegis detects PII (email, phone, SSN, credit card, API keys, etc.) in messages before they leave your application — regardless of which provider LiteLLM routes to.

### Proxy Mode Risks

LiteLLM is often used as a proxy server, handling requests from multiple applications. A single ungoverned proxy means every application behind it is ungoverned:

```python
import aegis
aegis.auto_instrument()

# Now every call through the LiteLLM proxy is governed,
# regardless of which application sent it.
```

### Fallback Chain Exposure

LiteLLM supports fallback chains (`model_list` with fallbacks). Without guardrails, a prompt that's safe for GPT-4 might be sent to a less restrictive fallback model:

```python
# Fallback chain: GPT-4 → Claude → Ollama local
response = litellm.completion(
    model="gpt-4o",
    messages=messages,
    fallbacks=["claude-3-5-sonnet-20241022", "ollama/llama3"],
)
# Aegis guardrails run ONCE before the first attempt.
# If the input contains injection, it's blocked before ANY provider sees it.
```

## Comparison

| Feature | Aegis | LiteLLM Callbacks | DIY Middleware |
|---------|-------|------------------|----------------|
| **Setup** | 2 lines | Custom callback class | Custom per endpoint |
| **Injection detection** | 85+ patterns, 4 languages | Write your own | Write your own |
| **PII detection** | 13 categories | Write your own | Write your own |
| **Audit trail** | Built-in (SQLite + JSONL) | success/failure hooks | DIY |
| **Latency** | Sub-millisecond | Depends on impl | Depends on impl |
| **Works with other frameworks** | 12 frameworks | LiteLLM only | Per-framework |

## Environment Variable (Zero Code Changes)

```bash
AEGIS_INSTRUMENT=1 python my_litellm_app.py
```

## Related Pages

- [**LiteLLM Governance Cookbook**](../cookbook/litellm-governance.md) — `completion`/`acompletion` recipe
- [**Prompt Injection Detection**](prompt-injection-detection.md) — 107 patterns, multi-language
- [**PII Detection for AI Agents**](pii-detection-ai-agent.md) — 13 categories
- [**LLM Guardrails for Python**](llm-guardrails-python.md) — framework-agnostic reference
- [**AI Agent Cost Governance**](ai-agent-cost-governance.md) — per-provider budget caps

## Try It Now

- [**Interactive Playground**](https://acacian.github.io/aegis/playground/) -- try Aegis in your browser, no install needed
- [**GitHub**](https://github.com/Acacian/aegis) -- source code, examples, and documentation
- [**PyPI**](https://pypi.org/project/agent-aegis/) -- `pip install agent-aegis`
