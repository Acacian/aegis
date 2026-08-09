---
description: "Add guardrails to OpenAI Agents SDK in 2 lines of Python. Prompt injection blocking, PII masking, and audit trail for Runner.run and tool calls."
---

# OpenAI Agents SDK Security: Guardrails for Agent Runs

The OpenAI Agents SDK (`openai-agents`) lets you build agents with tool calling, handoffs, and guardrails. But the built-in guardrails require you to write custom guardrail classes for each check. Aegis adds prompt injection detection, PII masking, toxicity filtering, and full audit trail to every `Runner.run` call — in 2 lines, no custom classes needed.

## Quick Start

```bash
pip install agent-aegis openai-agents
```

```python
import aegis
aegis.auto_instrument()

# Every Runner.run() and Runner.run_sync() call is now governed.

from agents import Agent, Runner

agent = Agent(
    name="Assistant",
    instructions="You are a helpful assistant.",
)

result = Runner.run_sync(agent, "What is the capital of France?")
# Aegis scanned the input for injection and the output for PII/toxicity.
print(result.final_output)
```

## What Gets Patched

| Target | What it does |
|--------|-------------|
| `Runner.run` | Async agent execution — input scanned before, output scanned after |
| `Runner.run_sync` | Sync agent execution — same guardrails as async |

Aegis wraps both entry points. Every user input is checked for prompt injection before it reaches the agent. Every agent output is checked for PII and toxicity before it's returned.

## Why Not Just Use Built-in Guardrails?

The OpenAI Agents SDK has a guardrails system, but it requires writing a Python class per guardrail:

```python
# OpenAI Agents SDK built-in approach — manual class per guardrail
from agents import GuardrailFunctionOutput, InputGuardrail

async def injection_guardrail(ctx, agent, input):
    # You write the detection logic yourself
    if "ignore previous" in input.lower():
        return GuardrailFunctionOutput(
            output_info={"reason": "injection"},
            tripwire_triggered=True,
        )
    return GuardrailFunctionOutput(output_info={}, tripwire_triggered=False)

agent = Agent(
    name="Assistant",
    input_guardrails=[InputGuardrail(guardrail_function=injection_guardrail)],
)
```

This approach requires:

- Writing detection logic for every attack category (13 categories, 85+ patterns)
- Maintaining and updating patterns as new attacks emerge
- Adding PII detection, toxicity filtering separately
- Building your own audit trail
- Repeating this for every agent

With Aegis:

```python
import aegis
aegis.auto_instrument()
# Done. 85+ injection patterns, 13 PII categories, toxicity, prompt leak — all active.
```

## Aegis + OpenAI Built-in Guardrails

Aegis and the SDK's built-in guardrails are complementary. Aegis handles the common cases (injection, PII, toxicity) as a baseline. You can add custom SDK guardrails for domain-specific logic on top:

```python
import aegis
aegis.auto_instrument()  # Baseline: injection, PII, toxicity, audit

from agents import Agent, InputGuardrail

# Your custom business logic guardrail
async def budget_guardrail(ctx, agent, input):
    # Domain-specific check that Aegis doesn't cover
    ...

agent = Agent(
    name="Finance Bot",
    input_guardrails=[InputGuardrail(guardrail_function=budget_guardrail)],
)
# Both Aegis guardrails AND your custom guardrail run on every call.
```

## Comparison

| Feature | Aegis auto_instrument | OpenAI SDK Built-in | DIY |
|---------|----------------------|--------------------|----|
| **Setup** | 2 lines | Class per guardrail | Full custom |
| **Injection detection** | 85+ patterns, 4 languages | Write your own | Write your own |
| **PII detection** | 13 categories | Write your own | Write your own |
| **Audit trail** | Built-in | None | DIY |
| **Latency** | Sub-millisecond | Depends on impl | Depends on impl |
| **Maintenance** | `pip install --upgrade` | Manual updates | Manual updates |
| **Works with other frameworks** | 12 frameworks | OpenAI SDK only | Per-framework |

## Related Pages

- [**OpenAI Agents Governance Cookbook**](../cookbook/openai-agents-governance.md) — `Runner.run` policy hook recipe
- [**Prompt Injection Detection**](prompt-injection-detection.md) — 101 patterns blocking attacks
- [**LLM Guardrails for Python**](llm-guardrails-python.md) — framework-agnostic guardrails
- [**Aegis vs NeMo Guardrails**](../comparisons/vs-nemo-guardrails.md) — when to use which
- [**Aegis vs Guardrails AI**](../comparisons/vs-guardrails-ai.md) — action security vs output validation

## Try It Now

- [**Interactive Playground**](https://acacian.github.io/aegis/playground/) -- try Aegis in your browser, no install needed
- [**GitHub**](https://github.com/Acacian/aegis) -- source code, examples, and documentation
- [**PyPI**](https://pypi.org/project/agent-aegis/) -- `pip install agent-aegis`
