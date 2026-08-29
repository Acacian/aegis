---
description: "Guardrails AI vs Aegis: LLM output validation vs agent action security. They solve different problems and work best together."
---

# Guardrails AI vs Aegis: Output Validation vs Action Security

## TL;DR

Guardrails AI validates what an LLM *produces* -- ensuring outputs are well-formed, on-topic, and safe. Aegis governs what an agent *does* with that output -- tool calls, API requests, and database writes. They solve different problems and are complementary, not competitive.

## What Guardrails AI Does

[Guardrails AI](https://www.guardrailsai.com/) is an LLM output validation framework. It wraps LLM calls with validators that check the response before it reaches your application.

Key strengths:

- **Output structure validation** -- enforce JSON schemas, Pydantic models, and typed responses
- **Content safety** -- detect toxic, biased, or inappropriate content in LLM output
- **Factuality checking** -- validate claims against reference text
- **PII detection** -- find and redact sensitive information in LLM responses
- **Re-ask loop** -- automatically retry the LLM when validation fails
- **Guardrails Hub** -- community-contributed validators for common use cases
- **Guardrails Server** -- deploy validators as a service

Guardrails AI is strong when you need to ensure the LLM produces correctly formatted, safe, and accurate text output.

**Trade-offs:**

- Focused on LLM output, not on the actions that follow
- Some validators require LLM calls (adds latency and cost)
- No built-in approval workflows for human oversight
- No action-level audit trail

## What Aegis Does

Aegis is an action-layer security framework. It governs what happens *after* the LLM produces output -- the concrete operations an agent executes based on that output.

Key strengths:

- **Action governance** -- control which tool calls, API requests, and DB writes are allowed
- **YAML policies** -- define rules with glob patterns, conditions, and risk levels
- **Approval workflows** -- human-in-the-loop via CLI, Slack, Discord, Telegram, email, webhook
- **Audit trail** -- every action logged with full context for compliance
- **Auto-instrumentation** -- one line governs LangChain, CrewAI, OpenAI Agents SDK, OpenAI, Anthropic
- **Runtime guardrails** -- prompt injection detection, PII masking, toxicity filtering on inputs and outputs
- **Deterministic evaluation** -- sub-millisecond, no LLM calls during policy checks

**Trade-offs:**

- Does not validate LLM output structure or format
- Does not enforce JSON schemas or Pydantic models on LLM responses
- No re-ask loop for malformed LLM output

## Side-by-Side Comparison

| Aspect | Guardrails AI | Aegis |
|--------|--------------|-------|
| **Primary focus** | LLM output validation | Agent action governance |
| **What it checks** | Text format, content safety, factuality, schema compliance | Tool calls, API requests, DB writes, file operations |
| **Where it runs** | Between LLM and application (output validation) | Between agent decision and execution (action gate) |
| **LLM dependency** | Some validators require LLM calls | None for policy evaluation |
| **Latency** | Varies (ms for regex, seconds for LLM-based validators) | < 1ms for policy checks |
| **Output schema enforcement** | Yes (Pydantic, JSON Schema, custom validators) | No (not its purpose) |
| **Re-ask on failure** | Yes (automatic retry with corrective prompt) | No (blocks or requires approval) |
| **Approval workflows** | No | 7 built-in handlers (CLI, Slack, Discord, Telegram, email, webhook, custom) |
| **Action-level audit trail** | No | Yes (SQLite, JSONL, webhook, Python logging) |
| **Auto-instrumentation** | No (explicit Guard wrapping) | Yes (`aegis.auto_instrument()`) |
| **Runtime guardrails** | Content validators (toxicity, PII, etc.) | Prompt injection (109 patterns), PII (13 categories), toxicity, prompt leak |
| **Framework support** | OpenAI, Anthropic, Cohere, LiteLLM, Hugging Face | LangChain, CrewAI, OpenAI Agents SDK, OpenAI, Anthropic, MCP, httpx, Playwright |
| **Community ecosystem** | Guardrails Hub (validator marketplace) | YAML policy patterns + cookbook recipes |
| **License** | Apache 2.0 | MIT |

## When to Use What

**Use Guardrails AI when:**

- You need to enforce output format (JSON, Pydantic models, typed fields)
- You need factuality validation against reference documents
- You want automatic re-ask when the LLM produces malformed output
- Your primary concern is what the LLM *says*, not what the agent *does*

**Use Aegis when:**

- Your agent performs real-world actions based on LLM output
- You need policy-based control over which actions are allowed
- You need human approval for sensitive operations
- You need a compliance-ready audit trail of every action
- You want to govern multiple AI frameworks with a single policy

**Use both for defense in depth:**

```python
from guardrails import Guard
from aegis import Action, Policy, Runtime

# Step 1: Validate LLM output with Guardrails AI
guard = Guard.from_pydantic(output_class=OrderAction)
validated_output = guard(llm_api=my_llm, prompt=user_request)

# Step 2: Govern the resulting action with Aegis
async with Runtime(
    executor=my_executor,
    policy=Policy.from_yaml("policy.yaml"),
) as runtime:
    result = await runtime.run_one(
        Action(
            type=validated_output.action_type,
            target=validated_output.target,
            params=validated_output.params,
        )
    )
```

```
LLM produces output
    |
    v
Guardrails AI  -- Is the output valid JSON? Is it safe? Is it factual?
    |
    v
Agent logic    -- Parse validated output into an action
    |
    v
Aegis          -- Is this action allowed? Does it need approval? Log it.
    |
    v
Execution      -- Tool call, API request, DB write
```

This is the recommended pattern: Guardrails AI ensures the LLM output is well-formed, Aegis ensures the resulting action is authorized. Neither replaces the other.

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
