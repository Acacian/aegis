---
description: "Control AI agent LLM costs with per-call, session, daily, and per-minute budget limits. Multi-agent cost attribution, loop detection, and built-in pricing for OpenAI, Anthropic, Google models."
---

# AI Agent Cost Governance

Autonomous AI agents can burn through API budgets in minutes. A single runaway loop — an agent retrying a failed tool call, or two agents delegating back and forth — can generate thousands of LLM calls before anyone notices. Aegis enforces cost limits at five dimensions (per-call, per-session, daily, per-minute token rate, and total budget) with automatic loop detection, blocking or warning before spend exceeds thresholds.

## Quick Start

```bash
pip install agent-aegis
```

### Policy-Based Cost Limits

Define cost limits in your `aegis.yaml` policy file:

```yaml
cost:
  budget_usd: 100.0            # Total budget ceiling
  per_call_limit_usd: 2.0      # Max cost per single LLM call
  per_session_limit_usd: 10.0  # Max cost per agent session
  daily_budget_usd: 50.0       # Max daily spend (resets at midnight UTC)
  per_minute_tokens: 100000    # Token rate limit (rolling 60s window)
  alert_threshold: 0.8         # Alert at 80% budget utilization
  on_exceed: block             # block | warn | log
```

### Programmatic Cost Enforcement

```python
from aegis.config import CostConfig
from aegis.core.cost_policy import CostPolicyEnforcer
from aegis.core.budget import TokenUsage

enforcer = CostPolicyEnforcer(CostConfig(
    budget_usd=100.0,
    per_session_limit_usd=5.0,
    daily_budget_usd=50.0,
    per_minute_tokens=100_000,
    on_exceed="block",
))

# Check before every LLM call
usage = TokenUsage(model="gpt-4o", input_tokens=5000, output_tokens=1000)
decision = enforcer.check_and_record(usage)

if decision.blocked:
    print(f"Blocked: {decision.reason}")
    # "Session spend $5.12 would exceed per-session limit $5.00"
else:
    print(f"Allowed. Cost: ${decision.cost_usd:.4f}, Total: ${decision.cumulative_usd:.4f}")
```

### Auto-Instrument with Cost Tracking

```python
import aegis

aegis.auto_instrument(cost=CostConfig(
    budget_usd=50.0,
    per_call_limit_usd=1.0,
    on_exceed="block",
))

# Every LLM call across LangChain, OpenAI, Anthropic, CrewAI
# is now cost-tracked and budget-enforced automatically.
```

## Cost Dimensions

Aegis enforces five independent cost dimensions. Each is optional — omit any limit you don't need.

| Dimension | Config Key | What It Prevents |
|-----------|-----------|-----------------|
| **Per-call** | `per_call_limit_usd` | A single expensive prompt (e.g., 128K context window) |
| **Per-session** | `per_session_limit_usd` | Runaway agent session burning through budget |
| **Daily** | `daily_budget_usd` | Daily spend cap, resets at midnight UTC |
| **Token rate** | `per_minute_tokens` | Token-per-minute rate limit (rolling 60s window) |
| **Total budget** | `budget_usd` | Hard ceiling across all sessions |

When a limit is hit, the `on_exceed` policy determines the response:

- **`block`** — The call is rejected before it reaches the LLM. Cost is not recorded.
- **`warn`** — The call proceeds, but a warning is logged and returned in the decision.
- **`log`** — Same as warn. The call proceeds with a log entry.

## Multi-Agent Cost Attribution

When multiple agents collaborate (orchestrator delegates to workers), you need to know which agent spent what. Aegis provides a `CostAttributionTree` that tracks costs across delegation chains with per-agent budgets that roll up to the parent.

```python
from aegis.core.cost_attribution import CostAttributionTree
from aegis.core.budget import TokenUsage

tree = CostAttributionTree(max_budget=50.0, session_id="run-42")

# Register agent hierarchy
tree.register_agent("orchestrator", max_budget=50.0)
tree.register_agent("researcher", parent_id="orchestrator", max_budget=20.0)
tree.register_agent("writer", parent_id="orchestrator", max_budget=15.0)
tree.register_agent("reviewer", parent_id="orchestrator", max_budget=10.0)

# Record costs as agents make LLM calls
tree.record("researcher", TokenUsage(model="gpt-4o", input_tokens=8000, output_tokens=2000))
tree.record("writer", TokenUsage(model="claude-sonnet-4", input_tokens=5000, output_tokens=3000))
tree.record("reviewer", TokenUsage(model="gpt-4o-mini", input_tokens=3000, output_tokens=500))

# Get attribution report
print(tree.format_report())
# Multi-Agent Cost Attribution
# ========================================
# Global: $0.1152 spent
# Budget: $50.00 (0% used)
#
# Agent                Direct   Delegated     Total  Calls
# ------------------------------------------------------------
# orchestrator         $  0.0000 $  0.1152 $  0.1152     0
#   researcher         $  0.0400 $  0.0000 $  0.0400     1
#   writer             $  0.0600 $  0.0000 $  0.0600     1
#   reviewer           $  0.0005 $  0.0000 $  0.0005     1
```

Child agent budgets are automatically capped to the parent's remaining budget. When a child exhausts its budget, only that agent is blocked — the orchestrator and siblings continue operating.

## Framework Cost Callbacks

Aegis provides plug-and-play cost extractors for popular AI frameworks. Each extracts token usage from the framework's native response objects and records it in a shared `CostTracker`.

### LangChain

```python
from aegis.core.budget import CostTracker
from aegis.core.cost_callbacks import LangChainCostCallback

tracker = CostTracker(max_budget=10.0)
callback = LangChainCostCallback(tracker, agent_id="research-agent")

# Use as a LangChain callback handler
from langchain_openai import ChatOpenAI
llm = ChatOpenAI(model="gpt-4o", callbacks=[callback])

response = llm.invoke("Summarize this document...")
print(f"Spent: ${tracker.spent:.4f}, Remaining: ${tracker.remaining:.4f}")
```

### OpenAI

```python
from aegis.core.cost_callbacks import OpenAICostExtractor
from aegis.core.budget import CostTracker

tracker = CostTracker(max_budget=5.0)
extractor = OpenAICostExtractor(tracker)

import openai
client = openai.OpenAI()
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Hello"}],
)
extractor.record(response)  # Extracts usage, records cost
```

### Anthropic

```python
from aegis.core.cost_callbacks import AnthropicCostExtractor
from aegis.core.budget import CostTracker

tracker = CostTracker(max_budget=5.0)
extractor = AnthropicCostExtractor(tracker)

import anthropic
client = anthropic.Anthropic()
message = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello"}],
)
extractor.record(message)  # Extracts usage, records cost
```

### Google Generative AI / ADK

```python
from aegis.core.cost_callbacks import GoogleCostExtractor
from aegis.core.budget import CostTracker

tracker = CostTracker(max_budget=5.0)
extractor = GoogleCostExtractor(tracker, default_model="gemini-2.5-flash")

# Works with google.generativeai and Google ADK responses
extractor.record(response, model="gemini-2.5-pro")
```

## Built-In Model Pricing

Aegis ships with a pricing table covering major model families (updated March 2026):

| Model Family | Input ($/M tokens) | Output ($/M tokens) | Cached ($/M tokens) |
|-------------|--------------------:|---------------------:|--------------------:|
| GPT-4o | 2.50 | 10.00 | 1.25 |
| GPT-4o Mini | 0.15 | 0.60 | 0.075 |
| GPT-4.1 | 2.00 | 8.00 | 0.50 |
| o3 | 10.00 | 40.00 | 2.50 |
| Claude Opus 4 | 15.00 | 75.00 | 1.50 |
| Claude Sonnet 4 | 3.00 | 15.00 | 0.30 |
| Gemini 2.5 Pro | 1.25 | 10.00 | 0.3125 |
| Gemini 2.5 Flash | 0.15 | 0.60 | 0.0375 |

Uses longest-prefix matching — `claude-sonnet-4-20250514` automatically matches `claude-sonnet-4` pricing. Register custom models:

```python
from aegis.core.budget import ModelPricing

pricing = ModelPricing()
pricing.register(
    "my-fine-tuned-model",
    input_per_million=5.0,
    output_per_million=15.0,
    cached_per_million=2.5,
)
```

## Loop Detection

The `CostTracker` includes automatic loop detection. When the same agent makes identical calls more than 5 times within 60 seconds, it raises `BudgetExhausted` — catching runaway retry loops before they drain your budget.

```python
from aegis.core.budget import CostTracker, TokenUsage, BudgetExhausted

tracker = CostTracker(max_budget=10.0)

# Simulate a runaway loop
for i in range(10):
    try:
        tracker.record(
            TokenUsage(model="gpt-4o", input_tokens=1000, output_tokens=200),
            agent_id="stuck-agent",
            action_type="retry_tool_call",
        )
    except BudgetExhausted:
        print(f"Loop detected at call {i + 1}")  # Loop detected at call 5
        break
```

The detection window and threshold are configurable:

```python
tracker = CostTracker(
    max_budget=10.0,
    loop_window=120.0,    # seconds (default: 60)
    loop_threshold=10,    # calls (default: 5)
)
```

## Cost Reports

Generate structured cost reports for monitoring and compliance:

```python
report = enforcer.get_report()
# {
#     "session_id": "run-42",
#     "max_budget": 100.0,
#     "spent": 12.3456,
#     "remaining": 87.6544,
#     "utilization": 0.1235,
#     "call_count": 47,
#     "by_model": {"gpt-4o": 8.2100, "claude-sonnet-4": 4.1356},
#     "by_agent": {"researcher": 5.0200, "writer": 7.3256},
#     "daily_spent": 12.3456,
#     "tokens_last_minute": 45230,
#     "limits": {
#         "budget_usd": 100.0,
#         "per_call_limit_usd": 2.0,
#         "per_session_limit_usd": 10.0,
#         "daily_budget_usd": 50.0,
#         "per_minute_tokens": 100000,
#         "on_exceed": "block",
#     }
# }
```

## Comparison with Alternatives

| Feature | Aegis | DIY | Guardrails AI | NeMo Guardrails |
|---------|-------|-----|--------------|-----------------|
| Multi-dimensional limits | Per-call, session, daily, rate, total | Manual tracking | N/A | N/A |
| Multi-agent attribution | Hierarchical tree with rollup | Custom code | N/A | N/A |
| Loop detection | Automatic (5 calls / 60s) | Manual | N/A | N/A |
| Built-in pricing table | 15+ models, prefix matching | Manual | N/A | N/A |
| Framework callbacks | LangChain, OpenAI, Anthropic, Google | Custom per-framework | N/A | N/A |
| Thread-safe | Lock-guarded | Depends on impl | N/A | N/A |
| Zero dependencies | Pure Python | Depends on impl | Multiple | Multiple |

## Next Steps

- [Quick Start](../getting-started/quickstart.md) — Get Aegis running in 5 minutes
- [Policy Patterns](../guides/policy-patterns.md) — Combine cost limits with security policies
- [Audit Trail](ai-agent-audit-trail.md) — Log every cost decision for compliance
- [EU AI Act Compliance](eu-ai-act-compliance.md) — Cost governance meets regulatory requirements
