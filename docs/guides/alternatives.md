---
description: "Aegis vs alternatives: how Aegis fits next to NeMo Guardrails, Guardrails AI, Microsoft AGT, mcp-scan, and DIY approaches. Pick the right governance tool."
---

# Aegis vs Alternatives

How Aegis fits into the AI agent governance landscape — and when to use what.

---

## Understanding the Landscape

AI agent governance isn't a single problem. It spans three distinct layers, each solving a different challenge:

| Layer | What it governs | Examples |
|-------|----------------|----------|
| **LLM Output Guardrails** | What the LLM *says* — output format, content safety, hallucination detection | Guardrails AI, NeMo Guardrails |
| **Action-Layer Governance** | What the agent *does* — API calls, tool use, database writes, file operations | **Aegis** |
| **Platform Governance** | Centralized infrastructure — fleet-wide policies, dashboards, compliance reporting | Galileo, JetStream, HumanLayer |

These layers are **complementary, not competing**. A production agent often needs coverage at multiple layers. Guardrails AI can validate that the LLM produced valid JSON before Aegis checks whether the agent is allowed to write that data to the database.

---

## Detailed Comparisons

### Aegis vs DIY (`if/else` Checks)

Every team starts here. Before reaching for a library, consider whether hand-rolled checks are enough.

**When DIY is fine:**

- Single tool, single framework
- No audit trail requirements
- Prototype or internal demo
- One developer, no policy handoff needed

**When Aegis wins:**

- Multiple tools or frameworks to govern with one policy
- Audit trail required for compliance or debugging
- Human approval workflows needed (Slack, CLI, custom)
- Conditional rules — time-of-day, parameter thresholds, weekday-only access
- Policy changes without code deploys (edit YAML, not Python)
- Team grows and policy needs to be readable by non-developers

```python
# DIY: grows fast, scatters across codebase
if action == "delete" and target.startswith("prod"):
    raise PermissionError("blocked")
elif action == "write" and not is_business_hours():
    await get_approval(...)
# ... repeated per tool, per framework, per project

# Aegis: one YAML file, all frameworks
# policy.yaml
# rules:
#   - name: block_prod_delete
#     match: { type: delete, target: "prod_*" }
#     approval: block
#   - name: approve_writes_off_hours
#     match: { type: write }
#     conditions: [{ field: "time_before", value: "09:00" }]
#     approval: approve
```

---

### Aegis vs Guardrails AI

[Guardrails AI](https://www.guardrailsai.com/) validates and structures LLM outputs. It ensures the model returns valid JSON, stays on topic, and doesn't produce harmful content.

Aegis governs what happens *after* the LLM produces output — the actions the agent takes based on that output.

| Aspect | Guardrails AI | Aegis |
|--------|--------------|-------|
| **Focus** | LLM output validation | Agent action governance |
| **What's governed** | Text, JSON, structured output | API calls, tool use, DB writes, file ops |
| **Human approval** | Not applicable | Built-in (CLI, callbacks, custom channels) |
| **Audit trail** | Validation logs | Full action audit (SQLite, JSONL, logging) |
| **Policy format** | Python validators / Rails | YAML rules with glob matching |
| **Framework support** | LLM-focused (OpenAI, Anthropic, etc.) | Agent-focused (LangChain, CrewAI, OpenAI Agents, MCP, etc.) |

**They're complementary.** Guardrails AI validates the LLM's output structure; Aegis governs the agent's resulting actions. Use both for defense in depth.

---

### Aegis vs NeMo Guardrails

[NVIDIA NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) controls conversation flow and safety at the dialogue level. It defines rails for what the LLM can and cannot discuss, handles topic steering, and enforces conversation boundaries.

Aegis operates one layer down — it doesn't care about conversation flow, only about the concrete actions the agent takes.

| Aspect | NeMo Guardrails | Aegis |
|--------|----------------|-------|
| **Focus** | Conversation flow and safety | Action execution governance |
| **What's governed** | Dialogue, topics, LLM behavior | Tool calls, API requests, DB operations |
| **Configuration** | Colang (domain-specific language) | YAML policies |
| **Human approval** | Not built-in | Built-in (CLI, callbacks, custom) |
| **Audit trail** | Conversation logs | Action-level audit (SQLite, JSONL) |
| **Best for** | Chatbots, dialogue agents | Tool-using agents, autonomous workflows |

**Also complementary.** NeMo Guardrails ensures the agent stays on topic and behaves safely in conversation. Aegis ensures the actions it takes are authorized and audited.

---

### Aegis vs Platform-Native Guardrails (OpenAI, Google, Anthropic)

Major LLM providers offer built-in safety features — content filters, function calling constraints, and usage policies. These work well within their ecosystem.

The limitation: they only cover their own platform. If your agent uses OpenAI for reasoning and Anthropic for a different task, or calls tools across multiple providers, you need a governance layer that spans all of them.

| Aspect | Platform-Native Guardrails | Aegis |
|--------|---------------------------|-------|
| **Cross-platform** | Single provider only | All providers, one policy |
| **Action governance** | Limited (function calling constraints) | Full (any action type, any target) |
| **Human approval** | Not available | Built-in with multiple channels |
| **Audit trail** | Platform-specific logs | Unified audit across all providers |
| **Custom policies** | Provider-defined limits | Your rules, your YAML |
| **Framework support** | Provider SDK only | LangChain, CrewAI, OpenAI, Anthropic, MCP, etc. |

**Use together.** Platform guardrails handle provider-specific safety. Aegis adds a consistent governance layer across everything.

---

### Aegis vs Enterprise Platforms (Galileo, JetStream, HumanLayer)

Enterprise governance platforms provide centralized dashboards, fleet-wide policy management, compliance reporting, and team management. They're designed for organizations running many agents at scale.

Aegis is a Python library. `pip install` and you have governance in 5 minutes. No Kubernetes, no cloud infrastructure, no vendor contracts.

| Aspect | Enterprise Platforms | Aegis |
|--------|---------------------|-------|
| **Setup time** | Days to weeks | 5 minutes |
| **Infrastructure** | K8s, cloud services, SaaS | None — it's a library |
| **Cost** | Enterprise pricing | Free, open-source (MIT) |
| **Target audience** | Platform teams, enterprise | Developers, small teams, startups |
| **Fleet management** | Centralized dashboards | Per-project YAML policies |
| **Compliance reporting** | Built-in | Audit trail + export (build your own reports) |
| **Approval workflows** | Full UI, Slack, Teams, etc. | CLI, callbacks, extensible handlers |
| **Vendor lock-in** | Varies | None |

**Different tools for different stages.** Aegis is ideal for development teams that need governance now without infrastructure overhead. Enterprise platforms serve organizations that need centralized control across many teams and agents. You can start with Aegis and migrate to a platform later — the policy concepts translate directly.

---

## When to Use What

```
Need to validate LLM output format/content?
  └─→ Guardrails AI

Need conversation safety rails and topic control?
  └─→ NeMo Guardrails

Need cross-platform action governance with zero infra?
  └─→ Aegis

Need enterprise-grade centralized control plane?
  └─→ Galileo / JetStream / HumanLayer

Need governance NOW for your development team?
  └─→ Start with Aegis, upgrade later if needed
```

For most teams building AI agents today, the practical path is:

1. **Start with Aegis** — `pip install agent-aegis`, write a YAML policy, ship governance today
2. **Add Guardrails AI** if you need LLM output validation
3. **Add NeMo Guardrails** if you need conversation flow control
4. **Evaluate enterprise platforms** when you have 10+ agents and need fleet-wide management

---

## Using Aegis Together With Other Tools

### Aegis + Guardrails AI

Validate LLM output first, then govern the resulting action:

```python
from guardrails import Guard
from aegis import Action, Policy, Runtime

# Step 1: Validate LLM output with Guardrails AI
guard = Guard.from_pydantic(output_class=OrderAction)
validated_output = guard(llm_api=my_llm, prompt=user_request)

# Step 2: Govern the action with Aegis
runtime = Runtime(
    executor=my_executor,
    policy=Policy.from_yaml("policy.yaml"),
)
result = await runtime.run_one(
    Action(
        type=validated_output.action_type,
        target=validated_output.target,
        params=validated_output.params,
    )
)
```

The two libraries don't conflict — Guardrails AI ensures the LLM output is well-formed, Aegis ensures the resulting action is authorized.

### Aegis + Platform-Native Guardrails

Platform guardrails handle provider-level safety. Aegis adds a cross-platform governance layer on top:

```python
from aegis import Action, Policy, Runtime
from aegis.adapters.langchain import LangChainExecutor

# Platform guardrails are configured at the provider level
# (e.g., OpenAI content filters, Anthropic usage policies)

# Aegis adds unified action governance across all providers
runtime = Runtime(
    executor=LangChainExecutor(tools=my_tools),
    policy=Policy.from_yaml("policy.yaml"),
)

# Every tool call — regardless of which LLM provider triggered it —
# goes through the same Aegis policy before execution
plan = runtime.plan([
    Action("search", "web", params={"query": "quarterly revenue"}),   # auto
    Action("write", "crm", params={"record_id": 42, "status": "closed"}),  # approve
    Action("delete", "crm", params={"record_id": 42}),  # block
])
results = await runtime.execute(plan)
```

This gives you provider-level safety *plus* consistent action governance that works the same way regardless of which LLM or framework you're using.
