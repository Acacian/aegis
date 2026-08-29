---
description: "Add guardrails to LangChain agents in 2 lines of Python. Policy-driven security with prompt injection detection, PII masking, and audit trail."
---

# LangChain Security: Guardrails for Tool Calls and LLM Outputs

LangChain agents can execute tool calls with no policy check, no human approval, and no audit trail. A single prompt injection or hallucinated function call can delete production data, leak PII, or send unauthorized emails. If you are searching for a way to add guardrails to LangChain, this page shows how to do it in 2 lines of Python.

## Quick Start

```bash
pip install agent-aegis
```

```python
import aegis
aegis.auto_instrument()

# That's it. Every LangChain LLM call and tool invocation is now governed.
# Prompt injection detection, PII masking, toxicity filtering, audit trail — all active.

from langchain_openai import ChatOpenAI
from langchain_core.tools import tool

@tool
def delete_user(user_id: str) -> str:
    """Delete a user from the database."""
    # Aegis checks this tool call against your policy before execution
    return f"Deleted {user_id}"

llm = ChatOpenAI(model="gpt-4o")
llm_with_tools = llm.bind_tools([delete_user])

# If the LLM tries to call delete_user, Aegis evaluates it against your policy.
# Blocked actions never execute.
```

Aegis monkey-patches `BaseChatModel.invoke/ainvoke` and `BaseTool.invoke/ainvoke` at import time. Your existing LangChain code stays untouched.

## How It Works

Aegis uses the same approach as OpenTelemetry (observability) and Sentry (error tracking): runtime monkey-patching. When you call `aegis.auto_instrument()`, it detects that LangChain is installed and wraps the core entry points.

Every LLM call and tool invocation passes through four guardrail checks before execution:

1. **Prompt injection detection** -- 109 patterns across 13 categories, 9 languages (EN/KO/ZH/JA/ES/DE/FR/TH/VI)
2. **PII detection** -- 12 categories including credit cards (Luhn-validated), SSNs, API keys
3. **Toxicity filtering** -- harmful/abusive content detection
4. **Prompt leak detection** -- system prompt extraction attempts

All checks are deterministic regex (no LLM calls) and run in sub-millisecond time.

### Adding Policy-Based Access Control

For fine-grained control over which tool calls are allowed, create a policy YAML file:

```yaml
# policy.yaml
version: "1"

defaults:
  risk_level: high
  approval: approve       # Default: require human review

rules:
  # Auto-allow all read operations
  - name: allow_reads
    match:
      type: "get_*"
    risk_level: low
    approval: auto

  # Allow search with no approval
  - name: allow_search
    match:
      type: "search_*"
    risk_level: low
    approval: auto

  # Block all delete operations
  - name: block_deletes
    match:
      type: "delete_*"
    risk_level: critical
    approval: block

  # Require approval for updates during off-hours
  - name: approve_updates_off_hours
    match:
      type: "update_*"
    conditions:
      time_after: "18:00"
    risk_level: high
    approval: approve
```

Load it with auto-instrumentation:

```python
import aegis
aegis.auto_instrument(policy="policy.yaml")
```

Or use the full Runtime API for manual control:

```python
from aegis import Action, Policy, Runtime
from aegis.adapters.langchain import LangChainExecutor

policy = Policy.from_yaml("policy.yaml")
runtime = Runtime(executor=LangChainExecutor(), policy=policy)

# Single action
result = await runtime.run_one(Action("delete_user", "users_db", params={"user_id": "123"}))
# result.status == BLOCKED — delete never executes
```

### Audit Trail

Every governed action is automatically logged with full context:

```bash
# View audit trail
aegis audit

# Export for compliance
aegis audit --format jsonl -o langchain_audit.jsonl
```

Each entry captures: timestamp, action type, target, parameters, risk level, matched policy rule, and outcome.

## Comparison

| Feature | Aegis | DIY if/else | NeMo Guardrails |
|---------|-------|-------------|-----------------|
| **Integration effort** | 2 lines | Grows per tool/framework | Config + Colang files |
| **Detection method** | Deterministic regex (109 patterns) | Manual rules | LLM-based classification |
| **Latency** | Sub-millisecond | Near-zero | 200-2000ms (LLM call) |
| **LLM dependency** | None | None | Requires LLM for every check |
| **Policy format** | YAML (declarative) | Python code | Colang DSL |
| **Audit trail** | Built-in (SQLite + JSONL + SIEM) | DIY | Limited |
| **Multi-framework** | LangChain + 8 other frameworks | Per-framework | LangChain only |
| **Human approval gates** | 7 handlers (Slack, CLI, webhook, ...) | DIY | No |
| **Cost per check** | $0 (no LLM calls) | $0 | $0.001-0.01 per LLM call |

**When to use NeMo Guardrails:** You need conversational flow control (dialog rails) or LLM-based semantic safety checks where regex patterns are insufficient.

**When to use Aegis:** You need policy-driven access control over tool calls, audit trails for compliance, human approval workflows, and sub-millisecond performance with zero LLM cost.

## Try It Now

- [**Interactive Playground**](https://acacian.github.io/aegis/playground/) -- try Aegis in your browser, no install needed
- [**GitHub**](https://github.com/Acacian/aegis) -- source code, examples, and documentation
- [**PyPI**](https://pypi.org/project/agent-aegis/) -- `pip install agent-aegis`
