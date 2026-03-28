# openai-agents-aegis

Aegis governance integration for OpenAI Agents SDK. Add policy enforcement to any agent tool with one function call.

## Installation

```bash
pip install openai-agents-aegis
```

## Quick Start

```python
from openai_agents_aegis import govern_tools

# Wrap your existing tools — no other code changes needed
governed = govern_tools(tools, policy="policy.yaml")
agent = Agent(name="my_agent", tools=governed)
```

## What It Does

`openai-agents-aegis` evaluates every tool call against an [Aegis](https://github.com/Acacian/aegis) YAML policy before execution. Blocked actions return a governance message instead of running.

```
Tool call → Aegis policy check → allowed? → execute
                                  blocked? → return "[BLOCKED by Aegis] ..."
```

## Policy Example

```yaml
# policy.yaml
version: "1"
defaults:
  risk_level: medium
  approval: auto
rules:
  - name: allow_reads
    match:
      type: "read_*"
    risk_level: low
    approval: auto

  - name: block_deletes
    match:
      type: "delete_*"
    risk_level: critical
    approval: block
```

## API

### `@governed_tool` decorator

Wrap a function with governance before passing it to `@function_tool`:

```python
from agents import function_tool
from openai_agents_aegis import governed_tool

@function_tool
@governed_tool(policy="policy.yaml")
async def web_search(query: str) -> str:
    """Search the web."""
    return await do_search(query)
```

### `GovernedFunctionTool`

Wrap an existing `FunctionTool` instance:

```python
from openai_agents_aegis import GovernedFunctionTool

governed = GovernedFunctionTool(existing_tool, policy=my_policy)
```

### `govern_tools(tools, policy)`

Wrap multiple tools with the same policy:

```python
from openai_agents_aegis import govern_tools

governed = govern_tools(
    [search_tool, calculator_tool, delete_tool],
    policy="policy.yaml",
)
agent = Agent(name="assistant", tools=governed)
```

### Policy as object

```python
from aegis import Policy

policy = Policy.from_yaml("policy.yaml")
governed = govern_tools(tools, policy=policy)
```

## How It Works

- Tool name maps to `Action.type` in Aegis policy matching
- Tool input parameters map to `Action.params`
- Glob patterns in policy rules match tool names (`delete_*`, `*`)
- First matching rule wins — same as Aegis core
- `GovernedFunctionTool` intercepts at the `on_invoke_tool` level
- `@governed_tool` decorator intercepts before function execution
- Both sync and async tool functions are supported

## Requirements

- Python 3.11+
- `agent-aegis >= 0.6.0`
- `openai-agents >= 0.1`

## License

MIT — same as [Aegis](https://github.com/Acacian/aegis).
