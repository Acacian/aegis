# langchain-aegis

Aegis governance integration for LangChain. Add policy enforcement to any LangChain tool with one function call.

## Installation

```bash
pip install langchain-aegis
```

## Quick Start

```python
from langchain_aegis import govern_tools

# Wrap your existing tools — no other code changes needed
governed = govern_tools(tools, policy="policy.yaml")
agent = create_react_agent(model, governed)
```

## What It Does

`langchain-aegis` evaluates every tool call against an [Aegis](https://github.com/Acacian/aegis) YAML policy before execution. Blocked actions return a governance message instead of running.

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

### `govern_tool(tool, policy)`

Wrap a single tool:

```python
from langchain_aegis import govern_tool

governed_search = govern_tool(search_tool, policy="policy.yaml")
result = governed_search.invoke({"query": "AI governance"})
```

### `govern_tools(tools, policy)`

Wrap multiple tools with the same policy:

```python
from langchain_aegis import govern_tools

governed = govern_tools(
    [search_tool, calculator_tool, delete_tool],
    policy="policy.yaml",
)
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
- Supports sync and async tool execution

## Requirements

- Python 3.11+
- `agent-aegis >= 0.1.3`
- `langchain-core >= 0.2`

## License

MIT — same as [Aegis](https://github.com/Acacian/aegis).
