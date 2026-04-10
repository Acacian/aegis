---
description: "Adapters API reference: BaseExecutor interface, built-in adapters for 12 Python AI frameworks, and custom adapter API for Aegis policy governance."
---

# Adapters

## BaseExecutor

```python
from aegis.adapters.base import BaseExecutor
```

Abstract base class. Only `execute()` is required.

| Method | Required | Description |
|--------|----------|-------------|
| `execute(action)` | Yes | Execute a single action |
| `verify(action, result)` | No | Post-execution verification |
| `setup()` | No | Initialize resources |
| `teardown()` | No | Clean up resources |

## PlaywrightExecutor

```python
from aegis.adapters.playwright import PlaywrightExecutor

executor = PlaywrightExecutor(headless=True, browser_type="chromium")
```

| Action Type | Params | Description |
|-------------|--------|-------------|
| `navigate` | `{"url": str}` | Go to a URL |
| `click` | `{"selector": str}` | Click an element |
| `fill` | `{"selector": str, "value": str}` | Fill an input field |
| `read` | `{"selector": str}` | Extract text content |
| `screenshot` | `{"path": str}` | Take a screenshot |

Requires: `pip install 'agent-aegis[playwright]'`

## LangChainExecutor

```python
from aegis.adapters.langchain import LangChainExecutor

executor = LangChainExecutor(tools=[...])
executor.register_tool(another_tool)
```

Maps `Action.type` to LangChain tool names.

Requires: `pip install 'agent-aegis[langchain]'`

## AegisTool (LangChain)

```python
from aegis.adapters.langchain import AegisTool

tool = AegisTool.from_runtime(
    runtime=runtime,
    name="tool_name",
    description="description",
    action_type="action_type",
    action_target="target",
)
```

Creates a LangChain `StructuredTool` that routes through Aegis.

## AegisCrewAITool

```python
from aegis.adapters.crewai import AegisCrewAITool

tool = AegisCrewAITool(
    runtime=runtime,
    name="tool_name",
    description="description",
    action_type="action_type",
    fn=my_function,
)
```

Requires: `pip install 'agent-aegis[crewai]'`

## HttpxExecutor

```python
from aegis.adapters.httpx_adapter import HttpxExecutor

executor = HttpxExecutor(
    base_url="https://api.example.com",
    default_headers={"Authorization": "Bearer ..."},
    timeout=30.0,
)
```

| Action Type | HTTP Method |
|-------------|-------------|
| `get` | GET |
| `post` | POST |
| `put` | PUT |
| `patch` | PATCH |
| `delete` | DELETE |
| `head` | HEAD |
| `options` | OPTIONS |

Supported `params` keys: `json`, `data`, `headers`, `query`, `timeout`.

Requires: `pip install 'agent-aegis[httpx]'`

## @governed_tool (OpenAI Agents SDK)

```python
from aegis.adapters.openai_agents import governed_tool

@governed_tool(runtime=runtime, action_type="write", action_target="crm")
async def my_tool(query: str) -> str:
    ...
```

Requires: `pip install 'agent-aegis[openai-agents]'`

## govern_tool_call (Anthropic Claude)

```python
from aegis.adapters.anthropic import govern_tool_call

result = await govern_tool_call(
    runtime=runtime,
    tool_name="update_contact",
    tool_input={"name": "Alice"},
    target="crm",
)
```

Requires: `pip install 'agent-aegis[anthropic]'`

## govern_mcp_tool_call (MCP)

```python
from aegis.adapters.mcp import govern_mcp_tool_call

result = await govern_mcp_tool_call(
    runtime=runtime,
    tool_name="read_file",
    arguments={"path": "/data.csv"},
    server_name="filesystem",
)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `runtime` | `Runtime` | Aegis runtime instance |
| `tool_name` | `str` | MCP tool name (becomes `Action.type`) |
| `arguments` | `dict` | Tool arguments (becomes `Action.params`) |
| `server_name` | `str` | MCP server name (becomes `Action.target`) |
| `description` | `str` | Optional description |

## AegisMCPToolFilter

```python
from aegis.adapters.mcp import AegisMCPToolFilter

tool_filter = AegisMCPToolFilter(runtime=runtime)

# Dry-run check
result = await tool_filter.check(server="filesystem", tool="delete_file")

# Full governance pipeline
result = await tool_filter.call_tool(
    server="filesystem", tool="read_file",
    arguments={"path": "/data.csv"},
)
```

| Method | Description |
|--------|-------------|
| `check(server, tool, arguments)` | Dry-run policy check |
| `call_tool(server, tool, arguments)` | Full governance pipeline |
