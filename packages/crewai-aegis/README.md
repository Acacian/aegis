# crewai-aegis

Aegis governance integration for CrewAI. Add policy enforcement to any CrewAI tool with one function call.

## Installation

```bash
pip install crewai-aegis
```

## Quick Start

### Option 1: Wrap tools directly

```python
from crewai_aegis import govern_tools

# Wrap your existing tools — no other code changes needed
governed = govern_tools(tools, policy="policy.yaml")
```

### Option 2: Register hooks on a Crew

```python
from crewai import Crew
from crewai_aegis import register_aegis_hooks

crew = Crew(agents=[agent], tasks=[task])
register_aegis_hooks(crew, policy="policy.yaml")
result = crew.kickoff()
```

## What It Does

`crewai-aegis` evaluates every tool call against an [Aegis](https://github.com/Acacian/aegis) YAML policy before execution. Blocked actions return a governance message instead of running.

```
Tool call -> Aegis policy check -> allowed? -> execute
                                   blocked? -> return "[BLOCKED by Aegis] ..."
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

### `govern_tools(tools, policy)`

Wrap multiple tools with the same policy:

```python
from crewai_aegis import govern_tools

governed = govern_tools(
    [search_tool, calculator_tool, delete_tool],
    policy="policy.yaml",
)
```

### `register_aegis_hooks(crew, policy)`

Register a before-tool-call hook on a Crew:

```python
from crewai import Crew
from crewai_aegis import register_aegis_hooks

crew = Crew(agents=[agent], tasks=[task])
register_aegis_hooks(crew, policy="policy.yaml")
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
- `GovernedCrewAITool` wraps individual tools with policy checks
- `register_aegis_hooks` uses CrewAI's `BeforeToolCallHook` protocol

## Requirements

- Python 3.11+
- `agent-aegis >= 0.6.0`
- `crewai >= 0.50`

## License

MIT — same as [Aegis](https://github.com/Acacian/aegis).
