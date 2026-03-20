# Integrations

Aegis integrates with popular AI agent frameworks. Install only what you need.

## LangChain

```bash
pip install 'agent-aegis[langchain]'
```

### Option A: Govern LangChain tools

Run existing LangChain tools through Aegis policy checks:

```python
from langchain_community.tools import DuckDuckGoSearchRun
from aegis import Action, Policy, Runtime
from aegis.adapters.langchain import LangChainExecutor

executor = LangChainExecutor(tools=[DuckDuckGoSearchRun()])
runtime = Runtime(
    executor=executor,
    policy=Policy.from_yaml("policy.yaml"),
)

plan = runtime.plan([
    Action("DuckDuckGoSearchRun", target="web", params={"query": "AI safety"}),
])
results = await runtime.execute(plan)
```

The action `type` matches the LangChain tool's `.name` property.

### Option B: Expose Aegis as a LangChain tool

Let a LangChain agent call Aegis-governed actions as regular tools:

```python
from aegis.adapters.langchain import AegisTool

tool = AegisTool.from_runtime(
    runtime=runtime,
    name="governed_search",
    description="Search the web with policy governance",
    action_type="search",
    action_target="web",
)

# Use in any LangChain agent
from langchain.agents import AgentExecutor
agent = AgentExecutor(tools=[tool], ...)
```

## OpenAI Agents SDK

```bash
pip install 'agent-aegis[openai-agents]'
```

Use the `@governed_tool` decorator to wrap any function tool:

```python
from agents import Agent, Runner
from aegis.adapters.openai_agents import governed_tool

@governed_tool(runtime=runtime, action_type="write", action_target="crm")
async def update_contact(name: str, email: str) -> str:
    """Update a contact in the CRM."""
    return await crm_api.update(name=name, email=email)

agent = Agent(name="sales_assistant", tools=[update_contact])
result = await Runner.run(agent, "Update John's email")
```

The decorator:

1. Intercepts the function call
2. Creates an Aegis `Action` from the arguments
3. Checks the policy and requests approval if needed
4. Executes the original function if allowed
5. Logs everything to the audit trail

## CrewAI

```bash
pip install 'agent-aegis[crewai]'
```

```python
from crewai import Agent, Task, Crew
from aegis.adapters.crewai import AegisCrewAITool

search_tool = AegisCrewAITool(
    runtime=runtime,
    name="governed_search",
    description="Search with policy governance",
    action_type="search",
    action_target="web",
    fn=lambda query: my_search(query),
)

agent = Agent(
    role="researcher",
    goal="Find information about AI governance",
    tools=[search_tool],
)
```

## Playwright

```bash
pip install 'agent-aegis[playwright]'
playwright install chromium
```

```python
from aegis.adapters.playwright import PlaywrightExecutor

runtime = Runtime(
    executor=PlaywrightExecutor(headless=True),
    policy=Policy.from_yaml("policy.yaml"),
)

plan = runtime.plan([
    Action("navigate", "app", params={"url": "https://app.example.com"}),
    Action("fill", "app", params={"selector": "#name", "value": "Alice"}),
    Action("click", "app", params={"selector": "#submit"}),
])
results = await runtime.execute(plan)
```

Supported actions: `navigate`, `click`, `fill`, `read`, `screenshot`.
