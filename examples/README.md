# Examples

Runnable examples demonstrating Aegis with different frameworks and use cases.

## No External Dependencies

These examples run with just `pip install agent-aegis`:

| Example | Description |
|---------|-------------|
| [`quickstart.py`](quickstart.py) | Basic policy engine demo with dry-run executor |
| [`conditions_demo.py`](conditions_demo.py) | Time-based, weekday, and param conditions |
| [`salesforce_demo.py`](salesforce_demo.py) | Real-world CRM governance scenario |

## Framework Integrations

These require additional dependencies (`pip install 'agent-aegis[all]'`):

| Example | Framework | Description |
|---------|-----------|-------------|
| [`httpx_demo.py`](httpx_demo.py) | httpx | REST API governance with httpbin.org |
| [`browser_demo.py`](browser_demo.py) | Playwright | Browser automation with approval gates |
| [`langchain_demo.py`](langchain_demo.py) | LangChain | Governed LangChain tool execution |
| [`crewai_demo.py`](crewai_demo.py) | CrewAI | CrewAI agent with governed tools |
| [`openai_agents_demo.py`](openai_agents_demo.py) | OpenAI Agents SDK | `@governed_tool` decorator pattern |
| [`anthropic_demo.py`](anthropic_demo.py) | Anthropic Claude | Govern Claude `tool_use` calls |

## Running

```bash
# Basic examples (no extra deps)
python examples/quickstart.py
python examples/conditions_demo.py

# httpx example
pip install 'agent-aegis[httpx]'
python examples/httpx_demo.py

# Browser example (requires Playwright)
pip install 'agent-aegis[playwright]'
playwright install chromium
python examples/browser_demo.py
```
