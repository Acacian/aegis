# Examples

Runnable examples demonstrating Aegis with different frameworks and use cases.

> **Want to try without installing?** [Open the Playground](https://acacian.github.io/aegis/playground/) — runs Aegis entirely in your browser.

## No External Dependencies

These examples run with just `pip install agent-aegis`:

| Example | Description | What You'll See |
|---------|-------------|----------------|
| [`quickstart.py`](quickstart.py) | Basic policy engine demo with dry-run executor | Execution plan + risk levels + audit log |
| [`conditions_demo.py`](conditions_demo.py) | Time-based, weekday, and param conditions | Conditional rule matching in action |
| [`salesforce_demo.py`](salesforce_demo.py) | Real-world CRM governance scenario | Full Salesforce workflow with policy gates |
| [`mcp_demo.py`](mcp_demo.py) | MCP tool call governance with per-server policies | MCP server-aware policy evaluation |
| [`multi_agent_demo.py`](multi_agent_demo.py) | Org → team → agent policy hierarchy | Conflict detection + most-restrictive-wins |
| [`compliance_demo.py`](compliance_demo.py) | SOC2/GDPR/HIPAA audit trail evidence | Full audit export for compliance review |
| [`saas_ops_demo.py`](saas_ops_demo.py) | AI support agent handling customer tickets | Tiered access: view=auto, refund=approve, delete=block |
| [`terminal_demo.py`](terminal_demo.py) | Colorized terminal demo for GIF recording | Terminal-friendly visual flow |

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
python examples/salesforce_demo.py

# httpx example
pip install 'agent-aegis[httpx]'
python examples/httpx_demo.py

# Browser example (requires Playwright)
pip install 'agent-aegis[playwright]'
playwright install chromium
python examples/browser_demo.py
```

## Expected Output

Running `quickstart.py`:

```
============================================================
  EXECUTION PLAN
============================================================
  5 actions | 2 auto-approved, 2 need approval, 1 blocked
  ...

============================================================
  RESULTS
============================================================
  navigate  → SUCCESS (auto-approved, low risk)
  read      → SUCCESS (auto-approved, low risk)
  write     → SUCCESS (approved, medium risk)
  bulk_update → SUCCESS (approved, high risk)
  delete    → BLOCKED (critical risk, policy blocks this)

============================================================
  AUDIT LOG
============================================================
  navigate | risk=LOW      | decision=auto     | result=SUCCESS
  read     | risk=LOW      | decision=auto     | result=SUCCESS
  write    | risk=MEDIUM   | decision=approve  | result=SUCCESS
  ...
```
