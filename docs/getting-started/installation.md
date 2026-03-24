# Installation

## Requirements

- Python 3.11 or newer

## Basic Install

```bash
pip install agent-aegis
```

This installs the core library including auto-instrumentation, runtime guardrails, YAML policy engine, CLI approval gate, and SQLite audit logger. Auto-instrumentation (`aegis.auto_instrument()`) works out of the box for any installed framework -- no extra dependencies needed.

## With Integrations

For adapter-based integrations (beyond auto-instrumentation), install the extras you need:

```bash
pip install 'agent-aegis[httpx]'           # REST API adapter
pip install 'agent-aegis[playwright]'      # Browser automation
pip install 'agent-aegis[langchain]'       # LangChain tools
pip install 'agent-aegis[crewai]'          # CrewAI tools
pip install 'agent-aegis[openai-agents]'   # OpenAI Agents SDK
pip install 'agent-aegis[all]'             # All integrations
```

## For Development

```bash
git clone https://github.com/Acacian/aegis.git
cd aegis
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
make test
```

Or use the Makefile for common tasks:

```bash
make help        # Show all available commands
make lint        # Run ruff linter
make typecheck   # Run mypy type checking
make coverage    # Run tests with coverage report
```

### GitHub Codespaces

Click the badge on the README or go to **Code → Codespaces → New codespace** for a pre-configured dev environment with Python 3.12 and all dependencies.

### Gitpod

Open the repo in Gitpod for a cloud-based workspace:

```
https://gitpod.io/#https://github.com/Acacian/aegis
```

## Playwright Setup

If using the Playwright adapter, install browsers after pip install:

```bash
playwright install chromium
```
