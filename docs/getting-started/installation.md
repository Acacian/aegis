# Installation

## Requirements

- Python 3.11 or newer

## Basic Install

```bash
pip install agent-aegis
```

This installs the core runtime with YAML policy engine, CLI approval gate, and SQLite audit logger.

## With Integrations

Install only the integrations you need:

```bash
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
pytest
```

## Playwright Setup

If using the Playwright adapter, install browsers after pip install:

```bash
playwright install chromium
```
