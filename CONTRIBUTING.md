# Contributing to Aegis

## Getting started

```bash
git clone https://github.com/Acacian/aegis.git
cd aegis
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"  # installs as agent-aegis, import as aegis
pytest
```

## Development workflow

1. Fork the repo and create a feature branch from `main`
2. Write code with type hints and docstrings
3. Add tests for new functionality
4. Ensure all checks pass:
   ```bash
   ruff check src/ tests/
   ruff format src/ tests/
   pytest
   ```
5. Open a PR against `main`

## Code style

- Python 3.11+
- Formatted and linted with [Ruff](https://docs.astral.sh/ruff/)
- Type hints on all public APIs
- Docstrings on all public classes and methods

## What to contribute

- Bug fixes
- New adapters (API executors, browser-use, etc.)
- Policy engine features (conditions, templates, inheritance)
- Approval handlers (Slack, web UI, etc.)
- Documentation improvements

## What NOT to contribute (yet)

- Dashboard/frontend (planned for later)
- MCP integration (planned for later)
- Breaking changes to the core API without an issue discussion first

## Tests

All PRs must include tests. Run the full suite:

```bash
pytest -v
```

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add Slack approval handler
fix: policy wildcard matching edge case
docs: update adapter documentation
test: add coverage for audit log filtering
```
