# Contributing to Aegis

Thank you for considering contributing to Aegis! This document explains how to get started.

## Quick Setup

```bash
git clone https://github.com/Acacian/aegis.git
cd aegis
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"   # installs as agent-aegis, import as aegis
pre-commit install         # optional: auto-lint on commit
```

Or use the **Makefile**:

```bash
make dev    # Install with dev deps + pre-commit
make test   # Run tests
make lint   # Run linter
```

### GitHub Codespaces / Gitpod

Click "Open in Codespaces" on the repo or use Gitpod — both are pre-configured.

## Development Workflow

1. **Fork** the repo and create a feature branch from `main`
2. **Write code** with type hints and docstrings
3. **Add tests** for new functionality
4. **Check everything passes:**
   ```bash
   make lint       # or: ruff check src/ tests/
   make test       # or: pytest -v
   make typecheck  # or: mypy src/aegis/
   make coverage   # Check coverage report
   ```
5. **Open a PR** against `main`

## Code Style

- **Python 3.11+** — use modern syntax (StrEnum, `X | Y` unions, etc.)
- **Ruff** — linting and formatting (config in `pyproject.toml`)
- **Type hints** on all public APIs
- **Docstrings** on all public classes and methods
- **Async-first** — all executor methods are async

## Project Structure

```
src/aegis/
├── core/        # Pure data models + policy engine (no I/O)
├── adapters/    # Pluggable executors (each with optional deps)
├── runtime/     # Orchestration, approval, audit
└── cli/         # CLI entry point
tests/           # pytest test suite
examples/        # Runnable demo scripts
docs/            # mkdocs-material documentation
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for design details.

## Your First PR (5-Minute Guide)

Not sure where to start? Here's a step-by-step path to your first contribution:

1. **Pick an issue** tagged [`good first issue`](https://github.com/Acacian/aegis/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
2. **Fork and clone:**
   ```bash
   gh repo fork Acacian/aegis --clone
   cd aegis && make dev
   ```
3. **Create a branch:** `git checkout -b fix/my-improvement`
4. **Make your change** — code, tests, or docs
5. **Verify:** `make lint && make test`
6. **Push and PR:** `git push -u origin fix/my-improvement && gh pr create`

**Easy first contributions** (no deep knowledge needed):
- Add a new example script in `examples/` for a use case you care about
- Add a test case for an edge case you found
- Fix a typo in docs
- Add a new policy template in `policies/`
- Improve error messages

## What to Contribute

### Non-code contributions
- Report bugs and suggest features via [Issues](https://github.com/Acacian/aegis/issues)
- Ask and answer questions in [Discussions](https://github.com/Acacian/aegis/discussions)
- Share your Aegis integration in [Show & Tell](https://github.com/Acacian/aegis/discussions/categories/show-and-tell)
- Translate documentation (see README.ko.md as an example)
- Write blog posts or tutorials about Aegis
- Star the repo to help others find it

### Good first contributions
- Bug fixes
- Documentation improvements
- New examples
- Test coverage improvements

### Feature contributions
- New adapters (API executors, browser-use, etc.)
- Policy engine features (conditions, templates, inheritance)
- Approval handlers (Slack, Discord, web UI)
- Audit backends (Elasticsearch, CloudWatch, etc.)
- CLI improvements

### What needs discussion first
- Breaking changes to the core API
- New core dependencies
- Architectural changes

Open an [issue](https://github.com/Acacian/aegis/issues) to discuss before starting large features.

## Writing Tests

All PRs must include tests. We use pytest with async support:

```python
import pytest
from aegis import Action, Policy
from aegis.core.policy import Approval

def test_my_feature():
    policy = Policy.from_dict({...})
    decision = policy.evaluate(Action("read", "test"))
    assert decision.approval == Approval.AUTO

@pytest.mark.asyncio
async def test_async_feature():
    result = await runtime.run_one(Action("read", "test"))
    assert result.ok
```

Run with coverage:

```bash
make coverage
# or: pytest --cov=aegis --cov-report=term-missing
```

## Writing Adapters

New adapters should:

1. Subclass `BaseExecutor` from `aegis.adapters.base`
2. Use lazy imports for optional dependencies
3. Include an import guard function (see existing adapters)
4. Have tests that work without the optional dependency installed
5. Be added to `pyproject.toml` optional dependencies

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add Slack approval handler
fix: policy wildcard matching edge case
docs: update adapter documentation
test: add coverage for audit log filtering
chore: update dependencies
```

## Pull Request Checklist

- [ ] Tests added/updated
- [ ] Linting passes (`make lint`)
- [ ] Type checking passes (`make typecheck`)
- [ ] Documentation updated (if applicable)
- [ ] Changelog entry added (if user-facing)
- [ ] Commit messages follow conventional commits

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
