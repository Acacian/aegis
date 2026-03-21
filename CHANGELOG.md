# Changelog

## 0.1.2 (2026-03-21)

### Improved
- **205 tests**, 98% code coverage (up from 92 tests / 74%)
- All `mypy --strict` type errors resolved (17 fixes)
- Comprehensive test suite for all 6 adapters, CLI, runtime, approval, audit
- Example smoke tests validate all 9 examples on every CI run

### Added
- README redesign: centered layout, full badge wall, collapsible integrations
- Korean README translation (`README.ko.md`)
- Cheatsheet docs page (one-page quick reference)
- Mermaid architecture diagrams (data flow, adapter tree, policy evaluation)
- GOVERNANCE.md, CITATION.cff for academic references
- GitHub Discussions enabled with 3 templates (Ideas, Q&A, Show & Tell)
- 8 good-first-issues for contributor onboarding
- OpenSSF Scorecard workflow
- Social media launch posts (`SOCIAL.md`)
- Examples index (`examples/README.md`)
- Shared test fixtures (`conftest.py`)

### Fixed
- Scorecard workflow no longer triggers on push (avoids false failures)
- CI: bumped all GitHub Actions to latest (checkout v6, setup-python v6, etc.)
- Removed redundant `--ignore-missing-imports` from mypy CI step
- Added `types-PyYAML` to dev dependencies

### Infrastructure
- 20 GitHub topics for discoverability
- Discussions URL added to PyPI project metadata
- `.mypy_cache/`, `.ruff_cache/` added to `.gitignore`

## 0.1.1 (2026-03-21)

### Added
- **Policy conditions** — time-based (`time_after`, `time_before`), weekday, and param-based (`param_gt`, `param_eq`, `param_matches`, etc.) rule conditions
- **httpx/REST adapter** (`HttpxExecutor`) — map action types to HTTP methods with full request/response handling
- **Python logging audit backend** (`LoggingAuditLogger`) — structured JSON to Python logging, maps risk levels to log levels
- **JSONL audit export** — `aegis audit --format jsonl` and `AuditLogger.export_jsonl()` for log pipeline integration
- **Policy JSON Schema** — `aegis schema` CLI command; `policy.schema.json` ships with the repo for editor integration
- **Runtime context manager** — `async with Runtime(...) as rt:` for automatic setup/teardown
- **`run_one()` convenience** — single-action governance shortcut
- **`aegis init`** — CLI command to generate starter policy
- Korean README translation (`README.ko.md`)
- 9 example scripts (httpx, conditions, CrewAI, OpenAI Agents, Anthropic, etc.)
- 187 tests, 98% code coverage
- Mermaid architecture diagrams

### Infrastructure
- Full `mypy --strict` compliance (0 errors)
- GitHub Actions bumped to latest (checkout v6, setup-python v6, etc.)
- Dependabot for pip + GitHub Actions
- Release Drafter, stale bot, CODEOWNERS, FUNDING.yml
- `.devcontainer` (Codespaces), `.gitpod.yml`, `.pre-commit-config.yaml`
- ARCHITECTURE.md, GOVERNANCE.md, CITATION.cff, SECURITY.md
- 8 good-first-issues for new contributors
- GitHub Discussions enabled
- 20 GitHub topics for discoverability

## 0.1.0 (2026-03-21)

### Added
- **Policy engine** with YAML-based rules (glob matching, 4 risk levels, 3 approval modes)
- **Adapters**: Playwright, LangChain, CrewAI, OpenAI Agents SDK, Anthropic Claude
- **Approval handlers**: CLI interactive, auto-approve, callback-based (sync/async)
- **Audit logger**: SQLite-backed with session tracking and full action lifecycle
- **Runtime**: plan -> approve -> execute -> verify -> audit pipeline
- **CLI**: `aegis validate` (policy checking), `aegis audit` (log viewer, table/JSON)
- **Documentation**: mkdocs-material site with guides and API reference
- **Examples**: quickstart, browser demo (httpbin), Anthropic E2E, LangChain E2E
- **CI/CD**: GitHub Actions (lint + test on 3.11/3.12/3.13), PyPI publish, docs deploy
