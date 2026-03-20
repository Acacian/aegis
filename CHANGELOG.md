# Changelog

## 0.1.1 (2026-03-21)

### Added
- **Policy conditions** — time-based (`time_after`, `time_before`), weekday, and param-based (`param_gt`, `param_eq`, `param_matches`, etc.) rule conditions
- **httpx/REST adapter** (`HttpxExecutor`) — map action types to HTTP methods with full request/response handling
- **Python logging audit backend** (`LoggingAuditLogger`) — structured JSON to Python logging, maps risk levels to log levels
- **JSONL audit export** — `aegis audit --format jsonl` and `AuditLogger.export_jsonl()` for log pipeline integration
- **Policy JSON Schema** — `aegis schema` CLI command; `policy.schema.json` ships with the repo for editor integration
- **Runtime context manager** — `async with Runtime(...) as rt:` for automatic setup/teardown
- **`run_one()` convenience** — single-action governance shortcut
- httpx demo example
- 45 new tests (90 total)

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
