# Changelog

## 0.1.4 (2026-03-22)

### Added
- **Multi-agent governance foundations** (backward-compatible):
  - `agent_id` field on `Action` for agent identity tracking
  - `PolicyHierarchy` class for org → team → agent policy layering
  - `match_agent` support in policy rules
  - Agent context in audit trail entries
  - `PolicyConflict` detection across policy layers
- **Performance optimizations**:
  - Compiled glob patterns for faster policy matching
  - `BatchAuditLogger` for high-throughput audit writing
  - `Policy.with_cache()` for evaluation result caching
- **MCP governance guide** — governing MCP tool calls with per-server policies
- **LangChain cookbook** — 5-minute governance setup for LangChain agents
- **CrewAI cookbook** — 5-minute governance setup for CrewAI crews
- **OpenAI Agents cookbook** — 5-minute governance setup with `@governed_tool`
- **Aegis vs Alternatives** comparison guide
- **MCP example** (`examples/mcp_demo.py`)
- **Security Model guide** — defense in depth with Docker container isolation

### Improved
- **485 tests**, 92% code coverage
- Repositioned messaging: "The simplest way to govern AI agent actions"
- "Why Aegis?" section: vs DIY, vs platform-native, vs enterprise platforms
- Updated PyPI description and GitHub topics (20 topics)
- All GitHub Actions pinned to SHA hashes for supply chain security
- Path traversal protection in Playwright screenshot action

### Fixed
- Security hardening across multiple adapters
- Lint issues from multi-agent commit

## 0.1.3 (2026-03-21)

### Added
- **REST API server**: `aegis serve policy.yaml` — evaluate, execute, audit, policy endpoints (Starlette ASGI)
- **Retry & rollback**: exponential backoff, error filters, automatic rollback on failure
- **Dry-run mode**: `runtime.execute(plan, dry_run=True)` evaluates policy without executing actions
- **Policy hot-reload**: `runtime.update_policy(new_policy)` replaces policy without restarting
- **Plan filtering**: `plan.filter(allowed_only=True, approval=..., risk_level=...)` for selective execution
- **Plan inspection**: `plan.to_dict()` structured output, `plan.auto_only` property, iteration/indexing
- **Runtime hooks**: `RuntimeHooks(on_decision=..., on_approval=..., on_execute=...)` for observability
- **`aegis simulate`** CLI command — test actions against policies without executing
- **Policy merge**: `policy.merge(other)` and `Policy.from_yaml_files()` for multi-file policies
- **Approval handlers**: Slack (Block Kit), Discord (rich embed), Telegram (inline keyboard), email (SMTP), webhook
- **Audit query filters**: filter by `action_type`, `risk_level`, `result_status`, date range; `audit.count()`
- **Audit CLI**: `aegis audit --tail` (live monitoring), `aegis stats` (rule statistics), color-coded output

### Improved
- 420 tests, 92% coverage
- Korean README at full parity with English
- `__all__` exports in all submodule `__init__.py` files
- `make check` target runs lint + typecheck + test in one command

## 0.1.2 (2026-03-21)

### Improved
- **205 tests**, 98% code coverage (up from 92 tests / 74%)
- All `mypy --strict` type errors resolved (17 fixes)
- Comprehensive test suite for all 6 adapters, CLI, runtime, approval, audit

### Added
- README redesign: centered layout, full badge wall, collapsible integrations
- Korean README translation (`README.ko.md`)
- Cheatsheet docs page, Mermaid architecture diagrams
- GOVERNANCE.md, CITATION.cff
- GitHub Discussions, 8 good-first-issues, OpenSSF Scorecard workflow
- Examples index (`examples/README.md`)

## 0.1.1 (2026-03-21)

### Added
- **Policy conditions** — time-based (`time_after`, `time_before`), weekday, and param-based rule conditions
- **httpx/REST adapter** (`HttpxExecutor`) — HTTP methods mapped to action types
- **Python logging audit backend** (`LoggingAuditLogger`)
- **JSONL audit export** — `aegis audit --format jsonl`
- **Policy JSON Schema** — `aegis schema` CLI command
- **Runtime context manager** — `async with Runtime(...) as rt:`
- **`run_one()` convenience** — single-action governance shortcut
- **`aegis init`** — CLI command to generate starter policy
- 9 example scripts, 187 tests, 98% code coverage

### Infrastructure
- Full `mypy --strict` compliance
- Dependabot, Release Drafter, stale bot, CODEOWNERS
- DevContainer, Gitpod, pre-commit hooks
- ARCHITECTURE.md, SECURITY.md

## 0.1.0 (2026-03-21)

### Added
- **Policy engine** with YAML-based rules (glob matching, 4 risk levels, 3 approval modes)
- **Adapters**: Playwright, LangChain, CrewAI, OpenAI Agents SDK, Anthropic Claude
- **Approval handlers**: CLI interactive, auto-approve, callback-based
- **Audit logger**: SQLite-backed with session tracking
- **Runtime**: plan → approve → execute → verify → audit pipeline
- **CLI**: `aegis validate`, `aegis audit`
- **Documentation**: mkdocs-material site
- **CI/CD**: GitHub Actions, PyPI publish, docs deploy
