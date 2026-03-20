# Changelog

## 0.1.0 (Unreleased)

### Added
- Policy engine with YAML-based rules (glob matching, risk levels, approval requirements)
- `PlaywrightExecutor` adapter (navigate, click, fill, read, screenshot)
- `LangChainExecutor` adapter + `AegisTool` for LangChain integration
- `AegisCrewAITool` for CrewAI integration
- `@governed_tool` decorator for OpenAI Agents SDK integration
- CLI approval gate (interactive y/n) + `AutoApprovalHandler` for testing
- SQLite audit logger
- `Runtime` orchestrator: plan -> approve -> execute -> verify -> audit
- CLI commands: `aegis validate`, `aegis audit`
- Example policy, quickstart demo, Salesforce demo script
- GitHub Actions CI (Python 3.11/3.12/3.13) + PyPI publish workflow
