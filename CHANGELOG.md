# Changelog

## 0.1.0 (Unreleased)

### Added
- Policy engine with YAML-based rules (glob matching, risk levels, approval requirements)
- `PlaywrightExecutor` adapter (navigate, click, fill, read, screenshot)
- CLI approval gate (interactive y/n)
- SQLite audit logger
- `Runtime` orchestrator: plan -> approve -> execute -> verify -> audit
- CLI commands: `aegis validate`, `aegis audit`
- Example policy and Salesforce demo script
