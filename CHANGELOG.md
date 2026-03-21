# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.4] - 2026-03-22

### Added

- Interactive playground with 14 presets for browser-based policy testing
- 10 industry-specific policy templates (healthcare, finance, legal, etc.)
- 7 framework integration cookbooks
- Docker deployment support
- GitHub Action for CI/CD policy enforcement
- 12+ example scripts covering common governance scenarios
- Production deployment guide
- Policy patterns guide
- Performance optimizations: compiled glob matching, batch audit writes, evaluation cache
- Security hardening: pinned all GitHub Actions to SHA hashes, security model guide

### Changed

- Expanded README with policy templates and compliance section

### Fixed

- Lint issues from multi-agent commit
- `mcp_demo` f-string formatting

## [0.1.3] - 2026-03-21

### Added

- MCP (Model Context Protocol) adapter
- Multi-agent orchestration foundations
- 486 tests with 92% code coverage

## [0.1.2] - 2026-03-20

### Added

- Core policy engine with YAML-based rule parsing
- Risk evaluation pipeline
- LangChain adapter
- CrewAI adapter
- OpenAI Agents adapter
- Audit logging system
- Approval handler framework

## [0.1.1] - 2026-03-19

### Added

- Initial public release on PyPI

[Unreleased]: https://github.com/Acacian/aegis/compare/v0.1.4...HEAD
[0.1.4]: https://github.com/Acacian/aegis/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/Acacian/aegis/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/Acacian/aegis/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Acacian/aegis/releases/tag/v0.1.1
