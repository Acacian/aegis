# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-03-23

### Added

- **Cryptographic audit chain**: SHA-256/SHA3-256 hash-linked, tamper-evident logging with `aegis audit --verify`, `--export-chain`, `--verify-chain`, and `--evidence` CLI commands
- **Regulatory compliance mapper**: EU AI Act (10 requirements), NIST AI RMF (8 requirements), SOC2 (6 requirements), and ISO 42001 mapping with automated gap analysis
- **Behavioral anomaly detection**: rate spike detection, burst analysis, new-action flagging, unusual target identification, and automatic policy generation from anomalies
- **Compliance report generator**: SOC2, GDPR, and governance reports generated directly from audit logs
- **Policy diff & impact analysis**: `aegis diff old.yaml new.yaml --replay actions.jsonl` for what-if comparison between policy versions
- **Fluent PolicyBuilder SDK**: programmatic policy definition with a chainable Python API
- **Rate limiter engine**: per-agent and global sliding-window rate limiting
- **Action replay & simulation engine**: replay historical actions against new policies for what-if analysis
- **Real-time agent monitoring dashboard**: `aegis monitor` CLI command for live operational visibility
- **Webhook notification system**: Slack, PagerDuty, and generic JSON webhook integrations for governance events
- **Enterprise tier system**: Community / Pro / Enterprise feature gating
- **GitHub Action for CI/CD governance gates**: enforce policies in pull request and deployment pipelines
- **Semantic conditions engine**: keyword matching and pluggable LLM evaluator for content-aware policy rules
- **Agent trust chain**: hierarchical identity model with delegation tokens and cascade revocation

### Stats

- 1,394 tests passing
- EU AI Act compliance: 10 requirements mapped (Articles 9, 13, 14, 15, 17, 26, 29, 52, 72, Annex IV)
- NIST AI RMF: 8 requirements mapped (Govern, Map, Measure, Manage functions)
- SOC2: 6 requirements mapped (CC6.1–CC6.6)

## [0.1.6] - 2026-03-23

### Added

- Standalone MCP server: `pip install 'agent-aegis[mcp]'` → `aegis-mcp-server`
- `langchain-aegis` 0.1.0: standalone PyPI package for LangChain governance integration
- MCP Registry publication (`io.github.Acacian/aegis`)
- Smithery.ai configuration (`smithery.yaml`)
- GEO (Generative Engine Optimization) for AI discoverability
- CI gate: service worker cache version bump check
- PyPI downloads badge in README

### Fixed

- MCP Registry name casing (`io.github.Acacian/aegis`)
- MCP server format and mypy strict compliance

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
- 518 tests with 92% code coverage

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

[Unreleased]: https://github.com/Acacian/aegis/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Acacian/aegis/compare/v0.1.6...v0.2.0
[0.1.6]: https://github.com/Acacian/aegis/compare/v0.1.4...v0.1.6
[0.1.4]: https://github.com/Acacian/aegis/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/Acacian/aegis/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/Acacian/aegis/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Acacian/aegis/releases/tag/v0.1.1
