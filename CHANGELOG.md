# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.5] - 2026-04-27

### Added

- **Governance Framework Server** — `aegis-server` CLI launches a centralized governance server with 37 REST endpoints (13 core + 24 extended). Supports config-driven setup via `aegis-server.yaml`.
- **Extended API endpoints** — policy versioning (commit/diff/rollback/tag), crypto audit verification, behavioral drift detection (5-axis), trust scoring (5-level per-agent), cost governance (budget tracking), session replay (forensic rescan), compliance reports (SOC2/GDPR/governance), and regulatory gap analysis (EU AI Act/NIST).
- **AsyncAegisClient** — async client SDK using `httpx.AsyncClient` with `async with` context manager, background heartbeat, and full API parity with the sync `AegisClient`.
- **Webhooks** — config-driven fire-and-forget notifications (Slack, PagerDuty) on block/rate-limit events.
- **Rate limiting** — sliding-window per-agent/global rate limits with glob-based rule matching, configurable via `aegis-server.yaml`.
- **Policy hot-reload** — `PolicyWatcher` monitors policy file changes and applies updates with zero downtime.
- **MCP STDIO Injection Guard** — 3-layer defense against the [OX Security MCP STDIO vulnerability](https://www.oxsecurity.io/blog/mcp-security-research) (2026-04-15). Detects JSON-RPC injection in tool responses, frame concatenation attacks, unicode escape bypass, double-encoded payloads, and Content-Length smuggling. Enabled by default in `aegis-mcp-proxy`.
- **Dashless SSN/RRN detection** — PII guardrail now catches Social Security Numbers and 주민등록번호 without dashes (keyword context required to prevent false positives)
- **NFKC normalization in PII detection** — catches fullwidth digit evasion (e.g., `４１１１` matching credit card patterns)

### Security

- **CRITICAL: Server API auth hardening** — `server/app.py` now requires `AEGIS_API_KEY` for all endpoints and `AEGIS_ADMIN_KEY` for policy updates, with `hmac.compare_digest` for timing-safe comparison
- **HIGH: ArgumentSanitizer unicode bypass** — NFKC normalization applied before pattern matching in `mcp_security.py`
- **HIGH: MCP proxy input size limit** — tool arguments exceeding 1MB are rejected (DoS prevention)
- **HIGH: OpenAI stream=True warning** — `patch_openai` now logs a warning when streaming is enabled (output guardrails are ineffective on streamed responses)
- **HIGH: AuditLogger thread safety** — added `threading.Lock` around all SQLite operations
- **HIGH: CryptoAuditChain timing attack** — hash comparisons now use `hmac.compare_digest`
- **MEDIUM: LRU cache memory exhaustion** — injection and PII guardrails skip caching for content >50KB
- **MEDIUM: Credit card log exposure** — `PIIMatch.matched_text` no longer stores full card numbers
- **MEDIUM: Pin store TOCTOU** — `RugPullDetector` uses atomic write (tempfile + rename)

### Changed

- Version bump: 0.9.4 → 0.9.5

## [Unreleased]

### Added

- **On-site SEO infrastructure** — `overrides/main.html` injects Open Graph + Twitter Card + JSON-LD (`SoftwareApplication`, `WebSite`, `BreadcrumbList`) on every docs page; per-page-type schemas (`TechArticle` for solutions/cookbook, `Article` for comparisons, `FAQPage` for FAQ); custom `overrides/sitemap.xml` with tier-based priority (home 1.0 / solutions+comparisons 0.9 / cookbook 0.8 / guides+api 0.7) and changefreq signals across all 69 URLs
- **5 SEO solution pages** — `crewai-security`, `openai-agents-security`, `litellm-security`, `llm-guardrails-python`, `ai-agent-vulnerability-scanner` targeting high-intent search queries
- **Demo assets** — animated asciinema SVG (47KB, 65-row, vector-sharp) for docs and dracula-themed GIF (222KB) for README, with typing-animation → instant-results choreography
- **Docs landing page redesign** — `docs/index.md` rewritten as a landing page with stat grid, 3-step flow, hub linking to all 14 solutions / 5 comparisons / 14 cookbook pages
- **Attack simulation in `aegis scan`** — output now shows concrete attack scenarios (prompt injection, PII leak, code exec) and the defenses `auto_instrument()` would apply
- **`aegis scan --fix`** — auto-inserts `import aegis; aegis.auto_instrument()` into affected files
- **`aegis scan` single-file support** — `aegis scan myfile.py` works directly (previously directory-only)
- **`aegis scan` actionable next steps** — 3-step guide (generate policy → instrument → set CI threshold) replaces generic footer
- **Colored CLI output** — `aegis scan` emits ANSI colors with auto-detection (`NO_COLOR` / `FORCE_COLOR` / TTY check); pipes and CI get plain text automatically
- **Unified guardrail result API** — `passed` and `guardrail_name` fields added to `PIIResult`, `ToxicityResult`, `HallucinationResult`, `PromptLeakResult`, `COTResult`, `OutputSchemaResult`
- **`auto_instrument()` runtime feedback** — prints instrumented framework list to stdout; warns to stderr when no frameworks detected
- **Search-oriented PyPI keywords** — added `llm-guardrails`, `llm-security`, `toxicity-detection`, `pii-masking`, `injection-detection`, `litellm`, `pydantic-ai`, `llamaindex`, `instructor`, `dspy`, `google-adk`, `gemini`, `selection-governance`, `policy-ci-cd`, `ai-safety`, `agent-security`, `tool-call-policy` for discoverability

### Changed

- **README scan output** — updated to show attack simulation, `--fix`, single-file usage, and the new 3-step next-steps block
- **Korean README** language switcher restored after broken Hangul characters

### Fixed

- **7.8x faster guardrails on long text** — `ToxicityGuardrail` and `PromptLeakGuardrail` now run cheap substring keyword pre-filter before expensive regex, short-circuiting clean text. Benchmarks on 6.5K chars: Toxicity 9.6ms → 1.5ms (6.4x), PromptLeak 3.3ms → 0.14ms (23x), full engine 14ms → 1.8ms (7.8x)
- **FAQPage schema text-mismatch** — hardcoded FAQ schema used "Agent-Aegis" while visible H3s used "Aegis"; rewrote schema to byte-match visible text so Google rich-result eligibility is preserved (8/8 Q&A now match)
- **Stale `docs/faq.md` capability counts** — corrected "7 adapters / 10 categories / 85+ patterns" to "12 frameworks / 13 categories / 107 patterns" in line with `llms.txt`
- **`site_description` truncation** — shortened from 297 chars to 153 chars to fit Google's ~155 char SERP limit
- **30 pages missing frontmatter description** — added per-page descriptions (139–154 chars) across `api/`, `cookbook/`, `guides/`, `security/`, `playground/`, troubleshooting, cheatsheet, index
- **Title length and collision issues** — duplicate `MCP Governance` titles disambiguated; long titles (`owasp-agentic-mapping` 76→31 chars) and short titles (`faq`, `api/audit`, home page) corrected for SERP CTR
- **`aegis validate` / `init` / `scan` error messages** — now suggest the next command to run (`aegis init`, `aegis schema`) instead of generic failures
- **`aegis init`** — prints next-step commands after generating starter policy
- **Instrument module docstring** — corrected framework count `9 → 10`
- **Demo GIF frame ordering** — reordered so first frame shows scan results (not blank screen) and trimmed initial blank
- **Camo cache busting** — appended `?v=2` query to demo GIF URL so GitHub re-fetches the updated frame order
- **Misplaced root directories removed** — `agents/`, `hooks/`, `loop/`, `skills/` deleted from repo root (correct location is `.claude/`); redundant `.gitignore` entries removed
- **Self-scan A grade** — added `# aegis: ignore` pragmas to false-positive internal calls so the project's own `aegis scan` produces an A

### Docs

- **`docs/api/index.md`** — new index page linking all API reference pages

## [0.9.3] — 2026-04-06

### Added

- **`aegis proxy` CLI** — external governance gateway as ASGI app. New subcommand starts the AegisProxy with configured policy, forwards governed requests downstream, and emits structured audit events
- **`Runtime.execute_claim()`** — public runtime API to execute a fully-formed `ActionClaim` through the policy + guardrail pipeline (used by proxy forwarders)
- **ClaimPolicy + proxy forwarders** — `aegis.runtime.proxy_forwarder` exposes async forwarder helpers; `ClaimPolicy` evaluates declared/assessed/chain fields with explicit deny precedence
- **ASGI proxy app** — drop-in middleware/standalone app for upstream services that want pre-LLM-call governance without integrating the library directly
- **Differentiation documentation** — comparison pages for vs MS AGT, vs NeMo Guardrails, vs Guardrails AI, vs mcp-scan, vs DIY published in `docs/comparisons/`
- **Pre-commit hook + pytest plugin** — `aegis-precommit` and pytest11 entry point so installs automatically appear in `pre-commit-config.yaml` and pytest framework discovery
- **15-framework scan detection** — `aegis scan` now classifies findings across 15 categories: OpenAI, Anthropic, LangChain, MCP, subprocess, HTTP, CrewAI, LlamaIndex, LiteLLM, PydanticAI, OpenAI Agents, Instructor, Google GenAI, DSPy, Google ADK
- **Scan DX features** — `--format json|sarif|suggest`, `--threshold A-F`, `--fix`, `.aegisscanignore`, `# aegis: ignore` inline pragmas, attack-simulation output
- **End-to-end v0.9 integration tests** — proxy forwarder, ClaimPolicy, ActionClaim execution paths covered

### Fixed

- **action.yml Marketplace compatibility** — description shortened to <125 chars for GitHub Marketplace publication
- **mypy strictness** — `StashKey[dict]` now carries explicit type args; scan.py dict annotations corrected (0 mypy errors on 181 files)

### Changed

- **GitHub Action ref bumped to v0.9.3** — `Acacian/aegis@v0.9.3` in README/CI examples

## [0.9.2] — 2026-04-05

### Added

- **Sub-package publish workflow** — separate publish pipeline for `langchain-aegis` and other sub-packages, dependency synced to 0.9.2 to avoid version drift
- **PR comment from GitHub Action** — Aegis Action posts scan results as a PR comment (governance score + ungoverned counts) for visible CI feedback
- **Policy CI/CD playground tab** — interactive `aegis plan` / `aegis test` demo in the browser playground
- **glama.json** — MCP directory ownership verification metadata for Glama.ai listing

### Fixed

- **Stale versions across repo** — removed dead `MANIFEST.in`, fixed stale version pins, exported 5 missing modules from public surface
- **Windows compatibility** — UTF-8 encoding enforcement, `pathlib` path handling, high-resolution timer fallback for Windows runners
- **Honest dependency claim** — README "zero deps" corrected to "1 dep (PyYAML)"; "20+" papers corrected to "24 papers"
- **Selection-by-negation positioning** — qualified from "first runtime" to "first OSS library" for accuracy

### Changed

- **README + playground restructured around `aegis scan`** — landing flow now leads with the scanner finding pain → auto_instrument fixing it → policy CI/CD locking it
- **Brand consolidated to Agent-Aegis** — playground files, benchmark report, and badges updated; benchmark rewritten as honest comparison

## [0.9.1] — 2026-04-05

### Fixed

- **Token-boundary keyword matching** — ImpactScorer no longer triggers on substrings (e.g. "undelete" no longer matches "delete"). Uses `_`-delimited token matching for single keywords and substring matching for compound keywords only
- **CongruenceChecker priority** — explicit DELETE > WRITE > READ priority replaces non-deterministic frozenset iteration order
- **Privilege escalation gaming** — scoring uses action_type, target, and param keys only; no longer blindly concatenates arbitrary param values
- **Resource consumption gaming** — `max(count, limit, batch_size)` prevents gaming with low count + high batch_size
- **PII keyword list** — synced with design doc: added `email` and `name` to PII indicators

### Added

- **SelectionAuditor thread safety** — `threading.Lock` protects `_history` for concurrent access
- **CommitRevealSelection TTL + capacity** — `max_pending` limit and `ttl_seconds` with automatic pruning of expired entries (prevents memory leak)
- **`@audit_selection` sync support** — decorator now works with both sync and async functions via `inspect.iscoroutinefunction`
- **33 new tests** — false positive scenarios, gaming resistance, NaN/inf rejection, thread safety, TTL expiry, sync decorator, PII keyword coverage

## [0.9.0] — 2026-04-05

### Added

- **Selection Governance** — detects what agents EXCLUDE, not just what they do. Based on Santander "Selection as Power" (arXiv:2602.14606) and COA-MAS (Carvalho) frameworks
- **ActionClaim tripartite structure** — separates DeclaredFields (agent-authored, untrusted), AssessedFields (Aegis-computed, independent), and ChainFields (delegation infrastructure) for independent verification of agent intent
- **ImpactVector** — frozen 6-dimensional impact assessment (destructivity, data_exposure, resource_consumption, privilege_escalation, reversibility, autonomy_depth) with L2 norm, Euclidean distance, and asymmetric gap computation
- **Justification Gap** — asymmetric distance between declared and assessed impact; thresholds: ≤0.15 APPROVE, 0.15–0.40 ESCALATE, >0.40 BLOCK
- **RuleBasedImpactScorer** — Tier 1 keyword-based impact scorer with CongruenceChecker for declared-action consistency validation
- **SelectionAuditor** — 4 detection types: high_elimination, better_option_eliminated, unjustified_elimination, systematic_exclusion
- **CommitRevealSelection** — commit-reveal protocol: agent commits full option set hash before governance reveals which option is selected, preventing post-hoc rationalization
- **CircuitBreaker** — fail-loud with QDV (Quality-Diversity-Volume) metric, CLOSED→OPEN→HALF_OPEN→CLOSED state machine, thread-safe with configurable thresholds
- **AegisProxy** — external governance gateway with authentication, claims assessment, circuit breaker, and policy evaluation pipeline
- **Monotone constraint validation** — ensures trust levels are non-increasing along delegation chains
- **Selection Governance playground demo** — interactive Selection Audit and Justification Gap demos with Korean/English i18n

## [0.7.0] — 2026-04-02

### Added

- **Streaming-aware guardrail engine** — `StreamingGuardrailEngine` scans streaming LLM responses with automatic strategy selection: windowed scan (configurable `window_size`) for incremental guardrails, full-buffer mode for guardrails where partial exposure is a violation (e.g. PII)
- **`requires_full_buffer` flag** on `Guardrail` base class — guardrails declare whether they need complete content before scanning; the streaming engine auto-selects the safest strategy based on active guardrails
- **Streaming Guard playground demo** — split-screen live comparison (unguarded vs Aegis-guarded streaming), 5 scenarios including AI-powered semantic PII detection via Gemini Flash

## [0.6.1] — 2026-03-30

### Changed

- **Guardrail performance optimization** — combined regex per category replaces individual pattern iteration; LRU cache on injection + PII detection functions
- **Realistic benchmark suite** — `benchmarks/bench_guardrails.py` via pytest-benchmark; per-call overhead 2.65ms (0.53% of LLM latency) for full 4-scan stack (injection + PII on input and output)

## [0.6.0] — 2026-03-28

### Fixed

- **18 security vulnerabilities** — fail-closed defaults, API auth middleware, audit data sanitization, SSRF protection, ReDoS protection, TOCTOU fixes

### Added

- **IBAN PII detection** — 13th PII category with mod-97 (ISO 7064) checksum validation, 5+ country formats
- **Policy CI/CD enhancements** — `PolicyImpactAnalyzer` (replay audit data against old/new policies), `PolicyTestRunner` (YAML test suites, JUnit XML, coverage reports, `--fail-under`)
- **Cost governance** — `CostPolicyEnforcer` with 5-dimension enforcement, model pricing tables
- **Compliance evidence** — `ComplianceReportGenerator` for EU AI Act, SOC2, NIST, ISO 42001
- **Behavioral drift detection** — `DriftDetector` + `DriftPolicyEvaluator`

## [0.5.0] — 2026-03-27

### Added

- **Auto-instrumentation for 6 additional frameworks** — LiteLLM, Google GenAI, Pydantic AI, LlamaIndex, Instructor, DSPy (total: 11 frameworks)
- **MCP Proxy Server** (`aegis-mcp-proxy`) — transparent governance proxy wrapping any MCP server with security checks, policy evaluation, guardrails, and audit logging
- **`aegis plan` CLI** — "terraform plan" for AI agent policies (diff + replay + CI exit codes)
- **`aegis test` CLI** — policy regression testing for CI/CD (generate, regression)

## [0.4.2] — 2026-03-25

### Added

- **Auto-Instrumentation** (`aegis.auto_instrument()`) — zero-code monkey-patching that adds governance to any installed AI framework at runtime
  - **LangChain** — patches `BaseChatModel.invoke/ainvoke`, `BaseTool.invoke/ainvoke`
  - **CrewAI** — patches `Crew.kickoff/kickoff_async`, registers global `BeforeToolCallHook`
  - **OpenAI Agents SDK** — patches `Runner.run`, `Runner.run_sync`
  - **OpenAI API** — patches `Completions.create` via existing `patch_openai`
  - **Anthropic API** — patches `Messages.create` via existing `patch_anthropic`
- **`AEGIS_INSTRUMENT=1` environment variable** — activate auto-instrumentation with zero code changes
- **Default guardrail engine** — built-in guardrails (injection block, toxicity block, PII warn, prompt leak warn) that require no configuration
- **Per-framework patching** — `patch_langchain()`, `patch_crewai()`, `patch_openai_agents()` for selective instrumentation
- **Instrumentation status API** — `status()` returns current patch state, `reset()` cleanly unpatches everything
- **`InstrumentationReport`** — structured summary of what was patched, skipped, or errored

## [0.4.1] — 2026-03-24

### Changed

- **Policy cache: FIFO → LRU** — `OrderedDict` with `move_to_end()` for O(1) LRU eviction, improving cache hit rates for frequently-evaluated actions
- **Policy cache correctness** — `_is_cacheable()` now checks all conditional rules' patterns against the action, preventing unconditional cache entries from shadowing conditional rules with different params
- **Rate limiter: pre-compiled glob patterns** — module-level `_glob_to_re()` cache eliminates redundant `fnmatch` compilation on every `matches()` call
- **O(n) → O(log n) timestamp pruning** — `bisect.bisect_left/right` replaces list comprehension in rate limiter and anomaly detector hot paths
- **SQLite WAL mode** — `PRAGMA journal_mode=WAL` for concurrent read/write performance
- **SQLite indexes** — 4 indexes on `session_id`, `timestamp`, `agent_id`, `action_type` for query performance
- **Lock memory leak fix** — `reset(agent_id)` now cleans up stale `_locks` entries in rate limiter and anomaly detector
- **Batch audit flush race fix** — buffer swap moved inside lock to prevent double-flush when concurrent threads both see `should_flush=True`
- **Anomaly detection: time-bounded rate calculation** — `_compute_rate_per_minute(window=60.0)` uses fixed window instead of last-N-events span for statistically accurate rate spike detection

### Added

- **`AnomalyDetector.check_all()`** — returns all detected anomalies at once (rate spike + high block rate simultaneously); `check()` now returns the most severe
- **`GuardrailEngine.acheck()` / `acheck_and_transform()`** — async wrappers via `run_in_executor` so guardrails don't block the event loop
- **`Runtime.execute(parallel=True)`** — concurrent action execution via `asyncio.gather()` for independent actions

## [0.4.0] — 2026-03-24

### Added

- **`aegis.init()` unified entry point** — single function call activates all governance (guardrails, policy, audit, cost tracking, auto-patching)
- **Runtime Guardrails Engine** — pluggable guardrail pipeline with block/mask/warn/log actions
- **PII Detection & Masking** — 12 categories (email, credit card, SSN, Korean RRN, phone numbers, API keys, IP addresses, passport, URL credentials)
- **Prompt Injection Detection** — 10 attack categories, 85+ compiled patterns, multi-language support (Korean, Chinese, Japanese)
- **Rule Pack Ecosystem** — YAML-based community-extensible rule packs with built-in @aegis/pii-detection and @aegis/prompt-injection
- **Zero-Code Integration** — `aegis.patch_openai()`, `aegis.patch_anthropic()` monkey-patching and `@guard` decorator
- **AGEF v1** (Agent Governance Event Format) — JSON Schema standard for AI governance events
- **AGP v1** (Agent Governance Protocol) — protocol specification complementing MCP for AI governance
- **Unified YAML configuration** — `aegis.yaml` single config file for all features
- **Redis audit backend** — production audit logging via Redis
- **PostgreSQL audit backend** — production audit logging via asyncpg
- **Redis rate limiter** — distributed rate limiting via Redis

## [0.3.0] - 2026-03-24

### Added

- **MCP supply chain security**: Tool poisoning detection (10 patterns), rug-pull detection (SHA-256 manifest pinning), argument sanitization, trust scoring (L0-L4)
- **MCP SBOM generation**: Software Bill of Materials for MCP tool inventories
- **MCP vulnerability database**: Known-vulnerability lookup for MCP tools
- **Cost circuit breaker**: 17-model price table, loop detection, hierarchical budgets, thread-safe enforcement
- **Cross-framework cost tracking**: Unified CostTracker across LangChain, OpenAI, Anthropic, and Google
- **Multi-agent cost attribution**: Delegation tree tracking, subtree cost rollup, attribution reports
- **A2A communication governance**: Capability-based messaging, PII/credential auto-scrubbing, rate limiting, audit logging
- **Session replay & retroactive scan**: Replay historical sessions against new policies for what-if analysis
- **OpenTelemetry export**: Policy, cost, anomaly, and MCP events exported as OTel spans with in-memory fallback
- **Policy git integration**: Git-like versioning with commit, diff, rollback semantics

### Changed

- Development status upgraded from Alpha to Beta
- PyPI keywords expanded with MCP, cost-management, supply-chain-security, A2A, observability

### Stats

- 2,238+ tests passing
- 92% code coverage

## [0.2.0] - 2026-03-23

### Added

- **Web governance dashboard**: Real-time SPA dashboard with 7 pages (overview, audit, policy, anomalies, compliance, regulatory, system)
- **WebSocket real-time streaming**: `/ws/audit` endpoint streams audit entries live to connected dashboard clients
- **Interactive playground**: Browser-only policy playground at `/playground/` — no install, no backend, YAML + glob matching in JS
- **Policy editor**: In-dashboard YAML editor with validate and save/reload (hot-reload via PUT `/api/v1/policy`)
- **Shields.io badge endpoint**: `GET /api/v1/badge/score` returns governance score badge for README embedding
- **Policy YAML export**: `GET /api/v1/dashboard/policy/yaml` exports current policy as YAML
- **Audit JSON export**: Dashboard audit page has one-click JSON export with current filters
- **CLI `--seed-demo N`**: `aegis serve policy.yaml --seed-demo 200` populates demo audit data before starting
- **Auto-refresh dashboard**: Overview page auto-refreshes every 30s (toggleable)
- **AuditLogger pub/sub**: `subscribe()`/`unsubscribe()` callbacks for real-time entry notifications
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
- **Multi-tenant isolation**: TenantContext, TenantRegistry, quota enforcement via contextvars
- **RBAC**: 12 granular permissions, 5 hierarchical roles, thread-safe AccessController
- **Policy testing framework**: automated rule testing, regression detection, auto-generation
- **Policy versioning**: git-like commit, diff, rollback, tagging with JSON persistence
- **Natural language autopolicy**: `aegis autopolicy` generates YAML from natural language descriptions
- **Adversarial probe**: `aegis probe` tests policies for glob bypass, missing coverage, escalation paths

### Stats

- 1,776+ tests passing
- 27 core modules, 65 source files
- EU AI Act compliance: 10 requirements mapped
- NIST AI RMF: 8 requirements mapped
- SOC2: 6 requirements mapped

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

[Unreleased]: https://github.com/Acacian/aegis/compare/v0.6.1...HEAD
[0.6.1]: https://github.com/Acacian/aegis/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/Acacian/aegis/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/Acacian/aegis/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/Acacian/aegis/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/Acacian/aegis/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/Acacian/aegis/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Acacian/aegis/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Acacian/aegis/compare/v0.1.6...v0.2.0
[0.1.6]: https://github.com/Acacian/aegis/compare/v0.1.4...v0.1.6
[0.1.4]: https://github.com/Acacian/aegis/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/Acacian/aegis/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/Acacian/aegis/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Acacian/aegis/releases/tag/v0.1.1
