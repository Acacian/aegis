# Security Audit Readiness

This document prepares Aegis for an independent security audit. It describes what an auditor needs, where to find it, and known areas of concern.

## Audit Scope (Recommended)

| Component | Priority | Lines of Code | Risk Level |
|-----------|----------|---------------|------------|
| Policy engine (`core/policy.py`) | Critical | ~400 | High — decision authority |
| Injection guardrail (`guardrails/injection.py`) | Critical | ~500 | High — security boundary |
| PII guardrail (`guardrails/pii.py`) | Critical | ~350 | High — data protection |
| Crypto audit chain (`core/crypto_audit.py`) | Critical | ~300 | High — tamper evidence |
| MCP supply chain (`mcp/`) | High | ~800 | High — tool trust |
| REST API server (`server/app.py`) | High | ~400 | Medium — network boundary |
| YAML config loader (`config.py`) | Medium | ~200 | Medium — input parsing |
| Audit backends (`runtime/audit*.py`) | Medium | ~600 | Medium — data integrity |
| RBAC (`core/rbac.py`) | Medium | ~300 | Medium — access control |
| CLI entry points (`cli/`) | Low | ~800 | Low — local execution |

**Total critical scope: ~1,550 lines.**

## Key Security Properties to Verify

### 1. Policy Engine Correctness
- First-match-wins semantics: verify no rule ordering bugs
- Glob pattern compilation: verify no ReDoS patterns
- Cache correctness: verify LRU cache doesn't return stale decisions
- Fail-closed: verify unmatched actions are not silently allowed

### 2. Injection Detection Soundness
- Pattern coverage: verify 85+ patterns match documented attacks
- Unicode handling: verify normalization prevents evasion
- Sensitivity levels: verify high catches more than medium catches more than low
- No false negatives on known attack corpus

### 3. PII Detection Accuracy
- Luhn validation for credit cards
- No catastrophic backtracking in regex patterns
- Masking completeness: verify no partial leaks in mask output

### 4. Cryptographic Chain Integrity
- SHA-256 computation matches specification
- Previous-hash linkage is continuous (no gaps)
- Verification detects single-bit changes
- Genesis block handling

### 5. MCP Trust Boundary
- Tool description scanner catches all 10 documented attack patterns
- Hash pinning detects any byte-level change
- Argument sanitization blocks path traversal and command injection

### 6. REST API Surface
- No unauthenticated write operations that could modify policy
- Input validation on all endpoints
- No SSRF via webhook configuration
- CORS configuration

## Test Suite

- **2,540+ tests** across all modules
- **92% code coverage**
- Run: `python -m pytest tests/ -x -v`
- Coverage: `python -m pytest --cov=src/aegis --cov-report=html tests/`

## Dependencies

Core (always installed):
- `pyyaml` — YAML parsing (well-audited, widely used)

Optional (user opt-in):
- `starlette`, `uvicorn` — REST API server
- `langchain-core` — LangChain adapter
- `anthropic`, `openai` — SDK patching
- `asyncpg`, `redis` — production audit backends

## Known Limitations (Honest Disclosure)

1. **Regex-based detection:** Injection and PII detection are regex-only. Sophisticated adversaries can evade regex. Recommended: layer with LLM-based classifiers.
2. **No authentication on REST API:** `aegis serve` exposes an unauthenticated API. Users must deploy behind a reverse proxy with auth.
3. **SQLite audit on local filesystem:** An attacker with filesystem access can delete the database (crypto chain detects tampering but not deletion). Recommended: external log shipping.
4. **Config file trust:** `aegis.yaml` is trusted input. A malicious config file in a parent directory could alter governance behavior.
5. **No runtime sandboxing:** Aegis governs at the library level, not the OS level. It cannot prevent an agent from bypassing governance entirely if it has raw access to the network.

## Artifacts for Auditor

| Artifact | Location |
|----------|----------|
| Source code | `src/aegis/` |
| Test suite | `tests/` |
| AGEF spec + JSON Schema | `specs/agef/v1/` |
| AGP protocol spec | `specs/agp/v1/` |
| Threat model | `docs/security/threat-model.md` |
| OWASP mapping | `docs/security/owasp-agentic-mapping.md` |
| Architecture | `.claude/context/architecture.md` |
| CI pipeline | `.github/workflows/ci.yml` |
| Conformance tests | `tests/conformance/` |

## Estimated Audit Cost

Based on scope (~1,550 critical LoC, ~3,000 total LoC in scope):
- **Lightweight review** (automated + 2-day manual): $5K-$10K
- **Standard audit** (1-2 week engagement): $15K-$30K
- **Comprehensive audit** (with threat modeling + pen test): $30K-$50K

Recommended: Start with a standard audit focused on the 5 critical components.
