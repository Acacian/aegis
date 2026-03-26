# Aegis Threat Model

Version: 1.0 | Date: 2026-03-24

## Scope

Aegis is a **library** (not a hosted service). It runs inside the user's Python process. This threat model covers:
- The Aegis library itself (pip package)
- The CLI tools (`aegis` command)
- The optional REST API server (`aegis serve`)
- The browser-based playground (static site, no backend)

Out of scope: the user's application code, the AI models called through Aegis, infrastructure hosting.

## Trust Boundaries

```
┌─────────────────────────────────────────────────┐
│ User's Application Process                      │
│  ┌───────────┐  ┌──────────┐  ┌──────────────┐ │
│  │ AI Agent  │→ │  Aegis   │→ │ AI Provider  │ │
│  │ Framework │  │ Library  │  │ (OpenAI etc) │ │
│  └───────────┘  └──────────┘  └──────────────┘ │
│                      │                          │
│              ┌───────┴────────┐                 │
│              │  Local SQLite  │                 │
│              │  Audit Store   │                 │
│              └────────────────┘                 │
└─────────────────────────────────────────────────┘
         │ optional
    ┌────┴─────┐
    │ REST API │  ← External network boundary
    │ Server   │
    └──────────┘
```

## Assets

| Asset | Sensitivity | Location |
|-------|-------------|----------|
| Policy YAML files | Medium | Filesystem |
| Audit logs (SQLite) | High — contains action metadata | Filesystem |
| aegis.yaml config | Medium — may contain backend credentials | Filesystem |
| AGEF events (exported) | High — contains governance decisions | SIEM/external |
| API tokens (Splunk HEC, Elastic) | Critical | Environment variables / config |

## Threat Categories

### T1: Policy Bypass

**Threat:** Attacker crafts action types or targets that evade glob matching rules.

**Mitigations:**
- `aegis probe` CLI command performs adversarial policy testing
- First-match-wins semantics are simple and predictable
- Wildcard coverage analysis detects gaps
- Conformance tests validate policy evaluation correctness

**Residual risk:** Low. Glob semantics are well-understood and tested (3,860+ tests).

### T2: Injection Pattern Evasion

**Threat:** Attacker bypasses injection detection via encoding, Unicode tricks, or novel patterns.

**Mitigations:**
- Unicode normalization before pattern matching
- 85+ patterns across 10 categories
- Multi-language support (KO, ZH, JA)
- 3 sensitivity levels including aggressive mode
- Rule pack ecosystem for community-contributed patterns

**Residual risk:** Medium. Regex-based detection has inherent limits. Defense-in-depth recommended (combine with LLM-based classifiers).

### T3: PII Leakage Through Masking Gaps

**Threat:** PII patterns not covered by regex (novel formats, typos, context-dependent PII).

**Mitigations:**
- 12 PII categories with secondary validation (Luhn for credit cards)
- Configurable action levels (mask/block/warn/log)
- Community-extensible rule packs

**Residual risk:** Medium. Named entity recognition (NER) would improve coverage. Currently regex-only.

### T4: Audit Log Tampering

**Threat:** Attacker with filesystem access modifies SQLite audit database.

**Mitigations:**
- Cryptographic audit chain: SHA-256 hash-linked entries
- `aegis audit --verify` detects any tampered entry
- Evidence export for external archival
- WAL mode prevents corruption from concurrent access

**Residual risk:** Low for detection. An attacker with root access could rewrite the entire chain — mitigate with external log shipping (SIEM export).

### T5: REST API Server Attacks

**Threat:** When `aegis serve` is exposed, standard web attack vectors apply.

**Mitigations:**
- Starlette ASGI framework with standard security practices
- API is read-heavy (evaluate, audit query) with limited write surface
- Designed for internal network deployment
- No authentication built-in (bring your own reverse proxy)

**Residual risk:** Medium. Users MUST deploy behind authentication if exposed to untrusted networks. This is documented.

### T6: Dependency Supply Chain

**Threat:** Compromised dependency injected via PyPI.

**Mitigations:**
- Minimal dependencies: only `pyyaml` required for core
- All optional deps are extras (`pip install 'agent-aegis[langchain]'`)
- CI pins GitHub Actions to SHA hashes
- Dependabot enabled for automated dependency updates

**Residual risk:** Low. Attack surface is minimal due to near-zero dependencies.

### T7: Configuration Injection

**Threat:** Malicious `aegis.yaml` loaded from unexpected location.

**Mitigations:**
- Auto-discovery limited to CWD + 5 parent directories
- Config file must be valid YAML (parsed with `yaml.safe_load`)
- No code execution from config (declarative only)

**Residual risk:** Low.

### T8: MCP Tool Supply Chain

**Threat:** Malicious MCP tool definitions (poisoning, rug pulls).

**Mitigations:**
- Tool description scanner: 10 attack patterns
- SHA-256 manifest pinning for rug-pull detection
- Argument sanitization (path traversal, command injection)
- Trust scoring (L0-L4)
- Known vulnerability database

**Residual risk:** Low for known patterns. Novel tool-level attacks may evade detection.

## Recommended Security Posture

1. **Run audit verification regularly:** `aegis audit --verify`
2. **Ship logs externally:** Use SIEM export (Splunk/Elastic) for tamper-resistant archival
3. **Deploy REST API behind auth:** Never expose `aegis serve` to untrusted networks without authentication
4. **Use injection detection + LLM classifier:** Regex is a first layer, not the only layer
5. **Review policies with `aegis probe`:** Adversarial testing catches glob gaps
6. **Pin aegis version in requirements:** Avoid uncontrolled upgrades

## Audit Contact

For security reports: open a GitHub Security Advisory at https://github.com/Acacian/aegis/security/advisories/new

For independent audit inquiries: see the repository maintainer contact.
