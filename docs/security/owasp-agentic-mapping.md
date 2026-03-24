# Aegis Coverage of OWASP Top 10 for Agentic Applications (2025)

This document maps Aegis capabilities to each OWASP Agentic AI risk category. It serves as both user documentation and as the basis for potential OWASP project contributions.

> **Disclaimer:** Aegis provides technical controls that mitigate these risks. No single tool eliminates all risk — defense-in-depth is required.

## Coverage Summary

| # | OWASP Risk | Aegis Coverage | Key Feature |
|---|-----------|----------------|-------------|
| 01 | Agent Goal Hijack | **Partial** | Prompt injection detection (85+ patterns, multi-language) |
| 02 | Tool Misuse | **Full** | YAML policy engine — per-tool allow/deny/review gates |
| 03 | Identity & Privilege Abuse | **Full** | Agent trust chain, RBAC (12 permissions), delegation tokens |
| 04 | Supply Chain Vulnerabilities | **Full** | MCP tool poisoning scanner, SHA-256 pinning, SBOM, vuln DB |
| 05 | Unexpected Code Execution | **Partial** | Policy rules can block `execute`/`eval` action types |
| 06 | Memory & Context Poisoning | **Partial** | Guardrails scan input/output; no persistent memory governance yet |
| 07 | Insecure Inter-Agent Comms | **Full** | A2A governance — capability gating, PII redaction, rate limiting |
| 08 | Cascading Failures | **Full** | Cost circuit breaker, rate limiter, anomaly detection, per-agent budgets |
| 09 | Human-Agent Trust Exploitation | **Partial** | Approval gates with context; structured approval UX reduces rubber-stamping |
| 10 | Rogue Agents | **Full** | Behavioral anomaly detection, auto-policy from observed behavior |

## Detailed Mapping

### OWASP-AGENT-01: Agent Goal Hijack

**Risk:** Agents redirected by hidden instructions in external content.

**Aegis mitigation:**
- `InjectionGuardrail`: 10 attack categories, 85+ compiled regex patterns
- Multi-language: Korean, Chinese (simplified + traditional), Japanese
- 3 sensitivity levels: low (high-confidence only), medium (recommended), high (aggressive)
- Delimiter injection detection: `<|endoftext|>`, ChatML tokens, XML role tags
- Context manipulation detection: fake authority claims, trust manipulation

**Gaps:** Semantic attacks that evade pattern matching. Mitigated by layered approach (combine with LLM-based classifiers).

**Code:** `src/aegis/guardrails/injection.py`

---

### OWASP-AGENT-02: Tool Misuse

**Risk:** Legitimate tools weaponized via manipulated agent reasoning.

**Aegis mitigation:**
- YAML policy engine: per-action-type rules with glob matching
- Approval gates: `auto` / `approve` / `block` per action
- Smart conditions: time-based, parameter-based, weekday-based rules
- Risk-level assignment: `low` / `medium` / `high` / `critical`
- Hot-reload: update policies without restarting

**Gaps:** None for declared actions. Actions the agent invokes outside governance are not covered (use `aegis scan` to detect ungoverned calls).

**Code:** `src/aegis/core/policy.py`, `src/aegis/cli/scan.py`

---

### OWASP-AGENT-03: Identity & Privilege Abuse

**Risk:** Compromised agents inherit all their permissions.

**Aegis mitigation:**
- Agent trust chain: hierarchical identity, delegation with intersection semantics
- RBAC: 12 granular permissions, 5 hierarchical roles
- Cascade revocation: revoking a parent agent revokes all delegated children
- Per-agent policy: different rules per agent_id

**Code:** `src/aegis/core/agent_identity.py`, `src/aegis/core/rbac.py`

---

### OWASP-AGENT-04: Supply Chain Vulnerabilities

**Risk:** Malicious MCP tools loaded at runtime.

**Aegis mitigation:**
- Tool poisoning scanner: 10 regex patterns against Unicode-normalized descriptions
- Rug-pull detection: SHA-256 hash pinning, alerts on definition changes
- Argument sanitization: path traversal, command injection, null byte detection
- Trust scoring: L0-L4 automated levels
- Vulnerability database: 8 built-in CVEs, version-range matching
- SBOM generation: CycloneDX-inspired bill of materials

**Code:** `src/aegis/mcp/`

---

### OWASP-AGENT-05: Unexpected Code Execution

**Risk:** Text input → system commands via code generation.

**Aegis mitigation:**
- Policy rules can match and block `execute`, `eval`, `shell` action types
- Guardrails detect encoded payloads (`base64`, `eval`, `exec`, `fromCharCode`)

**Gaps:** Cannot govern code execution inside the LLM itself. Combine with sandboxed execution (Docker, gVisor).

---

### OWASP-AGENT-06: Memory & Context Poisoning

**Risk:** Persistent memory corrupted by injection.

**Aegis mitigation:**
- Input/output guardrails scan all content passing through governed calls
- PII masking prevents sensitive data from entering memory stores

**Gaps:** No direct governance of vector DB writes or agent memory persistence. Future work.

---

### OWASP-AGENT-07: Insecure Inter-Agent Communication

**Risk:** No authentication between agents in multi-agent systems.

**Aegis mitigation:**
- A2A communication governance: capability-based messaging
- Automatic PII/credential scrubbing on inter-agent messages
- Per-agent rate limiting
- Full audit trail of inter-agent communication

**Code:** `src/aegis/a2a/`

---

### OWASP-AGENT-08: Cascading Failures

**Risk:** Errors propagate through multi-agent workflows.

**Aegis mitigation:**
- Cost circuit breaker: per-agent and global budgets, loop detection
- Rate limiter: sliding window, per-agent and global limits
- Anomaly detection: rate spikes, burst patterns, unusual behavior
- Hierarchical budgets: delegation tree cost rollup

**Code:** `src/aegis/cost/`, `src/aegis/core/rate_limiter.py`, `src/aegis/core/anomaly.py`

---

### OWASP-AGENT-09: Human-Agent Trust Exploitation

**Risk:** Humans rubber-stamp agent approval requests.

**Aegis mitigation:**
- Approval gates with full action context (type, target, params, risk level)
- 7 approval handlers (CLI, Slack, Discord, Telegram, email, webhook, custom)
- Risk-level highlighting in approval UI
- Audit trail of all approval decisions (who approved what and when)

**Gaps:** UI/UX improvements for approval fatigue reduction. Consider batch approvals with risk summaries.

---

### OWASP-AGENT-10: Rogue Agents

**Risk:** Agents develop misaligned objectives.

**Aegis mitigation:**
- Behavioral anomaly detection: per-agent profiling
- 5 anomaly types: rate spikes, bursts, new actions, unusual targets, high block rates
- Auto-policy generation from observed behavior
- Real-time monitoring dashboard (`aegis monitor`)

**Code:** `src/aegis/core/anomaly.py`

---

## OWASP Contribution Opportunities

1. **Reference implementation**: Aegis can serve as a reference implementation for OWASP Agentic guidance
2. **Conformance test suite**: The AGEF/AGP conformance tests can be contributed as a validation tool
3. **Threat model**: Aegis's threat model documentation can inform OWASP's guidance documents
4. **Pattern database**: The 85+ injection patterns and 10 MCP poisoning patterns are community-extensible
