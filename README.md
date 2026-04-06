<!-- mcp-name: io.github.Acacian/aegis -->
<p align="center">
  <h1 align="center">Agent-Aegis</h1>
  <p align="center">
    <strong>Find ungoverned AI calls in your codebase. Fix them before production.</strong>
  </p>
  <p align="center">
    <code>pip install agent-aegis && aegis scan .</code> — finds every unprotected LLM call and tool invocation in 30 seconds.<br/>
    Then add one line to govern them all: <code>aegis.auto_instrument()</code> adds injection blocking, PII masking, and audit trail to 11 frameworks. No code changes.
  </p>
</p>

<p align="center">
  <a href="https://github.com/Acacian/aegis/actions/workflows/ci.yml"><img src="https://github.com/Acacian/aegis/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/agent-aegis/"><img src="https://img.shields.io/pypi/v/agent-aegis?color=blue&cacheSeconds=3600" alt="PyPI"></a>
  <a href="https://pypi.org/project/langchain-aegis/"><img src="https://img.shields.io/pypi/v/langchain-aegis?label=langchain-aegis&color=blue&cacheSeconds=3600" alt="langchain-aegis"></a>
  <a href="https://pypi.org/project/agent-aegis/"><img src="https://img.shields.io/pypi/pyversions/agent-aegis?cacheSeconds=3600" alt="Python"></a>
  <a href="https://github.com/Acacian/aegis/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
  <a href="https://acacian.github.io/aegis/"><img src="https://img.shields.io/badge/docs-acacian.github.io%2Faegis-blue" alt="Docs"></a>
  <br/>
  <a href="https://github.com/Acacian/aegis/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/tests-6061%2B_passed-brightgreen" alt="Tests"></a>
  <a href="https://github.com/Acacian/aegis/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/coverage-92%25-brightgreen" alt="Coverage"></a>
  <a href="https://acacian.github.io/aegis/playground/"><img src="https://img.shields.io/badge/playground-Try_it_Live-ff6b6b" alt="Playground"></a>
  <a href="https://acacian.github.io/aegis/playground/scan-report.html"><img src="https://img.shields.io/badge/scan_report-39_Repos%2C_92%25_F-red" alt="Scan Report"></a>
  <a href="https://www.bestpractices.dev/projects/12253"><img src="https://www.bestpractices.dev/projects/12253/badge" alt="OpenSSF Best Practices"></a>
</p>

<p align="center">
  <a href="#try-it-30-seconds"><strong>Try It (30s)</strong></a> &bull;
  <a href="#add-to-ci"><strong>Add to CI</strong></a> &bull;
  <a href="#auto-instrumentation">Auto-Instrumentation</a> &bull;
  <a href="#policy-cicd">Policy CI/CD</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="https://acacian.github.io/aegis/">Docs</a> &bull;
  <a href="https://acacian.github.io/aegis/playground/"><strong>Playground</strong></a>
</p>

<p align="center">
  <b>English</b> &bull;
  <a href="./README.ko.md">한���어</a>
</p>

---

## Try It (30 Seconds)

```bash
pip install agent-aegis
aegis scan .
```

```
Scanning . for ungoverned AI calls...

  src/agent.py:12     openai.ChatCompletion.create()    NO GUARDRAIL
  src/agent.py:34     langchain.ChatOpenAI.invoke()      NO GUARDRAIL
  src/tools.py:8      anthropic.messages.create()        NO GUARDRAIL
  src/pipeline.py:21  crew.kickoff()                     NO GUARDRAIL

  4 ungoverned AI calls found in 3 files.
  Run `aegis.auto_instrument()` to add guardrails, or create a policy with `aegis init`.
```

## Add to CI

```yaml
- uses: Acacian/aegis@v0.9.2
  with:
    command: scan
    fail-on-ungoverned: true
```

Every PR gets scanned. Ungoverned AI calls block the merge. [See all options](action.yml).

---

## Auto-Instrumentation

Add guardrails to any project in one line. No refactoring, no wrappers.

```python
import aegis
aegis.auto_instrument()

# Every LangChain, CrewAI, OpenAI, Anthropic, LiteLLM, Google GenAI,
# Pydantic AI, LlamaIndex, Instructor, and DSPy call now passes through:
#   - Prompt injection detection (blocks attacks)
#   - PII detection (warns on personal data exposure)
#   - Prompt leak detection (warns on system prompt extraction)
#   - Full audit trail (every call logged)
```

Or zero code changes — just set an environment variable:

```bash
AEGIS_INSTRUMENT=1 python my_agent.py
```

### Supported Frameworks

| Framework | What gets patched | Status |
|-----------|------------------|--------|
| **LangChain** | `BaseChatModel.invoke/ainvoke`, `BaseTool.invoke/ainvoke` | Stable |
| **CrewAI** | `Crew.kickoff/kickoff_async`, global `BeforeToolCallHook` | Stable |
| **OpenAI Agents SDK** | `Runner.run`, `Runner.run_sync` | Stable |
| **OpenAI API** | `Completions.create` (chat & completions) | Stable |
| **Anthropic API** | `Messages.create` | Stable |
| **LiteLLM** | `completion`, `acompletion` | Stable |
| **Google GenAI** | `Models.generate_content` (new + legacy) | Stable |
| **Pydantic AI** | `Agent.run`, `Agent.run_sync` | Stable |
| **LlamaIndex** | `LLM.chat/achat/complete/acomplete`, `BaseQueryEngine.query/aquery` | Stable |
| **Instructor** | `Instructor.create`, `AsyncInstructor.create` | Stable |
| **DSPy** | `Module.__call__`, `LM.forward/aforward` | Stable |

### Default Guardrails

| Guardrail | Default | What it catches |
|-----------|---------|-----------------|
| **Prompt injection** | Block | 10 attack categories, 85+ patterns, multi-language (EN/KO/ZH/JA) |
| **PII detection** | Warn | 13 categories (email, credit card, SSN, IBAN, API keys, etc.) |
| **Prompt leak** | Warn | System prompt extraction attempts |
| **Toxicity** | Warn | Harmful, violent, or abusive content |

All guardrails are deterministic regex — no LLM calls, no network. **2.65ms cold / <1us warm** per check. [Benchmarks](benchmarks/).

---

## Policy CI/CD

Security tools protect at runtime. Aegis also manages the policy lifecycle.

### `aegis plan` — Preview before deploying

```bash
aegis plan current.yaml proposed.yaml --audit-db aegis_audit.db

# Policy Impact Analysis
#   Rules: 2 added, 1 removed, 3 modified
#   Impact (replayed 1,247 actions):
#     23 actions would change from AUTO → BLOCK
```

### `aegis test` — Regression testing for policies

```bash
aegis test policy.yaml tests.yaml              # Run in CI
aegis test policy.yaml --generate              # Auto-generate test suite
aegis test new.yaml tests.yaml --regression old.yaml  # Regression check
```

```yaml
# .github/workflows/policy-check.yml
- uses: Acacian/aegis@main
  with:
    policy: aegis.yaml
    tests: tests.yaml
    fail-on-regression: true
```

---

## Quick Start

### 1. Install

```bash
pip install agent-aegis
```

### 2. Auto-instrument (recommended)

```python
import aegis
aegis.auto_instrument()
# All 11 frameworks are now governed.
```

### 3. Or use a YAML policy for full control

```bash
aegis init  # Creates aegis.yaml
```

```yaml
# aegis.yaml
guardrails:
  pii: { enabled: true, action: mask }
  injection: { enabled: true, action: block, sensitivity: medium }

policy:
  version: "1"
  defaults:
    risk_level: medium
    approval: approve
  rules:
    - name: read_safe
      match: { type: "read*" }
      risk_level: low
      approval: auto
    - name: no_deletes
      match: { type: "delete*" }
      risk_level: critical
      approval: block
```

### 4. See what happened

```bash
aegis audit
```
```
  ID  Session       Action        Target   Risk      Decision    Result
  1   a1b2c3d4...   read          crm      LOW       auto        success
  2   a1b2c3d4...   bulk_update   crm      HIGH      approved    success
  3   a1b2c3d4...   delete        crm      CRITICAL  block       blocked
```

---

## Install Options

```bash
pip install agent-aegis                   # Core (includes auto_instrument for all frameworks)
pip install langchain-aegis               # LangChain standalone integration
pip install 'agent-aegis[mcp]'            # MCP server + proxy
pip install 'agent-aegis[server]'         # REST API + dashboard
pip install 'agent-aegis[all]'            # Everything
```

### MCP Proxy — govern any MCP server with zero code changes

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "uvx",
      "args": ["--from", "agent-aegis[mcp]", "aegis-mcp-proxy",
               "--wrap", "npx", "-y",
               "@modelcontextprotocol/server-filesystem", "/home"]
    }
  }
}
```

Works with Claude Desktop, Cursor, VS Code, Windsurf. Tool poisoning detection, rug-pull detection, argument sanitization, policy evaluation, full audit trail.

---

## Why Aegis?

| | Writing your own | Platform guardrails | Enterprise platforms | **Aegis** |
|---|---|---|---|---|
| **Setup** | Days of if/else | Vendor-specific config | Kubernetes + procurement | **`pip install` + one line** |
| **Code changes** | Wrap every call | SDK-specific | Months of integration | **Zero — auto-instruments** |
| **Cross-framework** | Rewrite per framework | Their ecosystem only | Usually single-vendor | **11 frameworks** |
| **Policy CI/CD** | None | None | None | **`aegis plan` + `aegis test`** |
| **Audit trail** | printf debugging | Platform logs only | Cloud dashboard | **SQLite + JSONL + webhooks** |
| **Compliance** | Manual docs | None | Enterprise sales cycle | **EU AI Act, NIST, SOC2 built-in** |
| **Cost** | Engineering time | Free-to-$$$ | $$$$ + infra | **Free (MIT). Forever.** |

---

## CLI

```bash
aegis scan ./src/                       # Detect ungoverned AI calls
aegis score ./src/ --policy policy.yaml # Governance score (0-100)
aegis init                              # Generate starter policy
aegis validate policy.yaml              # Validate syntax
aegis plan current.yaml proposed.yaml   # Preview policy changes
aegis test policy.yaml tests.yaml       # Policy regression testing
aegis audit                             # View audit log
aegis serve policy.yaml                 # REST API + dashboard
aegis probe policy.yaml                 # Adversarial policy testing
aegis autopolicy "block deletes"        # Natural language → YAML
```

## Documentation

Full documentation at **[acacian.github.io/aegis](https://acacian.github.io/aegis/)**:

- [Integration guides](https://acacian.github.io/aegis/) — LangChain, CrewAI, OpenAI, MCP, and more
- [Policy reference](https://acacian.github.io/aegis/) — conditions, templates, best practices
- [Security features](https://acacian.github.io/aegis/) — guardrails, anomaly detection, compliance
- [Architecture](ARCHITECTURE.md) — how the codebase is structured
- [Interactive playground](https://acacian.github.io/aegis/playground/) — try in browser, no install

## Contributing

```bash
git clone https://github.com/Acacian/aegis.git && cd aegis
make dev      # Install deps + hooks
make test     # Run tests
make lint     # Lint + format check
```

[Contributing Guide](CONTRIBUTING.md) &bull; [Good First Issues](https://github.com/Acacian/aegis/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) &bull; [![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/Acacian/aegis)

## License

MIT -- see [LICENSE](LICENSE) for details.

Copyright (c) 2026 구동하 (Dongha Koo, [@Acacian](https://github.com/Acacian)). Created March 21, 2026.

---

<p align="center">
  <sub>Policy CI/CD for AI agents. Built for the era of autonomous AI agents.</sub><br/>
  <sub>If Aegis helps you, consider giving it a star -- it helps others find it too.</sub>
</p>
