---
title: "Frequently Asked Questions"
description: "Frequently asked questions about Agent-Aegis: framework support, latency, security model, policy config, SOC2/GDPR/HIPAA audit trails."
---

# FAQ

## General

### What is Aegis?
Aegis is a policy engine that sits between your AI agent and the systems it controls. It checks every action against your policy rules, optionally asks for human approval, and logs everything.

### Why not just add if/else checks in my agent code?
You could, but policy rules will be scattered across your codebase, hard to audit, and impossible to change without redeploying. Aegis centralizes governance into a single YAML file.

### Does Aegis work with my framework?
Aegis auto-instruments 12 Python frameworks with one line of code: **LangChain**, **CrewAI**, **OpenAI Agents SDK**, **Anthropic Claude**, **LiteLLM**, **Google GenAI**, **Pydantic AI**, **LlamaIndex**, **Instructor**, **DSPy**, **OpenAI**, and **MCP** (Model Context Protocol). For anything else, write a custom adapter (~10 lines of code).

### Does Aegis work with non-Python agents?
Yes. Run `aegis serve policy.yaml` to start the REST API server, then call it from Go, TypeScript, Java, or any language via HTTP. See the [REST API Server guide](guides/rest-api.md).

### Can an agent bypass Aegis if it runs with admin privileges?
Aegis is an **application-level middleware**, not an OS-level sandbox. It only governs actions that go through `runtime.run_one()` or `runtime.execute()`. If agent code calls `os.system()` or accesses APIs directly without going through Aegis, those actions are not governed. It's the developer's responsibility to route all agent actions through Aegis. Think of it as a team rule ("always go through sudo") rather than a kernel-enforced permission.

### Is Aegis production-ready?
Aegis is in beta (v0.9.x). The core API is stable, but breaking changes may occur before v1.0. We follow semantic versioning.

## Policy

### What happens if no rule matches an action?
The defaults apply. By default: `risk_level: medium`, `approval: approve`. You can change defaults in your policy YAML.

### Can I have multiple policy files?
Yes. Use `Policy.from_yaml_files()` to merge multiple policy files:

```python
policy = Policy.from_yaml_files("base.yaml", "prod-overrides.yaml")
```

Or merge at runtime:

```python
base = Policy.from_yaml("base.yaml")
overrides = Policy.from_yaml("overrides.yaml")
merged = base.merge(overrides)
```

### Do conditions work with YAML anchors?
Yes. YAML anchors are resolved before Aegis sees the data, so conditions work fine with them.

### What timezone do time conditions use?
UTC. All time conditions (`time_after`, `time_before`) evaluate against UTC time. Convert your local time to UTC in the policy.

## Runtime

### Can I use Aegis synchronously?
The runtime is async-first. For synchronous code, use `asyncio.run()`:

```python
import asyncio
results = asyncio.run(runtime.execute(plan))
```

### Does Aegis support parallel execution?
Not yet. Actions are executed sequentially with fail-fast behavior. Parallel execution is on the roadmap.

### How do I test my policies?
Write unit tests that call `policy.evaluate(action)` and assert the expected decision:

```python
def test_delete_is_blocked():
    policy = Policy.from_yaml("policy.yaml")
    decision = policy.evaluate(Action("delete", "production"))
    assert decision.approval == Approval.BLOCK
```

## Audit

### Where is the audit log stored?
By default, in `aegis_audit.db` (SQLite) in the current directory. You can change this:

```python
AuditLogger(db_path="/path/to/audit.db")
```

Or use `LoggingAuditLogger` for Python logging integration.

### Can I export audit data?
Yes. Use JSONL export:

```bash
aegis audit --format jsonl -o audit.jsonl
```

Or JSON:

```bash
aegis audit --format json
```

## Adapters

### Do I need to install all adapter dependencies?
No. Install only what you need:

```bash
pip install 'agent-aegis[langchain]'  # Only LangChain
pip install 'agent-aegis[httpx]'      # Only httpx
pip install 'agent-aegis[all]'        # Everything
```

### Can I use multiple adapters at once?
Each `Runtime` instance uses one executor. For multiple backends, create multiple runtimes or build a composite executor.

## Performance

### What's the latency overhead?
Policy evaluation takes < 1ms (in-process regex/glob matching). For auto-approved actions, total overhead is < 5ms. Human approval adds variable latency (seconds to minutes) depending on the handler.

### What happens if the approval handler is slow or unresponsive?
Approval handlers can be configured with timeouts. If approval times out, the action is denied by default. You can customize this behavior in your `ApprovalHandler` implementation.

### Can I change policies without restarting?
Yes. Use hot-reload:

```python
runtime.update_policy(Policy.from_yaml("new_policy.yaml"))
```

All subsequent `plan()` calls use the new policy immediately. In-flight executions are not affected. The REST API server also supports hot-reload via `PUT /api/v1/policy`.

### Does Aegis add memory overhead?
Minimal. Aegis keeps the policy rules in memory (typically < 1KB for 100 rules) and writes audit entries to SQLite asynchronously. No background threads or persistent connections.

## Security

### How does Aegis handle policy injection?
Policies are loaded from trusted YAML files, not user input. The YAML parser rejects custom tags and constructors. If you load policies from external sources, validate them with `aegis validate` first.

### Can Aegis prevent prompt injection?
Yes. Since v0.4, Aegis includes built-in runtime guardrails that inspect and filter LLM prompts and responses. Prompt injection detection (13 attack categories, 107 patterns, multi-language), PII detection and masking (13 categories including Luhn-validated credit cards, SSNs, IBAN, API keys), and toxicity filtering all run automatically on every input and output when auto-instrumentation is active. Aegis also governs **actions** (API calls, database queries, file operations), so it provides defense in depth at both the prompt level and the action level.

### Is there a way to enforce Aegis in production?
Aegis is a library — it relies on the developer routing all agent actions through `runtime.run_one()`. For stronger enforcement in containerized environments, see the [Security Model guide](guides/security-model.md) which covers Docker defense-in-depth patterns.

## Compliance

### Does Aegis help with SOC2 compliance?
Aegis provides tooling that supports SOC2 evidence collection — immutable audit trails, approval gates, and access control logs map to Trust Services Criteria (CC6.1, CC7.2, CC8.1). Export audit logs as JSONL for your auditor. Aegis is not itself SOC2-certified; it generates evidence that your compliance team can include in their audit packages.

### Does Aegis help with GDPR?
Aegis logs which system accessed what data and when, providing data access documentation that supports GDPR Article 30 record-keeping. Combine with your data classification to track PII access. Consult your DPO for jurisdiction-specific obligations.

### Can I use Aegis for HIPAA audit trails?
The audit log captures access patterns with full action context and approval chains, which can support HIPAA audit trail requirements. See the [compliance demo](https://github.com/Acacian/aegis/blob/main/examples/compliance_demo.py) for a worked example. Aegis provides tooling, not certification — consult qualified counsel for your specific compliance obligations.

## Community

### Where can I ask questions?
Use [GitHub Discussions](https://github.com/Acacian/aegis/discussions) for questions, ideas, and showcases. For bugs and feature requests, use [GitHub Issues](https://github.com/Acacian/aegis/issues).

### How can I contribute?
Check [Good First Issues](https://github.com/Acacian/aegis/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) for starter tasks, or read the [Contributing Guide](https://github.com/Acacian/aegis/blob/main/CONTRIBUTING.md) for setup instructions.

### Can I use Aegis commercially?
Yes. Aegis is MIT-licensed — use it freely in commercial projects with no restrictions.
