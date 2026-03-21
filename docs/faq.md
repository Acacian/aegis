# FAQ

## General

### What is Aegis?
Aegis is a policy engine that sits between your AI agent and the systems it controls. It checks every action against your policy rules, optionally asks for human approval, and logs everything.

### Why not just add if/else checks in my agent code?
You could, but policy rules will be scattered across your codebase, hard to audit, and impossible to change without redeploying. Aegis centralizes governance into a single YAML file.

### Does Aegis work with my framework?
Aegis has built-in adapters for **LangChain**, **CrewAI**, **OpenAI Agents SDK**, **Anthropic Claude**, and **Playwright**. For anything else, write a custom adapter (it's ~10 lines of code).

### Is Aegis production-ready?
Aegis is in alpha (v0.1.x). The core API is stable, but breaking changes may occur before v1.0. We follow semantic versioning.

## Policy

### What happens if no rule matches an action?
The defaults apply. By default: `risk_level: medium`, `approval: approve`. You can change defaults in your policy YAML.

### Can I have multiple policy files?
Not yet (planned for v0.2 as "policy inheritance"). For now, use a single policy file or merge them in your application code.

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

### Where can I ask questions?
Use [GitHub Discussions](https://github.com/Acacian/aegis/discussions) for questions, ideas, and showcases. For bugs and feature requests, use [GitHub Issues](https://github.com/Acacian/aegis/issues).
