# Architecture

This document describes the high-level design of Aegis.

## Design Philosophy

1. **Policy-first**: Every agent action goes through policy evaluation before execution.
2. **Framework-agnostic**: Core engine has no framework dependencies. Adapters are optional.
3. **Audit everything**: Every decision and result is logged for post-hoc review.
4. **Fail-safe defaults**: Unknown actions default to `medium` risk with `approve` requirement.

## Module Structure

```
src/aegis/
├── core/           # Pure data models and policy engine (no I/O)
│   ├── action.py       # Action dataclass
│   ├── risk.py         # RiskLevel enum
│   ├── policy.py       # Policy engine, rules, decisions
│   ├── conditions.py   # Condition evaluators (time, params, weekday)
│   ├── result.py       # Result and status types
│   ├── plan.py         # ExecutionPlan model
│   └── schema.py       # Policy JSON Schema
│
├── adapters/       # Pluggable executors (each with optional deps)
│   ├── base.py         # BaseExecutor ABC
│   ├── playwright.py   # Browser automation
│   ├── httpx_adapter.py # REST API calls
│   ├── langchain.py    # LangChain integration
│   ├── crewai.py       # CrewAI integration
│   ├── openai_agents.py # OpenAI Agents SDK
│   └── anthropic.py    # Anthropic Claude
│
├── runtime/        # Orchestration and side effects
│   ├── engine.py       # Runtime: plan → approve → execute → verify → audit
│   ├── approval.py     # Approval handlers (CLI, auto)
│   ├── approval_callback.py  # Callback-based approval
│   ├── audit.py        # SQLite audit logger
│   └── audit_logging.py # Python logging audit backend
│
└── cli/            # Command-line interface
    └── main.py         # aegis validate | audit | schema
```

## Data Flow

```
                    ┌──────────────┐
                    │  Agent Code  │
                    └──────┬───────┘
                           │ Action(type, target, params)
                           ▼
                    ┌──────────────┐
                    │   Runtime    │
                    │   .plan()   │
                    └──────┬───────┘
                           │ PolicyDecision(risk, approval, rule)
                           ▼
              ┌────────────┴────────────┐
              │                         │
        ┌─────▼─────┐           ┌───────▼───────┐
        │   AUTO     │           │   APPROVE     │
        │ (execute)  │           │ (ask human)   │
        └─────┬─────┘           └───────┬───────┘
              │                         │ approved/denied
              └────────────┬────────────┘
                           ▼
                    ┌──────────────┐
                    │   Executor   │ ← Adapter (Playwright, httpx, etc.)
                    │  .execute()  │
                    └──────┬───────┘
                           │ Result(status, data)
                           ▼
                    ┌──────────────┐
                    │   Verify     │ ← Optional post-execution check
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │  Audit Log   │ ← SQLite, logging, or JSONL
                    └──────────────┘
```

## Key Design Decisions

### Why first-match-wins for policy rules?
Simpler mental model than priority-based systems. Developers order rules from specific to general, just like firewall rules or CSS selectors.

### Why glob patterns instead of regex?
Globs are familiar, readable, and sufficient for action type/target matching. Regex is available in conditions (`param_matches`) for complex cases.

### Why SQLite for audit?
Zero configuration, works everywhere, queryable. For production log aggregation, use `LoggingAuditLogger` to pipe to existing infrastructure.

### Why lazy imports for adapters?
Each adapter has heavy optional dependencies (playwright, langchain-core, etc.). Lazy imports ensure `import aegis` is fast and the core has no heavy deps.

### Why async-first?
AI agent frameworks are predominantly async. Sync wrappers are trivial to add, but async-first avoids event loop issues.

## Dependency Graph

```
aegis (core)
├── pyyaml          # Only required dependency
│
├── [playwright]    # Optional: PlaywrightExecutor
├── [langchain]     # Optional: LangChainExecutor, AegisTool
├── [crewai]        # Optional: AegisCrewAITool
├── [openai-agents] # Optional: governed_tool decorator
├── [anthropic]     # Optional: govern_tool_call
└── [httpx]         # Optional: HttpxExecutor
```

## Testing Strategy

- Unit tests for core (policy, actions, conditions) — no I/O
- Integration tests for runtime (in-memory SQLite, fake executors)
- Import guard tests for each adapter (verify graceful error without optional deps)
- CLI tests using capsys and tmp_path fixtures
