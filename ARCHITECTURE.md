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
├── instrument/     # Auto-instrumentation (monkey-patching layer)
│   ├── __init__.py      # auto_instrument(), status(), reset()
│   ├── _langchain.py    # Patches BaseChatModel, BaseTool
│   ├── _crewai.py       # Patches Crew.kickoff, BeforeToolCallHook
│   ├── _openai_agents.py # Patches Runner.run, Runner.run_sync
│   ├── _defaults.py     # Default guardrail engine builder
│   └── _state.py        # Thread-safe global instrumentation state
│
├── core/           # Pure data models and policy engine (no I/O)
│   ├── action.py       # Action dataclass
│   ├── risk.py         # RiskLevel enum
│   ├── policy.py       # Policy engine, rules, decisions
│   ├── conditions.py   # Condition evaluators (time, params, weekday)
│   ├── result.py       # Result and status types
│   ├── plan.py         # ExecutionPlan model
│   └── schema.py       # Policy JSON Schema
│
├── guardrails/     # Runtime content guardrails
│   ├── engine.py       # GuardrailEngine pipeline
│   ├── injection.py    # Prompt injection detection
│   ├── pii.py          # PII detection & masking
│   ├── toxicity.py     # Toxicity detection
│   └── prompt_leak.py  # Prompt leak detection
│
├── integrations/   # Zero-code API patching
│   ├── patch_openai.py    # Monkey-patches OpenAI API
│   ├── patch_anthropic.py # Monkey-patches Anthropic API
│   └── decorators.py     # @guard decorator
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
│   ├── engine.py       # Runtime: plan -> approve -> execute -> verify -> audit
│   ├── approval.py     # Approval handlers (CLI, auto)
│   ├── approval_callback.py  # Callback-based approval
│   ├── audit.py        # SQLite audit logger
│   └── audit_logging.py # Python logging audit backend
│
└── cli/            # Command-line interface
    └── main.py         # aegis validate | audit | schema
```

## Data Flow

### Auto-Instrumentation Path (zero-code)

```mermaid
graph TD
    AI["aegis.auto_instrument()"] --> DETECT[Detect installed frameworks]
    DETECT --> PATCH["Monkey-patch LangChain / CrewAI / OpenAI Agents / OpenAI / Anthropic"]
    PATCH --> GUARD["Build default guardrail engine"]

    APP["Your existing code (unchanged)"] --> FW["framework.invoke() / Runner.run() / etc."]
    FW --> IN["Input guardrails (injection, toxicity, PII, leak)"]
    IN -->|blocked| ERR["AegisGuardrailError / warn / log"]
    IN -->|passed| ORIG["Original framework method"]
    ORIG --> OUT["Output guardrails"]
    OUT -->|blocked| ERR
    OUT -->|passed| RES["Return response to your code"]

    style AI fill:#4a90d9,color:#fff
    style GUARD fill:#f5a623,color:#fff
    style IN fill:#7ed321,color:#fff
    style OUT fill:#7ed321,color:#fff
    style ERR fill:#d0021b,color:#fff
```

### Policy Engine Path (full control)

```mermaid
graph TD
    A[Your Agent Code] -->|"Action(type, target, params)"| B[Runtime.plan]
    B -->|"PolicyDecision(risk, approval, rule)"| C{Approval Mode}

    C -->|"auto: LOW"| D[Execute]
    C -->|"approve: HIGH"| E[Approval Handler]
    C -->|"block: CRITICAL"| F[Blocked]

    E -->|approved| D
    E -->|denied| F

    D -->|"Result(status, data)"| G[Verify]
    G --> H[Audit Logger]
    F --> H

    style A fill:#4a90d9,color:#fff
    style C fill:#f5a623,color:#fff
    style D fill:#7ed321,color:#fff
    style F fill:#d0021b,color:#fff
    style H fill:#9013fe,color:#fff
```

## Adapter Architecture

```mermaid
graph LR
    R[Runtime] --> B[BaseExecutor]
    B --> P[PlaywrightExecutor]
    B --> HX[HttpxExecutor]
    B --> LC[LangChainExecutor]
    B --> CR[AegisCrewAITool]
    B --> OA["@governed_tool"]
    B --> AN[AnthropicAdapter]
    B --> CU[Your Custom Executor]

    P -.->|optional| PW["playwright"]
    HX -.->|optional| HP["httpx"]
    LC -.->|optional| LK["langchain-core"]
    CR -.->|optional| CW["crewai"]
    OA -.->|optional| OAI["openai-agents"]
    AN -.->|optional| ANT["anthropic"]

    style R fill:#4a90d9,color:#fff
    style B fill:#f5a623,color:#fff
    style CU fill:#7ed321,color:#fff
```

## Policy Evaluation Flow

```mermaid
flowchart TD
    A["Action(type='bulk_update', target='crm')"] --> B{Match Rule 1?}
    B -->|No| C{Match Rule 2?}
    B -->|Yes| D[Check Conditions]
    C -->|No| E{Match Rule N?}
    C -->|Yes| D
    E -->|No| F[Apply Defaults]
    E -->|Yes| D

    D -->|All pass| G["PolicyDecision(rule, risk, approval)"]
    D -->|Any fail| C
    F --> G

    style A fill:#4a90d9,color:#fff
    style D fill:#f5a623,color:#fff
    style G fill:#7ed321,color:#fff
```

## Key Design Decisions

### Why first-match-wins for policy rules?
Simpler mental model than priority-based systems. Developers order rules from specific to general, just like firewall rules or CSS selectors.

### Why glob patterns instead of regex?
Globs are familiar, readable, and sufficient for action type/target matching. Regex is available in conditions (`param_matches`) for complex cases.

### Why SQLite for audit?
Zero configuration, works everywhere, queryable. For production log aggregation, use `LoggingAuditLogger` to pipe to existing infrastructure.

### Why monkey-patching for auto-instrumentation?
The same pattern used by OpenTelemetry (tracing), Sentry (error tracking), and datadog-trace (APM). It provides zero-code governance -- users add one line and all existing AI calls are governed without refactoring. All patches are reversible via `reset()`, idempotent, and skip cleanly if a framework is not installed.

### Why lazy imports for adapters?
Each adapter has heavy optional dependencies (playwright, langchain-core, etc.). Lazy imports ensure `import aegis` is fast and the core has no heavy deps.

### Why async-first?
AI agent frameworks are predominantly async. Sync wrappers are trivial to add, but async-first avoids event loop issues.

## Dependency Graph

```mermaid
graph TD
    AEGIS["aegis (core)"] --> YAML["pyyaml *(required)*"]

    AEGIS -.-> PW["playwright *(optional)*"]
    AEGIS -.-> LC["langchain-core *(optional)*"]
    AEGIS -.-> CR["crewai *(optional)*"]
    AEGIS -.-> OA["openai-agents *(optional)*"]
    AEGIS -.-> AN["anthropic *(optional)*"]
    AEGIS -.-> HX["httpx *(optional)*"]

    style AEGIS fill:#4a90d9,color:#fff
    style YAML fill:#7ed321,color:#fff
```

## Testing Strategy

- Unit tests for core (policy, actions, conditions) — no I/O
- Integration tests for runtime (in-memory SQLite, fake executors)
- Import guard tests for each adapter (verify graceful error without optional deps)
- CLI tests using capsys and tmp_path fixtures
