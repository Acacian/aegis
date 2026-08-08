---
description: "What Aegis 1.0 guarantees: which names are public API, what counts as a breaking change under semver, and which surfaces stay unstable on purpose."
---

# API Stability

Aegis follows [Semantic Versioning](https://semver.org/). From 1.0.0 onward, the
guarantees below are what the major version number is promising. This page is the
definition — if something is not listed as public here, it is not public, no matter
how importable it looks.

## What is public

**1. Everything re-exported from the `aegis` package root.**

```python
import aegis
aegis.__all__   # 161 names — this list is the contract
```

If a name is in `aegis.__all__`, its import path, its call signature, and the
meaning of its return value are stable for the life of 1.x.

**2. The documented modules under [API Reference](index.md).**

`aegis.core.*`, `aegis.runtime.*`, `aegis.guardrails.*`, `aegis.adapters.*` and
`aegis.instrument.*` are public at the module level: the names documented on those
pages keep working, and so do the `patch_*` / `unpatch_*` functions for every
framework listed in the README.

**3. The CLI.**

Every subcommand of `aegis` — its name, its flags, and its exit codes: `init`,
`validate`, `schema`, `simulate`, `score`, `scan`, `diff`, `plan`, `test`, `check`,
`probe`, `autopolicy`, `audit`, `stats`, `monitor`, `compliance`,
`compliance-report`, `regulatory`, `serve`, `proxy`, `uninstall-impact`. Plus the
`aegis-server`, `aegis-mcp-server` and `aegis-mcp-proxy` entry points.

Human-readable output text is not part of the contract; machine-readable output
(`--json`, JSONL exports, SARIF) is.

**4. The policy file format.**

A `version: "1"` policy file that validates today validates against every 1.x
release. New optional keys may be added; existing keys do not change meaning and
are not removed.

**5. The audit record schema and the AGEF event format.**

Fields may be added. Existing fields keep their name, type, and meaning, so a
downstream consumer parsing an audit row today keeps working.

## What is not public

- **Anything with a leading underscore** — modules (`aegis.instrument._langchain`),
  attributes (`DriftDetector._signals`), functions. These move without notice.
  Import them and a patch release can break you.
- **`aegis.server.*` and `aegis.proxy.*` internals.** The HTTP routes are stable;
  the Python classes behind them are not.
- **Guardrail detection contents.** Which specific patterns a guardrail matches,
  and the exact wording of a block reason, change in any release — that is
  security content, not API. What is stable is the *shape*: a blocked result is
  still a blocked result with the same fields.
- **Scores and thresholds.** Justification-gap scoring, drift scores, trust
  scoring and anomaly scores are tuned across minor releases. The types and ranges
  are stable; a specific number for a specific input is not.
- **Anything marked experimental in its own docstring.**

## What counts as a breaking change

Requiring a major version:

- Removing or renaming a name in `aegis.__all__`, or moving it to a different
  import path.
- Removing a parameter, making an optional parameter required, or reordering
  positional parameters on a public callable.
- Narrowing an accepted input type or widening a return type in a way that breaks
  callers.
- Changing a default in a way that makes governance *more permissive* — a default
  that starts blocking something new is a minor release; a default that stops
  blocking something is breaking.
- Removing a CLI command or flag, or changing an exit code's meaning.
- A policy file that was valid becoming invalid.
- Removing a field from an audit record or the AGEF event format.

Not breaking:

- Adding names, parameters with defaults, CLI flags, optional policy keys, or
  audit fields.
- Tightening detection — new injection patterns, new PII categories, new drift
  types. These can change whether your agent's input is blocked, by design.
- Performance changes, log wording, internal refactors.
- Dropping a Python version that has reached end of life.

## Framework adapters

The adapters carry a second kind of compatibility risk that semver does not
describe: upstream frameworks change under us. Aegis patches through each
framework's own hooks, and those hooks move.

The commitment is that the adapter surface — `auto_instrument()`, the per-framework
`patch_*` / `unpatch_*` functions, and the `InstrumentationReport` they return — is
stable API. Which upstream versions those adapters actually work against is
verified daily by the
[integration workflow](https://github.com/Acacian/aegis/blob/main/.github/workflows/integration.yml),
which installs every instrumented framework at its latest release and asserts a
guardrail fires through each one's real entrypoint. When an upstream release breaks
an adapter, that is a bug fixed in a patch release, not a breaking change in Aegis.

A framework that is installed but whose adapter cannot bind reports an error rather
than silently reporting "not installed" — see `InstrumentationReport.errors`.

## Deprecation policy

A public name scheduled for removal emits `DeprecationWarning` for at least one
minor release before it goes, and the CHANGELOG entry names the replacement.
Nothing in `aegis.__all__` is removed inside 1.x.
