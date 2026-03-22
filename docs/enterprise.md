# Enterprise

**Production-grade AI governance for regulated industries.**

Aegis provides the compliance infrastructure that AI-powered enterprises need -- cryptographic audit trails, regulatory mapping, behavioral anomaly detection, and policy-as-code enforcement -- in a single Python library.

---

## Pricing

| | **Community** | **Pro** | **Enterprise** |
|---|:---:|:---:|:---:|
| **Price** | Free | $99 / agent / mo | Custom |
| **License** | MIT | Commercial | Commercial + SLA |
| **Agents** | Unlimited | Unlimited | Unlimited |
| **Policy engine** | Full | Full | Full |
| **Audit logging** | JSONL / SQLite | JSONL / SQLite / Webhook | Custom sinks + S3 archival |
| **Cryptographic audit chain** | SHA-256 | SHA-256 / SHA3-256 | SHA3-256 + HSM integration |
| **Regulatory compliance mapper** | -- | EU AI Act, NIST AI RMF | EU AI Act, NIST, SOC2, ISO 42001 |
| **Compliance report generator** | -- | SOC2, GDPR | SOC2, GDPR + custom templates |
| **Behavioral anomaly detection** | -- | Rate spikes, burst analysis | Full suite + auto policy gen |
| **Policy diff & impact analysis** | -- | `aegis diff` | `aegis diff` + CI/CD integration |
| **Rate limiter** | Per-agent | Per-agent + global | Per-agent + global + custom windows |
| **Agent trust chain** | -- | -- | Hierarchical identity, delegation, cascade revocation |
| **Semantic conditions (LLM evaluator)** | -- | -- | Keyword + pluggable LLM evaluator |
| **Real-time monitoring dashboard** | -- | `aegis monitor` | `aegis monitor` + Grafana export |
| **Webhook notifications** | -- | Slack, PagerDuty | Slack, PagerDuty + custom |
| **Action replay & simulation** | -- | What-if analysis | What-if + batch simulation |
| **GitHub Action CI/CD gate** | Basic | Full | Full + custom gate logic |
| **PolicyBuilder SDK** | Full | Full | Full |
| **Support** | Community (GitHub) | Email, 48h SLA | Dedicated CSM, 4h SLA, Slack channel |
| **SSO / RBAC** | -- | -- | SAML, OIDC, role-based access |
| **Deployment** | Self-hosted | Self-hosted | Self-hosted, private cloud, or managed |

---

## Compliance Coverage

Aegis maps your AI agent operations to the requirements of major regulatory frameworks. Every action, decision, and override is recorded in a cryptographic audit chain that satisfies the evidentiary standards of each framework.

### EU AI Act

Aegis addresses obligations for providers and deployers of high-risk AI systems:

| Article | Requirement | Aegis Capability |
|---|---|---|
| Art. 9 | Risk management system | Risk evaluation pipeline with configurable levels (low / medium / high / critical) |
| Art. 13 | Transparency and information provision | Full audit trail with decision rationale logging |
| Art. 14 | Human oversight | Approval handler framework with human-in-the-loop gates |
| Art. 15 | Accuracy, robustness, cybersecurity | Behavioral anomaly detection and rate limiting |
| Art. 17 | Quality management system | Policy-as-code with version control and diff analysis |
| Art. 26 | Obligations of deployers | Governance runtime that enforces policies before execution |
| Art. 29 | Obligations of users | Action classification and risk-appropriate controls |
| Art. 52 | Transparency obligations | Audit chain export with `--export-chain` and `--evidence` |
| Art. 72 | Monitoring by market surveillance | Compliance report generator for regulatory submissions |
| Annex IV | Technical documentation | Automated documentation from audit logs and policy definitions |

### NIST AI RMF (AI 100-1)

| Function | Category | Aegis Capability |
|---|---|---|
| **Govern** | Policies and processes | YAML policy engine, PolicyBuilder SDK, enterprise tier gating |
| **Govern** | Accountability structures | Agent trust chain with hierarchical identity and delegation |
| **Map** | Context and risk identification | Action classification, risk evaluation pipeline |
| **Map** | Stakeholder engagement | Approval handlers, webhook notifications |
| **Measure** | Analysis and monitoring | Behavioral anomaly detection, real-time dashboard |
| **Measure** | Metrics and evaluation | Compliance report generator, audit chain verification |
| **Manage** | Risk response | Policy enforcement, rate limiting, action blocking |
| **Manage** | Continuous improvement | Policy diff & impact analysis, action replay simulation |

### SOC2 Trust Services Criteria

| Criterion | Description | Aegis Capability |
|---|---|---|
| CC6.1 | Logical and physical access controls | Agent trust chain, enterprise tier gating, RBAC |
| CC6.2 | System credentials and authentication | Agent identity model with delegation tokens |
| CC6.3 | Authorization for access | Policy engine with per-action, per-agent rules |
| CC6.4 | Access review and restriction | Approval handlers, cascade revocation |
| CC6.5 | Account management | Agent lifecycle management, trust chain |
| CC6.6 | Security event logging | Cryptographic audit chain (SHA-256/SHA3-256), tamper-evident logging |

### ISO 42001 (AI Management System)

Aegis supports organizations building an AI management system (AIMS) under ISO 42001 by providing:

- **Policy management**: version-controlled YAML policies with diff and impact analysis
- **Risk assessment**: automated risk classification and evaluation for every agent action
- **Monitoring and measurement**: real-time dashboard, behavioral anomaly detection, compliance reports
- **Evidence collection**: cryptographic audit chain with hash-linked, tamper-evident records
- **Continual improvement**: action replay and simulation for policy refinement

---

## Why Not Build It Internally?

Teams that attempt to build AI governance infrastructure in-house consistently underestimate three requirements:

### 1. Cryptographic Audit Integrity

A compliant audit trail is not a log file. Regulatory frameworks require **tamper-evident** records where any modification to a past entry is detectable. This means:

- Every record must be hash-linked to its predecessor (chain integrity)
- Hash algorithms must meet FIPS 140-2 / FIPS 202 standards (SHA-256, SHA3-256)
- Chain verification must be independently reproducible
- Export formats must satisfy legal evidentiary standards

Aegis implements this as a SHA-256/SHA3-256 hash chain with `aegis audit --verify-chain` for independent verification. Building this correctly -- handling clock skew, concurrent writes, chain forking, and recovery -- typically takes 3-6 months of dedicated engineering.

### 2. Multi-Framework Regulatory Mapping

Each regulatory framework defines different requirements, different evidence standards, and different reporting formats. A single AI agent action may trigger obligations under EU AI Act Article 9 (risk management), NIST Govern (accountability), and SOC2 CC6.6 (event logging) simultaneously.

Aegis maintains these mappings and generates framework-specific compliance reports from the same underlying audit data. Keeping these mappings current as regulations evolve is an ongoing maintenance burden that scales with the number of jurisdictions you operate in.

### 3. Behavioral Anomaly Detection at Scale

Identifying when an AI agent deviates from expected behavior requires statistical baselines, sliding-window analysis, and the ability to generate policy recommendations from detected anomalies. False positives must be low enough that alerts remain actionable.

Aegis provides rate spike detection, burst analysis, new-action flagging, and unusual-target identification out of the box, with automatic policy generation from detected patterns.

### The Build vs. Buy Calculus

| Factor | Build In-House | Aegis |
|---|---|---|
| Time to production | 6-12 months | Same day (`pip install agent-aegis`) |
| Cryptographic chain implementation | 3-6 months | Included, FIPS-compliant |
| Regulatory mapping maintenance | Ongoing, per-framework | Included, continuously updated |
| Anomaly detection tuning | ML/statistics expertise required | Pre-tuned, configurable thresholds |
| Audit preparation | Manual evidence collection | `aegis audit --export-chain --evidence` |
| Framework updates | Track each regulation yourself | Maintained by Aegis team |

---

## Getting Started

=== "Community (Free)"

    ```bash
    pip install agent-aegis
    ```

    Full policy engine, audit logging, and all framework adapters. No registration, no license key, no telemetry.

=== "Pro ($99/agent/mo)"

    ```bash
    pip install agent-aegis[pro]
    ```

    Adds compliance mapper, anomaly detection, monitoring dashboard, webhook notifications, and email support.

=== "Enterprise (Custom)"

    Contact us for agent trust chains, semantic LLM conditions, SSO/RBAC, HSM integration, managed deployment options, and dedicated support.

---

## Contact

**Enterprise inquiries**: [enterprise@aegis.dev](mailto:enterprise@aegis.dev)

**Schedule a demo**: [Book a 30-minute call](https://calendly.com/aegis-enterprise)

**GitHub**: [github.com/Acacian/aegis](https://github.com/Acacian/aegis)

---

<small>
Regulatory references: EU AI Act (Regulation (EU) 2024/1689), NIST AI RMF (AI 100-1, January 2023), SOC2 Trust Services Criteria (AICPA 2017), ISO/IEC 42001:2023. Aegis provides tooling to support compliance; it does not constitute legal advice. Consult qualified legal counsel for regulatory obligations specific to your jurisdiction and use case.
</small>
