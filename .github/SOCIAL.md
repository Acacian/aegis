# Social Media Launch Posts

Ready-to-use posts for promoting Aegis. Copy-paste and adjust as needed.

**Positioning: "The SQLite of AI agent governance"**
- We don't compete with enterprise platforms (JetStream, Galileo). They sell to CISOs.
- We compete with "the 30 lines of if/else developers write themselves."
- Key message: simplest path from zero to governed agent. No infra. Cross-platform.

**GeekNews 가입일:** 2026-03-21 → 작성 가능일: **2026-03-28 이후**

**Launch order:**
1. HN Show HN 먼저 (화~목 한국 밤 10시~자정) → 최적일: 2026-03-24(화) ~ 26(목)
2. Reddit r/Python (HN 반응 보고 1-2일 후)
3. GeekNews 한국어 포스트 (2026-03-28 이후)

---

## Reddit 활용법

신규 계정은 r/Python, r/MachineLearning 같은 큰 서브에서 자동 필터링될 수 있음.

**카르마 쌓기 (HN 포스팅 전까지):**
1. https://reddit.com 가입
2. r/Python, r/MachineLearning, r/LocalLLaMA 구독
3. 다른 사람 글에 유용한 댓글 달기 (하루 2-3개씩)
4. 최소 50~100 카르마 + 계정 나이 7일 이상이면 직접 글 가능

**포스팅 타겟 서브:**
- r/Python (~2M 구독) — 메인 타겟
- r/MachineLearning (~3M) — [P] 태그 필수
- r/LocalLLaMA — AI agent 관심 높음
- r/LangChain — 어댑터 직접 연관

**주의:** 홍보 티 내면 다운보트 + 삭제. "I built X, feedback wanted" 톤이 핵심.

---

## 1. Hacker News

**Title:** Show HN: Aegis -- Add governance to any AI agent in 5 minutes (pip install, YAML policy, done)

**Text:**

Hi HN, I built Aegis because I kept writing the same if/else checks every time I deployed an AI agent.

The pattern is always the same: agent gets tool_use access, you realize it can do dangerous things, you bolt on some permission checks. Then you need approval workflows. Then audit logs. Then you do it again for a different framework.

Aegis replaces all of that with one library:

    pip install agent-aegis

Write a YAML policy:

    rules:
      - name: read_safe
        match: { type: "read*" }
        risk_level: low
        approval: auto
      - name: no_deletes
        match: { type: "delete*" }
        risk_level: critical
        approval: block

Add 3 lines to your agent:

    from aegis import Action, Policy, Runtime
    runtime = Runtime(executor=..., policy=Policy.from_yaml("policy.yaml"))
    result = await runtime.run_one(Action("delete", "crm"))  # → BLOCKED

That's it. No servers to deploy, no Kubernetes, no platform to sign up for.

What you get:
- YAML policy rules with glob matching + smart conditions (time windows, param thresholds, weekday schedules)
- Human approval via Slack, Discord, Telegram, email, webhook, or CLI
- Full audit trail (SQLite + JSONL export + webhook to external SIEM)
- Works across 7 frameworks: LangChain, CrewAI, OpenAI Agents SDK, Anthropic, Playwright, httpx, MCP
- REST API server for non-Python agents: `aegis serve policy.yaml`
- Hot-reload, retry/rollback, dry-run, policy merge
- Also runs as a standalone MCP server (registered on the MCP Server Registry)
- 518 tests, mypy strict, MIT licensed

I know there are enterprise governance platforms out there (Galileo, JetStream, etc.) -- Aegis isn't trying to replace those. They're control planes for large orgs. Aegis is for individual developers and small teams who need governance **now**, without 6 months of procurement.

Think of it as SQLite vs PostgreSQL -- same category, different use case.

I'd love feedback on:
- Is the YAML policy DSL expressive enough?
- Would you actually use this for your agents?
- What's missing?

GitHub: https://github.com/Acacian/aegis
Docs: https://acacian.github.io/aegis/
PyPI: pip install agent-aegis
Try it in your browser: https://acacian.github.io/aegis/playground/

---

## 2. GeekNews (news.hada.io)

**제목:** Aegis - AI 에이전트 거버넌스를 5분 만에 추가하는 Python 라이브러리 (pip install, YAML 정책, 끝)

AI 에이전트를 배포할 때마다 같은 코드를 반복해서 짰습니다: 위험한 액션 체크, 승인 워크플로우, 감사 로그. 프레임워크 바뀔 때마다 다시.

이걸 라이브러리 하나로 바꿨습니다.

```bash
pip install agent-aegis
```

```python
from aegis import Action, Policy, Runtime
runtime = Runtime(executor=my_executor, policy=Policy.from_yaml("policy.yaml"))
result = await runtime.run_one(Action("delete", "crm"))  # → BLOCKED
```

**서버 배포 없음. 쿠버네티스 없음. 벤더 종속 없음.**

주요 특징:
- YAML 정책 파일 (글로브 패턴, 시간/요일/파라미터 조건)
- 4단계 위험 모델 (low/medium/high/critical)
- 승인 게이트: CLI, Slack, Discord, Telegram, Email, Webhook
- 감사 추적: SQLite + JSONL + 웹훅 (SOC2/GDPR 증빙 가능)
- 7개 어댑터: LangChain, CrewAI, OpenAI Agents SDK, Anthropic, Playwright, httpx, MCP
- REST API 서버: Python 외 언어도 HTTP로 거버넌스
- MCP Server Registry 등록 — MCP 클라이언트에서 바로 설치 가능
- 518 테스트, mypy strict

엔터프라이즈 거버넌스 플랫폼(Galileo, JetStream 등)이 있다는 건 알고 있습니다. Aegis는 그런 컨트롤 플레인과 경쟁하려는 게 아닙니다. 개발자가 지금 당장 `pip install` 하나로 거버넌스를 추가하고 싶을 때 쓰는 라이브러리입니다.

SQLite가 PostgreSQL을 대체하지 않듯이, Aegis는 엔터프라이즈 플랫폼을 대체하지 않습니다. 다른 용도입니다.

MIT 라이선스, 오픈소스입니다.

GitHub: https://github.com/Acacian/aegis
PyPI: pip install agent-aegis
문서: https://acacian.github.io/aegis/
브라우저에서 바로 사용: https://acacian.github.io/aegis/playground/

---

## 3. Reddit r/Python

r/Python 필수 포맷: What My Project Does / Target Audience / Comparison 3개 섹션 없으면 자동 삭제됨.

**Title:** I built Aegis -- add governance to any AI agent in 5 minutes (YAML policies, approval gates, audit logs, 7 framework adapters)

**What My Project Does**

Aegis is a Python library that adds governance to AI agent actions. You write YAML rules, Aegis enforces them -- policy checks, human approval gates, and audit logging. No server to deploy, no infrastructure to manage.

3 lines to add governance:
```python
from aegis import Action, Policy, Runtime
runtime = Runtime(executor=your_executor, policy=Policy.from_yaml("policy.yaml"))
result = await runtime.run_one(Action("delete", "crm"))  # → BLOCKED
```

Key features:
- YAML-first policies with glob matching, time windows, param thresholds, weekday schedules
- 4-tier risk model: low (auto) / medium (log) / high (human approval) / critical (block)
- 7 approval handlers: CLI, Slack, Discord, Telegram, email, webhook, custom
- Full audit trail: SQLite + JSONL + webhook to external SIEM
- 7 framework adapters: LangChain, CrewAI, OpenAI Agents SDK, Anthropic Claude, Playwright, httpx, MCP
- REST API server: `aegis serve policy.yaml` for Go/TypeScript/Java agents
- Hot-reload, retry/rollback, dry-run, policy merge
- Also runs as a standalone MCP server (registered on the MCP Server Registry)
- 518 tests, mypy strict, MIT licensed

**Target Audience**

Developers who are already running AI agents and want to add governance without deploying infrastructure:

- You use LangChain/CrewAI/OpenAI and want policy checks on what your agent can do
- Your agent calls multiple providers and you need one unified governance layer
- You need an audit trail for compliance but don't want to set up an enterprise platform
- You're the solo dev or small team who needs this **now**, not after a procurement cycle

**Comparison**

| | Aegis | Platform Guardrails (OpenAI, Google) | Enterprise Platforms (Galileo, JetStream) | DIY if/else |
|---|---|---|---|---|
| **Setup** | `pip install` + YAML | Built into platform | K8s / cloud infra required | None |
| **Cross-platform** | 7 frameworks | Own ecosystem only | Varies | Manual |
| **Human approval** | 7 channels | No | Yes | Build your own |
| **Audit trail** | SQLite + JSONL + webhook | Platform-specific | Yes | printf |
| **Cost** | Free (MIT) | Free with platform | Enterprise pricing | Developer time |
| **Time to integrate** | 5 minutes | Minutes (if you're on that platform) | Weeks-months | Days |

Aegis sits in the middle: more capable than DIY, simpler than enterprise platforms, and works across providers unlike platform-native guardrails.

- GitHub: https://github.com/Acacian/aegis
- PyPI: `pip install agent-aegis`
- Docs: https://acacian.github.io/aegis/

Would love feedback on the policy syntax and whether the comparison makes sense. There are [good first issues](https://github.com/Acacian/aegis/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) if anyone wants to contribute.

---

## 4. Reddit r/MachineLearning

r/MachineLearning 은 [P] 태그 필수 (Project). 3섹션 포맷은 r/Python만 해당.

**Title:** [P] Aegis: The simplest way to add governance to AI agents -- pip install, YAML policy, done

As AI agents get tool_use capabilities across multiple providers, there's a practical problem: how do you enforce consistent policies across LangChain + OpenAI + Anthropic + MCP in one codebase?

Enterprise platforms exist (Galileo Agent Control, JetStream) but they require infrastructure. Platform-native guardrails exist but they're locked to one ecosystem.

**Aegis** is a Python library that sits in the middle:

```bash
pip install agent-aegis
```

1. **EVALUATE** -- match action against YAML policy rules (glob patterns + conditions)
2. **APPROVE** -- auto-execute safe ops, require human approval for risky ones, block dangerous ones
3. **EXECUTE** -- run the action through the adapter
4. **VERIFY** -- post-execution verification hooks
5. **AUDIT** -- log everything to SQLite/JSONL/webhook

Works with 7 frameworks (LangChain, CrewAI, OpenAI Agents SDK, Anthropic Claude, Playwright, httpx, MCP). Also runs as a standalone MCP server (registered on the MCP Server Registry). No servers to deploy. Cross-platform by default.

518 tests, mypy strict.

GitHub: https://github.com/Acacian/aegis
Try it in your browser: https://acacian.github.io/aegis/playground/

Interested in feedback on whether a library-level approach makes sense vs. platform-level governance, and whether the YAML policy DSL is expressive enough for real agent workflows.
