<p align="center">
  <h1 align="center">Agent-Aegis</h1>
  <p align="center">
    <strong>AI 에이전트를 위한 거버넌스 레이어. 하나의 API, 12개 프레임워크, 모든 거버넌스 primitive.</strong>
  </p>
  <p align="center">
    Redis가 인메모리 자료구조를 통합했듯, Aegis는 에이전트 거버넌스를 통합합니다 — 프롬프트 인젝션 차단, PII 마스킹, 정책 집행, 신뢰 위임, 변조 방지 감사를 모든 에이전트 프레임워크에 하나의 런타임으로. 코드 변경 없이.<br/>
    <code>pip install agent-aegis</code> → <code>aegis.auto_instrument()</code> → 12개 프레임워크가 즉시 보호됩니다.
  </p>
</p>

<p align="center">
  <a href="https://www.bestpractices.dev/projects/12253"><img src="https://www.bestpractices.dev/projects/12253/badge" alt="OpenSSF Best Practices"></a>
  <a href="https://github.com/Acacian/aegis/actions/workflows/ci.yml"><img src="https://github.com/Acacian/aegis/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/agent-aegis/"><img src="https://img.shields.io/pypi/v/agent-aegis?color=blue&cacheSeconds=3600" alt="PyPI"></a>
  <a href="https://pypi.org/project/agent-aegis/"><img src="https://img.shields.io/pypi/pyversions/agent-aegis?cacheSeconds=3600" alt="Python"></a>
  <a href="https://github.com/Acacian/aegis/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
  <br/>
  <a href="https://github.com/Acacian/aegis/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/tests-6400%2B_passed-brightgreen" alt="Tests"></a>
  <a href="https://github.com/Acacian/aegis/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/coverage-92%25-brightgreen" alt="Coverage"></a>
  <a href="https://acacian.github.io/aegis/playground/"><img src="https://img.shields.io/badge/playground-브라우저에서_체험-ff6b6b" alt="Playground"></a>
</p>

<p align="center">
  <a href="#aegis란"><strong>Aegis란?</strong></a> &bull;
  <a href="#primitives">Primitives</a> &bull;
  <a href="#frameworks">Frameworks</a> &bull;
  <a href="#use-cases">Use Cases</a> &bull;
  <a href="#30초-시작"><strong>30초 시작</strong></a> &bull;
  <a href="#research">Research</a> &bull;
  <a href="https://acacian.github.io/aegis/">문서</a> &bull;
  <a href="https://acacian.github.io/aegis/playground/"><strong>Playground</strong></a>
</p>

<p align="center">
  <a href="./README.md">English</a> &bull;
  <b>한국어</b>
</p>

---

## Aegis란?

모든 AI 에이전트 프레임워크는 같은 거버넌스 primitive를 재발명합니다 — 그리고 각자 조금씩 다르게 구현합니다. Aegis는 이를 통합하는 추상화 레이어입니다.

| 레이어 | 역할 | 예시 |
|-------|------|------|
| **1. Primitives** | 모든 툴 콜에 대한 통일 계약 | `Action`, `ActionClaim`, `Policy`, `Result`, `DelegationChain`, `AuditEvent` |
| **2. Adapters** | 프레임워크 고유 훅을 통한 자동 계측 | LangChain 콜백, CrewAI `BeforeToolCallHook`, OpenAI Agents tracing, Google ADK `BasePlugin`, MCP 전송 계층, DSPy 모듈, httpx 미들웨어, Playwright 컨텍스트 |
| **3. Governance** | 정책으로 조합 가능한 선언적 primitive | 인젝션 / PII / 유출 / 유해 가드레일, RBAC, rate limit, 비용 예산, 드리프트 탐지, 이상 탐지, 신뢰 위임, justification gap, selection audit, Merkle 감사 체인 |
| **4. Lifecycle** | 하나의 런타임, 에이전트 운영의 전 단계 | Scan → Instrument → Policy CI/CD → Runtime → Proxy → Audit |

```python
import aegis
aegis.auto_instrument()    # 12개 프레임워크 거버닝. 다른 코드 변경 불필요.
```

LangChain 가드레일과 CrewAI 가드레일과 OpenAI 가드레일을 따로 쓰는 게 아니라 — **하나의 `Policy`를 쓰면 모든 프레임워크가 상속**받습니다.

### 기존 가드레일 라이브러리와 다른 점

푸는 문제가 다릅니다. 대부분 텍스트를 다루는 도구입니다. [Guardrails AI](https://github.com/guardrails-ai/guardrails)는 hub의 validator로 모델 출력을 검증하고, [NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails)는 Colang DSL로 대화·툴 정책을 작성합니다. [Snyk Agent Scan](https://github.com/snyk/agent-scan)(Snyk 인수 이후의 Invariant Labs `mcp-scan`)은 MCP 서버와 에이전트 스킬을 알려진 위험 패턴으로 스캔하고 런타임 프록시도 제공합니다. [LLM Guard](https://github.com/protectai/llm-guard)는 입출력 스캐너를 체인으로 엮었지만 2026년 7월 아카이브됐습니다. 이들은 모두 **직접 배선하는** 도구입니다 — 가드를 어디에 둘지 개발자가 정합니다. Aegis는 반대쪽에서 출발합니다. `auto_instrument()`가 이미 설치된 프레임워크를 찾아 그 자리에서 계측하므로, 에이전트 코드를 한 줄도 고치지 않고 하나의 `Policy`가 전부에 적용됩니다. 그리고 집행 대상이 프롬프트가 아니라 **에이전트의 행위**입니다 — 단조 신뢰 제약이 걸린 위임 체인, 에이전트가 선택한 것이 아니라 **배제한 것**에 대한 감사, 선언한 의도와 측정된 영향 사이의 간극, 변조 방지 감사 체인. 전부 결정론적이라 요청 경로에 두 번째 모델이 끼지 않습니다. 배타적 선택이 아닙니다 — semantic·모델 기반 디텍터는 `GuardrailEngine.add()`로 내장 가드레일과 함께 쓸 수 있습니다.

---

## Primitives

모든 adapter가 매핑되는 계약. 프레임워크 독립적으로 설계되었습니다.

| Primitive | 목적 | 모듈 |
|-----------|------|------|
| **`Action`** | 모든 프레임워크의 툴/LLM/HTTP/MCP 호출 통일 표현 | `aegis.core.action` |
| **`ActionClaim`** | 3분할 구조 — Declared(에이전트 작성) / Assessed(Aegis 계산) / Chain(위임) | `aegis.core.action_claim` |
| **`Policy`** | 선언적 YAML 규칙: match → risk → approval (`auto`/`approve`/`block`) | `aegis.core.policy` |
| **`ClaimPolicy`** | 툴 이름이 아닌 6차원 영향 벡터를 평가하는 정책 계층 | `aegis.core.claim_policy` |
| **`Guardrails`** | 인젝션, PII, 프롬프트 유출, 유해성에 대한 결정론적 regex — 콜드 2.65ms / 웜 <1µs | `aegis.guardrails` |
| **`DelegationChain`** | 단조 신뢰 제약(비증가)을 가진 멀티 에이전트 위임 추적 | `aegis.core.agent_identity` |
| **`AuditEvent`** | 변조 방지 append-only 로그, Merkle 체인, SQLite + JSONL + webhook sink | `aegis.core.merkle_audit` |
| **`SelectionAudit`** | 에이전트가 *제외한 것*을 감사 — 표면적 정렬(cosmetic alignment) 탐지 | `aegis.core.selection_audit` |
| **`JustificationGap`** | 6차원 비대칭 스코어링: 에이전트가 영향을 선언, Aegis가 독립 평가, 갭이 에스컬레이션 유발 | `aegis.core.justification_gap` |
| **`CryptoAuditChain`** | 장기 컴플라이언스 증거를 위한 Ed25519 서명 체인 | `aegis.core.crypto_audit` |

Aegis의 모든 거버넌스 기능 — 이상 탐지, 비용 예산, 드리프트, 연쇄 가드, 킬스위치 — 는 이 primitive들의 **조합**입니다. 자세한 내용은 [Concepts 가이드](https://acacian.github.io/aegis/getting-started/concepts/)를 참조하세요.

---

## Frameworks

하나의 API. 12개 에이전트 프레임워크 + 3개 프로토콜 레벨 adapter.

| 프레임워크 | 훅 | 통합 방식 |
|-----------|-----|----------|
| **Google ADK** | `BasePlugin` 라이프사이클 (툴 호출, 에이전트 라우팅, 세션) | **네이티브** — 패치는 플러그인 설치용 |
| **CrewAI** | global `BeforeToolCallHook`, `Crew.kickoff/kickoff_async` | **하이브리드** — 툴 콜은 네이티브 훅, crew 진입은 패치 |
| **Pydantic AI** | `AbstractCapability` · `Agent.run/run_sync` | **네이티브**(선택) · 패치(자동) |
| **OpenAI Agents SDK** | `tool_input_guardrail`/`tool_output_guardrail` · `Runner.run/run_sync` | **네이티브**(선택) · 패치(자동) |
| **LangChain** | `BaseChatModel.invoke/ainvoke`, `BaseTool.invoke/ainvoke` | 패치 |
| **OpenAI API** | `Completions.create` (chat & completions) | 패치 |
| **Anthropic API** | `Messages.create` | 패치 |
| **LiteLLM** | `completion`, `acompletion` | 패치 |
| **Google GenAI** | `Models.generate_content` (신/구) | 패치 |
| **LlamaIndex** | 모든 구체 서브클래스의 `LLM.chat/achat/complete/acomplete`, `BaseQueryEngine.query/aquery` | 패치 |
| **Instructor** | `Instructor.create`, `AsyncInstructor.create` | 패치 |
| **DSPy** | `Module.__call__`, `LM.forward/aforward` | 패치 |
| **MCP** | 임의의 MCP 서버를 위한 전송 계층 프록시 (stdio / HTTP) | 프록시 — 패치 없음 |
| **httpx** | 원시 HTTP 이그레스용 `HttpxExecutor` (REST 에이전트, 웹훅) | 래퍼 — 패치 없음 |
| **Playwright** | 브라우징 에이전트용 `PlaywrightExecutor` | 래퍼 — 패치 없음 |

`auto_instrument()`는 설치된 프레임워크만 감지해 패치합니다 — 하드 의존성 없음. [커스텀 adapter](https://acacian.github.io/aegis/guides/custom-adapters/)는 동일한 `BaseAdapter` 인터페이스를 사용합니다. 위 adapter는 전부 [통합 워크플로](.github/workflows/integration.yml)가 매일 최신 업스트림 릴리스에 대해 실제 진입점을 호출하고 가드레일 발화를 검증합니다 — 유닛 테스트는 프레임워크를 가짜로 대체하므로 업스트림 드리프트를 스스로 볼 수 없습니다.

**통합 정책.** **실제로 차단할 수 있는** 네이티브 확장 지점이 있으면 항상 그쪽을 씁니다. Google ADK의 `BasePlugin`과 CrewAI의 `BeforeToolCallHook`이 그런 경우고, 이때 `auto_instrument()`는 네이티브 객체를 설치할 만큼만 패치합니다. Pydantic AI와 OpenAI Agents SDK는 선택형 네이티브 구현(`AbstractCapability`, `tool_input_guardrail`)과 무코드용 패치 경로를 함께 제공합니다. 나머지는 차단 가능한 훅이 없어서 패치합니다 — 원시 OpenAI/Anthropic SDK와 DSPy는 훅 자체가 없고, LlamaIndex의 instrumentation dispatcher는 이벤트는 쏘지만 핸들러 예외를 삼켜서 관측만 되고 집행이 안 됩니다.

이 정책을 문서화하게 된 계기가 Pydantic AI입니다. 원래 monkey-patch였는데 코어 메인테이너 DouweM의 리뷰 — *"It doesn't look like those features are actually exposed as Pydantic AI capabilities?"* — 를 받고 네이티브 확장 API 위에 다시 만들었습니다 ([`src/aegis/contrib/pydantic_ai.py`](src/aegis/contrib/pydantic_ai.py), 리뷰 기록은 [pydantic-ai#4888](https://github.com/pydantic/pydantic-ai/pull/4888)).

패치는 선호가 아니라 **최후 수단**입니다. 업스트림 변화에 가장 노출된 부분이고, 통합 워크플로가 존재하는 이유가 그것입니다.

### 기본 가드레일

| 가드레일 | 기본 동작 | 탐지 대상 |
|---------|---------|----------|
| **프롬프트 인젝션** | 차단 | 13개 공격 카테고리, 109개 패턴, 9개 언어 (EN/KO/ZH/JA/ES/DE/FR/TH/VI) |
| **PII 탐지** | 경고 | 13개 카테고리 (이메일, 신용카드, SSN, IBAN, API 키 등) |
| **프롬프트 유출** | 경고 | 시스템 프롬프트 추출 시도 |
| **유해 콘텐츠** | 경고 | 유해, 폭력적, 학대적 콘텐츠 |
| **MCP STDIO 인젝션** | 차단 | JSON-RPC 삽입, 프레임 연결 공격, 유니코드 이스케이프 우회 ([OX Security 어드바이저리](https://www.oxsecurity.io/blog/mcp-security-research)) |

결정론적 regex — LLM 호출 없음, 네트워크 없음. **콜드 2.65ms / 웜 <1µs**.

---

## Use Cases

동일한 primitive, 네 가지 진입점. 워크플로우에 맞는 것을 선택하세요.

### 1. 런타임 보호 (가장 흔함)

한 줄. 어떤 프레임워크든.

```python
import aegis
aegis.auto_instrument()
```

또는 코드 변경 제로 — `AEGIS_INSTRUMENT=1 python my_agent.py`. 인젝션 차단, PII 마스킹, 프롬프트 유출 경고, 감사 추적, 정책 집행이 모든 LangChain / CrewAI / OpenAI / Anthropic / LiteLLM / ADK / DSPy / LlamaIndex / Pydantic AI 호출에 즉시 적용됩니다.

**Pydantic AI 네이티브 capability** — 몽키패칭 없이 에이전트별 명시적 제어:

```python
from pydantic_ai import Agent
from aegis.contrib.pydantic_ai import AegisCapability

agent = Agent(
    "openai:gpt-4o-mini",
    capabilities=[AegisCapability.default()],  # injection, PII, toxicity, prompt-leak, hallucination
)
result = await agent.run("What is AI governance?")
```

[Pydantic AI 통합 가이드 →](https://acacian.github.io/aegis/cookbook/pydantic-ai-governance/)

### 2. 프로덕션 전 스캔

배포 전에 보호되지 않은 AI 호출을 찾습니다.

```bash
pip install agent-aegis
aegis scan .
```

```
Aegis Governance Scan
=====================
Scanned: 47 files in ./src

Found 5 ungoverned tool call(s):
  agent.py:12   OpenAI        function call with tools= — no governance wrapper  [ASI02]
  tools.py:8    LangChain     @tool "search_db" — no policy check  [ASI02]
  llm.py:21     LiteLLM       litellm.completion() — no governance wrapper  [ASI02]
  run.py:5      subprocess    subprocess.run — direct shell execution  [ASI08]
  api.py:14     HTTP          requests.post — raw HTTP in agent code  [ASI07]

Governance Score: D (5 ungoverned call(s))
```

`--format json|sarif|suggest`, `--threshold A-F`, `.aegisscanignore`, 인라인 `# aegis: ignore` 프라그마 지원. `aegis scan --fix`로 자동 수정.

### 3. 정책 CI/CD

보안 도구는 런타임을 보호합니다. Aegis는 *또한* 정책 생명주기를 관리합니다 — 코드를 테스트하고 배포하는 것과 같은 방식으로.

```bash
aegis plan current.yaml proposed.yaml --audit-db aegis_audit.db

# Policy Impact Analysis
#   Rules: 2 added, 1 removed, 3 modified
#   Impact (replayed 1,247 actions):
#     23 actions would change from AUTO → BLOCK
```

```bash
aegis test policy.yaml tests.yaml                      # CI에서 실행
aegis test policy.yaml --generate                      # 테스트 자동 생성
aegis test new.yaml tests.yaml --regression old.yaml   # 회귀 검사
```

```yaml
# .github/workflows/policy-check.yml
- uses: Acacian/aegis@main
  with:
    policy: aegis.yaml
    tests: tests.yaml
    fail-on-regression: true
```

또는 PR 시점에 보호되지 않은 호출을 차단:

```yaml
- uses: Acacian/aegis@v1.0.0
  with:
    command: scan
    fail-on-ungoverned: true
```

### 4. 감사 & 컴플라이언스

모든 호출은 변조 방지 Merkle 체인에 기록되며, EU AI Act / NIST AI RMF / SOC2 매핑이 내장되어 있습니다.

```bash
aegis audit
```

```
  ID  Session       Action        Target   Risk      Decision    Result
  1   a1b2c3d4...   read          crm      LOW       auto        success
  2   a1b2c3d4...   bulk_update   crm      HIGH      approved    success
  3   a1b2c3d4...   delete        crm      CRITICAL  block       blocked
```

SQLite + JSONL + webhook sink. 장기 증거를 위한 Ed25519 서명. [Compliance 가이드](https://acacian.github.io/aegis/api/compliance/) 참조.

---

## 30초 시작

```bash
pip install agent-aegis
```

```python
import aegis
aegis.auto_instrument()
# 12개 프레임워크가 기본 가드레일로 즉시 보호됩니다.
```

또는 YAML 정책으로 세밀한 제어:

```bash
aegis init  # aegis.yaml 생성
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

---

## 설치 옵션

```bash
pip install agent-aegis                   # 코어 (12개 프레임워크 자동 계측 포함)
pip install langchain-aegis               # LangChain 독립 통합
pip install 'agent-aegis[mcp]'            # MCP 서버 + 프록시
pip install 'agent-aegis[server]'         # REST API + 대시보드
pip install 'agent-aegis[all]'            # 전부
```

### MCP 프록시 — 코드 변경 없이 MCP 서버 보호

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

Claude Desktop, Cursor, VS Code, Windsurf에서 사용 가능. STDIO 인젝션 방어, 툴 포이즈닝 탐지, 러그풀 탐지, 인자 살균, 정책 평가, 전체 감사 추적.

---

## 왜 Aegis인가?

| | 직접 구현 | 플랫폼 가드레일 | 엔터프라이즈 플랫폼 | **Aegis** |
|---|---|---|---|---|
| **추상화 수준** | 프레임워크별 if/else | 단일 벤더 SDK | 독점 게이트웨이 | **12개 프레임워크의 통일 primitive** |
| **설정** | if/else 며칠 | 벤더별 설정 | K8s + 구매 프로세스 | **`pip install` + 한 줄** |
| **코드 변경** | 모든 호출 래핑 | SDK별 통합 | 수개월 통합 | **제로 — 런타임 자동 계측** |
| **정책 이식성** | 프레임워크별 재작성 | 생태계에 종속 | 보통 단일 벤더 | **하나의 YAML 정책, 모든 프레임워크** |
| **거버넌스 primitive** | 처음부터 구현 | 부분집합, 벤더 정의 | 독점 | **10개 이상의 조합 가능 primitive** |
| **정책 CI/CD** | 없음 | 없음 | 없음 | **`aegis plan` + `aegis test`** |
| **감사 추적** | printf 디버깅 | 플랫폼 로그만 | 클라우드 대시보드 | **SQLite + JSONL + 웹훅 + Merkle 체인** |
| **컴플라이언스** | 수동 문서화 | 없음 | 엔터프라이즈 영업 | **EU AI Act, NIST, SOC2 내장** |
| **비용** | 엔지니어링 시간 | 무료~$$$ | $$$$ + 인프라 | **무료 (MIT). 영원히.** |

### Aegis만의 차별점

다른 도구는 입출력을 검사합니다. Aegis는 *결정 자체*를 거버닝합니다 — 다른 거버넌스 런타임에 없는 primitive로.

| 기능 | 의미 | 근거 |
|---|---|---|
| **3분할 ActionClaim** | 모든 툴 콜이 Declared(에이전트 작성, 비신뢰), Assessed(Aegis 계산), Chain(위임) 필드로 분리. 이 구조적 분리가 표면적 정렬(cosmetic alignment)을 탐지 가능하게 합니다. | [14,285개 tau-bench 호출에 대한 Justification Gap 측정](https://acacian.github.io/aegis/research/tripartite-action-claim/) |
| **Justification Gap** | 6차원 비대칭 스코어링: 에이전트가 영향을 선언, Aegis가 독립 평가, `per_dim = max(0, assessed − declared)`. 과소 보고 시 에스컬레이션(>0.15) 또는 차단(>0.40). | "ActionClaim" 이름은 [COA-MAS (Carvalho)](https://arxiv.org/abs/2401.05064); 6D 메트릭 + 런타임 형식은 원작 |
| **Selection Governance** | 에이전트가 *제외한 것*을 감사합니다. 위험한 옵션을 "도움이 되려고" 빼는 모델은 선택 권력을 행사하는 것 — Aegis가 이를 탐지합니다. | [Santander et al., arXiv:2602.14606](https://arxiv.org/abs/2602.14606) |
| **단조 신뢰 제약** | 위임된 에이전트는 자기 권한을 상승시킬 수 없습니다. 체인을 따라 신뢰 수준은 비증가 — 위반 시 자동 차단. | 격자 기반 접근 제어 |
| **풀 라이프사이클** | Scan(탐지) → Instrument(보호) → Policy CI/CD(테스트) → Runtime(거버닝) → Proxy(게이트웨이) → Audit(추적). 라이브러리 하나, `pip install` 한 번. | — |

---

## Research

공개 에이전트 트레이스 데이터셋에 대한 원저 측정. stdlib만 사용, 30초 안에 재현 가능.

- [**14,285개 Tau-Bench 툴 콜의 Justification Gap**](https://acacian.github.io/aegis/research/tripartite-action-claim/) — 3분할 ActionClaim의 형식 정의와 silent-baseline 실증 연구. 네 가지 model:domain 그룹에서 approve 90.3% / escalate 9.7% / block 0%. airline 도메인이 retail 대비 평균 갭 약 2배. 세 가지 구조 불변량의 건전성 스케치와 연구 중 발견한 `max`-only override 한계에 대한 솔직한 기록 포함.
- [**1,960개 Tau-Bench 궤적의 툴 분포 드리프트**](https://acacian.github.io/aegis/research/tau-bench-tool-distribution-drift/) — GPT-4o와 Sonnet 3.5 New의 툴 이름 시퀀스에 대한 Shannon 엔트로피. 점수화된 궤적의 39.8%가 종료 시점에 한두 개 툴로 붕괴. 쌍봉 분포, 모델 간 1.7배 격차. 모든 스크립트와 원시 데이터 포함.

자신의 트레이스에 동일한 신호 실행:

```bash
aegis check drift --trace path/to/trace.jsonl
```

CLI는 `tool_name` 필드만 읽습니다 — args, CoT, prompt는 절대 읽지 않으므로 엔터프라이즈 사용자가 PII 유출 없이 프로덕션 트레이스를 점수화할 수 있습니다.

공개 에이전트 레포 39개를 `aegis scan`으로 훑어 거버넌스 상태를 채점하기도 했습니다 — [92%가 F를 받았습니다](https://acacian.github.io/aegis/playground/scan-report.html). 특정 프로젝트가 아니라 생태계 전반에 대한 관찰입니다. 대부분의 에이전트 코드에는 툴 콜 정책이 아예 없습니다.

---

## CLI

```bash
aegis scan ./src/                       # 보호되지 않은 AI 호출 탐지
aegis score ./src/ --policy policy.yaml # 거버넌스 점수 (0-100)
aegis init                              # 시작 정책 생성
aegis validate policy.yaml              # 문법 검증
aegis plan current.yaml proposed.yaml   # 정책 변경 미리보기
aegis test policy.yaml tests.yaml       # 정책 회귀 테스트
aegis audit                             # 감사 로그 조회
aegis serve policy.yaml                 # REST API + 대시보드
aegis probe policy.yaml                 # 적대적 정책 테스트
aegis autopolicy "삭제 차단"             # 자연어 → YAML
```

## 문서

전체 문서: **[acacian.github.io/aegis](https://acacian.github.io/aegis/)**

- [통합 가이드](https://acacian.github.io/aegis/) — LangChain, CrewAI, OpenAI, MCP 등
- [정책 레퍼런스](https://acacian.github.io/aegis/) — 조건, 템플릿, 베스트 프랙티스
- [보안 기능](https://acacian.github.io/aegis/) — 가드레일, 이상 탐지, 컴플라이언스
- [API 안정성](https://acacian.github.io/aegis/api/stability/) — 1.x가 보장하는 범위와 breaking change의 정의
- [아키텍처](ARCHITECTURE.md) — 코드베이스 구조
- [인터랙티브 Playground](https://acacian.github.io/aegis/playground/) — 브라우저에서 체험

## 기여

```bash
git clone https://github.com/Acacian/aegis.git && cd aegis
make dev      # 의존성 + 훅 설치
make test     # 테스트 실행
make lint     # 린트 + 포맷 검사
```

[기여 가이드](CONTRIBUTING.md) &bull; [Good First Issues](https://github.com/Acacian/aegis/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) &bull; [![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/Acacian/aegis)

## 라이선스

MIT -- [LICENSE](LICENSE) 참조.

Copyright (c) 2026 구동하 (Dongha Koo, [@Acacian](https://github.com/Acacian)). Created March 21, 2026.

---

<p align="center">
  <sub>AI 에이전트를 위한 거버넌스 레이어. 하나의 API, 12개 프레임워크, 모든 거버넌스 primitive.</sub><br/>
  <sub>Aegis가 도움이 되셨다면, 스타를 눌러주세요 — 다른 사람들이 찾는 데 도움이 됩니다.</sub>
</p>
