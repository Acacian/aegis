<p align="center">
  <h1 align="center">Aegis</h1>
  <p align="center">
    <strong>AI 에이전트 거버넌스를 가장 단순하게. 인프라 불필요. 벤더 종속 없음. 순수 Python.</strong>
  </p>
  <p align="center">
    <code>pip install agent-aegis</code> &#8594; YAML 정책 &#8594; 5분 만에 거버넌스 적용.<br/>
    <strong>LangChain, CrewAI, OpenAI, Anthropic, MCP 등 7개 프레임워크 지원.</strong>
  </p>
</p>

<p align="center">
  <a href="https://github.com/Acacian/aegis/actions/workflows/ci.yml"><img src="https://github.com/Acacian/aegis/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/agent-aegis/"><img src="https://img.shields.io/pypi/v/agent-aegis?color=blue&cacheSeconds=3600" alt="PyPI"></a>
  <a href="https://pypi.org/project/agent-aegis/"><img src="https://img.shields.io/pypi/pyversions/agent-aegis?cacheSeconds=3600" alt="Python"></a>
  <a href="https://github.com/Acacian/aegis/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
  <a href="https://acacian.github.io/aegis/"><img src="https://img.shields.io/badge/docs-acacian.github.io%2Faegis-blue" alt="Docs"></a>
  <a href="https://pypi.org/project/agent-aegis/"><img src="https://img.shields.io/pypi/dm/agent-aegis?label=downloads&color=brightgreen" alt="Downloads"></a>
  <a href="https://github.com/Acacian/aegis"><img src="https://img.shields.io/github/stars/Acacian/aegis?style=social" alt="GitHub stars"></a>
  <br/>
  <a href="https://pypi.org/project/langchain-aegis/"><img src="https://img.shields.io/pypi/v/langchain-aegis?label=langchain-aegis&color=blue&cacheSeconds=3600" alt="langchain-aegis"></a>
  <a href="https://github.com/Acacian/aegis/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/tests-2238_passed-brightgreen" alt="Tests"></a>
  <a href="https://github.com/Acacian/aegis/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/coverage-92%25-brightgreen" alt="Coverage"></a>
  <a href="https://acacian.github.io/aegis/playground/"><img src="https://img.shields.io/badge/playground-브라우저에서_체험-ff6b6b" alt="Playground"></a>
</p>

<p align="center">
  <a href="https://acacian.github.io/aegis/playground/"><strong>브라우저에서 바로 체험하기</strong></a> &bull;
  <a href="#빠른-시작">빠른 시작</a> &bull;
  <a href="#작동-방식">작동 방식</a> &bull;
  <a href="https://acacian.github.io/aegis/">문서</a> &bull;
  <a href="#통합">통합</a> &bull;
  <a href="https://github.com/Acacian/aegis/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22">기여하기</a>
</p>

<p align="center">
  <a href="./README.md">English</a> &bull;
  <b>한국어</b>
</p>

---

## Aegis 없이 vs. Aegis로

**Aegis 없이** — if/else 흩뿌리기, 감사 추적 없음, 툴 추가할 때마다 수정:

```python
async def handle_agent_action(tool_name, args):
    if tool_name == "delete_users":
        raise Exception("Blocked")                              # 깨지기 쉬움
    if tool_name.startswith("bulk_") and args.get("count", 0) > 100:
        approved = await ask_slack_approval(tool_name, args)     # 툴마다 커스텀
        if not approved:
            raise Exception("Denied")
    if tool_name == "deploy" and datetime.now().hour >= 18:
        raise Exception("No deploys after hours")               # 하드코딩
    result = await execute(tool_name, args)
    # 감사 로그 없음. 일관성 없음. 에이전트/프레임워크마다 반복.
    return result
```

**Aegis로** — YAML 파일 하나로 전체 거버넌스, 감사 추적과 승인 게이트 내장:

```yaml
# policy.yaml
rules:
  - name: block_deletes
    match: { type: "delete*" }
    approval: block

  - name: bulk_approval
    match: { type: "bulk_*" }
    conditions: { param_gt: { count: 100 } }
    approval: approve          # Slack, CLI, Discord 등으로 사람에게 물어봄

  - name: no_after_hours
    match: { type: "deploy*" }
    conditions: { time_after: "18:00" }
    approval: block
```

```python
from aegis import Policy, Runtime

runtime = Runtime(executor=my_executor, policy=Policy.from_yaml("policy.yaml"))
result = await runtime.run_one(action)  # 정책 체크 + 승인 + 감사 — 끝.
```

**`pip install` 하나. YAML 파일 하나. LangChain, CrewAI, OpenAI, Anthropic, MCP 전부 지원.** 감사 추적, 사람 승인 게이트, 규제 컴플라이언스까지 — 서버 배포 없이.

**복사 → 붙여넣기 → 실행 — 설정 파일 없이 바로 동작:**

```python
from aegis import Action, Policy

policy = Policy.from_dict({
    "version": "1",
    "defaults": {"risk_level": "low", "approval": "auto"},
    "rules": [{"name": "block_delete", "match": {"type": "delete_*"},
               "risk_level": "critical", "approval": "block"}]
})

safe = policy.evaluate(Action(type="read_users", target="db"))
print(safe.approval)   # Approval.AUTO  ✅

danger = policy.evaluate(Action(type="delete_users", target="db"))
print(danger.approval)  # Approval.BLOCK 🚫
```

YAML 파일 사용 시 — **3줄:**

```python
from aegis import Action, Policy, Runtime

runtime = Runtime(executor=your_executor, policy=Policy.from_yaml("policy.yaml"))
results = await runtime.run_one(Action("write", "salesforce", params={...}))
```

**서버 배포 불필요. 쿠버네티스 불필요. 벤더 종속 없음.** `pip install` 하나, YAML 파일 하나면 정책 체크 + 사람 승인 게이트 + 완전한 감사 추적이 모든 AI 프로바이더에 걸쳐 동작합니다.

## 작동 방식

### 핵심 개념

Aegis는 3가지 핵심 요소로 구성됩니다:

| 개념 | 역할 | 사용자가 할 일 |
|------|------|-------------|
| **Policy** | 어떤 액션을 허용/승인/차단할지 정의하는 YAML 규칙 | 규칙 작성 |
| **Executor** | 실제로 무언가를 수행하는 어댑터 (API 호출, 버튼 클릭, 쿼리 실행 등) | 기본 제공 어댑터 사용 또는 직접 구현 |
| **Runtime** | Policy + Executor를 연결하는 엔진. 규칙 평가, 승인 게이트, 실행, 로깅을 처리 | 생성 후 `run_one()` 또는 `plan()` + `execute()` 호출 |

### 파이프라인

모든 액션은 5단계를 거칩니다. `runtime.run_one(action)` 한 번이면 자동 처리:

```
1. 평가(EVALUATE)    정책 규칙과 대조 (글로브 패턴 매칭)
                     → PolicyDecision: 위험 수준 + 승인 요구 사항 + 매칭된 규칙

2. 승인(APPROVE)     결정에 따라:
                     - auto:    즉시 진행 (저위험 액션)
                     - approve: 사람에게 확인 요청 (CLI, Slack, Discord, Telegram, 웹훅, 이메일)
                     - block:   즉시 거부 (위험한 액션)

3. 실행(EXECUTE)     Executor가 액션 수행.
                     기본 제공: Playwright(브라우저), httpx(HTTP), LangChain, CrewAI, OpenAI, Anthropic, MCP
                     커스텀: BaseExecutor 상속 (10줄)

4. 검증(VERIFY)      선택적 실행 후 검증 (executor.verify() 오버라이드)

5. 감사(AUDIT)       모든 결정과 결과가 SQLite에 자동 기록.
                     내보내기: JSONL, 웹훅, CLI/API로 조회 가능.
```

### 두 가지 사용 방법

**방법 A: Python 라이브러리 (가장 일반적)** -- 서버 불필요.

에이전트 코드에 Aegis를 임포트합니다. 같은 프로세스에서 실행됩니다.

```python
runtime = Runtime(executor=MyExecutor(), policy=Policy.from_yaml("policy.yaml"))
result = await runtime.run_one(Action("read", "crm"))
```

**방법 B: REST API 서버** -- Python 이외의 에이전트용 (Go, TypeScript 등).

```bash
pip install 'agent-aegis[server]'
aegis serve policy.yaml --port 8000
```

```bash
curl -X POST localhost:8000/api/v1/evaluate \
  -d '{"action_type": "delete", "target": "db"}'
# => {"risk_level": "CRITICAL", "approval": "block", "is_allowed": false}
```

### 승인 핸들러

정책 규칙이 `approval: approve`를 요구할 때, Aegis가 사람에게 확인을 요청합니다:

| 핸들러 | 작동 방식 | 상태 |
|--------|----------|------|
| **CLI** (기본값) | 터미널 Y/N 프롬프트 | Stable |
| **Slack** | Block Kit 메시지 전송, 스레드 답글 폴링 | Stable |
| **Discord** | 리치 Embed 전송, 콜백 폴링 | Stable |
| **Telegram** | 인라인 키보드 버튼, getUpdates 폴링 | Stable |
| **Webhook** | 임의 URL에 POST, 응답 확인 | Stable |
| **Email** | SMTP로 승인 요청 전송, 메일함 폴링 | Beta |
| **Auto** | 전부 자동 승인 (테스트/서버 모드용) | Stable |
| **Custom** | `ApprovalHandler`를 상속해 직접 구현 | Stable |

### 감사 추적

모든 액션이 로컬 SQLite에 자동 기록됩니다. 별도 설정 불필요.

```bash
aegis audit                              # 전체 조회
aegis audit --risk-level HIGH            # 위험도별 필터
aegis audit --tail                       # 실시간 모니터링 (1초 폴링)
aegis stats                              # 규칙별 통계
aegis audit --format jsonl -o export.jsonl  # 내보내기
```

---

## 빠른 시작

```bash
pip install agent-aegis
```

### 1. 정책 생성

```bash
aegis init  # 기본 정책 파일 policy.yaml 생성
```

```yaml
# policy.yaml
version: "1"
defaults:
  risk_level: medium
  approval: approve

rules:
  - name: read_safe
    match: { type: "read*" }
    risk_level: low
    approval: auto

  - name: bulk_ops_need_approval
    match: { type: "bulk_*" }
    conditions:
      param_gt: { count: 100 }  # count > 100일 때만
    risk_level: high
    approval: approve

  - name: no_deletes
    match: { type: "delete*" }
    risk_level: critical
    approval: block
```

### 2. 에이전트에 추가

```python
import asyncio
from aegis import Action, Policy, Runtime
from aegis.adapters.base import BaseExecutor
from aegis.core.result import Result, ResultStatus

class MyExecutor(BaseExecutor):
    async def execute(self, action):
        print(f"  실행 중: {action.type} -> {action.target}")
        return Result(action=action, status=ResultStatus.SUCCESS)

async def main():
    async with Runtime(
        executor=MyExecutor(),
        policy=Policy.from_yaml("policy.yaml"),
    ) as runtime:
        plan = runtime.plan([
            Action("read", "crm", description="연락처 조회"),
            Action("bulk_update", "crm", params={"count": 150}),
            Action("delete", "crm", description="테이블 삭제"),
        ])
        print(plan.summary())
        results = await runtime.execute(plan)

asyncio.run(main())
```

### 3. 감사 로그 확인

```bash
aegis audit
```
```
  ID  Session       Action        Target   Risk      Decision    Result
  1   a1b2c3d4...   read          crm      LOW       auto        success
  2   a1b2c3d4...   bulk_update   crm      HIGH      approved    success
  3   a1b2c3d4...   delete        crm      CRITICAL  block       blocked
```

## 주요 기능

| 기능 | 설명 |
|------|------|
| **YAML 정책** | 글로브 매칭, 첫 매치 우선, JSON Schema 검증 |
| **스마트 조건** | `time_after`, `time_before`, `weekdays`, `param_gt/lt/eq/contains/matches` |
| **시맨틱 조건** | 2단계 아키텍처: 내장 키워드 매칭 + 플러그형 LLM 평가기 프로토콜 |
| **4단계 위험 모델** | `low` / `medium` / `high` / `critical` (규칙별 오버라이드) |
| **승인 게이트** | CLI, Slack, Discord, Telegram, 이메일, 웹훅, 또는 커스텀 |
| **감사 추적** | SQLite, JSONL 내보내기, Python `logging`, 또는 외부 SIEM 웹훅 |
| **행동 이상 탐지** | 에이전트별 행동 프로필 학습, 속도 급증/버스트/새로운 액션/비정상 타겟 감지 |
| **컴플라이언스 리포트** | 감사 로그에서 SOC2/GDPR/거버넌스 보고서 생성, 점수화 |
| **정책 비교 & 영향 분석** | 정책 비교, 액션 리플레이, 규칙 변경 영향도 분석 |
| **에이전트 신뢰 체인** | 계층적 에이전트 ID, 위임(교집합 의미론), 연쇄 폐기 |
| **`aegis scan`** | AST 기반 정적 분석 -- 코드베이스에서 거버넌스 미적용 AI 도구 호출 탐지 |
| **`aegis score`** | 거버넌스 점수 (0-100) + shields.io 배지 생성 |
| **REST API 서버** | `aegis serve policy.yaml` -- 모든 언어에서 HTTP로 거버넌스 |
| **MCP 어댑터** | Model Context Protocol 도구 호출 거버넌스 |
| **MCP 공급망 보안** | 툴 포이즈닝 탐지 (10 패턴), 러그풀 감지 (SHA-256), 인자 새니타이징, 신뢰 점수 (L0-L4) |
| **MCP 취약점 DB** | 8개 빌트인 CVE, 버전 매칭, 자동 차단 권고 |
| **MCP SBOM 생성** | CycloneDX-inspired BOM, 도구 해시, 취약점 오버레이, JSON 내보내기 |
| **비용 차단기** | 17개 모델 가격표, 루프 탐지, 계층적 예산, 스레드 안전 |
| **크로스-프레임워크 비용 추적** | LangChain + OpenAI + Anthropic + Google → 통합 CostTracker |
| **멀티에이전트 비용 귀속** | 위임 트리, 서브트리 비용 롤업, 귀속 리포트 |
| **A2A 통신 거버넌스** | 케이퍼빌리티 기반 메시징, PII/크레덴셜 자동 삭제, 레이트 리밋, 감사 로그 |
| **정책 Git 통합** | Diff 포맷팅, 영향 분석, 드리프트 감지, YAML 내보내기 |
| **OpenTelemetry 내보내기** | 정책/비용/이상/MCP 이벤트 → OTel 스팬, 인메모리 폴백 |
| **세션 리플레이** | 에이전트 세션 녹화/재생 + 20개 패턴 소급 보안 스캔 |
| **재시도 & 롤백** | 지수 백오프, 에러 필터, 실패 시 자동 롤백 |
| **드라이런 & 시뮬레이션** | 실행 없이 정책 테스트: `aegis simulate policy.yaml read:crm` |
| **핫 리로드** | `runtime.update_policy(...)` -- 재시작 없이 정책 교체 |
| **정책 병합** | `Policy.from_yaml_files("base.yaml", "prod.yaml")` -- 설정 레이어링 |
| **런타임 훅** | `on_decision`, `on_approval`, `on_execute` 비동기 콜백 |
| **타입 안전** | `mypy --strict` 완전 통과, `py.typed` 마커 |

## 실전 사용 사례

| 시나리오 | 정책 | 결과 |
|----------|------|------|
| **금융** | $10K 초과 대량 이체는 CFO 승인 필요 | 에이전트가 안전하게 청구서 처리, 큰 금액은 Slack 승인 트리거 |
| **SaaS 운영** | 읽기 자동 승인, 계정 변경은 승인 필요 | 지원 에이전트가 실수로 계정 삭제 불가 |
| **DevOps** | 배포는 월-금 9-5시만 허용, 시간 외 차단 | CI/CD 에이전트가 새벽 3시 프로덕션 푸시 불가 |
| **데이터 파이프라인** | 프로덕션 테이블 DELETE 차단, 스테이징은 자동 승인 | ETL 에이전트가 프로덕션 데이터를 드롭할 수 없음 |
| **컴플라이언스** | 모든 외부 API 호출을 전체 컨텍스트와 함께 로깅 | SOC2 / GDPR 증빙을 위한 완전한 감사 추적 |

## 프로덕션 준비 완료

| 항목 | 상세 |
|------|------|
| **878+ 테스트, 92% 커버리지** | 모든 어댑터, 핸들러, 엣지 케이스 테스트 |
| **타입 안전** | `mypy --strict` 에러 제로, `py.typed` 마커 |
| **성능** | 정책 평가 < 1ms, 자동 승인 액션 오버헤드 < 5ms |
| **페일 세이프** | 차단된 액션은 절대 실행 안 됨, 정책 변경 없이 우회 불가 |
| **감사 불변성** | Result는 frozen 데이터클래스, 감사 기록은 반환 전에 완료 |
| **블랙 매직 없음** | 순수 Python, monkey-patching 없음, 전역 상태 없음 |

## 컴플라이언스 & 감사

Aegis 감사 추적은 규제 및 내부 컴플라이언스 증빙을 제공합니다:

| 표준 | Aegis가 제공하는 것 |
|------|-------------------|
| **SOC2** | 모든 에이전트 액션, 결정, 승인의 불변 감사 로그 |
| **GDPR** | 데이터 접근 문서화 — 누가/무엇이 어떤 시스템에 언제 접근했는지 |
| **HIPAA** | 전체 액션 컨텍스트와 승인 체인이 포함된 PHI 접근 추적 |
| **내부 규정** | 변경 관리 증빙, 액션별 위험 평가 |

JSONL로 내보내기, CLI/API로 조회, 또는 웹훅으로 외부 SIEM에 스트리밍 가능. 컨테이너 격리와 함께 쓰는 심층 방어 전략은 [Security Model](https://acacian.github.io/aegis/guides/security-model/) 가이드를 참고하세요.

## 통합

사용 중인 에이전트 프레임워크와 바로 연동:

```bash
pip install langchain-aegis               # LangChain (독립 통합 패키지)
pip install 'agent-aegis[langchain]'      # LangChain (어댑터)
pip install 'agent-aegis[crewai]'         # CrewAI
pip install 'agent-aegis[openai-agents]'  # OpenAI Agents SDK
pip install 'agent-aegis[anthropic]'      # Anthropic Claude
pip install 'agent-aegis[httpx]'          # 웹훅 승인/감사
pip install 'agent-aegis[playwright]'     # 브라우저 자동화
pip install 'agent-aegis[server]'         # REST API 서버
pip install 'agent-aegis[all]'            # 전부
```

<details>
<summary><b>LangChain</b> -- 함수 하나로 모든 LangChain 도구에 거버넌스 적용</summary>

**방법 A: `langchain-aegis` (권장)** — 독립 통합 패키지

```bash
pip install langchain-aegis
```

```python
from langchain_aegis import govern_tools

# 기존 도구에 거버넌스 추가 — 다른 코드 변경 없음
governed = govern_tools(tools, policy="policy.yaml")
agent = create_react_agent(model, governed)
```

**방법 B: `agent-aegis[langchain]`** — 어댑터 기반

```python
from aegis.adapters.langchain import LangChainExecutor, AegisTool

# 기존 LangChain 도구를 거버넌스로 래핑
executor = LangChainExecutor(tools=[DuckDuckGoSearchRun()])
runtime = Runtime(executor=executor, policy=Policy.from_yaml("policy.yaml"))

# 또는 거버넌스 액션을 LangChain 도구로 노출
tool = AegisTool.from_runtime(runtime, name="governed_search",
    description="Policy-governed search", action_type="search", action_target="web")
```
</details>

<details>
<summary><b>OpenAI Agents SDK</b> -- 데코레이터 기반 거버넌스</summary>

```python
from aegis.adapters.openai_agents import governed_tool

@governed_tool(runtime=runtime, action_type="write", action_target="crm")
async def update_contact(name: str, email: str) -> str:
    """CRM 연락처 업데이트 -- Aegis 정책으로 관리됨."""
    return await crm.update(name=name, email=email)
```
</details>

<details>
<summary><b>CrewAI</b> -- 크루를 위한 거버넌스 도구</summary>

```python
from aegis.adapters.crewai import AegisCrewAITool

tool = AegisCrewAITool(runtime=runtime, name="governed_search",
    description="Search with governance", action_type="search",
    action_target="web", fn=lambda query: do_search(query))
```
</details>

<details>
<summary><b>Anthropic Claude</b> -- tool_use 호출 거버넌스</summary>

```python
from aegis.adapters.anthropic import govern_tool_call

for block in response.content:
    if block.type == "tool_use":
        result = await govern_tool_call(
            runtime=runtime, tool_name=block.name,
            tool_input=block.input, target="my_system")
```
</details>

<details>
<summary><b>httpx</b> -- 거버넌스가 적용된 REST API 호출</summary>

```python
from aegis.adapters.httpx_adapter import HttpxExecutor

executor = HttpxExecutor(base_url="https://api.example.com",
    default_headers={"Authorization": "Bearer ..."})
runtime = Runtime(executor=executor, policy=Policy.from_yaml("policy.yaml"))

# 액션 타입이 HTTP 메서드에 매핑: get, post, put, patch, delete
plan = runtime.plan([Action("get", "/users"), Action("delete", "/users/1")])
```
</details>

<details>
<summary><b>MCP (Model Context Protocol)</b> -- 모든 MCP 도구 호출 거버넌스</summary>

```python
from aegis.adapters.mcp import govern_mcp_tool_call, AegisMCPToolFilter

# 옵션 1: 개별 도구 호출 거버넌스
result = await govern_mcp_tool_call(
    runtime=runtime, tool_name="read_file",
    arguments={"path": "/data.csv"}, server_name="filesystem")

# 옵션 2: 필터 기반 거버넌스
tool_filter = AegisMCPToolFilter(runtime=runtime)
result = await tool_filter.check(server="filesystem", tool="delete_file")
if result.ok:
    # 실제 MCP 호출 진행
    pass
```
</details>

<details>
<summary><b>REST API</b> -- 모든 언어에서 거버넌스</summary>

```bash
pip install 'agent-aegis[server]'
aegis serve policy.yaml --port 8000
```

```bash
# 액션 평가 (dry-run)
curl -X POST http://localhost:8000/api/v1/evaluate \
    -H "Content-Type: application/json" \
    -d '{"action_type": "delete", "target": "db"}'
# => {"risk_level": "CRITICAL", "approval": "block", "is_allowed": false}

# 전체 거버넌스 파이프라인으로 실행
curl -X POST http://localhost:8000/api/v1/execute \
    -H "Content-Type: application/json" \
    -d '{"action_type": "read", "target": "crm"}'

# 감사 로그 조회
curl http://localhost:8000/api/v1/audit?action_type=delete

# 정책 핫 리로드
curl -X PUT http://localhost:8000/api/v1/policy \
    -H "Content-Type: application/json" \
    -d '{"yaml": "rules:\n  - name: block_all\n    match: {type: \"*\"}\n    approval: block"}'
```
</details>

<details>
<summary><b>MCP 서버</b> -- Claude, Cursor, VS Code, Windsurf 원클릭 거버넌스</summary>

```bash
pip install 'agent-aegis[mcp]'
aegis-mcp-server --policy policy.yaml
```

**Claude Desktop** — `~/Library/Application Support/Claude/claude_desktop_config.json`에 추가:
```json
{ "mcpServers": { "aegis": { "command": "uvx", "args": ["--from", "agent-aegis[mcp]", "aegis-mcp-server"] }}}
```

**Cursor** — `.cursor/mcp.json`에 추가:
```json
{ "mcpServers": { "aegis": { "command": "uvx", "args": ["--from", "agent-aegis[mcp]", "aegis-mcp-server"] }}}
```

**VS Code Copilot** — `.vscode/mcp.json`에 추가:
```json
{ "servers": { "aegis": { "command": "uvx", "args": ["--from", "agent-aegis[mcp]", "aegis-mcp-server"] }}}
```

**Windsurf** — `~/.codeium/windsurf/mcp_config.json`에 추가:
```json
{ "mcpServers": { "aegis": { "command": "uvx", "args": ["--from", "agent-aegis[mcp]", "aegis-mcp-server"] }}}
```
</details>

<details>
<summary><b>커스텀 어댑터</b> -- 10줄이면 무엇이든 연동</summary>

```python
from aegis.adapters.base import BaseExecutor
from aegis.core.action import Action
from aegis.core.result import Result, ResultStatus

class MyAPIExecutor(BaseExecutor):
    async def execute(self, action: Action) -> Result:
        response = await my_api.call(action.type, action.target, **action.params)
        return Result(action=action, status=ResultStatus.SUCCESS, data=response)

    async def verify(self, action: Action, result: Result) -> bool:
        return result.data.get("status") == "ok"
```
</details>

## 정책 조건

글로브 매칭을 넘어서는 스마트 조건:

```yaml
rules:
  # 업무 시간 이후 쓰기 차단
  - name: after_hours_block
    match: { type: "write*" }
    conditions:
      time_after: "18:00"
    risk_level: critical
    approval: block

  # 임계치 초과 대량 작업 에스컬레이션
  - name: large_bulk_ops
    match: { type: "update*" }
    conditions:
      param_gt: { count: 100 }
    risk_level: high
    approval: approve

  # 평일에만 배포 허용
  - name: weekday_deploys
    match: { type: "deploy*" }
    conditions:
      weekdays: [1, 2, 3, 4, 5]
    risk_level: medium
    approval: approve
```

사용 가능: `time_after`, `time_before`, `weekdays`, `param_eq`, `param_gt`, `param_lt`, `param_gte`, `param_lte`, `param_contains`, `param_matches` (정규식).

### 시맨틱 조건

키워드 매칭을 넘어서는 2단계 시맨틱 조건 엔진:

```yaml
rules:
  - name: block_harmful_content
    match: { type: "generate*" }
    conditions:
      semantic: "유해하거나 폭력적이거나 불법적인 콘텐츠를 포함"
    risk_level: critical
    approval: block
```

1단계는 빠른 내장 키워드 매칭. 2단계는 `SemanticEvaluator` 프로토콜을 통해 LLM 평가기를 연결 -- 정밀한 콘텐츠 분석을 위해 자체 모델을 연동할 수 있습니다.

## 심층 기능

프로덕션 수준의 에이전트 거버넌스를 위한 고급 기능들.

### 행동 이상 탐지

Aegis가 에이전트별 행동 프로필을 학습하고 이상을 자동 탐지합니다 -- 수동 임계값 설정이 필요 없습니다.

```python
from aegis.core.anomaly import AnomalyDetector

detector = AnomalyDetector()

# 에이전트별 행동 프로필 구축을 위한 관찰 데이터 입력
detector.observe(agent_id="agent-1", action_type="read", target="crm")
detector.observe(agent_id="agent-1", action_type="read", target="crm")
detector.observe(agent_id="agent-1", action_type="read", target="crm")

# 이상 탐지: 속도 급증, 버스트, 새로운 액션, 비정상 타겟, 높은 차단율
alerts = detector.check(agent_id="agent-1", action_type="delete", target="prod_db")
# => [Anomaly(type=NEW_ACTION, detail="action 'delete' never seen for agent-1")]

# 관찰된 행동에서 자동으로 정책 생성
learned_policy = detector.generate_policy(agent_id="agent-1")
```

탐지 항목: **속도 급증** | **버스트 패턴** | **미관측 액션** | **비정상 타겟** | **높은 차단율**

### 컴플라이언스 리포트 생성기

기존 감사 로그에서 감사 대비 컴플라이언스 보고서를 생성합니다. 추가 도구 불필요.

```bash
aegis compliance --type soc2 --output report.json
aegis compliance --type gdpr --output gdpr-report.json
aegis compliance --type governance --days 30
```

```python
from aegis.core.compliance import ComplianceReporter

reporter = ComplianceReporter(audit_store=runtime.audit_store)
report = await reporter.generate(report_type="soc2", days=90)

print(report.score)        # 87.5
print(report.findings)     # 심각도별 발견 사항 목록
print(report.evidence)     # 연결된 감사 로그 항목
```

지원 보고서 유형: **SOC2** | **GDPR** | **Governance** -- 각각 점수, 발견 사항, 증빙 링크 포함.

### 정책 비교 & 영향 분석

두 정책 파일을 비교하고 정확히 무엇이 변경되었는지, 어떤 영향이 있는지 파악합니다.

```bash
# 두 정책 간 추가/삭제/수정된 규칙 표시
aegis diff policy-v1.yaml policy-v2.yaml

# 새 정책에 대해 과거 액션을 리플레이하여 영향도 분석
aegis diff policy-v1.yaml policy-v2.yaml --replay audit.db
```

```
 Rules: 2 added, 1 removed, 3 modified

 + bulk_write_block     CRITICAL/block   (new)
 + pii_access_approve   HIGH/approve     (new)
 - legacy_allow_all     LOW/auto         (removed)
 ~ read_safe            LOW/auto → LOW/auto  conditions changed
 ~ deploy_prod          HIGH/approve → CRITICAL/block  risk escalated
 ~ bulk_ops             MEDIUM/approve   param_gt.count: 100 → 50

 Impact (replayed 1,247 actions):
   23 actions would change from AUTO → BLOCK
    7 actions would change from APPROVE → BLOCK
```

### 에이전트 신뢰 체인

계층적 에이전트 아이덴티티와 위임, 기능 범위 기반 신뢰 관리.

```python
from aegis.core.trust import TrustChain, AgentIdentity, Capability

# 전체 권한을 가진 루트 에이전트 생성
root = AgentIdentity(
    agent_id="orchestrator",
    capabilities=[Capability("*")],  # 글로브 매칭
)

# 권한의 부분 집합을 위임 (교집합 의미론)
worker = root.delegate(
    agent_id="data-worker",
    capabilities=[Capability("read:*"), Capability("write:staging_*")],
)

# 워커는 루트 권한과 위임 권한의 교집합만 가능
chain = TrustChain()
chain.register(root)
chain.register(worker, parent=root)

# 런타임에서 권한 확인
chain.can(worker, "read:crm")           # True
chain.can(worker, "delete:prod_db")     # False -- 위임에 포함되지 않음

# 연쇄 폐기: 부모를 폐기하면 모든 자식도 폐기
chain.revoke(root)
chain.can(worker, "read:crm")           # False
```

### `aegis scan` -- 정적 분석

AST 기반 스캐너로 Python 코드베이스에서 거버넌스가 적용되지 않은 AI 도구 호출을 탐지합니다.

```bash
aegis scan ./src/

# 출력:
# src/agents/mailer.py:42  openai.ChatCompletion.create()  -- ungoverned
# src/agents/writer.py:18  anthropic.messages.create()     -- ungoverned
# src/tools/search.py:7    langchain tool "web_search"     -- ungoverned
#
# 3 ungoverned calls found. Run `aegis score` for governance coverage.
```

### `aegis score` -- 거버넌스 점수

거버넌스 적용률을 0-100 점수로 수치화하고 shields.io 배지를 생성합니다.

```bash
aegis score ./src/ --policy policy.yaml

# Governance Score: 84/100
#   Governed calls:   21/25 (84%)
#   Policy coverage:  18 rules covering 6 action types
#   Anomaly detection: enabled
#   Audit trail:       enabled
#
# Badge: https://img.shields.io/badge/aegis_score-84-brightgreen
```

리포에 배지 추가:
```markdown
![Aegis Score](https://img.shields.io/badge/aegis_score-84-brightgreen)
```

## 아키텍처

```
aegis/
  core/        Action, Policy 엔진, Conditions, Risk levels, Retry, JSON Schema
  core/anomaly     행동 이상 탐지 -- 에이전트별 프로파일링, 자동 정책 생성
  core/compliance  컴플라이언스 리포트 생성기 -- SOC2, GDPR, 거버넌스 점수화
  core/trust       에이전트 신뢰 체인 -- 계층적 아이덴티티, 위임, 폐기
  core/semantic    시맨틱 조건 엔진 -- 키워드 매칭 + LLM 평가기 프로토콜
  core/diff        정책 비교 & 영향 분석 -- 규칙 비교, 액션 리플레이
  adapters/    BaseExecutor, Playwright, httpx, LangChain, CrewAI, OpenAI, Anthropic, MCP
  runtime/     Runtime 엔진, ApprovalHandler, AuditLogger (SQLite/JSONL/웹훅/logging)
  server/      REST API (Starlette ASGI) -- 평가, 실행, 감사, 정책 엔드포인트
  cli/         aegis validate | audit | schema | init | simulate | serve | stats | scan | score | diff | compliance
```

## 왜 Aegis인가?

AI 에이전트에 거버넌스를 추가하는 방법은 여러 가지입니다. 비교해보겠습니다:

### vs. 직접 구현

| | 직접 구현 | Aegis |
|---|---|---|
| **정책 엔진** | 액션마다 if/else | YAML 규칙 + 글로브 + 조건 |
| **위험 모델** | 하드코딩 | 4단계 + 규칙별 오버라이드 |
| **사람 승인** | 직접 구현 | 플러그형 (CLI, Slack, Discord, Telegram, 이메일, 웹훅) |
| **감사 추적** | printf 디버깅 | SQLite + JSONL + 세션 추적 |
| **프레임워크 지원** | 프레임워크마다 재작성 | 7개 어댑터 기본 제공 |
| **재시도 & 롤백** | 직접 에러 처리 | 지수 백오프 + 자동 롤백 |
| **타입 안전** | 아마도 | mypy strict, py.typed |
| **연동 소요** | 며칠 | 몇 분 |

### vs. 플랫폼 내장 Guardrails

OpenAI, Google, Anthropic 각각 자체 guardrails를 제공하지만, 자기 에코시스템만 관리합니다. 에이전트가 OpenAI **와** Anthropic을 동시에 쓰거나, LangChain **과** MCP 도구를 섞어 쓴다면, 모든 것을 하나의 정책으로 관리하는 레이어가 필요합니다. 그게 Aegis입니다.

### vs. 엔터프라이즈 거버넌스 플랫폼

중앙 컨트롤 플레인 같은 엔터프라이즈 플랫폼은 쿠버네티스 클러스터, 클라우드 인프라, 도입 프로세스가 필요합니다. Aegis는 **라이브러리**입니다 — `pip install`이면 5분 안에 거버넌스가 동작합니다. 라이브러리로 시작하고, 필요할 때 플랫폼으로 올리세요.

## CLI

```bash
aegis init                              # 기본 정책 생성
aegis validate policy.yaml              # 정책 문법 검증
aegis schema                            # JSON Schema 출력 (에디터 자동완성용)
aegis simulate policy.yaml read:crm delete:db  # 실행 없이 정책 테스트
aegis audit                             # 감사 로그 조회
aegis audit --session abc --format json # 필터 + 포맷
aegis audit --tail                      # 실시간 모니터링
aegis audit --format jsonl -o export.jsonl  # 내보내기
aegis stats                             # 정책 규칙 통계
aegis serve policy.yaml --port 8000     # REST API 서버 시작
aegis scan ./src/                       # 거버넌스 미적용 AI 도구 호출 탐지 (AST 기반)
aegis score ./src/ --policy policy.yaml # 거버넌스 점수 (0-100) + 배지
aegis diff policy-v1.yaml policy-v2.yaml           # 정책 비교
aegis diff policy-v1.yaml policy-v2.yaml --replay  # 액션 리플레이 영향 분석
aegis compliance --type soc2 --output report.json  # 컴플라이언스 리포트 생성
```

## 로드맵

| 버전 | 상태 | 기능 |
|------|------|------|
| **0.1** | **출시됨** | 정책 엔진, 7개 어댑터 (MCP 포함), CLI, 감사 (SQLite + JSONL + 웹훅), 조건, JSON Schema |
| **0.1.3** | **출시됨** | REST API 서버, 재시도/롤백, 드라이런, 핫 리로드, 정책 병합, Slack/Discord/Telegram/이메일 승인, 시뮬레이션 CLI, 런타임 훅, 통계, 실시간 모니터링 |
| **0.1.4** | **출시됨** | 멀티 에이전트 기반 (agent_id, PolicyHierarchy, 충돌 감지), 성능 최적화 (컴파일된 글로브, 배치 감사, 평가 캐시), 보안 강화, MCP/LangChain/CrewAI/OpenAI 쿡북 |
| **0.1.5** | **출시됨** | 행동 이상 탐지, 컴플라이언스 리포트 생성기 (SOC2/GDPR), 정책 비교 & 영향 분석, 시맨틱 조건 엔진, 에이전트 신뢰 체인, `aegis scan` (정적 분석), `aegis score` (거버넌스 점수 + 배지) |
| **0.2** | **출시됨** | LangChain AgentMiddleware, CrewAI GuardrailProvider, OpenAI Agents 네이티브 가드레일, OWASP Agentic Top 10, HTML 컴플라이언스 리포트, 인터랙티브 플레이그라운드 |
| **0.3** | **출시됨** | MCP 공급망 보안 (포이즈닝/러그풀/SBOM/취약점 DB), 비용 차단기 (17 모델), 크로스-프레임워크 비용 추적 (LangChain/OpenAI/Anthropic/Google), A2A 통신 거버넌스, 세션 리플레이 + 소급 스캔, OpenTelemetry 내보내기, 정책 Git 통합 |
| **0.4** | 2026 Q3 | 중앙 정책 서버, 크로스 에이전트 감사 추적 |
| **1.0** | 2027 | 분산 거버넌스, 호스티드 SaaS, SSO/SCIM |

## 기여하기

기여를 환영합니다!

- [**Good First Issues**](https://github.com/Acacian/aegis/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) -- 시작하기 좋은 이슈들
- [**Contributing Guide**](CONTRIBUTING.md) -- 설정, 코드 스타일, PR 프로세스
- [**Architecture**](ARCHITECTURE.md) -- 코드베이스 구조

```bash
git clone https://github.com/Acacian/aegis.git && cd aegis
make dev      # 의존성 설치 + 훅
make test     # 테스트 실행
make lint     # 린트 + 포맷 검사
make coverage # 커버리지 리포트
```

또는 클라우드 환경에서 바로 시작:

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/Acacian/aegis)

## 배지

Aegis를 사용 중이신가요? 프로젝트에 배지를 추가하세요:

```markdown
[![Governed by Aegis](https://img.shields.io/badge/governed%20by-aegis-blue?logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIj48dGV4dCB5PSIuOWVtIiBmb250LXNpemU9IjkwIj7wn5uh77iPPC90ZXh0Pjwvc3ZnPg==)](https://github.com/Acacian/aegis)
```

[![Governed by Aegis](https://img.shields.io/badge/governed%20by-aegis-blue?logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIj48dGV4dCB5PSIuOWVtIiBmb250LXNpemU9IjkwIj7wn5uh77iPPC90ZXh0Pjwvc3ZnPg==)](https://github.com/Acacian/aegis)

## 라이선스

MIT -- [LICENSE](LICENSE) 참조.

Copyright (c) 2026 구동하 (Dongha Koo, [@Acacian](https://github.com/Acacian)). 최초 생성일: 2026년 3월 21일.

---

<p align="center">
  <sub>자율 AI 에이전트 시대를 위해 만들었습니다.</sub><br/>
  <sub>Aegis가 도움이 되셨다면, 별 하나 부탁드립니다 -- 더 많은 사람이 찾을 수 있게 됩니다.</sub>
</p>
