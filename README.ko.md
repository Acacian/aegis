<p align="center">
  <h1 align="center">Aegis</h1>
  <p align="center">
    <strong>AI 에이전트를 위한 거버넌스 레이어. 정책 엔진 + 승인 게이트 + 감사 로그.</strong>
  </p>
  <p align="center">
    AI 에이전트가 웹 브라우징, API 호출, SaaS 데이터 수정을 할 수 있습니다.<br/>
    <strong>Aegis는 먼저 허락을 구하도록 만듭니다.</strong>
  </p>
</p>

<p align="center">
  <a href="https://github.com/Acacian/aegis/actions/workflows/ci.yml"><img src="https://github.com/Acacian/aegis/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/agent-aegis/"><img src="https://img.shields.io/pypi/v/agent-aegis?color=blue&cacheSeconds=3600" alt="PyPI"></a>
  <a href="https://pypi.org/project/agent-aegis/"><img src="https://img.shields.io/pypi/pyversions/agent-aegis?cacheSeconds=3600" alt="Python"></a>
  <a href="https://github.com/Acacian/aegis/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
  <a href="https://acacian.github.io/aegis/"><img src="https://img.shields.io/badge/docs-acacian.github.io%2Faegis-blue" alt="Docs"></a>
  <a href="https://github.com/Acacian/aegis"><img src="https://img.shields.io/github/stars/Acacian/aegis?style=social" alt="GitHub stars"></a>
</p>

<p align="center">
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

## 문제

AI 에이전트가 실제 세계에 접근하고 있습니다. 거버넌스 없이는 환각하는 에이전트가:

- CRM 연락처를 대량 삭제하거나
- 잘못된 양식을 정부 포털에 제출하거나
- 새벽 3시에 되돌릴 수 없는 API 호출을 실행하거나
- 무한 루프로 클라우드 비용을 폭발시킬 수 있습니다

**AI 에이전트에는 `sudo`가 없었습니다. 지금까지는.**

## 해결책

Aegis는 AI 에이전트와 실제 실행 사이에 위치하는 **Python 미들웨어**입니다. 별도의 서버를 띄울 필요 없이 에이전트 코드에 직접 임포트하면, 모든 액션에 정책 체크 + 승인 게이트 + 감사 로깅이 자동 적용됩니다.

```
에이전트                        Aegis                         실제 세계
    |                           |                               |
    |-- "전체 유저 삭제" ------> |                               |
    |                      [정책 체크]                           |
    |                      위험=CRITICAL                        |
    |                      승인=BLOCK                           |
    |                           |--- X (차단, 기록됨) ---------> |
    |                           |                               |
    |-- "연락처 읽기" ---------> |                               |
    |                      [정책 체크]                           |
    |                      위험=LOW                             |
    |                      승인=AUTO                            |
    |                           |--- 실행 (기록됨) ------------> |
    |                           |                               |
    |-- "500건 대량 수정" -----> |                               |
    |                      [정책 체크]                           |
    |                      위험=HIGH                            |
    |                      승인=APPROVE                         |
    |                           |--- 사람에게 질문 (Slack/CLI) -> |
    |                           |<-- "승인" ------------------- |
    |                           |--- 실행 (기록됨) ------------> |
```

**3줄이면 거버넌스 추가:**

```python
from aegis import Action, Policy, Runtime

runtime = Runtime(executor=your_executor, policy=Policy.from_yaml("policy.yaml"))
results = await runtime.run_one(Action("write", "salesforce", params={...}))
```

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

| 핸들러 | 작동 방식 |
|--------|----------|
| **CLI** (기본값) | 터미널 Y/N 프롬프트 |
| **Slack** | Block Kit 메시지 전송, 스레드 답글 폴링 |
| **Discord** | 리치 Embed 전송, 콜백 폴링 |
| **Telegram** | 인라인 키보드 버튼, getUpdates 폴링 |
| **Email** | 승인 요청 이메일 전송, 답장 대기 |
| **Webhook** | 임의 URL에 POST, 응답 확인 |
| **Auto** | 전부 자동 승인 (테스트/서버 모드용) |
| **Custom** | `ApprovalHandler`를 상속해 직접 구현 |

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
| **4단계 위험 모델** | `low` / `medium` / `high` / `critical` (규칙별 오버라이드) |
| **승인 게이트** | CLI, Slack, Discord, Telegram, 이메일, 웹훅, 또는 커스텀 |
| **감사 추적** | SQLite, JSONL 내보내기, Python `logging`, 또는 외부 SIEM 웹훅 |
| **REST API 서버** | `aegis serve policy.yaml` -- 모든 언어에서 HTTP로 거버넌스 |
| **MCP 어댑터** | Model Context Protocol 도구 호출 거버넌스 |
| **재시도 & 롤백** | 지수 백오프, 에러 필터, 실패 시 자동 롤백 |
| **드라이런 & 시뮬레이션** | 실행 없이 정책 테스트: `aegis simulate policy.yaml read:crm` |
| **핫 리로드** | `runtime.update_policy(...)` -- 재시작 없이 정책 교체 |
| **정책 병합** | `Policy.from_yaml_files("base.yaml", "prod.yaml")` -- 설정 레이어링 |
| **런타임 훅** | `on_decision`, `on_approval`, `on_execute` 비동기 콜백 |
| **타입 안전** | `mypy --strict` 완전 통과, `py.typed` 마커 |

## 통합

사용 중인 에이전트 프레임워크와 바로 연동:

```bash
pip install 'agent-aegis[langchain]'      # LangChain
pip install 'agent-aegis[crewai]'         # CrewAI
pip install 'agent-aegis[openai-agents]'  # OpenAI Agents SDK
pip install 'agent-aegis[anthropic]'      # Anthropic Claude
pip install 'agent-aegis[httpx]'          # 웹훅 승인/감사
pip install 'agent-aegis[playwright]'     # 브라우저 자동화
pip install 'agent-aegis[server]'         # REST API 서버
pip install 'agent-aegis[all]'            # 전부
```

<details>
<summary><b>LangChain</b> -- 도구 래핑 또는 거버넌스 액션 노출</summary>

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

## 아키텍처

```
aegis/
  core/        Action, Policy 엔진, Conditions, Risk levels, Retry, JSON Schema
  adapters/    BaseExecutor, Playwright, httpx, LangChain, CrewAI, OpenAI, Anthropic, MCP
  runtime/     Runtime 엔진, ApprovalHandler, AuditLogger (SQLite/JSONL/웹훅/logging)
  server/      REST API (Starlette ASGI) -- 평가, 실행, 감사, 정책 엔드포인트
  cli/         aegis validate | audit | schema | init | simulate | serve | stats
```

## 직접 만들기 vs Aegis

| | 직접 구현 | Aegis |
|---|---|---|
| **정책 엔진** | 액션마다 if/else | YAML 규칙 + 글로브 + 조건 |
| **위험 모델** | 하드코딩 | 4단계 + 규칙별 오버라이드 |
| **사람 승인** | 직접 구현 | 플러그형 (CLI, Slack, Discord, Telegram, 이메일, 웹훅) |
| **감사 추적** | printf 디버깅 | SQLite + JSONL + 세션 추적 |
| **프레임워크 지원** | 프레임워크마다 재작성 | 7개 어댑터 기본 제공 |
| **검증** | 잘 됐기를 바라기 | 실행 후 검증 훅 |
| **재시도 & 롤백** | 직접 에러 처리 | 지수 백오프 + 자동 롤백 |
| **타입 안전** | 아마도 | mypy strict, py.typed |
| **연동 소요** | 며칠 | 몇 분 |

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
```

## 로드맵

| 버전 | 상태 | 기능 |
|------|------|------|
| **0.1** | **출시됨** | 정책 엔진, 7개 어댑터 (MCP 포함), CLI, 감사 (SQLite + JSONL + 웹훅), 조건, JSON Schema |
| **0.1.3** | **출시됨** | REST API 서버, 재시도/롤백, 드라이런, 핫 리로드, 정책 병합, 웹훅 승인/감사, Slack/Discord/Telegram/이메일 승인, 시뮬레이션 CLI, 런타임 훅, 컬러 CLI, 통계, 실시간 모니터링 |
| **0.2** | 계획됨 | 대시보드 UI, 속도 제한, 큐 기반 비동기 실행 |
| **0.3** | 계획됨 | 멀티 테넌트 정책, 팀 승인, 클라우드 감사 스토리지 |

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

## 라이선스

MIT -- [LICENSE](LICENSE) 참조.

---

<p align="center">
  <sub>자율 AI 에이전트 시대를 위해 만들었습니다.</sub><br/>
  <sub>Aegis가 도움이 되셨다면, 별 하나 부탁드립니다 -- 더 많은 사람이 찾을 수 있게 됩니다.</sub>
</p>
