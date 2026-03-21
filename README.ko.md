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
  <a href="https://pypi.org/project/agent-aegis/"><img src="https://img.shields.io/pypi/v/agent-aegis?color=blue" alt="PyPI"></a>
  <a href="https://pypi.org/project/agent-aegis/"><img src="https://img.shields.io/pypi/pyversions/agent-aegis" alt="Python"></a>
  <a href="https://github.com/Acacian/aegis/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
  <a href="https://acacian.github.io/aegis/"><img src="https://img.shields.io/badge/docs-acacian.github.io%2Faegis-blue" alt="Docs"></a>
  <a href="https://github.com/Acacian/aegis"><img src="https://img.shields.io/github/stars/Acacian/aegis?style=social" alt="GitHub stars"></a>
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

```
액션       정책 확인      승인 게이트     실행       감사
  |            |              |              |           |
CRM 읽기 --> 자동 (낮음) --> 건너뜀 ------> 실행 -----> 기록됨
대량 수정 --> 승인 (높음) --> 사람 y/n ----> 실행 -----> 기록됨
전체 삭제 --> 차단 (위험)  ----------------> X --------> 기록됨
```

Aegis는 에이전트와 실제 세계 사이에 위치합니다. **3줄이면 거버넌스 추가:**

```python
from aegis import Action, Policy, Runtime

runtime = Runtime(executor=your_executor, policy=Policy.from_yaml("policy.yaml"))
results = await runtime.run_one(Action("write", "salesforce", params={...}))
```

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
        print(f"  Executing: {action.type} -> {action.target}")
        return Result(action=action, status=ResultStatus.SUCCESS)

async def main():
    async with Runtime(
        executor=MyExecutor(),
        policy=Policy.from_yaml("policy.yaml"),
    ) as runtime:
        plan = runtime.plan([
            Action("read", "crm", description="Fetch contacts"),
            Action("bulk_update", "crm", params={"count": 150}),
            Action("delete", "crm", description="Drop table"),
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
| **승인 게이트** | CLI 프롬프트, 콜백 함수, 또는 직접 구현 (Slack, Discord 등) |
| **감사 추적** | SQLite (기본), JSONL 내보내기, Python `logging` 백엔드 |
| **컨텍스트 매니저** | `async with Runtime(...) as rt:` — 자동 setup/teardown |
| **단일 액션 모드** | `await runtime.run_one(action)` 간단한 케이스에 |
| **JSON Schema** | `aegis schema` — VS Code / JetBrains 자동완성 |
| **정책 생성기** | `aegis init` — 몇 초 만에 기본 정책 생성 |
| **타입 안전** | `mypy --strict` 완전 통과, `py.typed` 마커 |

## 통합

사용 중인 에이전트 프레임워크와 바로 연동:

```bash
pip install 'agent-aegis[langchain]'      # LangChain
pip install 'agent-aegis[crewai]'         # CrewAI
pip install 'agent-aegis[openai-agents]'  # OpenAI Agents SDK
pip install 'agent-aegis[httpx]'          # REST API
pip install 'agent-aegis[playwright]'     # 브라우저 자동화
pip install 'agent-aegis[all]'            # 전부
```

<details>
<summary><b>LangChain</b> — 도구 래핑 또는 거버넌스 액션 노출</summary>

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
<summary><b>OpenAI Agents SDK</b> — 데코레이터 기반 거버넌스</summary>

```python
from aegis.adapters.openai_agents import governed_tool

@governed_tool(runtime=runtime, action_type="write", action_target="crm")
async def update_contact(name: str, email: str) -> str:
    """CRM 연락처 업데이트 — Aegis 정책으로 관리됨."""
    return await crm.update(name=name, email=email)
```
</details>

<details>
<summary><b>CrewAI</b> — 크루를 위한 거버넌스 도구</summary>

```python
from aegis.adapters.crewai import AegisCrewAITool

tool = AegisCrewAITool(runtime=runtime, name="governed_search",
    description="Search with governance", action_type="search",
    action_target="web", fn=lambda query: do_search(query))
```
</details>

<details>
<summary><b>Anthropic Claude</b> — tool_use 호출 거버넌스</summary>

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
<summary><b>httpx</b> — 거버넌스가 적용된 REST API 호출</summary>

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
<summary><b>커스텀 어댑터</b> — 10줄이면 무엇이든 연동</summary>

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
  core/        Action, Policy 엔진, Conditions, Risk levels, JSON Schema
  adapters/    BaseExecutor, Playwright, httpx, LangChain, CrewAI, OpenAI, Anthropic
  runtime/     Runtime 엔진, ApprovalHandler, AuditLogger (SQLite/JSONL/logging)
  cli/         aegis validate | audit | schema | init
```

```
                    +----------------+
                    |   Your Agent   |
                    +-------+--------+
                            |
                     Action(type, target, params)
                            |
                    +-------v--------+
                    |  Policy Engine |  <-- policy.yaml (YAML 규칙 + 조건)
                    +-------+--------+
                            |
                   PolicyDecision(risk, approval, rule)
                            |
              +-------------+-------------+
              |             |             |
         auto: LOW    approve: HIGH   block: CRITICAL
              |             |             |
              v      +------v------+      v
           execute   | Approval    |   blocked
              |      | Handler     |      |
              |      +------+------+      |
              |             |             |
              v             v             |
         +---------+   +---------+        |
         | Adapter |   | Adapter |        |
         +---------+   +---------+        |
              |             |             |
              v             v             v
         +------------------------------------+
         |          Audit Logger              |
         |   (SQLite / JSONL / logging)       |
         +------------------------------------+
```

## 직접 만들기 vs Aegis

| | 직접 구현 | Aegis |
|---|---|---|
| **정책 엔진** | 액션마다 if/else | YAML 규칙 + 글로브 + 조건 |
| **위험 모델** | 하드코딩 | 4단계 + 규칙별 오버라이드 |
| **사람 승인** | 직접 구현 | 플러그형 (CLI, Slack, 커스텀) |
| **감사 추적** | printf 디버깅 | SQLite + JSONL + 세션 추적 |
| **프레임워크 지원** | 프레임워크마다 재작성 | 6개 어댑터 기본 제공 |
| **검증** | 잘 됐기를 바라기 | 실행 후 검증 훅 |
| **타입 안전** | 아마도 | mypy strict, py.typed |
| **연동 소요** | 며칠 | 몇 분 |

## CLI

```bash
aegis init                              # 기본 정책 생성
aegis validate policy.yaml              # 정책 문법 검증
aegis schema                            # JSON Schema 출력 (에디터 자동완성용)
aegis audit                             # 감사 로그 조회
aegis audit --session abc --format json # 필터 + 포맷
aegis audit --format jsonl -o export.jsonl  # 내보내기
```

## 로드맵

| 버전 | 상태 | 기능 |
|------|------|------|
| **0.1** | **출시됨** | 정책 엔진, 6개 어댑터, CLI, 감사 (SQLite + JSONL), 조건, JSON Schema |
| **0.2** | 계획됨 | 대시보드 UI, Slack/Discord 승인, 정책 상속, 핫 리로드 |
| **0.3** | 계획됨 | MCP 서버 어댑터, 롤백 지원, 웹훅 알림 |
| **0.4** | 계획됨 | 멀티 테넌트 정책, 팀 승인, 클라우드 감사 스토리지 |

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
