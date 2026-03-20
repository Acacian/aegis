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
  <a href="https://pypi.org/project/agent-aegis/"><img src="https://img.shields.io/pypi/dm/agent-aegis?color=green" alt="Downloads"></a>
  <a href="https://pypi.org/project/agent-aegis/"><img src="https://img.shields.io/pypi/pyversions/agent-aegis" alt="Python"></a>
  <a href="https://codecov.io/gh/Acacian/aegis"><img src="https://codecov.io/gh/Acacian/aegis/graph/badge.svg" alt="Coverage"></a>
  <a href="https://github.com/Acacian/aegis/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
  <a href="https://acacian.github.io/aegis/"><img src="https://img.shields.io/badge/docs-acacian.github.io%2Faegis-blue" alt="Docs"></a>
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
- 새벽 3시에 되돌릴 수 없는 API 호출을 실행할 수 있습니다

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
    approval: auto    # 사람 확인 불필요

  - name: bulk_ops
    match: { type: "bulk_*" }
    conditions:
      param_gt: { count: 100 }  # count > 100일 때만
    risk_level: high
    approval: approve  # 사람 확인 필요

  - name: no_deletes
    match: { type: "delete*" }
    risk_level: critical
    approval: block    # 절대 실행 안 함
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

## 주요 기능

| 기능 | 설명 |
|------|------|
| **YAML 정책** | 글로브 매칭, 첫 매치 우선, JSON Schema 검증 |
| **스마트 조건** | `time_after`, `time_before`, `weekdays`, `param_gt/lt/eq/contains/matches` |
| **4단계 위험 모델** | `low` / `medium` / `high` / `critical` |
| **승인 게이트** | CLI, 콜백, 또는 직접 구현 (Slack, Discord 등) |
| **감사 추적** | SQLite (기본), JSONL 내보내기, Python `logging` |
| **타입 안전** | `mypy --strict` 통과, `py.typed` 마커 |

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
```

## 라이선스

MIT -- [LICENSE](LICENSE) 참조.

---

<p align="center">
  <sub>자율 AI 에이전트 시대를 위해 만들었습니다.</sub><br/>
  <sub>Aegis가 도움이 되셨다면, 별 하나 부탁드립니다 -- 더 많은 사람이 찾을 수 있게 됩니다.</sub>
</p>
