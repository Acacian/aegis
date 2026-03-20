# CLAUDE.md

Constitutional contract for Claude in this repository.

## 1. Role
- Claude = single executor for all operations (reasoning, planning, git, file writes, shell).
- Spec changes require explicit user confirmation.

## 2. Execution Rules
- Claude uses all available tools directly: Read, Write, Edit, Bash, Glob, Grep, Agent, etc.
- Git via `Bash(git ...)`. File edits via Edit/Write tools. Shell commands via Bash.

## 2.1. Context Compaction
Defined in `PROTOCOLS.md`. Load on-demand.

## 2.3. Auto-Execution Policy
- Claude assesses task scope before execution.
- **Direct**: 1-4 files, single domain, follows existing patterns → execute immediately.
- **Auto-Loop**: 5+ files, cross-domain, structural, or refactoring → plan → execute → verify → repeat until done.
- **Auto-Finalize** applies to all completed tasks (§18).

## 3. Structural Approval
- Structural, architectural, persistence, or scope-level changes require explicit user approval before planning.

## 3.1. Decision Records
- GitHub Issues only (not local files). Labels: `adr`, `state`, `meeting`.
- Open = pending implementation. Closed = implemented/completed.
- Query pending: `gh issue list --label adr --state open`
- Query completed: `gh issue list --label adr --state closed`
- Local `.claude/adr/` prohibited.

### ADR 기록 의무 트리거
아래 중 하나라도 해당하면 작업 완료 시 반드시 ADR 이슈를 생성한다:
- 새로운 자동화/스크립트 동작 방식 결정 (예: loop-runner 정책)
- 디렉토리 구조/파일 배치 규칙 변경
- 새로운 라벨/태그/추적 체계 도입
- 인프라/배포/CI 정책 변경
- API 계약 또는 데이터 스키마 변경
- 보안/인증 정책 변경

크기와 무관하게 **"왜 이렇게 했는지" 미래의 컨텍스트가 필요한 결정**이면 ADR을 남긴다.

## 4. Agent Team Bootstrap
- Session start: load `.claude/agents/AGENTS.md` once. Per-command: signal-matching + Team construction per AGENTS.md.
- Operational scripts in `.claude/scripts/`. Root `scripts/` = production build only.

## 5. Plan Discipline
- Load `ENVIRONMENT.md` before planning (path/index map, no secrets).
- Plan construction governed by AGENTS.md. Stay within approved scope.

## 6. Output Format
- Governed by AGENTS.md. Default: structured and concise.

## 7. Growth Policy
- Growth/ads/monetization require explicit opt-in for 00-market.

## 8. Precedence
- `[admin]` > `CLAUDE.md` > `AGENTS.md`.
- `ENVIRONMENT.md` = path/index registry only.
