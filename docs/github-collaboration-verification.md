# GitHub 협업 설정 적용·검증 보고

확인일: 2026-11-11 KST. **협업 구성의 도입 PR 준비, 원격 보호 설정 미적용**.
후속 사용자 승인에 따라 Issue #25를 생성하고 `ci/25-github-collaboration` 전용 Worktree에 이번 설정만 옮겼다.
이 문서는 커밋 전 검증 기록이며 실제 커밋·푸시·PR·원격 CI 상태는 연결된 GitHub PR 기록을 확인한다.
Merge·관리자 설정 변경·Hook 상시 활성화는 이번 승인 범위에 포함하지 않는다.

후속 원격 검증: PR #26을 생성하고 `gicks04`에게 사람 리뷰를 요청했다.
첫 원격 실행에서 기존 격리 테스트 4개 묶음과 Ubuntu/macOS 정책 검사는 통과했다.
Windows 정책 검사는 cp1252 stdout에서 한국어 로그를 인코딩하지 못해 실패했다.
Workflow와 Git Bash Hook에 `PYTHONUTF8=1`을 설정했으며 후속 커밋의 실제 결과는 PR Checks에서 확인한다.
메타데이터 검사기로 실제 Issue #25·PR #26·전체 커밋을 읽기 전용 API 대조해 통과를 확인했다.
CodeRabbit 첫 실제 리뷰는 기본 설정으로 실행되어 영문으로 제공됐다. 한국어 설정의 적용은 기본 브랜치 반영 후 별도 확인한다.
코드블록 종료 규칙 지적도 재현해 제목/Closes 검사에 동일한 파서를 사용하고 회귀 테스트를 추가했다.

## 저장소 분석

| 항목 | 실제 확인 결과 |
|---|---|
| 저장소 / origin | `KU-GraduationProject/graduation-project` / `https://github.com/KU-GraduationProject/graduation-project.git` |
| 기본/현재 브랜치, HEAD | `main`, `92e70dbf8b9af14b9376df3fde3a7fb4db7e3e50` |
| 공개 범위/권한 | public, 현재 인증 계정 admin/maintain/push 가능 |
| GitHub 플랜 | 요금제 명칭 미조회. 공개 저장소이므로 Free의 CODEOWNERS/Rulesets 지원 범위에 해당 |
| 기술 스택 | Python FastAPI/Pydantic/HTTPX/Docker SDK, Zeek, Fluentd Ruby, Prometheus/Loki/Grafana, Docker Compose |
| frontend/backend | 소스 미포함; 외부 Nginx/Spring Boot 이미지 사용. 존재하지 않는 앱 디렉터리 생성 안 함 |
| 소스/테스트 | `aiops/{pipeline,remediation,network-observer}`, `scenarios/network`, 각 `tests/`, `testing/run_isolated.py` |
| 기존 설정 | `.github`, `.coderabbit.yaml`, `.githooks`, Husky, commitlint, CODEOWNERS, CONTRIBUTING 없음 |
| 기존 지침 | 미추적 `AGENTS.md`, 기존 `claude.md` 및 선행 미커밋 agent-context 설정 존재; 모두 보존 |
| Hook | core.hooksPath 미설정, 저장소 `.git/hooks`에 sample 이외 Hook 없음; 활성화 설정 변경 안 함 |
| 원격 Actions | enabled=true, allowed_actions=all, 기존 Workflow 0개 |
| 원격 Rulesets | API 결과 빈 목록 |
| main 보호 | Branch protection API: `404 Branch not protected` |
| 현재 HEAD checks | check-runs 0개 |
| CodeRabbit App | 조직 installations API: `coderabbitai`, app_id=347564, repository_selection=all, suspended_at=null |
| 실제 사람 리뷰어 | `galgalrobot`, `gicks04`: API에서 둘 다 User/admin/write 확인 |
| 기존 Issue/PR 관행 | Issue #2~#11 및 PR #23·#24에서 여러 제목 형식·번호 없는 브랜치 사용, 최근 PR 리뷰 요청 목록 비어 있음 |
| 기존 병합 설정 | merge/squash/rebase 모두 허용, squash 제목 `COMMIT_OR_PR_TITLE`; 변경하지 않음 |
| 보존 대상 | 기존 미커밋 변경/산출물, 연결 Worktree 5개(주 작업 디렉터리 포함), 모든 로컬 브랜치 |

충돌: 새 커밋·브랜치 형식은 기존 이력과 다르다. 과거 커밋을 소급 검사하지 않고 PR별 작업 커밋만 검사한다.
열린 PR #23·#24에 필수 체크를 도입하려면 담당자와 전환을 합의해야 한다. 강제 푸시·일괄 재작성은 수행하지 않았다.
기존 Workflow/Hook/CODEOWNERS와의 중복은 발견되지 않았다.

## PR에 포함하는 생성 파일 22개

| 파일 | 용도 |
|---|---|
| `.github/ISSUE_TEMPLATE/feature.yml` | 목적·배경·요구사항·범위·완료 조건·테스트 필수, 참고 자료 선택 |
| `.github/ISSUE_TEMPLATE/bug.yml` | 문제·재현·기대/실제 동작·완료 조건 필수, 오류 로그 선택 |
| `.github/ISSUE_TEMPLATE/task.yml` | 일반 작업/Chore 목적·항목·산출물·완료 조건 필수 |
| `.github/ISSUE_TEMPLATE/docs.yml` | 문서 전용 Form, type:docs/area:docs와 Task Type 기본 지정 |
| `.github/ISSUE_TEMPLATE/config.yml` | 일반 UI의 빈 Issue 버튼 제한 |
| `.github/pull_request_template.md` | 필수 6개 섹션, Closes 안내, 체크리스트 |
| `.github/CODEOWNERS` | 검증된 사람 2명을 저장소 전역 기본 소유자로 지정 |
| `.githooks/commit-msg` | Python 3 기반 로컬 커밋 메시지 검사 진입점, 실행 권한 설정 |
| `.github/scripts/collaboration.py` | stdlib만 사용하는 커밋·PR·브랜치·실제 Issue 검사, Issue 라벨 처리 |
| `.github/scripts/tests/test_collaboration.py` | 정상/실패·API mock·임시 Git 저장소 실제 Hook 검증 |
| `.github/workflows/commit-lint.yml` | `commit-lint` Job, PR 제목과 전체 작업 커밋 검사 |
| `.github/workflows/pr-template-check.yml` | `pr-template-check` Job, PR 양식·브랜치·Issue·Closes 검사 |
| `.github/workflows/issue-policy.yml` | `issue-policy` Job, 위반 Issue 라벨 추가/수정 후 제거 |
| `.github/workflows/project-tests.yml` | 정책 OS matrix + 기존 4개 격리 테스트, 최종 `project-tests` Job |
| `.github/labels.json` | 유형 7개·영역 8개·상태 5개의 색·설명 카탈로그 |
| `.github/scripts/collaboration_labels.py` | 유형/영역/상태 동기화, Issue Type, PR 책임자 처리 |
| `.github/scripts/tests/test_collaboration_labels.py` | 수동 라벨/담당자 보존, 멱등성, 외부 작성자·파일 누락 등 회귀 검사 |
| `.github/workflows/collaboration-labels.yml` | 기본 브랜치 코드로 Issue/PR 메타데이터 자동 분류 |
| `.coderabbit.yaml` | 한국어·비 Draft 자동/후속 리뷰·자동 승인 비활성·실제 경로별 지침 |
| `AGENTS.md` | GitHub 협업 규칙만 담은 에이전트 지침. 선행 로컬 메모리 설정은 포함하지 않음 |
| `docs/dev-rules.md` | 개발/AI 작업 규칙, Hook 통합, Ruleset 적용, 실패 해결, 작성 예시 |
| `docs/github-collaboration-verification.md` | 이 보고서 |

## PR에 포함하는 수정 파일 2개

- `.gitattributes`: 확장자 없는 `.githooks/*`도 LF로 체크아웃하도록 한 줄 추가.
- `claude.md`: 원격 main의 기존 본문 뒤 GitHub 규칙 요약만 추가. 선행 미커밋 AGENTS import는 포함하지 않았다.
  대문자 이름의 중복 파일은 생성하지 않았다.

기존 `.gitignore`와 기존 agent-context·rulepack·애플리케이션·시나리오·인프라는 수정하지 않았다.
주 작업 디렉터리의 미추적 AGENTS.md와 claude.md·.gitignore·agent-context·rulepack 변경은 그대로 보존했다.
새 Worktree에는 GitHub 협업 지침만 작성해 선행 Shared Memory 설정이나 존재하지 않는 문서 참조를 포함하지 않았다.
최종 변경은 PR Files changed 또는 `git diff origin/main...HEAD`로 확인한다.

## 실제 검증 결과

실행 환경: macOS arm64 / Python 3.11.15. 임시 가상환경에 기존 requirements와 README의 `rich`를 설치했다.
검증용 `jsonschema`와 `actionlint`도 임시 경로에만 사용했으며 앱 의존성 파일을 추가/변경하지 않았다.

| 검사 | 기대 / 관측 | 판정 |
|---|---|---|
| 정상 커밋, 허용 type 7개, CRLF 메시지 | PASS / PASS | PASS |
| type 오류·요약 없음·Issue 없음·0번·잘못된 번호 | FAIL / FAIL | PASS (정상 거부) |
| PR 제목 오류·브랜치 형식/Issue 불일치 | FAIL / FAIL | PASS (정상 거부) |
| 필수 섹션 누락·빈 HTML 예시·TODO·fenced 가짜 양식 | FAIL / FAIL | PASS (정상 거부) |
| 미완성/잘못된/주석·코드 속 Closes, 여러 Issue 종료 | FAIL / FAIL | PASS (정상 거부) |
| 완성된 PR 양식·테스트 결과·미실행 사유 | PASS / PASS | PASS |
| 실제 열린 Issue 존재 검사, PR 번호/닫힌 Issue 차단 | API mock 정상/실패 사례 | PASS (로컬 모의 검증) |
| 전체 커밋 페이지·수량 대조, 250개 초과/누락·API 403 | 실패 시 검사 차단 | PASS (로컬 모의 검증) |
| Issue 위반 라벨 지정/수정 후 제거 | API mock | PASS (로컬 모의 검증) |
| 실제 commit-msg 실행, 위조 Merge 거부/실제 merge context 허용 | 임시 Git 저장소, 실제 Hook 프로세스 | PASS |
| 정책 테스트 합계 | 36 tests, OK (코드블록·라벨/담당자 회귀 포함) | PASS |
| Pipeline 기존 격리 테스트 | 100 tests, OK | PASS |
| Remediation 기존 격리 테스트 | 270 tests, OK | PASS |
| Network 기존 격리 테스트 | 100 tests, OK | PASS |
| Observer 기존 격리 테스트 | 12 tests, OK | PASS |
| 기존 애플리케이션 테스트 합계 | 482 tests, OK | PASS |
| YAML 구문 / Issue Forms 출력 호환 | 설정 파싱, Form 생성 본문을 검사기에 입력 | PASS |
| CodeRabbit 공식 JSON Schema | jsonschema.validate 성공 | PASS |
| GitHub Workflow 정적 검사 | actionlint 1.7.12, 4개 Workflow, exit 0 | PASS |
| CODEOWNERS | 전역 패턴 구문, 두 실제 사용자·write 권한 API 확인 | PASS |
| 기존 파일·브랜치·Worktree·HEAD·hooksPath | 주 작업 디렉터리의 모든 미커밋 파일 보존. 새 브랜치·Worktree만 추가 | PASS |
| Windows/Linux 실제 Hook 실행 | CI matrix만 구성; 원격 실행 없음 | BLOCKED (원격 반영 전) |
| GitHub Actions 실제 실행·fork 이벤트 정책 | 원격 미반영; 설정 읽기만 수행 | BLOCKED |
| CodeRabbit 실제 한국어/후속 자동 리뷰 | App 설치 확인, YAML 작성; ready PR 실행 없음 | BLOCKED |
| CODEOWNERS 실제 자동 리뷰 요청 | base 브랜치 미반영 | BLOCKED |
| Ruleset/필수 체크 연결·사람 승인·병합 차단 | 관리자 설정 미적용 | BLOCKED |

후속 협업 분류 검증: 저장소의 기존 라벨 9개는 보존하고 관리 라벨 20개를 추가했다.
실제 Issue #25에는 `type:ci`, `area:github`, `area:docs`, `status:open`, 담당자 `galgalrobot`, 기본 Type `Task`를 적용했다.
실제 PR #26에는 `type:ci`, `area:github`, `area:docs`, `status:in-review`, 담당자 `galgalrobot`을 적용했으며
사람 리뷰 요청 대상 `gicks04`를 유지했다. 새로운 자동 분류 Workflow는 기본 브랜치 반영 후 작동한다.

초기 Network 검사는 `rich` 누락과 샌드박스의 루프백 bind 제한으로 실패했다.
기존 README의 rich를 CI 설치에 포함하고, Python 3.11 임시 환경에서 테스트 전용 루프백 접근을 허용해 다시 실행했다.
기존 `testing/run_isolated.py`의 Docker·외부 socket/DNS·subprocess 차단은 유지했으며 최종 100개가 통과했다.
테스트의 HTTP/Docker/Slack 성공 로그는 모의 응답이다. 실제 운영 호출·조치·E2E 완료를 의미하지 않는다.

공식 CodeRabbit 스키마 다운로드 SHA256:
`53ca372d5bbfefd61e2bad9ab5ef399e69d1e06b07a73221b006d83682a743fa`.
`request_changes_workflow`가 legacy alias인 것을 확인하고 `auto_approvals.enabled: false`도 명시했다.
Hook/메타데이터 검사에는 새 런타임 라이브러리가 필요하지 않다.

## 원격 적용·수동 작업

1. Issue #25와 `ci/25-github-collaboration` 브랜치로 **이번 변경만** 분리했다. 기존 main의 작업은 보존했다.
2. 사용자 명시 승인에 따라 Commit·Push·도입 PR을 진행한다. 초기 base에 검사기가 없으므로 bootstrap 절차를 따른다.
3. CODEOWNERS를 base에 반영하고 작성자 외 사람이 실제 자동 요청되는지 확인한다. 수동 요청 방법도 dev-rules에 있다.
4. CodeRabbit 관리 화면에서 저장소 자동 리뷰·이용 플랜/한도를 확인하고 ready PR/추가 push로 리뷰를 검증한다.
5. 관리자 승인 후 Ruleset에 PR 필수, 사람/Code Owner 승인 1명, 새 커밋 승인 만료, 대화 해결,
   force push/삭제 금지, 관리자 우회 제한을 적용한다.
6. 실제 Check 이름 **`commit-lint`, `pr-template-check`, `project-tests`**를 Required Status Check로 지정한다.
   GitHub Actions를 기대 소스로 선택하고 최신화 정책을 확인한다.
7. squash 제목 기본값을 PR title로 검토·변경하고 최종 커밋 제목을 병합 전에 확인한다.
8. 정상/실패 검증 PR로 Merge 버튼 차단과 재승인을 확인한다. 그 전에는 병합 차단 검증 완료로 표시하지 않는다.
9. 개발자별 기존 Hook과 Worktree 영향을 확인한 뒤 로컬 Hook을 선택 활성화한다. core.hooksPath를 자동 덮어쓰지 않는다.

메뉴 경로·활성화 옵션·적용 전후 검증·Issue/Commit/PR 복사 예시는
[dev-rules.md](dev-rules.md)에 정리했다. 원격 설정 변경은 이번 작업에서 실행하지 않았다.
