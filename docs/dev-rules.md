# GitHub 개발·리뷰 규칙

Issue 1개 = 작업 Branch 1개 = PR 1개. 하나의 PR에는 여러 커밋을 포함할 수 있다.
이 문서는 새 작업부터 적용한다. 기존 PR #23·#24와 진행 중 Worktree는 기존 이력을 보존하고,
담당자가 Issue 연결·브랜치·커밋·PR 양식을 정리한 뒤 필수 검사 도입 일정을 합의한다.
일괄 rebase, 기존 브랜치 이름 변경, 강제 푸시로 전환하지 않는다.

## 1. Issue → Branch → Commit

1. GitHub **Issues → New issue**에서 Feature, Bug, Docs 또는 Task / Chore Form을 선택한다.
   작업 목적·범위·완료 조건·검증 방법을 실제 내용으로 작성한다.
2. Issue 제목은 `[type] 작업 제목`이다. type은 `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `ci`다.
   문서는 Docs Form을 선택하면 `[docs]` 제목과 문서 라벨이 기본 적용된다.
3. 실제 발급된 Issue 번호로 `<type>/<issue-number>-<description>` 브랜치를 만든다.
   description은 영문 소문자·숫자·하이픈을 사용한다. 예: `feat/12-user-auth`.
4. 일반 커밋 제목은 `[type] 요약 (#이슈번호)`다. 모든 작업 커밋의 Issue 번호는 PR/브랜치와 같아야 한다.
   같은 작업의 테스트·문서 커밋은 type이 달라도 된다. 기본 브랜치에 직접 커밋하지 않는다.

빈 Issue 버튼은 숨긴다. API·CLI로 생성한 Issue까지 사전 차단하는 기능은 아니다.
`issue-policy`는 새 Issue·수정·재오픈 때 검사하고 위반 시 `needs-issue-update` 라벨을 붙이며 실패한다.
수정하면 라벨을 제거한다. 기존 Issue는 자동 일괄 수정하지 않는다. 라벨 API가 차단되면 관리자가 권한을 확인한다.
Feature/Bug/Docs/Task별 필수 본문은 Form과 `.github/scripts/collaboration.py`에 정의한다.

### 라벨·담당자·리뷰어

작업 유형은 **주된 목적 하나**, 영역은 **실제 변경 범위 여러 개**, 상태는 **현재 단계 하나**로 구분한다.
라벨의 색과 설명은 `.github/labels.json`에 관리한다. 기존 `bug`, `documentation` 등의 라벨도 보존한다.

| 구분 | 값 | 적용 기준 |
|---|---|---|
| 유형 | `type:feat`, `type:fix`, `type:docs`, `type:test`, `type:refactor`, `type:chore`, `type:ci` | 제목의 `[type]`에 맞는 라벨 하나 |
| 영역 | `area:github`, `area:docs`, `area:pipeline`, `area:remediation`, `area:observability`, `area:infra`, `area:scenarios`, `area:tooling` | PR은 변경 파일에서 계산, Issue는 담당자가 선택 |
| Issue 상태 | `status:open`, `status:done`, `status:closed` | 열림 / 완료 종료 / 진행하지 않음 등의 종료 |
| PR 상태 | `status:draft`, `status:in-review`, `status:done`, `status:closed` | Draft / 정식 PR 리뷰 단계 / 병합 / 미병합 종료 |
| Issue 기본 Type | `Feature`, `Bug`, `Task` | feat → Feature, fix → Bug, 나머지 → Task |

예를 들어 CI 설정과 문서를 함께 바꿨다면 `type:ci` + `area:github` + `area:docs`를 사용한다.
문서 파일이 포함됐다는 이유로 주된 작업 유형까지 `type:docs`로 중복 지정하지 않는다.
`status:in-review`는 정식 PR의 검토 단계이며 사람의 승인 완료를 뜻하지 않는다. 실제 승인은 Reviews에서 확인한다.
Issue의 Type 필드와 달리 PR은 유형 라벨로 구분한다.

담당자와 리뷰어는 서로 다른 역할이다.

- **Issue Assignees**: 구현 책임자. 작업 시작 전에 실제 담당자를 지정한다. 외부 제보자를 자동 담당자로 지정하지 않는다.
- **PR Assignees**: 변경 책임자. 미지정이면 write 권한이 확인된 사람 작성자를 자동 지정하며 기존 담당자는 유지한다.
- **PR Reviewers**: 작성자 이외 사람. CODEOWNERS 자동 요청을 확인하고 필요하면 수동으로 요청한다.
  Issue에는 PR과 같은 리뷰 요청 필드가 없으므로 리뷰 책임은 연결된 PR에서 관리한다.

현재 작업 #25/#26은 담당자 `galgalrobot`, 사람 리뷰어 `gicks04`로 구분했다.
새 자동화는 Issue/PR 생성·제목 수정·재오픈·종료, PR 커밋 추가·Draft/ready 전환 때 실행한다.
기존 사용자 라벨은 전체 교체하지 않는다. 제목 유형을 바꾸면 이전 관리 유형 라벨을 정리하고,
PR 파일 변경 시 관리 영역 라벨을 갱신한다. Issue의 수동 영역 라벨은 보존한다.
라벨 카탈로그에 없는 사용자 라벨·우선순위·기존 담당자는 자동 변경하지 않는다.

**현재 Issue/PR 메타데이터는 이미 적용했다.** 향후 자동 분류와 Form 기본값은 이 PR이 기본 브랜치에 반영된 뒤 작동한다.
Workflow는 신뢰하는 기본 브랜치의 코드만 실행하며 PR head 코드를 쓰기 권한으로 실행하지 않는다.
조직 Issue Type 자체를 생성/변경하지 않고, 조회로 확인된 기존 Type만 사용한다.
([공식 Issue Forms 라벨·Type 설정](https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/syntax-for-issue-forms))

GitHub 목록 검색 예시:

```text
is:issue is:open label:"type:docs"
is:issue is:open assignee:galgalrobot
is:pr is:open label:"type:feat"
is:pr is:open label:"area:github" label:"status:in-review"
is:pr is:open review-requested:gicks04
```

### 로컬 commit-msg Hook

Hook 파일은 제공하지만 **자동 설치·활성화하지 않는다**. 기존 Hook을 확인한 후 개발자가 적용한다.

```sh
git config --show-origin --get core.hooksPath
git rev-parse --git-path hooks
# 위 hooks 디렉터리의 기존 commit-msg와 다른 Hook을 확인한다.
```

`core.hooksPath`가 없고 기존 활성 Hook도 없을 때만 아래 설정을 선택할 수 있다.

```sh
git config --local core.hooksPath .githooks
```

이 설정은 같은 Git 저장소의 연결 Worktree에도 영향을 줄 수 있다. 모든 작업자와 합의한다.
이미 경로/Husky/Hook이 있으면 설정을 덮어쓰지 않는다. 기존 commit-msg에서 기존 검사를 유지하면서
`sh "$(git rev-parse --show-toplevel)/.githooks/commit-msg" "$1"`을 호출하고 실패 코드를 전달하도록 직접 병합한다.
기존 Hook이 `exec`로 끝나면 호출 순서를 검토한다. `--no-verify`로 실패를 우회하지 않는다.

Python 3과 POSIX sh(Windows는 Git Bash)가 필요하다. Hook은 python3 → python → py -3 순으로 찾는다.
파일은 LF로 체크아웃하며 CRLF/BOM 커밋 메시지도 처리한다. 실패 이유와 올바른 예시를 출력한다.
실제 merge 진행 중인 `MERGE_HEAD`와 `Merge ...` 제목만 로컬 예외다. 원격에서는 부모가 2개 이상인
실제 merge commit만 예외다. 일반 커밋이 `Merge`로 시작하는 것만으로 통과하지 않는다.
Revert·GitHub Revert·fixup/squash 임시 제목은 자동 면제하지 않는다. 최종 PR 전에 규칙에 맞게 고친다.
예: `[fix] 잘못된 인증 변경 되돌리기 (#12)`.

## 2. PR 작성과 검사

기본 브랜치 `main` 대상으로 `.github/pull_request_template.md`를 사용한다.
PR 제목은 커밋과 같은 형식이다. `관련 이슈`에는 `Closes #12`처럼 **실제 열린 Issue 하나**를 한 줄로 적는다.
PR 번호, 다른 저장소 Issue, 미완성 `Closes #`, HTML 주석·코드블록 속 예시는 허용하지 않는다.
GitHub는 기본 브랜치 대상으로 하는 closing keyword를 Issue에 연결하고 병합 시 종료한다.
([공식 Issue 연결 규칙](https://docs.github.com/en/issues/tracking-your-work-with-issues/using-issues/linking-a-pull-request-to-an-issue))

필수 섹션은 `개요`, `관련 이슈`, `변경 사항`, `테스트`, `리뷰 포인트`, `체크리스트`다.
각 섹션에 실제 내용을 작성한다. `테스트`에는 수행한 검사/명령과 `PASS`, `FAIL`, `통과` 등의 결과를 적는다.
미실행이면 `미실행. 사유: 구체적인 이유`와 후속 검증 계획을 적는다. 실행하지 않은 테스트를 통과로 쓰지 않는다.
체크리스트 6개 항목은 남겨 두되 실제 수행 상태에 맞게 표시한다. 검사기는 결과의 진실성을 증명하지 못하므로 리뷰어가 확인한다.

| 검사 Job 이름 | 검사 범위 |
|---|---|
| `commit-lint` | PR 제목, 전체 PR 작업 커밋 형식·Issue 일치, 실제 merge 예외 |
| `pr-template-check` | 제목·브랜치 형식, 같은 Issue 번호, 실제 열린 Issue, Closes, 필수 섹션·테스트 보고 |
| `project-tests` | 아래 모든 정책/애플리케이션 테스트 matrix가 success인지 집계 |

메타데이터 검사는 PR 생성·수정·재오픈·커밋 추가·ready 전환 때 실행한다. PR 검사는 리뷰 요청 변경 때도 실행한다.
PR API를 페이지 끝까지 읽고 커밋 수와 대조한다. REST 최대 250개를 넘으면 누락 통과 대신 실패하며 PR 분할이 필요하다.
([공식 PR 커밋 API](https://docs.github.com/en/rest/pulls/pulls#list-commits-on-a-pull-request))

메타데이터 Workflow의 `pull_request_target`은 **기본 브랜치의 스크립트만 실행**한다.
PR head checkout, PR 산출물 실행, 캐시 복원, 사용자 입력의 Shell 직접 삽입을 추가하지 않는다.
토큰은 필요한 읽기 권한만 사용하며 Issue 라벨 Workflow만 `issues: write`다.
공개 저장소의 `pull_request_target` 이벤트 정책도 확인해야 한다.
([공식 보안/이벤트 정책](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target))

### 프로젝트 테스트

```sh
python -m unittest discover -s .github/scripts/tests -v
python testing/run_isolated.py pipeline
python testing/run_isolated.py remediation
python testing/run_isolated.py network
python testing/run_isolated.py observer
```

애플리케이션 테스트는 서비스 requirements와 README에 명시된 기존 `rich` 의존성을 설치한 환경에서 실행한다.
CI는 Python 3.11에서 기존 격리 실행기 4개를 Ubuntu matrix로 실행하며 Docker·외부 IO 차단을 보존한다.
협업 검사와 실제 Hook fixture는 Ubuntu/macOS/Windows matrix에서 실행하도록 구성했다.
`project-tests`는 matrix 실패·취소·skip도 성공으로 처리하지 않는다. 필수 Workflow에 paths 필터는 두지 않는다.
실제 Docker·LLM·Slack·2대 PC E2E, Fluentd Ruby, 시나리오 전체를 검증하는 CI는 아니다.
기존 requirements의 넓은 버전 범위는 보존했으므로 의존성 갱신으로 CI 결과가 달라질 수 있다.
Merge queue는 이번 범위에서 구성하지 않았다. 도입 전에 `merge_group` 검증을 별도로 설계한다.

## 3. 리뷰어와 CodeRabbit

현재 확인된 협업자는 `galgalrobot`, `gicks04` 두 명이며 둘 다 저장소 admin/write 권한이 있다.
별도 디렉터리 소유권 합의가 없어 `.github/CODEOWNERS`의 전역 기본 소유자로 두 명을 등록한다.
PR 작성자 본인은 자동 리뷰 요청/승인을 대신할 수 없으며 다른 소유자가 검토한다.
Draft는 ready 전환 시 자동 요청된다. CODEOWNERS는 PR의 **base 브랜치에 반영된 뒤** 작동한다.
공개 저장소는 GitHub Free에서도 이 기능을 사용할 수 있다.
([공식 CODEOWNERS 지원·동작](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners))

자동 요청이 없으면 PR 우측 **Reviewers**에서 작성자 이외 사람을 지정한다.
권한과 실제 로그인 확인 후 수동 요청도 가능하다. 아래 `PR_NUMBER`, `REVIEWER_LOGIN`은 실제 값으로 교체한다.

```sh
gh pr edit PR_NUMBER --add-reviewer REVIEWER_LOGIN
```

리뷰 요청이 없으면 PR 검사 로그에 안내한다. 이미 리뷰한 사람은 요청 목록에서 사라질 수 있어 요청 부재만으로 실패시키지 않는다.
**사람 승인 1명과 Code Owner 승인**은 아래 Ruleset으로 요구한다. 봇 리뷰로 대신하지 않는다.

CodeRabbit App은 2026-11-11 조회에서 조직 전체 저장소에 설치되어 있고 suspend되지 않았다.
`.coderabbit.yaml`은 한국어, 비 Draft 자동 리뷰, push 후 추가 리뷰, 스타일 지적 최소화,
경로별 API·인증·안전 게이트·관측·테스트 검토를 설정한다. 비공개 heldout·인증서·.env는 제외한다.
`request_changes_workflow: false`는 현재 공식 스키마에서 이전 호환용 별칭이다.
현재 설정인 `auto_approvals.enabled: false`도 명시했다.
([공식 설정 참조](https://docs.coderabbit.ai/reference/configuration), [공식 스키마](https://coderabbit.ai/integrations/schema.v2.json))
YAML만으로 실제 자동 리뷰 실행을 보장하지 않는다. CodeRabbit 관리 화면에서 이 저장소의 자동 리뷰·플랜·사용량을 확인하고,
ready PR에서 한국어 리뷰 생성과 후속 push 리뷰를 확인한다. 지적은 수정하거나 재현 결과·설계 근거로 답한다.
CodeRabbit 상태 체크는 기본 필수 체크 목록에 포함하지 않는다. 필요 시 별도 합의하며 사람 승인은 유지한다.

## 4. 관리자 적용: Ruleset / Branch Protection

**이 문서 작성 시 원격 설정은 변경하지 않았다.** 공개 저장소이므로 Ruleset 지원 대상이다.
현재 admin 권한은 확인했으나 조직 요금제 명칭은 조회하지 않았다. 기존 Ruleset/Protection이 생겼다면 먼저 비교하고 병합한다.
([지원 범위·설정 권한](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository))

1. 먼저 도입용 Issue와 작업 브랜치를 준비하고 사용자 명시 승인 후 커밋·푸시·도입 PR을 만든다.
   이번 도입은 Issue #25의 `ci/25-github-collaboration` 브랜치와 전용 Worktree를 사용한다.
   기존 사용자 변경과 섞어 `git add .` 하지 않는다.
   필요한 새 파일과 `.gitattributes`·`AGENTS.md`·`claude.md`의 이번 추가 부분만 검토해 전달한다.
   주 작업 디렉터리의 선행 AGENTS/claude·agent-context 변경은 이번 PR에 포함하지 않는다.
2. 도입 PR에서는 base에 아직 스크립트가 없어 `pull_request_target` 검사가 작동하지 않을 수 있다.
   사람 리뷰와 로컬 검증·`project-tests`를 확인해 도입한 후, 승인된 별도 검증 PR로 3개 체크를 실제 실행한다.
   이 도입 전에는 새 필수 체크를 활성화하지 않는다. 기존 PR 이력은 자동 재작성하지 않는다.
3. GitHub 저장소 **Settings → Rules → Rulesets → New ruleset → New branch ruleset**.
   이름은 예를 들어 `main-collaboration`. Target은 **Default branch**. 기존 규칙을 삭제/교체하지 않는다.
4. 아래 옵션을 검토하고 승인 후 활성화한다.
   - **Require a pull request before merging**, **Required approvals: 1**.
   - **Require review from Code Owners**: 실제 사람 소유자 중 작성자 이외 1명 승인.
   - **Dismiss stale pull request approvals when new commits are pushed**.
   - **Require conversation resolution before merging**.
   - **Require status checks to pass**: `commit-lint`, `pr-template-check`, `project-tests`.
     실제 첫 실행의 check 이름/발행 App을 확인하고 가능하면 **GitHub Actions**를 기대 소스로 선택한다.
   - **Require branches to be up to date before merging**를 검토한다.
   - **Block force pushes**, **Restrict deletions**.
   - Bypass list는 기본 비움. 관리자도 검증을 거치도록 한다. 긴급 예외는 별도 합의와 기록이 필요하다.
   - Enforcement를 **Active**로 저장한다. Disabled 상태는 병합을 차단하지 않는다.
5. Rulesets를 못 쓰면 **Settings → Branches → Add branch protection rule**, pattern `main`에서
   같은 PR/승인/Code Owner/상태 체크/대화 해결/최신화 옵션을 적용한다.
   Force pushes·deletions는 허용하지 않고 **Do not allow bypassing the above settings**를 검토한다.
6. **Settings → General → Pull Requests**에서 Squash를 우선 검토한다.
   Squash 기본 제목을 **Pull request title**로 선택한다. 현재는 `COMMIT_OR_PR_TITLE`이며 변경하지 않았다.
   merge 직전 최종 제목도 `[type] 요약 (#숫자)`인지 확인한다. UI에서 제목을 임의 수정하면 사전 검사만으로 보장되지 않는다.
7. Commit metadata 제한은 플랜/UI 지원 확인 후 별도 도입한다.
   본문/merge/revert/기존 이력까지 차단할 수 있어 이번에는 설정하지 않았다.

[공식 Ruleset 옵션·상태 체크](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)

### 적용 전후 검증

적용 전에는 보호 없는 `main`과 빈 Ruleset 목록을 확인했다. 적용 후 관리자/리뷰어는 승인된 검증 PR에서 다음을 확인한다.

- 잘못된 커밋·PR 제목·누락 섹션·미완성 Closes로 실제 체크가 실패하고 **Merge 버튼이 차단**되는지.
- 정상 양식이어도 사람/Code Owner 승인 전에는 차단되는지. 새 커밋 후 승인이 만료되는지.
- 정상 체크 + 작성자 이외 사람 승인 + 대화 해결 + 최신화 후에만 병합 가능한지.
- 체크를 재실행하면 실패가 재현되고, 올바르게 수정하면 최신 커밋 검사로 바뀌는지.
- API/UI에서 Ruleset Active, 대상 기본 브랜치, 3개 체크와 기대 소스, 관리자 우회 금지를 재확인한다.

실제 보호 옵션 적용과 위 음성 검증 전에는 **병합 차단 검증 완료**라고 기록하지 않는다.
강제 푸시/브랜치 삭제로 운영 브랜치를 시험하지 않는다.

## 5. CI 실패 해결과 Merge 기준

- `commit-lint`: 실패 SHA의 제목·Issue 번호를 확인한다. 아직 push하지 않은 본인 커밋만 규칙에 맞게 정리한다.
  공유 이력 변경·강제 push는 수행하지 않고 작업자와 안전한 이관을 합의한다.
- `pr-template-check`: 본문을 Edit하여 실제 내용을 채우고 열린 Issue 번호·branch/base를 확인한다.
  API 403/404는 토큰 권한/Issue 접근성/정책을 확인한다. 실패를 무시해 성공을 출력하지 않는다.
- `issue-policy`: Issue 제목·필수 본문을 보완한다. 생성 차단기가 아니다.
- `project-tests`: matrix 상세 로그에서 실패 suite를 찾아 같은 격리 명령으로 재현한다.
  의존성 오류와 기능 회귀를 구분한다. 실제 Docker/Slack 연결로 격리 검사를 우회하지 않는다.
- Merge: 필수 검사 전체 통과, 작성자 이외 사람/Code Owner 승인 1명, 리뷰 지적 대응, 관련 Issue/문서 확인 후 수행한다.
  AI 에이전트는 사용자의 명시적 승인 후에만 Commit·Push·PR 생성·Merge를 수행한다.

## 6. 복사 가능한 작성 예시

아래 `12`는 형식 예시다. 이번 작업에서 Issue #12를 새로 만든 것이 아니다. 실제 발급된 **작업 Issue** 번호로 모두 바꾼다.

Issue 제목:

```text
[ci] GitHub 협업 규칙과 자동 리뷰 검사 구축
```

Task / Chore Issue 본문 (Docs도 같은 필수 섹션 사용):

```markdown
### 작업 목적
Git 규칙과 리뷰·테스트 기준을 일관되게 적용한다.
### 작업 항목
- Issue/PR 양식, 커밋 검사, CI, 리뷰어 정책을 구성한다.
### 산출물
.github 설정, .githooks/commit-msg, .coderabbit.yaml, docs/dev-rules.md
### 완료 조건
정상/실패 사례 검사, 사람 리뷰, Required Status Check 적용 후 병합 차단을 확인한다.
```

Branch / Commit 제목:

```text
ci/12-github-collaboration
[ci] GitHub 협업 규칙과 자동 리뷰 검사 구축 (#12)
```

PR 제목은 위 커밋 제목과 같다. PR 본문 예시는 아래 양식을 복사하되 **테스트 결과를 실제 실행 결과로 교체**한다.

```markdown
## 개요
Git 규칙 위반을 검사하고 리뷰·테스트 후 병합하는 절차를 추가한다.
## 관련 이슈
Closes #12
## 변경 사항
Issue/PR Forms, commit-msg Hook, GitHub Actions, CodeRabbit 및 협업 문서 추가.
## 테스트
미실행. 사유: 이 본문은 작성 예시다. 실제 PR 전에 로컬 검사와 CI를 실행해 결과를 기록한다.
## 리뷰 포인트
필수 상태 체크 이름, fork 안전성, 실제 사람 승인 및 기존 작업 보존을 확인한다.
## 체크리스트
- [ ] 관련 Issue 연결
- [ ] 로컬 테스트 완료
- [ ] 기존 기능 영향 확인
- [ ] 필요한 문서 수정
- [ ] 리뷰어 지정
- [ ] 민감정보 포함 여부 확인
```
