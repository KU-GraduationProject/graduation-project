# GitHub 협업 규칙

- 작업 시작 전 실제 GitHub Issue와 완료 조건을 확인한다. Issue 1개 = 작업 Branch 1개 = PR 1개이며, PR에 여러 커밋을 포함할 수 있다.
- 작업 브랜치는 `<type>/<issue-number>-<description>`이다. 기본 브랜치에 직접 커밋하지 않는다. 기존 미커밋 작업과 Worktree를 보존한다.
- 일반 커밋과 PR 제목은 `[type] 요약 (#이슈번호)`이며 type은 feat, fix, docs, test, refactor, chore, ci 중 하나다.
- PR은 `.github/pull_request_template.md`를 사용하고 같은 Issue를 `Closes #숫자`로 연결한다. 사람 리뷰어를 지정한다.
- 실행하지 않은 테스트를 통과로 기록하지 않는다. 테스트 결과 또는 미실행 사유와 후속 검증을 작성한다.
- CodeRabbit 지적은 수정하거나 근거를 남긴다. 사람 승인과 필수 CI를 우회하지 않는다.
- 사용자의 명시적 승인 없이 Commit, Push, PR 생성, Merge를 수행하지 않는다. 기존 보호 설정과 core.hooksPath를 임의 변경하지 않는다.
- 상세 절차와 Required Status Check 이름은 `docs/dev-rules.md`를 따른다.
