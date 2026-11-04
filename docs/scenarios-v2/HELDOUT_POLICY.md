# 평가용(heldout) 취급 정책

> 정책만 적는다. 평가용 변형의 내용·목록·분할 규칙은 이 문서에 없다.

## 대상 경로 (`.gitignore` 등록)
- `docs/scenarios-v2/heldout/` — 평가용 설계 문서, 분할 seed 규칙
- `scenarios/v2/heldout/` — 평가용 변형 코드(앞으로 만들 것)

레지스트리(`scenarios/v2/registry.py`)는 `scenarios/v2/heldout/` 이 있으면 선택적으로 읽고, 없으면 조용히 건너뛴다.
저장소에 이 폴더가 없어도 모든 테스트와 `--dry-run` 이 통과해야 한다.

## 규칙
1. **평가용은 룰 동결 후에 공개한다.** 그 전에는 커밋하지 않는다.
2. **`git add -f` 금지.** 무시 규칙을 우회해 평가용 파일을 스테이징하지 않는다.
3. **커밋 전 `git check-ignore` 로 확인한다.** 아래 점검이 모두 통과해야 커밋한다.
4. 평가용 내용을 `THREAT_SPEC.md`·`VARIANTS.md`·레지스트리 본체·주입 코드·LLM 프롬프트·커밋 메시지·PR 본문에 옮겨 적지 않는다.

## 커밋 전 점검
```bash
git check-ignore -v docs/scenarios-v2/heldout/ scenarios/v2/heldout/
```
두 줄 모두 `.gitignore:<행>:<패턴>` 으로 나와야 한다(아무것도 안 나오면 무시되지 않는 것 — 커밋 중단).

```bash
git diff --cached --name-only | grep -i heldout && echo "STOP: 평가용 파일이 스테이징됨" || echo "OK"
```

```bash
git ls-files | grep -i heldout && echo "STOP: 평가용 파일이 추적 중" || echo "OK"
```

## 백업 (저장소 밖)
평가용 폴더는 git 에 없으므로 저장소 밖에 따로 백업한다. 저장소 루트에서 실행:

```bash
mkdir -p ~/aiops-private/heldout-backup/docs ~/aiops-private/heldout-backup/scenarios
```

```bash
rsync -a docs/scenarios-v2/heldout/ ~/aiops-private/heldout-backup/docs/ && rsync -a scenarios/v2/heldout/ ~/aiops-private/heldout-backup/scenarios/
```

시점별로 남기려면:

```bash
tar -czf ~/aiops-private/heldout-backup/heldout-$(date +%Y%m%d-%H%M).tar.gz docs/scenarios-v2/heldout scenarios/v2/heldout
```

측정 PC(Windows, PowerShell)에서는:

```powershell
robocopy docs\scenarios-v2\heldout "$HOME\aiops-private\heldout-backup\docs" /E; robocopy scenarios\v2\heldout "$HOME\aiops-private\heldout-backup\scenarios" /E
```

복원은 같은 명령에서 원본과 대상을 바꾼다. 백업 폴더는 git 저장소·클라우드 동기화 폴더 안에 두지 않는다.

## 룰 동결 후 공개 절차
1. 룰 작성자가 룰 동결을 선언한다(동결 시점의 룰 커밋 해시를 기록).
2. 평가 회차를 마친 뒤, `.gitignore` 에서 두 경로를 지우는 변경과 평가용 파일 추가를 **한 커밋**으로 만든다.
3. 그 커밋 메시지에 동결 룰 커밋 해시를 적는다.
