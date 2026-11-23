# Remediation 개선 로컬 검증 기록 — 선행 P0 단계

이 문서의 646개 결과는 선행 P0 검증 기록이다. DB·배포·앱 API 및 Leafy 백엔드를 추가한 후속 결과는
[확장 실행기 검증](EXTENDED_EXECUTORS_VERIFICATION.md)을 따른다.

검증일: 2026-11-11 KST. 작업 브랜치 `feat/35-remediation-improvements`.
실행 환경: macOS, Python 3.11.15. 기준 head `49245e120191b84642e17a910ca9278e368f7966`
(선행 Socket Mode PR #32), 확인한 main `0443c6f56104652f06eb68c6f3a18e3c63f99265`.
커밋·푸시·PR·병합·운영 활성화는 수행하지 않았다.

## 요구사항 근거

[Notion 개선안](https://app.notion.com/p/415e7f8a345d80da9007e2a231868c85)의 본문과 7장의 모든 토글을 읽고,
현재 코드의 Policy Engine, RecordStore, Slack Socket Mode, Docker 실행기와 원격 Agent를 대조했다.
개발 종료 시 다시 조회한 원본 수정 시각도 `2026-11-11T14:03:58.052Z`로 동일했다.
개발용 원문 snapshot SHA256:
`a596b9c9ba186cc2077c926b03345411ff325bdc12bf112f69185c193765ad40`.
코드·검증·후속 조건의 대응은 [구현 설명](REMEDIATION_IMPROVEMENTS.md)의 추적표에 있다.

## 실행 결과

준비된 Python 환경으로 저장소 루트에서 실행했다. 아래 `python`은 해당 3.11.15 환경을 뜻한다.

| 명령 | 결과 | 수 |
|---|---|---:|
| `python testing/run_isolated.py remediation` | PASS | 355 |
| `python testing/run_isolated.py pipeline` | PASS | 143 |
| `python testing/run_isolated.py network` | PASS | 100 |
| `python testing/run_isolated.py observer` | PASS | 12 |
| `python -m unittest discover -s .github/scripts/tests` | PASS | 36 |
| 합계 | PASS | 646 |
| `python -m compileall -q aiops/remediation aiops/pipeline` | PASS | 문법/바이트코드 검사 |
| `git diff --check` | PASS | 공백 오류 없음 |
| `docker compose -f docker-compose.yml config --quiet` | PASS | 비밀값 없는 placeholder 환경 |
| `docker compose -f docker-compose.aiops.yml config --quiet` | PASS | 비밀값 없는 placeholder 환경 |

Remediation 355개에는 선행 테스트와 이번 회귀가 모두 포함된다. 집중 테스트 수와 합산하지 않는다.
이 결과는 원격 GitHub CI 결과나 사람 리뷰 승인을 의미하지 않는다.

애플리케이션 테스트는 수집 전에 실제 Docker 생성자·socket 연결·DNS·subprocess·pipe를 차단한다.
네트워크 suite의 자신이 만든 `127.0.0.1` 임시 HTTP fixture만 예외다. 최초 sandbox 실행에서
그 임시 포트 bind가 OS 권한으로 차단되어 8개 오류가 났고, 같은 격리 실행기를 포트 bind가 허용되는
환경에서 실행해 100개가 통과했다. 외부 사이트나 실제 컨테이너에 연결한 검증이 아니다.
Compose config 검사는 구문만 확인하며 컨테이너 생성·시작·재시작을 하지 않았다.

## 핵심 안전 회귀

- 승인/거부 경쟁에서 한 상태 전이만 성공하고, 거부·만료·실행 후 승인은 재실행하지 않는다.
- 동일 사건/조치는 재전송·재시작 뒤 같은 레코드를 반환한다. 다른 조치·파라미터는 409다.
- 불완전한 identity/fingerprint/startsAt으로 실행 가능한 사건을 합성하지 않는다.
- 다른 Workspace/채널·변조한 버튼·없는 레코드·만료 승인은 Docker 변경 0회다.
- 지정 채널의 사용자별 허용 목록에 없는 구성원도 정상 승인하고 user.id를 감사 기록에 남긴다.
- 승인 전 고정한 Agent·전체 컨테이너 ID·이미지·라벨을 실행/복구 때 대조한다.
  교체된 컨테이너와 잘못된 PC/Agent는 실행하지 않는다.
- 로컬 inspect 지연, 원격 전달 지연, Agent 증거 저장 지연이 승인 만료를 넘기면 변경하지 않는다.
  이미 부분 변경이 있을 수 있는 실패는 UNKNOWN으로 남긴다.
- RESTART 실행 전 상태 증거를 보존하며 Docker 전체 환경변수·원시 로그는 수집하지 않는다.
- 상태 저장/rename/부모 디렉터리 fsync 실패는 실행을 막고, 실행 후 최종 저장 실패는 성공으로 응답하지 않는다.
- `/notify`는 승인 버튼·실행 레코드·Docker 호출이 없다. HMAC 서명이 유효해도
  notify_only 본문을 최초에 `/action`으로 보내면 요청 목적 불일치로 거부한다.
- 원격 UNKNOWN은 Agent 영속 기록으로 조회하며 retry:true 재전송은 차단한다.
- 재시작/Agent 상태 동기화로 복구 승인이 필요해진 기록은 최초 승인 창을 발행한다.
  이미 만료된 승인 창을 자동 연장하지 않는다.
- 32개 추천 어휘와 22개 후속 조치 계약은 일치하며 미구현 실행기는 모든 심각도에서 차단된다.

## 검증하지 않은 범위와 인수 조건

- 실제 Slack Socket Mode 연결, 채널 설정, 메시지 수신과 버튼 동작.
- PC 2 Windows Docker Desktop, Tailscale/HTTPS/ACL, 실제 Docker 변경·복구와 Zeek 재관측.
- Windows Host PostgreSQL 17 세션 종료·백업·복원·서비스 재시작. 현재 NOTIFY/수동 대응 범위다.
- DB·배포·앱 API·Nginx·MinIO·Host·관측·기록 실행기: 토글의 후보·위험도·선행 조건만 반영했고 실행 구현은 차단한다.
- Controller 단일 worker/replica와 영속 저장소 보존을 전제로 한다. 다중 프로세스 JSON 저장소와
  모든 전원/스토리지 장애에서의 exactly-once를 보장하지 않는다. Windows 네이티브 directory fsync는 미지원이다.
- 현재 한 관측 identity당 대상 하나다. 다중 대상에는 대상별 관측/승인 계약이 추가로 필요하다.

기본 운영값은 disabled, RCA 알림 opt-in false, 대상 bindings 빈 목록이다.
이후 실환경 인수는 [구현 설명](REMEDIATION_IMPROVEMENTS.md)의 설정 절차와 기존 원격 Agent 인수 기준을 따른다.

## 기존 작업 보존

별도 로컬 clone에서 개발했다. 원본 `graduation-project`의 backup 브랜치와 기존 Worktree,
미커밋 협업 설정·룰팩, 전역 설정·Hook, 인증정보·로컬 `.env`, 비공개 평가 자료는 수정하지 않았다.
Notion 페이지 내용도 변경하지 않았다. 작업 정의만 [Issue #35](https://github.com/KU-GraduationProject/graduation-project/issues/35)에 등록했다.
