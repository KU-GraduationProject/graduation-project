# Notion 기반 Remediation 개선 구현

후속 요청으로 DB·배포·앱 API의 실제 실행기 6개와 Leafy 관리자 API를 추가했다.
현재 확장 구현·운영 조건은 [실제 실행기 설명](EXTENDED_EXECUTORS.md)을 따른다.
현재 코드에서 새 6개는 수동 승인 경로로 구현돼 있으며, 나머지 후속 후보는 미구현으로 차단한다.

요구사항 원본: [Leafy AIOps Remediation 개선안](https://app.notion.com/p/415e7f8a345d80da9007e2a231868c85),
2026-11-11 조회, 마지막 수정 `2026-11-11T14:03:58.052Z`. 7장의 모든 토글을 포함한다.
작업 [Issue #35](https://github.com/KU-GraduationProject/graduation-project/issues/35).
기준은 main `0443c6f`와 선행 Socket Mode [PR #32](https://github.com/KU-GraduationProject/graduation-project/pull/32)
head `49245e1`이다. 이 변경은 PR #32를 포함한 브랜치 위에서 개발했다.

실제 운영 활성화와 코드 개발을 구분한다. 기본 `REMEDIATION_MODE=disabled`,
`REMEDIATION_NOTIFICATION_ENABLED=false`, 신뢰 대상 `bindings: []`를 유지한다.
이 문서는 실제 Slack 연결, PC 2 Docker 변경, Windows Host DB 조치를 완료했다는 의미가 아니다.

## 구현 계약과 요구사항 추적

| Notion 요구사항 | 구현 위치 | 검증 또는 후속 조건 |
|---|---|---|
| 2.1 거부·조건부 상태 전이 | `store.py`, `main.py` | Reject 후 실행 차단, 승인/거부 경쟁, 저장 실패 차단 |
| 2.2 사건 멱등성 | `store.py`의 사건 키·조치 해시·영속 검색 | 같은 사건/조치 재사용, 다른 조치 409, 재시작 이후 중복 차단 |
| 2.3 지정 채널 승인·만료 | `slack_socket.py`, `main.py`, `store.py` | HTTP/Socket 공통 팀·채널·레코드·만료 검사, user.id 감사 |
| 2.4 대상·Agent 식별 | `executor/identity.py`, `executor/local_docker.py`, `agent/` | 전체 ID·이미지·라벨 고정, 교체/모호/Host 대상 차단 |
| 2.5 RCA 알림 | `pipeline/main.py`, `actions/notify.py`, `POST /notify` | 서명 알림 전용 전달, Controller 레코드 없는 승인 버튼 제거 |
| 3.1 실행 직전 승인 | `claim_execution()`, `_perform()` | 저장된 상태·승인 근거·만료와 대상 바인딩 재검증 |
| 3.2 사건/조치 분리 | `incident_key()`, `action_hash()` | action parameters·TTL·복구 모드가 달라지면 충돌 |
| 3.3 원격 결과 불확실 | `executor/remote_sync.py`, `/remote/reconcile` | UNKNOWN 보존, 조회만 허용, retry:true 거부 |
| 7.3 위험도/심각도 토글 | `policy/engine.py`, `policy/schema.py` | 정책 고정 위험도, high 조치 승인 필수, low 위협/high 조치 검토, high 위협/low 변경 차단 |
| 7.4 실행기·정책 위험도 토글 | `policy/catalog.py`, `remediation_policy.yml`, `executor/router.py` | 32개 권고 어휘·16개 미구현 제안·신규 6개 실제 실행기, 미구현 실행기 차단 |
| 7.5 시나리오 토글 | `SCENARIO_RECOMMENDATIONS` | S1/S2/S3/F1/F2/F3 권고 후보. 시나리오 ID를 실행 권한으로 사용하지 않음 |
| 7.6 증거·검증·복구·시간 | `evidence.py`, `recovery.py`, `store.py`, Agent ledger | 기존 기능 재사용, 고정 대상 재검증, MTTR/containment 분리 |
| 7.7/7.8 범위 구분 | 본 문서와 정책의 proposed_actions | DB·배포·앱 API 신규 6개 실제 구현, 나머지 16개 후속 후보 차단; 운영 활성화는 별도 인수 |

## 알림과 승인 API

- `POST /notify`: 기존 Pipeline HMAC 인증, `{operation: "notify_only", alert, analysis}` 본문. Slack 정보 메시지만 전송한다.
  권장 조치 이름은 표시할 수 있지만 승인 버튼·실행 레코드·Docker 조치를 만들지 않는다.
  반환 `dispatch.sent`를 실제 Slack 전송 성공 여부로 사용한다.
- `POST /action`: 별도의 명시적 조치 제안 경로다. Pipeline은 자동으로 이 경로에 연결하지 않는다.
  본문의 `operation`은 `propose_action` 또는 기존 명시 클라이언트 호환용 생략만 허용한다.
  `notify_only` 등 다른 목적의 서명 본문은 실행 전에 거부한다. 실행 가능한 제안에는
  원본 경보의 `fingerprint`, 유효한 `startsAt`, 다섯 identity가 필요하다.
  정보가 부족하면 실행 가능한 현재 시각이나 대상을 합성하지 않는다.
- `POST /slack/action`: HTTP 호환 모드에서 서명을 검증한 후 공통 승인 핸들러를 사용한다.
  Socket Mode도 같은 채널/상태/만료/레코드 검사와 실행 선점을 사용한다.
- `POST /remote/reconcile`: 서명된 `operation=reconcile_remote` 요청으로 기존 기록을 조회한다.
  불확실한 조치를 재전송하는 `retry:true`는 거부한다.

사건 키는 `site/service/source/runtime/target + fingerprint + startsAt`이다.
조치 해시는 `action_type/targets/TTL/recovery_mode/action_parameters`의 정규화된 내용이다.
같은 사건·조치는 저장된 결과를 반환하고, 다른 조치는 409로 검토를 요구한다.
Pipeline 시간 창 분석 dedup과 Controller 영속 사건 키의 목적은 다르다.

승인·거부·만료·실행 선점은 단일 Controller 저장소의 lock 아래서 처리한다.
저장 실패는 실행을 차단한다. JSON 저장소는 단일 worker/replica 전제이며 별도
프로세스나 복제본끼리의 선점을 보장하지 않는다. 상태 파일·Agent SQLite를 삭제하거나
과거 백업으로 되돌려 멱등성을 우회해서는 안 된다. POSIX에서는 파일 내용과 부모
디렉터리를 fsync한 뒤 실행을 허용한다. Windows 네이티브에서는 portable 디렉터리
fsync가 없어 전원 손실 시 같은 보장을 주장하지 않는다. 운영 Controller는 Linux 컨테이너 전제다.

## 대상 바인딩과 운영 설정

1. `SLACK_TEAM_ID`와 `SLACK_CHANNEL_ID`를 지정한다. 지정 채널 구성원 누구나 승인할 수 있다.
   `SLACK_ALLOWED_USER_IDS`는 권한 기준에서 제거했다. user.id만 승인 주체 감사 기록에 남긴다.
2. `SLACK_APPROVAL_TTL_SEC` 기본 900초로 최초 승인과 복구 승인 만료를 저장한다.
   거부·만료·실행된 조치를 오래된 버튼으로 다시 열지 않는다.
3. `aiops/policy/remediation_targets.yml`은 초기 `bindings: []`다. 운영자가 실제 PC에서
   확인한 값을 [대상 예제](../../deploy/aiops-pc/remediation-targets.example.yml) 형식으로 저장소 밖 파일에 등록하고,
   `.env`의 `REMEDIATION_TARGET_BINDINGS_LOCAL_PATH`에 절대 경로를 지정한다.
   예제의 placeholder는 유효한 전체 ID가 아니므로 그대로 사용하면 검증에 실패한다.
4. Compose는 정책과 대상 파일을 읽기 전용으로 마운트하며
   `REMEDIATION_TARGET_BINDINGS_PATH=/app/config/remediation_targets.yml`로 전달한다.
   수동 Python 실행에서는 해당 환경변수에 검증한 파일 경로를 명시한다.
5. remote 바인딩의 Agent URL/ID는 Agent의 `agent_id/site/source`와 일치해야 한다.
   Agent의 인증된 읽기 전용 `/v1/targets/{target}`로 승인 전에 대상 상태를 대조한다.
6. 승인 후 실행·복구 직전에 동일한 바인딩과 실제 전체 컨테이너 ID·이미지 ID·라벨을 확인한다.
   새 컨테이너에 이전 승인을 적용하지 않는다. identity runtime은 기존 계약의 `container/host`다.
   현재 한 관측 identity에는 대상 하나만 허용한다. 여러 대상 조치는 대상별 identity 계약 전까지 차단한다.
7. 실제 Slack 수신 검증 후 운영자가 `REMEDIATION_NOTIFICATION_ENABLED=true`로 알림을 켤 수 있다.
   이 설정은 `/action` 연결이나 Docker 실행 모드를 활성화하지 않는다.

외부 Docker 작업과 저장소 쓰기를 하나의 트랜잭션으로 묶을 수 없다. 보장 목표는
영속 선점에 따른 **최대 한 번 실행 시도**다. 응답 유실은 UNKNOWN으로 보존하고,
Agent 조회로도 결과가 확정되지 않으면 수동 확인한다.

## 토글 제안 전체의 반영 범위

| 제안/계약 이름 | 실행기 | 이번 구현 상태 |
|---|---|---|
| RESTART, PAUSE/UNPAUSE, THROTTLE/UNTHROTTLE, ISOLATE/RECONNECT | Docker/Agent | 기존 실행·증거·복구 기능에 승인·멱등성·대상 검증 연결 |
| CAPTURE | 관측 | 증거 수집을 기존 gate에서 재사용; 독립 CAPTURE API는 미구현으로 차단 |
| BLOCK_EGRESS | 네트워크 | 세밀한 출구 차단·원복 계약 필요, 차단 |
| KILL_SESSIONS | DB | 고정 SQL로 실제 세션 종료/쿼리 취소, 계획·클러스터·승인·역할·사후 검증 필수 |
| BACKUP_DB, RESTORE_DB, DISABLE_DB_ROLE | DB | pg_dump/복원/NOLOGIN 후보와 필수 권한·무결성·복구 조건, 차단 |
| ROLLBACK, RECREATE | 배포 | 실제 Docker SDK 재배포 구현, 이미지·설정·백업·헬스 검증과 새 ID 재바인딩 |
| LOCK_ACCOUNT, REVOKE_SESSION, DISABLE_FEATURE | 앱 API | 실제 HTTPS 어댑터와 Leafy 관리자 API/JWT·기능 차단 구현, 별도 배포·검증된 계약 필요 |
| SET_LOG_LEVEL, PACKET_CAPTURE, SILENCE_ALERT | 관측 | TTL·개인정보·저장 접근·경보 은폐 조건 필요, 차단 |
| BLOCK_PATH, RATE_LIMIT, MAINTENANCE_MODE | Nginx | 설정 검증·원복·NAT/프록시 영향 필요, 차단 |
| RESTRICT_BUCKET, DISABLE_KEY | MinIO | 앱 계정 분리·정책 복구·자격증명 의존성 필요, 차단 |
| RESTART_HOST_SVC, CLEAN_DISK | Host | 별도 실행기·삭제 대상/서비스 권한·검증 필요, 차단 |
| NOTIFY/NONE | 사람 | 알림 또는 실행 없음 |
| RECORD_INCIDENT | 기록 | GitHub 인시던트 기록 계약·중복 방지 필요, 자동 외부 쓰기는 차단 |

proposed_actions는 위험도·실행기·단계·선행 조건을 보존하며 `executor_ready`는 항상 false다.
원안의 '1차'는 구현 약속이나 완료 표시가 아니다. 독립 실행기 router도 미구현 가족을 거부하므로
정책에 조치 이름을 추가하는 것만으로 Docker/DB/Host 실행이 열리지 않는다.

원안에 위험도가 명시되지 않은 CAPTURE/DB 백업·복원/로그·패킷 캡처/Silence/기록의 값은
`risk_origin: integration_review_default`로 구분한다. 이는 후속 검토용 보수적 분류이며 실행 권한이 아니다.
`threat_level`은 현재 스키마의 low/medium/high/critical 4단계를 보존하고 critical도 승인을 생략하지 않는다.

Windows Host PostgreSQL 17 및 F2-c 조치는 기본 비활성이다. 후속 요청으로 고정 SQL 실행기를 추가했으며,
명시적인 확장 모드·검증된 DB 설정·수동 승인 없이는 호출하지 않는다. F2-c 점유·해제 시나리오 주입기나 실제 DB 설정은 변경하지 않았다.

## 검증 결과와 남은 인수

검증 결과는 [개선 검증 기록](REMEDIATION_IMPROVEMENTS_VERIFICATION.md)에 기록한다.
테스트는 `testing/run_isolated.py`로 Docker 생성자·네트워크·DNS·subprocess·pipe 접근을 차단한다.
실제 Slack WebSocket/메시지, 컨테이너 전후 상태, 원격 네트워크/PC 2, Windows Host DB는 별도 인수 대상이다.
MTTR은 검증된 정상 복구 시각까지이며 조치 검증 시각까지는 별도 containment 지표다.
