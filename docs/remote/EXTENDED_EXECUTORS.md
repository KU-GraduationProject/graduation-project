# DB·배포·앱 API 실제 실행기

근거는 [Notion 개선안](https://app.notion.com/p/415e7f8a345d80da9007e2a231868c85) 7.4/7.5와
현재 프로젝트 코드다. 사용자의 추가 요청으로 기존 후속 후보 중 아래 6개 조치의
실제 호출 구현을 추가했다. 선행 P0 안전성은 [Remediation 개선 구현](REMEDIATION_IMPROVEMENTS.md)을 따른다.

| 조치 | 실제 구현 | 검증하는 효과 |
|---|---|---|
| KILL_SESSIONS | `executor/postgres.py`의 psycopg TCP·고정 SQL | 승인한 유휴 세션 종료 또는 승인한 장기 쿼리 취소 |
| RECREATE | `executor/deployment.py`의 Docker SDK | 같은 고정 이미지와 승인 설정으로 새 컨테이너 생성·healthy 확인 |
| ROLLBACK | 동일 배포 실행기 | 승인한 known-good 이미지/설정·백업 조건과 새 컨테이너 healthy 확인 |
| LOCK_ACCOUNT | `executor/app_api.py`의 HTTP 변경·재조회 | 지정 계정 잠금과 백엔드가 보장하는 만료 시각 |
| REVOKE_SESSION | 동일 앱 API 실행기 | 지정 계정 세션/토큰 회수와 자원 버전 변경 |
| DISABLE_FEATURE | 동일 앱 API 실행기 | 허용한 기능의 비활성화와 자원 버전 변경 |

정책에는 총 14개 조치(NONE/NOTIFY와 기존 Docker 4개, 신규 6개 및 수동 앱 복구 2개)가 정의돼 있다.
권고 어휘는 34개를 유지하고, 나머지 16개 후속 후보는 계속 미구현으로 차단한다.
새 6개는 위험도와 무관하게 모두 수동 승인한다. 자동 조치로 전환하지 않았다.

## Controller 연결

`REMEDIATION_MODE=extended`를 명시하면 `ExtendedExecutorRouter`가 조치별 실행기를 선택한다.
전역 실행기를 요청마다 바꾸지 않고 개별 레코드에 실제 실행기 이름을 고정하므로,
DB·배포·앱 조치가 동시에 들어와도 다른 실행기로 섞이지 않는다.

1. `/action`은 완전한 사건 identity와 고정 정책·조치 파라미터를 확인한다.
2. 허용되지 않은 명령/SQL/비밀번호 필드는 저장 전에 거부한다.
3. 실행기 `plan_record()`는 읽기 전용으로 실제 자원과 실행 계획을 확인한다.
4. 대상·계획·설정 해시를 `target_bindings`에 영속 저장한 후 Slack 승인을 요청한다.
   Slack에는 선택한 PID·조치 조건, 배포 이미지/버전 또는 계정·기능 대상을 표시한다.
5. 유효한 지정 채널 승인 후 실행을 영속 선점하고 자원·계획·만료를 재검증한다.
6. 계획 증거를 저장한 뒤 `execute_record()`가 실제 SQL/SDK/HTTP 호출을 수행한다.
7. 사후 조회로 확인된 효과만 성공으로 기록한다. 응답 유실·부분 실행·최종 기록 실패는
   UNKNOWN으로 보존하며 자동 재전송하지 않는다.

`disabled` 모드에서는 DB/API preflight 연결도 하지 않는다. 기본 모드는 계속 disabled다.
확장 모드의 기존 Docker 재시작·격리 경로도 기본 disabled다. 운영자가 기존 경로를
함께 쓸 때만 `REMEDIATION_EXTENDED_DOCKER_MODE=docker|remote`를 명시한다.
이미 진행 중인 복구 레코드는 기록된 실행기와 일치하는 경로로만 처리한다.

## PostgreSQL 17 세션 조치

[예제](../../deploy/aiops-pc/remediation-postgres.example.yml)를 저장소 밖에 복사하고
실제 클러스터 system_identifier·DB·서버 주소/포트·5개 identity·전용 실행 계정을 설정한다.
Controller는 Docker와 무관한 TCP/libpq 연결을 사용하므로 Windows Host PostgreSQL 17도 대상이 될 수 있다.
자격 증명은 환경변수 참조로만 읽고 레코드·오류에 비밀번호나 쿼리 원문을 저장하지 않는다.

```json
{"action_type":"KILL_SESSIONS","action_targets":["leafy-db"],
 "action_parameters":{"operation":"terminate_idle_sessions","max_sessions":3}}
```

위 analysis는 기존 서명된 `/action` 본문의 일부다. alert에 `site/service/source/runtime/target`,
fingerprint, startsAt과 `operation=propose_action`도 필요하다. 장기 쿼리는
`operation=cancel_long_queries`로 별도 승인한다. 요청의 min_age_seconds/max_sessions는
설정 조건을 더 좁힐 수만 있다.

- 실행 역할은 설정의 executor_role과 정확히 일치해야 한다. superuser/replication/role생성/DB생성/RLS우회 역할은 거부한다.
- 운영자가 미리 부여한 pg_signal_backend, pg_read_all_stats 및 pg_control_system 실행 권한이 필요하다.
  연결 슬롯 고갈 대응에는 운영자가 별도로 구성한 예약 연결 권한/슬롯도 필요할 수 있다. 실행기가 역할·권한을 생성하지 않는다.
- 대상은 정확히 허용된 DB/역할/application_name/client IP의 일반 client backend다.
  자신의 연결, 관리자/예약 역할 세션, 복제·시스템 연결, idle-in-transaction 세션은 제외한다.
  현재 DB 로그인 계정이 관리자라면 그 세션은 종료 대상이 되지 않는다.
- PID·backend_start·query_start·state/state_change를 승인 계획에 고정하고 같은 SQL 문에서 재검사한 뒤 신호 함수를 호출한다.
- PostgreSQL의 pg_cancel_backend/pg_terminate_backend는 PID에 신호를 보내는 함수다.
  pg_stat_activity를 잠가 다른 세션의 다음 쿼리 시작까지 원자적으로 막을 수는 없다.
  검사와 신호 사이의 짧은 서버 내부 경쟁을 완전히 제거했다고 주장하지 않는다.
- SQLite 영속 실행 기록은 같은 요청의 재전송을 막는다. 상태 파일/ledger를 삭제해 재실행하지 않는다.
  세션·쿼리 조치 성공과 DB/Backend 서비스 전체의 정상 복구는 구분한다.

SQL 근거: [PostgreSQL 17 신호 함수](https://www.postgresql.org/docs/17/functions-admin.html),
[pg_stat_activity](https://www.postgresql.org/docs/17/monitoring-stats.html).

## 배포 재생성·롤백

자세한 설정은 [배포 실행기](DEPLOYMENT_EXECUTOR.md)를 따른다.
현재 저장소 Compose 이미지인 gicks/ai-ops-leafy-backend/frontend만 대상으로 한다.
상태 저장 DB·MinIO를 재생성하지 않고, 이미 로컬에 존재하는 고정 이미지 ID만 사용한다.
자동 pull, 임의 shell, 임의 Docker Host 연결은 없다.

실행기는 검증된 Docker 호스트에 함께 배치하고 local Unix socket을 명시 마운트해야 한다.
PC 1에 배치한 실행기로 PC 2 컨테이너를 조작할 수 있다고 간주하지 않는다.
원격 배포는 PC2 Agent의 별도 `/v1/deployment/plans`와 `/v1/deployments`에 연결했다.
PC2의 같은 로컬 SDK 실행기를 재사용하며 양쪽 명시 opt-in·허용 목록이 필요하다.
전체 통합 및 현재 검증은 [통합 보고](REMEDIATION_INTEGRATION.md)를 참조한다.

기존 컨테이너는 중지·이름 변경·네트워크 해제 후 보존한다. 새 컨테이너는 승인한
포트·마운트·환경 파일 해시·네트워크 ID·이미지·헬스체크를 검증한다. 볼륨을 삭제하지 않는다.
Backend 롤백은 스키마 호환성에 대한 운영자 확인과 해당 DB의 검증된 백업을 추가로 요구한다.
부분 실패는 두 컨테이너 ID와 보존 이름을 남기고 UNKNOWN으로 멈춘다.
성공해도 새 ID를 이후 조치에 쓰려면 바인딩을 다시 확인하고 새 승인을 받아야 한다.

## 앱 관리자 API

HTTP 어댑터는 고정 HTTPS origin과 운영자가 확인한 API 계약만 호출한다.
경로·메서드·본문 필드·권한·계정/기능 허용 목록·상태 재조회 조건은
[앱 API 계약](APP_API_EXECUTOR_CONTRACT.md)에 명시한다.
`If-Match`에 승인 전 자원 버전을, `Idempotency-Key`에 고정 요청 식별자를 전달한다.
리다이렉트·임의 URL/메서드·관리자 계정 조작은 허용하지 않는다.

사용자가 제공한 실제 백엔드는 [Project-Leafy/api-server](https://github.com/Project-Leafy/api-server)다.
연결·서버측 계정/토큰/기능 제어 변경은 별도 백엔드 작업 폴더와 패치로 제공한다.
HTTP 200만 반환하는 가짜 API나 상태 필드만 바꾸고 실제 인증/기능을 유지하는 구현은 성공 기준이 아니다.

## 설정과 검증 범위

기본 정책 파일 3개의 targets는 빈 목록이며 운영 자격 증명은 없다.
검증한 설정 파일은 저장소 밖에 두고 `.env`에 아래 호스트 파일 경로를 지정한다.

```dotenv
REMEDIATION_POSTGRES_CONFIG_LOCAL_PATH=/absolute/private/postgres.yml
REMEDIATION_DEPLOYMENT_CONFIG_LOCAL_PATH=/absolute/private/deployment.yml
REMEDIATION_APP_API_CONFIG_LOCAL_PATH=/absolute/private/app-api.yml
```

실제 운영 활성화는 별도 환경 인수 후에 수행한다. 예제 extended override는 실행 위치/마운트/권한을
검토한 운영자가 선택하는 설정이며, 이번 개발에서 적용하지 않았다. private token/env/backup 파일은
실행기 설정의 컨테이너 내부 경로에 읽기 전용으로 추가 마운트해야 한다.

Python 테스트는 실제 Docker·HTTP·DB 연결을 차단한다. psycopg의 libpq는 Python socket audit를
우회할 수 있으므로 테스트 수집 전에 실제 psycopg.connect도 차단한다. Fake DB/Docker/HTTP로
SQL 파라미터·실제 SDK/HTTP 요청·승인 연결·사후 검증·실패/만료·UNKNOWN을 검사한다.
