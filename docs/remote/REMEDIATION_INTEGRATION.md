# Remediation 통합 구현 보고

2026-11-12 KST. [Notion 원문 및 토글](https://app.notion.com/p/415e7f8a345d80da9007e2a231868c85),
[Issue #35](https://github.com/KU-GraduationProject/graduation-project/issues/35), 실제 코드를 대조했다.
원문 최종 편집 시각은 2026-11-11T14:03:58.052Z이며 토글을 포함해 조회했다.

## 1. 구현 전 상태와 기준

- 가져온 원격 `origin/main`: `0443c6f56104652f06eb68c6f3a18e3c63f99265`.
- 기존 작업의 기반 HEAD: `49245e120191b84642e17a910ca9278e368f7966` (Socket Mode PR #32).
- 기존 미커밋 구현을 보존하고 새 로컬 브랜치 `feat/35-remediation-integration`에서 작업했다.
  작업 폴더는 `remediation-improvement-20261111`이다. main을 병합하거나 변경하지 않았다.
- 백엔드: `leafy-api-remediation-20261111`, `feat/remediation-admin-api`,
  [api-server](https://github.com/Project-Leafy/api-server)의 `6dab427f25f2a0192d085da9347ebcaf73dc067b` 기반.
  이 브랜치에도 미커밋 상태로 보존했다.

| 기능 | main / 기존 작업 상태 | 이번 변경 |
|---|---|---|
| Pipeline RCA | 기존 분석·identity·수집기 있음 | typed 파라미터와 최대 3단계 계획 추가 |
| `/notify` | 기존 작업에 알림 전용 경로 구현 | 그대로 유지, 실행 불가능한 정보 전달 |
| RCA→`/action` | 기존 작업은 `/notify`만 호출 | 별도 opt-in 수동 계획 handoff 연결 |
| 정책/Slack/RecordStore | 기존 승인·멱등·대상 고정 안전성 구현 | 단계/개정/복구 연결과 원자적 신규 레코드 생성 |
| Docker/DB/배포/앱 실행기 | 실제 코드 구현, 로컬 범위 테스트 완료 | 재사용, 새 서비스를 만들지 않음 |
| 원격 Agent | Docker 기본 조치 지원 | RECREATE/ROLLBACK의 원격 계획·실행 추가 |
| MTTR | Docker 원복 시각을 MTTR로 사용 | Health+신선한 지표 연속 정상 확인 이후만 확정 |
| 앱 복구 | 백엔드 unlock/enable API만 존재 | 저장된 조치의 별도 Slack 복구 승인 연결 |
| 추가 조치 16개 | 메타데이터만 존재 | 중복/위험/비용/우선순위 평가, 실행 차단 유지 |

## 2. 주요 파일과 변경

| 파일/경로 | 핵심 변경 |
|---|---|
| `aiops/pipeline/schemas/remediation_plan.py`, `llm_output.py` | 원시 LLM 입력의 유효성, 조치별 엄격 파라미터, 오류 값 폐기, 계획 변환 |
| `aiops/pipeline/main.py`, `config.py`, `prompt/builder.py` | 승인 opt-in, 분석 완료 후 signed manual proposal, 불확실 전달 시 다른 실행 요청 금지 |
| `aiops/remediation/plans.py` | Controller가 독립적으로 wire identity/사건/내용/단계를 검증 |
| `main.py`, `store.py`, `actions/notify.py` | 새 수동 요청, 재계획/단계 진행/앱 복구 API, 이전 레코드 보존·링크·CAS, Slack 표시 |
| `agent/{contract,api,service}.py`, `executor/{remote,remote_sync}.py` | 인증된 원격 배포 계획·명령, Agent SQLite 선점/중복/조회, UNKNOWN 보존 |
| `executor/{deployment,identity,extended,router}.py` | 이동 가능한 계획 digest, 정확한 호스트/대상/실행기, PC 1 로컬 fallback 차단 |
| `executor/app_api.py`, 정책/카탈로그 | UNLOCK_ACCOUNT/ENABLE_FEATURE 실제 계약·수동 승인·부모 레코드 요구 |
| `service_verification.py`, `recovery.py`, `store.py` | 읽기 전용 서비스 검증, 승인 전 프로필 고정, 신선도·연속 샘플·타임아웃, 별도 MTTR |
| `.env.example`, 두 Compose, `deploy/**` 예제 | 기본 비활성화, 승인/원격 배포/서비스 확인 설정과 읽기 전용 마운트 |
| 백엔드 `RemediationService`, `RemediationAdminController` | ADMIN 인증 `GET /api/admin/remediation/health`, 실제 DB 필수 행 확인, 고정 JSON 응답 |

기존 실행기 6개 확장의 상세 내용은 [이전 실행기 설명](EXTENDED_EXECUTORS.md)을 참조한다.
현재 정책 정의는 14개(NONE/NOTIFY, Docker 4개, 기존 확장 6개, 앱 수동 복구 2개),
권고 어휘는 34개다. 어휘 수가 실행 가능한 조치 수를 의미하지 않는다.

## 3. 연결된 E2E와 안전 조건

```text
탐지 이벤트의 identity / fingerprint / startsAt
  → 기존 Pipeline 수집·RCA
  → 검증된 action_parameters / 최대 3단계 계획
  → /action (propose_manual_action 또는 propose_plan, force_manual=true)
  → 정책 검사 + 실행기 읽기 전용 계획 + 영속 레코드 + 프로필 고정
  → 지정 Slack Workspace/채널의 승인 또는 거부
  → 현재 정책·승인 만료·저장 계획·대상/버전 재검증 + 영속 실행 선점
  → 기존 Executor Router
      Docker 기본 조치 / DB / 앱 HTTPS / 원격 배포
      PC1 RemoteExecutor → HMAC PC2 Agent → SQLite ledger → DeploymentExecutor
  → 조치 효과 재조회 (action_verified_at, VERIFIED)
  → 읽기 전용 Health + Prometheus 지표/실제 scrape 신선도 연속 검사
  → service_recovered_at / MTTR 영속 저장 + 감사 이벤트
```

- `REMEDIATION_APPROVAL_ENABLED=false`가 기본이다. 켜도 RCA 요청은 항상 별도 수동 승인이다.
  새 operation을 구버전 Controller에 보내면 거부돼 구버전 자동 THROTTLE로 진행되지 않는다.
  낮은 신뢰도(<0.8), 잘못된 파라미터, 미지원 조치, identity 충돌은 알림/수동 검토로 남긴다.
- SQL/명령/주소/이미지/인증정보/정책·헬스 기준을 LLM에서 받아 실행하지 않는다.
  실행 세부 설정은 검증한 운영자 파일에서만 결정한다.
- 같은 사건/계획은 재사용한다. 변경된 조치는 보통 409다. 명시적 `replan_action`만
  이전 레코드에 새 개정 레코드를 연결하고 새 대상을 읽어 별도 승인한다.
  이전 대기 버튼은 SUPERSEDED로 차단하며 기록/결과를 덮어쓰지 않는다.
- `/plans/advance`는 직전 단계의 저장된 효과 검증이 확인된 경우만 다음 단계를 만든다.
  매 단계 새 승인·현재 대상 재검증이 필요하다. 자동 단계 진행은 없다.
- EXECUTING/RECOVERING/UNKNOWN/RECOVERY_UNKNOWN/NEEDS_REVIEW는 새 실행을 막는다.
  원격 응답 유실은 Agent 기록을 조회한다. 조회가 불확실하면 UNKNOWN을 유지하며 재전송하지 않는다.
- 원격 배포는 양쪽 명시 opt-in, Agent 허용 목록의 전체 컨테이너 ID/이미지/라벨,
  PC 2의 private 배포 파일이 필요하다. 기존 HMAC·method/path/body·nonce 영속 검증을 재사용한다.
  원격 기능이 꺼져 있어도 PC 1의 로컬 배포로 대체하지 않는다.
- 재생성 후 새 전체 ID를 보존하고 이후 조치를 위해 운영자가 바인딩을 다시 검증해야 한다.
  기존 컨테이너·볼륨은 보존한다. 백업을 생성하거나 DB 복원을 자동 실행하지 않는다.
- `/recovery/request`는 검증된 LOCK_ACCOUNT/DISABLE_FEATURE의 동일 자원만 새
  UNLOCK_ACCOUNT/ENABLE_FEATURE로 계획한다. 별도 `approve_recovery` 버튼과 동일 승인 검증을 거친다.
  기존 잠금/차단 승인을 재사용하지 않는다. 과거 세션을 되살리는 역조치는 없다.
- 서비스 검증 프로필은 정확한 5개 identity에 매핑하며 승인 전에 해시를 고정한다.
  Health JSON과 모든 지표가 최소 2회(기본 3회), 간격을 두고 연속 통과해야 한다.
  PromQL 평가 시각과 실제 scrape 시각을 따로 확인해 오래된 데이터가 성공이 되지 않게 한다.
  없거나 여러 개의 series, NaN, 응답 오류, stale sample, 범위 초과는 복구를 확정하지 않는다.
- `__CONTAINER_ID__`는 검증된 배포 결과의 새 전체 ID 또는 승인된 Docker 바인딩에서만 치환한다.
  유지된 이전 컨테이너 지표로 새 서비스의 복구를 확인하지 않는다.
- 실행 효과와 Docker 설정 원복은 서비스 복구와 다르다. `recovery_verified_at`만 있어도 MTTR은 null이다.
  `MTTR = service_recovered_at - alert_active_at`; `time_to_contain`은 별도다.
  다단계 계획의 중간 단계는 HEALTHY_INTERMEDIATE만 기록하고 마지막 단계에서 MTTR을 확정한다.
  검증 타임아웃은 서비스 TIMEOUT이며 성공한 조치 자체를 실패/UNKNOWN으로 바꾸지 않는다.

## 4. 검증 결과

아래 결과는 격리된 로컬 테스트다. 실제 PC/Slack/Docker/운영 DB 검증이 아니다.

| 검사 | 결과 | 테스트 수 |
|---|---|---:|
| Remediation 격리 suite | PASS | 475 |
| Pipeline 격리 suite | PASS | 150 |
| Network 격리 suite | PASS | 100 |
| Observer 격리 suite | PASS | 12 |
| GitHub 협업 도구 회귀 | PASS | 36 |
| 백엔드 Remediation Java (17 Security + 8 H2/JPA + 9 Service) | PASS | 34 |
| 총계 | PASS | 807 |

Python 3.11.15 + psycopg 3.3.8 import 환경. 실제 Docker 생성자·소켓/DNS·subprocess와
native libpq 연결을 차단한 `testing/run_isolated.py`로 검사했다. Network suite만 자체 임시
loopback fixture를 사용한다. Java는 JDK17/캐시된 Gradle 의존성/실제 로컬 H2를 사용했다.
백엔드 전체 suite의 외부 데이터 수집 테스트는 실행하지 않았다.

새 통합 테스트는 `test_pipeline_to_agent_e2e.py`, `test_remote_deployment_flow.py`,
`test_integrated_plans.py`, `test_service_verification.py`, Pipeline의 `test_approval_handoff.py`다.
실제 HTTP 앱·파서·HMAC·JSON/SQLite 영속 전이를 사용한다. RCA 출력/수집 자료, Slack 수신,
Docker SDK, Health/Prometheus는 모의다. 응답 유실·중복·만료·교체 ID·이전 승인·동시 재계획도 검사한다.

두 저장소 diff 검사/Python compileall, all-in-one Compose, PC1 remote+extended Compose,
PC2 live+deployment override의 `config --quiet`를 확인했다. Compose 검사는 가상 환경값을
주입한 구문 검사이며 컨테이너를 시작하지 않았다. 최초 누락된 필수 환경값 오류는 가상값으로
보완해 재검사했다. 실제 운영 secret을 읽어 이 검사를 통과시키지 않았다.

## 5. 남은 항목과 한계

- [미구현 조치 16개와 우선순위](REMEDIATION_BACKLOG.md), 별도 SCALE. 모두 차단 유지.
- 실제 backend 패치/수동 migration/새 이미지 배포, PC1·PC2의 운영자 설정·권한·인증서·키 설치.
- 운영 Slack 수신·클릭·원격 네트워크 단절·재시작·서비스 SLO 확인을 포함한 실제 인수.
- 백엔드 Health는 앱/DB readiness다. 장애별 기능·오류율·지연/DB/보안 정상 여부는
  해당 서비스의 실제 지표/임계값을 프로필에 지정해야 한다. 예제 임계값은 SLO가 아니다.
- 단일 Controller 프로세스/복제본, 단일 Agent ledger 소유자 전제. 다중 replica 저장소는 미구현.
  완전한 exactly-once 효과 대신 최대 한 번 실행 시도와 불확실 상태 보존을 우선한다.
- PC2 Agent는 Docker/배포 경계다. Host PostgreSQL SQL은 별도 DB 실행기이며 Docker Agent로 보내지 않는다.
- 커밋·푸시·PR 생성·main 병합, 운영 변경은 수행하지 않았다.

## 6. PC 1 / PC 2 실환경 검증 절차 (미실행)

1. **사전 준비**: 검토된 두 패치/필수 CI/사람 리뷰 후 검증 환경에 빌드한다. 백엔드 수동 스키마를
   검토하고 적용한 뒤 `REMEDIATION_ADMIN_ENABLED=true`, 정확한 `REMEDIATION_TARGET`으로 배포한다.
   보존할 DB에 dev create-drop 프로필을 쓰지 않는다. 새 Health API를 ADMIN access JWT로 GET해
   `{status:"UP",target:<정확한 대상>,database:"UP"}`와 미인증/일반 사용자 거부를 확인한다.
2. **PC2 Agent**: base `compose.yml`로 먼저 disabled 상태, 별도 HMAC 키·영속 ledger·Tailscale HTTPS
   origin·허용 목록을 확인한다. site/source/Agent ID/전체 컨테이너 ID/이미지/라벨을 실제 inspect와 대조한다.
   명시 허가된 검증 대상에 한해 `compose.live.yml`을 추가한다. 배포 검증은 추가
   `compose.deployment.example.yml`, PC2 private config/env/백업 참조 파일과 허용 조치가 필요하다.
   이전 컨테이너/볼륨 보존 및 되돌릴 절차를 먼저 확보한다.
3. **PC1 Controller**: `docker-compose.aiops.yml` + `remediation-remote.example.yml` +
   `remediation-extended.example.yml` 순으로 사용하고 `REMEDIATION_EXTENDED_DOCKER_MODE=remote`로 지정한다.
   `REMEDIATION_REMOTE_DEPLOYMENT_ENABLED`는 배포 인수 전 false로 둔다. PC1에 Docker socket을 주지 않는다.
   정확한 target 바인딩/Slack team·channel/승인 TTL/영속 state mount를 준비한다.
4. **읽기 검증**: Health 프로필을 저장소 밖에 작성해 `REMEDIATION_SERVICE_VERIFICATION_LOCAL_PATH`로
   마운트한다. Health와 Prometheus에 PC1에서 GET하고 단일 series/실제 scrape 시각/장애별 정상 범위를 확인한다.
   예제 Health 토큰은 private 환경의 `LEAFY_HEALTH_READ_TOKEN`으로 전달한다. 임의 토큰 참조 이름은
   별도 Compose 환경 주입이 필요하다. 프로필 변경은 기존 승인에 적용되지 않는다.
5. **알림→승인**: 처음 `REMEDIATION_NOTIFICATION_ENABLED=true`, approval=false로 정확한 identity와
   원래 fingerprint/startsAt의 검증 이벤트를 보낸다. Slack 정보만 표시되고 mutation/승인 레코드 0건인지 확인한다.
   다음 검증 환경에서 approval=true로 전환해 같은 안전한 사건의 typed plan이 승인 대기로 저장되는지 확인한다.
   승인 전 실행 0회, 잘못된 채널/Reject 후 Approve/만료/변조 버튼 실행 0회를 확인한다.
6. **명시 승인된 단일 조치**: 운영자 승인 범위의 검증 컨테이너에 한해 승인한다. PC1 레코드와 PC2 ledger의
   사건/승인/계획/대상 ID를 대조하고 효과 검증 시각을 확인한다. 조치 성공 직후 MTTR=null이어야 한다.
   연속 Health+지표 검증 후 SERVICE_RECOVERED 감사 이벤트와 MTTR을 확인한다.
   복구 스캐너 기본 간격은 60초이며 `REMEDIATION_TTL_SCAN_SEC=0`이면 자동 검사가 꺼진다.
7. **단절/중복/교체**: 승인 이벤트 중복은 새 실행이 없어야 한다. 승인 후 Agent 응답만 유실시키는 통제된
   검증에서는 `/remote/reconcile`의 `operation:reconcile_remote`, `retry:false`로 조회만 수행한다.
   UNKNOWN이 남으면 자동 재실행하지 않는다. 검증용 컨테이너를 교체한 경우 이전 승인이 차단되는지 확인하고
   운영자가 새 ID/이미지/라벨을 다시 확인한 뒤 명시적 재계획·재승인한다.
8. **확장 검증**: `/plans/advance`는 이전 검증 완료 후에만 다음 승인 요청을 만들고 실행하지 않아야 한다.
   앱 복구는 `/recovery/request` 후 새 Slack 복구 승인으로만 허용한다. 잠금 만료/해제 후에도 과거 JWT는
   무효여야 한다. PostgreSQL은 전용 검증 DB의 허용된 시험 세션만 별도 승인해 확인한다.
   DB 복원/디스크 정리/16개 미구현 조치는 이 절차에서 실행하지 않는다.

모든 제어 API는 `REMEDIATION_API_KEY`로 **원본 JSON 바이트**에 기존 HMAC 서명이 필요하다.
새 요청도 같은 incident를 유지하며 서명 timestamp를 갱신한다. secret을 명령행/로그에 출력하지 않는다.

| 경로 | 필수 body의 의미 |
|---|---|
| `/action` | `operation:propose_manual_action`, `force_manual:true`, `alert`, `analysis`, `plan` |
| `/action` (다단계) | `operation:propose_plan`, `force_manual:true`, `alert`, `plan_steps:[{analysis,plan},...]` |
| `/action` (재계획) | `operation:replan_action`, `force_manual:true`, `replan_of`, `reason`, 새 `alert/analysis/plan` |
| `/plans/advance` | `operation:advance_plan`, `previous_remediation_id` |
| `/recovery/request` | `operation:request_recovery`, 원본 `remediation_id`, `reason` |
| `/service/verify` | `operation:verify_service`, `remediation_id`; 고정 프로필로 읽기 검증만 수행 |

wire `plan`은 `version:1`, `action_type`, `targets`, `parameters`, 정확한 `identity`,
`incident:{fingerprint,starts_at}`이다. HTTP 200만으로 Slack 전달/실제 조치/서비스 복구를 PASS로 기록하지 않는다.
