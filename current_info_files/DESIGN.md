# System Design

검증 기준일: 2026-09-19. **아래 계약은 To-Be이며 구현 전이다.** As-Is 근거는 [ARCHITECTURE](./ARCHITECTURE.md), 구현 순서는 [TASKS](./TASKS.md)를 따른다.

## 공통 계약

### 식별자와 저장 경계

| 필드 | 의미 / 소유자 |
|---|---|
| run_id | 시나리오 실행 UUID. runner/verifier가 생성. 일반 detector가 이 값을 자동 전파한다고 가정하지 않음 |
| occurrence_id | Alert 발생 건 식별자. 원본 전체 labels와 정규화된 startsAt의 결정적 hash. Pipeline 생성, 조회 결과에 원본도 보존 |
| result_id | Pipeline이 수락한 개별 분석 시도의 UUID. 동일 발생 건의 나중 재분석과 구분. Remediation/Slack callback까지 전달 |
| event_id | 개별 상태 전이/notification 시도의 UUID. 같은 이벤트 재기록 시 유지 |
| container | 정규화된 Docker 이름 또는 null. host-level 값은 이름으로 사용하지 않음 |
| app_log_tag | 앱 로그 조회용 backend/frontend/leafy-db 또는 null |
| source | alertmanager / direct_webhook / periodic. 수신 경로의 주장으로서 detector 검증 완료 증거는 아님 |
| detector | prometheus / loki / none / unknown. verifier가 API 증거로 확정; Pipeline 단독 추정은 unknown 허용 |

occurrence_id의 입력은 원본 labels 전체를 key 순으로 정렬한 JSON과 UTC startsAt이다. 동등한 timezone 표기를 정규화하고 소수초 정밀도를 임의 절삭하지 않는다. annotation의 변경은 발생 건 identity를 바꾸지 않는다. AlertLabel의 현재 필드 제한으로 추가 labels가 사라지지 않도록 보존한다. 이 hash는 인증 수단이 아니다.

Loki의 기존 job/alert/container 같은 저 cardinality 라벨은 유지한다. run_id/occurrence_id/result_id/event_id는 JSON 본문에 기록하고 LogQL JSON 필터로 조회한다. 새 고 cardinality stream label로 만들지 않는다. 기존 이벤트는 역사 조회에 남지만 식별자가 없는 항목을 현재 실행에 자동 연결하지 않는다.

### 상태와 시간

- analysis_status: pending / succeeded / failed / skipped.
- remediation_status: recommended / awaiting_approval / executing / succeeded / failed / skipped. 상태를 조회하지 못하면 null이며 별도 observation_status=unknown이다.
- notification_status: SUCCESS / FAILED / SKIPPED / NOT_APPLICABLE. 대기 중 또는 전송 결과 불명은 null이다. 결과 불명은 observation_status=unknown, reason=delivery_unknown으로 표시하고 재전송하지 않는다.
- observation_status: known / pending / unknown. 시스템 오류를 정상 no-data로 숨기지 않는다.
- reason: 상태의 원인 코드. 예: unsupported_action, missing_target, rejected, webhook_not_configured, auto_action_no_notification, dependency_error, delivery_unknown, correlation_ambiguous.
- event_at: 실제 해당 단계에서 로컬 UTC로 측정한 시각. RFC3339 Z 형식 하나만 사용한다. +00:00Z 같은 이중 timezone 표현을 만들지 않는다.
- Loki stream timestamp: 최초 event_at과 같은 시각을 사용하고 재전송 시 보존한다. 수집/조회 시각은 업무 이벤트 시각을 대체하지 않는다.

analysis 성공은 유효한 분석 결과를 얻었다는 뜻이다. remediation 성공은 특정 Docker 조치의 완료·후조건 확인이며 서비스 복구는 별도 verification이다. notification 성공은 Slack webhook 성공 응답을 받았다는 뜻이며 운영자 acknowledgement가 아니다.

상태 전이는 작은 함수와 명시적 필드로 구현한다. 범용 workflow engine, event-sourcing framework, 신규 저장 서비스는 도입하지 않는다.

## D1. Container identity / Loki application mapping

### Problem

Docker 조치 대상과 앱 로그 태그가 달라 분석 로그가 누락된다. unknown host alert가 컨테이너로 처리되거나 Loki rule이 잘못된 대상에 귀속될 수 있다.

### Current Behavior

aiops/pipeline/main.py::analyze_alerts는 annotation.container → labels.container를 사용한다. HighCpuUsage만 unknown일 때 _resolve_top_cpu_container를 호출한다. LogsCollector는 받은 이름을 그대로 Loki selector에 넣는다. HighNetworkReceive의 unknown (host-level)은 정확히 unknown을 검사하는 조건을 통과한다. SuspiciousProcessExecution rule은 frontend/backend를 합산하지만 annotation은 leafy-backend로 고정한다.

### Root Cause

Docker 이름, Fluentd tag, Prometheus 라벨을 하나의 container 문자열로 취급한다. 자동 CPU 조회에는 실제 rule의 container_name_info join이 빠져 있다.

### Target Behavior

작은 명시적 mapping으로 leafy-backend→backend, leafy-frontend→frontend, leafy-db→leafy-db를 사용한다. 역방향 변환은 이 세 항목에만 적용한다. 임의 prefix 제거로 이름을 추정하지 않는다.

각 annotation/label 후보를 trim·검증한 뒤 annotation → 유효 label fallback → unknown 분류 → 필요한 CPU auto-resolve 순서로 처리한다. null/빈 값/unknown/unknown (host-level)을 컨테이너 이름으로 사용하지 않는다. HighNetworkReceive의 host-level 신호는 컨테이너 자동 추정 없이 수동 확인 대상으로 남긴다.

CPU auto-resolve는 기존 container_name_info join과 제외 범위를 사용하고 후보가 유효할 때만 진행한다. 기존 alertname에 무관한 최고 CPU 컨테이너를 다른 종류의 alert에 귀속하지 않는다. SuspiciousProcessExecution은 container별 집계를 보존하고 실제 tag에 대응하는 Docker annotation을 생성한다.

### Interface / Data Contract

- MetricsCollector와 Docker action에는 container를 전달한다.
- LogsCollector에는 app_log_tag를 전달한다. 앱 stdout/stderr source 조건도 사용해 같은 라벨의 AIOps 결과 로그가 입력으로 섞이지 않게 한다.
- mapping 미등록 대상은 app_log_tag=null이며 전체 Loki 로그로 fallback하지 않는다.
- Pipeline 결과에 container, app_log_tag, resolution_method(annotation/label/cpu_auto/unresolved), 수집 실패·부재 reason을 기록한다.
- LLM action_targets는 정규화된 실제 대상과 일치해야 한다. host/unresolved는 Docker action을 생성·실행하지 않는다.

### Files Involved

aiops/pipeline/main.py, aiops/pipeline/collector/logs.py, aiops/pipeline/collector/metrics.py, aiops/pipeline/prompt/builder.py, leafy/fluentd/fluent.conf, docker-compose.yml, monitoring/prometheus/rules/alert.rules.yml, monitoring/loki/rules/fake/security-rules.yml, scenarios/run.py. 설정은 우선 읽기 근거이며 변경은 필요한 rule 내용으로 한정한다.

### Error Handling

Docker 대상으로 검증되지 않은 이름이나 host-level은 analysis skipped 또는 수동 확인 결과로 기록하고 조치는 skipped/missing_target이다. Docker 대상은 유효하지만 앱 tag mapping만 없는 경우에는 앱 로그 수집을 skipped/unmapped_app_tag로 기록하며, 그것만으로 대상 식별 실패라고 하지 않는다. HTTP 조회 오류와 정상적인 앱 로그 부재는 D6에 따라 구분한다. frontend 이벤트를 backend로 대체하지 않는다.

### Acceptance Criteria

- 세 서비스의 Docker 대상·앱 태그 매핑과 로그 source 필터를 검증한다.
- 유효 annotation 우선, 잘못된 annotation+유효 label fallback, unknown/host, CPU 후보 없음·조회 실패를 검증한다.
- frontend의 의심 프로세스 로그가 backend 조치 권고로 귀속되지 않는다.
- 기존 container_name_info와 CPU/메모리 탐지 join이 유지된다.

### Trade-offs / Non-goals

Compose 일괄 rename, 범용 resolver, rules/fake 이동은 하지 않는다. 현재 세 앱에 맞춘 mapping으로 범위를 제한한다. 새로운 서비스의 앱 태그는 명시적 추가가 필요하다.

## D2. Result retrieval / execution correlation

### Problem

TUI와 평가 코드가 없는 endpoint를 호출한다. 과거 결과나 다른 컨테이너의 같은 alert를 현재 실행 결과로 표시할 수 있다.

### Current Behavior

Pipeline은 deque(maxlen=20)와 Loki에 분석을 기록하지만 결과 route가 없다. run.py는 /results 개수 증가를, cli_demo.py는 /results/latest를 기대한다. ResultViewer는 최근 1시간의 같은 alert 결과를 조회하고 batch_runner는 dict 응답을 기대한다.

### Root Cause

공통 조회 계약과 실행/발생 건 식별자가 없다. bounded deque의 길이를 신규 이벤트 수로 사용할 수 없다.

### Target Behavior

**Loki를 canonical result source로 선택한다.** Pipeline의 메모리는 진단용이며 API fallback source가 아니다. Grafana·재시작 후 조회·Remediation 이벤트와 같은 저장소를 사용하기 위해서다. Loki 장애 시 명시적으로 조회 불능을 표시하는 가용성 trade-off를 수용한다.

공식 통합 TUI는 scenarios/run.py다. 개별 scenario의 ResultViewer와 batch_runner도 동일 조회 계약을 사용한다. cli_demo는 같은 계약으로 수정하고 없는 module 항목은 실행 불가로 표시하거나 메뉴에서 제외한다. 연출이 실제 실행 성공을 주장하지 않게 한다.

### Interface / Data Contract

**신규 예정 endpoint: GET /results. TASK-002 이전에는 존재하지 않는다. /results/latest는 추가하지 않고 모든 소비자를 이동한다.**

- 요청: since, until(UTC 구간, 필수), alert_name, container(대상 있는 조회), occurrence_id/result_id(확정 후 정확 조회), limit(기본 100, 최대 500), cursor(후속 페이지).
- 응답 envelope: status=ok, data=[result records], truncated=false/true, next_cursor=null/불투명 cursor. result record는 received_at/result_id 순, record 내 events는 event_at/event_id 순으로 안정 정렬한다. cursor는 동일 query 조건과 고정 until에서만 유효하다.
- result record: occurrence_id, result_id, source, 원본 labels/startsAt, alert_name, container, app_log_tag, analysis_status, result(기존 LLM schema), received_at, analysis_completed_at, remediation_status, notification_status, observation_status, events, reason.
- 시도별 최신 상태는 같은 result_id의 이벤트에서만 합성한다. target별 remediation events도 보존해 일부 성공을 전체 성공으로 보이지 않게 한다.
- 오류: 잘못된 요청 422, Loki 조회/응답 오류 503와 status=error 및 reason. 200 빈 data는 해당 구간에 일치 결과가 없다는 뜻만 가진다.
- 잘린 결과는 cursor로 끝까지 조회하거나 verification을 unknown으로 처리한다. limit 포화 응답을 완전한 결과라고 주장하지 않는다.

실행 연결 절차:

1. runner/verifier가 run_id, 기대 alert·대상·detection_mode를 가진 run context를 생성한다. 통합 runner는 subprocess에 같은 ID와 기대 조건을 전달하고 개별 실행은 자체 생성한다. 실제 시작 wall/monotonic 시각은 준비 작업 이후 부하/공격 주입 직전 verifier.start_timer에서 확정한다. 부모 UI 시작 시각을 실험 시작으로 대입하지 않는다.
2. 자연 탐지 측정은 시작 전 해당 detector/Alertmanager의 같은 alert·대상 active/pending 상태와 발생 건을 확인한다. 잔여 상태가 있거나 API 확인 불가이면 측정 실행을 시작하지 않고 blocked/unknown으로 보고한다. direct_webhook/log_only는 detector FIRING을 선행 조건으로 요구하지 않되, 직접 분석 요청에는 dedup과 기존 실행 간섭 여부를 확인한다.
3. 자연 발화는 실제 Alertmanager의 원본 labels/startsAt와 Pipeline result record를 대조해 occurrence_id를 연결한다. run_id가 Prometheus/Loki에 자동 전파된다고 가정하지 않는다. 시작 이후 새 후보 하나만 허용하며 이전 발생 건은 제외한다.
4. 후보가 여러 개거나 원본 대응을 확인할 수 없으면 correlation_ambiguous로 중단한다. 이후에는 occurrence_id와 result_id를 고정해 polling한다. 같은 alert·대상의 동시 실험은 지원하지 않는다.
5. 직접 webhook 시나리오는 labels에 scenario_run_id와 scenario_mode=direct_webhook을 명시해 발생 건을 구분한다. 이 경로에는 자동 detection 성공을 부여하지 않는다.
6. Pipeline이 occurrence_id/result_id를 Loki 본문, /action 요청, Slack 버튼/승인 상태까지 전달한다. run context는 선택된 ID를 검증 결과에 기록한다.

dedup 300초는 유지하되 정규화된 대상 기준으로 처리한다. 같은 발생 건의 webhook 반복을 수락하지 않았을 때 새 result_id를 만들지 않는다. 다른 새 발생 건이 dedup 때문에 분석되지 않으면 occurrence_id에 analysis_status=skipped, reason=deduplicated, result_id=null인 수신 기록을 남긴다. 같은 발생 건의 기존 성공 결과를 skipped로 덮어쓰지 않는다. window 이후 재분석이 수락되면 새 result_id를 부여하며 이전 실행의 조치 이벤트와 섞지 않는다. dedup과 순차 실행 제한을 실험 준비에 포함한다.

### Files Involved

aiops/pipeline/main.py, aiops/remediation/main.py, aiops/remediation/actions/notify.py, scenarios/run.py, scenarios/cli_demo.py, scenarios/common/result_viewer.py, scenarios/common/verifier.py, scenarios/eval/batch_runner.py, scenarios/category1_infra/memory_leak.py, scenarios/category1_infra/false_positive_cpu.py, scenarios/category2_security/secret_dump.py.

### Error Handling

Loki 오류를 빈 목록으로 숨기거나 메모리의 과거 결과로 대체하지 않는다. 식별자 없는 legacy 이벤트는 이력 화면에서만 표시한다. 분석 실패도 같은 result_id에 failed로 남긴다. HTTP 이벤트 전달 보장은 D6에서 보완한다.

### Acceptance Criteria

- 모든 결과 소비자가 같은 envelope와 ID 필터를 사용하며 /results/latest와 개수 증가 방식이 제거된다.
- 동일 alert의 이전 실행·다른 대상·다중 후보·deque 포화·Pipeline 재시작·Loki 오류에서 결과를 잘못 연결하지 않는다.
- 자연 발화와 직접 webhook의 연결 방식이 각각 검증된다.
- 제한 초과 결과를 페이지 처리하거나 불완전하다고 표시한다.

### Trade-offs / Non-goals

Loki 장애 시 조회 가용성보다 사실 정확성을 우선한다. 신규 DB/JSONL writer/범용 실행 등록 서비스는 추가하지 않는다. 동시에 같은 alert·대상에 대한 자연 발화 실험을 지원하기 위한 distributed tracing은 범위 밖이다. TASK-002는 result 조회와 식별 계약을 구현하고 정확한 조치 상태·시간 측정은 후속 TASK에서 완성한다.

## D3. Actual remediation result / approval

### Problem

LLM 권고가 실제 실행 성공처럼 표시되고 일부 미실행도 Success로 반환된다. 승인 가능한 조치와 callback handler가 다르다.

### Current Behavior

run.py::panel_remediation은 action_risk로 성공을 추정한다. ContainerActions.isolate는 고정 네트워크 부재를 무시한다. 자동 handler는 4개, 승인 handler는 2개다. schema의 SCALE은 실행되지 않는다. callback에는 서명·중복 승인 검증이 없다.

### Root Cause

조치 실행 결과가 문자열이고 타겟 후조건·상태 계약·승인 대상 검증이 없다. LLM의 risk 필드만으로 실행 권한을 결정한다.

### Target Behavior

상태 전이: recommended → executing → succeeded/failed 또는 recommended → awaiting_approval → executing → succeeded/failed. 거부·NONE·미지원은 skipped와 reason이다. observation unknown은 상태 성공으로 추정하지 않는다.

실행 정책은 코드에서 명시한다. RESTART/ISOLATE/PAUSE는 승인 필수, THROTTLE은 low risk와 confidence>=0.7일 때 자동 실행 가능, 그 외는 기존 medium/low-threat 알림 또는 승인 정책을 따른다. NOTIFY/NONE은 Docker 조치를 하지 않는다. SCALE은 unsupported_action으로 skipped이며 실행 가능한 승인 버튼을 제공하지 않는다. prompt의 THROTTLE 위험도 규칙도 low 예제와 일치시킨다.

### Interface / Data Contract

- /action 입력: 기존 alert/analysis + occurrence_id/result_id/정규화된 container. schema로 target을 검증하며 LLM이 임의로 지정한 다른 컨테이너에 조치하지 않는다.
- 조치 결과: action_type, target, remediation_status, reason, started_at, completed_at, verification(후조건), result_id.
- target별 성공 조건: RESTART는 재시작 후 running 및 시작 시각 변화, PAUSE는 paused=true, THROTTLE은 의도한 CPU quota/period, ISOLATE는 실제 대상이 연결된 Compose leafy-net의 연결 해제 확인.
- 네트워크는 컨테이너 연결 목록/Compose network label에서 찾는다. 누락·모호함은 failed이며 임의 다른 네트워크를 끊지 않는다. 원래 미연결은 skipped/already_disconnected다. ISOLATE는 leafy-net 분리이며 mgmt-net까지 격리됐다는 뜻이 아니다.
- 자동·승인 실행 모두 aiops-remediation에 같은 상태 계약으로 기록한다. timeline은 별도 event로 연결하고 동일 조치를 중복 실행하지 않는다.
- 승인 요청은 서버가 저장한 pending action(result_id, action_type, targets)에 바인딩한다. callback 입력 값만 신뢰하지 않는다. 유효 pending 건 하나를 원자적으로 executing으로 전환해 중복 클릭을 막는다.
- SLACK_SIGNING_SECRET으로 callback 서명·요청 시각을 검증한다. 누락 시 승인 실행을 비활성화하고 실패 원인을 표시한다. 외부 callback URL/프록시 설정은 운영 환경에서 확인한다.
- 승인 callback은 요청 확인 후 background로 실제 조치하고 결과 이벤트와 Slack message를 갱신한다. 서버 재시작으로 pending 상태가 사라지면 재승인을 거부하고 새 요청을 요구한다.

### Files Involved

aiops/remediation/main.py, aiops/remediation/actions/container.py, aiops/remediation/actions/notify.py, aiops/pipeline/prompt/builder.py, aiops/pipeline/schemas/llm_output.py, scenarios/run.py, scenarios/cli_demo.py, scenarios/common/result_viewer.py, docker-compose.yml(향후 signing secret 전달).

### Error Handling

Docker 오류·후조건 실패는 failed, 실행 결과 불명은 observation unknown으로 표시한다. notification 실패와 조치 실패를 분리한다. 승인 누락/불일치/재사용은 실행하지 않는다. TUI와 Slack는 권고와 실제 결과를 구분하며 조치 성공을 서비스 복구로 표현하지 않는다.

### Acceptance Criteria

6개 최소 상태와 미관측 null을 표시한다. 네트워크 부재·Docker 예외·empty target·미지원 SCALE·NONE을 성공으로 표시하지 않는다. PAUSE/THROTTLE 승인 handler를 포함하고 중복/잘못된 서명 callback이 조치를 실행하지 않는다. 서버 정책상 고위험 조치는 LLM이 low라고 응답해도 자동 실행되지 않는다.

### Trade-offs / Non-goals

실행 권한 및 상태를 확인하는 작은 pending map과 handler 수준 검증으로 제한한다. 영속 승인 DB·전체 RBAC·여러 replica 간 exactly-once 조치는 범위 밖이다. 프로세스 재시작 이후 자동 재실행하지 않는다. 이미 수행한 Docker 조치를 코드 rollback이 자동 되돌리지 않는다.

## D4. MTTD / Slack notification latency

### Problem

현재 mtta_seconds는 시나리오 시작부터 Slack Loki 이벤트까지인데 문서와 화면은 Alert부터라고 표시한다. 중복 이벤트·이전 발생 건·clock 차이가 측정을 왜곡한다.

### Current Behavior

verifier.start_timer는 _start_time=time.time()을 저장한다. verify는 Prometheus FIRING polling 시각을 _alert_firing_time으로 저장한다. verify_mtta는 Slack Loki timestamp에서 _start_time을 뺀다. _query_loki_slack_sent는 관측된 FIRING 시각부터 전체 job 50건을 조회하고 첫 성공을 반환한다. notify.py와 remediation/main.py가 중복 이벤트를 기록한다. dispatched_at은 HTTP 요청 전이다.

### Root Cause

측정 기준점과 이벤트 의미가 정의되지 않았고 Alert 발생 건 연결이 없다.

### Target Behavior

- MTTD: Scenario start → Alert FIRING observed. 동일 verifier의 monotonic 시각 차이를 사용한다.
- Slack Notification Latency: Alert FIRING 기준점 → Slack delivery success event. **운영자 acknowledgement가 아니다.**
- 현재 API만으로 실제 FIRING 전이 시각을 보장할 수 없으므로 초기 구현은 FIRING observed를 기준점으로 사용하고 basis=firing_observed를 반드시 표시한다. 실제 전이 시각을 측정했다고 주장하지 않는다. startsAt/activeAt을 임의 대입하지 않는다.
- Slack 성공이 늦은 polling 관측보다 먼저라면 음수를 0으로 보정하지 않는다. latency=null, reason=late_firing_observation으로 기록한다. notification 성공 자체는 유지한다.

### Interface / Data Contract

- _start_time: 시나리오 시작 UTC epoch, 조회 구간/발생 건 연결용. 별도 monotonic 시작 시각을 함께 보관한다.
- _alert_firing_time: API FIRING 응답을 확인한 직후의 wall 시각. 같은 순간 monotonic 값을 보관한다. 요청 직전의 오래된 loop now를 사용하지 않는다.
- mttd_seconds = firing_observed_monotonic - scenario_started_monotonic.
- slack_notification_latency_seconds = notification.event_at - firing_observed_at, basis=firing_observed. 서로 다른 프로세스의 clock 차이·polling 오차를 기록하고 시간 정합성이 불확실하면 null/clock_uncertain이다.
- mtta_seconds는 새 writer에서 사용하지 않는다. 과거 필드는 legacy_metric으로 표시하고 새 지표 평균에 포함하지 않는다. ResultViewer.show 인자와 scenario 호출부·결과 출력도 함께 변경한다.
- Notifier는 dispatch 결과만 반환한다. Remediation._push_slack_status 한 곳에서 각 시도당 aiops-slack 이벤트를 쓴다. event_at은 HTTP 성공/실패 응답 또는 예외가 결정된 직후 시각이다. 기존 dispatched_at은 requested_at으로 의미를 명확히 구분한다.
- notification 이벤트: occurrence_id, result_id, event_id, event_at, notification_status, response_code, response_text(비밀 제거), reason, notification_type.
- SUCCESS: HTTP 200 및 본문 ok. FAILED: 명시적 거부 응답 또는 전송되지 않았음이 확정된 오류. timeout처럼 수락 여부가 불명확하면 notification_status=null, observation_status=unknown, reason=delivery_unknown이다. SKIPPED: webhook 미설정 등 필요한 알림을 못 보냄. NOT_APPLICABLE: 자동 조치 정책상 notification이 필요 없음.
- auto 경로도 NOT_APPLICABLE decision을 기록해 verifier가 timeout까지 기다리지 않게 한다. notification이 필요한 시나리오의 SKIPPED는 해당 acceptance 실패다.
- 조회는 run 시작 구간부터 정확한 occurrence_id/result_id/event를 필터링하고 페이지를 확인한다. 모든 stream의 일치 성공 중 가장 이른 event_at을 사용한다. 이력의 같은 alert만으로 성공 판정하지 않는다.

### Files Involved

scenarios/common/verifier.py, scenarios/common/result_viewer.py, scenarios/run.py, scenarios/eval/batch_runner.py, scenarios/eval/report.py, scenarios/category1_infra 및 category2_security의 ResultViewer 호출부, aiops/remediation/main.py, aiops/remediation/actions/notify.py, aiops/pipeline/main.py.

### Error Handling

notification timeout, 전송 실패, Loki 조회 불능, 상관관계 불명, 시계 이상, NOT_APPLICABLE을 구분한다. 나노초 정밀도는 clock 정확성을 보장하지 않는다. 측정 실패로 notification 성공 사실을 지우지 않는다. 전송 재시도에 의한 가장 이른 성공 선택은 기록된 시도에만 적용하며 신규 자동 재전송 정책은 추가하지 않는다.

### Acceptance Criteria

시작 0초·발화 관측 30초·Slack 성공 50초 fixture에서 MTTD=30, notification latency=20이다. 과거 발생 건·중복 이벤트·다른 stream 순서·빠른 Slack·FAILED/SKIPPED/NOT_APPLICABLE·clock 오류를 각각 검증한다. 자동 조치의 무알림은 timeout/실패로 기록하지 않는다.

### Trade-offs / Non-goals

Prometheus Histogram, operator acknowledgement/승인 지연 측정, 기존 로그 일괄 변환은 범위 밖이다. 단일 실행의 지연과 여러 유효 실행의 평균을 구분한다. Polling 기반 측정의 정확도 한계를 숨기지 않는다.

## D5. Detector / scenario verification contract

### Problem

단순 로그 발견 또는 직접 webhook 분석을 자동 탐지 end-to-end 성공처럼 기록한다.

### Current Behavior

verifier._get_alert_state는 Prometheus /api/v1/alerts만 조회한다. verify_loki는 keyword 존재를 확인한다. brute_force·secret_dump·lateral_movement·suspicious_process_exec·container_escape_attempt·sql_injection 등은 로그 발견으로 결과를 기록한다. memory_leak/false_positive_cpu/secret_dump에는 직접 webhook 경로가 있다.

### Root Cause

scenario의 공격 성공, 로그 생성, rule 발화, 전달 성공이 하나의 success 값으로 합쳐져 있다.

### Target Behavior

각 run에 detection_mode=prometheus/loki/direct_webhook/log_only와 required_stages를 명시한다. 최소 단계는 log_generation, detection, alertmanager_delivery, analysis, notification, remediation, recovery다. 해당 run에 필요한 단계만 판정하고 범위 밖은 skipped/not_required로 표시한다.

### Interface / Data Contract

- Prometheus: 기존 /api/v1/alerts에서 기대 alert·대상을 matching하고 FIRING 확인. Alertmanager /api/v2/alerts의 원본 발생 건과 이어서 연결.
- Loki: 설치 버전의 GET /prometheus/api/v1/alerts 또는 /prometheus/api/v1/rules 응답에서 해당 Ruler FIRING과 labels를 확인한 뒤 Alertmanager 원본과 연결. 공식 [Loki HTTP API](https://grafana.com/docs/loki/latest/reference/loki-http-api/)에 정의된 외부 API다. 설치 버전의 실제 응답은 runtime에서 확인하며 repository의 FastAPI route로 추가하지 않는다. endpoint 미지원이면 검증 불능으로 처리하고 로그 발견으로 대체하지 않는다.
- Alertmanager active는 라우팅 상태 증거이며 detector FIRING과 동일 개념이 아니다. silence/inhibition/전달 대기는 별도 원인으로 표시.
- Pipeline의 동일 occurrence_id 수신/분석 이벤트까지 확인해야 전달·분석 단계를 완료한다.
- direct_webhook: 자동 detection/Alertmanager 단계는 status=skipped, reason=not_applicable로 기록하고 실제 분석 이후 단계만 검증한다. 자연 탐지 검증 run에는 직접 webhook을 보내지 않는다.
- log_only: keyword 발견을 log_generation success로만 기록한다. UnauthorizedDBAccess의 >3 조건을 로그 한 건으로 대체하지 않는다.
- 단계별 status=succeeded/failed/skipped/unknown 및 reason과 evidence(조회 API, labels, timestamps, result_id)를 검증 기록에 보존한다. 비적용 단계는 status=skipped, reason=not_applicable이며 notification의 NOT_APPLICABLE과 명시적으로 대응한다.
- verifier는 로컬 검증 기록에 더해 aiops-timeline에 event=verification_stage를 기록한다. detector/대상/run_id와 연결된 occurrence_id/result_id, 원래 관측 event_at을 포함한다. 발생 건 연결 전 증거는 로컬에 유지하고 연결 후 기록하며, 연결 불능을 임의 ID에 붙이지 않는다. 이 기록이 D7의 Loki 검증 이력 표시 근거다. 기록 실패는 D6 기준으로 관측 불능이다.
- 전체 verification 성공은 required_stages가 모두 통과한 경우다. 기대한 비적용(NOT_APPLICABLE)만 허용하며 명시적 실패·unknown을 success로 합산하지 않는다.

### Files Involved

scenarios/common/verifier.py, scenarios/run.py, scenarios/eval/batch_runner.py, scenarios/eval/report.py, scenarios/category1_infra/*.py, scenarios/category2_security/*.py, scenarios/category3/scenario_pgminer.py. Prometheus/Loki rules와 Alertmanager 설정은 기대 조건을 정하는 읽기 근거다.

### Error Handling

detector/AM API 장애, 이전 pending/firing, 침묵·억제, 조건 미충족, 전달 timeout을 구분한다. 한 rule에 여러 target 후보면 ambiguous로 처리한다. 시간창이 끝났다는 이유로 임의 직접 webhook을 보내 자동 탐지를 통과시키지 않는다. scenario 종료·cleanup은 실제 시나리오의 기존 복구 절차를 확인해 수행한다.

### Acceptance Criteria

Prometheus 자연 발화 1종, Loki 자연 발화 1종, direct webhook 1종, 로그만 있고 rule 조건은 미충족인 경우를 검증한다. Loki 자연 발화는 Ruler→AM→Pipeline 연결 증거가 모두 있어야 통과한다. 기존 로그 파일을 덮어써 과거 의미를 바꾸지 않는다.

### Trade-offs / Non-goals

모든 보안 시나리오를 무조건 자연 탐지 성공 사례로 바꾸지 않는다. data_exfil 같은 탐지 사각지대도 명시적 결과다. detector별 관측 API를 작은 분기로 구현하며 범용 검증 플랫폼을 도입하지 않는다.

## D6. HTTP / integration failure handling

### Problem

HTTP 4xx/5xx와 query 실패가 성공 또는 정상 no-data처럼 보인다. Loki 장애에서는 실패 기록 자체도 남지 않을 수 있다.

### Current Behavior

forward_to_remediation과 여러 Loki push가 응답 상태를 확인하지 않는다. collector와 조회 helper 일부는 응답 JSON의 빈 data를 정상 결과처럼 사용한다. Pipeline timeline timestamp에 +00:00Z가 붙는다.

### Root Cause

전송 완료, HTTP 수락, 업무 성공, 관측 가능성을 구분하지 않는다.

### Target Behavior

모든 관련 HTTP 호출에서 status와 응답 계약을 검사한다. query 오류는 dependency_error, 정상 empty는 no_data로 구분한다. 데이터 수집 자체가 실패한 경우 분석을 정상 완료했다고 하지 않고 조치를 진행하지 않는다. 정상적인 빈 앱 로그만으로 LLM 호출 전체를 실패시키지는 않되 evidence 부족을 기록한다.

### Interface / Data Contract

- Loki push는 정상 2xx 수락 확인 후 기록 성공으로 본다. failed push를 성공 로그로 남기지 않는다.
- /action의 2xx는 request 처리 응답이며 조치 성공은 D3의 구조화 상태로 판단한다.
- /action timeout/접속 종료 후 실제 실행 여부를 알 수 없으면 observation_status=unknown, reason=delivery_unknown. side effect 요청을 자동 재시도하지 않는다.
- canonical 분석 결과 기록 실패 시 해당 분석의 자동 조치 전달을 중단한다. 이미 완료한 조치의 후속 기록 실패는 조치 자체를 실패했다고 덮어쓰지 않는다.
- Loki 기록 불능은 로컬 structured logger에 ID·단계·오류를 남기고 조회 API는 503을 반환한다. Loki에 실패 이벤트를 무한 재귀 기록하지 않는다.
- Loki가 복구되어도 기록이 유실된 단계는 unknown으로 유지하며 과거 성공을 만들어 넣지 않는다. /results가 정상 응답하지만 해당 event가 없으면 완료 timeout 이후 observation unknown으로 표시한다.
- Slack webhook URL, 서명 secret, API credential은 오류 payload에 포함하지 않는다.

### Files Involved

aiops/pipeline/main.py, aiops/pipeline/collector/metrics.py, aiops/pipeline/collector/logs.py, aiops/remediation/main.py, aiops/remediation/actions/notify.py, scenarios/common/verifier.py, scenarios/common/result_viewer.py, scenarios/eval/batch_runner.py.

### Error Handling

연결 실패·timeout·4xx·5xx·잘못된 JSON·유효한 빈 결과를 각각 처리한다. Loki append 재시도를 나중에 추가한다면 같은 event_id/event_at을 유지해야 하나 이번 단계는 durable retry queue를 만들지 않는다. 임의 재시도로 Docker/Slack side effect를 반복하지 않는다.

### Acceptance Criteria

HTTP fixture로 400/500/timeout/잘못된 응답/empty를 검증한다. 실패를 success 로그·빈 결과·TUI 완료로 바꾸지 않는다. Docker 요청 응답 유실은 실행 실패 단정 대신 unknown이다. Loki 실패 중에도 로컬 오류는 남고 secondary exception으로 원인을 덮지 않는다.

### Trade-offs / Non-goals

새 circuit breaker framework, 영속 outbox, 분산 재시도 시스템은 도입하지 않는다. 계측 저장소 장애 시 일부 가시성을 잃는 한계를 명시한다. 해당 함수의 작은 명시적 처리로 한정한다.

## D7. Existing Grafana dashboard correctness

### Problem

provisioning 누락이라는 기존 전제가 틀렸고 일부 패널 의미가 rule과 맞지 않는다.

### Current Behavior

provider, datasource와 dashboard 두 개가 존재한다. DB 패널은 aggregate sum/50, rule은 개별 값/40이다. Prometheus ALERTS로 Loki 전체 alert를 나타낼 수 없다. SOC CPU 패널은 전체 컨테이너 합계다.

### Root Cause

패널 제목·query·집계·탐지 범위를 코드와 대조하지 않고 신규 작성 작업으로 분류했다.

### Target Behavior

기존 UID aiops-main/leafy-aiops와 datasource UID를 유지한다. panel별 query, threshold, aggregation, datasource, alert representation을 검증하고 필요한 부분만 수정한다.

### Interface / Data Contract

- DB 총 연결 수 패널은 총합으로 유지하되 rule 임계값이라고 표시한 50 선/제목을 제거한다. Alert 비교 패널이 필요하면 실제 rule의 개별 series >40과 동일 의미로 표시한다. rule 의미 자체는 이 작업에서 바꾸지 않는다.
- Prometheus ALERTS 패널은 Prometheus 범위라고 명시한다. Loki detection/AM 전달은 D5의 검증 이벤트와 Pipeline 수신 기록으로 구분해 표시하며 전체 current firing 목록이라고 주장하지 않는다.
- 분석 건수는 Loki target을 확인하고 전체 건수 목적이면 stream별 count를 sum한다. 같은 분석을 timeline과 중복 합산하지 않는다.
- SOC CPU 전체 합계는 host 전체 컨테이너 합계라고 표시하거나 데모 대상별 join/filter로 한정한다. LLM 자체 CPU를 공격 대상 CPU로 오해시키지 않는다.
- 정상 no-data, 0건, query 오류, source 장애를 분리한다. 조회된 notification SUCCESS와 remediation succeeded를 혼용하지 않는다.

### Files Involved

monitoring/grafana/provisioning/dashboards/aiops_dashboard.json, monitoring/grafana/provisioning/dashboards/leafy_aiops_soc_dashboard.json, monitoring/grafana/provisioning/dashboards/dashboards.yml, monitoring/grafana/provisioning/datasources/datasources.yml, monitoring/prometheus/rules/alert.rules.yml, monitoring/loki/rules/fake/security-rules.yml, docker-compose.yml.

### Error Handling

query error가 있는 패널을 0으로 가려서 통과시키지 않는다. ID가 없는 이전 이벤트는 이력 데이터로 표시하고 새 correlation 성공률 계산에서 제외한다.

### Acceptance Criteria

두 JSON 파싱, provider path/mount/datasource UID 확인, 기존 UID 조회, 정상/이벤트/장애 상태별 패널 확인. DB 패널은 rule 임계값과 다른 집계임을 명확히 하고 Loki alert 범위를 정직하게 표시한다. 무이벤트 상태에 모든 panel nonempty를 요구하지 않는다.

### Trade-offs / Non-goals

새 dashboard 생성, row/panel 수 확대, UID rename, Grafana-managed alert 체계 이전은 하지 않는다. provider와 mount는 실제 문제가 확인될 때만 수정한다.

## D8. Periodic scan flag / lifecycle

### Problem

periodic 활성화를 코드 주석 편집으로 제어하며 활성화 시 일반 분석과 LLM 자원을 경쟁한다.

### Current Behavior

lifespan의 create_task/cancel은 주석 처리돼 있다. periodic_log_check와 periodic_llm_health 본체는 존재한다. _call_llm_raw는 일반 _llm_semaphore를 우회한다. periodic 로그 입력은 backend/frontend/leafy-db 태그이며 Slack을 직접 보낸다.

### Root Cause

실행 flag와 task 정리 계약이 없고 로그 태그가 조치 대상까지 전달될 수 있다.

### Target Behavior

ENABLE_PERIODIC_SCAN=false를 기본으로 한다. true일 때 기존 coroutine 두 개를 각각 한 번 시작하고 shutdown finally에서 cancel한 뒤 await해 정리한다. 기존 시작 지연과 10분/5분 주기를 유지한다. false에서도 webhook 분석은 정상 동작한다.

### Interface / Data Contract

- config.py에서 true/false(대소문자 허용)를 명시 파싱한다. bool('false') 방식은 쓰지 않는다. 지원하지 않는 값은 시작 시 설정 오류로 표시한다.
- Compose에 환경변수 기본 false를 전달한다.
- 일반 call_llm과 periodic _call_llm_raw는 같은 semaphore를 사용하되 중첩 acquire하지 않는다. worker 확대나 Ollama 병렬 수 증가는 하지 않는다.
- periodic app tag는 D1 mapping을 거쳐 Docker target으로 전환한다. periodic 이벤트는 source=periodic, 별도 occurrence_id/result_id를 생성해 기존 correlation 필드 형식을 재사용하되 detector latency 측정에서 제외한다.
- periodic 승인/notification은 Remediation의 D3/D4 경로를 재사용하도록 전달한다. source를 보존하고 기존 Pipeline 직접 Slack 전송으로 status writer를 다시 분산하지 않는다. periodic 요청은 자동 Docker 조치하지 않고 승인 또는 알림 정책을 유지한다.
- llm_health_check의 aiops-pipeline 대상은 알림 전용이며 임의 자동 자기 조치를 허용하지 않는다.

### Files Involved

aiops/pipeline/config.py, aiops/pipeline/main.py, aiops/remediation/main.py, docker-compose.yml. notifier는 기존 D3/D4 인터페이스 재사용 대상이다.

### Error Handling

CancelledError는 정상 shutdown 경로로 처리한다. 한 scan 실패가 webhook 처리를 중단하지 않는다. true에서 dependency 실패는 D6 기준으로 기록한다. feature flag false로 되돌리면 periodic만 중단돼야 한다.

### Acceptance Criteria

false: task 0개, webhook 정상. true: 두 task 1회 시작, 공유 semaphore 최대 동시 LLM 호출 1, shutdown 시 잔여 task 없음. periodic backend 태그가 Docker target으로 그대로 전달되지 않으며 결과는 source=periodic으로 구분된다.

### Trade-offs / Non-goals

스케줄러 framework나 별도 task 관리 서비스를 만들지 않는다. TASK-008은 lifecycle·flag·기존 notification 경로 연결만 수행한다. 선행 TASK에서 확정한 identity/state/HTTP 계약을 재사용하고 scan 탐지 알고리즘은 바꾸지 않는다.

## 설계와 TASK 대응

| 설계 | 구현 TASK |
|---|---|
| D1 | TASK-001 |
| D2 및 공통 ID | TASK-002 |
| D3 | TASK-003 |
| D4 | TASK-004 |
| D5 | TASK-005 |
| D6 | TASK-006 (기본 오류 계약은 앞선 TASK에서도 준수) |
| D7 | TASK-007 |
| D8 | TASK-008 |
| 전체 계약과 runtime 가정 | TASK-009 |

일부 TASK만 완료된 동안 후속 단계의 상태를 임의 성공으로 채우지 않는다. null/pending/unknown으로 표시하고 integration acceptance는 TASK-009에서 최종 확인한다.
