# Implementation Tasks

검증 기준일: 2026-09-19. **모든 TASK는 Pending이며 아직 구현하지 않았다.**

[ARCHITECTURE](./ARCHITECTURE.md)의 As-Is와 [DESIGN](./DESIGN.md)의 D1~D8·공통 계약을 따른다. 아래 Test procedure는 향후 구현 단계용이다. 이번 문서 편집에서는 Docker 실행/재시작, 공격 시나리오, 앱 테스트를 실행하지 않는다.

## 작업 원칙

- 한 TASK의 소스·검증·문서 변경 범위를 먼저 확인하고 해당 작업만 구현한다. 앞선 TASK에서 정의한 인터페이스를 재사용한다.
- Files to inspect는 읽기 대상, Files likely to modify는 예상 수정 대상이다. 검증 결과 수정이 필요 없는 설정까지 일괄 편집하지 않는다.
- 목록의 source/configuration 파일은 현재 실제 repository에 존재한다. GET /results와 새 필드는 TASK-002 이후 구현할 To-Be 계약이지 현재 존재하는 기능이 아니다.
- 구체적 테스트 파일은 현재 존재하지 않는 경로를 실행 명령으로 지어내지 않는다. 향후 구현 단계에서 버그를 검증할 최소 fixture/test를 작성하고 실제 생성한 위치를 해당 TASK에 기록한다.
- 검증은 정상 케이스와 의미 있는 실패 케이스로 한정한다. reversible 문구 변경마다 별도 테스트를 만들지 않는다.
- 코드 rollback은 해당 TASK의 변경만 되돌린다. 사용자의 기존 변경·legacy·기존 로그를 reset/checkout으로 덮어쓰지 않는다.
- source가 구현과 다르면 As-Is는 source를 따르고 목표 계약을 재검토한다. 시간 추정·실행 성공을 근거 없이 작성하지 않는다.

## 최종 목록과 의존성

| ID | Goal 요약 | 필수 선행 | 상태 |
|---|---|---|---|
| TASK-001 | Container identity / Loki app log mapping | 없음 | Pending |
| TASK-002 | TUI result retrieval / execution correlation | 001 | Pending |
| TASK-003 | Remediation 실제 결과 / 성공 상태 / 승인 검증 | 001, 002 | Pending |
| TASK-004 | MTTD / Slack notification latency | 002, 003 | Pending |
| TASK-005 | Loki Ruler / scenario 검증 계약 | 001, 002, 004 | Pending |
| TASK-006 | HTTP / integration failure handling 완성 | 002, 003, 004, 005 | Pending |
| TASK-007 | 기존 Grafana dashboard 검증·보정 | 003, 004, 005, 006 | Pending |
| TASK-008 | Periodic scan flag / lifecycle | 001, 002, 003, 004, 006 | Pending |
| TASK-009 | E2E smoke test / 최종 문서 | 001~008 | Pending |

권장 순서: **001 → 002 → 003 → 004 → 005 → 006 → 007 → 008 → 009**.

007과 008 사이에는 기술적 선행 관계가 없다. 기본 webhook 경로는 periodic flag를 필요로 하지 않는다. 006이 뒤에 있어도 앞선 TASK에서 새로 만드는 API는 처음부터 status/오류 계약을 준수해야 한다. 006은 남아 있는 기존 호출·교차 경로를 완성하는 작업이다.

## TASK-001 — Container identity / Loki app log mapping

### Goal

D1에 따라 Docker 조치 대상과 Loki 앱 로그 태그를 분리하고 host alert의 오귀속을 막는다.

### Problem

LogsCollector가 leafy-backend/leafy-frontend로 앱 로그를 조회한다. unknown (host-level)이 유효 대상처럼 전달되고 CPU auto-resolve가 name join 없이 실행된다. SuspiciousProcessExecution은 frontend 이벤트도 backend로 귀속시킬 수 있다.

### Files to inspect

- aiops/pipeline/main.py, aiops/pipeline/collector/logs.py, aiops/pipeline/collector/metrics.py
- aiops/pipeline/prompt/builder.py, docker-compose.yml, leafy/fluentd/fluent.conf
- monitoring/prometheus/rules/alert.rules.yml, monitoring/loki/rules/fake/security-rules.yml
- scenarios/run.py

### Files likely to modify

- aiops/pipeline/main.py, aiops/pipeline/collector/logs.py
- monitoring/loki/rules/fake/security-rules.yml: 해당 rule의 집계/annotation만
- scenarios/run.py: 잘못된 loki_container 값만
- current_info_files/ARCHITECTURE.md, current_info_files/DESIGN.md, current_info_files/TASKS.md: 구현 사실 갱신

### Dependencies

없음. D1의 mapping/unknown 정책을 기준으로 진행한다.

### Implementation steps

1. 세 서비스 mapping과 후보 정규화를 작은 함수/상수로 정의한다.
2. annotation 우선·유효 label fallback·unknown/host 분류를 기존 analyze_alerts에 적용한다.
3. HighCpuUsage auto-resolve에 container_name_info join과 올바른 대상 범위를 적용한다.
4. collector에는 앱 tag/source 조건을 전달하고 Metrics/Docker에는 Docker 이름을 유지한다.
5. SuspiciousProcessExecution의 container별 집계와 annotation을 수정한다. fake 디렉터리는 유지한다.
6. 로그 없음과 식별 불능을 결과 reason으로 구분한다.

### Explicit non-goals

Compose 전체 rename, 범용 resolver, rule 임계값 전면 조정, fake 이동, 다른 시나리오 리팩터링.

### Acceptance criteria

- [ ] backend/frontend/db 앱 로그 입력과 Docker target이 D1 mapping대로 연결된다.
- [ ] 앱 source만 조회하고 AIOps 결과 로그를 앱 증거로 재사용하지 않는다.
- [ ] annotation·label·unknown·host·CPU fallback 각각의 기대 대상이 검증된다.
- [ ] frontend 의심 프로세스 alert가 backend로 귀속되지 않는다.
- [ ] 기존 /metrics mapping과 CPU/메모리 join은 유지된다.

### Test procedure

HTTP/Docker fixture로 실제 labels와 tag를 재현해 collector query와 resolved target을 확인한다. rule query는 사용 가능한 실제 evaluator로 container별 결과를 확인하고 도구가 없으면 정적 확인과 runtime 미검증을 구분한다. 향후 실행 환경에서 세 앱의 sample 로그를 각각 조회해 mapping을 확인한다.

### Failure cases

빈 annotation, 잘못된 annotation과 유효 label, unknown (host-level), Docker 조회 실패, CPU 결과 무명/빈 결과, 앱 로그 없음, frontend/backend 동시 의심 로그.

### Rollback considerations

mapping/관련 rule 변경을 함께 되돌린다. 기존 rule 파일과 이름을 보존하고 container를 재생성하지 않는다. frontend 귀속 오류가 다시 생기는 rollback임을 기록한다.

## TASK-002 — TUI result retrieval / execution correlation

### Goal

D2의 Loki canonical result와 단일 GET /results를 구현하고 모든 결과 소비자를 실행별 조회로 연결한다.

### Problem

결과 route가 없고 TUI의 개수 기반 polling·1시간 lookback이 과거 결과를 섞는다. 모델이 원본 Alert labels를 일부 버린다.

### Files to inspect

- aiops/pipeline/main.py, aiops/pipeline/schemas/llm_output.py
- aiops/remediation/main.py, aiops/remediation/actions/notify.py
- scenarios/run.py, scenarios/cli_demo.py, scenarios/common/result_viewer.py, scenarios/common/verifier.py
- scenarios/eval/batch_runner.py
- scenarios/category1_infra/memory_leak.py, scenarios/category1_infra/false_positive_cpu.py, scenarios/category2_security/secret_dump.py

### Files likely to modify

- aiops/pipeline/main.py, aiops/remediation/main.py, aiops/remediation/actions/notify.py
- scenarios/run.py, scenarios/cli_demo.py, scenarios/common/result_viewer.py, scenarios/common/verifier.py
- scenarios/eval/batch_runner.py
- scenarios/category1_infra/memory_leak.py, scenarios/category1_infra/false_positive_cpu.py, scenarios/category2_security/secret_dump.py
- current_info_files/ARCHITECTURE.md, current_info_files/DESIGN.md, current_info_files/TASKS.md, current_info_files/README.md

식별 envelope는 기존 main.py에 정의한다. 기존 LLM output schema에 운영 ID를 출력하도록 요구하지 않는다.

### Dependencies

TASK-001. 후속 TASK-003/004의 상태 값은 아직 없을 수 있으므로 null/pending으로 처리하고 성공을 추정하지 않는다.

### Implementation steps

1. 원본 labels/startsAt 보존 및 occurrence_id, result_id, event_id 생성 계약을 구현한다.
2. Pipeline 수신·분석 상태와 결과를 Loki 본문에 기록하고 /action·Slack payload에 식별자를 전달한다.
3. Loki query adapter로 GET /results envelope, 필수 구간, 필터, pagination, 422/503 처리를 구현한다.
4. run context를 runner→subprocess/verifier로 전달하고 개별 실행의 자체 생성 경로를 만든다.
5. D2의 baseline·새 발생 건 하나·원본 AM payload 대응 방식으로 실행과 결과를 연결한다. 이전/여러 후보는 매칭하지 않는다.
6. /results/latest·결과 개수 비교·식별 없는 이력 fallback을 소비 코드에서 제거한다. cli_demo의 없는 module 참조도 정리한다.
7. direct webhook payload에 scenario_run_id와 mode를 넣고 자동 detection과 구분한다.

### Explicit non-goals

신규 DB/JSONL writer, /results/latest 추가, 동시 동일 대상 자연 실험 지원, LLM schema에 run_id 추론 요구, 새 dashboard.

### Acceptance criteria

- [ ] GET /results 계약과 원본 라벨/시각 보존이 fixture로 확인된다.
- [ ] 모든 결과 소비자는 동일 envelope를 사용한다.
- [ ] 과거/타 컨테이너/다중 후보/ID 없는 이벤트가 현재 성공으로 표시되지 않는다.
- [ ] Pipeline 재시작 이후 Loki 결과 조회가 가능하고 deque 포화와 무관하다.
- [ ] Loki 실패는 503이며 API 빈 목록과 구분된다.
- [ ] 잘린 페이지를 끝까지 처리하거나 관측 불완전으로 표시한다.

### Test procedure

이 TASK에서 route 구현 후 HTTP fixture/앱 테스트 클라이언트로 /results를 호출한다. 고정 Loki fixture에 과거 실행·새 발생 건·같은 발생 건의 재분석·다른 target을 넣고 ID 매칭을 확인한다. runner/subprocess context 전달과 각 소비자 파싱을 검증한다. 자연 detector/AM payload 대응은 TASK-005/009에서 runtime 확인한다.

### Failure cases

빈 결과, malformed Loki JSON, 503, 후보 2개, ID 누락, timestamp 표현 차이, 제한 초과, 재분석, 프로세스 재시작, 존재하지 않는 demo module.

### Rollback considerations

API와 소비자 변경을 한 단위로 되돌린다. Loki에 남은 새 ID 필드는 삭제하지 않는다. rollback 후 route 누락 상태로 돌아간다는 점을 기록하며 과거 이벤트를 변환하지 않는다.

## TASK-003 — Remediation actual result / success-state correctness

### Goal

D3에 따라 권고와 실제 조치 결과를 분리하고 미실행을 성공으로 남기지 않는다.

### Problem

risk 기반 성공 추정, isolate no-op 성공, 승인 handler 부족, 서명·중복 승인 검사 부재가 있다.

### Files to inspect

- aiops/remediation/main.py, aiops/remediation/actions/container.py, aiops/remediation/actions/notify.py
- aiops/pipeline/prompt/builder.py, aiops/pipeline/schemas/llm_output.py
- scenarios/run.py, scenarios/cli_demo.py, scenarios/common/result_viewer.py
- docker-compose.yml

### Files likely to modify

위 파일들과 current_info_files/DESIGN.md, current_info_files/TASKS.md, current_info_files/ARCHITECTURE.md. Compose 변경은 향후 SLACK_SIGNING_SECRET 전달 등 이 TASK에 필요한 부분만 해당한다.

### Dependencies

TASK-001, TASK-002.

### Implementation steps

1. target별 구조화 결과와 recommended/awaiting_approval/executing/succeeded/failed/skipped 전이를 구현한다.
2. D3의 서버 조치 정책과 target 일치 검사를 적용한다. 고위험 조치의 LLM low 응답을 그대로 신뢰하지 않는다.
3. 네 가지 Docker handler의 완료 후조건과 실제 Compose leafy-net resolution을 적용한다.
4. 승인/자동 실행 handler를 일치시키고 SCALE 등 미지원 동작은 skipped로 처리한다.
5. pending action·서명/시각 검증·중복 callback 차단을 구현한다. callback은 확인 후 background 실행한다.
6. 자동/수동 조치의 Loki 상태를 통일하고 TUI/Slack 결과 문구를 실제 상태로 표시한다.
7. THROTTLE prompt 규칙과 예제의 risk 모순을 수정한다.

### Explicit non-goals

영속 승인 DB, 전체 RBAC, 다중 replica exactly-once, 서비스 복구 자동 보장, ISOLATE를 모든 네트워크 차단으로 확대.

### Acceptance criteria

- [ ] 최소 6개 상태가 권고/실제 결과와 구분되어 표시된다.
- [ ] 미연결 네트워크·empty target·NONE/SCALE을 succeeded로 표시하지 않는다.
- [ ] PAUSE/THROTTLE 승인 실행이 실제 지원되며 정책상 고위험은 승인 필수다.
- [ ] 잘못된 서명·변조 target·중복 callback·소실 pending 건이 실행되지 않는다.
- [ ] Docker 후조건 실패가 명시적 실패이며 일부 target 성공을 전체 성공으로 처리하지 않는다.

### Test procedure

Docker mock으로 각 handler의 정상·예외·후조건 실패를 재현한다. 서명된 fixture callback과 변조/중복 요청으로 실행 횟수를 검증한다. TUI renderer에 각 상태를 입력해 권고를 완료로 표시하지 않는지 확인한다. 실제 조치 smoke는 TASK-009의 승인된 격리된 데모 환경에서 수행한다.

### Failure cases

network 없음/여러 후보, target 없음/타 컨테이너, Docker APIError, 요청 후 상태 불변, SCALE, approval secret 미설정, 변조·재전송, 서버 재시작 후 승인.

### Rollback considerations

이미 수행한 pause/throttle/network 변경은 소스 rollback으로 복구되지 않는다. 테스트 대상의 원래 상태를 별도 확인해 복구한다. 실행 정책·callback·표시 코드는 호환되는 단위로 되돌리고 ID 이벤트는 보존한다.

## TASK-004 — MTTD / Slack notification latency correctness

### Goal

D4의 측정 정의와 단일 notification writer를 구현한다.

### Problem

mtta_seconds가 잘못된 기준점을 사용하고 Slack 기록 중복·잘못된 발생 건 매칭·자동 조치 timeout이 있다.

### Files to inspect

- scenarios/common/verifier.py, scenarios/common/result_viewer.py, scenarios/run.py
- scenarios/eval/batch_runner.py, scenarios/eval/report.py
- scenarios/category1_infra/*.py, scenarios/category2_security/*.py의 metric/ResultViewer 호출부
- aiops/remediation/main.py, aiops/remediation/actions/notify.py, aiops/pipeline/main.py

### Files likely to modify

위의 실제 측정/출력/notification 함수 및 필요한 호출부, current_info_files/DESIGN.md, current_info_files/TASKS.md. 시나리오 공격 동작은 변경하지 않는다.

### Dependencies

TASK-002, TASK-003. detector별 자연 발화 검증은 다음 TASK-005에서 완성한다.

### Implementation steps

1. 시작·발화 관측의 wall/monotonic 시각을 구분하고 polling 응답 확인 직후 시각을 저장한다.
2. slack_notification_latency_seconds와 basis=firing_observed를 도입한다. 과거 mtta_seconds의 출력·평균을 분리한다.
3. Notifier는 dispatch 결과만 반환하고 Remediation 한 곳에서 notification event를 기록한다.
4. SUCCESS/FAILED/SKIPPED/NOT_APPLICABLE과 reason, ID, 완료 event_at을 전달한다.
5. 정확한 발생 건/분석 시도의 최초 성공을 정렬·선택한다. 페이지 포화·clock 오류·늦은 FIRING 관측을 명시 처리한다.
6. UI·검증 결과·평가 출력·모든 관련 ResultViewer 호출부를 새 필드로 연결한다.

### Explicit non-goals

MTTA라는 이름의 LLM Histogram, acknowledgement/승인 지연 측정, JSONL 결과 writer, 과거 로그 일괄 수정, Slack 자동 재시도 추가.

### Acceptance criteria

- [ ] 0/30/50초 fixture에서 MTTD 30초, Slack latency 20초다.
- [ ] UI는 firing_observed 기준과 clock/polling 한계를 표시한다.
- [ ] negative latency를 0이나 성공 시간으로 꾸미지 않는다.
- [ ] notification 시도당 한 status event이며 자동 조치에는 NOT_APPLICABLE을 즉시 인식한다.
- [ ] FAILED/SKIPPED/조회 불능과 이전 실행 이벤트를 구분한다.

### Test procedure

고정 clock과 여러 Loki stream fixture로 순서·중복·실행별 filtering을 검사한다. HTTP 200+ok, 200+다른 본문, 4xx, webhook 미설정, 자동 조치 경로를 검증한다. runtime timing 정확도는 TASK-009에서 별도 기록한다.

### Failure cases

늦은 FIRING 관측, clock 역행/불확실성, 동일 event 중복, 다른 발생 건 SUCCESS, query 50건 초과, missing timestamp, delivery_unknown, NOT_APPLICABLE.

### Rollback considerations

새 writer와 소비자를 함께 되돌리되 새 필드를 과거 mtta_seconds에 복사하지 않는다. 기존 로그를 삭제하거나 평균에 혼합하지 않는다.

## TASK-005 — Loki Ruler alert verification / scenario contract

### Goal

D5의 detector별 증거와 단계별 성공 계약을 scenario/verifier에 연결한다.

### Problem

verify_loki가 로그만 확인하고 자동 발화로 표시한다. direct webhook 경로와 자연 탐지 경로가 섞여 있다.

### Files to inspect

- scenarios/common/verifier.py, scenarios/run.py, scenarios/eval/batch_runner.py, scenarios/eval/report.py
- scenarios/category1_infra/*.py, scenarios/category2_security/*.py, scenarios/category3/scenario_pgminer.py
- monitoring/prometheus/rules/alert.rules.yml, monitoring/loki/rules/fake/security-rules.yml
- monitoring/loki/loki-config.yml, monitoring/alertmanager/alertmanager.yml

### Files likely to modify

- scenarios/common/verifier.py, scenarios/run.py, scenarios/eval/batch_runner.py, scenarios/eval/report.py
- scenarios/category1_infra/*.py, scenarios/category2_security/*.py의 검증 호출부
- scenarios/category3/scenario_pgminer.py, aiops/pipeline/main.py의 수신 단계 이벤트
- current_info_files/ARCHITECTURE.md, current_info_files/DESIGN.md, current_info_files/TASKS.md, current_info_files/README.md

Loki mount/tenant 구조는 수정하지 않는다.

### Dependencies

TASK-001, TASK-002, TASK-004.

### Implementation steps

1. scenario registry에 detection_mode/required_stages를 명시한다.
2. Prometheus FIRING과 Loki Ruler FIRING 조회를 구분한다. API endpoint/labels는 설치 버전에서 확인한다.
3. detector 발화→AM 발생 건→Pipeline 수신/분석을 occurrence_id로 연결한다.
4. verify_loki 결과를 log_generation으로 명확히 분리한다.
5. 직접 webhook이 있는 scenario는 명시적 모드로 분리해 자연 탐지 검증에서 실행하지 않는다.
6. 단계별 status/reason/evidence와 전체 검증 판정을 로컬 결과 및 aiops-timeline의 verification_stage로 기록하고 평가 출력에 연결한다.

### Explicit non-goals

rules/fake rename, 로그만으로 발화 대체, 모든 보안 시나리오를 성공 사례로 강제, 탐지 사각지대 삭제.

### Acceptance criteria

- [ ] 자연 Loki 테스트는 Ruler FIRING·AM·Pipeline 증거가 모두 존재한다.
- [ ] 로그 한 건만 있는 UnauthorizedDBAccess는 rule 검증을 통과하지 않는다.
- [ ] direct webhook은 detection/AM을 NOT_APPLICABLE로 기록한다.
- [ ] 이전 pending/firing이나 모호한 발생 건에서 측정을 시작하지 않는다.
- [ ] 각 scenario의 success는 required_stages 기준으로 정의된다.

### Test procedure

먼저 Prometheus/Loki/AM API fixture로 정상·pending·silenced·미지원 API를 검증한다. 향후 runtime에서는 기존 cpu_stress.py의 Prometheus 경로, lateral_movement.py의 Loki 경로, false_positive_cpu.py의 direct 경로를 각 모드에 맞게 실행한다. 이 파일들은 실제 존재하지만 mode/단계 계약은 이 TASK에서 구현한 이후 검증한다. detector 조건 미충족 로그 fixture도 확인한다.

### Failure cases

Loki API 미지원, rule 미로딩, 로그 생성만 성공, silence/inhibition, AM 미전달, Pipeline timeout, 다중 후보, 직접 webhook에 의한 우회 성공.

### Rollback considerations

검증 단계 필드와 소비자를 함께 되돌린다. 이미 기록한 새 evidence와 과거 로그는 보존한다. 자연 탐지 실패를 감추기 위해 직접 webhook을 복구 수단으로 자동 추가하지 않는다.

## TASK-006 — HTTP / integration failure handling

### Goal

D6에 따라 남아 있는 기존 HTTP 호출의 실패 표현과 교차 서비스 오류 처리를 완성한다.

### Problem

Pipeline→Remediation, Loki push, collector/조회 helper에서 4xx/5xx 또는 malformed 응답을 정상처럼 처리할 수 있다.

### Files to inspect

- aiops/pipeline/main.py, aiops/pipeline/collector/metrics.py, aiops/pipeline/collector/logs.py
- aiops/remediation/main.py, aiops/remediation/actions/notify.py
- scenarios/common/verifier.py, scenarios/common/result_viewer.py, scenarios/eval/batch_runner.py

### Files likely to modify

위의 실패 확인이 빠진 함수들, current_info_files/DESIGN.md, current_info_files/TASKS.md, current_info_files/ARCHITECTURE.md.

### Dependencies

TASK-002, TASK-003, TASK-004, TASK-005. 각 앞선 TASK의 신규 인터페이스는 기본 오류 처리를 이미 포함해야 한다.

### Implementation steps

1. outbound 호출별 성공 HTTP/응답 schema를 확인하고 검사 누락을 보완한다.
2. query 오류와 정상 empty를 분리한다. 분석 입력 조회 실패에서는 조치를 진행하지 않는다.
3. 분석 결과 Loki 기록 실패 시 자동 조치 전달을 막고 ID 포함 로컬 로그를 남긴다.
4. /action 응답 유실은 delivery_unknown으로 표시하고 재실행하지 않는다.
5. 기록 저장 실패와 실제 조치 결과를 구분한다. Loki 실패 중 실패 push 재귀를 막는다.
6. TUI/verification에서 503·missing completion·unknown을 성공/0건으로 바꾸지 않는지 확인한다.
7. timestamp 형식을 통일하고 오류 출력의 credential 노출을 제거한다.

### Explicit non-goals

영속 retry queue/outbox, 자동 Docker/Slack 재시도, 공통 resilience framework, 모든 source의 무관한 HTTP 코드 리팩터링.

### Acceptance criteria

- [ ] 4xx/5xx/timeout/malformed/empty를 구분한다.
- [ ] HTTP 2xx만으로 Docker succeeded를 생성하지 않는다.
- [ ] Loki 장애에서 조회 실패와 로컬 로그가 확인되며 메모리 fallback 성공이 없다.
- [ ] /action timeout 이후 요청을 자동 반복하지 않는다.
- [ ] side effect 후 기록 실패를 조치 실패라고 단정하지 않는다.

### Test procedure

mock HTTP transport로 오류 행렬을 실행하고 호출 횟수·return status·구조화 로그·TUI 상태를 확인한다. 실제 서비스를 중단시키는 fault injection은 TASK-009의 승인된 환경에서만 수행한다.

### Failure cases

요청은 도달했으나 응답 유실, Loki 500, Loki 잘못된 JSON, collector 404, 정상 빈 query, Slack response_url 실패, local logging 외 저장 불가능.

### Rollback considerations

오류 계약과 해당 소비자 표현을 호환되게 되돌린다. 실패 확인을 제거하면 다시 false success가 생기는 위험을 기록한다. 재시도 추가로 rollback을 보완하지 않는다.

## TASK-007 — Existing Grafana dashboard validation and correction

### Goal

D7에 따라 기존 두 dashboard의 의미와 실제 query를 검증·보정한다.

### Problem

기존 provisioning을 누락으로 분류했고 DB 임계값·집계·전체 alert 범위를 잘못 표현한다.

### Files to inspect

- monitoring/grafana/provisioning/dashboards/aiops_dashboard.json
- monitoring/grafana/provisioning/dashboards/leafy_aiops_soc_dashboard.json
- monitoring/grafana/provisioning/dashboards/dashboards.yml
- monitoring/grafana/provisioning/datasources/datasources.yml
- monitoring/prometheus/rules/alert.rules.yml, monitoring/loki/rules/fake/security-rules.yml
- docker-compose.yml, aiops/pipeline/main.py, aiops/remediation/main.py

### Files likely to modify

기존 dashboard JSON 두 개, current_info_files/ARCHITECTURE.md, current_info_files/DESIGN.md, current_info_files/TASKS.md. provider/datasource/Compose는 실제 로딩 문제를 확인한 경우에만 수정 후보로 재검토한다.

### Dependencies

TASK-003, TASK-004, TASK-005, TASK-006. 기본 provisioning 정적 확인은 먼저 가능하나 이벤트 표시 완료 검증은 선행 계약에 의존한다.

### Implementation steps

1. JSON·provider path·Compose mount·datasource UID 대응을 확인한다.
2. DB 합계 패널의 잘못된 rule 50 임계값 표시를 제거한다.
3. CPU 대상 범위와 LLM count 집계·target datasource를 검증한다.
4. Prometheus ALERTS와 Loki 검증/수신 이력을 구분해 이름과 query를 보정한다.
5. D3/D4의 실제 상태, no-data, dependency error를 화면에서 구분한다.

### Explicit non-goals

새 dashboard JSON, UID/title 전면 교체, 5개 row/12개 panel 같은 임의 숫자 목표, Grafana alert 체계 이전.

### Acceptance criteria

- [ ] 기존 UID aiops-main/leafy-aiops 및 datasource UID를 유지한다.
- [ ] 총합 DB 지표를 개별 series rule 임계값처럼 표시하지 않는다.
- [ ] Loki 발화를 Prometheus ALERTS 전체 목록으로 주장하지 않는다.
- [ ] 정상 no-data와 query/접속 오류를 구분한다.
- [ ] 자동/승인/notification 상태를 실제 이벤트와 대조한다.

### Test procedure

JSON을 메모리에서 파싱하고 target별 datasource/query를 검토한다. 향후 Grafana 실행 환경에서 UI 또는 실제 설치 버전이 지원하는 UID 조회 API로 두 dashboard를 확인한다. API 경로·인증은 설치 버전에서 확인하고 고정 admin:admin이나 존재하지 않는 slug를 가정하지 않는다. 정상 무이벤트·분석·notification·조치 실패 데이터를 차례로 확인한다.

### Failure cases

provider 미로딩, datasource UID 불일치, target datasource override 오해, Loki no-data, HTTP/query 오류, 과거 이벤트와 신규 ID 혼합.

### Rollback considerations

원래 JSON/UID를 보존한 채 변경 panel만 되돌린다. Grafana volume을 삭제하지 않으며 UI 임시 변경과 provisioning 파일 변경의 차이를 기록한다.

## TASK-008 — Periodic scan flag / lifecycle

### Goal

D8의 단순 feature flag로 기존 periodic coroutine을 관리하고 선행 계약을 재사용한다.

### Problem

주석 편집으로 실행을 제어하며 _call_llm_raw가 일반 semaphore를 우회한다. periodic tag/Slack 경로도 일반 분석과 분리되어 있다.

### Files to inspect

- aiops/pipeline/config.py, aiops/pipeline/main.py
- aiops/remediation/main.py, aiops/remediation/actions/notify.py
- docker-compose.yml

### Files likely to modify

aiops/pipeline/config.py, aiops/pipeline/main.py, aiops/remediation/main.py, docker-compose.yml, current_info_files 네 문서.

### Dependencies

TASK-001, TASK-002, TASK-003, TASK-004, TASK-006. Grafana 작업과 기술적 의존 관계는 없다.

### Implementation steps

1. ENABLE_PERIODIC_SCAN을 true/false 명시 파싱하고 기본 false로 설정한다.
2. lifespan에서 true일 때 기존 두 coroutine을 한 번씩 생성하고 finally에서 cancel/await한다.
3. _call_llm_raw에 기존 semaphore를 공유해 중첩 acquire 없이 호출 수를 제한한다.
4. periodic app tag→Docker mapping과 source=periodic ID를 적용한다.
5. 기존 직접 Slack 경로를 Remediation notification/승인 계약으로 연결한다. periodic 자동 Docker 실행은 허용하지 않는다.
6. 로그 스캔/LLM health 주기와 시작 지연은 유지한다.

### Explicit non-goals

Pipeline 서비스 신규 추가, /health 신규 구현, scheduler framework, 별도 worker, Ollama 병렬 증가, scan 알고리즘 변경, periodic notification용 별도 writer 재도입.

### Acceptance criteria

- [ ] false에서 periodic 0개, webhook 분석 정상.
- [ ] true에서 coroutine 각각 1개, shutdown 후 잔여 task 없음.
- [ ] 일반/periodic LLM 동시 호출은 최대 1개.
- [ ] 잘못된 bool 설정을 조용히 true로 해석하지 않음.
- [ ] periodic 이벤트는 일반 detector 시간 지표에 포함되지 않음.
- [ ] periodic 승인/notification은 D3/D4 결과 계약과 Docker 이름을 사용함.

### Test procedure

가짜 clock/sleep·LLM transport로 긴 실제 주기를 기다리지 않고 lifespan과 취소를 확인한다. 일반 webhook과 periodic scan을 동시에 주입해 semaphore 횟수를 검증한다. 후속 runtime smoke에서 flag false/true를 각각 확인하되 실제 긴 scan 실행은 별도 통제한다.

### Failure cases

잘못된 env 값, 시작 직후 종료, scan 예외, semaphore 대기 중 취소, LLM timeout, 로그 없음, webhook 미설정, periodic backend 태그의 잘못된 Docker 전달.

### Rollback considerations

우선 flag false로 periodic만 중단한다. 코드 rollback 시 lifecycle과 설정을 함께 되돌린다. 주석 수동 편집을 새 운영 절차로 만들지 않는다. 기존 webhook을 중단할 필요가 없어야 한다.

## TASK-009 — End-to-End integration / smoke test / final documentation

### Goal

앞선 TASK가 연결된 실제 경로와 runtime 가정을 검증하고 문서 상태를 구현 사실에 맞게 갱신한다.

### Problem

정적 설정·단위 fixture만으로 exporter 라벨, Ruler 로딩, Slack 도달, 실제 Docker 조치와 시계 정합성을 증명할 수 없다.

### Files to inspect

- docker-compose.yml, aiops/pipeline/Dockerfile, aiops/pipeline/requirements.txt
- aiops/remediation/Dockerfile, aiops/remediation/requirements.txt
- monitoring/prometheus/prometheus.yml, monitoring/prometheus/rules/alert.rules.yml
- monitoring/loki/loki-config.yml, monitoring/loki/rules/fake/security-rules.yml
- monitoring/alertmanager/alertmanager.yml, monitoring/grafana/provisioning/**
- scenarios/run.py, scenarios/common/verifier.py, scenarios/common/result_viewer.py
- scenarios/category1_infra/cpu_stress.py, scenarios/category1_infra/false_positive_cpu.py
- scenarios/category2_security/lateral_movement.py, scenarios/category3/scenario_pgminer.py
- current_info_files 네 문서

### Files likely to modify

current_info_files/ARCHITECTURE.md, current_info_files/DESIGN.md, current_info_files/TASKS.md, current_info_files/README.md. 구현 결함은 관련 선행 TASK로 되돌려 해당 source 범위를 명시한 뒤 수정한다. root README와 legacy는 갱신 대상에 포함하지 않는다.

### Dependencies

TASK-001~008. 이 작업의 runtime 실행은 별도 구현 단계에서 허용된 데모 환경에 한정한다.

### Implementation steps

1. 이미지/실제 버전/GPU/모델/인증서/필수 환경변수·콜백 도달 경로를 확인한다. secret 값을 보고서에 남기지 않는다.
2. scrape·앱 tag·rules/fake tenant 로딩·provider UID를 확인한다.
3. 자연 Prometheus, 자연 Loki, 직접 webhook, notification-only, 승인, 자동 조치 경로를 단계별 검증한다.
4. 미지원 조치·알림 미설정·HTTP 오류·이전 alert 잔여 상태를 확인한다.
5. 같은 run_id/occurrence_id/result_id를 TUI·API·Loki 이벤트에서 대조한다.
6. 실제 action 후조건과 별도 서비스 recovery를 확인한다. 필요한 알림이 없는 경우를 성공으로 합산하지 않는다.
7. 수집한 runtime 증거와 남은 제한을 기록하고 완료된 TASK만 완료 처리한다.

### Explicit non-goals

실험 결과 조작, legacy/기존 로그 수정, 모든 security scenario 성공 강제, 성능 목표나 평균 시간을 사전 약속, 프로덕션 배포.

### Acceptance criteria

- [ ] natural Prometheus와 natural Loki 각각 detector→AM→Pipeline 연결 증거가 있다.
- [ ] direct webhook은 자동 탐지 성과에 포함되지 않는다.
- [ ] 현재 실행 결과가 과거 이벤트와 섞이지 않는다.
- [ ] 조치/알림/승인/복구 상태가 서로 구분된다.
- [ ] flag false/true와 오류 경로의 UI/API 표현이 계약과 일치한다.
- [ ] 실제 시각 정합성과 firing_observed 지표 한계가 문서에 기록된다.
- [ ] 미검증 사항을 통과로 표시하지 않고 runtime evidence가 있는 TASK만 완료한다.

### Test procedure

먼저 side effect 없는 /health, 기존 /metrics, TASK-002에서 구현한 /results 및 query API를 확인한다. 이후 실제 존재하는 위 시나리오를 각 detection_mode로 실행한다. 각 실행 전 이전 alert/dedup/서비스 상태를 확인하고 동시에 같은 대상 실험을 실행하지 않는다. 실제 Slack 메시지/승인/자동 조치는 허용된 테스트 채널과 데모 컨테이너에서만 검증한다. 실패 주입은 데이터 삭제 없이 일시적 의존성 오류로 제한한다. 결과에는 버전·run ID·관측 단계·실패 이유를 남긴다.

### Failure cases

GPU/모델 미준비, cert 없음, exporter 라벨 불일치, Loki API/버전 차이, Ruler/Fluentd 단절, callback 도달 불가, signature 실패, clock 차이, dedup 재분석 누락, 180초 두 번 LLM 시도+queue가 TUI timeout을 초과하는 경우.

### Rollback considerations

실험 시작 전의 container/network/quota/pause 상태와 비교해 복구한다. Loki/Grafana/DB volume 또는 기존 결과 로그를 삭제하지 않는다. 실패가 발생하면 해당 TASK를 미완료로 유지하고 코드와 문서 수정 범위를 다시 한정한다.

## 완료 시 기록할 것

각 TASK에 실제 수정 파일, 실행한 검증과 결과, runtime 미검증 항목, 계약 변경 여부를 기록한다. 명세에 적힌 Test procedure를 읽었거나 정적 검토했다는 이유만으로 실행 완료 처리하지 않는다. 문서 작성 단계가 끝나면 멈추고 TASK-001 구현을 자동 시작하지 않는다.
