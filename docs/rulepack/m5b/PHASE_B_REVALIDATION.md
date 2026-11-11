# M5-B Phase B — 통합·실제 배포 후 읽기 전용 재인수

상태: **DEFERRED / NOT_EXECUTED**. A(OI-09), B(OI-02/03/04)는 이 worktree에 통합하지 않았다. 다른 브랜치를 가져오거나 Pipeline·producer·배포 설정·탐지 룰을 수정하지 않는다. 아래 PASS는 실행 절차의 조건이며 현재 결과가 아니다.

## 선행 조건과 비교 기준

1. 통합 담당자가 실제로 통합·배포한 버전, 이미지 digest, 배포 시각, 승인된 프로파일과 관측 source 목록을 확인한다. 저장소 수정·테스트 통과와 실행 중 이미지 반영을 구분한다.
2. 원래 후보의 manifest 및 두 생성 파일 SHA256을 이번 `runtime.json`과 비교한다. 달라졌으면 **새 후보 버전**으로 별도 매트릭스를 만든다. 이번 21개 결과를 새 식에 승계하지 않는다.
3. 실제 PC↔job/instance↔runtime/service↔container id/host identity 대응은 운영자가 비공개 inventory와 대조한다. 보고서에는 GC/JH 등 논리 source와 조회별 opaque token만 기록한다. IP·원본 로그·URI·인증값은 복사하지 않는다.
4. 기존 후보의 `cadvisor`/`pipeline-metadata` 고정 selector와 `sum by(name)`/전체 `sum`은 source를 제한하거나 보존하지 못할 수 있다. **A/B 코드 통합만으로 후보 source 격리가 해결되지 않는다.** 실제 GC job/instance가 다르면 원래 후보는 empty일 수 있다. 본 세션에서는 룰을 고치지 않고 불일치를 소유자에게 넘긴다.
5. 자연 발생 사건과 해당 source의 증거가 있어야 발화 이후 단계를 인수한다. 데이터가 없으면 UNVERIFIED를 유지하며 사건을 만들지 않는다.

## 기본 GET 재실행

실제 API에 이미 접근 가능한 환경에서 저장소 루트 기준으로 실행한다. URL은 기존 승인된 origin을 사용하며 명령/증거에 인증정보를 넣지 않는다. 로컬 기본값이 원격 관리 서버라는 가정은 하지 않는다.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/rulepack/integrate_m5.py --check
PYTHONDONTWRITEBYTECODE=1 python3 tools/rulepack/acceptance_m5b.py \
  --prometheus "$M5_PROMETHEUS_ORIGIN" --loki "$M5_LOKI_ORIGIN" \
  --alertmanager "$M5_ALERTMANAGER_ORIGIN" --pipeline "$M5_PIPELINE_ORIGIN" \
  --ollama "$M5_OLLAMA_ORIGIN" --expected-model "$M5_DEPLOYED_MODEL" \
  --output docs/rulepack/m5b/runtime.phase-b.json
```

변수는 운영자가 이미 확인한 origin/model이다. `--expected-model`은 tags와의 일치만 확인한다. 실제 배포 설정 모델임은 별도 증거가 필요하며 추론 성공을 의미하지 않는다. API 인증이 필요한 경우 기존 승인된 조회 경로를 사용한다. 도구가 지원하지 않는 인증을 우회하지 않는다.

과거 사건 query는 `--at '<timezone 포함 RFC3339>'`로 별도 파일에 저장한다. 입력 표본은 query 시각 직전 30분/selector별 최대 50줄, 후보는 instant query이다. RCA/timeline 조회는 그 시각 직전 24시간/각 최대 50줄이다. 사건 **후** RCA는 해당 완료 시각을 포함하도록 별도 시각으로 조회한다. targets/rules/AM/health/tags는 조회 현재값이므로 과거 상태를 복원하지 않는다. `exit 0`은 수집 완료이며 인수 PASS가 아니다.

## A — OI-09 재인수

| 항목 | 읽기 전용 확인 및 PASS 조건 | 미충족 처리 |
|---|---|---|
| webhook 계약 | 배포 OpenAPI가 실제 source/site/runtime/job/instance 등 채택한 identity를 보존하는지 A 계약과 대조한다. 정적 기본 extra 무시 문제와 실제 입력 보존을 분리한다. | 스키마만 맞으면 CONFIGURED이다. 실제 webhook 수신 증거까지 필요하다. |
| source-aware dedup | 기존 자연 발생 기록 중 같은 source·같은 사건의 반복 수신은 정책대로 중복 제거되고, 다른 PC의 같은 service/alert는 독립 수신·분석되는 두 사건을 선택한다. window·재시도·실패 후 처리도 비교한다. | 두 source 사건이 없거나 수신 로그에 identity가 없으면 UNVERIFIED이다. 테스트 POST를 하지 않는다. |
| 다른 PC 동명 서비스 | Ruler/AM 라벨, Pipeline 수신 identity, 선택한 앱/메트릭/network selector, RCA metadata가 같은 source로 이어진다. 동명 서비스의 타 PC 문맥이 섞이지 않는다. | alias 이름만 같거나 GC 값 대신 JH Docker 값을 쓰면 FAIL/차단한다. |
| host PG17 | runtime=host, service=db, PG17 jsonlog 필드/타입과 논리 host source를 확인한다. host 전용 분석 경로가 선택되고 Docker DB id/top-CPU/전역 host fallback으로 바뀌지 않는다. | Docker `leafy-db`와 host DB alias 충돌이 남으면 인수하지 않는다. |
| root/미상 대상 | root 네트워크 신호가 명시적 host/unknown 처리 정책을 따르는지 기존 사건에서 확인한다. 근거 없이 특정 컨테이너를 선택하지 않는다. | 문자열 alias 처리만 바뀌면 해결로 기록하지 않는다. |
| 결과 identity | 실제 Ollama 결과와 저장된 RCA/timeline에 source/runtime/service, 사건 상관키, 선택한 대상/자료 출처가 보존된다. 시작·완료 시각과 모델 증거가 같은 사건을 지시한다. | schema나 결과 키만 존재하는 것으로 값의 정확성/추론 성공을 승인하지 않는다. |

현재 main 기준 dedup은 `alertname:container`이며 source 필드가 AlertLabel에서 보존되지 않는다. 이 사실은 A 작업의 실패 판정이 아니라 **통합 전 기준선**이다.

## B — OI-02/03/04 재인수

| 항목 | GET 확인 및 PASS 조건 | 미충족 처리 |
|---|---|---|
| GC targets | targets의 health/lastScrape/오류와 비공개 inventory를 대조한다. cAdvisor·metadata·restart producer가 **GC** 자원/동일 관측점을 가리킨다. | exporter가 up인 것만으로 GC 대응을 승인하지 않는다. |
| job/instance | 실제 pair와 이번 후보 selector의 pair를 정확히 대조한다. PC별 동일 job 또는 id/name 충돌, metadata 조인 유일성을 확인한다. | actual pair가 다르면 후보 SELECTOR/INPUT 미인수이다. 자동 재매핑하지 않는다. |
| CPU | `container_cpu_usage_seconds_total` cpu/id·단위·counter continuity, metadata id/name과 같은 GC source인지 확인한다. 30초 irate에 필요한 실제 표본을 bounded query_range로 확인한다. | 표본 없음/조인 오류/리셋과 정상 0을 구분한다. |
| 메모리 | `container_memory_working_set_bytes`, 양수 `container_spec_memory_limit_bytes`의 전체 라벨 일치·단위·limit 의미·id 유일성을 확인한다. | `memory_usage`나 호스트 전체 값을 후보 working_set/limit의 증거로 대체하지 않는다. |
| 수신 | `container_network_receive_bytes_total`의 GC container/interface/name 및 root 분기를 확인한다. Docker presence guard가 다른 source에 의해 억제되지 않는지 대조한다. | root 신호를 GC 컨테이너 신호로 승인하지 않는다. |
| restart | `aiops_docker_container_restarts_total`, `aiops_docker_container_started_at_seconds` 및 producer 수집 성공 지표를 확인한다. GC id/name·5초 연속 표본·reset·실제 기존 재시작 시각을 비교한다. | counter 0/StartedAt 존재만으로 restart 사건 또는 경보 발화를 주장하지 않는다. 10분/5초 subquery가 누락 표본을 복구하지 않는다. |
| 후보 평가 | 9개 원래 PromQL을 그대로 GET 평가하고 join/parse 오류, empty, 유한값/양수 결과를 구분한다. | B producer 성공으로 후보 고정 selector·집계 source 손실을 자동 해결 처리하지 않는다. |

## 자연 발생 사건의 시간순 인수표

각 후보 정의·source·사건마다 별도 행을 만들고 아래 순서를 연결한다. 기존 운영 17개 룰의 사건은 별도 baseline 기록이며 후보 발화 수에 포함하지 않는다.

| 순서 | 필요한 증거 | 상태 승격 조건 |
|---|---|---|
| 1 입력 | 실제 source/runtime, selector, 타입·단위·필요 표본/연속성 | INPUT_VERIFIED. 도구는 sample presence만으로 이 단계를 자동 승인하지 않는다. |
| 2 평가/로드 | 정확한 후보 expr GET 결과와 실제 Ruler group/식/labels/annotations/for/keep_firing_for/interval | QUERY_SUCCESS와 RULE_LOADED를 각각 판정한다. native 파싱 PASS로 대체하지 않는다. |
| 3 pending/firing | 같은 candidate group의 lastEvaluation/health·실제 active alert·startsAt 및 필요한 지속 시간의 보존된 기록 | FIRING_VERIFIED. 현재 API의 단일 state만으로 과거 pending 전이를 재구성하지 않는다. |
| 4 AM | 동일 사건의 label/annotation·startsAt·receiver/억제/현재 상태 | ALERT_DELIVERED는 **Ruler→AM** 수신이다. AM history API가 있다고 가정하지 않는다. |
| 5 수신 | 같은 identity/시간의 Pipeline webhook 수신 로그와 대상 결정 | PIPELINE_RECEIVED. AM route 설정/queued 응답만으로 대체하지 않는다. |
| 6 RCA | 실제 Ollama 모델/분석 성공, 유효 결과, 해당 source의 자료 출처, 사건 이후 신규 저장 결과 | RCA_VERIFIED. health/tags/완료 로그/과거 같은 alert명/zero-confidence fallback은 충분하지 않다. |
| 7 해소 | 조건 소멸, Ruler inactive/resolved, AM endsAt·해소 통지의 보존된 기록 | 해소 시각을 별도 기록한다. AM 현재 목록에서 사라진 것만으로 과거 해소 전송을 확정하지 않는다. |

현재 도구는 FIRING/DELIVERED/RECEIVED/RCA를 자동 승격하지 않는다. 실제 사건의 metadata를 운영자가 내부에서 대조하고 원문 없는 상관 증거표로 별도 승인한다. run-local token은 같은 실행의 equality 확인용이며 다른 실행 간 연결에는 쓸 수 없다.

## 쓰기가 반드시 필요한 경우의 보류 절차

현재 실행 승인 범위는 GET뿐이다. 자연 사건이 없으면 **E2E UNVERIFIED**를 유지한다. 다음 조건이 모두 보고·별도 승인되기 전에는 canary/주입/POST/룰 적용을 실행하지 않는다.

- 별도 테스트 Ruler/AM/Pipeline/Ollama와 전용 데이터·결과 저장소, 테스트 전용 대상 identity를 명시한다.
- 운영 receiver 및 Slack/메일 등 외부 알림 출구, Remediation API·Docker socket·운영 서비스 credentials/네트워크를 실제로 격리한다. `disabled` 설정이나 `test=true` 라벨만으로 격리를 간주하지 않는다.
- 승인 요청에 쓰기 endpoint·payload 종류·기간·관찰 창·중단 기준·담당자와 원복 전후 확인 항목을 포함한다. 공격/장애 주입은 현재 범위 밖이다.
- 원복은 테스트 송신 중단, 테스트 alert의 제한된 TTL/해소 확인, 테스트 route/rule/config의 사전본 복구, 변경한 테스트 자원 제거와 원래 health 비교이다. 운영 사건/분석 이력은 삭제하지 않는다.
- AM 직접 POST는 Ruler를 우회하는 transport 검사이다. 성공해도 후보의 입력·query·firing 인수로 승계하지 않는다.

Phase B 완료는 실제 통합·배포 후 위 증거가 연결된 경우에만 판정한다. 일부 후보가 미발화/접근 불가이면 후보별 UNVERIFIED와 전체 미완료 상태를 유지한다.
