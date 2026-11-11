# M4 — 정상 데이터 기반 Baseline 수립 및 탐지 임계값 검토

## 1. Executive Summary

작업 구간은 **2026-11-10~11(KST)**이며 기준 HEAD는 `main`의 `92e70dbf8b9af14b9376df3fde3a7fb4db7e3e50`이다. 시작 상태는 `main...origin/main`, tracked 변경 0개와 기존 `docs/rulepack/`·`tools/rulepack/` 미커밋 산출물이 존재하는 상태이다. 원격 HEAD를 새로 확인한 결과는 아니다.

**M4는 PARTIAL: 분석 도구 및 오프라인 검증 완료 / 실측 Baseline 수립 대기인 상태이다.** 정상이라고 확인된 시간 구간과 실제 분석용 표본을 확보하지 못하여 평균·P95·P99·정상 초과 횟수·후보 임계값을 산출하지 않은 결과이다. 확인되지 않은 값을 0이나 합성 측정값으로 채우지 않았다. 개별 데이터 실행의 BLOCKED 표시는 실측 입력 부재이며 도구 개발 중단을 의미하지 않는 구분이다.

GC PC → JH PC의 관측 데이터 전달은 사용자 직접 확인 사실이다. 이번 작업은 그 경로를 재감사하지 않았으며 PC 접속 정보를 요청하지 않았다. 현재 개발 Mac의 두 조회 API만 확인한 결과는 연결 거부이다. 이 결과를 GC/JH 실서버의 장애나 전송 실패로 해석하지 않았다.

2026-11-11 사용자 추가 확인은 **확정 가능한 정상 구간과 검증 근거가 없음**이다. 이 확인에 따라 `NORMAL_UNCONFIRMED`, 시간 구간 `null`, 후보 임계값 없음 상태를 유지한 결과이다. 추가 확인 질문이나 API 재조사 없이 구현·검증을 마무리한 작업이다.

구현은 읽기 전용 API 수집/비민감 export 입력, source·시계열별 통계, 원본 scrape/결측 검사, 기존 조건 및 `for` 초과 구간, S2 목적지/전송량 분리, 분석 결과 JSON/Markdown 생성인 범위이다. 기본 계획은 **PromQL 11개 + LogQL 11개 + 원본 입력 probe 7개**이다. 정상 근거가 없으면 `NORMAL_UNCONFIRMED`로 두고 확정 Baseline과 후보 평가에서 제외하는 구현이다.

기존 M1~M3·OI 문서/코드/매핑과 관련 운영 파일 **44개**의 시작 SHA256을 기록하고 종료 시 일치함을 확인한 결과이다. 운영 룰·기존 임계값·수집기·DB·네트워크 설정을 변경하지 않은 작업이다. Docker 실행/재시작·룰 reload·공격 시나리오 실행·Git commit/push/PR 생성은 없는 작업이다. 시나리오 주입 코드·공격 강도·Heldout을 분석 자료로 사용하지 않았다.

## 2. 사용한 정상 데이터와 증거

**실제로 사용한 정상 데이터의 범위는 없음**이다. 정상이라고 확인된 시각·근거가 아직 제공되지 않아 특정 현재/과거 구간을 정상이라고 추정하지 않은 상태이다. 기존 [M1](M1_OBSERVABILITY_AUDIT.md), [M2-1](M2_STATIC_GENERALIZATION.md), [M2-2](M2_2_INFRA_GENERALIZATION.md), [M2-3](M2_3_RESOURCE_GENERALIZATION.md), [M3](M3_NEW_DETECTION_RULES.md), [OI-1](OBSERVABILITY_INFRA_MILESTONE.md)의 입력 계약과 실제 룰 정의를 재사용한 작업이다.

| 증거 | 직접 확인한 사실 | 해석 |
|---|---|---|
| [availability.json](m4/availability.json) | 2026-11-10 **23:44:58 KST / 14:44:58Z**, 개발 Mac의 `127.0.0.1:9090/api/v1/targets`, `127.0.0.1:3100/loki/api/v1/labels` 모두 `Connection refused`이다. | 접근한 로컬 API에서 분석 데이터를 얻지 못한 사실이다. GC/JH 간 전달의 부정 증거가 아니다. |
| 최초 제한 실행 | 같은 두 GET은 sandbox에서 `Operation not permitted`인 결과이다. 이후 허용된 읽기 전용 실행으로 위 연결 거부를 확인한 것이다. | 권한 오류를 서비스 장애 증거로 집계하지 않은 처리이다. |
| 정상 구간 | 시작/종료·운영 정상 근거·장애/주입 제외 증거가 없는 상태이다. | `NORMAL_UNCONFIRMED`이며 확정 Baseline에서 제외이다. |
| [current_run/analysis.json](m4/current_run/analysis.json) | `data_kind=none`, `status=BLOCKED`, 입력 시계열 없음인 실행 결과이다. | 실측 통계가 없는 결과이다. 합성 fixture를 넣은 보고서가 아니다. |
| [execution_record.json](m4/execution_record.json) | HEAD·입력 부재·정상 구간 부재·분석 계획 수·변경 미적용을 기록한 파일이다. | 이번 실행의 재현 기록이다. |

정상 확인에는 운영자가 확인한 장애·주입 없는 구간과 정상 업무 근거가 필요한 기준이다. 알림이 없거나 `up=1`인 사실만으로 정상 운영을 인증하지 않는 기준이다. 정상 기간 안의 SQLi 매치도 개별 판독 없이 False Positive로 확정하지 않는 기준이다.

## 3. 수집 source 및 시간 범위

실제 측정 시작/종료 시각은 **미지정**이다. [analysis.yml](m4/analysis.yml)의 시간은 `null`, 정상·scope 확인은 모두 `false`인 상태이다. 아래는 실행된 실서버 인벤토리가 아닌 **기존 설정에 근거한 분석 계획**이다.

| 분석 source | 설정상 입력 | 분리 기준·현재 상태 |
|---|---|---|
| `integrated` | cAdvisor `cadvisor:8080`, Pipeline `pipeline:8000`의 job/instance이다. | M2의 통합 Docker 범위이며 PC 2 수집 증거가 아니다. 실제 scope는 UNVERIFIED이다. |
| `leafy-web` | Nginx exporter job/instance, `service=frontend,runtime=container` 로그이다. | exporter 시계열별 rate와 로그 target별 건수를 분리하는 계획이다. |
| `leafy-host-postgres` | Postgres exporter job/instance, `service=db,runtime=host` 로그이다. | host PG17 로그와 연결 메트릭의 실제 서버 대응을 확인할 항목이다. 통합 PG16 컨테이너와 혼합하지 않는 기준이다. |
| `leafy-backend-network` | `log_type=network,src_service=backend` canonical 이벤트이다. | body의 observer별·목적지별로 분리하는 계획이다. 허용 정책 적용은 아직 미확인이다. |

정확한 쿼리는 [query_plan.json](m4/query_plan.json)의 재생성 가능한 계획이다. 서로 다른 source의 평균·P99·바이트를 합산하지 않는 구현이다. host fallback은 name이 있어도 `host_scope`이며 앱 컨테이너 값으로 표시하지 않는 구현이다.

분석 창은 명시적인 timezone 포함 시각이며 실행당 최대 24시간인 계약이다. 여러 날은 별도 실행으로 비교할 범위이다. rate/irate·로그 count의 lookback이 정상 구간 밖 데이터를 읽지 않도록 실제 평가 시작에 30초/1분/2분/1시간 warmup을 적용하는 구현이다. 1시간 요청 집계의 최소 유효 길이를 확보하려면 그 앞의 1시간 warmup도 필요한 구조이다.

## 4. 데이터 품질·결측 점검

[baseline_m4.py](../../tools/rulepack/baseline_m4.py)의 확정 Baseline 게이트는 다음과 같은 기준이다.

| 게이트 | 구현한 검사 |
|---|---|
| 정상 선정 | `normal.confirmed`, 장애/주입 제외 확인, 확인 역할/alias와 근거, 명시적 시간 구간이다. |
| 관측점 | source/target의 `scope_confirmed`, 정확한 job/instance 또는 기존 로그 selector이다. 겹치는 수집 범위는 거부이다. |
| provenance | export의 version/data_kind·config SHA256·plan SHA256·window 일치이다. 합성 입력은 항상 `SYNTHETIC_TEST_ONLY`로 제외이다. |
| 표본 | 기대 5초 grid, 실제 표본 수·유효률·최대 공백·앞/뒤 공백·중복 timestamp 검사이다. NaN/Inf·범위 밖·grid 불일치는 제외이며 중복은 오류이다. |
| 원본 입력 | `query_range` 평가값 외에 instant query의 range vector로 저장된 원본 표본 간격을 확인하는 처리이다. 반복된 lookback 값을 연속 scrape로 오인하지 않는 기준이다. |
| 메모리 | full-label 분자/분모 대응, limit 양수/확인된 무제한 표현, metadata id 유일성·값 1, limit 의미 확인이다. |
| 로그 | API 성공 외에 `log_continuity_confirmed`와 운영 근거가 필요한 기준이다. raw sample 상한·파싱 실패·관측 범위 부족은 별도로 기록이다. |
| 후보 | 확정 정상·품질 조건을 통과한 시계열과 단위/검토 근거가 있는 명시적 후보만 비교하는 처리이다. |

기본 품질 하한은 유효 계산 구간 1시간, 표본 100개, coverage 95%, 원본 최대 간격 2 step인 설정이다. 통계적 충분성이나 일/주 단위 계절성 검증을 보장하는 숫자가 아닌 최소 검토 게이트이다. P99 배율이나 운영 탐지 임계값으로 쓰는 숫자가 아니다.

지표별 통계는 동일 5초 평가 grid의 표본 통계이다. 평균·중앙값·선형 보간 P90/P95/P99·최대·모표준편차·변동계수·UTC 시간대별 통계·시간당 선형 추세가 구현된 항목이다. **정상 미확인 또는 합성 입력의 중앙값/P90/P95/P99는 raw 입력 진단·S2 연결별 분포·시간대별 요약까지 JSON에서 `null`이며 정상 분위수 표에도 표시하지 않는 처리**이다. 통계 함수 자체의 분위수 계산은 합성 단위 테스트에서 검증하는 범위이다. 평균·표본 수 등 다른 진단 정보가 있더라도 정상 판정을 대신하지 않는 기준이다. 메모리 추세만으로 누수를 진단하는 기능은 아니다.

초과 구간은 엄격한 `>` 비교와 연속 표본으로 계산한 관측 하한이다. 5초 표본의 CPU 30초 조건은 첫 초과부터 30초 뒤 표본까지 지속되어야 하는 기준이다. 결측은 pending을 끊는 보수적 처리이다. 구간 전후의 실제 Ruler 상태는 UNVERIFIED이며 알림 재전송/그룹화·실제 발화 횟수와 동일한 수치가 아니다.

API 접근은 GET만 허용한 구현이며 URL의 인증정보·query/fragment와 redirect를 거부하는 처리이다. 서버 오류 본문은 저장하지 않고 partial/warning 응답은 품질 실패인 처리이다. API 형식의 근거는 [Prometheus HTTP API](https://prometheus.io/docs/prometheus/latest/querying/api/)와 [Loki HTTP API](https://grafana.com/docs/loki/latest/reference/loki-http-api/)이다.

## 5. CPU Baseline

대상은 기존 `HighCpuUsage`와 M2-2의 **`irate(...[30s])`, `/docker/` id, `cpu=total`, metadata id 조인과 name 합계**이다. 분석용 쿼리는 최종 `> 0.5`만 제거하고 name membership을 보존한 식이다.

단위는 **CPU core 상당 사용량**이다. `0.5`는 약 0.5 core이며 전체 호스트 CPU의 50%가 아니다. 서비스/source별 평균·중앙값·P90/P95/P99·최대·시간대 변화·변동성 및 `>0.5`, `for:30s`의 표본 초과와 지속 구간을 분석하는 코드이다.

이번 실제 평균·분위수·정상 초과 표본/지속 구간은 모두 **미산출**이다. 원격 CPU 입력이 없다고 0 core로 표시하지 않은 결과이다. 후보 배율이나 새 임계값도 없는 상태이다.

## 6. 메모리 Baseline

대상은 `container_memory_working_set_bytes`, `container_spec_memory_limit_bytes` 및 원본 full-label 나눗셈과 metadata 조인 뒤 `max by(name)` 비율이다. 최종 `>0.85`만 제거하고 **분모의 `>0` 필터**를 보존한 식이다.

working set/limit 원본의 진단 통계, 비율 P50/P90/P95/P99, 시간당 추세와 `>0.85`, `for:5m`의 지속 구간을 분리한 구현이다. limit 0·미수집·사용자가 확인한 무제한 값은 유효한 비율 0이 아닌 제외 사유이다. 매우 큰 양수 limit를 자동으로 유한한 앱 상한이라고 확정하지 않도록 별도 의미 확인 flag가 필요한 구조이다.

이번 실제 working set/limit·비율·추세·5분 지속 초과는 **미산출**이다. 같은 source의 raw labelset 불일치나 metadata 중복은 진단으로 남기고 확정 Baseline에서 제외하는 검사이다.

## 7. 네트워크 Baseline

### 7.1 HighNetworkReceive

단위는 **1분 rate의 bytes/second**이다. 컨테이너 분기의 name 합계와 host root 분기를 별도 쿼리로 두고, 원본의 **어떤 `/docker/` 수신 시계열이라도 있으면 host fallback을 막는 조건**을 보존한 구현이다. 이름 없는 컨테이너·감시 목록 밖의 컨테이너·loopback 시계열이 guard를 막는 원래 의미도 보존인 상태이다.

root rate와 presence guard를 별도로 조회하여 `MASKED_BY_ANY_DOCKER_SERIES`, `HOST_FALLBACK_ACTIVE`, `ROOT_RATE_MISSING`, 조회 미확인/불일치를 구분하는 진단이다. fallback 비어 있음 자체를 수집 공백으로만 단정하지 않는 처리이다. host 활성 분기의 분포는 조건부 분포이며 source 전체의 연속 Baseline으로 승격하지 않는 보수적 출력이다.

평균/P95/P99·컨테이너별 변화·`>1e7`, `for:30s`의 급증·누락 및 fallback 활성 구간은 분석 가능한 기능이나 이번 실측 결과는 **없음**이다.

### 7.2 S2 Canonical Network Event

입력은 [events.py](../../aiops/network-observer/enricher/events.py)의 `observer_instance`, `connection_id`, source/destination IP·port, `timestamp`, `bytes_sent`와 목적지 service 계약이다. `bytes_sent`는 originator의 payload bytes이며 HighNetworkReceive의 NIC 수신 rate와 다른 신호이다.

최종 `event_type=connection`만 전송량 분포에 사용하는 구현이다. `connection_threshold` 누적값은 합산에서 제외하며, observer+연결 identity의 동일 최종 로그도 중복 제외이다. 같은 identity에 서로 다른 최종 바이트가 있으면 max나 합계로 택하지 않고 충돌 identity 전체를 제외하는 처리이다. nullable bytes를 0으로 바꾸지 않는 처리이다.

| 창 | 이번 실제 범위·표본 | 구현한 요약 |
|---|---|---|
| 최근 5분 | 미확보 / 표본 수 미확정이다. | observer/목적지별 연결 수·payload bytes·연결당 분포와 현재 5분 허용 정책 조건의 표본 일치이다. |
| 최근 1시간 | 미확보 / 표본 수 미확정이다. | 목적지별 특성과 전송량·확보한 이전 참조 구간에서의 첫 관측 후보이다. |
| 최근 24시간 | 미확보 / 표본 수 미확정이다. | 실제 확보 길이·표본/상한·목적지 특성이다. 24시간이 없으면 완전한 24시간 창으로 표시하지 않는 구조이다. |

허용 여부의 근거는 기존 [allowlist 정책](../../aiops/policy/allowlist.yml)이며 정상 통신의 빈도나 큰 전송량 자체로 허용 목적지를 학습하는 구현이 아니다. 정책 설정과 실환경 적용 확인을 분리하며 allowed 대용량 전송을 byte 임계값만으로 비인가 반출로 판정하지 않는 기준이다.

목적지/IP/연결 ID/observer는 실행 중 임의 HMAC 키로 비식별화하는 처리이다. 원문 IP·port identity·URI·사용자 필드는 저장 대상이 아니다. 같은 export 안에서의 비교만 가능하며 다른 수집 실행의 token을 동일 목적지로 비교할 수 없는 제약이다. 첫 관측 후보도 확보한 이전 구간 안의 후보이며 전역 신규 목적지/공격 판정이 아니다.

raw 로그는 최대 2,000줄인 기본 표본이며 상한 도달 시 `truncated=true`이다. 페이지 전체 회수 기능이 아니므로 큰 구간의 완전한 분포나 신규 목적지 비율을 보증하지 않는 한계이다. 연결 시작 event time과 최종 기록 시점이 달라 장기 연결의 지연/누락도 남은 관측 조건이다.

## 8. Nginx HTTP Baseline

요청 수와 비율을 다음과 같이 구분한 계획이다.

| 데이터 | 분석 단위 |
|---|---|
| exporter `rate(nginx_http_requests_total[1m])` | 개별 exporter 시계열의 requests/second이다. |
| Loki 전체 요청의 1분·1시간 count | target별 events/minute, events/hour이다. 두 단위를 자동 합산하지 않는 처리이다. |
| 2xx/3xx/4xx/5xx | 상태코드별 사건 건수이다. error rate라는 이름만으로 백분율을 표시하지 않는 처리이다. |
| 경로별 빈도 | query를 제거한 path의 HMAC token별 표본 건수이다. 사용자 식별자가 포함된 path 원문도 저장하지 않는 처리이다. |

`HighNginxErrorRate`의 실제 조건은 1분 5xx **건수 >10**, `VulnerabilityScanningDetected`는 1분 4xx **건수 >50**, `HighNginxRequestRate`는 rate **>30 requests/s, for 30s**이다. 각 식의 최종 임계 비교만 제거한 값의 P95/P99와 기존 조건을 함께 분석하는 구현이다.

이번 시간당/분당 요청 수·상태 분포·정상 4xx/5xx 빈도·조건 충족 횟수는 **미산출**이다. 표본의 minute/hour bucket은 관측된 bucket만 기록이며 빈 bucket을 정상 0으로 보간하지 않는 기준이다. sliding window count를 모든 5초 표본에 걸쳐 더하면 중복 사건 수가 되므로 전체 요청 건수로 합산하지 않는 기준이다.

## 9. SQLInjection 오탐 검토

M3의 전체 `SQLInjection` LogQL과 기존 `SQLInjectionAttempt`의 대상 범위를 재사용한 읽기 전용 metric query이다. 신규 조건은 한 번 URL 디코딩한 URI의 2분 매치 **>0**이며 기존은 원문 전체 로그의 2분 매치 **>5**인 비교이다.

정상 구간의 두 룰 매치 count 시계열·구간 전체 native count, 1건 신호의 지속 구간을 비교 가능한 기능이다. 구간 전체 count는 별도 instant query이며 sliding count 표본을 더한 값이 아니다. 통계의 event count와 실제 Ruler 발화/Alertmanager 통지 횟수는 다른 값이다.

실제 정상 URI가 없어 업무 검색어/키워드/인코딩 충돌·불필요 경보 여부는 **UNVERIFIED**이다. 현재 1건 기준을 완화/강화할 근거도 없는 상태이다. 정상 구간의 모든 매치를 False Positive로 자동 라벨링하는 기능은 없다. 해당 후보의 적법한 업무 입력 여부를 운영자가 로컬에서 비식별 판독해야 하는 후속 조건이다. 실제 요청/인증정보를 보고서에 복사하는 절차는 아니다.

## 10. PostgreSQL 연결 Baseline

기존 룰에 존재하는 `pg_stat_activity_count`를 정확한 job/instance로 조회하되 **labelset별 세션 수**로 유지한 구현이다. state 라벨이 실제 제공되면 알려진 상태값을 별도 dimension으로 보존하고 DB/상태 전체를 근거 없이 합산하지 않는 처리이다.

| 항목 | 이번 결과 |
|---|---|
| 기존 세션 메트릭의 평상시 분포 | 실측 미확보이다. 개별 시계열 >40/30초는 분석 가능한 조건이다. |
| 전체 서버 연결 수·상태별 전체 수 | exporter 실제 차원/범위의 확인이 없어 보류이다. |
| `max_connections`·예약 슬롯 | 실제 값/메트릭 이름이 없어 보류이다. 기본값이나 가상 계측명을 넣지 않은 상태이다. |
| 서버 연결 사용률 | 정확한 분자·분모가 없어 보류이다. 신규 사용률 룰은 생성하지 않은 상태이다. |
| 서버 거부 사건 | M3의 host PG17 FATAL/53300·서버 슬롯 문구 조건을 조회하는 구현이며 실제 사건 수는 미확보이다. |
| HikariCP | 정확한 현재 계측명·pool/단위가 미확정으로 별도 보류이다. 서버 슬롯과 합산하지 않은 상태이다. |

추가 SQL 확인이 필요한 경우 GC PC의 이미 허가된 읽기 전용 계정으로 아래 조회가 가능한 절차이다. 비밀번호는 `-W` 비표시 프롬프트이며 명령·보고서에 넣지 않는 절차이다.

```powershell
# GC PC / 실제 PG17 접속값으로 치환하는 조회이다.
psql -X -W -h 127.0.0.1 -p <실제포트> -U <읽기전용계정> -d <실제DB> -c "SELECT name,setting FROM pg_settings WHERE name IN ('server_version','max_connections','reserved_connections','superuser_reserved_connections') ORDER BY name; SELECT backend_type,state,count(*) AS sessions FROM pg_stat_activity GROUP BY backend_type,state ORDER BY backend_type,state; SELECT count(*) AS all_backends, count(*) FILTER (WHERE backend_type='client backend') AS client_backends FROM pg_stat_activity;"
```

이 결과는 한 시점의 서버 설정/세션 snapshot이며 장시간 분포나 Prometheus의 상시 수집 성공을 뜻하지 않는 자료이다. 점검 연결·내부 backend·계정 권한 범위를 함께 기록해야 하는 기준이다. 정확한 exporter/Hikari 이름은 실제 metrics 노출 또는 현재 Prometheus 이름 discovery 이후에만 추가 분석할 대상이다.

## 11. 기존 임계값과 후보 비교

아래 `—`는 정상 측정값/근거가 없어 산출하지 않았다는 표시이며 숫자 0이 아니다. 기존 조건 보존은 통계적으로 최적이라는 추천이 아니라 이번 변경 금지 범위 준수이다.

| 탐지 룰 | 기존 임계값·지속 조건 | 정상 P95 | 정상 P99 | 후보 임계값 | 근거 | 검증 상태 |
|---|---|---|---|---|---|---|
| HighCpuUsage | >0.5 core 상당 / 30s | — | — | 보류 | 정상 분포 없음이다. | BLOCKED |
| HighMemoryUsage | >0.85 working set/limit / 5m | — | — | 보류 | 정상 분포·limit 의미 미확정이다. | BLOCKED |
| HighNetworkReceive 컨테이너 | >1e7 bytes/s / 30s | — | — | 보류 | 실제 수신 분포 없음이다. | BLOCKED |
| HighNetworkReceive host fallback | >1e7 bytes/s / 30s | — | — | 보류 | 활성 구간·host 범위 미확정이다. | BLOCKED |
| HighNginxRequestRate | >30 requests/s / 30s | — | — | 보류 | 정상 요청량 없음이다. | BLOCKED |
| HighNginxErrorRate | 1m 5xx >10 / 0m | — | — | 보류 | 정상 5xx 분포 없음이다. | BLOCKED |
| VulnerabilityScanningDetected | 1m 4xx >50 / 0m | — | — | 보류 | 정상 4xx 분포 없음이다. | BLOCKED |
| SQLInjectionAttempt | 2m 원문 매치 >5 / 0m | — | — | 보류 | 실제 정상 매치/판독 없음이다. | BLOCKED |
| SQLInjection | 2m URI 매치 >0 / 0m | — | — | 보류 | 1건 정책의 정상 오탐 근거 없음이다. | BLOCKED |
| HighPostgresConnections | 개별 시계열 >40 sessions / 30s | — | — | 보류 | 실제 라벨·분포 미확정이다. | BLOCKED |
| DBConnectionLimit | 2m 서버 거부 >0 / 0m | — | — | 보류 | 실제 서버 거부 사건 없음/정상 여부 모두 미확정이다. | UNVERIFIED |
| UnauthorizedDataTransfer | 비허용 목적지 5m >1,048,576 payload bytes / 0m | — | — | 보류 | 정상 목적지별 분포·정책 적용 미확정이다. | BLOCKED |

기존 조건/후보의 초과 표본 비율·구간 수·관측 지속시간·`for` 충족 구간은 코드에 구현한 비교 항목이다. 이번 실제 정상 초과 현황은 **미확정**이며 0회라고 기록하지 않는 결과이다. `candidates: {}`인 기본 설정으로 P99 배율을 자동 결정하지 않은 상태이다. 검토된 절대 후보를 넣는 경우에도 단위·근거·확정 정상·품질 게이트를 통과해야 비교 가능한 구조이다.

Baseline fitting과 M6 평가용 시간은 별도이다. `reserved_evaluation_windows`와 fitting 창은 **경계 표본 하나까지 겹치면 거부**하는 검사이다. 최종 FPR용 대조군/Heldout 파일을 읽는 기능이 아니며 정상 자료만으로 탐지 재현율을 주장하지 않는 단계이다.

## 12. 미검증 항목 및 추가 측정 조건

### 12.1 운영 PC에서의 재현 실행

실행 위치는 기존 Prometheus/Loki 관리 포트에 이미 접근 가능한 **JH 운영 환경의 저장소 루트**이다. GC에서 직접 얻을 DB snapshot은 §10의 별도 조회이다. Python/PyYAML이 필요한 도구이며 네트워크 개방·서비스 배포·수집기 변경은 없는 절차이다.

다음 명령의 임시 파일은 분석용 복사본이며 운영 설정이 아니다. 먼저 복사본에 운영자가 확인한 시간 구간·정상 근거·실제 source/job/instance를 넣는 절차이다. 없는 수집 항목은 해당 mapping을 비워 독립적인 항목부터 실행할 수 있는 구조이다.

```powershell
$M4Run = Join-Path $env:TEMP 'leafy-m4-fit'
New-Item -ItemType Directory -Path $M4Run -Force | Out-Null
$M4Config = Join-Path $M4Run 'analysis.yml'
Copy-Item docs/rulepack/m4/analysis.yml $M4Config
# 분석용 복사본의 window.start/end: timezone 포함 실제 시각이다.
# normal: 확인 역할/alias·정상 근거·장애/주입 제외를 확인한 경우만 true이다.
# source/target: 실제 범위에 맞는 job/instance와 scope_confirmed이다.
# memory limit/log continuity/policy flag도 해당 증거가 있는 경우만 true이다.
# M6 평가 구간은 fitting과 별도로 예약하는 metadata이다.
python tools/rulepack/baseline_m4.py plan --config $M4Config --output (Join-Path $M4Run 'query-plan.json')
python tools/rulepack/baseline_m4.py collect --config $M4Config --prometheus http://127.0.0.1:9090 --loki http://127.0.0.1:3100 --output (Join-Path $M4Run 'observations.sanitized.json')
python tools/rulepack/baseline_m4.py analyze --config $M4Config --input (Join-Path $M4Run 'observations.sanitized.json') --output (Join-Path $M4Run 'result')
```

시간 범위를 CLI에서 직접 지정하는 방법도 제공한 구현이다. 아래 placeholder는 운영자가 실제로 선택한 timezone 포함 시각으로 바꿀 값이며 현재 정상 구간을 지정한 예가 아니다.

```powershell
$M4Start = '<운영자가 선택한 시작 시각: RFC3339 + timezone>'
$M4End = '<운영자가 선택한 종료 시각: RFC3339 + timezone>'
python tools/rulepack/baseline_m4.py plan --config $M4Config --start $M4Start --end $M4End --output (Join-Path $M4Run 'query-plan.json')
python tools/rulepack/baseline_m4.py collect --config $M4Config --start $M4Start --end $M4End --output (Join-Path $M4Run 'observations.sanitized.json')
python tools/rulepack/baseline_m4.py analyze --config $M4Config --start $M4Start --end $M4End --input (Join-Path $M4Run 'observations.sanitized.json') --output (Join-Path $M4Run 'result')
```

`--start`·`--end`는 함께 필요하며 timezone 누락·역전·24시간 초과는 거부인 계약이다. 원본 설정 파일에 쓰지 않고 메모리의 유효 window만 변경하는 구현이다. export 재분석에도 같은 시각 옵션을 사용해야 hash/window가 일치하는 구조이다. 시간 지정은 정상 확인이 아니므로 현재 기본 설정에서는 계속 `NORMAL_UNCONFIRMED`이다. 이미 확인된 구간의 정상 근거를 다른 CLI 구간에 승계하는 요청은 거부하는 안전장치이다.

주소는 실제 기존 publish와 대조할 값이다. 인증이 필요한 환경은 이미 승인된 로컬 조회 경로에서 실행할 범위이며 토큰을 명령/보고서에 넣는 절차가 아니다. 로그 원문은 API 응답을 메모리에서 집계한 뒤 폐기하는 처리이다. raw sample cap을 넘는 전체 분석은 상한·시간 범위를 검토한 후 구간을 분리할 별도 작업이며 현재 요약을 전체 분포로 과장할 수 없는 기준이다.

### 12.2 기존 비민감 export 입력 계약

`analyze --input`은 `collect`가 작성한 JSON 또는 같은 계약의 비민감 export를 읽는 기능이다. 필수 envelope는 `version=1`, `data_kind=observed/synthetic`, `config_sha256`, `plan_sha256`, 동일 `window`, `series`, `checks`, `raw_quality`, `log_summaries`이다. config/plan hash는 내용의 일치 검사이며 원격 데이터의 진위를 암호학적으로 보증하는 서명은 아니다.

각 series는 계획의 `query_id`, 고유 `series_id`, 비민감 entity, `[Unix seconds,value]` points인 형식이다. 단위·threshold·source는 export의 임의 값이 아니라 계획 정의에서 읽는 구현이다. raw_quality는 원본 표본의 quality/labelset token/metadata·limit 검사 결과이며 생략 시 확정 메트릭 Baseline에서 제외인 계약이다. `event_totals`는 전체 창 native 집계이며 선택 항목이다. 정상 확인이나 scope를 나중에 수정하면 새 config/plan에 맞는 재수집/재생성 export가 필요한 구조이다.

재생성만 수행하는 현재 상태 확인 명령은 다음과 같다.

```shell
PYTHONDONTWRITEBYTECODE=1 python3 tools/rulepack/baseline_m4.py plan --output docs/rulepack/m4/query_plan.json
PYTHONDONTWRITEBYTECODE=1 python3 tools/rulepack/baseline_m4.py analyze --output docs/rulepack/m4/current_run
```

입력 없이 실행한 두 번째 명령은 의도적으로 BLOCKED 보고서를 만드는 검사이다. 운영 룰을 생성하거나 샘플을 만드는 명령이 아니다. 저장소 내부 출력은 `docs/rulepack/m4/`로 제한한 구현이다.

## 13. 오프라인 테스트 결과

검사 도구는 앞선 M2/M3에서 공식 release digest와 대조한 임시 LogCLI 3.7.1, promtool 3.7.3이다. 이번에 서비스를 가동하거나 실측 트래픽을 생성하지 않은 검사이다.

| 검사 | 결과·범위 |
|---|---|
| M4 unittest | **28개 PASS, SKIP 0개**이다. |
| M2~M4 전체 회귀 | **77개 PASS, SKIP 0개**이다. |
| Native 문법 | 분석용 PromQL 11개와 LogQL 11개 파싱/구조 PASS이다. |
| Native 값/단위 | 합성 counter/gauge에서 CPU core 상당량·메모리 비율·컨테이너 bytes/s·Nginx requests/s와 root fallback 억제/활성을 검사한 PASS이다. 실제 Baseline 측정이 아니다. |
| 통계/시간 | 분위수 보간·평균/변동성/시간대·추세, 초과 경계·30초/5분 지속·gap에 의한 단절 PASS이다. |
| 품질/선정 | 비유한 값·중복·raw jitter·lookback 뒤 원본 공백, memory label/limit, 정상 미확인·합성 제외·config/provenance·M6 경계 중복 거부 PASS이다. |
| HTTP/S2 | URI/사용자 비식별·표본 상한, 최종/threshold 분리·중복/충돌 제외·observer 분리·창 길이·첫 관측 범위 PASS이다. |
| API/파일 | GET만 사용·partial/오류/empty와 0 구분·warmup 범위·비민감 export·운영 출력 경로 차단 PASS이다. |
| 추가 사용자 지시 | 정상 미확인/합성 분위수의 전체 출력 차단, CLI 시각/짝/timezone·설정 불변, 다른 구간으로 정상 확인 자동 승계 거부 PASS이다. |

합성 숫자는 테스트 코드 안에만 존재하는 입력이며 `m4/current_run`의 측정 결과로 내보내지 않은 작업이다. Native PromQL 합성 평가도 정상 데이터의 실제 분포나 재현율을 증명하지 않는 검사이다. Loki는 전체 식 파싱과 기존 M3 pipeline 검증까지이며 서버의 실제 count/Ruler 평가 성공은 별도 인수인 상태이다.

```shell
M4_LOGCLI=/path/to/logcli M4_PROMTOOL=/path/to/promtool PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s tools/rulepack/tests -p test_baseline_m4.py -v
M2_LOGCLI=/path/to/logcli M2_PROMTOOL=/path/to/promtool \
M3_LOGCLI=/path/to/logcli M3_PROMTOOL=/path/to/promtool \
M4_LOGCLI=/path/to/logcli M4_PROMTOOL=/path/to/promtool PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s tools/rulepack/tests -v
```

M4 도구 경로가 없으면 native 3개 검사는 SKIP이며 통과로 집계하지 않는 계약이다. PowerShell에서는 `$env:M4_LOGCLI`, `$env:M4_PROMTOOL`, `$env:PYTHONDONTWRITEBYTECODE='1'`을 현재 프로세스에 지정한 뒤 동일 unittest 명령을 사용하는 절차이다.

작성한 파일은 [분석 코드](../../tools/rulepack/baseline_m4.py), [테스트](../../tools/rulepack/tests/test_baseline_m4.py), [분석 설정](m4/analysis.yml), [계획](m4/query_plan.json), [API 증거](m4/availability.json), [실행 기록](m4/execution_record.json), [분석 JSON](m4/current_run/analysis.json), [생성 요약](m4/current_run/summary.md), 이 보고서이다.

## 14. M4 완료 판정 및 M5 선행 조건

| 항목 | 판정 | 결과 |
|---|---|---|
| M4-A 정상 수집 가능성/선정 기준 | PARTIAL | 기존 계약·실행 계획·정상/품질 게이트 구현 완료이며 확인된 정상 구간은 없는 상태이다. |
| M4-B CPU 실제 Baseline | BLOCKED | 정상 원본/평가 표본이 없는 상태이다. |
| M4-C 메모리 실제 Baseline | BLOCKED | 정상 표본과 limit 의미/라벨 검증 증거가 없는 상태이다. |
| M4-D 수신/S2 실제 Baseline | BLOCKED | 정상 전송·scope·관측 창 증거가 없는 상태이다. |
| M4-E HTTP 실제 Baseline | BLOCKED | 정상 로그/요청량 표본이 없는 상태이다. |
| M4-F SQLi 정상 오탐 판독 | UNVERIFIED | 실제 매치·정상 업무 판독이 없는 상태이다. |
| M4-G DB 전체/상한·Hikari | BLOCKED | 실제 전체 scope/계측 계약과 정상 표본이 없는 상태이다. |
| M4-H 분석 도구·재현 설정·검증 | PASS | 입력 유무에 맞는 분석·비식별 export·보고서 생성과 합성 검증 완료이다. |
| M4-I 임계값 후보 확정 | BLOCKED | 정상 근거가 없어 후보를 제안하지 않은 상태이다. |
| 기존 산출물/운영 조건 보존 | PASS | 시작 시 44개 해시 일치와 tracked 변경 없음인 결과이다. |
| M4 전체 | **PARTIAL** | **분석 도구 및 오프라인 검증 완료 / 실측 Baseline 수립 대기**이다. |

M5의 상세 범위는 현재 요청에서 정의되지 않은 상태이다. 도구/설계 등 독립적인 후속 개발은 진행 가능한 상태이나, 정상 Baseline 확정·임계값 동결을 전제로 하는 실험 인수는 M4 완료로 승인할 수 없는 상태이다. 해당 source의 정상 선정·연속성·단위/identity·기존 조건 초과 및 SQLi 매치 판독이 필요한 선행 증거이다. 모든 OI 항목을 기다리는 공통 게이트가 아니라 입력이 확보된 항목부터 순차 인수할 범위이다.

M6 최종 FPR 평가는 fitting과 분리한 정상 평가 구간으로 진행할 조건이다. 현재는 정상 임계값 변경 근거나 탐지 재현율을 주장할 단계가 아닌 결과이다.
