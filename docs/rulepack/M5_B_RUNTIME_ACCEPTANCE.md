# M5-B — 실제 룰팩 통합 검증 및 E2E 인수

## 1. 현재 판정

**M5-B 미완료 — Phase A 읽기 전용 검증/오프라인 회귀 완료, 실제 후보 평가·발화·E2E 미인수. Phase B는 A/B 통합 및 실제 배포 후 대기이다.** GC→JH 관측 데이터 전달은 사용자의 확인을 수용했고 전달 경로를 처음부터 조사하지 않았다.

대상은 M5-A 원본 후보 **21개 정의(Loki 12 / Prometheus 9), alert 이름 18종**이다. 실제 서버에서 평가한 후보 0개, 신규 후보 발화 인수 0개, 실제 사건 E2E 인수 0개이다. API 접근 실패를 데이터 부재·무경보·원격 장애로 해석하지 않았다. M4의 **NORMAL_UNCONFIRMED**와 manifest의 `deployment_allowed=false`를 유지한다.

본 작업은 독립 worktree `m5b-runtime-acceptance`, 브랜치 `test/m5b-runtime-acceptance`, 기준 HEAD `92e70db`에서 수행했다. 원래 저장소의 미커밋 M1~M5 문서·생성기·테스트 등 43개 파일을 symlink/Heldout/cache를 제외하고 복사했다. [source_snapshot.json](m5b/source_snapshot.json)은 복사 시점 해시이다. 복사본은 입력 자료이며 M5-A·기존 룰을 수정하지 않았다. A/B 브랜치는 가져오지 않았다.

수정 소유 파일은 [acceptance_m5b.py](../../tools/rulepack/acceptance_m5b.py), [test_acceptance_m5b.py](../../tools/rulepack/tests/test_acceptance_m5b.py), 이 문서와 `m5b/`뿐이다. 운영 룰 교체/reload, Docker 실행/재시작, alert POST, 시나리오 주입, 추론 요청, stash/reset/clean, commit/push/PR은 수행하지 않았다. 원본 로그·URI·인증정보·실제 IP는 보고서에 저장하지 않았다.

## 2. 실제 조회 시각과 접근 환경

이번 접근 환경은 **JH 개발 Mac의 실행 호스트 loopback**이다. 이를 JH 관리 서버 또는 GC 배포 환경으로 간주하지 않았다. 현재 설정의 관리 API URL 키만 제한적으로 확인했으나 원격 관리 origin이 지정되지 않았고 실제 file_sd `.yml`도 없었다. `.env` 본문/값은 출력하지 않았다. 이는 전체 네트워크나 원격 설정의 부재를 주장하는 조사가 아니다. [접근 문맥](m5b/access_context.json).

최종 GET 실행 시각: **2026-11-11 02:21:14 KST / 2026-11-10 17:21:14 UTC**. endpoint별 정확한 시각은 [runtime.json](m5b/runtime.json)의 `at_utc`에 있다.

| 실행 증거 | 결과·해석 |
|---|---|
| [runtime.initial.json](m5b/runtime.initial.json) | 기본 검증기 7 GET 모두 ACCESS_DENIED. 샌드박스 제한이며 서비스 장애 판정이 아니다. |
| [runtime.network.json](m5b/runtime.network.json) | 기존 검증기의 같은 7 GET을 허용된 네트워크 실행으로 재조회했다. 연결 거부 및 Pipeline 계약 불일치를 확인했다. |
| [runtime.json](m5b/runtime.json) | 보완 검증기로 **11 GET** 수행. loaded rules/build info도 주 조회와 독립적으로 시도했다. 주소는 run-local opaque token으로 저장했다. |

| 서비스 / API | 직접 관측 결과 | 아직 확인하지 못한 항목 |
|---|---|---|
| Prometheus / targets, rules, buildinfo | 모두 CONNECTION_REFUSED | targets health, 실제 metric/label·PC 대응, loaded rule·평가 오류·empty 여부 |
| Loki / labels, Ruler rules, buildinfo | 모두 CONNECTION_REFUSED | 실제 stream/service/runtime/log_format, URI 타입, PG17 필드, network event, 서버 LogQL 호환성·Ruler 로드 |
| Alertmanager / status, alerts | 모두 CONNECTION_REFUSED | 실제 loaded config/receiver, 현재 alert labels/annotations·startsAt/endsAt·억제 상태 |
| Pipeline / health | HTTP 404 | Leafy health 성공·실행 이미지/설정 |
| Pipeline / OpenAPI | UNEXPECTED_RESPONSE | Leafy webhook 계약과 source 필드의 실제 배포 상태 |
| Ollama / tags | CONNECTION_REFUSED | 실제 모델 존재·배포 모델과 일치·실제 추론 결과 |

Prometheus/Loki는 primary·rules·build 세 GET이 모두 도달 실패여서 같은 origin의 후보/input query와 Loki RCA/timeline 조회를 생략했다. **후보 empty 결과 21건이라는 뜻이 아니다.** HTTP 401/403/404나 metadata 스키마 불일치만 있으면 query를 독립 시도하도록 보완했다. 한 서비스의 실패로 다른 서비스 수집을 중단하지 않는다.

## 3. source/selector와 입력 계약

아래는 **후보 파일에서 읽은 설정값**이다. 실제 입력 확인 결과는 모두 UNVERIFIED이다. `{service="db"}` 또는 동명 exporter만으로 PC를 특정하지 않는다.

| 후보 범위 | 확인한 후보 selector / 요구 입력 | 남은 실제 검증 |
|---|---|---|
| 기존 marker·process·path 룰 5개 | backend 또는 frontend/backend service; 원문 marker/명령 문자열 | stream source/runtime, marker 의미. 로그 문자열은 실제 프로세스 실행·탈출 성공 증거가 아니다. |
| network 2개 | log_type=network, src_service=backend, event_type=connection / connection_threshold; dst_service 제외 조건 | canonical event 키/타입, bytes_sent·목적지·observer_instance, 같은 PC/연결의 사건 대응 |
| HTTP 2개 | service=frontend, log_format=json; status | 실제 JSON 타입/오류 처리, source별 5xx/4xx 매치 |
| UnauthorizedDBAccess | service=db; 인증 실패 문자열 | host/container·PC 귀속, 실제 DB 로그 형식 |
| SQLInjection | service=frontend, runtime=container, log_format=json | 문자열 request_uri, fromJson/urldecode 등의 실제 서버 평가 |
| DBConnectionLimit | service=db, runtime=host, log_format=json | PG17 jsonlog error_severity/state_code/message 문자열, FATAL/53300/서버 슬롯 거부 의미 |
| HighPostgresConnections | pg_stat_activity_count, job/instance 제한 없음 | 실제 metric/label와 대상 DB. 개별 시계열 >40이며 전체 연결 합계나 사용률이 아니다. |
| HighNginxRequestRate | nginx_http_requests_total, job=nginx-exporter | 실제 instance/PC 대응, counter·단위·필요 표본 |
| CPU 4개 | container_cpu_usage_seconds_total + container_name_info, id join, 대상별 name | cadvisor/cadvisor:8080과 pipeline-metadata/pipeline:8000이 같은 GC source인지, id 유일성·단위·연속성 |
| ContainerRestarted | aiops_docker_container_restarts_total / aiops_docker_container_started_at_seconds, backend name | GC producer, 5초 표본·reset·실제 기존 restart 사건, StartedAt 의미 |
| HighMemoryUsage | container_memory_working_set_bytes / positive container_spec_memory_limit_bytes + metadata | 전체 라벨 일치, limit 의미, source 전체 name 범위·중복 id |
| HighNetworkReceive | container_network_receive_bytes_total, 앱 4개 name 및 root fallback/presence guard | GC container/root 구분, 다른 source의 guard 간섭·호스트 오귀속 |

CPU·메모리·재시작은 위 고정 job/instance를 참조한다. GC의 실제 pair와 다르면 API가 정상이어도 empty일 수 있다. 집계로 source label이 사라지는 후보는 source-aware Pipeline만으로 복구할 수 없다. `leafy-db`는 Docker CPU와 host PostgreSQL이 공유하는 alias라 별도 identity 인수가 필요하다.

## 4. 21개 후보별 인수 매트릭스

[I=INPUT_VERIFIED, S=SELECTOR_VERIFIED, Q=QUERY_SUCCESS, L=RULE_LOADED, F=FIRING_VERIFIED, A=ALERT_DELIVERED(Ruler→AM), P=PIPELINE_RECEIVED, R=RCA_VERIFIED]. **U=UNVERIFIED, B=BLOCKED**, V=VERIFIED, F=FAIL이다. 열 F(발화)와 셀 F(실패)를 구분한다. 이번 셀에는 실패 판정이 없다.

| # | 엔진 | 후보 / 대상 | I | S | Q | L | F | A | P | R |
|---:|---|---|---|---|---|---|---|---|---|---|
| 1 | loki | SecretDumpAttempt / leafy-backend | U | B | B | U | U | U | U | U |
| 2 | loki | SuspiciousProcessExecution / leafy-backend | U | B | B | U | U | U | U | U |
| 3 | loki | SuspiciousProcessExec / leafy-backend | U | B | B | U | U | U | U | U |
| 4 | loki | PathTraversalAttempt / leafy-frontend | U | B | B | U | U | U | U | U |
| 5 | loki | ContainerEscapeAttempt / leafy-backend | U | B | B | U | U | U | U | U |
| 6 | loki | UnauthorizedDataTransfer / leafy-backend | U | B | B | U | U | U | U | U |
| 7 | loki | UnauthorizedTransferEarly / leafy-backend | U | B | B | U | U | U | U | U |
| 8 | loki | HighNginxErrorRate / leafy-frontend | U | B | B | U | U | U | U | U |
| 9 | loki | VulnerabilityScanningDetected / leafy-frontend | U | B | B | U | U | U | U | U |
| 10 | loki | UnauthorizedDBAccess / leafy-db | U | B | B | U | U | U | U | U |
| 11 | loki | SQLInjection / leafy-frontend | U | B | B | U | U | U | U | U |
| 12 | loki | DBConnectionLimit / leafy-db | U | B | B | U | U | U | U | U |
| 13 | prometheus | HighPostgresConnections / leafy-db | U | B | B | U | U | U | U | U |
| 14 | prometheus | HighNginxRequestRate / leafy-frontend | U | B | B | U | U | U | U | U |
| 15 | prometheus | HighCpuUsage / leafy-frontend | U | B | B | U | U | U | U | U |
| 16 | prometheus | HighCpuUsage / leafy-backend | U | B | B | U | U | U | U | U |
| 17 | prometheus | ContainerRestarted / leafy-backend | U | B | B | U | U | U | U | U |
| 18 | prometheus | HighCpuUsage / leafy-db | U | B | B | U | U | U | U | U |
| 19 | prometheus | HighCpuUsage / leafy-minio | U | B | B | U | U | U | U | U |
| 20 | prometheus | HighMemoryUsage / 동적 name | U | B | B | U | U | U | U | U |
| 21 | prometheus | HighNetworkReceive / 동적 name/host fallback | U | B | B | U | U | U | U | U |

기계 판독 결과는 [acceptance_matrix.json](m5b/acceptance_matrix.json), endpoint 근거는 [runtime.json](m5b/runtime.json)이다. 입력/loaded/firing 이후 단계는 증거가 없어 U이며 selector/query는 현재 접근 경로 차단 때문에 B이다. 룰 자체를 실패 또는 정상으로 판정하지 않는다.

도구는 input sample이 존재하면 SELECTOR만 승격한다. 타입·단위·연속성·PC mapping을 요구하는 INPUT과 사건 상관이 필요한 FIRING/DELIVERED/RECEIVED/RCA는 자동 승격하지 않는다. QUERY_SUCCESS는 empty와 별개이며 warnings/infos는 PARTIAL이다. 같은 alertname·expr만으로 RULE_LOADED를 승인하지 않고 후보 group·식·static labels·annotations·for·keep_firing_for와 명시 interval까지 비교한다. API 표현 정규화로 해시가 다르면 수동 의미 비교가 필요하며 불일치를 의미 변경으로 단정하지 않는다.

## 5. loaded rule과 후보 차이

실제 loaded inventory는 두 엔진 모두 UNVERIFIED이다. 현재 저장소의 운영 정의는 Loki 11 + Prometheus 6 = **17개**, 후보는 12 + 9 = **21개**이다. [정적 계약](m5b/static_contract.json)과 [M5-A manifest](m5/manifest.json)을 대조했다.

- 원본 유지 8개, M2로 대체하는 원본 이름 8종, SQLInjectionAttempt reference 분리, CPU 4대상 확장과 SQLInjection/DBConnectionLimit이 M5-A 구성이다.
- 기존 17개의 실발화는 후보 21개의 실발화로 계수하지 않는다. 동일 식인 유지 룰도 candidate group/실제 로드 증거를 요구한다.
- 같은 이름의 구/신 룰 병행, 기존 SQLInjectionAttempt와 신규 SQLInjection, network 생성 결과의 중복 로드 가능성이 있다. 실제 API에서 중복 0을 확인하지 못했다.
- 후보/reference는 운영 mount 밖에 있다. 이번 세션은 운영 룰 교체·reload를 하지 않았다. reference/backup을 함께 로드하지 않는다.

## 6. Alertmanager / Pipeline / Ollama 증거

**실제 API 증거**는 §2의 실패/계약 불일치이다. 현재 활성 경보가 0개임을 확인한 것이 아니고, 실제 loaded config·전송·수신·추론은 모두 UNVERIFIED이다.

**정적 기준선**은 통합 전 HEAD의 코드/설정이다. Alertmanager는 webhook `/webhook/alert`, send_resolved=true, group_wait/group_interval=10초, repeat=240초이다. Pipeline은 version/groupKey/status/alerts 및 각 alert status/labels/startsAt/annotations를 수신하며 container annotation을 우선한다. AlertLabel 선언 필드는 alertname/severity/instance/container이고 dedup은 alertname:container이다. 다른 PC의 동명 서비스를 구분하는 OI-09는 아직 해결로 기록하지 않았다.

host PostgreSQL과 Docker alias 충돌, local Docker id 기반 메트릭 조회·service 중심 앱 로그 조회, 정확히 unknown인 대상 처리와 host fallback도 통합 전 위험이다. queued 응답은 비동기 분석 완료가 아니다. Ollama tags 존재·health와 실제 `/api/chat` 분석 완료는 별개이며 이번 추론 호출은 하지 않았다. 도구의 code-default model 비교와 실제 배포 모델 비교도 구분했다.

**접근 가능한 기존 RCA 파일 metadata**: 원래 저장소의 로컬 `aiops/pipeline/results/llm_results.jsonl`을 메모리에서 요약했다. [existing_rca_metadata.json](m5b/existing_rca_metadata.json)에 파일 해시·조회 시각·키 구조·시각만 기록했다. **15건, 2026-06-02~06-05 UTC, source identity 키 0건**이다. 실제 Ollama 생성 여부/모델·배포 출처·입력 source·수신/발화 이력이 연결되지 않아 자연 발생 사건 또는 이번 후보 RCA로 승인하지 않았다. 파일 행 번호는 local_line_index이며 Loki 관측 timestamp가 아니다.

현재 AM 상태, 6월 로컬 결과, 이번 11월 조회를 같은 사건으로 연결하지 않았다. 보존된 Ruler pending/firing→AM→Pipeline 수신→실제 Ollama 결과→자료 출처→해소 증거의 완전한 사슬은 확보하지 못했다. 따라서 임의 alert POST 없이 E2E 미확인 상태를 유지한다.

## 7. SQLInjection 정책과 교체 위험

| 항목 | 기존 SQLInjectionAttempt | 신규 SQLInjection |
|---|---|---|
| 임계값 | 2분 >5, 즉 6건 이상 | 2분 >0, 즉 1건 이상 |
| 입력 | frontend 원문 전체 | frontend/container/json의 문자열 request_uri |
| 처리 | 원문 정규식 | JSON/타입 검증, URI URL decode 한 번, 일부 SQL 구문/주석 패턴 |
| 호환성 차이 | URI 밖 문자열도 매치 가능 | runtime/log_format 누락 또는 URI 타입 차이로 누락 가능; 서버 template 함수 호환성 필요 |
| 이번 결과 | 로컬 native 회귀 PASS, 실제 서버 미평가 | 로컬 native 회귀 PASS, 실제 서버 미평가 |

정상 검색·교육/디버그 문구·스캐너 요청이 1건 기준에 매치할 수 있고, URI 밖 신호를 제외하는 의미 차이도 있다. URL decode는 이중 디코딩/본문 탐지를 보장하지 않는다. 한 요청이 sliding window의 여러 평가에서 잡혀도 여러 독립 사건으로 세지 않는다.

서로 다른 alertname이므로 기존 Pipeline dedup이 의미 중복을 제거하지 않는다. 두 정의 병행 로드 시 중복 알림/RCA가 가능하다. label/annotation/필드 계약과 실제 LogQL 서버의 fromJson/printf/index/urldecode/drop 평가, parse/template/unwrap 오류를 실제 API에서 확인하기 전에는 호환성을 인수하지 않는다.

**확정 정상 운영 데이터가 없어 FPR·재현율·임계값 우수성을 산출/주장하지 않는다. NORMAL_UNCONFIRMED를 유지한다.** 오프라인 합성 회귀는 서버 호환성·운영 FPR 증거가 아니다.

## 8. 코드 보완과 검증

기존 검증기를 재사용해 소유 영역에만 보완했다.

- 8개 독립 stage와 exact-definition/group 비교를 추가하고 기존 운영 룰의 동명/동일 식을 후보 로드로 자동 승인하지 않게 했다.
- metadata API 실패와 query 가능성을 분리했다. 서버 오류는 JOIN/PARSE/TEMPLATE/PIPELINE 분류만 보존하고 원문은 저장하지 않는다.
- endpoint/job/instance/source/id 값은 실행 내 equality token으로 축약했다. 다른 실행 사이의 token 연결은 지원하지 않는다.
- 기존 RCA/timeline의 bounded GET metadata, AM startsAt/endsAt와 webhook 필드/required 계약, 배포 확인 모델과 tags의 선택적 비교를 추가했다. 기존 RCA를 실제 추론 증거로 자동 승인하지 않는다.

| 검사 | PASS | SKIP | FAIL | 의미 |
|---|---:|---:|---:|---|
| 초기 기본 전체 회귀 | 73 | 28 | 0 | native 경로 미지정으로 28 SKIP. 이후 아래 검사로 보완했다. |
| 최종 M2~M5-B 전체 회귀 | 106 | 0 | 0 | 기존 93 + 기존 M5-B 8 + 새 경계 검사 5. 개별 결과는 regression.json이다. |
| M5-B 단독 경계 검사 | 13 | 0 | 0 | GET/민감정보/접근 실패/empty·0·NaN/구 룰 오인/단계 승격/과거 RCA 구분 |
| M5-A integrate --check | 1 | 0 | 0 | 재생성·manifest/후보 drift 없음, 운영 변경 없음 |
| 실제 후보 입력·query·firing/E2E | 0 | 21개 후보 미평가 | 0 | 테스트 PASS 수에 포함하지 않는다. BLOCKED/UNVERIFIED이다. |

[regression.json](m5b/regression.json)에 각 test의 PASS/SKIP/FAIL과 도구 해시를 기록했다. 사용한 기존 로컬 도구는 promtool 3.7.3 / LogCLI 3.7.1이다. 서비스나 Docker를 시작하지 않고 native 문법·합성 fixture 평가를 실행했다. 합성 입력은 실제 공격/장애 주입이나 Heldout이 아니다. 실제 서버 버전은 API 미접근으로 확인하지 못했다.

검사 명령은 M2/M3/M4/M5의 PROMTOOL/LOGCLI 변수를 기존 로컬 바이너리로 지정한 뒤 `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tools/rulepack/tests`이다. `integrate_m5.py --check`는 별도로 수행했다. 최종 보존 검사는 [verification.json](m5b/verification.json)을 따른다.

## 9. A/B 의존 항목과 최종 재검증

| 의존 | 현재 상태 | 실제 배포 후 필요한 증거 |
|---|---|---|
| A / OI-09 | 통합 전 기준선, 해결 미기록 | source-aware 계약·dedup, PC별 동명 서비스 분리, host PG17 경로, 결과 identity/자료 출처 보존 |
| B / OI-02/03/04 | 통합 전 기준선, 해결 미기록 | GC CPU/메모리/network·restart producer, 실제 5초 표본, 정확한 job/instance/id mapping과 조인 유일성 |
| 탐지 룰 소유자 | 원래 M5-A 후보 유지 | 실제 GC selector와 고정 후보의 차이, 집계 source 손실·host/container alias 충돌 검토 |
| 자연 발생 사건·실행 환경 | 미확보/접근 불가 | 후보의 실제 로드·pending/firing·AM·webhook·실제 모델 RCA·정확한 대상/source·해소의 시간순 연결 |

실행 가능한 상세 절차와 각 단계 PASS 조건, 쓰기가 필요할 때의 격리·외부 알림/Remediation 차단·원복 요건은 [PHASE_B_REVALIDATION.md](m5b/PHASE_B_REVALIDATION.md)에 분리했다. A/B 결과를 다른 브랜치에서 가져오거나 원본을 덮어쓰지 않았다. **통합 및 실제 배포 전 Phase B 완료로 판정하지 않는다.**

자연 사건을 확보하지 못했으므로 테스트 경보를 보내지 않는다. 쓰기가 필수인 다음 단계는 별도 승인된 격리 환경과 출구 차단/원복 계획을 보고한 뒤 실행 보류이다. 현재 GET 수집 범위는 완료했으며 M5-B 전체 인수는 위 runtime 증거가 채워질 때까지 미완료이다.
