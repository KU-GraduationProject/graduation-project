# 07. Mock 계약 예시 — DB 연결 슬롯 고갈 (`DBConnectionLimit`)

> **합성 데이터다.** 실제 GC/JH 장비·로그·주소가 아니며, 시나리오를 실행해 얻은 값이 아니다. IP는 문서용 대역(192.0.2.0/24)과 placeholder다.
> 파일: [examples/db-connection-limit/](examples/db-connection-limit/) · 필드 정의: [01](01_DATA_CONTRACT.md) · 상태 규칙: [04](04_DATA_QUALITY.md)

## 1. 시나리오 선택 이유

| 후보 | 판단 |
|---|---|
| **`DBConnectionLimit`** (GC host PostgreSQL 17, FATAL `53300`) | **채택.** host runtime(`container=null`)·PG jsonlog·24225 경로·Network host endpoint·메트릭 미매핑을 한 사건에서 모두 시험한다 |
| F2-c `f2c_db_pool_exhaustion` | Mock은 시나리오 실행 결과가 아니라 합성이므로 경보(`DBConnectionLimit`)를 기준으로 삼고, F2-c는 증거 형태(too many clients)만 참고한다. PR #33 이후 실행기가 Host 모드(`F2C_DB_MODE=host`, 로컬 `psql`)로 GC PG17을 지원하므로([F2C_RUNTIME.md:13](../../scenarios/v2/F2C_RUNTIME.md#L13)) **실환경 검증 단계에서 이 사건의 원천 데이터를 만드는 실행기 후보**다. 실행 결과·정답은 Gold에 넣지 않는다([00](00_EXISTING_SYSTEM_ANALYSIS.md) §9). Runbook의 "Docker DB 전용" 문구는 낡았다(X-08) |
| `UnauthorizedDBAccess` | 보안 경보라 "DB 장애" 대표성이 낮다 |

**룰 상태:** `DBConnectionLimit`은 M3에서 만든 룰로 [docs/rulepack/m5/generated/loki.rules.yml](../rulepack/m5/generated/loki.rules.yml)에 있으나 **운영 mount 대상이 아니다**(`monitoring/loki/rules/`에 없음, M5-A "offline candidate"). 경보 label의 `site/source/service/runtime/target`은 릴리스 후보 생성기(`prepare_release.py`)가 붙이는 형태를 가정했다.

## 2. 합성 환경

| 항목 | primary (경보 대상) | related (선언된 의존 대상, DEC-06) |
|---|---|---|
| identity | `fixture-gc` / `fixture-host-pg` / `db` / `host` / `fixture-pg17` | `fixture-gc` / `fixture-docker` / `backend` / `container` / `fixture-backend` |
| binding | logs + network, **metrics 없음** | logs + metrics(`gc-telemetry-v1`) + network |
| 검증 | 실제 `identity.parse_bindings()` 통과, 경보는 `resolve_identity()` → `resolved` | 같음 |

[01_bindings.json](examples/db-connection-limit/01_bindings.json)은 `OBSERVATION_BINDINGS` 형식 그대로이며 값은 fixture 전용이다.

## 3. 타임라인 (UTC)

| 시각 | 사건 |
|---|---|
| 02:59:58.000 | PG `LOG connection received` (정상) |
| 03:00:18.405 / 19.098 | Network: backend → db(host-bound) 짧은 연결 2건 `closed` |
| 03:00:18.412 / 19.105 / 21.733 | PG `FATAL 53300` (too many clients ×2, reserved slots ×1) |
| 03:00:19.300 | backend ERROR `Failed to obtain JDBC Connection` (메시지에 합성 비밀값 포함) |
| 03:00:20.000 | 미래 MAJOR(`schema_version 2.0`) Network 이벤트 1건 — 소비자가 quarantine해야 함 |
| **03:00:20.512** | **경보 `startsAt` (anchor)** |
| 03:00:40.000 | backend INFO 200 응답 (미리 열린 연결로 아직 정상) |
| 03:00:50.731 / .735 | Hikari timeout ERROR, 16KB 초과 stack trace의 partial 미완성 줄(`json_invalid`) |
| 03:00:58.240 | 실시간 Pipeline이 RCA envelope를 Loki `aiops-llm`에 push (NOTIFY, confidence 0.74) |
| 03:01:03.250 | PG FATAL — timestamp zone `JST`라 Fluentd가 수신 시각을 사용(`log_time_parse_error`) |
| 03:02:10.000 | PG 긴 statement LOG (`log_truncated`) |
| 03:05:20.512 | 사건 창 끝 (anchor + 5m) |
| 03:16:20.512 | 획득 창(패딩 60s) 끝 + 지연 허용 600s → 이후 획득은 `window_closed=true` |
| **03:20:00** | Airflow `dp_incident_build` — Bronze 10건 획득 → Silver 7 build → Gold build 1 |
| **03:40:00** | Airflow `dp_reprocess` — db_log 강제 재획득(limit 3), 2번째 페이지 timeout → `partial` → Silver db_log·Gold 재빌드 |

## 4. 입력 계약 (Bronze)

| 파일 | 내용 | 시험하는 계약 |
|---|---|---|
| [00_incident_request.json](examples/db-connection-limit/00_incident_request.json) | Airflow conf. `expected_incident_id` = `inc_3f9a00917bce9babb36e68f4` | 사건 ID 결정성(§1.1) |
| [10_bronze_acquisition.jsonl](examples/db-connection-limit/10_bronze_acquisition.jsonl) | 획득 11건 | 상태 8종 중 `ok`·`partial`·`empty_verified`·`empty_unverified`·`scope_unavailable` |
| [11_bronze_loki_entry.jsonl](examples/db-connection-limit/11_bronze_loki_entry.jsonl) | Loki 행 19건 (PG 6+3 중복, Network 3+2 중복, App 4, RCA 1) | 원문 보존, 획득 간 중복 |
| [12_bronze_prometheus_sample.jsonl](examples/db-connection-limit/12_bronze_prometheus_sample.jsonl) | backend `cpu_usage` 49점(15s, 패딩 포함) | 파리티 PromQL, 시각 ms 변환 |
| [13_bronze_raw_page_example.json](examples/db-connection-limit/13_bronze_raw_page_example.json) | 첫 획득의 Loki 응답 원문(바이트 그대로) | `raw_sha256` 재계산 |

획득 상태 요약:

| 획득 | scope | 상태 | 이유 |
|---|---|---|---|
| db_log (03:20) | primary | `ok` | 6행 |
| network_dst / network_src | primary | `ok` / `empty_unverified` | db는 출발지가 아니라 stream 자체가 없음 → "검증 불가 빈 결과"가 정상적으로 나옴 |
| host_metrics | primary | `scope_unavailable` / `collector_unmapped` | binding에 metrics 없음 → **질의하지 않음** |
| app_log | related | `ok` | 4행 |
| network_src / network_dst | related | `ok` / `empty_verified` | stream은 있으나 창 안 0건 |
| cpu_usage | related | `ok` | 49점 |
| rca_result / fluentd_internal | global | `ok` / `empty_unverified` | Fluentd 경고 stream이 아예 없음 → 전송 유실 여부는 "확인 불가" |
| db_log 재획득 (03:40) | primary | `partial` / `page_failed:timeout` | 받은 3행은 보존, 같은 `acquisition_key` |

## 5. 기대 출력 (Silver)

| 파일 | 행 | 확인 포인트 |
|---|---|---|
| [20_silver_db_log.jsonl](examples/db-connection-limit/20_silver_db_log.jsonl) | 6 | 3행 `_dup_count=2`·`duplicate`(재획득 중복), 1행 `receiver_fallback`+`event_time_fallback`+`log_time_parse_error`, 1행 `log_truncated`. PK = `(site, source, target, session_id, line_num, timestamp)` |
| [21_silver_app_log.jsonl](examples/db-connection-limit/21_silver_app_log.jsonl) | 4 | `label_profile=release_v1`, `log_stream=stdout`, partial 줄은 `log_format=json_invalid` + `log_parse_error` + `log_partial_incomplete`. **비밀값은 원문 그대로 남는다**(C-12) |
| [22_silver_network_event.jsonl](examples/db-connection-limit/22_silver_network_event.jsonl) | 2 | primary·related 획득에서 같은 이벤트 → 각 `_dup_count=2`. 원 스키마 27필드 그대로, `dst_container=null` |
| [23_silver_metric_point.jsonl](examples/db-connection-limit/23_silver_metric_point.jsonl) | 49 | identity는 획득 scope |
| [24](examples/db-connection-limit/24_silver_alert_event.jsonl) / [25](examples/db-connection-limit/25_silver_rca_result.jsonl) | 1 / 1 | envelope → alert_event·rca_result. `fallback_reason=null` |
| [26_silver_quarantine.jsonl](examples/db-connection-limit/26_silver_quarantine.jsonl) | 1 | `unsupported_schema_version` (조용히 버리지 않음) |
| [27_silver_transport_issue.jsonl](examples/db-connection-limit/27_silver_transport_issue.jsonl) | 0 | **빈 build도 manifest가 있다** → "없음"과 "안 만듦"을 구분 |

## 6. 기대 출력 (Gold)

| scope | 채널 | status | 근거 |
|---|---|---|---|
| primary | log | `complete` | 획득 `ok`+`partial` → 최선 `ok`, 6행 매칭 |
| primary | metric | `unavailable` / `collector_unmapped` | 규칙 2 |
| primary | network | `unavailable` / `host_target_field_absent` | 창 안 2행, 모두 `target_unresolvable`(Canonical schema에 `dst_target` 없음) + quarantine 1. 실시간 collector도 accepted 0 / skipped 3 ([60](examples/db-connection-limit/60_realtime_parity.json)) |
| related | log / metric / network | `complete` | 같은 Network 이벤트가 backend(container, `src_container` 일치)에서는 매칭 → flow 1건 |

- `overall_status = partial` (primary 중 log만 complete).
- evidence 12행: db 로그 6, app 로그 4(1행 `masked` — `password=***`), cpu series 1(`samples=41` = 실시간 ±5m·15s 파리티), flow 1(`allowlist=ok`, bytes는 최종 이벤트만).
- `rca_link` 1행 `post_hoc_same_alert`: 실시간 RCA는 이 Gold를 보지 않았다.
- `gold.incident`의 `transport_check_status = empty_unverified`, `transport_loss_suspected = false`.

## 7. 버전·리니지

| 항목 | 값 |
|---|---|
| Gold build | `gb_20261110T032015Z_edd1b412`(1차) → `gb_20261110T034045Z_124c3f4f`(현재, `supersedes` 1차) |
| Silver db_log | `sb_20261110T032010Z_62bad93f`(1차) → `sb_20261110T034042Z_c4d90e9a`(현재). 나머지 Silver는 1차 build가 현재 |
| evidence_id | 두 Gold build에서 **동일**(재빌드 비교 가능) |
| edge | 124 = Silver 69(`normalized_from` 68 + `quarantined_from` 1) + Gold 55(`anchored_on` 1, `selected_from` 10, `aggregated_from` 43, `linked_from` 1) |
| 다대다 | Network 이벤트 1건 ← Bronze 2행(두 획득), flow 1건 ← Silver 2행, cpu evidence ← Silver 41행 |
| run | 6 (`dp_incident_build` 3 task + `dp_reprocess` 3 task), `git_sha`는 fixture용 `0`×40 |

1차 build(대체됨)는 manifest만 있고 행 파일은 생략했다. 대체된 build의 행 sha256은 manifest에 있으나 fixture에서 재계산할 수 없다.

## 8. 이 예시로 각 Track이 시작할 수 있는 것

| Track | 입력으로 쓰는 파일 | 기대 결과로 쓰는 파일 |
|---|---|---|
| A | 00, 01, 13(+ 같은 형식으로 만든 응답) | 10, 11, 12 |
| B | 10, 11, 12 | 20~27 + Silver manifest·edge |
| C | 01, 10, 20~27 | 30~35 + Gold edge, 60(파리티) |
| D | 전체 | 40, 50, 51 + 검증 보고서 |

fixture 재생성 스크립트는 저장소에 넣지 않았다(구현 착수 금지 범위). STEP 0.5에서 fixture 로더와 함께 정식 도구로 만들지 결정한다.
