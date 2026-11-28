# 01. 공통 데이터 계약 — Bronze / Silver / Gold 스키마

> 상태: **STEP 0 제안 (승인 전)**. 계약 버전 `dp-contract 0.1`. 모든 데이터셋 `schema_version`은 `1.0`에서 시작한다.
> 기존 계약 **변경 없음**: Canonical Network Event v1.0([NETWORK_EVENT_SCHEMA.md](../network-observability/NETWORK_EVENT_SCHEMA.md)), Observation Identity([OI_09_SOURCE_IDENTITY.md](../rulepack/OI_09_SOURCE_IDENTITY.md)), RCA envelope v2.0([main.py:308-321](../../aiops/pipeline/main.py#L308-L321)).
> 표의 `N`은 NOT NULL, `Y`는 nullable. 예시는 [examples/db-connection-limit/](examples/db-connection-limit/).

## 1. 공통 규약

| ID | 규약 |
|---|---|
| C-1 Canonical JSON | `json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")` |
| C-2 해시 | `h(v) = sha256(canonical_json(v)).hexdigest()` (소문자 64자). 접두어가 붙은 ID는 `prefix + h(...)[:N]` |
| C-3 시각 | 저장은 UTC. Parquet `timestamp[us, tz=UTC]`. JSON 예시는 `YYYY-MM-DDTHH:MM:SS.ffffffZ`. 원천 원문 시각은 `*_raw` 문자열로 보존. Loki 시각은 `int64 ns`(`*_ts_ns`), Prometheus 시각은 `int64 ms`(`*_ts_ms`)로 원래 정밀도를 유지하고 float로 저장하지 않는다 |
| C-4 시각 비교 | 문자열 비교 금지. `correlation.to_instant()`와 같은 규칙(offset 없는 시각 거부) |
| C-5 Identity | `site, source, service, runtime, target`(=`ObservationIdentity` 앞 5개). 미확인 값은 `"UNKNOWN"`(`identity.py` 직렬화 규칙). **Network Event의 `unknown`(소문자)은 원문 그대로 둔다** — 두 규칙을 섞지 않는다 |
| C-6 Null | 값 없음은 `null`. `unknown/UNKNOWN`은 기존 계약이 정의한 필드에만 쓴다 |
| C-7 JSON 컬럼 | 중첩 객체는 Parquet `string`(canonical JSON)으로 저장한다(DuckDB에서 `::JSON`). 리스트는 Parquet `list<…>` |
| C-8 Envelope 컬럼 | Silver·Gold 모든 행: `_schema_version`(N), `_dataset_version`(N, 그 행을 만든 build id), `_run_id`(N), `_quality_flags`(N, `list<string>`, 어휘는 [04](04_DATA_QUALITY.md) §3). `_` 접두어는 원천 필드명과 충돌하지 않게 하기 위함이다(예: Network의 `schema_version`과 데이터셋의 `_schema_version`) |
| C-9 Silver 추가 Envelope | `_dup_count`(N, 합쳐진 Bronze 행 수), `_first_acquired_at`(N), `_last_acquired_at`(N) |
| C-10 스키마 버전 | `MAJOR.MINOR`, 변경 규칙은 [NETWORK_EVENT_SCHEMA.md §14.2](../network-observability/NETWORK_EVENT_SCHEMA.md)와 동일. **기본 키 도출식 변경은 MAJOR**. 저장 경로에 `v{MAJOR}`를 둔다 |
| C-11 변환 버전 | 행에 넣지 않고 `lineage.run`과 manifest에 `code_version`(semver), `git_sha`(40자), `git_dirty`를 기록한다 |
| C-12 비밀값 | Bronze/Silver는 원문을 보존하므로 비밀·개인정보가 있을 수 있다. 사람이 읽는 Gold 텍스트(`rendered_line`)는 반드시 기존 `mask_secrets()`를 거친다 |

### 1.1 ID 형식

| ID | 형식 | 결정성 |
|---|---|---|
| `acquisition_id` | `acq_{YYYYMMDDTHHMMSSZ}_{8hex}` | 시도마다 고유 |
| `acquisition_key` | `h({plan_id, binding_sha256, query_name, query_text, window_start, window_end})[:32]` — 페이징 파라미터(`limit`, `direction`)는 제외. binding이 바뀌면 다른 키가 되어 사건 모드도 새 binding으로 다시 획득한다 | 같은 논리 요청이면 같음 (재실행·강제 재획득 판정용) |
| `bronze_id` | `{acquisition_id}:{page:04d}:{row:06d}` | 획득 내 위치 |
| `record_key` (Loki) | `h([stream_labels(객체), str(entry_ts_ns), line])` | 내용 동일하면 같음 |
| `record_key` (Prometheus) | `h([query_text_sha256, series_labels(객체), sample_ts_ms, value_raw])` | 내용 동일하면 같음 |
| `record_key` (시나리오 실행 기록) | `h(["scenario_run", line])` — 줄 번호 제외(파일을 매번 통째로 다시 읽어도 같은 실행이면 같음) | 내용 동일하면 같음 |
| `alert_event_id` | `h({"labels": alert_labels, "starts_at": starts_at(C-3 형식)})` | 같은 경보 episode면 같음 |
| `incident_id` | `"inc_" + alert_event_id[:24]` | v1: **사건 1건 = 경보 episode 1건** (다중 경보 묶음은 DEC-09) |
| `silver_build_id` / `gold_build_id` | `sb_…` / `gb_…` + `{YYYYMMDDTHHMMSSZ}_{8hex}` | build마다 고유 |
| `coverage_id` | `"cov_" + h([dataset, plan_id, plan_binding_sha256, window_start, window_end])[:24]`. `plan_binding_sha256` = `h(sorted({그 plan 실행의 획득 계획 항목 binding_sha256} - {null}))` — 과거 획득의 누적이 아니라 **이번 실행에 적용한 scope별 binding 집합** | 같은 범위·같은 binding 집합이면 같음. binding이 바뀌면 새 coverage([03](03_LINEAGE.md) §4) — incident `plan_id`에는 binding이 없으므로 이 항이 필요 |
| `run_id` | `"run_" + h([orchestrator, dag_id, airflow_run_id, task_id, try_number] + ([map_index] if map_index is not None and map_index >= 0 else []))[:20]` | task 시도마다 고유. mapped task는 `map_index`(0 이상)로 구분. unmapped task는 Airflow가 `-1`을 주므로 `null`과 같이 취급해 해시에서 뺀다(기존 식과 같은 값) |
| `evidence_id` | `h([kind, incident_id, …자연키])[:32]` (§4) | 재빌드해도 같은 근거면 같음 → 버전 간 비교 가능 |

### 1.2 시각 필드의 의미

| 필드 | 의미 |
|---|---|
| `event_time` | 사건이 일어난 시각. 출처는 `event_time_source`로 명시 |
| `loki_ts_ns` / `entry_ts_ns` | Loki entry 시각(색인 시각). 출처별 의미는 [00](00_EXISTING_SYSTEM_ANALYSIS.md) §2 |
| `requested_at` / `completed_at` | 데이터 플랫폼이 원천에 질의한 시각 = **수집 시각**. Fluentd/Loki 수신 시각은 원천에 남지 않아 알 수 없다 |
| `window_start` / `window_end` | 질의 창 |
| `anchor_time` | 사건 기준 시각(경보 `startsAt`) |

`event_time_source` 어휘: `loki_entry`(Docker driver 시각) · `body_timestamp`(원문 시각을 C-4로 해석) · `receiver_fallback`(원문 해석 실패, 수신 시각) · `prometheus_sample`.

## 2. Bronze — 획득 원천과 메타데이터 (append-only, 불변)

Bronze는 **원천 API가 반환한 것**을 해석 없이 보존한다. 같은 데이터가 여러 획득에 중복될 수 있다(창 겹침·재시도·강제 재획득). 중복 제거는 Silver의 책임이다.

### 2.1 `bronze.acquisition` — 질의 1건(페이지 합산)당 1행

| 컬럼 | 타입 | Null | 설명 |
|---|---|---|---|
| `acquisition_id` | string | N | PK |
| `acquisition_key` | string | N | §1.1 |
| `plan_id` | string | N | `incident:{incident_id}` 또는 `continuous:{binding_sha256[:12]}:{stream_class}` |
| `incident_id` | string | Y | 사건 단위 획득일 때 |
| `scope_role` | string | N | `primary`(경보 identity) · `related`(명시 지정한 관련 identity, DEC-06) · `global`(identity와 무관한 job 스트림) |
| `source_system` | string | N | `loki` · `prometheus` · `scenario_run_log`(§2.5) |
| `api` | string | Y | `loki.query_range` · `prometheus.query_range` · `file.read`. `scope_unavailable`이면 null |
| `stream_class` | string | N | §2.4 |
| `query_name` | string | N | plan 내 이름 (`logs`, `network_dst`, `cpu_usage` …) |
| `query_text` | string | Y | 실행한 LogQL/PromQL 원문. 미실행이면 null |
| `query_params` | string(JSON) | N | `query`를 제외한 요청 파라미터(start/end/limit/direction/step) |
| `window_start` / `window_end` | timestamp | N | 요청 창(패딩 포함, [02](02_STORAGE_DESIGN.md) §5) |
| `scope_identity` | string(JSON) | N | binding의 `ObservationIdentity.to_dict()` (global이면 모두 `UNKNOWN`) |
| `scope_selector` | string(JSON) | N | 사용한 binding selector(`logs`/`metrics`/`network` 맵). 없으면 `{}` |
| `binding_sha256` | string | Y | `h(binding 원본 행)` — 어떤 binding 설정으로 질의했는지 |
| `requested_at` / `completed_at` | timestamp | N / Y | 수집 시각 |
| `page_count` | int32 | N | 받은 페이지 수 |
| `row_count` | int64 | N | 이 획득이 남긴 Bronze 행 수 |
| `response_bytes` | int64 | N | 원문 응답 바이트 합 |
| `http_status_last` | int32 | Y | 마지막 HTTP 상태. timeout이면 null |
| `status` | string | N | 획득 상태 ([04](04_DATA_QUALITY.md) §1) |
| `status_reason` | string | Y | 상태 사유 |
| `limit_hit` | bool | N | 어떤 페이지라도 limit에 닿았는지 |
| `series_preflight` | string | N | `present` · `absent` · `not_run` |
| `warnings` | list<string> | N | API warnings/infos 원문 |
| `raw_pages` | list<string> | N | 원문 응답 object key |
| `raw_sha256` | list<string> | N | **압축 전** 응답 본문 sha256 (gzip은 비결정적이므로) |
| `window_closed` | bool | N | `requested_at >= window_end + lateness_margin` |
| `lateness_margin_s` | int32 | N | 적용한 지연 허용치 |
| `run_id` | string | N | |
| `_schema_version` | string | N | `1.0` |

### 2.2 `bronze.loki_entry`

| 컬럼 | 타입 | Null | 설명 |
|---|---|---|---|
| `bronze_id` | string | N | PK |
| `acquisition_id` | string | N | FK |
| `stream_class` | string | N | 획득 plan이 정한 분류(본문 해석으로 정하지 않음) |
| `stream_labels` | string(JSON) | N | 반환된 stream label 전체 (C-1) |
| `stream_labels_sha256` | string | N | |
| `entry_ts_ns` | int64 | N | Loki entry 시각 |
| `line` | string | N | **원문 그대로** |
| `line_sha256` | string | N | |
| `record_key` | string | N | §1.1 |
| `_schema_version` | string | N | `1.0` |

### 2.3 `bronze.prometheus_sample`

| 컬럼 | 타입 | Null | 설명 |
|---|---|---|---|
| `bronze_id` | string | N | PK |
| `acquisition_id` | string | N | FK |
| `query_name` | string | N | |
| `query_text_sha256` | string | N | |
| `series_labels` | string(JSON) | N | 반환 series label |
| `series_labels_sha256` | string | N | |
| `sample_ts_ms` | int64 | N | `int(Decimal(str(t)) * 1000)` (Prometheus float 초 → ms, 정밀도 손실 없이) |
| `value_raw` | string | N | 반환 문자열 그대로(`"NaN"`, `"+Inf"` 포함) |
| `record_key` | string | N | §1.1 |
| `_schema_version` | string | N | `1.0` |

v1 메트릭 plan은 **실시간 Pipeline과 같은 PromQL·step**(`query_range`, 15s)을 실행한다(파리티). raw sample 수집은 DEC-11.

### 2.4 `stream_class` 어휘와 획득 대상

| 값 | selector 출처 | scope_role |
|---|---|---|
| `app_log` | binding `logs` (runtime=container) | primary/related |
| `db_log` | binding `logs` (service=db, runtime=host) | primary/related |
| `network_event` | `{log_type="network", src_service\|dst_service=…} \| json \| observer=… and observer_instance=…` (collector와 동일) | primary/related |
| `metric` | binding `metrics` + collector 쿼리 템플릿 | primary/related |
| `rca_result` | `{job="aiops-llm"}` (+ identity label exact) | global |
| `rca_error` | `{job="aiops-llm-error"}` | global |
| `fluentd_internal` | `{log_type="fluentd_internal"} \|= "failed to write post"` | global |
| `fluentd_error` | `{log_type="fluentd_error"}` | global |
| `scenario_run` | 질의 없음. `DP_SCENARIO_RUN_LOG` 파일(`scenarios/v2` `runs.jsonl`)을 통째로 읽음 (§2.5) | global |
| `remediation_event` | `{job="aiops-remediation", alert=…}` · `{job="aiops-timeline", alert=…, event=~"remediation_decision_started\|manual_approval_executed\|auto_remediation_completed\|recovery_approval_required"}`. 창 = `anchor−5m−pad ~ anchor+80m+pad`를 15분 이하 chunk로 나눔(DEC-19, [09](09_REMEDIATION_LINK.md) §3) | global |

**금지:** `{job="network-experiment"}`, Heldout 경로, binding이 없는 identity에 대한 넓은 selector([00](00_EXISTING_SYSTEM_ANALYSIS.md) §9). binding이 없으면 `status=scope_unavailable` 행만 남기고 질의하지 않는다.

### 2.5 `bronze.scenario_run_entry` — 시나리오 실행 기록 한 줄당 1행

`scenarios/v2/run.py`가 실행마다 남기는 `runs.jsonl`(scenario_id, variant_id, seed, started_at, ended_at, status)을 사건 획득 때 **통째로** 읽는다. 파일 전체가 raw page 1개(`raw_sha256` = 파일 바이트 sha256), 빈 줄이 아닌 줄마다 Bronze 1행이다. 줄 분리는 `scenarios/v2/fixtures.py`와 같다(universal newline, 빈 줄 건너뜀). 해석은 Silver가 한다.

| 컬럼 | 타입 | Null | 설명 |
|---|---|---|---|
| `bronze_id` | string | N | PK |
| `acquisition_id` | string | N | FK |
| `line_no` | int64 | N | 획득 시점 파일의 줄 번호(1부터). 파일이 다시 쓰이면 바뀔 수 있어 키에 넣지 않음 |
| `line` | string | N | **원문 그대로**(줄 끝 문자 제외) |
| `line_sha256` | string | N | |
| `record_key` | string | N | §1.1 |
| `_schema_version` | string | N | `1.0` |

획득 상태: 경로 미설정 `not_attempted`(`run_log_unconfigured`), 파일 없음 `failed`(`file_not_found`), 읽기·UTF-8 해석 실패 `failed`(`read_error`), 0줄 `empty_verified`, 그 외 `ok`. 정답 레이블(`threat_level`·`expected_action`·`expected_action_ideal`·`incident_class`)은 이 파일에 없고([fixtures.py](../../scenarios/v2/fixtures.py) `ANSWER_LABEL_KEYS`), 데이터 플랫폼은 `scenarios/v2/registry.py`를 읽지 않는다.

## 3. Silver — 정제·정규화 (build 단위 불변, coverage 단위 최신본)

공통: §1 C-8/C-9 Envelope + 아래 컬럼. 품질 문제가 있는 행도 **버리지 않고** `_quality_flags`로 표시한다. 해석 불가 행만 `silver.quarantine`으로 간다(조용한 삭제 금지, [04](04_DATA_QUALITY.md) DQ-S01).

### 3.1 `silver.app_log` (Docker 앱 로그)

| 컬럼 | 타입 | Null | 설명 |
|---|---|---|---|
| `log_id` | string | N | PK = Bronze `record_key` |
| `event_time` | timestamp | N | v1은 Loki entry(Docker driver 시각) |
| `event_time_source` | string | N | `loki_entry` |
| `loki_ts_ns` | int64 | N | |
| `site`,`source`,`service`,`runtime`,`target` | string | N | stream label에서. 레포 기본 프로파일은 `site/source/target`=`UNKNOWN` |
| `stream_labels` | string(JSON) | N | Loki stream label 원문 (Gold `render_log_line` 파리티에 필요) |
| `container_name` | string | Y | label `container_name` |
| `log_stream` | string | Y | `stdout`·`stderr` (릴리스: label `log_stream`, 레포 기본: label `source`) |
| `label_profile` | string | N | `release_v1`(label `log_stream` 있음) · `legacy`(없음) |
| `log_format` | string | N | `json`·`text`·`json_invalid`·`absent`(label 없음) |
| `severity` | string | N | `TRACE·DEBUG·INFO·WARN·ERROR·FATAL·UNKNOWN` (§3.9) |
| `severity_raw` | string | Y | `level` 원문 |
| `is_priority` | bool | N | 기존 `log_line.is_priority()` 결과 |
| `message` | string | Y | |
| `http_status` | int32 | Y | `status` |
| `request_id` | string | Y | |
| `exception_class` | string | Y | |
| `body` | string(JSON) | N | Loki line 객체 전체 |
| `docker_meta` | string(JSON) | Y | `docker`(또는 `_docker`) 객체 |
| `truncated_original_bytes` | int64 | Y | `log_truncated.original_bytes` |
| `parse_error` | string | Y | `log_parse_error` |

### 3.2 `silver.db_log` (PostgreSQL 17 jsonlog)

| 컬럼 | 타입 | Null | 설명 |
|---|---|---|---|
| `db_log_id` | string | N | PK. `session_id`·`line_num`이 있으면 `h(["pg", site, source, target, session_id, line_num, pg_timestamp_raw])`, 없으면 Bronze `record_key` |
| `event_time` | timestamp | N | `pg_timestamp_raw`를 Fluentd와 같은 규칙(UTC/GMT/KST/숫자 offset)으로 해석 |
| `event_time_source` | string | N | `body_timestamp` · `receiver_fallback`(해석 실패 → Loki entry) |
| `loki_ts_ns` | int64 | N | |
| `site`,`source`,`service`,`runtime`,`target` | string | N | |
| `stream_labels` | string(JSON) | N | Loki stream label 원문 |
| `label_profile` | string | N | `release_v1`(label `site` 있음) · `legacy` |
| `log_format` | string | N | `json` · `text`(Fluent Bit 파싱 실패 `{"log":…}`) |
| `severity` | string | N | §3.9 |
| `severity_raw` | string | Y | `error_severity` |
| `is_priority` | bool | N | `log_line.is_priority()` |
| `pg_timestamp_raw` | string | Y | `timestamp` |
| `state_code` | string | Y | SQLSTATE |
| `message`,`detail`,`hint`,`query` | string | Y | |
| `user_name` | string | Y | 원문 `user` |
| `dbname`,`application_name`,`backend_type` | string | Y | |
| `pid` | int32 | Y | |
| `session_id` | string | Y | |
| `line_num` | int64 | Y | |
| `remote_host` | string | Y | |
| `pg_log_file` | string | Y | Fluent Bit Path_Key |
| `body` | string(JSON) | N | line 객체 전체 |
| `truncated_original_bytes` | int64 | Y | |
| `time_parse_error` | string | Y | `log_time_parse_error` |

### 3.3 `silver.network_event`

Canonical Network Event v1.x 필드를 **이름·타입 그대로** 컬럼으로 둔다. 새 필드를 만들거나 `*_target`을 추측하지 않는다.

| 컬럼 | 타입 | Null | 설명 |
|---|---|---|---|
| `network_event_id` | string | N | PK. `connection_id`가 있으면 `h(["net", observer, observer_instance, event_type, connection_id])`, 없으면 `h(["net", observer, observer_instance, event_type, timestamp, protocol, src_ip, src_port, dst_ip, dst_port])` — [collector/network.py:155-178](../../aiops/pipeline/collector/network.py#L155-L178)와 같은 의미 |
| `event_time` | timestamp | N | `to_instant(timestamp)` |
| `loki_ts_ns` | int64 | N | |
| `schema_version` … `observer_meta` | (원 스키마) | (원 스키마) | NETWORK_EVENT_SCHEMA §5의 27개 필드: `schema_version, timestamp, event_type, observer, src_service, src_container, src_runtime, src_ip, src_port, dst_service, dst_container, dst_runtime, dst_ip, dst_port, protocol, network, interface, app_protocol, connection_state, duration_ms, bytes_sent, bytes_received, direction, connection_id, request_id, observer_instance, observer_meta`. `observer_meta`는 string(JSON) |
| `extra_fields` | string(JSON) | N | 원 스키마에 없는 필드(전방 호환). 없으면 `{}` |

MAJOR가 `1`이 아니거나 필수 필드가 없으면 quarantine(`unsupported_schema_version`·`missing_required_field`). 모르는 enum 값은 그대로 보존한다(§14.3).

### 3.4 `silver.metric_point`

| 컬럼 | 타입 | Null | 설명 |
|---|---|---|---|
| `metric_point_id` | string | N | PK = `h([query_text_sha256, series_labels(객체), sample_ts_ms])` — **값 제외**. 같은 점이 다른 값으로 다시 오면 마지막 `window_closed` 획득 값을 쓰고 `value_revised` 표시 |
| `sample_time` | timestamp | N | |
| `sample_ts_ms` | int64 | N | |
| `query_name` | string | N | |
| `query_text_sha256` | string | N | |
| `metric_name` | string | N | `series_labels.__name__`, 없으면(`rate()` 등) `query_name` |
| `series_labels` | string(JSON) | N | |
| `value` | double | N | `NaN/±Inf`도 보존하고 `nonfinite_value` 표시 |
| `site`,`source`,`service`,`runtime`,`target` | string | N | 획득 scope identity(반환 label 검증 통과분) |

### 3.5 `silver.alert_event`

| 컬럼 | 타입 | Null | 설명 |
|---|---|---|---|
| `alert_event_id` | string | N | PK (§1.1) |
| `alertname` | string | N | |
| `starts_at` | timestamp | N | |
| `starts_at_raw` | string | N | AM 원문 |
| `fingerprint` | string | Y | AM fingerprint |
| `severity`,`category`,`rulepack_target` | string | Y | labels |
| `alert_labels`,`alert_annotations` | string(JSON) | N | |
| `site`,`source`,`service`,`runtime`,`target` | string | N | envelope `identity` |
| `identity_status` | string | N | envelope 값 그대로 |
| `origin` | string | N | v1: `rca_envelope`만 (Prometheus `ALERTS` 추가는 DEC-10) |

### 3.6 `silver.rca_result`

> `_schema_version` **1.1**: `remediation_id` 추가(DEC-19, MINOR — 저장 경로 `v1` 유지). 1.0 build에는 이 컬럼이 없고 null로 읽는다.

| 컬럼 | 타입 | Null | 설명 |
|---|---|---|---|
| `rca_id` | string | N | PK = Bronze `record_key` |
| `rca_time` | timestamp | N | envelope `timestamp` |
| `loki_ts_ns` | int64 | N | |
| `envelope_schema_version` | string | Y | `"2.0"`. 버전 없는 과거 envelope은 null + `legacy_unversioned` 표시 |
| `alert_event_id` | string | Y | FK |
| `alert_name`,`alert_fingerprint` | string | N / Y | |
| `site`,`source`,`service`,`runtime`,`target` | string | N | |
| `identity_status` | string | Y | |
| `evidence_sources` | string(JSON) | Y | 원문 그대로 |
| `root_cause`,`action_type` | string | N | `LLMAnalysisResult`로 재검증한 값 |
| `action_description` | string | Y | 원문 `result`에 있을 때만(#29 이전 LLM 출력). 현재 출력에는 없어 null |
| `threat_level` | string | N | `LLMAnalysisResult`로 재검증한 값 |
| `incident_class` | string | Y | LLM이 낸 사건 분류(**예측값**, 평가 정답 아님). 키가 없는 #29 이전 envelope(`llm_output_legacy` 표시)과 Pipeline 분석 실패(`analysis_status=invalid`)는 null. 나머지 필드는 같은 모델로 검증하고, 그 외 검증 실패는 `invalid_value` quarantine |
| `analysis_status` | string | Y | Pipeline 파서 메타 `valid`·`invalid` 원문. 없으면(#29 이전) null |
| `action_targets`,`evidence` | list<string> | N | |
| `confidence` | double | N | |
| `fallback_reason` | string | Y | `source_unresolved`([main.py:300](../../aiops/pipeline/main.py#L300)) · `llm_parse_failure`([main.py:888](../../aiops/pipeline/main.py#L888)) — root_cause 문자열 **완전 일치**로만 판정 |
| `handoff_status` | string | Y | |
| `remediation_dispatched`,`notification_dispatched` | bool | Y | |
| `remediation_id` | string | Y | envelope `remediation_id` 원문(handoff `approval_pending`·`auto_*`). 없거나 문자열이 아니면 null |

### 3.7 `silver.transport_issue`

| 컬럼 | 타입 | Null | 설명 |
|---|---|---|---|
| `transport_issue_id` | string | N | PK = `record_key` |
| `event_time` | timestamp | N | Loki entry |
| `loki_ts_ns` | int64 | N | |
| `issue_kind` | string | N | `loki_write_failed`(`failed to write post`) · `fluentd_error_route` · `other` |
| `stream_labels` | string(JSON) | N | |
| `message_excerpt` | string | N | 앞 300자, `mask_secrets` 적용 |

### 3.8 `silver.quarantine`

| 컬럼 | 타입 | Null | 설명 |
|---|---|---|---|
| `quarantine_id` | string | N | PK = `h([record_key, target_dataset, reason_code])` |
| `first_bronze_id` | string | N | 전체 부모는 lineage |
| `record_key` | string | N | |
| `target_dataset` | string | N | 들어가려던 Silver 데이터셋 |
| `reason_code` | string | N | `invalid_json`·`not_object`·`unsupported_schema_version`·`missing_required_field`·`invalid_timestamp`·`invalid_value` |
| `detail` | string | Y | 200자 이내 |
| `acquired_at` | timestamp | N | |
| `_schema_version`,`_dataset_version`,`_run_id` | string | N | (`_quality_flags` 없음) |

### 3.9 정규화 규칙

- **severity**: 대문자화 후 `DEBUG1-5→DEBUG`, `INFO·NOTICE·LOG→INFO`, `WARNING→WARN`, `CRITICAL·SEVERE·PANIC→FATAL`, 그 외 인식 불가→`UNKNOWN`. `is_priority`는 기존 함수를 그대로 쓴다(정규화값으로 다시 계산하지 않음).
- **label profile**: 앱 로그는 label `log_stream` 존재 → `release_v1`. 없으면 `legacy`이며 label `source`는 출력 채널이므로 `log_stream`으로 옮기고 identity `source=UNKNOWN` + `identity_unverified`.
- **dedup**: Silver PK가 같은 Bronze 행들은 1행으로 합치고 `_dup_count`·`_first/_last_acquired_at`을 기록, 모든 부모를 lineage edge로 남긴다.
- **창**: Silver는 획득 창(패딩 포함) 전체를 담는다. 사건 창 필터는 Gold가 적용한다.

### 3.10 `silver.scenario_run`

| 컬럼 | 타입 | Null | 설명 |
|---|---|---|---|
| `scenario_run_id` | string | N | PK = Bronze `record_key` |
| `scenario_id` | string | N | `scenarios/v2/registry.py`의 id |
| `variant_id` | string | Y | |
| `seed` | int64 | Y | |
| `started_at`,`ended_at` | timestamp | N | C-4로 해석(offset 없는 시각은 quarantine `invalid_timestamp`) |
| `started_at_raw`,`ended_at_raw` | string | N | 원문 |
| `status` | string | N | 원문(`run.py`: `ok` · `error`). 짝짓기는 `ok`만 쓴다 |

필수 키(`scenario_id`·`started_at`·`ended_at`·`status`)가 없으면 `missing_required_field`, 타입이 다르면 `invalid_value`로 quarantine한다. 그 밖의 키는 읽지 않는다(Bronze 원문에는 남음).

### 3.11 `silver.remediation_event`

Remediation(`aiops-remediation`)·timeline(`aiops-timeline`) Loki 이벤트 1건당 1행. 원문을 보존하고 Gold 연결은 하지 않는다([09](09_REMEDIATION_LINK.md) §4). coverage 창은 remediation 창 전체다(chunk 획득을 모음).

| 컬럼 | 타입 | Null | 설명 |
|---|---|---|---|
| `remediation_event_id` | string | N | PK = Bronze `record_key` |
| `event_time` | timestamp | N | 본문 `timestamp`(C-4). 해석 실패 시 Loki entry 시각 + `event_time_fallback` |
| `event_time_source` | string | N | `body_timestamp` · `receiver_fallback` |
| `loki_ts_ns` | int64 | N | |
| `stream_job` | string | N | stream label `job` 원문: `aiops-remediation` · `aiops-timeline` |
| `event` | string | N | 본문 `event`(없으면 quarantine `missing_required_field`) |
| `status` | string | Y | 본문 `status` |
| `alertname` | string | Y | 본문 `alert` |
| `remediation_id` | string | Y | 본문 값. null이면 Gold에서 연결하지 않는다(`auto_remediation` 등). `policy_decision`은 값이 있어도(#81) v1 Gold에 연결하지 않는다 |
| `action_type` | string | Y | |
| `targets` | list<string> | N | 본문 `targets` 또는 `[target]`, 없으면 `[]` |
| `record_state` | string | Y | 레코드 이벤트(`aiops-remediation`, 본문에 `state`)의 `state` |
| `alert_active_at` | timestamp | Y | 레코드 이벤트의 `alert_active_at`(= 경보 `startsAt`) C-4 해석값. 해석 불가면 null |
| `alert_active_at_raw` | string | Y | 원문 |
| `approved_by` | string | Y | `manual_approval_executed`의 Slack user id |
| `result` | string | Y | 실행 결과 요약(`auto_remediation`·`manual_approval_executed`) |
| `verified` | bool | Y | |
| `reason` | string | Y | `*_blocked`·`db_backup_failed`·`duplicate_execution_suppressed` 사유 |
| `policy` | string(JSON) | Y | `policy_decision`의 `decision.as_dict()` 필드 묶음(`timestamp`·`event`·`alert`·`source`·`status` 제외) |
| `timings` | string(JSON) | Y | 레코드 이벤트의 시각 지표(`approval_requested_at`…`service_recovery_sec`, `alert_active_at` 제외) |
| `event_body` | string(JSON) | N | 본문 전체(C-1). C-12: Silver는 원문 보존 |

JSON 아님·객체 아님은 기존 사유로 quarantine한다. 알 수 없는 `event` 이름도 행으로 남긴다.

## 4. Gold — 사건별 RCA Evidence Mart (사건 단위 build, 버전 보존)

모든 Gold 행: `incident_id`, `gold_build_id` + C-8 Envelope(`_dataset_version = gold_build_id`).

### 4.1 `gold.incident` — 사건 × build 당 1행

| 컬럼 | 타입 | Null | 설명 |
|---|---|---|---|
| `incident_id` | string | N | PK(+`gold_build_id`) |
| `gold_build_id` | string | N | |
| `alert_event_id` | string | N | |
| `alertname` | string | N | |
| `severity`,`category`,`rulepack_target` | string | Y | |
| `site`,`source`,`service`,`runtime`,`target` | string | N | 경보 identity (primary) |
| `identity_status` | string | N | `resolved`가 아니면 모든 primary 채널 `unavailable` |
| `anchor_time` | timestamp | N | `starts_at` |
| `window_start`,`window_end` | timestamp | N | `anchor ± 5m` (양끝 포함, 실시간 파리티) |
| `window_policy` | string | N | `symmetric_5m` |
| `scope_policy` | string | N | `alert_identity_only` · `alert_identity_plus_related` (DEC-06) |
| `overall_status` | string | N | `complete`·`partial`·`insufficient` ([04](04_DATA_QUALITY.md) §5) |
| `evidence_count` | int32 | N | evidence 테이블 행 합 |
| `rca_count` | int32 | N | 연결된 RCA 수 |
| `transport_loss_suspected` | bool | N | 창 안 `transport_issue` 존재 |
| `transport_check_status` | string | N | `fluentd_internal` 획득 상태 |
| `input_versions` | string(JSON) | N | `{silver 데이터셋: [silver_build_id…]}` |
| `built_at` | timestamp | N | |

### 4.2 `gold.incident_channel` — 사건 × 채널 × scope

| 컬럼 | 타입 | Null | 설명 |
|---|---|---|---|
| `incident_id`,`gold_build_id` | string | N | |
| `channel` | string | N | `log` · `metric` · `network` |
| `scope_role` | string | N | `primary` · `related` |
| `site`,`source`,`service`,`runtime`,`target` | string | N | 이 채널의 scope identity |
| `status` | string | N | 채널 상태 ([04](04_DATA_QUALITY.md) §4) |
| `status_reason` | string | Y | |
| `acquisition_ids` | list<string> | N | |
| `acquisition_statuses` | list<string> | N | 같은 순서 |
| `rows_in_window` | int64 | N | 사건 창 안 Silver 행 |
| `rows_matched` | int64 | N | identity/endpoint 검증 통과 |
| `rows_selected` | int64 | N | evidence로 집계·선택된 행 |
| `skipped` | int64 | N | 창 안이지만 scope 검증에서 제외된 행 (기존 `skipped` 의미) |
| `skipped_reasons` | string(JSON) | N | `{reason: count}` — `observer_mismatch`(body observer/observer_instance ≠ binding) · `runtime_mismatch` · `target_unresolvable`(해당 endpoint에 target 필드 자체가 없음: host는 `*_target`, container는 `*_container`) · `target_mismatch`(있으나 다름) |
| `quarantined` | int64 | N | 이 채널 획득에서 quarantine된 레코드 수 |
| `truncated` | bool | N | 기존 `truncated` 의미(limit 도달) |
| `window_closed` | bool | N | 모든 획득이 닫힌 창이었는지 |

### 4.3 `gold.evidence_log`

| 컬럼 | 타입 | Null | 설명 |
|---|---|---|---|
| `evidence_id` | string | N | `h(["log", incident_id, log_dataset, silver_key])[:32]` |
| `incident_id`,`gold_build_id` | string | N | |
| `scope_role` | string | N | |
| `log_dataset` | string | N | `app_log` · `db_log` |
| `silver_key` | string | N | `log_id` 또는 `db_log_id` |
| `event_time` | timestamp | N | |
| `severity` | string | N | |
| `is_priority` | bool | N | |
| `rank` | int32 | Y | 파리티 정렬 순위(1부터). 미선택은 null |
| `selected_for_prompt` | bool | N | scope_role별 priority ≤30 + 기타 ≤20 ([builder.py:125-132](../../aiops/pipeline/prompt/builder.py#L125-L132)) |
| `rendered_line` | string | N | `render_log_line()` 결과(마스킹·200자) |

창 안의 scope 검증 통과 로그는 **모두** 행으로 남기고, 실시간 프롬프트 선별 결과는 `selected_for_prompt`로 표시한다.

### 4.4 `gold.evidence_metric` — 쿼리 × series

| 컬럼 | 타입 | Null | 설명 |
|---|---|---|---|
| `evidence_id` | string | N | `h(["metric", incident_id, query_name, series_labels_sha256])[:32]` |
| `incident_id`,`gold_build_id`,`scope_role` | string | N | |
| `query_name`,`metric_name` | string | N | |
| `series_labels` | string(JSON) | N | |
| `samples` | int32 | N | 창 안 유한값 수 |
| `latest`,`peak`,`minimum`,`mean` | double | Y | 유한값 기준. 없으면 null |
| `first_time`,`last_time` | timestamp | Y | |
| `nonfinite_count` | int32 | N | |
| `rank` | int32 | Y | 쿼리 내 series 순서 |
| `selected_for_prompt` | bool | N | 쿼리당 앞 5개 series |
| `rendered_line` | string | N | `{metric_name}: latest=…, peak=…, samples=…` (builder 형식) |

### 4.5 `gold.evidence_network_flow`

| 컬럼 | 타입 | Null | 설명 |
|---|---|---|---|
| `evidence_id` | string | N | `h(["flow", incident_id, scope_role, scope_identity(객체), src_service, dst_service, dst_ip, dst_port, protocol])[:32]` — 같은 `scope_role`의 related scope가 여럿이어도 구분 |
| `incident_id`,`gold_build_id`,`scope_role` | string | N | |
| `scope_identity` | string(JSON) | N | 그 flow를 관측한 scope의 `ObservationIdentity` 전체(`site,source,service,runtime,target,job,instance,observer`). Bronze `scope_identity`와 같은 값 → observer만 다른 binding도 구분 |
| `src_service`,`dst_service` | string | N | |
| `dst_ip` | string | Y | |
| `dst_port` | int32 | Y | |
| `protocol` | string | N | |
| `conns` | int32 | N | 최종 `connection` 이벤트 수 |
| `states`,`app_protocols` | string(JSON) | N | `{값: count}` |
| `bytes_sent_sum`,`bytes_received_sum` | int64 | Y | **최종 이벤트만** 합산(`connection_threshold` 제외) |
| `duration_ms_avg` | double | Y | |
| `duration_ms_max` | int64 | Y | |
| `early_count` | int32 | N | `connection_threshold` 수 |
| `early_first_time` | timestamp | Y | |
| `early_peak_bytes` | int64 | Y | |
| `allowlist_decision` | string | N | `ok`·`violation`·`not_applicable`·`not_evaluated` |
| `allowlist_reason` | string | Y | `PolicyEvaluator` reason |
| `events_matched` | int32 | N | 이 flow에 들어간 Silver 이벤트 수 |
| `rank` | int32 | Y | `network_section._aggregate` 정렬 순서 |
| `selected_for_prompt` | bool | N | 앞 8개 (문자 예산 1600자는 재현하지 않음) |
| `rendered_line` | string | N | `_flow_line()` 형식 |

### 4.6 `gold.rca_link`

| 컬럼 | 타입 | Null | 설명 |
|---|---|---|---|
| `incident_id`,`gold_build_id` | string | N | |
| `rca_id` | string | N | |
| `link_type` | string | N | `post_hoc_same_alert`(실시간 RCA는 Gold를 사용하지 않았음) · `consumed_gold`(DEC-07 승인 시) |
| `rca_time` | timestamp | N | |
| `fallback_reason` | string | Y | |

### 4.7 `gold.scenario_link` — 사건 × build 당 정확히 1행

사건이 어느 시나리오 실행에서 나왔는지 평가용으로 연결한다. 짝짓기 규칙은 [scenarios/v2/fixtures.py](../../scenarios/v2/fixtures.py) `pair_context`와 같다: `status=ok`이고 `started_at ≤ pair_time ≤ ended_at + 300s`(양끝 포함)인 실행이 **정확히 1건**이면 `paired`. 없거나 여럿이어도 행을 남긴다(조용히 버리지 않음). 기준 시각만 다르다: `pair_context`는 Pipeline 수신 시각, Gold는 수신 시각이 없어 경보 `startsAt`(`anchor_time`)을 쓴다(차이 ≈ Alertmanager `group_wait` 10s).

| 컬럼 | 타입 | Null | 설명 |
|---|---|---|---|
| `incident_id`,`gold_build_id` | string | N | |
| `link_status` | string | N | `paired` · `no_run` · `ambiguous_run` · `run_log_unavailable`(실행 기록 획득이 `ok`/`empty_verified`가 아님 — "실행 없음"과 구분) |
| `pair_time` | timestamp | N | 짝짓기 기준 시각 = `gold.incident.anchor_time` |
| `pair_time_source` | string | N | `alert_starts_at` |
| `grace_s` | int32 | N | `300` |
| `candidate_run_ids` | list<string> | N | 규칙에 걸린 `silver.scenario_run` PK 전부(`started_at` 순). paired 1, ambiguous ≥2, 그 외 0 |
| `scenario_run_id`,`scenario_id`,`variant_id` | string | Y | `paired`일 때만 |
| `seed` | int64 | Y | `paired`일 때만 |
| `run_started_at`,`run_ended_at` | timestamp | Y | `paired`일 때만 |
| `run_log_status` | string | N | `scenario_run` 획득의 최선 상태([04](04_DATA_QUALITY.md) §1). 획득이 없으면 `not_attempted` |

- 실행 기록 줄이 quarantine되면 `run_log_quarantined` 플래그를 붙인다(그 줄이 짝이었을 수 있으므로 `no_run`을 그대로 믿지 않는다).
- **정답 레이블은 넣지 않는다**(DQ-G08). 평가는 `scenario_id`로 `scenarios/v2/registry.py`에서 `threat_level`·`expected_action`·`expected_action_ideal`·`incident_class`를 조회한다.
- **LLM 입력 금지(제안)**: `scenario_id`는 사실상 정답 힌트다. RCA가 Gold를 입력으로 쓰게 되더라도(DEC-07) 이 테이블은 프롬프트에 넣지 않기를 LLM 담당에게 제안한다. 데이터 플랫폼은 프롬프트 코드를 바꾸지 않는다.
- 실행 기록은 실행이 **끝날 때** 쓰인다. 사건 획득 시점에 아직 끝나지 않은 실행은 `no_run`으로 남으므로, 평가 전에 실행 기록을 다시 획득해 Gold를 재빌드한다([aiops/dataplatform/README.md](../../aiops/dataplatform/README.md)).

### 4.8 `gold.remediation_link` — 사건 × build × RCA 당 1행

`gold.rca_link`의 RCA마다 1행(DQ-G10). RCA envelope의 `remediation_id`로 **정확히** 잇는 것만 연결하고, 경보 이름·시각 근접 추정 연결은 만들지 않는다(DEC-19). 판정 규칙은 [09](09_REMEDIATION_LINK.md) §5.

| 컬럼 | 타입 | Null | 설명 |
|---|---|---|---|
| `incident_id`,`gold_build_id` | string | N | |
| `rca_id` | string | N | `gold.rca_link` 행과 1:1 |
| `rca_time` | timestamp | N | |
| `handoff_status` | string | Y | RCA envelope 원문(왜 `remediation_id`가 없는지 설명) |
| `remediation_id` | string | Y | `silver.rca_result.remediation_id` |
| `link_basis` | string | Y | v1 어휘 `rca_remediation_id` 하나. `linked`가 아니면 null |
| `link_status` | string | N | `linked` · `no_remediation_id` · `events_not_found` · `cross_check_failed`(`alertname` 또는 `alert_active_at ≠ anchor_time`) |
| `policy_decision_link` | string | N | v1 고정값 `unlinked_no_key` — `policy_decision`은 연결하지 않음. #81로 생긴 키를 쓰는 연결은 DEC-19 개정 |
| `action_type`,`final_state` | string | Y | `linked`일 때만. 마지막 레코드 이벤트의 값 |
| `targets` | list<string> | N | `linked`가 아니면 `[]` |
| `approval_requested_at`,`approved_at`,`action_started_at`,`action_verified_at`,`recovery_due_at`,`recovery_verified_at`,`service_recovered_at` | timestamp | Y | 마지막 레코드 이벤트의 `timings` |
| `approved_by` | string | Y | `manual_approval_executed`(같은 `remediation_id`) |
| `execution_results` | string(JSON) | N | `[{target,status,result,verified}]`, 없으면 `[]` |
| `block_events` | string(JSON) | N | `[{event,reason,event_time}]`(`evidence_gate_blocked`·`capture_blocked`·`db_backup_failed`·`duplicate_execution_suppressed`), 없으면 `[]` |
| `mttr_sec`,`approval_latency_sec` | double | Y | `timings` 값 그대로 |
| `remediation_status` | string | N | `complete` · `partial` · `unlinked` |
| `partial_reasons` | list<string> | N | `window_open` · `acquisition_incomplete` · `beyond_window` |
| `remediation_window_start`,`remediation_window_end` | timestamp | N | remediation 창([09](09_REMEDIATION_LINK.md) §3.2) |

- `linked`가 아니면 상세 컬럼은 null·`[]`이다(Silver 행을 끌어오지 않음, DQ-G11).
- `gold.incident`·`overall_status`는 이 테이블로 바뀌지 않는다.

## 5. 기존 계약 보존 확인

| 기존 계약 | 이 문서의 처리 |
|---|---|
| Canonical Network Event v1.0 | Silver에 필드명·타입·null 정책 그대로. `*_target` 추가·추측 없음. label 6개 그대로 조회 |
| Observation Identity | 다섯 필드·`UNKNOWN`·`identity_status`를 재정의하지 않고 `identity.py`를 그대로 사용. binding 없는 질의 금지 |
| RCA envelope v2.0 | Loki `aiops-llm` 원문을 Bronze에 그대로, Silver는 읽기만. Pipeline 쓰기 경로 변경 없음 |
| LLMAnalysisResult | Silver 검증에 그대로 사용. action_type 어휘 변경 없음 |
| scenarios/v2 실행 기록·레지스트리 | `runs.jsonl`은 읽기만(Bronze 원문 보존). `run.py`·`fixtures.py`·`registry.py` 변경 없음, 정답 레이블은 Gold에 없음 |
| Remediation 감사·timeline 이벤트 | Loki `aiops-remediation`·`aiops-timeline`을 읽기만(Bronze 원문 보존). Remediation 코드·SQLite·이벤트 필드 변경 없음(필드 보강은 #81) |

## 6. Data Dictionary로 넘길 항목 (이번 범위 제외)

컬럼별 업무 정의·예시값·허용값 표, 원천 필드 → 컬럼 매핑표, 개인정보 등급. 이 문서의 표가 그 입력이다.
