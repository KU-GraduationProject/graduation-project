# 00. 기존 시스템 분석 (Data Platform STEP 0)

> 기준: `origin/main` @ `0443c6f` (2026-11-11 22:14 KST, PR #23 머지)에서 작성, `2117eaf`(PR #32·#34 머지)에서 재검증. 이 문서가 읽은 경로는 두 커밋 사이에 변경이 없다([08](08_CONSISTENCY_REVIEW.md) §4). 코드를 읽어 확인한 사실만 적었다.
> **코드가 존재한다는 것은 실환경에서 동작한다는 뜻이 아니다.** 실환경 판정은 아래 "운영 상태" 열의 근거 문서를 따른다.
> 표기: **[기존]** 저장소에 구현됨 / **[후보]** 저장소에 있으나 운영 mount·배포 안 됨 / **[신규]** 이번 데이터 플랫폼이 새로 만들어야 함

## 1. GC PC → Tailscale → JH PC 수집 흐름

| 구간 | GC PC (관측 대상, Windows 11) | 전송 | JH PC (AIOps, Windows) | 근거 |
|---|---|---|---|---|
| 앱 로그 | Docker fluentd log driver (frontend/backend/minio) | GC → JH `:24224/tcp`, 인증 없음(Tailscale ACL만), `fluentd-async`, `fluentd-request-ack`, `mode: non-blocking`, `max-buffer-size: 4m` | Fluentd `@DOCKER` → concat → `@DOCKER_APP` → `leafy_docker_log` → Loki | [leafy-compose-logging.example.yml:12-28](../../deploy/leafy-pc/leafy-compose-logging.example.yml#L12-L28), [fluent.conf:55-119](../../leafy/fluentd/fluent.conf#L55-L119) |
| DB 로그 | Windows PostgreSQL 17 jsonlog → Windows Fluent Bit tail | GC → JH `:24225/tcp`, `shared_key`, `Require_Ack_Response On`, filesystem buffer 1G, `Retry_Limit no_limits` | Fluentd `@POSTGRES` → `leafy_postgres_log` (service=db, runtime=host) → Loki | [postgresql/fluent-bit.conf](../../deploy/leafy-pc/postgresql/fluent-bit.conf), [fluent.conf:127-151](../../leafy/fluentd/fluent.conf#L127-L151) |
| Network | Zeek(backend netns) → Enricher → `network-events.jsonl` → Fluent Bit shipper | GC → JH `:24224/tcp`, tag `network.event`, filesystem buffer 512M | Fluentd `@DOCKER`의 `match network.event` → `@NETWORK` → Loki (`log_type=network`) | [network-observer/fluent-bit.conf](../../deploy/leafy-pc/network-observer/fluent-bit/fluent-bit.conf), [fluent.conf:59-62,159-192](../../leafy/fluentd/fluent.conf#L159-L192) |
| 메트릭 | cAdvisor + GC Telemetry Collector (loopback listener) | **JH → GC pull** (승인된 private transport) | Prometheus `file_sd` (`targets/*.yml`, 커밋 안 함) | [prometheus.aiops.yml:35-47](../../monitoring/prometheus/prometheus.aiops.yml#L35-L47), [OI_02_03_04_TELEMETRY.md](../rulepack/OI_02_03_04_TELEMETRY.md) |
| 탐지·RCA | — | — | Prometheus/Loki Ruler → Alertmanager → `POST /webhook/alert` → Pipeline → Ollama → Loki `{job="aiops-llm"}` | [alertmanager.yml](../../monitoring/alertmanager/alertmanager.yml), [main.py:258-329](../../aiops/pipeline/main.py#L258-L329) |

JH의 Loki(`127.0.0.1:3100`), Prometheus(`127.0.0.1:9090`), Alertmanager(`127.0.0.1:9093`)는 loopback에만 publish된다. 데이터 플랫폼은 JH에서 이 읽기 API만 사용할 수 있다.

**운영 상태:** [GC_JH_WINDOWS_E2E_RUNBOOK.md:6](../demo/GC_JH_WINDOWS_E2E_RUNBOOK.md#L6) 기준 "실제 Windows 2PC E2E는 BLOCKED". GC→JH 로그 전달은 과거 사용자 확인 기록이 있으나([OI_02_03_04_TELEMETRY.md:4](../rulepack/OI_02_03_04_TELEMETRY.md#L4)) 오늘의 성공 판정이 아니다. 메트릭 pull 경로는 UNVERIFIED다.

## 2. Docker Fluentd 로그 vs PostgreSQL vs Zeek 로그

| 항목 | Docker 앱 로그 | PostgreSQL 17 (host) | Zeek Network Event |
|---|---|---|---|
| Loki entry 시각 | Docker driver 시각 (sub-second 옵션) | jsonlog `timestamp` 해석값. **해석 실패 시 수신 시각** + `log_time_parse_error` | event `timestamp` (connection **시작**, UTC ms) |
| 레포 기본 Loki label | `container`(LEGACY tag), `source`(=stdout/stderr), `service`, `container_name`, `runtime`, `log_format` | `service=db`, `runtime=host`, `log_format` | `log_type=network`, `event_type`, `src_service`, `dst_service`, `protocol`, `network` |
| 릴리스 후보 label **[후보]** | `source`=**observation source**, `log_stream`=stdout/stderr, `site`, `target` 추가 | `site`, `source`, `target` 추가 (dedicated receiver일 때) | 변경 없음 |
| 본문(line) | 앱 JSON 필드 + `docker{}` 메타, 비JSON은 `{"message": 원문}` | jsonlog 필드 그대로 + `pg_log_file`(Fluent Bit Path_Key) | Canonical Network Event v1.0 그대로 |
| 기존 품질 표식 | `log_format=json_invalid`, `log_parse_error`, `log_partial_incomplete`, `log_truncated` | `log_time_parse_error`, `log_truncated`, Fluent Bit 파싱 실패 시 `{"log": 원문}` + `log_format=text` | Enricher가 변환 실패 레코드를 skip(카운트만, 출력 없음) |
| 크기 제한 | 240KB로 축소(`LeafyLogSize`) | 240KB 축소. **GC Fluent Bit `Skip_Long_Lines` 1MB 초과 줄은 GC에서 버려짐(JH에서 탐지 불가)** | GC Fluent Bit 1MB 초과 skip |
| 유실 가시성 | Docker non-blocking 4m 버퍼 초과분은 GC에서 조용히 버려짐(JH 탐지 불가). Loki 4xx 거부는 `{log_type="fluentd_internal"}` 경고 | 동일 | 동일 |
| 중복 가능성 | at-least-once(request-ack) | at-least-once(Require_Ack_Response) | at-least-once. 같은 `connection_id`라도 `connection`/`connection_threshold`는 다른 이벤트 |

근거: [filter_leafy_docker_log.rb:32-67](../../leafy/fluentd/plugins/filter_leafy_docker_log.rb#L32-L67), [filter_leafy_postgres_log.rb:25-50](../../leafy/fluentd/plugins/filter_leafy_postgres_log.rb#L25-L50), [leafy_log_size.rb](../../leafy/fluentd/plugins/leafy_log_size.rb), [prepare_release.py:183-195](../../tools/rulepack/prepare_release.py#L183-L195), [enricher/main.py:135-160](../../aiops/network-observer/enricher/main.py#L135-L160).

**데이터 플랫폼에 주는 함의:** Loki `source` label의 **의미가 프로파일마다 다르다**(레포 기본=출력 채널, 릴리스 후보=관측 producer). Silver는 `log_stream` label 존재 여부로 프로파일을 판별해야 하며, 레포 기본 프로파일의 `source=stdout|stderr`를 observation source로 승격하면 안 된다([identity.py:110-113](../../aiops/pipeline/identity.py#L110-L113)과 같은 규칙).

## 3. Loki / Prometheus 조회 방식과 현재 한도

| Collector | 조회 | 한도·특성 | 근거 |
|---|---|---|---|
| `LogsCollector` | `/loki/api/v1/series` preflight → `query_range`, `direction=forward` | **`limit=200`, 페이지네이션 없음.** 창 앞쪽 200줄만 남고 사건 직후 로그가 잘릴 수 있음 → `truncated`. timeout 30s | [collector/logs.py:12-48](../../aiops/pipeline/collector/logs.py#L12-L48) |
| `NetworkCollector` | src/dst selector 2개 + `\| json \| observer=… and observer_instance=…` | selector당 `limit=500`, timeout 10s, 응답 body 재검증 후 중복 제거 | [collector/network.py:66-123](../../aiops/pipeline/collector/network.py#L66-L123) |
| `MetricsCollector` | `query_range`, `step=15s`, `rate(...[1m])` | binding의 job/instance(/id) exact selector만. host는 node exporter OS 지표만 | [collector/metrics.py:14-86](../../aiops/pipeline/collector/metrics.py#L14-L86) |
| 공통 시간창 | `startsAt ± 5분` | **webhook 직후 실행**되므로 창의 뒤쪽(사건 이후 최대 5분)은 조회 시점에 아직 존재하지 않는다. Fluentd flush 5s·concat 10s·Fluent Bit 재시도 지연도 반영되지 않는다 | [main.py:286-290](../../aiops/pipeline/main.py#L286-L290) |
| 저장소 보존 | Prometheus `retention.time=30d` / Loki retention 미설정(compactor retention 비활성), `reject_old_samples_max_age=168h`, `max_entries_limit_per_query` 등은 Loki 기본값(서버 실제값 미확인) | — | [docker-compose.aiops.yml:70](../../docker-compose.aiops.yml#L70), [loki-config.yml:29-34](../../monitoring/loki/loki-config.yml#L29-L34) |

## 4. Network Event Canonical Schema (변경 금지 대상)

- 정의: [NETWORK_EVENT_SCHEMA.md](../network-observability/NETWORK_EVENT_SCHEMA.md) `schema_version "1.0"` — 필수 공통 4 / src 5 / dst 5 / network 4 / connection 4 / 선택 5 필드. `service`는 not-null(`unknown`), `container`는 nullable, IP는 identity가 아닌 observed fact, Loki label 6개.
- 구현: [enricher/events.py:46-128](../../aiops/network-observer/enricher/events.py#L46-L128) — `event_type`은 `connection`과 **`connection_threshold`**(조기 이벤트) 두 종류를 만든다. `schema_version`은 둘 다 `"1.0"`([zeek_map.py:11-18](../../aiops/network-observer/enricher/zeek_map.py#L11-L18)).
- 소비: Pipeline은 MAJOR `"1"`만 받아들이고, 모르는 필드는 무시한다([collector/network.py:28,132-133](../../aiops/pipeline/collector/network.py#L132-L133)).
- **문서·코드 차이**(수정하지 않음, [08_CONSISTENCY_REVIEW.md](08_CONSISTENCY_REVIEW.md) X-01~X-03): 스키마 문서는 v1.0 event_type을 `connection`만으로 정의, `src_target`/`dst_target` 필드는 스키마·Enricher 어디에도 없지만 Pipeline은 host endpoint 검증에 이 필드를 요구한다.

## 5. 경보와 로그·메트릭·네트워크 상관분석 방식 **[기존]**

1. `resolve_identity()`가 alert labels/annotations와 `OBSERVATION_BINDINGS`로 다섯 identity(`site/service/runtime/target/source`)를 확정한다. 결과 상태: `resolved | source_unknown | source_unmapped | identity_conflict | ambiguous_source` ([identity.py:107-165](../../aiops/pipeline/identity.py#L107-L165)).
2. `CorrelationContext.around(service, startsAt, 5분)`으로 같은 UTC 창을 만든다. 시각 비교는 `to_instant()`로 instant 변환 후에만 한다(offset 없는 시각 거부) ([correlation.py:117-186](../../aiops/pipeline/correlation.py#L117-L186)).
3. 세 collector가 **binding이 지정한 exact selector로만** 조회하고 반환 label을 다시 검증한다. 범위를 넓히는 fallback이 없다.
4. binding이 없거나 scoped evidence가 모두 없으면 LLM을 호출하지 않고 `confidence=0, action_type=NONE` 결과를 남긴다 ([main.py:298-301](../../aiops/pipeline/main.py#L298-L301)).
5. dedup: `alertname + identity + 원래 식별 label` 해시, 300초, **프로세스 메모리**. 분석 이력 `deque(maxlen=20)`도 메모리뿐이다 ([main.py:38-48](../../aiops/pipeline/main.py#L38-L48), [identity.py:168-176](../../aiops/pipeline/identity.py#L168-L176)).

**현재 main의 실제 구성에서 `OBSERVATION_BINDINGS`는 어디에도 설정되어 있지 않다**(기본 `[]`, `docker-compose.aiops.yml`·`deploy/` 검색 결과 없음). 따라서 main을 그대로 배포하면 모든 RCA가 `source_unknown/unmapped` + LLM 미호출이다. 데이터 플랫폼도 같은 binding을 써야 하므로(§7) **실데이터 적재는 OI-09의 BLOCKED 항목에 그대로 묶인다.** Mock 기반 개발은 영향받지 않는다.

## 6. LLM 프롬프트 구성과 데이터 선별 **[기존]**

| 단계 | 규칙 | 근거 |
|---|---|---|
| 헤더 | `=== OBSERVATION IDENTITY ===` + identity JSON + 채널별 가용성(status/reason/query_status/selector/observer) | [builder.py:76-84](../../aiops/pipeline/prompt/builder.py#L76-L84) |
| METRICS | 쿼리별 앞 5개 series, `latest/peak/samples` | [builder.py:107-120](../../aiops/pipeline/prompt/builder.py#L107-L120) |
| LOGS | `is_priority` 우선 30줄 + 기타 20줄 → 시각순. 줄당 200자, `mask_secrets` 적용 | [builder.py:125-132](../../aiops/pipeline/prompt/builder.py#L125-L132), [log_line.py:114-147](../../aiops/pipeline/prompt/log_line.py#L114-L147) |
| 길이 | user 본문 6000자 절단 후 NETWORK 섹션(최대 1600자, flow 8개)을 METRICS와 LOGS 사이에 삽입 | [builder.py:136-147](../../aiops/pipeline/prompt/builder.py#L136-L147), [network_section.py:25-75](../../aiops/pipeline/prompt/network_section.py#L25-L75) |
| NETWORK 집계 | `(src, dst, dst_ip, dst_port, proto)` flow. bytes 합계는 최종 `connection`만, `connection_threshold`는 early 신호로 분리. Allowlist 판정 표기 | [network_section.py:78-158](../../aiops/pipeline/prompt/network_section.py#L78-L158) |
| LLM 호출 | `llama3.1:8b`, temperature 0.3, num_ctx 4096, num_predict 400, `format=json`, 최대 2회 | [config.py:9-16](../../aiops/pipeline/config.py#L9-L16), [main.py:847-895](../../aiops/pipeline/main.py#L847-L895) |
| 결과 저장 | Loki `{job="aiops-llm"}` envelope `schema_version="2.0"`(identity, alert labels/annotations, evidence_sources, result). 실패 원문은 `{job="aiops-llm-error"}` | [main.py:308-323,781-819](../../aiops/pipeline/main.py#L781-L819) |

**리니지 관점의 공백 [신규 필요]:** 실제 프롬프트 본문, 선택된 로그 줄, 사용한 모델 options는 어디에도 저장되지 않는다. evidence_sources에는 selector·상태만 있고 줄/샘플은 없다. 또 `storage_status`는 Loki push **이후**에 entry에 추가되므로 Loki에 저장된 envelope에는 이 필드가 없다([main.py:323](../../aiops/pipeline/main.py#L323)).

## 7. 기존 품질 플래그와 source identity 검증 **[기존]**

| 계층 | 플래그/상태 | 의미 |
|---|---|---|
| Fluentd 레코드 | `log_truncated{original_bytes, fields}` | 240KB 초과 필드 축소 |
| | `log_partial_incomplete` | Docker partial 재조립 미완료 |
| | `log_parse_error`, `log_format=json_invalid` | `{`로 시작했으나 JSON 객체가 아님 |
| | `log_time_parse_error` | PG timestamp zone 해석 실패 → 수신 시각 사용 |
| Collector | `ok`, `empty`, `truncated`, `partial`, `api_error`, `invalid_response`, `source_mismatch`, `scope_unavailable`(+`reason`: `source_unknown`/`collector_unmapped`/`no_matching_series`) | [OI_09_SOURCE_IDENTITY.md:95-105](../rulepack/OI_09_SOURCE_IDENTITY.md#L95-L105) |
| Network | `skipped`(파싱·검증·scope 불일치 수), `truncated`, `errors`, `query_complete` | [collector/network.py:31-58](../../aiops/pipeline/collector/network.py#L31-L58) |
| Metrics | `query_status`(쿼리별), `unsupported_metrics`(producer 미지원은 0이 아님) | [collector/metrics.py:39-51,83-86](../../aiops/pipeline/collector/metrics.py#L39-L51) |
| Identity | `identity_status` 5종, `UNKNOWN` 직렬화 | [identity.py:7-41](../../aiops/pipeline/identity.py#L7-L41) |
| Producer | `aiops_docker_status_scrape_success`, `leafy_telemetry_collection_success` 등 | [main.py:192-209](../../aiops/pipeline/main.py#L192-L209), OI-02/03/04 |

기존 계약의 핵심 원칙 — **"empty는 정상·무트래픽의 증명이 아니다", "실패를 0으로 채우지 않는다", "selector를 넓히지 않는다"** — 를 데이터 플랫폼 계약이 그대로 상속한다.

한계: `no_matching_series`는 "라벨이 틀림"과 "창 안에 로그가 없음"을 구분하지 못한다(series API는 창 안에 entry가 있는 stream만 반환). 이 구분은 [04_DATA_QUALITY.md](04_DATA_QUALITY.md)의 lookback preflight로 새로 해결한다.

## 8. 기존 기능 vs 신규 기능

| 기능 | 상태 | 재사용 방식 |
|---|---|---|
| Observation identity·binding 파싱·충돌 검사 | [기존] `identity.py` | Bronze plan 생성과 Silver/Gold identity 판정에 **그대로 사용** (read-only import) |
| 시각 정규화 `to_instant`, 창 `CorrelationContext` | [기존] `correlation.py` | 그대로 사용 |
| scoped selector 생성 `selector()`, 반환 label 검증 `matches()` | [기존] | 그대로 사용 |
| Network 중복 키·scope/endpoint 검증 | [기존] `collector/network.py` | 같은 규칙을 Silver dedup·Gold 매칭에 이식(파리티 테스트로 고정) |
| 로그 렌더링·우선순위·비밀 마스킹 | [기존] `prompt/log_line.py` | Gold `rendered_line`에 그대로 사용 |
| Network flow 집계·Allowlist 판정 | [기존] `network_section.py`, `policy/allowlist.py` | Gold flow 집계에 같은 의미 적용 |
| LLM 결과 정규화 | [기존] `schemas/llm_output.py` | Silver `rca_result` 검증 |
| 재전송 영수증 패턴 | [기존] `scenarios/network/result_telemetry.py` | 멱등 적재 설계 참고(코드 재사용 아님) |
| 테스트 격리 실행기 | [기존] `testing/run_isolated.py` | 신규 suite 등록(Track D, 공유 파일) |
| 페이지네이션·완전 조회, 원문 응답 보존 | **[신규]** | — |
| 데이터 레이크(MinIO 분리 인스턴스·Parquet·DuckDB) | **[신규]** | — |
| Manifest·checkpoint·버전 포인터·재처리 | **[신규]** | — |
| Silver 통합 스키마(event_time, label profile, dedup, quarantine) | **[신규]** | — |
| 사건 ID·Gold Evidence Mart | **[신규]** | — |
| 레코드 단위 Lineage, run·Git SHA 기록 | **[신규]** | — |
| Airflow 오케스트레이션 | **[신규]** | — |
| 경보 이력 영속화 | **[신규, 부분]** | AM에는 이력 API가 없고 Pipeline dedup은 메모리. 현재 영속 근거는 Loki `aiops-llm` envelope뿐 (Loki Ruler 경보 중 분석 실패·dedup 억제분은 남지 않음) |

## 9. 데이터 플랫폼이 읽으면 안 되는 것

- `{job="network-experiment"}` 스트림과 `scenarios/network/results/*` — 시나리오 측정 결과(정답 성격). Evidence에 섞이면 평가 누설이 된다.
- `docs/scenarios-v2/heldout/`, `scenarios/v2/heldout/` — [HELDOUT_POLICY.md](../scenarios-v2/HELDOUT_POLICY.md).
- Allowlist 판정은 "정책 근거"이지 정답 라벨이 아니다([network_section.py:16-17](../../aiops/pipeline/prompt/network_section.py#L16-L17)).
