# 04. Data Quality Metadata 계약

> 상태: **STEP 0 제안**. 기존 플래그 `log_truncated`, `log_partial_incomplete`, `source_mismatch`, `truncated`, `skipped`는 **이름과 의미를 그대로** 쓴다.
> 상속 원칙: empty는 정상의 증명이 아니다 · 실패를 0으로 채우지 않는다 · selector를 넓히지 않는다 · 조용히 버리지 않는다.

## 1. 획득 상태 `bronze.acquisition.status`

| 값 | 조건 | 해석 |
|---|---|---|
| `ok` | 모든 페이지 성공, 행 ≥1, limit 미도달(또는 페이지네이션 완료) | 수집 성공 |
| `empty_verified` | 성공, 행 0, `series_preflight=present`(창 또는 24h lookback) | **데이터 없음** — scope stream은 존재. 그래도 "정상"의 증명은 아님 |
| `empty_unverified` | 성공, 행 0, `series_preflight=absent` | 데이터 없음 **또는** 라벨·수집 경로 문제 — 구분 불가 |
| `truncated` | `max_pages` 도달 또는 페이지네이션 불가로 limit에서 멈춤(같은 ns가 limit 이상이면 `status_reason=same_ts_overflow`, [02](02_STORAGE_DESIGN.md) §6) | 일부만 수집 |
| `partial` | 일부 페이지 실패(받은 페이지는 보존) → `status_reason` = `page_failed:<사유>` (사유는 `failed`와 같은 어휘, 예: `page_failed:timeout`). 또는 원천 응답이 경고를 담음 → `source_warnings` (§1.1) | 일부만 수집되었을 수 있음 |
| `failed` | 첫 페이지부터 실패. `status_reason` ∈ `api_error`·`timeout`·`connection_error`·`invalid_response`·`auth_error` | **수집 실패** — 데이터 유무 알 수 없음 |
| `source_mismatch` | 반환 label이 scope selector와 다름 | 다른 출처 데이터. 원문 보존, 하류 사용 금지 |
| `scope_unavailable` | binding·selector 없음. `status_reason` ∈ `source_unknown`·`collector_unmapped`·`no_matching_series` | **수집 시도 안 함** |
| `not_attempted` | 상위 단계 실패·채널 비활성으로 건너뜀 | 수집 시도 안 함 |

### 1.1 기존 Collector 상태와의 대응

| 기존 (`collector/*`) | 이 계약 | 비고 |
|---|---|---|
| `ok` | `ok` | |
| `empty` | `empty_verified` / `empty_unverified` | lookback preflight로 분리(신규) |
| `truncated` | `truncated` | 페이지네이션 후에도 남으면 |
| `partial` (metrics: 응답 `warnings`/`infos`) | `partial` + `status_reason=source_warnings` | 페이지 실패가 아니다. warnings 원문은 `bronze.acquisition.warnings`에 보존 |
| `partial` (network: skipped/truncated) | Bronze는 `ok`/`truncated` | skipped는 Bronze가 아니라 Silver quarantine·Gold `skipped`로 표현. 원문은 Bronze에 모두 보존 |
| `api_error` | `failed` + `api_error` | |
| `invalid_response` | `failed` + `invalid_response` | |
| `source_mismatch` | `source_mismatch` | |
| `scope_unavailable` + reason | `scope_unavailable` + 같은 reason | `no_matching_series`는 lookback도 없을 때만 |

## 2. "데이터 없음" vs "수집 실패" 판정표

| 관측 | 판정 | Gold 채널 상태 | LLM/사람에게 말할 수 있는 것 |
|---|---|---|---|
| HTTP 오류·timeout·형식 오류 | 수집 실패 | `failed` | "알 수 없음" |
| binding 없음 | 미수집 | `unavailable` | "관측 경로 미매핑" |
| 성공, 0행, stream 존재 확인 | 데이터 없음 | `complete_empty` | "이 창에 기록 없음(정상 증명 아님)" |
| 성공, 0행, stream 존재 미확인 | 판단 불가 | `unavailable` (`scope_unverified`) | "기록 없음 또는 수집 경로 문제" |
| 행 있음, scope 검증 0건 통과 | 매칭 불가 | `unavailable` (`host_target_field_absent` 등) | "데이터는 있으나 대상과 연결 불가" |
| 창이 닫히기 전 수집 | 잠정 | 상태 + `window_open` | "지연 도착 가능" |
| 창 안 Fluentd Loki 쓰기 실패 경고 | 유실 의심 | 상태 유지 + `transport_loss_suspected` | "전송 중 유실 가능" |

## 3. 레코드 플래그 어휘 `_quality_flags`

| 플래그 | 출처 | 단계 | 의미 |
|---|---|---|---|
| `log_truncated` | **기존** Fluentd `LeafyLogSize` | Silver | 큰 필드가 축소됨. 원래 크기는 `truncated_original_bytes` |
| `log_partial_incomplete` | **기존** `leafy_docker_log` | Silver | Docker partial 재조립 미완료 |
| `log_parse_error` | **기존** body 키 | Silver | JSON 객체 해석 실패(`log_format=json_invalid`) |
| `log_time_parse_error` | **기존** body 키 | Silver | PG 시각 zone 해석 실패 |
| `source_mismatch` | **기존** collector 의미 | Silver | 행의 label이 획득 scope와 다름. Gold 사용 금지 |
| `event_time_fallback` | 신규 | Silver | `event_time_source=receiver_fallback` |
| `identity_unverified` | 신규 | Silver | legacy label 프로파일 등으로 identity 일부 `UNKNOWN` |
| `duplicate` | 신규 | Silver | `_dup_count > 1` |
| `value_revised` | 신규 | Silver | 같은 metric 점이 다른 값으로 재획득됨 |
| `nonfinite_value` | 신규 | Silver | NaN/Inf |
| `legacy_unversioned` | 신규 | Silver | 버전 없는 과거 RCA envelope |
| `window_open` | 신규 | Silver/Gold | 닫히지 않은 창에서만 획득됨 |
| `partial_acquisition` | 신규 | Silver | `partial`/`truncated` 획득에서만 나온 행 |
| `reacquisition_incomplete` | 신규 | Gold(채널) | 같은 쿼리의 앞선 획득은 `ok`라 채널 상태는 최선 상태를 따르지만, 나중 재획득이 `partial`/`truncated`/`failed`로 끝남 ([02](02_STORAGE_DESIGN.md) §7) |
| `masked` | 신규 | Gold | `mask_secrets` 적용 전후의 렌더 결과가 다름(비밀값 패턴이 실제로 치환됨) |

`truncated`와 `skipped`는 레코드 플래그가 아니라 **집계 값**이다: `truncated`는 `bronze.acquisition.limit_hit`/`status`와 `gold.incident_channel.truncated`, `skipped`는 `gold.incident_channel.skipped`(+`skipped_reasons`)와 manifest `quality.skipped`(Silver 파싱 단계의 quarantine 수). 기존 Network collector의 `skipped`(파싱 실패 + scope 불일치)는 이 계약에서 **파싱 실패 = quarantine**, **scope 불일치 = Gold `skipped`**로 나뉜다.

## 4. 채널 상태 `gold.incident_channel.status` 도출 규칙

입력: 그 채널·scope의 모든 획득(같은 `query_name`의 획득들 중 **최선 상태** = `ok > truncated > partial > empty_verified > empty_unverified > source_mismatch > failed > scope_unavailable > not_attempted` 순으로 가장 좋은 것), 사건 창 안 Silver 행 수, 매칭 수. 데이터를 받은 획득이 빈 획득보다 우선한다(늦게 도착한 데이터가 앞선 빈 결과에 가려지지 않게), 완전한 획득이 불완전한 획득보다 우선한다.

| 순서 | 조건 | status | status_reason |
|---|---|---|---|
| 1 | `identity_status != resolved` | `unavailable` | identity_status 값 |
| 2 | 모든 쿼리 최선 상태가 `scope_unavailable`/`not_attempted` | `unavailable` | 획득 reason |
| 3 | 모든 쿼리 최선 상태가 `failed`/`source_mismatch` | `failed` | 첫 사유 |
| 4 | 창 안 행 ≥1, 매칭 0 | `unavailable` | host 대상에서 `target_unresolvable`이 있으면 `host_target_field_absent`, 그 외에는 가장 많은 skipped 사유 이름 |
| 5 | 어떤 쿼리든 최선 상태가 `partial`/`truncated`/`failed`/`source_mismatch`/`scope_unavailable`/`not_attempted` | `partial` | 해당 상태(미수집 쿼리는 그 획득 reason) — 매칭이 있어도 일부 쿼리를 받지 못했으면 `complete`가 아니다 |
| 6 | 매칭 ≥1 | `complete` | null |
| 7 | 매칭 0, 창 안 행 0, **모든** 쿼리의 최선 상태가 `empty_verified` 또는 `ok` | `complete_empty` | null — `ok`는 획득 창(패딩 포함)에 행이 있어 stream 존재가 확인된 것이므로 "사건 창에 기록 없음"의 근거로 충분하다 |
| 8 | 그 외 모든 경우(규칙 5·7을 거친 뒤에는 매칭 0이고 `empty_unverified` 쿼리가 있는 경우만 남음) | `unavailable` | `scope_unverified` |

`not_applicable`은 identity에 원래 없는 채널(예: producer `unsupported_metrics`만으로 이루어진 쿼리)에만 쓴다. Network의 src/dst처럼 한쪽이 `empty_unverified`여도 다른 쪽에 매칭이 있으면 규칙 6이 먼저 적용된다. 매칭이 0이면 미검증 쪽 때문에 "기록 없음"을 말할 수 없으므로 규칙 8(`unavailable`)이다(§2 판정표와 같음).

## 5. 사건 상태 `gold.incident.overall_status`

| 값 | 조건 (primary 채널만) |
|---|---|
| `complete` | 모든 채널이 `complete`/`complete_empty`/`not_applicable` |
| `insufficient` | `complete` 채널이 하나도 없음 (실시간 경로가 LLM을 호출하지 않는 조건과 같은 취지) |
| `partial` | 그 외 |

related 채널은 overall에 반영하지 않고 채널 행으로만 보고한다.

## 6. 품질 규칙 목록

`BLOCK` 위반 시 build를 commit하지 않는다. `WARN`은 플래그·manifest `quality`에 기록하고 진행한다.

| ID | 단계 | 규칙 | 수준 |
|---|---|---|---|
| DQ-B01 | Bronze | 실행한 모든 질의는 `bronze.acquisition` 행을 가진다(실패 포함) | BLOCK |
| DQ-B02 | Bronze | manifest rows = Parquet rows = `row_count`, raw `raw_sha256` 재계산 일치 | BLOCK |
| DQ-B03 | Bronze | 반환 stream label ⊇ scope의 stream selector label, `\| json \|` 본문 필터 조건(Network `observer`·`observer_instance`)은 파싱한 본문이 일치 (불일치 시 상태 `source_mismatch`) | WARN |
| DQ-B04 | Bronze | `entry_ts_ns`/`sample_ts_ms`가 요청 창 안 | WARN |
| DQ-B05 | Bronze | `window_closed=false`면 `window_open` 전파 | WARN |
| DQ-B06 | Bronze | 금지 스트림(`network-experiment`, Heldout) 미포함 | BLOCK |
| DQ-S01 | Silver | 모든 Bronze 입력 행 → Silver 행 또는 quarantine 행의 부모 (조용한 삭제 0) | BLOCK |
| DQ-S02 | Silver | PK 유일 | BLOCK |
| DQ-S03 | Silver | `event_time` not null, fallback이면 플래그 | BLOCK |
| DQ-S04 | Silver | Network MAJOR=1, 필수 필드 존재 (아니면 quarantine) | BLOCK |
| DQ-S05 | Silver | `source` label이 stdout/stderr인 행을 observation source로 쓰지 않음 | BLOCK |
| DQ-S06 | Silver | 기존 Fluentd 플래그가 `_quality_flags`로 빠짐없이 옮겨짐 | BLOCK |
| DQ-G01 | Gold | 모든 evidence·incident·rca_link 행에 Silver 부모 edge ≥1 | BLOCK |
| DQ-G02 | Gold | 모든 primary 채널(log/metric/network) 행 존재, `status` 기본값 없음 | BLOCK |
| DQ-G03 | Gold | §4 규칙과 상태 일치 | BLOCK |
| DQ-G04 | Gold | `rendered_line`이 `mask_secrets` 적용본 (`mask_secrets(x) == x`) | BLOCK |
| DQ-G05 | Gold | `identity_status != resolved`이면 evidence 0행 | BLOCK |
| DQ-G06 | Gold | 선택 상한(30/20/5/8) 준수 | WARN |
| DQ-G07 | Gold | Network flow bytes는 `connection`만 합산(`connection_threshold` 제외) | BLOCK |
| DQ-L01 | Lineage | [03](03_LINEAGE.md) §7 전체 | BLOCK |

manifest `quality` 섹션 키: `flag_counts {flag: n}`, `quarantined`, `skipped`(Silver), `status_counts {status: n}`(Bronze), `rules {DQ-ID: "pass|warn|fail"}`. 해당 계층에 없는 키는 생략한다(fixture는 `rules` 생략 — 규칙 실행기는 Track D 범위).
