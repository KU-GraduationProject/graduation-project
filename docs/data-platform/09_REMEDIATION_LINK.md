# 09. Remediation 연결 — `gold.remediation_link` (DEC-19)

> 상태: **구현**(Issue #77). 기준 origin/main `feca84f`(#71 `gold.scenario_link`, #81 Remediation 이벤트 연결 키 병합 후).
> 범위: 데이터 플랫폼(`aiops/dataplatform/`, `docs/data-platform/`)만. **Remediation·Pipeline(LLM 프롬프트·스키마 포함) 코드 변경 없음.** Loki는 읽기만 한다.
> 계약 원본: Bronze [01](01_DATA_CONTRACT.md) §2.4, Silver §3.6·§3.11, Gold §4.8, 품질 [04](04_DATA_QUALITY.md) §6, 리니지 [03](03_LINEAGE.md) §3. 이 문서는 근거·판정 규칙·절차를 둔다.

## 1. 목적과 축소 범위

Gold 사건 1건에서 "LLM 판단(RCA) → 조치 레코드 → 승인 → 실행·복구"를 **정확히 이어지는 것만** 한 행으로 본다.

| 포함 | 제외 (DEC-19) |
|---|---|
| RCA envelope의 `remediation_id`로 잇는 연결(`link_basis=rca_remediation_id`) | 경보 이름·시각 근접 추정 연결 (`heuristic_alertname_time` 만들지 않음) |
| Remediation 이벤트 원문을 Silver에 보존(정확히 못 잇는 `policy_decision`·`auto_remediation` 포함) | 정확히 못 잇는 이벤트의 Gold 연결 — Gold에는 "연결 안 됨"으로만 표시 |
| `alertname`·`alert_active_at == anchor_time` 교차 검증 | Remediation SQLite 직접 읽기, Remediation·Pipeline 코드 수정, Loki 쓰기 |

정책 결정까지의 1:1 연결은 DEC-19 개정으로 다룬다. Remediation 이벤트 필드 보강(#81, PR #84)으로 키는 생겼지만 v1은 쓰지 않는다(§9 D-4).

## 2. 원천 사실 (코드 확인, 읽기만)

| 사실 | 근거 |
|---|---|
| RCA envelope(`aiops-llm`)에 handoff 결과로 `remediation_id`가 실린다(`approval_pending`·`auto_*`). Remediation이 `existing`(같은 incident key·action의 기존 레코드)으로 답해도 `approval_pending`으로 실린다 | [pipeline/main.py:1049-1059](../../aiops/pipeline/main.py#L1049-L1059), envelope 갱신 [main.py:359-361](../../aiops/pipeline/main.py#L359-L361) |
| 1.0까지 `silver.rca_result`는 `remediation_id`를 버렸다(1.1에서 추가, §4.2) | [silver/normalize.py](../../aiops/dataplatform/silver/normalize.py) `rca_result` |
| 레코드 이벤트(`_push_record`)는 `remediation_id`·`alert`·`state`·`alert_active_at`(=경보 `startsAt` 원문)·시각 지표를 싣는다 | [remediation/main.py:845](../../aiops/remediation/main.py#L845), [recovery.py:223](../../aiops/remediation/recovery.py#L223), [store.py:228](../../aiops/remediation/store.py#L228) |
| #81 전 `policy_decision`은 레코드 생성 전에 push되고 `remediation_id`·fingerprint·identity가 없었다. #81(PR #84)부터 레코드가 생긴 경로는 `remediation_id`, 모든 경로는 `alert_fingerprint`·`alert_starts_at`·`identity`를 싣고, 레코드 이벤트에는 `incident_key`·`plan_id`·`rejected_by`가 붙는다. v1은 이 키를 Silver 원문(`event_body`)에만 보존한다 | [remediation/main.py:236](../../aiops/remediation/main.py#L236), 호출 [main.py:513](../../aiops/remediation/main.py#L513) |
| 승인자는 `aiops-timeline`의 `manual_approval_executed`에만 있다. 거부자는 이벤트에 없다 | [remediation/main.py:773](../../aiops/remediation/main.py#L773) |
| `aiops-timeline`은 Pipeline도 쓴다(`llm_analysis_completed`) | [pipeline/main.py:892](../../aiops/pipeline/main.py#L892) |
| Remediation이 붙이는 Loki label: `job`, `event`, `status`, (있으면) `alert`. 본문 `timestamp`는 `utcnow().isoformat()+"Z"` | [remediation/main.py:1078-1088](../../aiops/remediation/main.py#L1078-L1088) |

## 3. Bronze — `stream_class=remediation_event` (global)

### 3.1 Selector

| `query_name` | LogQL | 비고 |
|---|---|---|
| `remediation_audit` | `{job="aiops-remediation", alert="<alertname>"}` | `alert` label이 없는 `auth_denied`는 사건과 무관하므로 들어오지 않는다 |
| `remediation_timeline` | `{job="aiops-timeline", alert="<alertname>", event=~"remediation_decision_started\|manual_approval_executed\|auto_remediation_completed\|recovery_approval_required"}` | Remediation 이벤트 이름으로만 거른다(stream label 매칭, 본문 파싱 없음). Pipeline의 `llm_analysis_completed`·Slack 이벤트는 들어오지 않는다 |

실제 질의 문자열은 Pipeline `identity.selector` 형식(키 정렬, 공백 없음)이다: `{alert="DBConnectionLimit",job="aiops-remediation"}`.

- `scope_role=global`, `scope_identity` 전부 `UNKNOWN`, `binding_sha256=null` (기존 `rca_result`와 같은 규칙). series preflight selector = 질의 문자열.
- `alert` 값은 `rca_result` selector와 같이 경보 `alertname`이다. identity label은 Remediation 스트림에 없으므로 붙이지 않는다.
- DQ-B06 금지 토큰 검사 대상에 그대로 포함된다.
- Airflow 매핑 이름(`phases.label`)은 chunk 시작 시각을 붙여 chunk마다 다르다(`global:remediation_event:remediation_audit@2026-…`).

### 3.2 획득 창 — 15분 이하 질의 여러 개

| 항목 | 값 |
|---|---|
| remediation 창 | `[anchor − 5m − pad, anchor + 80m + pad]` (pad = `acquisition_padding_s`, 기본 60s) → 기본 87분 |
| 분할 | 앞에서부터 **15분 이하** chunk. 기본 6개: 15·15·15·15·15·12분. chunk i의 끝 = chunk i+1의 시작(빈틈·겹침 없음, DQ-B07). 경계 시각과 정확히 같은 entry는 두 chunk에 다 들어올 수 있고 Silver `record_key` dedup으로 1행이 된다 |
| 질의 수 | chunk × selector 2 = 기본 **12회/사건** (pool 1, timeout 30s, 페이지 간 지연 그대로) |
| 80분 근거 | 승인 대기 `SLACK_APPROVAL_TTL_SEC` 기본 900s([slack_socket.py:26](../../aiops/remediation/slack_socket.py#L26)) + [remediation_policy.yml](../../aiops/policy/remediation_policy.yml) 최대 `ttl_seconds` 3600s(`PAUSE`) + 여유 300s = 4800s |
| 창 안 / 창 밖 | `THROTTLE`(ttl 1800s, `recovery_mode: auto`)은 승인 대기를 더해도 TTL 자동 복구까지 창 안에 들어온다. `PAUSE`(3600s)·`ISOLATE`(1800s)의 `require_approval` 복구처럼 **사람이 복구 승인을 늦게 누르는 경우**는 창 밖일 수 있고 `beyond_window`로 남긴다(§5.2) |
| 상수 | `bronze/plan.py` `REMEDIATION_HORIZON = timedelta(seconds=900 + 3600 + 300)`, `REMEDIATION_CHUNK = 15m`. 데이터 플랫폼은 정책 파일·Remediation 설정을 **읽지 않는다** — 값은 상수로 두고 위 근거(환경변수 이름·정책 파일·action)를 주석으로 단다. 정책 값이 바뀌면 이 상수와 DEC-19를 함께 고친다 |
| `acquisition_key` | 기존 식 그대로 — chunk마다 `window_start/end`가 달라 키가 다르다 |
| `window_closed` | chunk별 기존 판정. 열린 chunk는 재실행 시 다시 획득된다(닫힌 것만 재사용, [acquire.py](../../aiops/dataplatform/bronze/acquire.py) `find_reusable`) |

실시간 비간섭([05](05_PARALLEL_TRACKS.md) §6) 대조: 요청 창 ≤15분 ✅ · pool 1 ✅ · timeout 30s ✅ · Loki 쓰기 없음 ✅ · 실시간 경로 파일 변경 없음 ✅. 부하 증가는 사건당 Loki 질의 +12회(재획득 시 열린 chunk만큼 추가).

### 3.3 Silver coverage와 창

다른 데이터셋의 coverage는 plan 창과 **같은** `window_start/end`의 획득만 입력으로 받는다([silver/build.py](../../aiops/dataplatform/silver/build.py) `coverage_inputs`). `silver.remediation_event`만 다르다.

- coverage 창 = remediation 창 전체(§3.2). `coverage_id`는 기존 식에 이 창을 넣는다.
- 입력 = 같은 `plan_id`·`stream_class=remediation_event`이고 chunk 창이 coverage 창 **안에 있는** 획득(재획득한 chunk도 포함).
- Gold 입력 acquisitions에도 remediation chunk 획득을 더한다(§5.2 `partial` 판정용).

## 4. Silver

### 4.1 `silver.remediation_event` (신규, `_schema_version=1.0`)

컬럼 표는 [01](01_DATA_CONTRACT.md) §3.11. 요점:

- PK = Bronze `record_key`. `event_time`은 본문 `timestamp`(C-4), 해석 실패 시 Loki entry 시각 + `event_time_fallback`.
- **레코드 이벤트** = `stream_job=aiops-remediation`이고 본문에 `state`가 있는 행(`_push_record`). `record_state`·`alert_active_at`·`timings`는 이 행에만 있다.
- `policy`는 `policy_decision` 본문에서 `timestamp`·`event`·`alert`·`source`·`status`를 뺀 나머지(`decision.as_dict()`), `event_body`는 본문 전체(C-1). Silver는 원문을 보존한다(C-12).
- JSON 아님·객체 아님·`event` 없음 → `silver.quarantine`(기존 사유). 알 수 없는 `event` 이름도 행으로 남긴다.

### 4.2 `silver.rca_result` 1.0 → **1.1** (MINOR, C-10)

| 추가 컬럼 | 타입 | Null | 설명 |
|---|---|---|---|
| `remediation_id` | string | Y | envelope `remediation_id` 원문. 없거나 문자열이 아니면 null |

- 기본 키·기존 컬럼 변경 없음 → 저장 경로 `v1` 유지. 1.0 build를 읽을 때 이 컬럼은 null로 본다(Gold는 `row.get`).
- 데이터셋별 버전 표 `schemas.SCHEMA_VERSIONS = {"silver.rca_result": "1.1"}`, 나머지는 `1.0`.
- `LLMAnalysisResult` 재검증·Pipeline 모듈은 그대로 읽기만 한다.

## 5. Gold — `gold.remediation_link` (신규)

**사건 × build × RCA당 1행.** `gold.rca_link`의 모든 RCA가 한 행씩 갖는다 — 연결이 안 된 RCA도 "연결 안 됨"으로 보인다. 컬럼 표는 [01](01_DATA_CONTRACT.md) §4.8.

### 5.1 `link_status` 판정 (위에서 처음 맞는 것)

| 값 | 조건 | 상세 컬럼 |
|---|---|---|
| `no_remediation_id` | RCA에 `remediation_id` 없음(알림만, 정책 BLOCKED/NOTIFY, 응답 미확인 등) | null |
| `events_not_found` | 같은 `remediation_id` 레코드 이벤트가 remediation 창 안(`loki_ts_ns` 기준)에 없음 | null |
| `cross_check_failed` | 레코드 이벤트 중 하나라도 `alertname ≠ incident.alertname` 또는 `alert_active_at ≠ incident.anchor_time`(C-4 instant 비교, 문자열 비교 금지, 해석 불가도 불일치) | null |
| `linked` | 위 셋이 아님 | 채움 |

`linked`만 `link_basis=rca_remediation_id`로 상세를 채운다. 그 밖에는 Silver 이벤트 행을 Gold로 끌어오지 않는다(`targets=[]`, `execution_results=[]`, `block_events=[]`, 나머지 null). `policy_decision_link`는 모든 행에서 `unlinked_no_key`.

상세 값(`linked`):

- 사용 이벤트 = 같은 `remediation_id`의 창 안 Silver 행 전부(`event_time`, `loki_ts_ns`, PK 순).
- `action_type`·`targets`·`final_state`·시각 컬럼·`mttr_sec`·`approval_latency_sec` = **마지막 레코드 이벤트**의 값(`timings`). 시각은 C-4로 해석해 C-3 형식으로, 해석 불가면 null.
- `approved_by` = 첫 `manual_approval_executed`의 `approved_by`. `execution_results` = `manual_approval_executed`마다 `{target,status,result,verified}`. `block_events` = `evidence_gate_blocked`·`capture_blocked`·`db_backup_failed`·`duplicate_execution_suppressed`마다 `{event,reason,event_time}`.

### 5.2 `remediation_status`

remediation chunk 획득을 `(query_name, window_start)`로 묶어 본다(재획득 포함).

- `window_open`: 어떤 chunk도 닫힌(`window_closed=true`) 획득이 없음.
- `acquisition_incomplete`: 계획한 chunk × selector 중 획득이 없는 것이 있거나, 최선 상태([04](04_DATA_QUALITY.md) §1)가 `ok`/`empty_verified`가 아님.
- `beyond_window`: `recovery_due_at > remediation_window_end`이거나, 창이 모두 닫혔는데(`window_open` 아님) `final_state`가 미정착 상태 — 결과가 창 밖에서 정해진다. 창이 열려 있는 동안의 미정착은 `window_open`으로만 본다.

| `remediation_status` | 조건 |
|---|---|
| `complete` | `linked`이고 사유 없음 |
| `partial` | `linked`이고 사유 ≥1, 또는 `events_not_found`이면서 `window_open`/`acquisition_incomplete`(아직 안 들어왔을 수 있음) |
| `unlinked` | 그 밖(`partial_reasons=[]`) |

정착/미정착 상태 어휘(데이터 플랫폼 `enums`에 복사, Remediation 코드 import 안 함; [store.py:41-59](../../aiops/remediation/store.py#L41-L59) 기준):

| 구분 | 상태 |
|---|---|
| 미정착 | `PROPOSED` `AWAITING_APPROVAL` `APPROVED` `EXECUTING` `RECOVERY_PENDING` `RECOVERY_APPROVAL_REQUIRED` `RECOVERING` |
| 정착 | `VERIFIED` `FAILED` `BLOCKED` `SKIPPED` `REJECTED` `EXPIRED` `SUPERSEDED` `RECOVERED` `RECOVERY_FAILED` `NEEDS_REVIEW` `UNKNOWN` `RECOVERY_UNKNOWN` |

remediation chunk가 열려 있으면 행에 `window_open` 플래그도 붙인다(DQ-B05). `gold.incident`·`overall_status`는 **바꾸지 않는다**(증거 채널 상태와 조치 연결 상태를 섞지 않음).

### 5.3 리니지

- `gold.remediation_link`(`child_key = {incident_id}:{rca_id}`) → `silver.rca_result` (`linked_from`, 모든 행)
- `gold.remediation_link` → `silver.remediation_event` (`linked_from`, `linked` 행이 사용한 이벤트마다)

## 6. 품질 규칙 추가 (04 §6)

main에 DQ-G08(정답 레이블 금지)·DQ-G09(`scenario_link` 1행)가 있으므로 Gold 규칙은 G10부터 쓴다.

| ID | 규칙 | 검사 위치 |
|---|---|---|
| DQ-B07 | `remediation_event` chunk 창 ≤ 15분, chunk 합집합 = remediation 창(빈틈·겹침 없음) | `bronze/plan.py` plan 생성 시(BLOCK) |
| DQ-G10 | `gold.remediation_link` 행 수 = 같은 build의 `gold.rca_link` 행 수, `rca_id` 집합 동일 | `gold/checks.py` |
| DQ-G11 | `link_status=linked` ⇔ `link_basis=rca_remediation_id`. 다른 `link_basis` 값 금지(추정 연결 금지), `linked`가 아니면 상세 비움, `policy_decision_link=unlinked_no_key` | `gold/checks.py` |
| DQ-G12 | `linked` 행: 사용한 모든 레코드 이벤트의 `alertname`이 사건과 같고 `alert_active_at`이 `anchor_time`과 같은 instant | `gold/checks.py` |

## 7. 계약 반영 (main `6382aef` 기준 diff 요약)

```diff
 ## 01 §2.4 stream_class
 | `scenario_run` | 질의 없음. `DP_SCENARIO_RUN_LOG` 파일 … | global |
+| `remediation_event` | `{job="aiops-remediation", alert=…}` · `{job="aiops-timeline", alert=…, event=~"<Remediation 이벤트 4종>"}`, 15분 이하 chunk (DEC-19, 09 §3) | global |

 ## 01 §3.6 silver.rca_result
+> `_schema_version` 1.1: `remediation_id` 추가 (DEC-19)
 | `remediation_dispatched`,`notification_dispatched` | bool | Y | |
+| `remediation_id` | string | Y | envelope 원문. 1.0 build에서는 null |
+### 3.11 `silver.remediation_event`        (09 §4.1)
+### 4.8 `gold.remediation_link`            (09 §5)

 ## 03 §3 relation `linked_from`: gold.remediation_link → silver.rca_result · silver.remediation_event
 ## 04 §6 DQ-B07, DQ-G10~G12
 ## README.md 결정 표: DEC-19 결정됨, 상태 문단 #71 구현됨·#77 반영

 ## contracts/enums.py
-STREAM_CLASSES = (…, "fluentd_error", "scenario_run")
+STREAM_CLASSES = (…, "fluentd_error", "scenario_run", "remediation_event")
+    "silver.remediation_event": ("remediation_event",),
-GOLD_DATASETS = (…, "gold.rca_link", "gold.scenario_link")
+GOLD_DATASETS = (…, "gold.rca_link", "gold.scenario_link", "gold.remediation_link")
+REMEDIATION_LINK_BASES = ("rca_remediation_id",)
+REMEDIATION_LINK_STATUSES = ("linked", "no_remediation_id", "events_not_found", "cross_check_failed")
+REMEDIATION_STATUSES = ("complete", "partial", "unlinked")
+REMEDIATION_PARTIAL_REASONS = ("window_open", "acquisition_incomplete", "beyond_window")
+POLICY_DECISION_LINKS = ("unlinked_no_key",)
+RECORD_STATES_UNSETTLED / RECORD_STATES_SETTLED, REMEDIATION_TIMELINE_EVENTS, REMEDIATION_BLOCK_EVENTS
 ## contracts/schemas.py
+DOC_TABLES["silver.remediation_event"], DOC_TABLES["gold.remediation_link"], DOC_TABLES["silver.rca_result"] += remediation_id
+SCHEMA_VERSIONS = {"silver.rca_result": "1.1"}; schema_version(dataset)
```

`LINK_STATUSES`(`gold.scenario_link`)와 `REMEDIATION_LINK_STATUSES`는 컬럼 이름(`link_status`)이 같지만 데이터셋별 어휘다.

## 8. 테스트와 fixture

테스트(먼저 작성, `aiops/dataplatform/tests/test_remediation.py`):

1. Bronze: chunk 분할(≤15분, 빈틈·겹침 없음, 기본 6개, 끝 = anchor+80m+pad), DQ-B07 위반 시 plan 거부, selector 2종 문자열, global scope·binding null, 열린 chunk만 재획득.
2. Silver: `remediation_event` 정규화(레코드 이벤트·`manual_approval_executed`·`policy_decision`·본문 시각 실패 fallback·비JSON quarantine), `rca_result` 1.1 `remediation_id`, coverage가 chunk 획득을 모으는지.
3. Gold: `link_status` 4종, 교차 검증 실패 시 상세 null, `policy_decision`이 Gold에 안 붙음, `remediation_status`(`window_open`·`acquisition_incomplete`·`beyond_window`·`complete`), DQ-G10~G12 위반 시 commit 거부.
4. fixture 이력(03:20·04:32 build)과 E2E(`phases.run_all` → validate). 기존 테스트의 fixture 숫자(Bronze 16→28, RCA 1→4, 현재 Gold)는 함께 갱신했다.

fixture([examples/db-connection-limit](examples/db-connection-limit/)): 입력 `03_remediation_events.jsonl`(Remediation·timeline Loki entry, 합성)을 mock 원천이 서빙하고, 파생값은 `tests/tools/regen_fixture.py`가 계산한다.

| RCA (`rca_time`) | handoff → `remediation_id` | 이벤트 | 03:40 build (창 열림) | 04:32 재획득 build |
|---|---|---|---|---|
| 03:00:58 `NOTIFY` (기존) | `deferred_…` → 없음 | — | `no_remediation_id` · `unlinked` | 같음 |
| 03:01:28 `KILL_SESSIONS` db | `approval_pending` → A | 승인 요청 → 승인·실행 → `VERIFIED` | `linked` · `partial[window_open]` | `linked` · `complete` |
| 03:03:58 `THROTTLE` backend | `approval_pending` → B (이전 firing의 기존 레코드) | `alert_active_at=02:54:30.208Z` | `cross_check_failed` · `unlinked` | 같음 |
| 03:05:28 `PAUSE` backend | `approval_pending` → C | 승인·실행 → TTL 04:07 `RECOVERY_APPROVAL_REQUIRED`, 복구 승인 04:26(창 밖, Bronze에 없음) | `linked` · `partial[window_open]` | `linked` · `partial[beyond_window]` |

- 1회차(03:20) 획득은 chunk 1만 닫혀 있다. mock은 획득 시각 이후 entry를 돌려주지 않는다(`FixtureSources.now_ns`).
- 04:32 실행이 §9.1 절차다: 같은 요청으로 다시 획득 → 닫힌 획득은 재사용, 열린 chunk 2~6만 다시 질의(10건) → `silver.remediation_event`·Gold 재빌드. 이 Gold가 현재 build다.

## 9. 의존성과 충돌 지점

| 항목 | 내용 |
|---|---|
| D-1 fixture 기준선 | #70(PR #76) 병합 — `incident_class` 반영 |
| D-2 scenario_link | #71(PR #83) 병합 — enums·schemas·fixture를 그 위에서 바꿨다 |
| D-3 #69 사건 자동 발견 | discover는 획득 창 종료+10분(≈anchor+16분)에 한 번만 trigger한다. remediation chunk 대부분은 그때 열려 있어 `partial(window_open)`이 된다. **결정: #69에 두 번째 trigger를 넣지 않는다.** 평가에 쓰는 사건은 §9.1 문서 절차로 처리한다. `partial(window_open)` 사건을 창 종료 뒤 자동으로 다시 획득하는 일반 규칙은 나중에 별도 Issue(아직 만들지 않음) |
| D-4 Remediation 이벤트 필드 보강 | #81(PR #84) 병합됨. `policy_decision`(`remediation_id`·`alert_starts_at`)과 `rejected_by`·`plan_id`를 Gold에 쓰는 것은 DEC-19 개정으로 따로 한다(별도 Issue). 그때까지 `remediation_id`가 있어도 `policy_decision`은 연결하지 않고 `policy_decision_link=unlinked_no_key`다. fixture 이벤트는 #81 전 형식이다 |

### 9.1 평가 전 재획득 → Gold 재빌드 (D-3 절차)

`gold.scenario_link`의 평가 전 절차([aiops/dataplatform/README.md](../../aiops/dataplatform/README.md) "시나리오 실행 기록 연결")와 같은 방식이다. 자동 실행은 없다(수동 conf 1회).

1. 평가할 사건의 `gold.remediation_link`에 `partial_reasons ∋ window_open`이 있는지 본다.
2. remediation 창이 닫힐 때까지 기다린다: `requested_at ≥ remediation_window_end + lateness_margin` = 기본 **anchor + 81m + 600s ≈ anchor + 91분**.
3. 같은 사건 요청으로 `dp_bronze_acquire`를 다시 실행한다. `force_reacquire`는 필요 없다 — 닫힌 획득은 재사용되고 열렸던 chunk만 다시 질의된다. 시나리오 실행 기록도 함께 갱신하려면 그 절차의 `stream_classes`에 `remediation_event`를 더해 한 번에 한다.
4. Silver·Gold가 입력 변경을 감지해 새 build를 만든다(이전 build는 보존, 03 §4). 새 build에서 `window_open`이 빠졌는지 확인하고, 남은 `beyond_window`는 그대로 평가 기록에 둔다.

```sh
docker exec dp-airflow airflow dags trigger dp_bronze_acquire --conf '{…요청…, "stream_classes": ["remediation_event"]}'
```
