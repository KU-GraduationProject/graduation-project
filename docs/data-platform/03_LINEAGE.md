# 03. Data Lineage 설계

> 상태: **STEP 0 제안**. 목표: 어떤 Gold 근거·RCA 결과든 **원천 시스템·관측 대상·Bronze 원문 행·변환 코드 버전·Airflow 실행**까지 질의 하나로 역추적한다.

## 1. 추적 대상과 저장 위치

| 추적 항목 | 저장 위치 | 키 |
|---|---|---|
| 원천 시스템·관측 대상 | `bronze.acquisition` (`source_system`, `api`, `query_text`, `scope_identity`, `scope_selector`, `binding_sha256`) | `acquisition_id` |
| Bronze 원천 레코드 | `bronze.loki_entry` / `bronze.prometheus_sample` + raw page (`raw_sha256`) | `bronze_id` (페이지·행 위치 포함) |
| Silver 결과와 부모 레코드 | `lineage.edge` (`normalized_from`, `quarantined_from`) | (child, parent) |
| Gold 집계에 사용한 Silver 레코드 | `lineage.edge` (`selected_from`, `aggregated_from`, `anchored_on`, `linked_from`) | 다대다 |
| 변환 코드 버전·Git SHA | `lineage.run` + manifest (`code_version`, `git_sha`, `git_dirty`, `image_ref`) | `run_id` |
| Airflow 실행 ID | `lineage.run` (`dag_id`, `airflow_run_id`, `task_id`, `try_number`, `map_index`) | `run_id` |
| 데이터셋 버전 | manifest (`build_id`, `inputs`, `supersedes`) → DuckDB view | `manifest_id` |
| LLM RCA ↔ Gold 버전 | `gold.rca_link`(v1) / `lineage.rca_input`(DEC-07) | (`rca_id`, `gold_build_id`) |

## 2. `lineage.run`

| 컬럼 | 타입 | Null | 설명 |
|---|---|---|---|
| `run_id` | string | N | PK (01 §1.1) |
| `orchestrator` | string | N | `airflow` · `local_cli` · `test` |
| `dag_id`,`airflow_run_id`,`task_id` | string | Y | Airflow가 아니면 null (`local_cli`는 `airflow_run_id`에 UUID) |
| `try_number` | int32 | Y | |
| `map_index` | int32 | Y | dynamic task mapping |
| `code_version` | string | N | `aiops/dataplatform` 패키지 semver |
| `git_sha` | string | N | 40자. 이미지 빌드 시 주입. 알 수 없으면 실행 거부(`unknown` 저장 금지) |
| `git_dirty` | bool | N | 미커밋 변경으로 만든 이미지면 true → 운영 DAG는 거부 |
| `image_ref` | string | Y | 컨테이너 이미지 digest |
| `params` | string(JSON) | N | 실행 파라미터(C-1). **비밀값 제외** |
| `started_at`,`ended_at` | timestamp | N / Y | |
| `status` | string | N | `success` · `failed` · `partial` |
| `_schema_version` | string | N | `1.0` |

## 3. `lineage.edge` — 레코드 단위 다대다

| 컬럼 | 타입 | Null | 설명 |
|---|---|---|---|
| `edge_id` | string | N | `h([child_dataset, child_key, child_version, parent_dataset, parent_key, parent_version])[:32]` |
| `child_dataset`,`child_key`,`child_version` | string | N | version = 그 행의 build id |
| `parent_dataset`,`parent_key`,`parent_version` | string | N | Bronze의 version = `acquisition_id` |
| `relation` | string | N | 아래 표 |
| `run_id` | string | N | edge를 만든 실행 |
| `_schema_version` | string | N | `1.0` |

| relation | child ← parent | 카디널리티 |
|---|---|---|
| `normalized_from` | silver 행 ← bronze 행 | 1 ← N (중복 병합) |
| `quarantined_from` | silver.quarantine ← bronze 행 | 1 ← N |
| `anchored_on` | gold.incident ← silver.alert_event | 1 ← 1 |
| `selected_from` | gold.evidence_log ← silver 로그 행 | 1 ← 1 |
| `aggregated_from` | gold.evidence_metric / evidence_network_flow ← silver 행 | 1 ← N |
| `linked_from` | gold.rca_link ← silver.rca_result | 1 ← 1 |

- **다대다**: Silver 한 행은 겹치는 여러 사건의 Gold에 동시에 쓰일 수 있고(사건 창 겹침, primary/related 동시 사용), Gold 한 행은 여러 Silver 행을 집계한다. edge 테이블이 두 방향을 모두 표현한다.
- Raw page → Bronze 행은 `bronze_id`에 `{acquisition_id}:{page}:{row}`가 들어 있어 edge를 따로 만들지 않는다.
- edge 파일은 그 build의 manifest `outputs`에 포함된다(데이터와 원자적 commit, [02](02_STORAGE_DESIGN.md) §4).
- 사건 창 단위라 edge 수는 사건당 수백~수천 수준으로 예상한다. 실측 후 조정(연속 모드는 partition 단위 edge 요약으로 바꿀 수 있음, DEC-05).

## 4. 재처리와 버전 보존

| 상황 | 동작 | 남는 것 |
|---|---|---|
| 같은 코드로 같은 사건 재빌드 | 새 `gold_build_id`. 내용 해시가 같으면 no-op로 종료(선택) | 이전 build 그대로 |
| 코드 변경(git_sha 변경) | 새 Silver/Gold build, `current` 포인터 이동, manifest `supersedes`=이전 | 이전 build·edge·run 보존 |
| 지연 도착 데이터 | 새 Bronze 획득 → 해당 coverage Silver 재빌드 → Gold 재빌드 | 이전 획득·build 보존 |
| binding 변경 | `binding_sha256`이 달라진 새 획득. 이전 획득과 섞지 않고 새 coverage | 이전 coverage 보존 |
| PK 도출식 변경 | **MAJOR** → `v2/` 경로의 새 데이터셋 | `v1` 전체 보존 |

`gold.rca_link`와 `lineage.rca_input`은 항상 **특정 `gold_build_id`**를 가리킨다. 재빌드 뒤에도 "이 RCA가 그때 본(또는 같은 사건의) Gold 버전"이 바뀌지 않는다.

## 5. LLM RCA 결과와 Gold의 관계

| 경로 | 현재 | 리니지 표현 |
|---|---|---|
| 실시간 RCA (Alertmanager → Pipeline → LLM) | **Gold를 쓰지 않는다**. 근거는 실시간 collector 조회 | `gold.rca_link.link_type = post_hoc_same_alert`. 같은 `alert_event_id`에 사후 연결. "이 RCA는 이 Gold를 보고 판단했다"는 뜻이 아님 |
| Gold 기반 배치 RCA | **없음** (DEC-07) | `lineage.rca_input`에 `gold_build_id`, `gold_manifest_id`, `prompt_sha256`, `model`, `llm_options`, `prompt_builder_version` 기록 후 `link_type = consumed_gold` |

`lineage.rca_input` (DEC-07 승인 전에는 생산자 없음):

| 컬럼 | 타입 | Null |
|---|---|---|
| `rca_id`,`incident_id`,`gold_build_id`,`gold_manifest_id` | string | N |
| `prompt_sha256`,`model`,`prompt_builder_version` | string | N |
| `llm_options` | string(JSON) | N |
| `created_at` | timestamp | N |
| `_schema_version` | string | N |

## 6. 대표 리니지 질의

```sql
-- Gold 근거 1건 → Silver → Bronze → 원천 질의·관측 대상
WITH RECURSIVE up AS (
  SELECT child_dataset, child_key, parent_dataset, parent_key, parent_version, 1 AS depth
  FROM edge WHERE child_dataset = 'gold.evidence_network_flow' AND child_key = :evidence_id
  UNION ALL
  SELECT e.child_dataset, e.child_key, e.parent_dataset, e.parent_key, e.parent_version, up.depth + 1
  FROM edge e JOIN up ON e.child_key = up.parent_key AND e.child_dataset = up.parent_dataset
)
SELECT up.*, a.source_system, a.query_text, a.scope_identity, a.binding_sha256, r.git_sha, r.airflow_run_id
FROM up
LEFT JOIN bronze_acquisition a ON up.parent_dataset LIKE 'bronze.%' AND a.acquisition_id = up.parent_version
LEFT JOIN run r ON r.run_id = a.run_id;
```

```sql
-- Silver 한 행이 쓰인 모든 사건 (영향 분석)
SELECT DISTINCT g.incident_id, e.child_dataset, e.child_version
FROM edge e JOIN gold_incident g ON g.gold_build_id = e.child_version
WHERE e.parent_dataset = 'silver.network_event' AND e.parent_key = :network_event_id;
```

## 7. 리니지 무결성 규칙 (Track C 검증기)

- 모든 Silver 행과 quarantine 행은 ≥1개의 Bronze 부모 edge를 가진다.
- 모든 Bronze 행은 정확히 하나의 Silver 행 또는 quarantine 행의 부모다(같은 coverage의 현재 build 기준). 사건 창 밖 패딩 영역의 행도 Silver에 들어가므로 예외가 없다.
- 모든 Gold evidence·rca_link·incident 행은 ≥1개의 Silver 부모 edge를 가진다.
- edge의 `parent_version`은 해당 build manifest의 `inputs` 체인 안에 있어야 한다.
- `lineage.run.git_sha`는 40자 hex, `git_dirty=false`(운영 DAG).
