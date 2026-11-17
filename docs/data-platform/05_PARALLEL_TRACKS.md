# 05. 병렬 개발 구조 — Track A~D

> 상태: **STEP 0 제안**. 아래 경로는 모두 **신규**이며 아직 만들지 않았다. 승인 전에는 어떤 Track도 구현을 시작하지 않는다.

## 1. 단계와 의존성

```text
STEP 0  공통 계약 문서 (이 문서 세트)  ── 사용자 검토·승인 게이트
   │
STEP 0.5 계약 코드 스켈레톤 + 공유 Mock fixture  (1 PR, 2인 리뷰)
   │      contracts/ · storage/ · lineage 레코드 writer · tests/fixtures 로더
   ├──────────────┬──────────────┬──────────────┐
Track A        Track B        Track C        Track D          ← 병렬 (각자 worktree·브랜치·PR)
Bronze         Silver         Gold+Lineage   Airflow+검증
   │  (fixture만 사용, 서로의 구현에 의존하지 않음)  │
   └──────────────┴──────┬───────┴──────────────┘
                 통합 E2E (Track D 소유, A→B→C를 fixture HTTP로 연결)
                         │
                 공유 파일 PR (Track D: run_isolated suite, CI matrix, 라벨) ── 사용자 승인
                         │
                 실환경 활성화 (binding 인수 이후, 사용자 승인) ── 이번 범위 밖
```

**병렬 가능 여부: 가능.** 단, STEP 0.5가 선행되어야 한다. STEP 0.5 없이 시작하면 네 Track이 해시·ID·manifest 형식을 각자 구현해 계약이 갈라진다.

Track 간 런타임 의존은 **저장소의 데이터 계약(Parquet 스키마 + manifest)** 하나뿐이다. 함수 호출로 서로를 import하지 않는다(Track D만 각 Track의 진입점 함수를 호출).

## 2. 디렉터리 구조 (제안)

```text
aiops/dataplatform/
  README.md                      STEP 0.5
  requirements.txt               STEP 0.5 (DEC-02 결정 후)
  contracts/                     STEP 0.5 — 동결. 변경은 "계약 변경 PR"(전 Track 리뷰)
    __init__.py
    canonical.py                 C-1/C-2 canonical_json, h(), ID 생성
    enums.py                     stream_class, 상태, 플래그, relation 어휘
    schemas.py                   데이터셋별 컬럼 명세 (이름·타입·null) — 01 문서의 코드판
    pipeline_compat.py           aiops/pipeline 모듈 read-only 로딩 (identity, correlation, log_line …)
  storage/                       STEP 0.5
    store.py                     ObjectStore 프로토콜 · LocalFsStore · S3Store
    manifest.py                  manifest 쓰기/읽기·commit·current 포인터
    lineage_writer.py            run/edge 레코드 직렬화 (생산은 각 Track)
  bronze/                        Track A
  silver/                        Track B
  gold/                          Track C
  lineage/                       Track C (질의·무결성 검증·추적 CLI)
  orchestration/                 Track D (DAG가 부르는 순수 task 함수, 설정)
  airflow/dags/                  Track D
  tests/
    fixtures/                    STEP 0.5 — docs/data-platform/examples를 읽는 로더만 (복사 금지)
    contracts/                   STEP 0.5
    bronze/  silver/  gold/  lineage/  orchestration/  e2e/   각 Track
docker-compose.dataplatform.yml  Track D (신규 파일, 기존 Compose 미수정)
deploy/dataplatform/             Track D (MinIO 정책·Airflow env 예시, 비밀값 없음)
```

`aiops/` 아래에 두는 이유: Pipeline/Remediation과 같은 서비스 계층이고 `aiops/pipeline` 모듈을 재사용한다. 단, 현재 라벨 자동 분류에 `aiops/dataplatform/*` 규칙이 없어 PR 영역 라벨이 붙지 않는다(DEC-13).

## 3. 파일 소유권

| 경로 | 소유 | 다른 Track |
|---|---|---|
| `docs/data-platform/**` | STEP 0 (이 PR) | 읽기만. 변경은 계약 변경 PR |
| `aiops/dataplatform/contracts/**`, `storage/**`, `tests/fixtures/**`, `tests/contracts/**` | STEP 0.5 | 읽기·import만 |
| `aiops/dataplatform/bronze/**`, `tests/bronze/**` | **A** | 금지 |
| `aiops/dataplatform/silver/**`, `tests/silver/**` | **B** | 금지 |
| `aiops/dataplatform/gold/**`, `lineage/**`, `tests/gold/**`, `tests/lineage/**` | **C** | 금지 |
| `aiops/dataplatform/orchestration/**`, `airflow/**`, `tests/orchestration/**`, `tests/e2e/**`, `docker-compose.dataplatform.yml`, `deploy/dataplatform/**` | **D** | 금지 |

### 3.1 공유 기존 파일 — 동시 수정 금지

| 기존 파일 | 필요한 변경 | 단일 소유·시점 |
|---|---|---|
| `testing/run_isolated.py` | `SUITES`에 `"dataplatform"` 1줄 | D, A~C 병합 후 |
| `.github/workflows/project-tests.yml` | matrix·의존성 설치 | D, 위와 같은 PR, `area:github` 리뷰 |
| `.github/labels.json`, `.github/scripts/collaboration_labels.py` | `area:data-platform`(DEC-13) | D 또는 github 담당, 별도 PR |
| `.gitignore` | `.lake/` 로컬 저장소 무시 | STEP 0.5 |
| `aiops/pipeline/**`, `leafy/fluentd/**`, `monitoring/**`, `aiops/remediation/**`, `docker-compose.aiops.yml` | **변경 없음** | 어떤 Track도 수정 금지 |

### 3.2 `aiops/pipeline` 재사용 방식

Pipeline 모듈은 패키지가 아니라 `from identity import …`처럼 **작업 디렉터리 기준 import**를 쓴다. 수정 없이 재사용하려면 `contracts/pipeline_compat.py`가 `aiops/pipeline`을 `sys.path`에 넣고 모듈을 읽어온다(쓰기 없음, `-B`/`PYTHONDONTWRITEBYTECODE`). `correlation.py`와 collector는 `httpx`를 import하므로 런타임에 `httpx`가 필요하다. 사설 함수(`network_section._aggregate`)는 import하지 않고 의미를 이식한 뒤 **파리티 테스트**(같은 입력 → 같은 출력)로 고정한다. 파이프라인 코드가 바뀌면 파리티 테스트가 깨져 알린다.

## 4. 공통 인터페이스 (STEP 0.5에서 시그니처 동결)

```python
# 모든 진입점은 순수 함수. 네트워크·시계·저장소는 인자로 주입한다.
RunContext(run_id, orchestrator, dag_id, airflow_run_id, task_id, try_number, map_index, code_version, git_sha, git_dirty, now)

# Track A
plan_incident(request: IncidentRequest, bindings: tuple[ObservationBinding, ...]) -> list[AcquisitionPlanItem]
acquire(item: AcquisitionPlanItem, store: ObjectStore, run: RunContext, transport: httpx.BaseTransport) -> ManifestRef

# Track B
build_silver(dataset: str, coverage: Coverage, inputs: list[ManifestRef], store: ObjectStore, run: RunContext) -> ManifestRef

# Track C
build_gold(incident: IncidentRef, silver_inputs: dict[str, list[ManifestRef]], acquisitions: list[ManifestRef],
           store: ObjectStore, run: RunContext) -> ManifestRef
trace(store: ObjectStore, dataset: str, key: str) -> LineageGraph

# Track D
validate(store: ObjectStore, manifests: list[ManifestRef]) -> ValidationReport
```

## 5. Track별 상세

### Track A — Bronze Ingestion & Persistence

| 항목 | 내용 |
|---|---|
| 책임 | 사건 요청 → 획득 plan → Loki/Prometheus 읽기 질의 → raw page·Bronze Parquet·acquisition 행 → manifest commit → (연속 모드) checkpoint |
| 범위 | 페이지네이션, series·lookback preflight, 반환 label 검증, 금지 스트림 차단, 지연 허용·`window_closed`, `force_reacquire`, 부분 실패 보존. **제외**: 해석·dedup(B), Airflow(D) |
| 입력 | `IncidentRequest`([examples/00](examples/db-connection-limit/00_incident_request.json)), `OBSERVATION_BINDINGS` JSON(Pipeline과 **같은 값**), Loki/Prometheus HTTP |
| 출력 | `bronze.acquisition`, `bronze.loki_entry`, `bronze.prometheus_sample`, raw page, manifest |
| 재사용 | `identity.parse_bindings/selector/matches`, `correlation.to_instant/CorrelationContext/network_event_selectors`, collector 쿼리 템플릿(메트릭 쿼리 문자열 파리티) |
| 의존 | STEP 0.5만 |
| Mock | `httpx.MockTransport`가 fixture의 raw page를 반환. 페이지 실패·timeout·label 불일치·빈 응답을 주입 |
| 테스트 | ① fixture 요청 → `10/11/12_*.jsonl`과 같은 행(acquisition_id·시각 제외) ② limit 3 페이지네이션 경계 중복 제거 ③ 2페이지 timeout → `partial` + 받은 행 보존 ④ series absent → `empty_unverified` ⑤ binding 없음 → 질의 0회 + `scope_unavailable` ⑥ `network-experiment` 요청 거부 ⑦ 메트릭 쿼리 문자열 = `MetricsCollector` 생성 문자열 ⑧ 같은 ns entry `L+1`개 + 이후 entry → 무한 반복 없이 `truncated`/`same_ts_overflow`, 받은 `L`행 보존 |
| 완료 기준 | 위 테스트 PASS, DQ-B01~B06 구현, 실제 HTTP 0회(격리 실행기), 기존 Pipeline 테스트 변화 없음 |

### Track B — Silver Transformation & Quality

| 항목 | 내용 |
|---|---|
| 책임 | Bronze → Silver 8개 데이터셋, label profile 판별, 시각 정규화, dedup, 기존 플래그 승계, quarantine, Silver→Bronze edge |
| 범위 | 01 §3 전체, DQ-S01~S06. **제외**: 사건 창 필터·scope 매칭(C) |
| 입력 | Bronze manifest 목록(coverage 단위) |
| 출력 | `silver.*` Parquet, quarantine, edge, manifest, current 포인터 |
| 재사용 | `log_line.is_priority`, `correlation.to_instant`, `LLMAnalysisResult`, Network dedup 의미 |
| 의존 | STEP 0.5. Track A 구현에는 의존하지 않음(fixture Bronze 사용) |
| Mock | `11_bronze_loki_entry.jsonl`·`12_bronze_prometheus_sample.jsonl` → LocalFsStore Parquet로 적재하는 fixture 로더 |
| 테스트 | ① fixture Bronze → `20~27_silver_*.jsonl`과 일치 ② 같은 record_key 2건 → 1행 `_dup_count=2` ③ JST 시각 → `receiver_fallback` ④ schema_version 2.0 → quarantine ⑤ legacy label → `source=UNKNOWN` ⑥ 모든 Bronze 행이 edge 또는 quarantine로 설명됨 |
| 완료 기준 | 위 테스트 PASS, PK 유일, 재실행 시 동일 내용 해시 |

### Track C — Gold RCA Evidence Mart & Lineage

| 항목 | 내용 |
|---|---|
| 책임 | 사건 창·scope 매칭, 채널 상태 규칙, evidence 3종(log/metric/flow), rca_link, Gold→Silver edge, 리니지 질의·무결성 검증 |
| 범위 | 01 §4, 03 전체, 04 §4·§5·DQ-G/L. **제외**: LLM 호출(DEC-07) |
| 입력 | Silver manifest(사건 coverage), 해당 Bronze acquisition manifest(상태 계산용), bindings |
| 출력 | `gold.*`, edge, manifest, `current/gold/{incident_id}` |
| 재사용 | `render_log_line`, `mask_secrets`, `PolicyEvaluator`, collector의 endpoint 검증 규칙, `network_section` 집계 의미 |
| 의존 | STEP 0.5. Track B 구현에는 의존하지 않음(fixture Silver 사용) |
| Mock | `20~27_silver_*.jsonl` + `10_bronze_acquisition.jsonl` |
| 테스트 | ① fixture → `30~35_gold_*.jsonl` 일치 ② `rendered_line` = 기존 함수 출력(`60_realtime_parity.json`) ③ db host network → `unavailable/host_target_field_absent`, skipped 2 ④ 같은 Silver 이벤트가 related flow에는 사용됨(다대다) ⑤ 재빌드 → 새 gold_build_id, evidence_id 동일, 이전 build 보존 ⑥ trace(evidence) → Bronze acquisition·query·run 도달 |
| 완료 기준 | 위 테스트 PASS, DQ-G01~G07·DQ-L01 구현 |

### Track D — Airflow Orchestration & Validation

| 항목 | 내용 |
|---|---|
| 책임 | DAG, task 래퍼, 설정 주입, pool·동시성, `dp_validate`, 통합 E2E, 데이터 플랫폼 Compose(신규), CI/공유 파일 PR |
| DAG | `dp_incident_build`(conf=IncidentRequest 또는 discovery) · `dp_incident_discover`(Silver `rca_result`에서 새 사건 찾기, 기본 off) · `dp_reprocess`(수동, 범위·사건 지정) · `dp_validate`(일 1회: manifest 무결성, orphan, DQ 규칙, 리니지 커버리지) |
| 입력 | 각 Track 진입점, 설정(엔드포인트·버킷·binding 경로·지연값) |
| 출력 | `lineage.run`, 검증 보고서, Airflow 실행 기록 |
| 의존 | STEP 0.5 시그니처. A~C 구현 전에는 **stub 진입점**(fixture manifest를 그대로 commit)으로 DAG 구조를 개발 |
| Mock | Airflow 없이 `orchestration/` task 함수를 직접 호출하는 단위 테스트, DAG 파일은 import·구조 검사만 |
| 테스트 | ① DAG import·task 순서 ② retry 시 같은 coverage가 새 build로 끝나고 이전 것 보존 ③ 실패 task → manifest 미생성 ④ `git_dirty=true`면 운영 DAG 거부 ⑤ E2E: fixture HTTP → A → B → C → validate PASS |
| 완료 기준 | 위 테스트 PASS, Compose 파일 `docker compose config` 문법 검사만(기동 금지), 실시간 경로 비간섭 체크리스트(§6) 충족 |

## 6. 실시간 경로 비간섭 보장 (Track D 완료 기준에 포함)

| 위험 | 보장 |
|---|---|
| Alertmanager → Pipeline 경로 | `alertmanager.yml` 수신기·route 변경 없음. Airflow는 경보를 받지 않는다(사건은 Loki `aiops-llm` 또는 수동 conf로 발견) |
| Loki/Prometheus 부하로 Ruler 평가 지연 | pool 1, 요청 창 ≤15분, timeout 30s, 페이지 간 지연, 사건 창 종료 + 10분 뒤 실행 |
| Ollama 경합 | v1은 LLM을 호출하지 않는다. `OLLAMA_NUM_PARALLEL=1`, `OLLAMA_MAX_QUEUE=1`이라 배치 호출은 실시간 요청을 거부시킬 수 있다(DEC-07 전제) |
| JH 자원 경합 | Airflow·MinIO 컨테이너에 CPU·메모리 상한, LocalExecutor 동시성 1~2 |
| 장애 전파 | 기존 Compose와 `depends_on`·공유 volume 없음. 데이터 플랫폼 중단은 실시간 RCA에 무영향 |
| 쓰기 | 데이터 플랫폼은 Loki/Prometheus/AM에 **쓰지 않는다**(push 금지) |

## 7. 일정상 주의

- 실데이터 적재는 OI-09 BLOCKED 항목(binding 실값, Loki site/target label, 원격 메트릭 경로)이 풀려야 가능하다. 그 전에는 fixture와 합성 HTTP로만 완료를 판정한다.
- 각 Track은 **실행한 테스트만 PASS로 기록**한다(AGENTS.md). Airflow/MinIO 실제 기동 검증은 사용자 승인 후 별도 단계다.
