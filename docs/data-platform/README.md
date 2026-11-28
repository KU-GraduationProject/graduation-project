# Leafy AIOps Data Platform — STEP 0 공통 계약

> 상태 (2026-11-28, `origin/main` @ `6382aef` 기준). 구현 세부와 구현 중 결정은 [aiops/dataplatform/README.md](../../aiops/dataplatform/README.md)를 따른다.
>
> **구현됨** — [aiops/dataplatform/](../../aiops/dataplatform/)
> - STEP 0 계약 문서·합성 fixture: 이 디렉터리, [examples/](examples/) (#36, PR #37)
> - Airflow Phase별 DAG와 오케스트레이션: `airflow/dags/`, `orchestration/` (#38, PR #39)
> - 계약 코드·저장소와 Bronze·Silver·Gold·Lineage·mock 원천: `contracts/`, `storage/`, `bronze/`, `silver/`, `gold/`, `lineage/`, `mock_sources/` (#40, PR #42)
> - DAG를 실제 진입점(`orchestration/phases.py`)에 연결, mock 원천으로 E2E 확인 (#41, PR #43)
> - 사건 자동 발견·배치 스케줄: `orchestration/discover.py`, `airflow/dags/dp_incident_discover.py` (#68, PR #69)
> - fixture RCA envelope를 현재 LLM 출력 형식에 맞춤: `silver/normalize.py`, [examples/](examples/) (#70, PR #76)
> - fixture LLM 출력 기대값에 `target_evidence` 반영 (#79, PR #80)
> - Gold 사건과 시나리오 실행 기록 연결(`gold.scenario_link`): `gold/build.py`, [01](01_DATA_CONTRACT.md) §4.7 (#71, PR #83)
> - Gold 사건과 Remediation 조치 기록 연결(`gold.remediation_link`, DEC-19): Bronze `remediation_event` chunk 획득 → `silver.remediation_event` → Gold, [09](09_REMEDIATION_LINK.md) (#77)
>
> **미구현**
> - 정책 결정(`policy_decision`)과 조치의 1:1 연결: 연결 키는 #81(PR #84)로 생겼으나 Gold 연결은 DEC-19 개정(별도 Issue). 그때까지 `policy_decision_link=unlinked_no_key`
> - remediation 창이 열린 채 만든 Gold(`partial_reasons ∋ window_open`)의 자동 재획득: 평가 전 수동 절차([09](09_REMEDIATION_LINK.md) §9.1)로 처리, 일반 규칙은 별도 Issue(미생성)
> - 실데이터 원천 연결: `DP_LOKI_URL`/`DP_PROMETHEUS_URL`을 주지 않으면 mock 원천을 읽는다. 실제 Loki/Prometheus 적재는 OI-09 binding이 풀린 뒤 사용자 승인 단계다 ([05](05_PARALLEL_TRACKS.md) §7)
> - Parquet codec·DuckDB(DEC-02, pyarrow 미설치), MinIO 저장소 어댑터(DEC-03, 현재 로컬 `LocalFsStore`)
>
> 00~08 계약 문서의 기준 코드는 STEP 0 작성 시점 `2117eaf`(최초 `0443c6f`, 2026-11-17 재검증 — [08](08_CONSISTENCY_REVIEW.md) §4)이다.

## 목표

기존 실시간 경로(Alertmanager → Pipeline → LLM)는 그대로 두고, 그 옆에 배치 데이터 플랫폼을 둔다.

```text
GC PC ──Tailscale──▶ JH Fluentd ─▶ Loki ─┐                 ┌─▶ (기존) Alertmanager → Pipeline → Ollama → Loki aiops-llm
                      Prometheus ◀─pull─┘ ├─ 읽기 전용 ─▶ Airflow ─▶ Bronze ─▶ Silver ─▶ Gold (RCA Evidence Mart)
                                          │                         (MinIO lake + Parquet, DuckDB 계산)
                                          └──────────── Lineage: 원천 질의 → Bronze 행 → Silver 행 → Gold 근거 → RCA 결과
```

## 문서

| 문서 | 내용 |
|---|---|
| [00_EXISTING_SYSTEM_ANALYSIS.md](00_EXISTING_SYSTEM_ANALYSIS.md) | 기존 수집·조회·상관·프롬프트·품질 분석, 기존/신규 구분 |
| [01_DATA_CONTRACT.md](01_DATA_CONTRACT.md) | 공통 규약, ID, Bronze/Silver/Gold 스키마 |
| [02_STORAGE_DESIGN.md](02_STORAGE_DESIGN.md) | MinIO 분리·버킷·경로·manifest·commit 순서·checkpoint·부분 실패 |
| [03_LINEAGE.md](03_LINEAGE.md) | run·edge·다대다·재처리 버전 보존·RCA 연결 |
| [04_DATA_QUALITY.md](04_DATA_QUALITY.md) | 획득·채널·사건 상태, 플래그 어휘, "없음 vs 실패", 품질 규칙 |
| [05_PARALLEL_TRACKS.md](05_PARALLEL_TRACKS.md) | STEP 0.5, Track A~D, 디렉터리·파일 소유권, 실시간 비간섭 |
| [06_ISSUE_DRAFTS.md](06_ISSUE_DRAFTS.md) | Issue 초안 6건 (생성 안 함) |
| [07_MOCK_DB_INCIDENT.md](07_MOCK_DB_INCIDENT.md) | DB 연결 슬롯 고갈 Mock 입력·출력 계약 |
| [08_CONSISTENCY_REVIEW.md](08_CONSISTENCY_REVIEW.md) | 기존 문서·코드 불일치, 이 문서 세트의 자체 검증 결과 |
| [09_REMEDIATION_LINK.md](09_REMEDIATION_LINK.md) | Gold 사건 ↔ Remediation 조치·승인·복구 연결(DEC-19): 원천 사실, chunk 획득, 판정 규칙, 평가 전 재획득 절차 |
| [examples/db-connection-limit/](examples/db-connection-limit/) | 합성 fixture (Bronze → Silver → Gold → Lineage) |

표기: **[기존]** 저장소에 구현됨 · **[후보]** 저장소에 있으나 운영 mount 안 됨 · **[신규]** 이번에 새로 만들 것.

## 위치 선택

`docs/` 아래 기존 주제별 디렉터리(`network-observability/`, `rulepack/`, `scenarios-v2/`)와 같은 방식으로 `docs/data-platform/`에 두었다. 충돌하는 기존 경로는 없다.

## 구현 전 결정 사항 (DEC)

### STEP 0.5 착수 전

| ID | 결정 | 제안 |
|---|---|---|
| DEC-01 | 코드 위치 | `aiops/dataplatform/` (05 §2) |
| DEC-02 | 의존성 | `pyarrow`(Parquet·S3 FS) + `duckdb`(계산). DuckDB `httpfs`는 런타임 다운로드가 필요할 수 있어 오프라인 번들 또는 pyarrow로 읽기. 버전 고정. Airflow 이미지와 Python 버전 정합(CI 3.11) |
| DEC-03 | Lake 저장소 이미지 | Leafy는 MinIO 공식 배포 중단으로 소스 빌드 이미지(`gicks/minio:RELEASE.2025-09-07…`)를 쓴다([docker-compose.yml:175-176](../../docker-compose.yml#L175-L176)). 같은 이미지로 **별도 인스턴스**를 쓸지, 다른 S3 호환 저장소를 쓸지, 당분간 `LocalFsStore`만 쓸지 결정. 조건부 쓰기 지원 여부 확인 |
| DEC-13 | `area:data-platform` 라벨 | 추가 권장. 없으면 `aiops/dataplatform/*` PR에 영역 라벨이 자동으로 붙지 않음 |
| DEC-18 | 테이블 형식 | **결정됨: 자체 manifest 유지.** Delta Lake가 아니라 02의 자체 manifest·current 포인터·`supersedes`를 쓴다. 계약·fixture·검증이 manifest 기준이다([aiops/dataplatform/README.md](../../aiops/dataplatform/README.md) 결정 기록 DEC-18). 레코드 단위 lineage edge(03)는 별도로 둔다 |
| DEC-16 | 브랜치 이름 | **결정됨:** Issue #36 생성, 브랜치 `docs/36-data-platform-step0` |

### Track 착수 전

| ID | 결정 | 제안 |
|---|---|---|
| DEC-04 | Lake 컨테이너의 Loki/Prometheus 접근 | (a) 외부 네트워크 `leafy-aiops_aiops-net`에 읽기 목적으로 참가 (b) `host.docker.internal:3100/9090` loopback. 기존 Compose 수정 없이 둘 다 가능 |
| DEC-05 | 획득 모드 | v1은 **사건 단위만**. 연속 모드는 Prometheus 30일 보존 대비가 필요할 때 추가 |
| DEC-06 | 사건 scope | `alert_identity_only`(실시간 파리티) 기본 + 사건 요청에 **명시 선언한** related scope만 허용(fixture는 후자를 시험). 토폴로지 자동 추론은 하지 않음 |
| DEC-14 | Airflow 배치 | JH, LocalExecutor, 전용 메타DB(Leafy PostgreSQL과 무관), 자원 상한. 버전은 DEC-02와 함께 고정 |
| DEC-17 | 기본값 | 사건 창 ±5m, 획득 패딩 60s, 지연 허용 600s, Loki pool 1 |
| DEC-19 | Remediation 연결 | **결정됨(#77):** `silver.rca_result.remediation_id`로 정확히 잇는 것만 Gold에 연결(`link_basis=rca_remediation_id`, `alertname`·`alert_active_at==anchor_time` 교차 검증). 추정 연결 금지. `policy_decision` 등은 Silver에만 두고 Gold `policy_decision_link=unlinked_no_key`(#81 키를 쓰는 연결은 개정으로). remediation 창 `anchor−5m−pad ~ anchor+80m+pad`(승인 900s + 최대 ttl 3600s + 여유 300s, 상수)를 15분 이하 chunk로 획득, 창 밖 결과는 `partial(beyond_window)`. 열린 창은 자동 재trigger 없이 평가 전 재획득 → Gold 재빌드 절차로 처리([09](09_REMEDIATION_LINK.md) §9.1) |

### 이후 (v1 범위 밖)

| ID | 결정 |
|---|---|
| DEC-07 | Gold를 입력으로 하는 배치 RCA(LLM 호출) 도입 여부. `OLLAMA_NUM_PARALLEL=1`/`MAX_QUEUE=1`이라 실시간 RCA와 경합 |
| DEC-08 | 보존 기간(Bronze raw·대체된 build·orphan 삭제 승인 절차) |
| DEC-09 | 여러 경보를 한 사건으로 묶는 정책 (v1: 경보 episode = 사건) |
| DEC-10 | 경보 이력 원천 추가(Prometheus `ALERTS`, AM API 스냅샷, AM 추가 receiver — 마지막은 기존 파일 변경이라 별도 승인) |
| DEC-11 | Prometheus raw sample 획득(v1은 파리티 PromQL만) |
| DEC-12 | 소형 Parquet compaction |
| DEC-15 | Canonical Network Event에 `src_target`/`dst_target`(optional, v1.1 MINOR) 추가 제안 여부. **기존 계약 변경이므로 Network 담당 승인 필요.** 그 전까지 host 대상 Network 근거는 `unavailable/host_target_field_absent` |

## 승인 체크리스트

- [ ] 01 스키마·ID·시각 규약
- [ ] 02 저장소 분리와 commit 프로토콜
- [ ] 03 리니지와 RCA 연결 의미(`post_hoc_same_alert`)
- [ ] 04 상태 규칙과 "없음 vs 실패" 판정
- [ ] 05 파일 소유권과 STEP 0.5 선행
- [ ] DEC-01/02/03/13/16/18 결정
