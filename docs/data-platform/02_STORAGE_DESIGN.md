# 02. 저장소 설계 — MinIO + Parquet + DuckDB

> 상태: **STEP 0 제안**. 이 문서의 서비스·버킷·포트는 아직 존재하지 않는다. 설치·기동하지 않았다.

## 1. 후보 검토 결론

| 후보 | 판단 | 이유 |
|---|---|---|
| **MinIO (별도 인스턴스)** | 채택 제안 | S3 API라 로컬 FS 어댑터와 같은 key 레이아웃을 쓸 수 있다. JH에 이미 Docker가 있다. Leafy MinIO와 물리적으로 분리 가능 |
| **Parquet** | 채택 제안 | 컬럼 타입 고정(스키마 계약을 파일이 강제), 압축, DuckDB·pyarrow 직접 조회 |
| **DuckDB** | 채택 제안 (**계산 엔진으로만**) | Parquet 위의 SQL 변환·검증. `.duckdb` 파일은 진실 원천으로 쓰지 않는다(단일 writer 잠금, 공유 불가) |
| Loki/Prometheus 재사용 | 기각 | Loki retention 미설정·Prometheus 30d, 재처리 버전 보존 불가, 실시간 경로와 부하 공유 |
| Leafy MinIO 재사용 | 금지 | 사용자 요구사항. 앱 데이터와 권한·수명주기·장애 영역이 섞인다 |

## 2. Leafy MinIO와의 분리

| 항목 | Leafy MinIO (기존) | Data Lake MinIO (제안) |
|---|---|---|
| 위치 | GC PC (all-in-one은 같은 PC) | **JH PC** |
| container | `leafy-minio` | `lake-minio` |
| Compose | Leafy 앱 Compose / `docker-compose.yml` | 신규 `docker-compose.dataplatform.yml` (project `leafy-datalake`) |
| volume | `minio_data` | `lake_minio_data` |
| 자격증명 | `STORAGE_ACCESS_KEY/SECRET_KEY` | `LAKE_MINIO_ROOT_USER/PASSWORD` + 트랙별 서비스 계정 (재사용 금지) |
| 포트 | publish 안 함 | `127.0.0.1:19000`(API), `127.0.0.1:19001`(console). Tailscale·0.0.0.0 publish 금지 |
| 네트워크 | `leafy-net` | `datalake-net` (Loki/Prometheus 접근 방식은 DEC-04) |

기존 `docker-compose.aiops.yml`은 수정하지 않는다. 새 Compose는 기존 서비스에 `depends_on`을 걸지 않고, 기존 서비스도 새 Compose를 모른다 → 데이터 플랫폼이 죽어도 실시간 경로는 영향이 없다.

## 3. 버킷과 경로

버킷은 계층별로 나눠 서비스 계정 권한을 분리한다.

| 버킷 | 쓰기 권한 | 읽기 권한 | 내용 |
|---|---|---|---|
| `lake-bronze` | bronze-writer (Track A) | silver-writer, reader | 획득 원문·Bronze Parquet |
| `lake-silver` | silver-writer (Track B) | gold-writer, reader | Silver Parquet |
| `lake-gold` | gold-writer (Track C) | reader | Gold Parquet |
| `lake-meta` | 각 writer는 자기 layer prefix만 | 모두 | manifest, current pointer, checkpoint, lineage |

```text
lake-bronze/
  v1/acquisition/acq_date=YYYY-MM-DD/{acquisition_id}.parquet
  v1/loki_entry/stream_class={sc}/acq_date=YYYY-MM-DD/{acquisition_id}/part-0000.parquet
  v1/prometheus_sample/acq_date=YYYY-MM-DD/{acquisition_id}/part-0000.parquet
  raw/{loki|prometheus}/acq_date=YYYY-MM-DD/{acquisition_id}/page-0000.json.gz
lake-silver/
  v1/{dataset}/event_date=YYYY-MM-DD/{silver_build_id}/part-0000.parquet
  v1/quarantine/acq_date=YYYY-MM-DD/{silver_build_id}/part-0000.parquet
lake-gold/
  v1/{dataset}/incident_date=YYYY-MM-DD/{incident_id}/{gold_build_id}/part-0000.parquet
lake-meta/
  manifests/{bronze|silver|gold}/{build_id}.json          ← commit point
  current/silver/{dataset}/{coverage_id}.json             ← 최신 build 포인터
  current/gold/{incident_id}.json
  checkpoints/{plan_id_sha256}.json                       ← continuous 모드 전용
  lineage/v1/run/run_date=YYYY-MM-DD/{run_id}.parquet
  lineage/v1/edge/run_date=YYYY-MM-DD/{build_id}.parquet
```

- 날짜 partition은 **UTC**. 파티션 값은 파일 안 컬럼에도 그대로 있다(파일 단독으로 해석 가능).
- 모든 데이터 파일 경로에 고유 build id가 들어가므로 **어떤 파일도 덮어쓰지 않는다**.
- Parquet: `zstd`, 타임스탬프 `timestamp[us, tz=UTC]`, JSON은 string. 소형 파일 compaction은 범위 밖(DEC-12).

로컬 개발·테스트는 같은 key 레이아웃을 `LocalFsStore(root=./.lake)`에 둔다(Track 공통 어댑터, [05](05_PARALLEL_TRACKS.md) STEP 0.5). MinIO 없이 Mock 개발이 가능하다.

## 4. Manifest — commit 프로토콜

**독자는 prefix를 list하지 않고 committed manifest가 가리키는 파일만 읽는다.** 이것이 부분 쓰기를 보이지 않게 하는 유일한 장치다.

```json
{
  "manifest_id": "mf_{build_id}",
  "manifest_schema_version": "1.0",
  "layer": "bronze | silver | gold",
  "build_id": "acquisition_id | silver_build_id | gold_build_id",
  "build_kind": "acquisition | silver_build | gold_build",
  "plan_id": "incident:inc_…",
  "incident_id": "inc_… | null",
  "coverage_id": "cov_… | null",
  "status": "committed",
  "build_status": "ok | partial | … (bronze는 획득 상태)",
  "created_at": "…Z",
  "run_id": "run_…",
  "code_version": "x.y.z",
  "git_sha": "40hex",
  "git_dirty": false,
  "inputs": ["mf_…"],
  "outputs": [
    {"dataset": "silver.db_log", "schema_version": "1.0", "rows": 6,
     "files": [{"path": "s3://lake-silver/…/part-0000.parquet", "rows": 6, "bytes": 1234, "sha256": "…"}]}
  ],
  "quality": {"flag_counts": {"duplicate": 3}, "quarantined": 0, "skipped": 0},
  "supersedes": "mf_… | null"
}
```

- `outputs`에는 데이터 파일과 그 build의 **lineage edge 파일**이 함께 있다 → 데이터와 리니지가 원자적으로 함께 commit된다.
- `lineage.dataset_version`은 별도 테이블로 저장하지 않고 manifest JSON 위의 DuckDB view로 만든다(이중 기록 금지).

### 4.1 쓰기 순서

| 단계 | 동작 | 이 단계에서 죽으면 |
|---|---|---|
| 1 | 고유 prefix에 데이터·raw·edge 파일 쓰기 | manifest 없음 → 보이지 않는 orphan. `dp_validate`가 N시간 지난 orphan을 보고(삭제는 사람 승인) |
| 2 | 파일별 rows·bytes·sha256 계산 | 위와 같음 |
| 3 | `manifests/…/{build_id}.json` 쓰기 = **commit** | — |
| 4 | (Silver/Gold) `current/…` 포인터 갱신 | commit됐지만 최신이 아님 → 다음 실행이 포인터보다 새 committed manifest를 감지해 재지정 |
| 5 | (Bronze continuous) checkpoint 갱신 | 같은 창 재획득 → Bronze 중복 → Silver dedup으로 흡수 (at-least-once) |

포인터 JSON: `{coverage_id|incident_id, dataset, layer, build_id, manifest_id, previous_build_id, updated_at, run_id}`. 포인터는 한 coverage에 writer가 하나뿐이도록 Airflow pool/`max_active_runs=1`로 직렬화한다(동시 갱신 경합 방지; 조건부 쓰기 지원 여부는 DEC-03에서 MinIO 버전 확인).

## 5. 획득 창·지연·멱등성

| 항목 | 기본값(제안) | 근거 |
|---|---|---|
| 사건 창 | `anchor ± 5m` | 실시간 파리티 [main.py:288](../../aiops/pipeline/main.py#L288) |
| 획득 패딩 | 양쪽 `60s` | 창 경계, PC 간 시계 차이. Gold가 정확한 사건 창을 다시 적용 |
| 지연 허용(`lateness_margin_s`) | `600` | Fluent Bit flush 1s + Fluentd buffer 5s + concat 10s + 재시도 상한 60s를 넘는 여유. 장시간 단절은 무한(`Retry_Limit no_limits`)이므로 `window_closed`는 "완전" 보장이 아니다 → `transport_loss_suspected`와 함께 판단 |
| 사건 단위 획득 시점 | `window_end + lateness` 이후 | 실시간 경로가 보지 못한 사건 이후 구간까지 정착된 데이터로 확보 |

- **사건 모드(v1 기본)**: 같은 `acquisition_key`의 committed·`window_closed`·`ok` 획득이 있으면 건너뛴다. `force_reacquire=true`면 새 `acquisition_id`로 다시 받는다(이전 것 보존).
- **연속 모드(DEC-05)**: plan별 checkpoint `{plan_id, high_watermark, last_acquisition_id, open_failures[], updated_at, run_id}`. 창은 반열림 `[start, end)`로 타일링한다. 닫히지 않은 창은 받지 않는다.

## 6. 원천 조회 규칙 (Track A 구현 계약)

| 규칙 | Loki | Prometheus |
|---|---|---|
| scope | binding selector만. binding 없으면 `scope_unavailable` 행만 기록 | 같음 |
| preflight | `/loki/api/v1/series`(창) → 없으면 `[window_start-24h, window_end]` lookback → `present/absent` | `/api/v1/series`(binding selector) |
| 페이지네이션 | `direction=forward`, `limit=L`(서버 `max_entries_limit_per_query` 이하, 실제값 확인 필요). 다음 `start` = 마지막 entry ns(포함) → 경계 중복은 `record_key`로 제거. `max_pages` 도달 시 `truncated`. 한 페이지가 **모두 같은 ns이고 limit에 도달**하면 커서를 전진할 수 없으므로 받은 행을 보존하고 `truncated` + `status_reason=same_ts_overflow`로 끝낸다(`start`를 ns+1로 옮기면 같은 ns의 나머지를 건너뛰므로 금지) | `query_range` 단일 요청(11,000점/series 한도 내) |
| 반환 검증 | 모든 stream label이 scope와 `matches()` → 아니면 `source_mismatch`(원문은 보존) | 모든 series label 검증 |
| 부하 보호 | Airflow pool `loki_read`=1, 요청 timeout 30s, 페이지 간 지연, 요청 창 ≤ 15분 | pool `prom_read`=1 |
| 실패 | 페이지 일부 실패 → 받은 페이지는 저장하고 `partial` commit, checkpoint 진행 안 함 | `failed`(사유) |

## 7. 부분 실패 처리

- 획득은 **받은 만큼 보존**한다. `partial`/`truncated`도 committed manifest를 가지며 상태로 구분된다.
- Silver는 coverage 안의 **모든 committed 획득의 합집합**을 입력으로 하고 dedup한다. 채널 상태는 쿼리별 **최선 상태**(어느 한 획득이 `ok`면 `ok`)로 계산한다([04](04_DATA_QUALITY.md) §4).
- Silver/Gold build 실패는 manifest를 쓰지 않는다 → 이전 current가 그대로 유효하다.
- 재처리는 항상 **새 build**다. 이전 build·manifest·edge는 지우지 않는다(보존 기간 DEC-08).

## 8. DuckDB 사용 방식

- 변환 task마다 in-memory DuckDB 연결을 만들고, 입력 manifest의 파일 목록만 `read_parquet([...])`로 연다.
- 조회용 view: `silver_current_{dataset}` = current 포인터가 가리키는 build들의 합집합에서 PK별 최신 `_dataset_version` 1행.
- MinIO 접근: DuckDB `httpfs`(extension 설치가 런타임 다운로드를 요구할 수 있음 → 오프라인 번들 필요, DEC-02) 또는 pyarrow S3 filesystem으로 읽어 Arrow로 전달.

## 9. 보안·용량

- 모든 버킷 private, anonymous 정책 금지, console loopback 전용.
- Bronze/Silver에는 마스킹 전 원문이 있다 → reader 계정은 사람에게 기본 발급하지 않는다. Gold `rendered_line`만 마스킹 보장.
- 용량은 실측 전 추정하지 않는다. `dp_validate`가 일별 bytes·rows를 manifest에서 집계해 보고한다.
