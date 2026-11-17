# 06. GitHub Issue 초안

> **초안이다. GitHub에 생성하지 않았다.** 형식은 `.github/ISSUE_TEMPLATE/feature.yml`·`docs.yml`의 필드를 따른다.
> 라벨은 `.github/labels.json`에 있는 것만 썼다. `area:data-platform`은 없으므로(DEC-13) 결정 전까지 실제 변경 경로에 맞는 기존 영역 라벨을 수동 지정한다.
> 브랜치는 Issue 번호 발급 후 `<type>/<번호>-<설명>`으로 만든다. 아래 `#N`은 placeholder다.

## 순서

| 순서 | Issue | 선행 |
|---|---|---|
| 1 | [docs] 데이터 플랫폼 STEP 0 공통 계약 | — |
| 2 | [feat] 데이터 플랫폼 계약 코드 스켈레톤 (STEP 0.5) | 1 승인·병합, DEC-01/02/03 |
| 3~6 | [feat] Track A / B / C / D | 2 병합 |

---

## 1. `[docs] 데이터 플랫폼 STEP 0 공통 계약 (#N)`

- 라벨: `type:docs`, `area:docs`, `status:open` · 브랜치: `docs/N-data-platform-step0`

**작업 목적** — Medallion(Bronze/Silver/Gold)·Lineage·품질 계약을 구현 전에 확정해 4개 Track이 같은 계약으로 병렬 개발하게 한다.

**작업 항목** — 기존 시스템 분석, Bronze/Silver/Gold 스키마, 저장소(MinIO 분리·Parquet·DuckDB)·manifest·checkpoint, 레코드 단위 리니지, 품질 상태·플래그, Track 분리·파일 소유권, DB 장애 Mock fixture, 문서·코드 불일치 검토.

**산출물** — `docs/data-platform/` 문서 10개 + `examples/db-connection-limit/` fixture.

**완료 조건** — 사용자 검토·승인, README의 DEC 항목 중 "STEP 0.5 전" 결정 완료, 문서의 모든 상대 링크 유효, fixture가 계약과 불일치 0건(08 문서의 검증 방법).

---

## 2. `[feat] 데이터 플랫폼 계약 코드 스켈레톤과 공유 fixture 로더 (#N)`

- 라벨: `type:feat`, `area:tooling`(임시), `status:open` · 브랜치: `feat/N-dp-contract-skeleton`

**작업 목적** — 네 Track이 공유하는 해시·ID·스키마·저장소·manifest 코드를 한 번만 만든다.

**배경 및 필요성** — 이 단계 없이 병렬 시작하면 `record_key`·manifest 형식이 Track마다 달라진다.

**요구사항** — 01 §1의 C-1~C-12, 02 §4 manifest/commit 순서, 03의 run/edge 직렬화, `LocalFsStore`, 01 §2~§4 컬럼 명세 코드화, `aiops/pipeline` read-only 로딩.

**구현 범위** — `aiops/dataplatform/{contracts,storage}/`, `tests/fixtures/`(docs 예시를 읽는 로더), `tests/contracts/`, `requirements.txt`, `.gitignore`에 `.lake/`. **제외:** Bronze/Silver/Gold 로직, Airflow, MinIO 기동.

**완료 조건** — fixture의 모든 ID·해시를 계약 코드로 재계산해 일치, `run_id`의 `map_index` = `null`·`-1`(같은 값)·`0`·`1`(서로 다른 값) 계약 테스트, LocalFsStore로 manifest commit·포인터·orphan 시나리오 테스트 PASS, 기존 4개 suite 회귀 PASS.

**테스트 방법** — `python -m unittest discover -s aiops/dataplatform/tests -v` (네트워크·Docker 차단 상태). `tests/`와 하위 디렉터리(`tests/contracts/` 등)에 `__init__.py`를 두어 discover가 재귀 탐색하게 한다. 기존 suite 회귀: `python testing/run_isolated.py pipeline`, `… remediation`, `… network`, `… observer` (suite당 1회 실행).

**참고 자료** — 01, 02, 03, 05 §2·§4, 07.

---

## 3. `[feat] Track A — Bronze 획득·영속화 (#N)`

- 라벨: `type:feat`, `area:pipeline`(임시), `status:open` · 브랜치: `feat/N-dp-bronze-ingestion`

**작업 목적** — Loki/Prometheus에서 사건 창의 원천 데이터를 빠짐없이 받아 원문·메타데이터와 함께 영속화한다.

**배경 및 필요성** — 실시간 collector는 `limit=200`·페이지네이션 없음·webhook 직후 조회라 사건 이후 구간과 대량 로그가 누락된다. 원문 응답도 저장하지 않는다.

**요구사항** — 05 §5 Track A 표. binding 없는 질의 금지, 금지 스트림 차단, lookback preflight, 페이지네이션·경계 중복 제거, `window_closed`, 부분 실패 보존, 같은 `acquisition_key` 재획득.

**구현 범위** — `aiops/dataplatform/bronze/**`, `tests/bronze/**`. **제외:** 파싱·dedup, Airflow, 실제 Loki/Prometheus 호출.

**완료 조건** — fixture 요청으로 `10/11/12` 재현(ID·시각 제외), DQ-B01~B06, 실제 HTTP 0회.

**테스트 방법** — `httpx.MockTransport` + fixture 응답, 격리 실행기. 실환경 미실행(사유: binding 실값 미인수).

**참고 자료** — 00 §3, 01 §2, 02 §5·§6, 04 §1.

---

## 4. `[feat] Track B — Silver 변환·품질 (#N)`

- 라벨: `type:feat`, `area:pipeline`(임시), `status:open` · 브랜치: `feat/N-dp-silver-transform`

**작업 목적** — Bronze를 출처별 정규 스키마로 바꾸고 중복·시각·identity·품질 표식을 일관되게 만든다.

**배경 및 필요성** — 출처마다 시각 의미와 Loki `source` label 의미가 다르고, at-least-once 전송과 재획득으로 중복이 생긴다.

**요구사항** — 01 §3 전체, 04 §3 플래그, DQ-S01~S06. Canonical Network Event 필드 변경 금지.

**구현 범위** — `aiops/dataplatform/silver/**`, `tests/silver/**`. **제외:** 사건 창 필터·scope 매칭.

**완료 조건** — fixture Bronze → `20~27` 일치, 모든 Bronze 행이 edge 또는 quarantine로 설명됨, 재실행 시 내용 해시 동일.

**테스트 방법** — fixture 로더 + LocalFsStore, 격리 실행기.

**참고 자료** — 01 §3, 04, 07 §5.

---

## 5. `[feat] Track C — Gold RCA Evidence Mart·Lineage (#N)`

- 라벨: `type:feat`, `area:pipeline`(임시), `status:open` · 브랜치: `feat/N-dp-gold-lineage`

**작업 목적** — 사건별 근거·채널 상태·RCA 연결을 영속화하고, 어떤 근거든 원천까지 역추적한다.

**배경 및 필요성** — 실시간 RCA는 어떤 로그·지표를 근거로 썼는지 남기지 않는다. 재처리 시 이전 판단 근거가 사라진다.

**요구사항** — 01 §4, 03 전체, 04 §4·§5·DQ-G01~G07·DQ-L01. 렌더·마스킹·flow 집계는 기존 함수와 파리티.

**구현 범위** — `aiops/dataplatform/gold/**`, `lineage/**`, 해당 tests. **제외:** LLM 호출(DEC-07).

**완료 조건** — fixture Silver → `30~35` 일치, `60` 파리티 일치, trace(evidence) → Bronze 획득·run 도달, 재빌드 시 evidence_id 동일·이전 build 보존.

**테스트 방법** — fixture 로더 + LocalFsStore, 격리 실행기.

**참고 자료** — 01 §4, 03, 04 §4·§5, 07 §6·§7.

---

## 6. `[feat] Track D — Airflow 오케스트레이션·검증 (#N)`

- 라벨: `type:feat`, `area:infra`, `area:tooling`, `status:open` · 브랜치: `feat/N-dp-airflow-orchestration`

**작업 목적** — A~C를 실시간 경로와 분리된 배치로 자동화하고 적재·변환·검증·재처리를 운영 가능하게 한다.

**배경 및 필요성** — 사건 이후 정착된 데이터로 재획득·재처리할 실행 주체가 없다. 실시간 Alertmanager → Pipeline 경로는 그대로 두어야 한다.

**요구사항** — 05 §5 Track D, §6 비간섭 표 전체. DAG 4종, pool, `git_dirty` 거부, `dp_validate`.

**구현 범위** — `aiops/dataplatform/{orchestration,airflow}/**`, `tests/{orchestration,e2e}/**`, `docker-compose.dataplatform.yml`, `deploy/dataplatform/**`. A~C 병합 후 별도 PR로 `testing/run_isolated.py`·CI matrix. **제외:** 기존 Compose·AM·Pipeline 수정, 컨테이너 기동.

**완료 조건** — DAG 구조 테스트, stub/실구현 E2E(fixture HTTP) PASS, `docker compose -f docker-compose.dataplatform.yml config` 문법 검사 PASS(기동 없음).

**테스트 방법** — task 함수 단위 테스트, DAG import 검사, E2E. Airflow·MinIO 실제 기동은 미실행(사유: 사용자 승인 전).

**참고 자료** — 02 §2·§4, 05 §5·§6, DEC-04/05/14.
