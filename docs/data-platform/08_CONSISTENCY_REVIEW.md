# 08. 계약 불일치 검토

> 두 부분으로 나눈다. **§1 기존 문서·코드 사이의 불일치**(이번에 고치지 않음, 담당자 판단 필요)와 **§3 이 문서 세트의 자체 검증 결과**.

## 1. 기존 저장소에서 발견한 불일치 (수정하지 않음)

| ID | 불일치 | 근거 | 데이터 플랫폼의 처리 | 필요한 결정 |
|---|---|---|---|---|
| X-01 | Network 스키마 문서는 v1.0 `event_type`을 `connection`만으로 정의하지만, Enricher는 `connection_threshold`도 `schema_version "1.0"`으로 낸다. 스키마 §14.2 기준 enum 추가는 MINOR(1.1) | [NETWORK_EVENT_SCHEMA.md:135](../network-observability/NETWORK_EVENT_SCHEMA.md#L135), [zeek_map.py:11-18](../../aiops/network-observer/enricher/zeek_map.py#L11-L18) | MAJOR `1`이면 모두 수용, `event_type` 원문 보존. Gold flow는 최종/조기 분리 | Network 담당: 문서 갱신 또는 버전 표기 |
| X-02 | Pipeline은 host endpoint 검증에 `src_target`/`dst_target`을 요구하지만 Canonical 스키마와 Enricher에 그 필드가 없다 → **host(db) 대상 Network 근거는 항상 skipped** | [collector/network.py:149-153](../../aiops/pipeline/collector/network.py#L149-L153), [OI_09_SOURCE_IDENTITY.md:38](../rulepack/OI_09_SOURCE_IDENTITY.md#L38), [events.py:46-79](../../aiops/network-observer/enricher/events.py#L46-L79) | 필드를 추측하지 않는다. Gold 채널 `unavailable/host_target_field_absent` (fixture에서 재현) | DEC-15 |
| X-03 | Observer 설정 `observer.instance: null`인데 binding의 network scope는 `observer_instance`가 필수 → 현재 설정의 이벤트는 어떤 binding과도 매칭되지 않음 | [aiops/network-observer/config/observer.yml:12](../../aiops/network-observer/config/observer.yml#L12), [deploy/…/observer.yml:9](../../deploy/leafy-pc/network-observer/config/observer.yml#L9), [identity.py:93-96](../../aiops/pipeline/identity.py#L93-L96) | Bronze 질의 자체가 `observer_instance` 필터를 포함하므로 실데이터는 0건이 된다(파이프라인과 동일) | OI-09 BLOCKED 항목과 함께 인수 |
| X-04 | Network 스키마 문서 §10.1·§13의 "현재 상태"가 낡았다: Pipeline이 `{container=…}`로 조회, 앱 로그 `line_format key_value`, `aiops-llm` label에 `action_risk` | [NETWORK_EVENT_SCHEMA.md:403-408](../network-observability/NETWORK_EVENT_SCHEMA.md#L403-L408), [:683](../network-observability/NETWORK_EVENT_SCHEMA.md#L683) vs [fluent.conf:100-103](../../leafy/fluentd/fluent.conf#L100-L103), [main.py:784-795](../../aiops/pipeline/main.py#L784-L795) | 문서가 아닌 코드 기준으로 설계 | 문서 담당: 이력 표기 |
| X-05 | Loki `source` label 의미가 레포 기본(stdout/stderr)과 릴리스 후보(observation source, `log_stream` 별도)에서 다르다 | [fluent.conf:106](../../leafy/fluentd/fluent.conf#L106), [prepare_release.py:183](../../tools/rulepack/prepare_release.py#L183) | Silver `label_profile`로 판별, legacy의 `source`를 identity로 승격 금지(DQ-S05) | 전환 시 dashboard/query 영향 검토(M5 readiness에 기록됨) |
| X-06 | LLM `action_type` 어휘가 세 곳에서 다르다: 스키마 7종(SCALE 포함), RCA 프롬프트 6종(SCALE 없음), 주기 스캔 프롬프트 5종(PAUSE·THROTTLE 없음) | [llm_output.py:33](../../aiops/pipeline/schemas/llm_output.py#L33), [builder.py:37](../../aiops/pipeline/prompt/builder.py#L37), [main.py:345](../../aiops/pipeline/main.py#L345) | Silver는 스키마(7종)로 검증·보존 | Pipeline 담당 |
| X-07 | F2-c 정답이 본문(`NOTIFY`)과 요약표(`RESTART`)에서 다르다 | [THREAT_SPEC.md:75](../scenarios-v2/THREAT_SPEC.md#L75), [:129](../scenarios-v2/THREAT_SPEC.md#L129) | 정답 데이터를 Gold에 넣지 않으므로 직접 영향 없음 | 시나리오 담당 |
| X-08 | Runbook은 "F2-c는 Docker DB 전용이며 GC Windows PostgreSQL 17에 사용할 수 없다"고 하지만, PR #33이 Host 모드를 추가했다(Runbook은 갱신되지 않음) | [GC_JH_WINDOWS_E2E_RUNBOOK.md:18](../demo/GC_JH_WINDOWS_E2E_RUNBOOK.md#L18) vs [F2C_RUNTIME.md:13](../../scenarios/v2/F2C_RUNTIME.md#L13), [:27](../../scenarios/v2/F2C_RUNTIME.md#L27) | 07 §1의 F2-c 판단을 코드 기준으로 갱신. Mock fixture에는 영향 없음 | 데모/시나리오 담당: Runbook 갱신 |

### 1.1 확인했으나 불일치가 아닌 것

- RCA envelope의 `storage_status`가 Loki 저장본에 없는 것은 OI-09 문서가 "메모리 history의 값"으로 정의한 그대로다([OI_09_SOURCE_IDENTITY.md:105](../rulepack/OI_09_SOURCE_IDENTITY.md#L105)). Silver `rca_result`에는 이 컬럼을 두지 않았다.
- `OBSERVATION_BINDINGS` 미설정 시 source 미확인 RCA만 남는 것은 OI-09가 명시한 운영 상태다. 다만 **데이터 플랫폼 실데이터 적재도 같은 이유로 막힌다**([00](00_EXISTING_SYSTEM_ANALYSIS.md) §5).

## 2. 이 문서 세트의 계약 간 대응표

| 계약 요소 | 정의 | 사용처 |
|---|---|---|
| ID·해시 | 01 §1.1 | 02 경로, 03 edge, 07/fixture |
| 획득 상태 | 04 §1 | 01 §2.1 `status`, 02 §6·§7, 04 §4 |
| 레코드 플래그 | 04 §3 | 01 C-8 `_quality_flags` |
| 채널·사건 상태 | 04 §4·§5 | 01 §4.1·§4.2 |
| edge relation | 03 §3 | 01 §3 dedup, 02 §4 manifest outputs |
| manifest | 02 §4 | 03 §1 dataset version, 04 §6 `quality` |
| Track 입출력 | 05 §4·§5 | 06 Issue, 07 §8 |

## 3. 자체 검증 결과

검증 방법: 합성 fixture를 계약대로 생성한 뒤, 별도 검증 스크립트가 **마크다운 표를 직접 파싱**해 fixture와 대조했다. 두 스크립트는 저장소 밖 임시 작업 공간에 있고 커밋 대상이 아니다(구현 착수 금지 범위). 실행: Python 3.12, 기존 Pipeline 모듈을 바이트코드 생성 없이 read-only import.

| ID | 검사 | 결과 |
|---|---|---|
| S-01 | 01·03의 19개 데이터셋 표 ↔ fixture 컬럼 집합·Null·타입 | PASS (최종 실행) |
| S-02 | fixture의 상태·사유·플래그·relation·enum 값이 문서 어휘에 존재 | PASS |
| S-03 | `incident_id`·`acquisition_key`·`record_key`·`db_log_id`·`network_event_id`·`metric_point_id`·`quarantine_id`·`evidence_id`·`edge_id`·`run_id`·`coverage_id` 재계산 | PASS |
| S-04 | 현재 build manifest의 rows·bytes·sha256, `13` 원문 sha256, 원문 → Bronze 행 평탄화 | PASS |
| S-05 | fixture에 DQ-B02·B06·S01·S02·G01·G02·G04·G06·L01 적용 | PASS |
| S-06 | 기존 코드 파리티: `render_log_line`, Network 실시간 skipped(3) = Gold skipped(2) + quarantine(1), `resolve_identity` → `resolved` | PASS |
| S-07 | 문서 상대 링크·줄 앵커 | PASS |
| S-08 | DEC·DQ·X·S 참조가 모두 정의됨 | PASS |

### 3.1 검증 중 발견해 고친 계약 결함

| 결함 | 수정 |
|---|---|
| `acquisition_key`에 `limit`이 들어가 강제 재획득이 다른 요청으로 보임 | 페이징 파라미터 제외 (01 §1.1) |
| Silver 로그에 stream label이 없어 기존 `render_log_line` 파리티 불가 | `stream_labels` 컬럼 추가 (01 §3.1·§3.2) |
| 최선 상태 순위에서 `empty_verified`가 `truncated`보다 높아 늦게 온 데이터가 가려질 수 있음 | 데이터를 받은 상태 우선 (04 §4) |
| scope 제외 사유에 "값이 다름"이 없음 | `target_mismatch` 추가 (01 §4.2) |
| `partial`의 `status_reason` 형식 미정 | `page_failed:<사유>` (04 §1) |
| fixture 비밀값이 200자 렌더 범위 밖이라 마스킹 시험이 안 됨 | 렌더 범위 안으로 이동 → `masked` 1건 |

### 3.2 검증하지 못한 것

- Parquet 타입·DuckDB SQL(03 §6)·MinIO 동작: 라이브러리·인프라 미설치. JSON 수준 타입만 검사했다.
- Loki/Prometheus 응답 형식은 기존 collector 코드가 기대하는 형식으로 합성했다. 실제 서버 응답을 받아 비교하지 않았다.
- 대체된 build(1차 Silver db_log, 1차 Gold)의 행 sha256은 행을 fixture에 넣지 않아 재계산할 수 없다.
- Airflow DAG 의미(재시도·pool)는 설계 문서 수준이며 실행 검증 대상이 아니다.

## 4. 기준 커밋 재검증 (`0443c6f` → `2117eaf`, 2026-11-17)

그 사이 main에 병합된 것은 PR #32(Slack Socket Mode, Issue #31)와 PR #34(F2-c Windows Host, Issue #33) 두 건이다.

| ID | 검사 | 결과 |
|---|---|---|
| R-01 | 이 문서 세트가 읽은 경로(`aiops/pipeline`, `aiops/network-observer`, `leafy/fluentd`, `monitoring`, `tools/rulepack`, `docs/{rulepack,network-observability,scenarios-v2,demo}`, `deploy/leafy-pc`)의 `git diff 0443c6f 2117eaf` | 변경 없음 → 00 분석, S-06 파리티, `60` 기대값 유지 |
| R-02 | 모든 상대 링크·줄 앵커를 두 커밋에서 비교(앵커 범위의 행 내용 동일 여부) | 기존 83건 모두 동일 내용, 깨진 링크 0. 이번에 추가한 `F2C_RUNTIME.md` 앵커 3건은 `2117eaf`에만 있는 파일이며 범위 유효 |
| R-03 | 변경 파일(`docker-compose*.yml`, `.env.example`, `aiops/remediation/**`, `scenarios/v2/**`)이 계약에 주는 영향 | Compose 변경은 `remediation` 서비스의 Slack 환경변수·주석뿐 → 02 저장소 설계·DEC-04 무영향. F2-c Host 지원 → 07 §1 갱신, X-08 추가 |
| R-04 | fixture JSON/JSONL 파싱 | 25개 파일, 319개 객체 파싱 PASS |

S-01~S-06(ID 재계산·manifest 해시·파리티)은 이번에 **다시 실행하지 않았다**. 당시 검증 스크립트가 저장소 밖에 있어 남아 있지 않다. fixture와 R-01의 입력 경로가 바뀌지 않았으므로 결과가 유지된다고 판단하지만, STEP 0.5의 `tests/contracts/`에서 코드로 재검증한다.

Remediation의 Slack 승인·조치 이력(`aiops/remediation/store.py`)은 향후 Gold의 대응 결과 원천 후보지만 v1 범위 밖이며, 별도 진행 중인 Remediation 작업(#35)의 계약이 정해진 뒤 검토한다.
