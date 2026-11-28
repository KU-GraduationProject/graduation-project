# DB 연결 슬롯 고갈 Mock fixture

**모든 값은 합성이다.** 실제 장비·로그·주소·자격증명이 아니다. `password=fixture-not-a-secret`은 마스킹 시험용 합성 문자열이다.

설명: [../../07_MOCK_DB_INCIDENT.md](../../07_MOCK_DB_INCIDENT.md) · 스키마: [../../01_DATA_CONTRACT.md](../../01_DATA_CONTRACT.md)

| 접두 | 계층 | 형식 |
|---|---|---|
| `00`, `01`, `02` | 입력(사건 요청, binding, 시나리오 실행 기록 `runs.jsonl` — `scenarios/v2/run.py`가 쓰는 형식) | JSON / JSONL |
| `10`~`14` | Bronze | JSONL (Parquet 행과 같은 컬럼), `13`은 Loki 응답 원문 바이트, `14`는 실행 기록 줄 |
| `20`~`28` | Silver (현재 build) | JSONL |
| `30`~`36` | Gold (현재 build) | JSONL |
| `40`, `41` | Lineage run / edge (현재 build) | JSONL |
| `50`, `51` | Manifest(전체 23건, 대체된 build 포함) / current 포인터 | JSONL / JSON |
| `60` | 기존 Pipeline 코드(`0443c6f`)로 계산한 파리티 기대값. `aiops/pipeline`은 `2117eaf`까지 변경 없음. 단 `llm_result_model_dump`는 #70에서 현재 `LLMAnalysisResult`(`ffc996c`)로 다시 계산했고, #79에서 #72의 기본값 필드(`target_evidence` 등)를 반영해 `tests/tools/regen_fixture.py`로 재계산 | JSON |

fixture 규약:

- JSON의 timestamp 컬럼은 `YYYY-MM-DDTHH:MM:SS.ffffffZ` 문자열, JSON 컬럼은 canonical JSON 문자열이다.
- manifest의 `files[].sha256`·`bytes`는 실제 Parquet가 아니라 **해당 행들을 canonical JSON으로 한 줄씩 이은 바이트**로 계산했다(fixture 전용 규약). `13`의 sha256은 `10`의 첫 획득 `raw_sha256[0]`과 같다.
- `02` 실행 기록 3건: 사건과 짝인 `f2_c_db_pool_exhaustion`(`fill-steady`, ok) 1건, 유예 300s 안이지만 `status=error`라 제외되는 1건, 시각이 겹치지 않는 1건 → `36`은 `paired`.
- 파생값(sha·record key·Silver/Gold 행·edge·manifest)은 손으로 고치지 않는다. 저장소 루트에서 `python aiops/dataplatform/tests/tools/regen_fixture.py`로 다시 계산한다(이 폴더에만 씀, 최신 fixture에서 돌리면 변경 없음).
- 대체된 build(`mf_sb_20261110T032010Z_62bad93f`, `mf_gb_20261110T032015Z_edd1b412`)는 manifest만 있고 행은 없다.
