# DB 연결 슬롯 고갈 Mock fixture

**모든 값은 합성이다.** 실제 장비·로그·주소·자격증명이 아니다. `password=fixture-not-a-secret`은 마스킹 시험용 합성 문자열이다.

설명: [../../07_MOCK_DB_INCIDENT.md](../../07_MOCK_DB_INCIDENT.md) · 스키마: [../../01_DATA_CONTRACT.md](../../01_DATA_CONTRACT.md)

| 접두 | 계층 | 형식 |
|---|---|---|
| `00`, `01` | 입력(사건 요청, binding) | JSON |
| `10`~`13` | Bronze | JSONL (Parquet 행과 같은 컬럼), `13`은 Loki 응답 원문 바이트 |
| `20`~`27` | Silver (현재 build) | JSONL |
| `30`~`35` | Gold (현재 build) | JSONL |
| `40`, `41` | Lineage run / edge (현재 build) | JSONL |
| `50`, `51` | Manifest(전체 21건, 대체된 build 포함) / current 포인터 | JSONL / JSON |
| `60` | 기존 Pipeline 코드(`0443c6f`)로 계산한 파리티 기대값. `aiops/pipeline`은 `2117eaf`까지 변경 없음 | JSON |

fixture 규약:

- JSON의 timestamp 컬럼은 `YYYY-MM-DDTHH:MM:SS.ffffffZ` 문자열, JSON 컬럼은 canonical JSON 문자열이다.
- manifest의 `files[].sha256`·`bytes`는 실제 Parquet가 아니라 **해당 행들을 canonical JSON으로 한 줄씩 이은 바이트**로 계산했다(fixture 전용 규약). `13`의 sha256은 `10`의 첫 획득 `raw_sha256[0]`과 같다.
- 대체된 build(`mf_sb_20261110T032010Z_62bad93f`, `mf_gb_20261110T032015Z_edd1b412`)는 manifest만 있고 행은 없다.
