# E2E 측정 결과 채점

시나리오를 실제로 돌린 뒤, pipeline이 남긴 RCA 결과를 시나리오 실행 기록과 짝지어 LLM 판단 지표를 계산한다.
채점 함수는 오프라인 하네스(`aiops/eval/harness.py score`)와 같다.

## 1. 측정 설정 — Ollama로 고정

평가 기준 모델은 Ollama `llama3.1:8b`(temperature 0.3, num_ctx 4096, num_predict 400)다.
앱 기본값(`LLM_PROVIDER=gemini`)은 바꾸지 않는다. 측정할 때만 셸에서 변수를 지정해 띄운다(`.env`는 수정하지 않는다).

- `LLM_MODEL=llama3.1:8b`는 compose에 고정돼 있다.
- temperature·num_ctx·num_predict는 pipeline 기본값(0.3 / 4096 / 400)이다. `LLM_TEMPERATURE`·`LLM_NUM_CTX`·`LLM_NUM_PREDICT`를 셸에 설정하지 않는다.
- `PROMPT_BUILDER`는 기본 `v2`다. legacy 비교가 필요할 때만 `PROMPT_BUILDER=legacy`.

macOS / Linux (저장소 루트):

```bash
LLM_PROVIDER=ollama docker compose --profile ollama up -d
```

Windows RTX (PowerShell, 저장소 루트):

```powershell
$env:LLM_PROVIDER = "ollama"; docker compose -f docker-compose.yml -f docker-compose.gpu.yml --profile ollama up -d
```

분리 구성(AIOps PC 단독)은 `docker-compose.aiops.yml`에 같은 방식으로 `LLM_PROVIDER=ollama`와 `--profile ollama`를 붙인다.

확인: pipeline 로그에 `[LLM] model=llama3.1:8b options={'temperature': 0.3, 'num_ctx': 4096, 'num_predict': 400} ...`가 찍혀야 한다. `[LLM] provider=gemini`가 보이면 측정을 멈추고 다시 띄운다.
모델이 없으면 `docker exec ollama ollama pull llama3.1:8b`.

## 2. 측정 중 남는 것

| 파일 | 만드는 곳 | 내용 |
|---|---|---|
| `scenarios/v2/fixtures_data/runs.jsonl` | `scenarios/v2/run.py` | 시나리오 id·변형·seed·시작/끝 시각·상태 (정답 없음) |
| Loki `{job="aiops-llm"}` | pipeline | 경보별 RCA 항목: `alert_starts_at`, `alert_fingerprint`, `result`(LLM 결과·대상 검증) |

`fixtures_data/`는 gitignore 대상이다. 측정 결과 파일은 커밋하지 않는다.

## 3. RCA 결과 내보내기

측정 구간을 덮도록 `start`·`end`를 정한다(RFC3339). Loki 주소는 AIOps PC 기준이다.

```bash
curl -sG "http://localhost:3100/loki/api/v1/query_range" --data-urlencode 'query={job="aiops-llm"}' --data-urlencode "start=2026-11-27T00:00:00Z" --data-urlencode "end=2026-11-28T00:00:00Z" --data-urlencode "limit=5000" -o rca.json
```

```powershell
curl.exe -sG "http://localhost:3100/loki/api/v1/query_range" --data-urlencode "query={job=`"aiops-llm`"}" --data-urlencode "start=2026-11-27T00:00:00Z" --data-urlencode "end=2026-11-28T00:00:00Z" --data-urlencode "limit=5000" -o rca.json
```

`logcli query --output=raw '{job="aiops-llm"}' ... > rca.jsonl` 형식(한 줄에 항목 하나)도 받는다.

## 4. 채점

`aiops` 디렉터리에서:

```bash
python -m eval.e2e_score --results ../rca.json --runs ../scenarios/v2/fixtures_data/runs.jsonl --out ../e2e_scored
```

- 짝짓기: RCA 항목의 `alert_starts_at`이 `[실행 시작, 실행 끝 + 300초]` 안인 실행 하나. 없거나 여럿이면 제외하고 사유를 남긴다(`--grace`로 여유 조정).
- 평가 분할 실행(공개 튜닝 변형이 아닌 변형)은 기본으로 제외한다. 룰 동결 뒤 평가 회차에서만 `--include-eval`.
- 출력: 표준 출력에 요약 표. `--out`이면 `scored.jsonl`(항목별 채점), `summary.json`(요약 + 제외 목록), `summary.md`.

## 5. 지표 정의

| 지표 | 정의 |
|---|---|
| JSON 유효율 | `analysis_status=valid` 비율 |
| action 정확도(현재 대체 조치) | 최종 `action_type == expected_action`. invalid는 오답 |
| action 정확도(이상 조치) | 최종 `action_type`이 `expected_action_ideal`(‘+’로 여러 개면 그중 하나)과 같음 |
| 대상 일치율 | 최종 조치가 대상을 갖고, 레지스트리 대상에 실제 이름(`leafy-*`)이 있을 때 `action_targets[0]`이 그 안에 있는 비율. 대상이 서술형("공격 대상 계정")이면 제외 |
| 증거에 없는 대상 생성률 | LLM이 대상이 필요한 조치를 골랐을 때 대상이 증거에 없어 낮춰진(`target_reason=target_not_in_evidence`) 비율 |
| 다운그레이드율 | 유효한 분석 중 `target_validation=downgraded` 비율. 사유별 개수는 `downgrade: <사유>` 행 |
| threat_level / incident_class 정확도, 과잉·과소대응률, confidence 분포 | 하네스와 같음 |

정답 기준(`expected_action`)은 바꾸지 않았다. 이상 조치는 참고 기준으로만 함께 보고한다.
프롬프트 토큰·지연은 RCA 항목에 없어 `n/a`로 나온다. pipeline 로그의 `[LLM] model=… prompt_eval_count=… total_duration=…` 줄로 따로 확인한다.

## 6. 주의

- 낮춰진(downgraded) 결과의 최종 조치는 NOTIFY다. 현재 대체 조치가 NOTIFY인 시나리오에서는 정답으로 잡히므로, 대상 지표와 함께 읽는다.
- Remediation 전달은 기본 꺼짐이다(`REMEDIATION_APPROVAL_ENABLED=false`). 채점은 LLM 판단만 보며 실제 조치 실행과 무관하다.
- 표본이 작으면(시나리오별 몇 회) 수치는 경향으로만 읽는다.
