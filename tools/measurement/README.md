# 측정 도구 (tools/measurement)

위양성 기준선·대조 이벤트 측정과 탐지 룰 재생에 쓴 보조 스크립트 모음이다. 애플리케이션/룰 런타임에는 포함되지 않으며, 측정 PC에서 손으로 돌린다.

공통 규칙
- Python 도구는 저장소 밖 데이터를 읽고 쓰므로 `python -I` 로 실행한다(사용자 사이트 격리).
- 접속 대상(Prometheus/Loki/Alertmanager/프론트)·인가 목적지·도구 폴더는 **하드코딩하지 않고 인자/파라미터**로 받는다. 기본값은 로컬(`127.0.0.1`)이다.
- 결과 데이터·로그·테스트 계정 파일(accounts.json 등)은 이 폴더에 넣지 않는다(저장소 밖 run 디렉터리에 둔다).

## 트래픽 생성
### `traffic_gen.py`
정상 사용자 트래픽(가입·로그인·조회·업로드)과 **대조 모드**(`--control none|wrong-password|not-found|mixed`)를 생성한다. `--control-plan "분당건수:분,..."` 으로 구간별 속도를 준다.
```
python -I traffic_gen.py --base http://<frontend> --dir <run dir> --setup 5           # 계정 N개만 준비
python -I traffic_gen.py --base http://<frontend> --dir <run dir> --duration 7200 --seed 42
python -I traffic_gen.py --base http://<frontend> --dir <run dir> --control mixed --control-plan "0:15,2:10,20:5" --seed 42
```
### `traffic_gen_v1_baseline.py`
초기(v1) 기준선 생성기. 대조 모드가 없던 버전으로, 기준선 재현·비교용으로 보관한다. 인자는 `traffic_gen.py` 와 같다(`--base --dir --duration --seed --setup`).

## 룰 재생
### `replay_rule.py`
Prometheus 룰 식을 과거 구간에 다시 적용해 `for` 조건까지 반영한 발화 횟수·시간을 계산한다(룰 변경 전후 비교에 쓴다).
```
python -I replay_rule.py --expr "<PromQL>" --for 60 --start <ISO> --end <ISO> [--step 5 --prom http://127.0.0.1:9090 --out out.json]
```

## 경보 기록
### `alert_recorder.py`
Alertmanager 를 주기적으로 조회해 활성 경보를 jsonl 로 덧붙인다(측정 중 상시 실행).
```
python -I alert_recorder.py --out <run dir>\alerts.jsonl [--interval 15 --url http://127.0.0.1:9093]
```

## 집계
### `collect.py`
측정 구간을 집계한다: 경보 에피소드, 각 룰의 headroom(구간 최댓값 vs 임계), 수집 경로 확인(Loki 라인 수·타깃 up), 트래픽 요약 → `<run dir>/summary.json`.
```
python -I collect.py --dir <run dir> --start <ISO> --end <ISO> \
    [--prom http://127.0.0.1:9090 --loki http://127.0.0.1:3100 --authorized-dst-ip 10.210.0.30 --authorized-dst-port 8080]
```
### `collect_control.py`
대조 이벤트(C-c/C-e) 구간을 집계한다(구간 계획·요청·경보·pipeline 로그) → `<run dir>/summary_control.json`.
```
python -I collect_control.py --dir <run dir> [--loki http://127.0.0.1:3100]
```

## 정찰(프롬프트 재구성)
### `recon_prompt.py`
pipeline 이 경보 분석 때 LLM 에 보낸 프롬프트를 같은 코드 경로로 다시 만든다(pipeline 은 프롬프트를 저장하지 않는다). **pipeline 컨테이너 안에서** 조회 전용으로 실행한다.
```
docker exec -i -e RECON_INPUT='{"alert": <Alertmanager 경보>, "analysis_time": "<ISO>"}' aiops-pipeline python - < recon_prompt.py
```

## 시각·실행 보조 (PowerShell)
### `timesync.ps1`
Windows / WSL(docker-desktop) / 컨테이너 / Prometheus 시각 차이를 재서 한 줄 JSON 으로 남긴다.
```
powershell -File timesync.ps1 -Label start -Out <run dir>\timesync.jsonl [-Prom http://127.0.0.1:9090]
```
### `start_control_run.ps1`
예약 시각(`-NotBefore`)까지 기다렸다가 timesync → 경보 기록기 → 트래픽 생성기(대조 모드)를 `Win32_Process.Create` 로 띄운다(세션이 끝나도 계속 돈다). `-Base` 는 트래픽을 보낼 프론트 URL, `-Tools` 는 도구 폴더(기본=이 스크립트 폴더).
```
powershell -File start_control_run.ps1 -Run <run dir> -NotBefore "2026-11-01T22:00:00" -Plan <plan> -Seed 42 -Duration 3600 [-Base http://<frontend> -Tools <폴더>]
```
