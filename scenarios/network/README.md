# S2 / C-a 네트워크 탐지 시나리오

비인가 목적지로의 데이터 전송(S2)을 탐지하면서, **완전히 동일한** 인가 목적지
전송(C-a)은 오탐하지 않는지를, 프로그램의 자기보고가 아니라 **Zeek가 관측한 실제
네트워크 이벤트**로 증명·평가하기 위한 시나리오다.

- **S2** (비인가): 침해된 backend를 가정(Assumed Breach)하고, backend 네트워크
  공간에서 PostgreSQL `leaked_users`(합성 더미)를 읽어 Allowlist에 없는 **Sink B**로
  전송 → 탐지되어야 한다 (True Positive).
- **C-a** (정상 대조군): 같은 DB 조회·같은 전송 파일·같은 크기/속도/프로토콜로
  Allowlist에 있는 **Sink A**로 전송 → 경보가 없어야 한다 (True Negative).
- 정상/공격을 가르는 1차 기준은 **목적지 허용 여부**다. 전송량이 크거나 느리다는
  이유만으로 공격이라 판단하지 않는다.

> ⚠ 데이터: `leaked_users`는 프로젝트의 **합성 더미**다. 실제 개인정보가 아니다.
> 전송 파일 중 DB 원본으로 채우지 못한 부분은 **합성 패딩**으로 명시 분리한다
> (`payload.py`, 본문 내 `SYNTHETIC PADDING` 마커). 생성된 전체를 원본이라 하지 않는다.

## 전체 흐름

```
호스트 Python(오케스트레이터/TUI)
  → Docker SDK 로 backend 네트워크 공간에서 송신 트리거 (E1)
      → PostgreSQL db:5432 에서 leaked_users 조회
      → 전송 파일 생성(원본 + 합성 패딩, 결정적, SHA-256)
      → HTTP POST → Sink A(인가) / Sink B(비인가)
  → Zeek(eth0) 가 실제 패킷 관측 (ConnThreshold 조기 이벤트 + conn.log)
  → Enricher → Fluentd → Loki
  → Loki Ruler(Allowlist 기반 LogQL) → Alertmanager
  → AIOps Pipeline → LLM RCA (Network Context)
  → ScenarioVerifier(FIRING/Alertmanager/전달 + MTTD) → TUI/평가
```

## 구성 요소

| 경로 | 역할 |
|------|------|
| `scenarios/network/sink/sink_server.py` | 수신 Sink (바이트·SHA-256 기록, `/stats` 조회) |
| `scenarios/network/payload.py` | 전송 파일 생성(원본+합성, 결정적, 해시) — P1 순수 로직 |
| `aiops/policy/allowlist.yml` | 목적지 Allowlist(사람 작성) — P3 단일 정책 소스 |
| `aiops/pipeline/policy/` | Allowlist 평가기 + LogQL 규칙 생성기 (P3) |
| `aiops/network-observer/zeek/local.zeek` | Zeek conn.log + ConnThreshold 조기 이벤트 (P6) |
| `monitoring/loki/rules/fake/network-allowlist.yml` | 생성된 Loki Ruler 규칙 (누적+조기) |
| `docker-compose.s2.yml` | 기본 Sink 배치(leafy-net) 오버레이 |
| `docker-compose.s2.sink-net.yml` | 대체 Sink 배치(sink-net, UNVERIFIED) |

## Sink 배치 (Step 1 / P2)

Zeek는 `network-observer-zeek`가 backend의 netns를 공유해 **eth0 = leafy-net**을
캡처한다. 따라서 전송이 eth0을 통과해야 관측된다.

### 기본 추천 배치 — leafy-net (관측 구성상 보장)
`docker-compose.s2.yml`. 두 Sink를 leafy-net 고정 IP로 둔다.
- `sink-a` → `10.210.0.30:8080` (인가, C-a)
- `sink-b` → `10.210.0.31:8080` (비인가, S2)

backend→sink 트래픽이 eth0을 지나므로 Zeek가 본다. 목적지는 실제 관측된
`dst_ip:dst_port`로 구분된다(두 IP가 달라 Allowlist 판정이 명확하다).

```bash
docker compose -f docker-compose.yml -f docker-compose.s2.yml up -d --build sink-a sink-b
```

> 전체 스택을 처음 올릴 때 fluentd 가 막 재생성되면, fluentd 로그 드라이버를 쓰는
> `leafy-db`/`leafy-minio` 가 `failed to initialize logging driver: dial tcp [::1]:24224`
> 로 첫 기동에 실패할 수 있다 (로컬 검증에서 확인, 기존 스택 동작). `up -d` 를 한 번 더
> 실행하면 올라온다. 이후 `docker compose ps` 로 Zeek 가 재시작 반복 중이 아닌지 확인한다.

### 대체 배치 — sink-net 분리 (UNVERIFIED)
`docker-compose.s2.sink-net.yml`. Sink를 별도 bridge(`10.211.0.0/24`)에 두고
backend를 그 네트워크에도 연결한다. 이때 전송은 backend의 **다른 인터페이스**로
나가므로 **eth0만 보는 현재 Zeek는 놓칠 수 있다.** 전환하려면 Zeek 캡처
인터페이스를 조정해야 한다(파일 하단 주석 참고). 실측 전 탐지된다고 단정하지 않는다.

### 실측 명령 (Step 1 — Docker 필요)
```bash
# 1) Sink 헬스
curl -s http://127.0.0.1:8091/healthz   # sink-a
curl -s http://127.0.0.1:8092/healthz   # sink-b

# 2) backend 네트워크 공간에서 두 Sink 로 실제 도달 확인(아래 orchestrator 사용 가능)
#    전송 1회씩 후 수신 집계 확인
curl -s http://127.0.0.1:8091/stats
curl -s http://127.0.0.1:8092/stats

# 3) Zeek 가 두 전송을 모두 관측했는지 conn.log 확인
docker exec network-observer-zeek sh -c "tail -n 50 /zeek-logs/conn.log" \
  | grep -E '10.210.0.3[01]'
```

### 합격 기준
- 두 Sink 모두 `/stats`에 전송이 기록되고, 수신 바이트와 **SHA-256이 A/B 동일**.
- `conn.log`에 backend→`10.210.0.30`과 backend→`10.210.0.31`이 **모두** 나타난다
  (한쪽만 보이면 관측 경로 실패 → 배치 재검토).

### 배치 전환
기본(leafy-net) ↔ 대체(sink-net)는 `up` 시 오버레이 파일만 바꾼다. Allowlist의
IP(`aiops/policy/allowlist.yml`)도 선택한 배치의 실측 IP로 맞춘 뒤 규칙을 재생성한다.

## 탐지 (Step 3 / P3 · P6)

### P3 — Allowlist 기반 탐지
`aiops/policy/allowlist.yml` 하나가 단일 정책 소스다. Loki Ruler 규칙과 LLM Network
Context 가 모두 이 파일을 읽어 일관성을 유지한다.

- **허용 방식**: `endpoint`(ip:port 정확 비교, 인가 Sink) / `service`(dst_service 라벨,
  정상 내부 peer db·minio·frontend — 오탐 방지).
- **경보 조건**: 비인가 목적지 + 전송 바이트 누적 임계 초과. `dst_service=unknown`
  단독으로는 공격이 아니다 (목적지 정책 + 전송량으로 판단).
- Loki Ruler 는 YAML 을 직접 읽지 않는다. 정책을 바꾸면 규칙을 재생성·검증·커밋한다:
  ```bash
  cd aiops/pipeline && python -m policy.rulegen ../policy/allowlist.yml \
    ../../monitoring/loki/rules/fake/network-allowlist.yml
  ```
  (`test_policy.py` 가 커밋된 규칙과 정책의 일치를 검사한다 — 드리프트 방지.)

생성되는 규칙 2개:
- `UnauthorizedDataTransfer` (누적, `event_type=connection`): 분할된 여러 연결의
  전송 바이트를 window 안에서 합산 → V1 분할 전송 탐지.
- `UnauthorizedTransferEarly` (조기, `event_type=connection_threshold`): 아래 P6.

### P6 — 전송 중(연결 종료 전) 조기 탐지
`local.zeek` 가 ConnThreshold 로 originator 전송 바이트가 임계값 N(`byte_threshold`,
기본 1MB, redef 가능)을 넘는 순간 `conn_threshold.log` 에 중간 이벤트를 1회(single-shot)
남긴다. enricher 가 이를 `event_type=connection_threshold` canonical event 로 바꾸고,
조기 규칙이 비인가 목적지의 이런 이벤트가 나타나면 즉시 경보한다. 저속 전송(V2)이
연결 종료 전에 탐지되도록 한다.

**중복 집계 방지**: 조기·최종 이벤트는 같은 `connection_id` 를 갖지만 `event_type` 이
다르다. NetworkCollector dedup 은 둘을 보존하고, 규칙은 event_type 으로 분리해(누적은
connection, 조기는 threshold) 바이트를 이중 계산하지 않는다.

**동결 대상(Step 5/6)**: 임계값 N, 전송률 R, 탐지 제한시간 T, min_transfer_bytes 는
아직 FROZEN 이 아니다. 개발용 저속 케이스로 튜닝 후 V2 전에 동결한다 (E4).

## 송신 (Step 2 / P1 · E1)

실제 DB 조회와 HTTP 전송은 **backend 의 netns 를 공유하는 사이드카**(`s2-sender`)가
수행한다(Zeek 와 같은 `network_mode: container:leafy-backend` 패턴). 이렇게 하면
전송이 backend 의 eth0 로 나가 Zeek 가 `src=backend` 로 관측하고, Spring 앱 이미지는
건드리지 않는다.

> E1 설계 결정: 사용자 계획은 "backend 내부에서 직접 실행"을 요구한다. backend 이미지에
> `psql`/`curl` 이 있는지 이 환경에서는 확인할 수 없어(그리고 Spring 앱 비침습 우선),
> 이미지 내용에 의존하지 않고 E1(전송이 backend 네트워크 공간에서 발생)을 보장하는
> netns 사이드카를 1순위로 구현했다. backend 이미지에 도구가 있어 `docker exec` 방식을
> 선호한다면 아래 실측 명령으로 확인 후 전환할 수 있다.
> ```bash
> docker exec leafy-backend sh -lc 'command -v psql curl python3 || true'
> ```

구성 요소:
- `sender/send.py` — 사이드카 안에서 실행: psql CSV 조회(자격증명은 `PGPASSWORD`
  env 로만) → `payload.py` 확장 → 모드별 HTTP 전송 → 송신 메타데이터 독립 기록.
- `sender/Dockerfile` — `python:3.12-slim + postgresql-client`. 빌드 컨텍스트는
  `scenarios/network` (`docker build -t s2-sender:latest -f sender/Dockerfile .`).
- `orchestrator.py` — 호스트에서 지휘: 이미지 빌드 → 사이드카 1회 실행 → 로그에서
  `SENDER_META` 파싱 → Sink `/stats` 와 **교차검증**(송신/수신 바이트·SHA-256 일치).
- `transfer_spec.py` — S2/C-a 는 `TransferSpec` 를 공유하고 **목적지만 다르다**(E2).
  GT 라벨(`should_alert`)은 평가 전용이며 송신기/탐지기/LLM 에 넣지 않는다.

전송 모드: `single`(한 번에) · `split`(여러 연결, V1 튜닝) · `slow`(한 연결 전송률 제한,
V2 저속·P6 조기탐지 대상).

## RCA·검증 (Step 4 / P4 · P5)

### P4 — LLM Network Context 개선 (`aiops/pipeline/prompt/network_section.py`)
flow 를 (src, dst_service, dst_ip, dst_port, protocol)로 집계해 **IP/포트가 다른 흐름을
합치지 않는다.** LLM 에게 목적지 IP:포트, 전송 바이트, 프로토콜·상태, **Allowlist 위반
여부**(같은 정책 평가기 사용 → Loki 규칙과 일관), 조기(threshold) 신호 시각을 제공한다.
조기/최종 중복집계 방지를 위해 bytes_sent 는 최종 이벤트만 합산하고 조기 이벤트는
`early=` 신호로만 표기한다. 토큰 예산(NETWORK_MAX_CHARS) 안에서 수집 상태·해석 규칙은
자르지 않는다. Allowlist 위반은 정책 근거이지 정답 라벨이 아니다.

### P5 — ScenarioVerifier (`scenarios/network/verifier.py`)
세 단계를 **독립적으로** 검증한다: A) Loki Ruler FIRING, B) Alertmanager 수신,
C) 전달(AIOps/Slack). 이전 실행 경보와 섞이지 않도록 t0 이후의 activeAt/startsAt
occurrence 만 선택하고, 실험 간 쿨다운(`wait_ruler_inactive`)으로 Ruler inactive 를
확인한다.

MTTD = **t2(Ruler firing 전이 activeAt) − t0(송신 시작)**. polling 으로 처음 관측한
시각과 전이 시각을 구분해 둘 다 기록한다. Alertmanager group_wait 은 MTTD 에 넣지
않는다. 기존 `scenarios/common/verifier.py`(Prometheus 검증)는 손대지 않는다.

## 실험·평가 (Step 5 V1 / Step 6 V2)

`experiment.py` 가 송신(orchestrator) · 검증(verifier) · 판정/집계(evaluation) · 동결
(freeze)을 묶는다. 같은 전송 코드로 S2/C-a 를 반복 실행하고 TP/FP/TN/FN · MTTD 를
기록한다.

- **E3 판정**: S2 탐지=TP·미탐=FN, C-a 오탐=FP·무오탐=TN. 전송 교차검증 실패 실행은
  무효(invalid)로 집계 제외. Confusion Matrix + precision/recall/specificity/FPR/F1/MTTD.
- **실행 간 격리**: 매 실행 전 Sink `/stats` 초기화 + `wait_ruler_inactive`.
- **E4**: V1(분할)·dev-slow(저속)은 튜닝용, **V2(저속)는 held-out**. V2 는 동결 스냅샷을
  요구하고, 평가 직전 파일 해시가 동결 당시와 다르면(drift) 평가를 거부한다.
- **기본 반복**: S2-V2=30, C-a-V2=75(50~100), 설정 가능.
- **동결 지문**: allowlist·규칙·zeek 파일 SHA-256 + N·T·전송 파라미터 + Git SHA + 시각.

```bash
cd scenarios/network
# (1) V1 튜닝 (분할 전송)
DB_PASSWORD=... python3 experiment.py run V1 --s2-reps 5 --ca-reps 5
# (2) 최종 평가 전 설정 동결
python3 experiment.py freeze --out results/frozen.json --N 1048576 --T 60
# (3) V2 held-out 최종 평가 (동결 필수)
DB_PASSWORD=... python3 experiment.py run V2 --frozen results/frozen.json
```

> ⚠ 실제 실행(전송·Zeek·Loki·FIRING·MTTD)은 Docker/Loki 런타임이 있어야 한다. 이
> 환경엔 없으므로 **최종 수치는 UNVERIFIED** 다. 추정 TP/FN/FP/TN·MTTD 를 만들지 않는다.

## 테스트

```bash
cd scenarios/network && python3 -m unittest discover -s tests -v   # Sink/송신/정책/검증기/평가/동결
cd aiops/pipeline     && python3 -m unittest discover -s tests -v   # 정책/규칙/Network Context
cd aiops/network-observer && PYTHONPATH=enricher python3 -m unittest discover -s tests -v
```

## 검증 상태

이 코드는 Docker 데몬이 없는 환경에서 작성되었다. 런타임(실제 전송/Zeek 관측/Loki
FIRING/MTTD)은 **UNVERIFIED**이며, 단위 테스트로 검증 가능한 로직(전송 파일 생성,
Sink 수신/해시, Allowlist 판정, 규칙 생성 등)만 실행해 확인했다. 자세한 단계별
검증 상태는 커밋/최종 보고서 참조.
