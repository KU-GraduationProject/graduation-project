# S2 / C-a 네트워크 탐지 시나리오 — 구현 보고서

- 브랜치: `feature/s2_scenario` (origin/main 기준 신규 생성)
- 작성 기준: 사용자가 이 스레드에 올린 상세 구현 스펙 + 프로젝트 메모리 요약
- 작업 환경: **Docker 데몬 없는 클라우드 세션.** 런타임(실제 전송·Zeek·Loki·경보·MTTD)은
  실행하지 못했으므로 **UNVERIFIED** 로 표기한다. 추정 TP/FN/FP/TN·MTTD 수치는 만들지 않았다.
- 문서 접근: 업로드된 PDF(시나리오.pdf 등)는 별도로 열지 않고, 스레드의 상세 스펙과
  프로젝트 메모리에 담긴 확정 설계를 기준으로 구현했다. 기존 설계의 목적·정답 라벨은 바꾸지 않았다.

---

## A. 개요 및 범위

침해된 backend 를 가정하고, PostgreSQL `leaked_users`(합성 더미)를 **인가 목적지(Sink A, C-a)**
와 **비인가 목적지(Sink B, S2)** 로 실제 HTTP 전송한다. 탐지는 프로그램 자기보고가 아니라
**Zeek 가 관측한 실제 네트워크 이벤트**로 수행한다.

성공 조건: **S2 탐지(TP) · 동일 조건 C-a 무오탐(TN) · 그 차이를 실제 네트워크 이벤트로 증명.**
정상/공격을 가르는 1차 기준은 전송량·속도가 아니라 **목적지 허용 여부**다 (E2/E3).

범위 제외(사용자 지정 유지): 웹 UI/Nginx 시각화, F2 RCA 장애 시나리오, 기존 Spring 비즈니스
로직 변경.

---

## B. 구현 내역 (Step 1~6 / P1~P6 / E1~E4)

### Step 1 — P2 Sink A/B
- `scenarios/network/sink/sink_server.py` — 순수 stdlib 수신 서버. POST 본문을 스트리밍으로
  받아 수신 바이트·SHA-256 기록, `GET/DELETE /stats` 로 회차별 집계·초기화. A/B 는 같은
  이미지를 `SINK_ROLE` 로만 구분(목적지만 다른 대조 조건). 자기보고 로그를 남기지 않는다.
- `scenarios/network/sink/Dockerfile`, `docker-compose.s2.yml`(기본 leafy-net 배치),
  `docker-compose.s2.sink-net.yml`(대체 sink-net 배치, 관측 미보장 → UNVERIFIED).

### Step 2 — P1 · E1 송신기
- `scenarios/network/payload.py` — DB CSV 를 목표 전송량으로 **결정적** 확장(원본/합성 분리
  집계 + 합성 마커). 같은 입력 → 같은 해시 ⇒ S2/C-a 동일 payload 보장.
- `scenarios/network/sender/send.py` + `Dockerfile` — **backend netns 공유 사이드카**에서
  실행(Zeek 와 같은 패턴). psql 로 조회(자격증명은 `PGPASSWORD` env, argv/로그 비노출),
  전송 모드(single/split/slow)로 HTTP POST, 송신 메타데이터(t0 포함) 독립 기록.
  - **E1 설계 결정**: backend 이미지의 도구 유무를 이 환경에서 확인할 수 없고 Spring 앱
    비침습이 우선이므로, 이미지 내용에 의존하지 않고 "전송이 backend 네트워크 공간에서
    발생"을 보장하는 netns 사이드카를 1순위로 구현. `docker exec` 전환 방법은 README 에 명시.
- `scenarios/network/orchestrator.py` — 호스트 지휘(이미지 빌드→사이드카 실행→`SENDER_META`
  파싱→Sink `/stats` **교차검증**: 송신/수신 바이트·SHA-256 일치).
- `scenarios/network/transfer_spec.py` — S2/C-a 가 `TransferSpec` 공유, **목적지만 다름(E2)**.
  GT 라벨(`should_alert`)은 평가 전용 — 송신기/탐지기/LLM 입력에 넣지 않는다.

### Step 3 — P3 Allowlist · P6 Zeek 조기 탐지
- `aiops/policy/allowlist.yml` — **단일 정책 소스**. endpoint(ip:port 정확 비교)로 인가 Sink,
  service(dst_service)로 정상 내부 peer(db/minio/frontend) 허용 → 오탐 방지. 경보는 비인가
  + 전송량 임계 초과만. `dst_service=unknown` 단독으로는 공격 아님.
- `aiops/pipeline/policy/allowlist.py`(평가기) + `rulegen.py`(YAML→LogQL 생성기).
- `monitoring/loki/rules/fake/network-allowlist.yml` — 생성 규칙 2개:
  - `UnauthorizedDataTransfer`(누적, `event_type=connection`): 분할 연결(V1) 전송량 window
    누적, JSON/unwrap 오류 처리, 정상통신·인가 목적지 제외.
  - `UnauthorizedTransferEarly`(조기, `event_type=connection_threshold`): P6.
- `docker-compose.yml` pipeline 에 allowlist 읽기전용 마운트 + `ALLOWLIST_PATH` 추가(규칙과
  LLM 해석이 같은 정책 사용).
- P6: `aiops/network-observer/zeek/local.zeek` — ConnThreshold 로 orig 바이트 N(기본 1MB,
  redef) 초과 시 `conn_threshold.log` 에 중간 이벤트 1회(single-shot), 새 스트림 유지하도록
  스트림 정리 로직 수정. `enricher/events.py`(빌더 분리, 테스트 가능) + `main.py`(두 로그 동시
  tail, `event_type=connection_threshold` 생성). **중복 집계 방지**: `collector/network.py`
  dedup 키에 event_type 포함(조기/최종 보존), 규칙·Network Context 에서 event_type 분리.

### Step 4 — P4 Network Context · P5 검증기
- `aiops/pipeline/prompt/network_section.py` — flow 를 (src, dst_service, dst_ip, dst_port,
  protocol)로 집계해 **IP/포트 다른 흐름 미병합**. LLM 에 목적지 IP:포트·전송 바이트·
  프로토콜·상태·**Allowlist 위반 여부**(동일 평가기 → 규칙과 일관)·조기 신호 시각 제공.
  bytes_sent 는 최종 이벤트만 합산(조기 `early=` 로만 표기 → 중복집계 방지). 토큰 예산 유지,
  모순 시 네트워크 단독 신뢰 금지 규칙. Allowlist 위반은 근거이지 정답 라벨 아님.
- `scenarios/network/verifier.py` — **세 단계 독립 검증**: A) Loki Ruler FIRING, B)
  Alertmanager 수신, C) 전달(AIOps/Slack). 이전 실행 혼입 방지(t0 이후 occurrence),
  쿨다운(`wait_ruler_inactive`). **MTTD = t2(Ruler firing 전이 activeAt) − t0(송신 시작)**;
  polling 관측 시각과 전이 시각 구분 기록; Alertmanager group_wait 제외. 기존
  `scenarios/common/verifier.py`(Prometheus 검증)는 **미변경**.

### Step 5/6 — V1/V2 실험 · 평가 (E3/E4)
- `scenarios/network/evaluation.py` — TP/FP/TN/FN 분류 + ConfusionMatrix(precision/recall/
  specificity/FPR/F1/accuracy/MTTD). 전송 교차검증 실패 실행은 무효로 집계 제외.
- `scenarios/network/freeze.py` — 설정 동결(allowlist/규칙/zeek SHA-256 + N·T·전송 파라미터 +
  Git SHA + 시각), `verify_unchanged` 로 drift 감지.
- `scenarios/network/experiment.py` — 같은 전송 코드로 S2/C-a 반복 실행, 실행 간 Sink 초기화+
  Ruler inactive 대기, 결과 JSONL/CSV/요약 저장. **V1(분할)·dev-slow(저속)=튜닝, V2(저속)=
  held-out**(동결 필수·drift 시 거부). 기본 반복 S2-V2=30, C-a-V2=75(50~100), 설정 가능. CLI:
  `run`/`freeze`.

---

## C. 검증 상태 (VERIFIED / UNVERIFIED)

**VERIFIED (이 환경에서 실제 실행해 확인):**
- 전송 파일 생성(크기/해시 결정성/원본·합성 분리), Sink 수신·해시·집계·초기화.
- 송신 모드(single/split/slow)별 동작 + 송신↔수신 해시 교차검증(로컬 Sink 상대).
- Allowlist 판정(endpoint/service/포트불일치/unknown=비공격), YAML→LogQL 규칙 생성·검증,
  커밋된 규칙↔정책 일치.
- 조기/최종 이벤트 빌더, collector dedup 분리(중복집계 방지의 전제).
- Network Context: 엔드포인트 미병합·Allowlist 위반 표기·조기 신호·바이트 중복집계 방지.
- 검증기: occurrence 격리·세 단계 독립 판정·MTTD(전이 기준).
- 판정/집계(혼동행렬·지표·무효 제외), 설정 동결(해시 결정성·drift 감지·저장로드),
  실험 계획(E2 공유)·결과 저장·V2 held-out 보호.

**UNVERIFIED (Docker/Loki 런타임 필요 — 이 환경에 Docker 데몬 없음):**
- Step 0 전체 스택 기동 및 A1~A5 런타임 검증.
- Step 1 Sink 실제 도달 + Zeek `conn.log` 에 두 전송 관측(배치 합격 기준 확인).
- 실제 backend netns 전송(psql 조회·HTTP POST), Zeek ConnThreshold 이벤트 발생.
- Loki Ruler FIRING, Alertmanager 수신, Slack 전달, **MTTD 실측**.
- `local.zeek` 의 Zeek 문법/ConnThreshold 동작(Zeek 미설치), LogQL 의 Loki 실행 결과.
- V1/V2 실제 반복 실행 및 **TP/FN/FP/TN·탐지 지연 수치** (생성하지 않음).

---

## D. 테스트 결과

| 스위트 | 명령 | 결과 |
|--------|------|------|
| 네트워크 시나리오 | `cd scenarios/network && python3 -m unittest discover -s tests` | **57 PASS** |
| AIOps 파이프라인 | `cd aiops/pipeline && python3 -m unittest discover -s tests` | **90 PASS** |
| Enricher 이벤트 | `cd aiops/network-observer && PYTHONPATH=enricher python3 -m unittest discover -s tests` | **4 PASS** |
| Remediation(회귀) | `cd aiops/remediation && python3 -m unittest discover -s tests` | **6 PASS** (fastapi·docker 설치 후) |

스펙 §9 테스트 항목 대응: ①Allowlist IP 판정 ②YAML→규칙 생성 ③LogQL/정책 필터
④S2/C-a 전송 동일성 ⑤데이터 크기·SHA-256 ⑥중간/최종 중복 방지 ⑦연결별 바이트 누적
⑧Network Context 생성 ⑨검증기 occurrence 연결 ⑩Confusion Matrix ⑪V1/V2 분리 — 모두
단위 테스트로 커버. ⑫기존 시나리오 회귀: pipeline/remediation 기존 테스트 전부 통과(의존성
설치 외 변경 없음), `scenarios/common/verifier.py`·`run.py`·`batch_runner.py` 미변경.

> 참고: 이 환경엔 `httpx`,`fastapi`,`docker` 가 기본 미설치여서 해당 스위트 실행 전 설치가
> 필요했다(코드 변경과 무관한 환경 문제).

---

## E. 실행 방법

```bash
# Step 0 — 전체 스택 기동 (Docker 필요)
docker compose up -d --build

# Step 1 — Sink 기동(기본 leafy-net 배치) 및 실측
docker compose -f docker-compose.yml -f docker-compose.s2.yml up -d --build sink-a sink-b
curl -s http://127.0.0.1:8091/healthz ; curl -s http://127.0.0.1:8092/healthz
#   합격 기준: 두 Sink /stats 에 수신 기록 + A/B SHA-256 동일, conn.log 에 두 전송 모두 관측

# Step 3 — 정책 변경 시 규칙 재생성
cd aiops/pipeline && python -m policy.rulegen ../policy/allowlist.yml \
  ../../monitoring/loki/rules/fake/network-allowlist.yml

# Step 5 — V1 튜닝
cd scenarios/network && DB_PASSWORD=... python3 experiment.py run V1 --s2-reps 5 --ca-reps 5

# Step 6 — 동결 후 V2 held-out
python3 experiment.py freeze --out results/frozen.json --N 1048576 --T 60
DB_PASSWORD=... python3 experiment.py run V2 --frozen results/frozen.json
```

배치 전환(leafy-net ↔ sink-net), 실측 명령, 합격 기준은 `scenarios/network/README.md` 참조.

---

## F. 남은 작업 · 주의

1. **동결 전 확정(아직 FROZEN 아님)**: Zeek ConnThreshold **N**, 전송률 **R**, 탐지 제한시간
   **T**, Allowlist **min_transfer_bytes**. 개발용 저속 케이스(dev-slow)·V1 으로 튜닝 후 V2 전에
   동결(`experiment.py freeze`). V2 는 held-out 유지(튜닝에 쓰지 않음).
2. **Sink 배치**: 기본은 leafy-net(Zeek eth0 관측 보장). sink-net 분리는 Zeek 캡처 인터페이스
   조정이 필요하며 Step 1 실측 전에는 탐지된다고 단정하지 않는다.
3. **Zeek 스크립트**: `local.zeek` 의 ConnThreshold 는 문서화된 API 기준으로 작성했으나 Zeek
   런타임으로 실행 검증하지 못했다(UNVERIFIED). Step 0 기동 시 `conn_threshold.log` 생성과
   조기 이벤트 발생을 확인할 것.
4. **LogQL**: 생성된 규칙의 문자열 구조·정책 반영은 테스트했으나 Loki 실행 결과는 미검증.
   Step 3 에서 샘플 이벤트로 FIRING 확인 필요.
5. **대조 공정성(E2)**: S2/C-a 는 동일 `TransferSpec` 를 공유하고 목적지만 다르다. GT 라벨은
   평가 측에만 두며 탐지기/LLM 입력에 넣지 않았다. 규칙·LLM 설명은 같은 Allowlist 평가기를
   쓴다(일관성).
6. **데이터**: `leaked_users` 는 합성 더미이며, 전송 파일의 합성 패딩은 원본과 분리 집계·표기해
   "전체가 원본"이라는 주장을 피했다.
