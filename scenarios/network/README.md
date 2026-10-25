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
| `scenarios/network/policy/allowlist.yml` | 목적지 Allowlist(사람 작성) — P3 단일 정책 소스 |
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
IP(`policy/allowlist.yml`)도 선택한 배치의 실측 IP로 맞춘다.

## 테스트

```bash
cd scenarios/network && python3 -m unittest discover -s tests -v
```

## 검증 상태

이 코드는 Docker 데몬이 없는 환경에서 작성되었다. 런타임(실제 전송/Zeek 관측/Loki
FIRING/MTTD)은 **UNVERIFIED**이며, 단위 테스트로 검증 가능한 로직(전송 파일 생성,
Sink 수신/해시, Allowlist 판정, 규칙 생성 등)만 실행해 확인했다. 자세한 단계별
검증 상태는 커밋/최종 보고서 참조.
