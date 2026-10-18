# Cross-platform Traffic Capture PoC - Windows

> Issue #4 (spike) — **구현이 아니라 capture 가능성 검증 결과 기록 문서**이다.
> 선행 문서: [../NETWORK_OBSERVABILITY_REQUIREMENTS.md](../NETWORK_OBSERVABILITY_REQUIREMENTS.md) (R1–R7, C1–C4, PoC Success Criteria 기준)
> Baseline: [../../verification/PRE_IMPLEMENTATION_BASELINE_VERIFICATION.md](../../verification/PRE_IMPLEMENTATION_BASELINE_VERIFICATION.md)
>
> - 실행일: 2026-09-20
> - 이 문서는 **Windows Docker Desktop 실측 결과만** 담는다. Mac은 `NOT TESTED`.
> - `docker-compose.yml`, application source, logging/monitoring/pipeline/remediation 코드는 **수정하지 않았다.**
> - Zeek는 정식 서비스로 추가하지 않았다. 실험은 임시 container / 임시 compose 파일로만 수행했다.

---

## Environment

| Item | Value |
|---|---|
| OS | Windows 11 Pro 10.0.26200 (셸: MINGW64_NT-10.0-26200, Git Bash) |
| Docker | Server 28.5.1 / Client 28.5.1 (Docker Desktop, WSL2 backend) |
| Docker Compose | v2.40.2-desktop.1 |
| Git branch | `feature/kjh` |
| Git commit | `8d8a11ad1af6c55c9656f8aa043cfd565abdbcaf` ("#3 완료") |
| Docker Desktop VM kernel | `6.6.87.2-microsoft-standard-WSL2` |

### 실행 중 서비스 (`docker compose ps -a` 요약)

| 상태 | 서비스 |
|---|---|
| Up | frontend, backend, db, fluentd, prometheus, alertmanager, loki, grafana, node-exporter, cadvisor, ollama, pipeline, remediation |
| Exited (사전 상태, 변경하지 않음) | `nginx-exporter` (Exited 0), `postgres-exporter` (Exited 2) |

> 참고: 두 exporter가 내려가 있어 `leafy-net` 안의 관측용 노이즈 트래픽이 평소보다 적은 상태였다.
> 이는 PoC 결과 판정에 유리하게 작용했을 수 있으므로, 재현 시 exporter가 살아있으면 필터링이 더 필요하다.

---

## Runtime Network

`docker network inspect graduation-project_leafy-net` 기준

- name: `graduation-project_leafy-net`, driver: `bridge`
- subnet: `172.18.0.0/16`, gateway: `172.18.0.1` → Baseline 문서와 일치
- VM 내부 bridge interface 이름: **`br-5557cd1b31e3`** (network id `5557cd1b31e3` 유래, **runtime 값**)

| Service | Container | IP | Network |
|---|---|---|---|
| frontend | leafy-frontend | 172.18.0.5 | graduation-project_leafy-net |
| backend | leafy-backend | 172.18.0.4 | graduation-project_leafy-net |
| backend | leafy-backend | 172.21.0.12 | graduation-project_mgmt-net (eth1) |
| db | leafy-db | 172.18.0.3 | graduation-project_leafy-net |
| (참고) fluentd | fluentd | 172.18.0.2 | graduation-project_leafy-net |

> IP는 runtime 값이며 identity로 고정하지 않는다 (#3 §7.2). 위 값은 이번 실행의 evidence로만 기록한다.
> `backend`는 2개 network에 속하므로 **관측 대상 interface를 반드시 구분해야 한다** (아래 §Case 1 주의사항 참고).

---

## Candidate Results

| Candidate | Case 1 | Case 2 | Privilege | Compose Reproducibility | Result |
|---|---|---|---|---|---|
| A. Docker bridge capture (`network_mode: host` + `br-<id>`) | PASS | PASS | `NET_ADMIN` + `NET_RAW` (privileged 불필요) | 조건부 가능 (interface 이름이 runtime 값) | PASS |
| B. Service network namespace sharing (`network_mode: container:leafy-backend`) | PASS | PASS | `NET_ADMIN` + `NET_RAW` (privileged 불필요) | 가능 (`network_mode` 로 선언 가능) | PASS |
| C. eBPF | - | - | privileged 필요 + 추가 요건 미충족 | 미검증 | NOT TESTED |
| D. Traffic mirroring | - | - | 네트워크 설정 변경 필요 | 미검증 | NOT TESTED |

### C. eBPF — NOT TESTED 사유 (실측한 사실만 기록)

- VM 커널 `6.6.87.2-microsoft-standard-WSL2`, BTF 존재 확인: `/sys/kernel/btf/vmlinux` (6,050,732 bytes) → CO-RE 방식 가능성 있음
- 그러나 `--privileged --network host` 로도 **debugfs / tracefs 가 마운트되어 있지 않음** (`/sys/kernel/debug`, `/sys/kernel/tracing` 비어 있음, `mount | grep -c debugfs` = 0)
- 즉 kprobe/tracepoint 기반 도구는 추가 설정 없이는 동작하지 않을 가능성이 있다.
- A/B가 이미 두 Case를 모두 만족했고, eBPF 검증에는 privileged + 추가 host/VM 설정이 필요하므로 **이번 PoC에서는 실행하지 않았다.**

### D. Traffic mirroring — NOT TESTED 사유

- 구현하려면 실행 중인 network에 `tc` / `iptables TEE` 등 **네트워크 설정 변경**이 필요하다.
- 이는 이번 작업의 안전 규칙(host/Docker 네트워크 설정 임의 변경 금지)에 저촉되므로 실행하지 않았다.
- A/B로 요구사항이 충족되어 추가 검증 필요성이 낮다.

---

## Case 1 Evidence

**Traffic:** `frontend -> backend` (leafy-frontend nginx → leafy-backend:8080, HTTP)

트래픽 생성 방법 (application 코드 변경 없음):

```bash
# nginx는 :80에서 https로 301 redirect하므로 :443을 사용해야 실제 proxy_pass가 발생한다
curl -sk -H "Host: leafy-pr.com" https://localhost/api/plants
# -> HTTP 302 (backend Spring Security가 oauth2로 redirect). 302 응답 자체는 PoC 판정과 무관하다.
```

### Candidate B (namespace sharing) — 사용 명령

```bash
docker run -d --name poc-ns-backend \
  --network container:leafy-backend \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  poc-capture:tmp "tcpdump -i eth0 -nn -l -tttt 'tcp port 8080 or tcp port 5432' > /tmp/cap.txt 2>&1"
```

capture output (일부):

```text
2026-09-20 13:08:56.229629 IP 172.18.0.5.53602 > 172.18.0.4.8080: Flags [S], seq 472584635, win 64240, length 0
2026-09-20 13:08:56.229645 IP 172.18.0.4.8080 > 172.18.0.5.53602: Flags [S.], seq 2595709690, ack 472584636, win 65160, length 0
2026-09-20 13:08:56.229686 IP 172.18.0.5.53602 > 172.18.0.4.8080: Flags [.], ack 1, win 502, length 0
2026-09-20 13:08:56.229736 IP 172.18.0.5.53602 > 172.18.0.4.8080: Flags [P.], seq 1:184, ack 1, length 183: HTTP: GET /api/plants HTTP/1.0
2026-09-20 13:08:56.229742 IP 172.18.0.4.8080 > 172.18.0.5.53602: Flags [.], ack 184, win 508, length 0
2026-09-20 13:08:56.230788 IP 172.18.0.4.8080 > 172.18.0.5.53602: Flags [P.], seq 1:416, ack 184, length 415: HTTP: HTTP/1.1 302
```

### Candidate A (bridge capture) — 사용 명령

```bash
docker run -d --name poc-bridge \
  --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  poc-capture:tmp "tcpdump -i br-5557cd1b31e3 -nn -l -tttt 'tcp port 8080 or tcp port 5432' > /tmp/cap.txt 2>&1"
```

capture output (일부):

```text
listening on br-5557cd1b31e3, link-type EN10MB (Ethernet)
2026-09-20 13:07:11.505266 IP 172.18.0.5.47092 > 172.18.0.4.8080: Flags [S], seq 593977268, win 64240, length 0
2026-09-20 13:07:11.505286 IP 172.18.0.4.8080 > 172.18.0.5.47092: Flags [S.], seq 811770829, ack 593977269, length 0
2026-09-20 13:07:11.505342 IP 172.18.0.5.47092 > 172.18.0.4.8080: Flags [P.], seq 1:184, ack 1, length 183: HTTP: GET /api/plants HTTP/1.0
2026-09-20 13:07:11.506302 IP 172.18.0.4.8080 > 172.18.0.5.47092: Flags [P.], seq 1:416, ack 184, length 415: HTTP: HTTP/1.1 302
```

### 확인된 정보

| 항목 | 값 (Candidate B 기준) | 확인 |
|---|---|---|
| capture 위치 | backend netns `eth0` (Candidate B) / VM `br-5557cd1b31e3` (Candidate A) | O |
| source IP | `172.18.0.5` (= leafy-frontend) | O |
| destination IP | `172.18.0.4` (= leafy-backend) | O |
| source port | `53602` (ephemeral, 요청마다 변동) | O |
| destination port | `8080` | O |
| protocol | TCP (payload: HTTP) | O |
| connection state | SYN → SYN/ACK → ACK → PSH → FIN 전체 lifecycle 관측 | O |
| bytes | 패킷별 `length` 확인 (183 / 415 …) — 연결 단위 합산은 후처리 필요 | 부분 |
| duration | 동일 4-tuple의 first/last timestamp로 산출 가능 (`13:08:56.229629` ~ 종료) | 산출 가능 |

### 주의사항 (중요)

- 최초 시도에서 `tcpdump -i any` 를 사용했더니 **mgmt-net(eth1)의 `prometheus(172.21.0.4) → backend:8080` 트래픽이 섞여 나왔다.**
- `backend`는 leafy-net / mgmt-net 양쪽에 붙어 있으므로, **port 8080 필터만으로는 Case 1을 식별할 수 없다.**
- Case 1을 정확히 관측하려면 **interface(`eth0`) 또는 leafy-net 대역으로 반드시 범위를 좁혀야 한다.** → #7 / #5 설계 시 반영 필요.

**Result: PASS** (Candidate A, B 모두)

---

## Case 2 Evidence

**Traffic:** `backend -> db` (leafy-backend → leafy-db:5432, PostgreSQL over TCP)

- business query를 별도로 발생시키지 않았다. **Hikari connection pool의 keepalive 트래픽**을 대상으로 사용했다 (#3 §2.4 전제에 따라 허용).
- 즉 별도 트래픽 생성 명령 없이, capture 중 자연 발생한 실제 service communication이다.

capture output (Candidate B, backend netns `eth0`):

```text
2026-09-20 13:08:55.785448 IP 172.18.0.4.55798 > 172.18.0.3.5432: Flags [P.], seq 256477474:256477480, ack 4202936315, win 501, length 6
2026-09-20 13:08:55.785569 IP 172.18.0.3.5432 > 172.18.0.4.55798: Flags [P.], seq 1:12, ack 6, win 509, length 11
2026-09-20 13:08:55.785576 IP 172.18.0.4.55798 > 172.18.0.3.5432: Flags [.], ack 12, win 501, length 0
```

동일 connection이 Candidate A(bridge `br-5557cd1b31e3`)에서도 **같은 timestamp로 관측됨** (두 방식의 상호 검증):

```text
2026-09-20 13:08:55.785468 IP 172.18.0.4.55798 > 172.18.0.3.5432: Flags [P.], seq 256477474:256477480, ack 4202936315, length 6
2026-09-20 13:08:55.785568 IP 172.18.0.3.5432 > 172.18.0.4.55798: Flags [P.], seq 1:12, ack 6, length 11
```

### 확인된 정보

| 항목 | 값 | 확인 |
|---|---|---|
| capture 위치 | backend netns `eth0` / VM `br-5557cd1b31e3` | O |
| source IP | `172.18.0.4` (= leafy-backend) | O |
| destination IP | `172.18.0.3` (= leafy-db) | O |
| source port | `55798` (pool connection별 상이: 41044, 44462, 47100 등도 관측) | O |
| destination port | `5432` | O |
| protocol | TCP (PostgreSQL) | O |
| connection state | `conntrack`에서 `ESTABLISHED` 확인 (아래) | O |
| bytes | 패킷별 `length` 확인 (6 / 11 / 0) | 부분 |
| duration | 장기 유지 connection (pool) — timestamp 기반 산출 가능 | 산출 가능 |

### 보조 evidence — connection state / 방향성 (conntrack)

```bash
docker run --rm --network host --cap-add NET_ADMIN --cap-add NET_RAW \
  poc-capture:tmp "conntrack -L -p tcp | grep -E '5432|8080'"
```

```text
tcp 6 431924 ESTABLISHED src=172.18.0.4 dst=172.18.0.3 sport=41044 dport=5432 ... [ASSURED]
tcp 6     46 TIME_WAIT   src=172.18.0.5 dst=172.18.0.4 sport=43646 dport=8080 ... [ASSURED]
tcp 6 431977 ESTABLISHED src=172.18.0.4 dst=172.18.0.3 sport=47100 dport=5432 ... [ASSURED]
```

→ `connection_state`(ESTABLISHED / TIME_WAIT)와 **연결의 originator 방향**을 packet capture와 별개로 확보 가능함을 확인했다.
(단, conntrack은 host/VM netns 기준이므로 Candidate A 계열에서만 동일하게 사용 가능하다.)

**Result: PASS** (Candidate A, B 모두)

---

## Requirement Evaluation

| Requirement | Result | Evidence |
|---|---|---|
| R1 frontend -> backend | PASS | `172.18.0.5:53602 > 172.18.0.4:8080` SYN~FIN 전체 관측 (Candidate A, B) |
| R2 backend -> db | PASS | `172.18.0.4:55798 > 172.18.0.3:5432` 관측 + conntrack ESTABLISHED |
| R3 Mac Docker Desktop | NOT TESTED | 이번 실행 플랫폼이 Windows이므로 추측 판정하지 않음 |
| R4 Windows Docker Desktop | PASS | 본 문서 전체가 Windows Docker Desktop 실측 결과 |
| R5 application unchanged | PASS | application source / compose / logging / monitoring 코드 무변경. `git status` clean (§Safety 참고). leafy-frontend/backend/db 컨테이너 재시작 없음 (PoC 전후 uptime 연속) |
| R6 Compose reproducibility | PASS (조건부) | 임시 `docker-compose.poc.yml`로 A/B 두 observer 기동 및 capture 성공. 단 Candidate A는 `br-<network-id>`가 runtime 값이라 compose에 고정 불가 |
| R7 raw traffic visibility | PASS | src/dst IP, src/dst port, protocol, TCP flag(connection state), packet length 확보. structured event 생성에 필요한 원천 정보 충분 |

### R6 상세 — 임시 Compose 검증 결과

`docs/network-observability/poc/tmp/docker-compose.poc.yml` (기존 compose 파일과 **완전 분리된 별도 파일**)로 검증:

```bash
docker compose -f docker-compose.poc.yml config --quiet   # CONFIG VALID
docker compose -f docker-compose.poc.yml up -d            # poc-ns-backend, poc-bridge 모두 Up
```

- `network_mode: "container:leafy-backend"` → Compose에서 정상 선언/동작 확인
- `network_mode: host` + `cap_add: [NET_ADMIN, NET_RAW]` → Compose에서 정상 선언/동작 확인
- **발견한 함정**: 이미지 `ENTRYPOINT ["/bin/sh","-c"]` 사용 시 compose `command:`를 문자열로 주면 Compose가 공백 단위로 분해해 `sh -c tcpdump` 만 실행된다.
  이때 tcpdump가 `-i` 옵션을 못 받아 **엉뚱한 interface(`services1`)를 감시하며 조용히 실패**했다.
  `command: ["<전체 명령 1개 문자열>"]` 형태(단일 원소 리스트)로 고쳐야 정상 동작했다. → #5 구현 시 반드시 주의.

---

## Cross-platform Findings

### host bridge visibility (C1) — 실측

- **Windows host(OS) 레벨에는 Docker bridge adapter가 존재하지 않는다.**
  `Get-NetAdapter` 결과: `Hamachi`, `vEthernet (WSL (Hyper-V firewall))`, 이더넷, Bluetooth 네트워크 연결 — `docker0` / `br-*` 없음.
- 반면 `docker run --network host` 컨테이너에서 `/proc/net/dev`를 읽으면 **Docker Desktop WSL2 VM의 netns**가 보이며, 여기에는 존재한다:
  `docker0`, `br-5557cd1b31e3`(leafy-net), `br-00f5a75b3343`(mgmt-net), 다수 `veth*`, `eth0`, `services1`
- **결론: C1은 "Windows host에서는 불가, Docker Desktop VM netns에서는 가능"이다.**
  `--network host`는 Windows에서 "호스트 OS 네트워크"가 아니라 "VM 네트워크"를 의미한다. #3 C1의 "당연히 가능하다고 가정하지 않는다"가 실제로 맞았다.

### namespace visibility

- `--network mode: container:leafy-backend` 로 backend netns 진입 성공. 관측된 주소: `eth0=172.18.0.4`(leafy-net), `eth1=172.21.0.12`(mgmt-net), `lo`.
- **backend 한 곳의 netns만 공유해도 Case 1(inbound)과 Case 2(outbound)를 동시에 관측할 수 있음을 확인했다.** → observer 1개로 PoC 요구 충족.
- 단 backend가 multi-homed이므로 interface 단위 구분이 필수 (§Case 1 주의사항).

### required privileges

- 두 후보 모두 **`--privileged` 없이 `NET_ADMIN` + `NET_RAW` 만으로 성공**했다. (최소 권한 관점에서 긍정적)
- `--network host` 또는 `--network container:<name>` 은 privilege가 아니라 network mode이지만, **다른 컨테이너/VM의 네트워크를 들여다보는 권한**이라는 점은 #5에서 보안 관점으로 별도 검토 필요.
- `conntrack` 조회에도 `NET_ADMIN`으로 충분했다.
- eBPF 경로는 privileged가 필요할 것으로 보이나 **검증하지 않았다** (위 Candidate C).

### Docker Desktop 제약

- `tcpdump -i any` 는 promiscuous mode 미지원 경고를 출력한다(`That device doesn't support promiscuous mode`). 캡처 자체는 동작했으나 **`any`는 network 구분이 사라져 Case 식별에 부적합**하다.
- debugfs / tracefs 미마운트 → eBPF 계열 도구 제약 가능성.
- bridge interface 이름이 `br-<network-id 12자>` 로 **compose project 재생성 시 변경된다.** (`docker network inspect -f '{{.Id}}' | cut -c1-12` 로 runtime 유도는 가능하나 compose 정적 선언 불가)

### platform-specific 고려사항

- Windows에서는 Docker Desktop이 WSL2 backend로 동작하므로 capture 지점이 "VM 내부"로 한 단계 들어간다.
- Mac은 Docker Desktop이 다른 VM(virtualization framework) 위에서 동작하므로 **`--network host`의 동작이 Windows와 동일하다고 가정할 수 없다.** → Mac 실측 필요.
- 반면 `network_mode: container:<name>` 은 컨테이너 netns 공유이므로 **VM 구현 방식에 덜 의존적일 것으로 예상**되나, 이 역시 Mac에서 확인해야 한다 (추측 금지).

---

## Recommended Capture Method

**Current platform candidate (Windows): Candidate B — Service network namespace sharing**

```yaml
# 개념 예시 (production 구현 아님)
observer:
  network_mode: "container:leafy-backend"
  cap_add: ["NET_ADMIN", "NET_RAW"]
```

선정 근거 (Windows 실측 기준):

| 관점 | Candidate B (namespace sharing) | Candidate A (bridge capture) |
|---|---|---|
| Case 1 / Case 2 | 둘 다 PASS (observer 1개) | 둘 다 PASS |
| Compose 정적 선언 | **가능** (`container:leafy-backend` — 이름 고정) | interface 이름이 runtime 값 → 정적 선언 불가 |
| platform 의존성 | VM 구현에 덜 의존할 것으로 예상 (Mac 검증 필요) | `--network host`의 의미가 platform별로 다름 |
| 관측 범위 | backend 관련 트래픽으로 한정 | leafy-net 전체 (향후 attacker traffic 확장에 유리) |
| privilege | NET_ADMIN + NET_RAW | NET_ADMIN + NET_RAW (+ VM netns 접근) |
| conntrack 사용 | 불가/제한 | 가능 |

> Candidate A도 Windows에서 PASS했으므로 **탈락이 아니라 보조 후보로 유지**한다.
> leafy-net 전체 가시성이 필요해지는 시점(공격 트래픽 확장)에는 A가 유리할 수 있다.
>
> **Mac 검증 전이므로 최종 확정이 아니다.**

---

## Unresolved

### Mac Docker Desktop에서 반드시 검증할 항목

1. `network_mode: container:leafy-backend` 로 Case 1 / Case 2 관측 가능 여부 (Candidate B) — 최우선
2. `--network host` 가 Mac에서 무엇을 의미하는지, `br-<id>` bridge interface가 보이는지 (Candidate A / C1)
3. `NET_ADMIN` + `NET_RAW` 만으로 충분한지, privileged가 필요한지
4. `conntrack` 사용 가능 여부
5. Mac host(OS) 레벨에 Docker bridge adapter가 없는 것이 맞는지 확인 (Windows와 동일한지)
6. eBPF 전제(BTF / debugfs / tracefs) 상태 비교

### 플랫폼 무관하게 남은 항목

- bridge interface 이름(`br-<network-id>`)을 Compose에서 안정적으로 다루는 방법 (Candidate A 채택 시)
- backend가 multi-homed이므로 **leafy-net 트래픽만 선별하는 필터 규칙**을 어디서 정의할지 (#7 / #5)
- packet 단위 `length` → **connection 단위 `bytes` / `duration` 집계 책임을 어디에 둘지** (Observer vs 후처리) → #7
- IP → service/container identity 매핑 수행 지점 → #7
- observer가 다른 컨테이너 netns를 들여다보는 구성의 **보안 영향 검토** → #5

---

## Final Status

**PLATFORM PASS (Windows)**

| PLATFORM PASS 조건 | 결과 |
|---|---|
| Case 1 network traffic capture 성공 | PASS (`172.18.0.5:53602 > 172.18.0.4:8080`, TCP, SYN~FIN) |
| Case 2 network traffic capture 성공 | PASS (`172.18.0.4:55798 > 172.18.0.3:5432`, TCP, ESTABLISHED) |
| application source 수정 없음 | PASS (무변경, 컨테이너 재시작 없음) |
| structured event 생성에 필요한 raw traffic 정보 확보 가능 | PASS (src/dst IP·port, protocol, connection state 확보) |

> ⚠️ **Issue #4 전체는 아직 COMPLETE가 아니다.** Mac Docker Desktop 실측(`MAC_TRAFFIC_CAPTURE_POC.md`)이 없으므로
> `CROSS_PLATFORM_CAPTURE_DECISION.md`는 생성하지 않았다.

---

## Safety / Cleanup

### 변경한 것

생성한 파일은 아래뿐이다 (기존 파일 수정 0건, `git status` clean 상태에서 시작).

| 경로 | 목적 | 삭제 가능 |
|---|---|---|
| `docs/network-observability/poc/WINDOWS_TRAFFIC_CAPTURE_POC.md` | 본 보고서 | 보존 |
| `docs/network-observability/poc/tmp/Dockerfile.capture` | tcpdump/iproute2/conntrack-tools 포함 임시 capture 이미지 정의 | O |
| `docs/network-observability/poc/tmp/docker-compose.poc.yml` | R6(Compose 재현성) 검증용 임시 compose. **기존 `docker-compose.yml`과 완전 분리된 별도 파일이며 override가 아니다** | O |

### 임시 파일이 필요했던 이유

- `Dockerfile.capture`: host에 패키지를 설치하지 않고 capture 도구를 확보하기 위해, 이미 로컬에 있던 `nginx:alpine`을 base로 임시 이미지를 빌드했다. (host 패키지 설치 0건)
- `docker-compose.poc.yml`: R6는 "Compose로 재현 가능한가"를 묻기 때문에 `docker run`만으로는 검증할 수 없었다. 기존 compose를 수정하지 않기 위해 별도 파일로 만들었다.

### 정리 상태

```bash
docker compose -f docker-compose.poc.yml down   # 완료
docker ps -a --filter name=poc-                 # 결과 없음 (정리 완료)
docker ps --filter name=leafy                   # leafy-backend/db/frontend 계속 Up (영향 없음)
```

남아 있는 것: 임시 이미지 `poc-capture:tmp` (필요 시 `docker rmi poc-capture:tmp`로 제거)

### USER ACTION REQUIRED

이번 실행에서 **필요했던 host/Docker Desktop 설정 변경은 없다.** 다음 항목만 향후 판단이 필요하다.

1. **eBPF 후보를 실제로 검증하려면** debugfs/tracefs 마운트 등 Docker Desktop VM 설정 확인이 필요할 수 있다. → 실행하지 않았음. 승인 필요.
2. **Mac에서 동일 PoC를 실행**해야 Issue #4를 닫을 수 있다. → 사용자 실행 필요.
3. `nginx-exporter`, `postgres-exporter`가 Exited 상태다. → 이번 PoC에서 **의도적으로 건드리지 않았다.** 복구 여부는 별도 판단 사항.
