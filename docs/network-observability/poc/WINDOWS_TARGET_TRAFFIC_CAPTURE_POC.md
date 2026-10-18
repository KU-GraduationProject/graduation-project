# Target Architecture Traffic Capture PoC - Windows

> Issue #4 (spike) — Target Architecture 기준 capture mechanism 검증 결과.
> 선행: [../NETWORK_OBSERVABILITY_REQUIREMENTS.md](../NETWORK_OBSERVABILITY_REQUIREMENTS.md)
> Legacy evidence (보존, 삭제/덮어쓰기 없음): [WINDOWS_TRAFFIC_CAPTURE_POC.md](WINDOWS_TRAFFIC_CAPTURE_POC.md)
>
> 실행일: 2026-10-04
> **결론 요약: PLATFORM PARTIAL** — Target Case 2의 전제(Host PostgreSQL)가 이 환경에 존재하지 않아 실측 불가.
> 단, 그 핵심 메커니즘(backend netns observer가 host-bound traffic을 보는가)은 **별도 probe로 검증했다.**

---

## 1. Environment

| Item | Value |
|---|---|
| OS | Windows 11 Pro 10.0.26200 (셸: MINGW64_NT-10.0-26200) |
| Architecture | x86_64 |
| Docker Desktop | 예 (WSL2 backend) |
| Docker | Server / Client 28.5.1 |
| Docker Compose | v2.40.2-desktop.1 |
| Git Branch | `feature/network-poc` |
| Git Commit | `ba2b2a0` (Merge pull request #12 from KU-GraduationProject/feature/kjh) |

> 실행 시점에 Docker engine이 내려가 있어 **Docker Desktop 애플리케이션을 기동**했다.
> Docker Desktop **설정은 변경하지 않았다** (기동만 수행, reversible).

---

## 2. Target Architecture

### 2.1 팀원이 정의한 To-Be (지시서 기준)

```text
Client -> Tailscale -> Windows Desktop
  -> Leafy Frontend (Nginx container, gicks/ai-ops-leafy-frontend)
  -> Leafy Backend  (Spring container, gicks/ai-ops-leafy-backend)
  -> PostgreSQL 17  (Windows Host, container 아님, :5432)

Frontend/Nginx -> MinIO container (leafy-minio) -> /files/*

application subnet: 10.203.0.0/24
frontend nginx:     10.203.0.10
backend:            TRUSTED_PROXIES=10.203.0.10/32
```

### 2.2 실제 source/config에서 확인된 구조 (As-Is)

확인 대상: `docker-compose.yml` (저장소 내 유일한 compose 파일), 전체 branch.

```text
leafy-frontend (gicks/leafy-frontend:latest)   -- HTTP --> backend:8080
leafy-backend  (gicks/leafy-backend:latest)    -- JDBC --> db:5432  (leafy-db container, postgres:16)
```

- `SPRING_DATASOURCE_URL: jdbc:postgresql://db:5432/leafy` → **DB는 여전히 Docker container**
- networks: `leafy-net`(172.18.0.0/16), `mgmt-net`(172.21.0.0/16) — compose에 subnet 미지정, Docker 런타임 할당
- MinIO: compose에 **없음**
- `back/deploy` 등 별도 deployment compose: **없음**

---

## 3. Document / Implementation Differences

**DOCUMENT / IMPLEMENTATION MISMATCH — 다수 존재. 어느 쪽도 수정하지 않았다.**

확인 방법 (전체 branch 대상):

```bash
git grep -lI -iE "minio|ai-ops-leafy|10\.203\.|TRUSTED_PROXIES" \
  origin/main origin/develop origin/feature/kjh origin/repair_ver3
# -> 전 branch에서 결과 없음
```

| # | 항목 | Target 문서 (To-Be) | 실제 repo / runtime (As-Is) | 영향 |
|---|---|---|---|---|
| M1 | **DB runtime** | Windows Host PostgreSQL 17 (container 아님) | `leafy-db` container (`postgres:16`), datasource `jdbc:postgresql://db:5432/leafy` | **Target Case 2 검증 불가 (치명)** |
| M2 | Host PostgreSQL 존재 | 존재 전제 | **Windows host에 5432 LISTEN 없음**, `postgresql*` 서비스 없음 | Target Case 2 검증 불가 |
| M3 | frontend image | `gicks/ai-ops-leafy-frontend` | `gicks/leafy-frontend:latest` | 이미지 미존재 |
| M4 | backend image | `gicks/ai-ops-leafy-backend` | `gicks/leafy-backend:latest` | 이미지 미존재 |
| M5 | MinIO | `leafy-minio` container, `/files/*` | compose에 서비스 없음, `leafy-minio` container 없음 | MinIO finding 불가 |
| M6 | application subnet | `10.203.0.0/24` | `172.18.0.0/16` (leafy-net, Docker 자동 할당) | 고정 IP 체계 미적용 |
| M7 | frontend 고정 IP | `10.203.0.10` | 고정 IP 설정 없음. runtime `172.18.0.5` (기동 순서 의존) | TRUSTED_PROXIES 전제 불성립 |
| M8 | `TRUSTED_PROXIES` | `10.203.0.10/32` | **어떤 config/source에도 존재하지 않음** | XFF 처리 미구현 |
| M9 | Tailscale | 경로에 포함 | 저장소/compose에 흔적 없음 | 이번 범위 아님 |

> 판단: 팀원 Target Architecture는 **아직 코드/배포에 반영되지 않은 설계 문서** 상태다.
> 지시서 원칙대로 어느 한쪽으로 자동 수정하지 않았고, 실제 실행 상태를 기준으로 판정했다.

### subnet overlap 확인 (변경 없음)

| network | subnet |
|---|---|
| graduation-project_leafy-net | 172.18.0.0/16 |
| graduation-project_mgmt-net | 172.21.0.0/16 |
| Target 의도 | 10.203.0.0/24 |

- Target `10.203.0.0/24`는 현재 AIOps network(172.18/172.21)와 **overlap 없음** → 도입 시 충돌 위험은 낮아 보인다.
- 단 `172.18.0.0/16`은 /16이라 Docker 기본 대역과 겹치기 쉬운 구조다. (관찰만, 변경하지 않음)

---

## 4. Runtime Identity

`docker network inspect graduation-project_leafy-net` 기준 (IP는 evidence일 뿐 identity 아님)

| Service | Container | Runtime | IP / Endpoint | Network |
|---|---|---|---|---|
| frontend | leafy-frontend | container | 172.18.0.5 | graduation-project_leafy-net |
| backend | leafy-backend | container | 172.18.0.4 (eth0) / 172.21.0.12 (eth1) | leafy-net + mgmt-net (**multi-homed**) |
| db | **leafy-db (container)** — Target은 `null` 이어야 함 | **container (As-Is)** | 172.18.0.3:5432 | graduation-project_leafy-net |
| db (Target) | null | Windows Host | **미존재** (5432 LISTEN 없음) | N/A |
| minio | leafy-minio | **미존재** | N/A | N/A |

- leafy-net: subnet `172.18.0.0/16`, gateway `172.18.0.1`
- 참고: `fluentd` 172.18.0.2도 leafy-net에 연결됨

---

## 5. Capture Candidate

검증한 방식: **Service Network Namespace Sharing** (우선순위 1)

| 항목 | 값 |
|---|---|
| 방식 | observer container가 backend의 network namespace 공유 |
| 사용 semantic | `--network container:leafy-backend` |
| `network_mode: "service:backend"` 검토 | **이번엔 사용하지 않음.** Leafy가 기존 compose project로 이미 떠 있어 observer를 동일 project 안에 넣으려면 production compose 수정이 필요 → 금지 사항. `service:` semantic은 observer를 같은 compose project에 정식 편입하는 #5 단계에서 적용 검토 |
| capability | `NET_ADMIN`, `NET_RAW` 만 부여 |
| `--privileged` | **사용하지 않음** (불필요 확인) |
| capture 도구 | tcpdump (임시 이미지 `poc-capture:tmp`, base `nginx:alpine`) |
| capture interface | `eth0` (leafy-net) / 호스트 방향 probe는 `-i any` |

---

## 6. Case 1 — frontend -> backend

**Traffic:** leafy-frontend (nginx) → leafy-backend:8080

트래픽 생성 (application source 변경 없음, 실제 Leafy 경로 사용):

```bash
# :80은 https로 301 redirect하므로 :443을 사용해야 proxy_pass가 실제 발생
curl -sk -H "Host: leafy-pr.com" https://localhost/api/plants
```

observer 기동:

```bash
docker run -d --name poc-ns \
  --network container:leafy-backend \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  poc-capture:tmp "tcpdump -i eth0 -nn -l -tttt 'tcp port 8080' > /tmp/c1.txt 2>&1"
```

capture output:

```text
2026-10-04 05:08:14.969642 IP 172.18.0.5.39374 > 172.18.0.4.8080: Flags [S], seq 2138025729, win 64240, length 0
2026-10-04 05:08:14.969652 IP 172.18.0.4.8080 > 172.18.0.5.39374: Flags [S.], seq 1113893836, ack 2138025730, length 0
2026-10-04 05:08:14.969666 IP 172.18.0.5.39374 > 172.18.0.4.8080: Flags [.], ack 1, win 502, length 0
2026-10-04 05:08:14.969707 IP 172.18.0.5.39374 > 172.18.0.4.8080: Flags [P.], seq 1:184, ack 1, length 183: HTTP: GET /api/plants HTTP/1.0
2026-10-04 05:08:14.974506 IP 172.18.0.4.8080 > 172.18.0.5.39374: Flags [P.], seq 1:416, ack 184, length 415: HTTP: HTTP/1.1 302
2026-10-04 05:08:14.974604 IP 172.18.0.5.39374 > 172.18.0.4.8080: Flags [F.], seq 184, ack 416, length 0
```

| 항목 | 값 |
|---|---|
| source | 172.18.0.5 (leafy-frontend) |
| destination | 172.18.0.4 (leafy-backend) |
| src port | 39374 (ephemeral) |
| dst port | 8080 |
| protocol | TCP (payload HTTP) |
| interface | `eth0` (backend netns, leafy-net) |
| TCP lifecycle | SYN → SYN/ACK → ACK → PSH → FIN 전부 관측 |

**Result: PASS**

> 주의: Case 1의 컨테이너는 Target 이미지(`ai-ops-leafy-*`)가 아니라 현재 실제 이미지(`gicks/leafy-*`)다.
> 다만 **토폴로지(frontend container → backend container)는 Target과 동일**하므로 capture mechanism 검증으로는 유효하다.

---

## 7. Case 2 — backend -> Host PostgreSQL

**Result: NOT TESTED**

### 사유 (추측 아닌 실측 근거)

1. 현재 datasource는 `jdbc:postgresql://db:5432/leafy` → **container `leafy-db`를 가리킨다** (M1)
2. Windows host에 PostgreSQL이 **존재하지 않는다**:
   ```powershell
   Get-NetTCPConnection -LocalPort 5432 -State Listen   # 결과 없음
   Get-Service -Name 'postgresql*'                      # 결과 없음
   ```
3. 따라서 `backend -> Host PostgreSQL:5432` traffic은 **이 환경에서 발생 자체가 불가능**하다.

> 지시서 §9 원칙에 따라, 기존 `leafy-db` container traffic 관측을 Target Case 2 PASS로 처리하지 **않았다.**

### 7.1 대체 검증 — Host-bound Traffic Visibility Probe (핵심)

Target Case 2를 직접 검증할 수는 없지만, **그 성패를 가르는 메커니즘 질문**은 분리해서 검증할 수 있다:

> "backend의 network namespace를 공유하는 observer가, backend netns에서 **Windows host 쪽으로 나가는** TCP traffic을 관측할 수 있는가?"

방법: backend netns 안에서 host 쪽 실제 listening port(Grafana의 published port 3000, Windows host에 이미 열려 있음)로 TCP 연결을 발생시키고 관측.
**새로운 host port를 열지 않았고, firewall/host network 설정을 변경하지 않았다.**

```bash
# observer (backend netns 공유)
docker run -d --name poc-ns2 --network container:leafy-backend \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  poc-capture:tmp "tcpdump -i any -nn -l -tttt 'tcp port 3000' > /tmp/h.txt 2>&1"

# backend netns 안에서 host로 연결 (backend container 자체는 건드리지 않음)
docker run --rm --network container:leafy-backend poc-capture:tmp \
  "wget -q -O /dev/null -T 5 http://host.docker.internal:3000/login"   # -> HOST_CONNECT_OK
```

capture output:

```text
2026-10-04 05:08:35.473866 eth0  Out IP 172.18.0.4.43780 > 192.168.65.254.3000: Flags [S], seq 2217215501, win 64240, length 0
2026-10-04 05:08:35.475662 eth0  In  IP 192.168.65.254.3000 > 172.18.0.4.43780: Flags [S.], seq 3161057153, ack 2217215502, length 0
2026-10-04 05:08:35.475680 eth0  Out IP 172.18.0.4.43780 > 192.168.65.254.3000: Flags [.], ack 1, win 502, length 0
2026-10-04 05:08:35.475775 eth0  Out IP 172.18.0.4.43780 > 192.168.65.254.3000: Flags [P.], seq 1:107, ack 1, length 106
2026-10-04 05:08:35.482864 eth0  In  IP 192.168.65.254.3000 > 172.18.0.4.43780: Flags [.], seq 1:1421, ack 107, length 1420
```

**결과: host-bound traffic은 backend netns observer에서 완전히 관측된다** (양방향, 전체 TCP lifecycle).

→ Target Case 2가 실제로 구성되면 **동일 메커니즘으로 관측될 가능성이 매우 높다.**
   단 이것은 **메커니즘 검증이지 Target Case 2 PASS가 아니다.** Target Case 2는 여전히 NOT TESTED.

### 7.2 이 probe에서 나온 중요한 발견

| 발견 | 내용 | 영향 |
|---|---|---|
| **host의 dst_ip가 `192.168.65.254`** | Windows host의 LAN IP가 아니라 **Docker Desktop 내부 host-gateway 주소**로 보인다 | Target Case 2의 `dst_ip`는 `192.168.65.254`가 된다. 이 IP는 **service identity로 해석 불가** → #7에서 전용 매핑 규칙 필요 |
| DNS와 실제 경로 불일치 | `getent hosts host.docker.internal` → IPv6 `fdc4:f303:9324::254` 를 반환하지만, 실제 연결은 **IPv4 192.168.65.254** 로 성립 | IPv4 전용 가정이나 DNS 기반 식별은 위험. BPF filter는 port 기준이 안전 |
| 방향 식별 | `-i any` 사용 시 `Out`/`In` 방향 표기가 제공됨 | connection originator 판별에 활용 가능 |

---

## 8. Legacy PoC Comparison

| 구분 | Traffic | 결과 | 비고 |
|---|---|---|---|
| **LEGACY CASE 1** | frontend container → backend container | **PASS** | 2026-09-20 최초 검증 |
| **LEGACY CASE 2** | backend container → **db container** (`172.18.0.4 → 172.18.0.3:5432`) | **PASS (보존)** | Hikari keepalive + conntrack ESTABLISHED. [WINDOWS_TRAFFIC_CAPTURE_POC.md](WINDOWS_TRAFFIC_CAPTURE_POC.md) 참조 |
| **TARGET CASE 1** | frontend container → backend container | **PASS** | 2026-10-04 재검증 (본 문서 §6) |
| **TARGET CASE 2** | backend container → **Host PostgreSQL:5432** | **NOT TESTED** | 전제 미충족 (M1, M2) |
| (참고) Host-bound mechanism probe | backend netns → host:3000 | **관측 성공** | Target Case 2 대체 검증 아님, 메커니즘 근거 |

> Legacy 결과는 무효화하지 않는다. 단 **Legacy Case 2(db container)를 Target Case 2의 충족 근거로 사용하지 않는다.**

---

## 9. Additional Findings

### MinIO traffic
**NOT TESTED** — `leafy-minio` container가 존재하지 않고 compose에도 정의되어 있지 않다 (M5).
(호스트에 `minio/minio:latest` 이미지는 있으나 무관한 `api-server` 프로젝트 소속이며 Leafy와 연결되어 있지 않다.)

### multi-homed backend (재확인, 중요)
`leafy-backend`는 `eth0=172.18.0.4`(leafy-net), `eth1=172.21.0.12`(mgmt-net) 2개 interface를 가진다.

- 이전 PoC에서 `tcpdump -i any 'tcp port 8080'` 사용 시 **`prometheus(172.21.0.4) → backend:8080` management traffic이 Case 1에 섞여 들어왔다.**
- 이번에는 `-i eth0`으로 범위를 좁혀 회피했다.
- → **port 필터만으로 Case를 식별하면 안 된다.** interface + src/dst IP + network membership을 함께 사용해야 한다.

### Docker Desktop host routing
- container → Windows host 경로는 VM 내부 gateway `192.168.65.254`를 통한다.
- `--network host`는 Windows host가 아니라 **Docker Desktop WSL2 VM**의 netns를 의미한다 (legacy PoC에서 확인).
- Windows host(OS)에는 docker bridge adapter가 존재하지 않는다 (`Get-NetAdapter`에 `docker0`/`br-*` 없음).

### capability 제약
- `NET_ADMIN` + `NET_RAW` 만으로 Case 1 및 host-bound probe 모두 성공. **`--privileged` 불필요.**
- `-i any` 는 promiscuous mode 미지원 경고를 내지만 동작하며, 대신 interface 구분이 사라져 Case 식별에 불리하다.

### 환경 상태 (참고, 변경하지 않음)
- 실행 시점에 `leafy-frontend/backend/db`가 `Exited (128)` 상태였다 → 기존 compose 그대로 `docker compose up -d db backend frontend` 로 기동했다 (**compose 파일 수정 없음**).
- `nginx-exporter`(Exited 0), `postgres-exporter`(Exited 2)는 **의도적으로 건드리지 않았다.**

---

## 10. Requirement Evaluation

| Requirement | Result | Evidence |
|---|---|---|
| frontend -> backend visibility | **PASS** | `172.18.0.5:39374 > 172.18.0.4:8080`, TCP SYN~FIN, backend netns `eth0` (§6) |
| backend -> Host PostgreSQL visibility | **NOT TESTED** | Host PostgreSQL 미존재 + datasource가 container를 가리킴 (M1/M2). 메커니즘은 §7.1에서 간접 검증 |
| application source unchanged | **PASS** | `git diff` 비어 있음. source/compose/logging/monitoring/pipeline 무변경 |
| NET_ADMIN + NET_RAW sufficient | **PASS** | 두 capability만으로 Case 1 및 host-bound probe 성공 |
| privileged unnecessary | **PASS** | `--privileged` 미사용, 전 실험 성공 |
| Compose reproducibility | **PASS (조건부)** | legacy PoC에서 `network_mode: "container:leafy-backend"` compose 기동 검증 완료. 단 `network_mode: "service:backend"` semantic은 **미검증** (production compose 수정 필요하여 보류) |
| raw traffic visibility | **PASS** | src/dst IP·port, protocol, TCP flag, packet length, 방향(In/Out) 확보 |

---

## 11. Current Platform Candidate

**CURRENT PLATFORM CANDIDATE (Windows): Service Network Namespace Sharing**

```yaml
# 개념 예시 — production 구현 아님
observer:
  network_mode: "container:leafy-backend"   # #5에서 "service:backend" 로 전환 검토
  cap_add: ["NET_ADMIN", "NET_RAW"]         # privileged 불필요
  command: tcpdump -i eth0 ...              # interface 한정 필수
```

근거:
- backend netns **하나만 공유해도** inbound(frontend→backend)와 outbound(backend→host) 양방향이 모두 보인다.
- host 방향 traffic까지 동일 지점에서 관측되므로, DB가 container든 host든 **capture 지점을 바꿀 필요가 없다.** → Target 전환에 강하다.
- 최소 권한(NET_ADMIN + NET_RAW)으로 충분하다.

> Mac 미검증 상태이므로 **FINAL ARCHITECTURE 아님.** `CURRENT PLATFORM CANDIDATE`로만 유지한다.

---

## 12. Follow-up

### #7 — Canonical Network Event Schema 에서 반영할 사항

1. **host-resident service의 identity 매핑 규칙**: Target Case 2의 `dst_ip`는 `192.168.65.254`(Docker Desktop host gateway)가 된다. 이 IP를 `service=db, container=null, runtime=host`로 해석하는 전용 규칙이 필요하다. IP→container 조회로는 절대 해결되지 않는다.
2. **container=null 표현**: db처럼 container가 없는 service를 schema에서 어떻게 표현할지 정의 필요 (`container` 필드 nullable).
3. **multi-homed 구분 필드**: `interface` 또는 `network` 를 event에 포함해야 application traffic과 management traffic을 구분할 수 있다. port만으로는 불가능.
4. **IPv4/IPv6 혼재**: `host.docker.internal`이 IPv6를 반환하지만 실제 연결은 IPv4였다. `src_ip`/`dst_ip` 타입은 두 family를 모두 수용해야 한다.
5. **application `source_ip` ≠ network `src_ip`**: TRUSTED_PROXIES/XFF로 해석된 client identity와 packet endpoint는 다른 값이다. 별도 필드로 유지해야 한다. (현재 TRUSTED_PROXIES는 미구현 — M8)

### #5 — Zeek/Observer Compose Integration 에서 반영할 사항

1. `network_mode: "service:backend"` semantic 실제 검증 (이번엔 production compose 수정 금지로 보류).
2. **interface 한정 필수** — `-i any` 또는 port-only 필터는 management traffic 오염을 일으킨다.
3. compose `command:`를 문자열로 주면 공백 분해되어 `-i` 옵션이 유실되고 **엉뚱한 interface를 조용히 감시**한다(legacy PoC에서 실제 발생). 단일 원소 리스트로 줄 것.
4. observer가 타 컨테이너 netns를 공유하는 구성의 **보안 영향** 검토.
5. backend netns 공유 방식은 **backend 생명주기에 종속**된다 (backend 재시작 시 observer 처리 방안 필요).

### Mac / Windows — 다른 플랫폼 재검증 사항

1. `container:leafy-backend` netns 공유로 Case 1 관측 가능 여부 (최우선)
2. Mac에서 container → host 경로의 gateway 주소가 무엇인지 (Windows는 `192.168.65.254`)
3. `NET_ADMIN` + `NET_RAW` 만으로 충분한지
4. `--network host`가 Mac에서 무엇을 의미하는지

### 선행 조건 (팀 차원)

**Target Case 2는 Target Architecture가 실제 배포에 반영되기 전에는 검증 자체가 불가능하다.**
최소한 다음이 필요하다: Windows Host PostgreSQL 17 기동 + `SPRING_DATASOURCE_URL`을 host 주소로 전환 (M1, M2).

---

## 13. Final Status

**PLATFORM PARTIAL**

| 조건 | 결과 |
|---|---|
| Case 1 PASS | **PASS** |
| Target Case 2 PASS | **NOT TESTED** (전제 미충족) |
| Application source 변경 없음 | **PASS** |
| raw traffic visibility 확보 | **PASS** |

> 지시서 §13 원칙: Target Host PostgreSQL을 실제로 검증하지 못했으므로 PLATFORM PASS로 판정하지 않는다.
> Mac 결과도 없으므로 Issue #4 전체는 COMPLETE가 아니다.

---

## 14. Safety / Cleanup

### 생성·변경 내역

| 경로 | 상태 |
|---|---|
| `docs/network-observability/poc/WINDOWS_TARGET_TRAFFIC_CAPTURE_POC.md` | 신규 (본 문서) |
| `docs/network-observability/poc/WINDOWS_TRAFFIC_CAPTURE_POC.md` | **보존 — 수정/삭제하지 않음** |
| `docs/network-observability/poc/tmp/Dockerfile.capture` | 기존 임시 파일 재사용 (변경 없음) |
| `docs/network-observability/poc/tmp/docker-compose.poc.yml` | 기존 임시 파일 재사용 (변경 없음) |

`git diff` 비어 있음 — **tracked source/config 변경 0건.**

### 수행한 환경 조작 (전부 reversible, 설정 변경 아님)

1. Docker Desktop 애플리케이션 기동 (engine이 내려가 있었음) — 설정 변경 없음
2. `docker compose up -d db backend frontend` — 기존 compose 그대로, 파일 수정 없음
3. 임시 observer container (`poc-ns`, `poc-ns2`) 생성 → **삭제 완료** (`docker ps -a --filter name=poc-` 결과 없음)
4. 임시 이미지 `poc-capture:tmp` 잔존 → `docker rmi poc-capture:tmp` 로 제거 가능

**하지 않은 것**: host firewall / host network / Docker Desktop 설정 / PostgreSQL 설정 / Tailscale 설정 / production compose 변경. 새 host port를 열지 않았다.

### USER ACTION REQUIRED

1. **Target Case 2 검증을 위해**: Windows Host PostgreSQL 17 기동 및 `SPRING_DATASOURCE_URL`의 host 전환이 선행되어야 한다. → 이번 작업에서 수행하지 않음 (승인 필요).
2. **Target Architecture 반영 여부 확인 필요**: 문서상 구조가 전 branch에 미반영 상태다 (§3). 팀 차원에서 "문서가 선행 설계인지, 반영 누락인지" 확정이 필요하다.
3. **Mac PoC 실행** 필요 (`MAC_TARGET_TRAFFIC_CAPTURE_POC.md`).
