# Canonical Network Event Schema

> Issue #7 — **설계 문서. 구현 아님.**
> 이 문서는 Network Observer가 어떤 방식으로 capture하든(Zeek / tcpdump / eBPF), AIOps / Loki / Pipeline이 **동일한 형태로 소비할 수 있는 canonical event 형식**을 정의한다.
>
> - 작성일: 2026-10-04 / schema_version: **1.0**
> - 이 문서는 코드/설정을 변경하지 않는다. 구현은 #5 (Observer Integration)에서 수행한다.
> - 선행: [NETWORK_OBSERVABILITY_REQUIREMENTS.md](NETWORK_OBSERVABILITY_REQUIREMENTS.md) (#3), [poc/WINDOWS_TRAFFIC_CAPTURE_POC.md](poc/WINDOWS_TRAFFIC_CAPTURE_POC.md) (#4 legacy), [poc/WINDOWS_TARGET_TRAFFIC_CAPTURE_POC.md](poc/WINDOWS_TARGET_TRAFFIC_CAPTURE_POC.md) (#4 target)
> - Mac PoC (`MAC_TARGET_TRAFFIC_CAPTURE_POC.md`) 는 **존재하지 않는다.** 추측하지 않았다.

---

## 1. Purpose

현재 Leafy AIOps는 **Application Log (Loki)** 와 **Metrics (Prometheus)** 만 관측한다.
서비스 간 통신에서 실제로 무슨 일이 일어났는지(연결 성립/거부, 전송량, 지속시간)는 어느 쪽에도 남지 않는다.

이 문서의 목적은 그 공백을 메울 **Network Event의 canonical 형태를 확정**하는 것이다. 구체적으로:

1. Observer 구현(Zeek 등)이 바뀌어도 **소비자(Pipeline/Grafana)가 영향을 받지 않도록** 계약(contract)을 고정한다.
2. network packet에는 존재하지 않는 **service identity를 어떻게 부여할지** 규칙을 정한다.
3. Loki에 저장할 때 **label / JSON body 경계를 확정**하여 cardinality 폭발을 사전에 차단한다.

---

## 2. Design Principles

| # | 원칙 | 이유 |
|---|---|---|
| P1 | **Observed fact와 Enriched identity를 분리한다** | packet에서 직접 읽은 값(IP/port/flag)과, runtime 조회로 덧붙인 값(service/container)은 신뢰도와 실패 양상이 다르다 |
| P2 | **IP는 identity가 아니라 observed fact다** | Docker runtime IP는 재기동마다 바뀐다. identity key로 쓰면 schema가 환경에 종속된다 |
| P3 | **service는 필수, container는 nullable** | Host PostgreSQL처럼 container가 없는 service가 Target Architecture에 실재한다 |
| P4 | **container-only 환경을 가정하지 않는다** | Target의 db는 Windows Host 프로세스다. Docker inspect만으로 모든 endpoint를 해석할 수 없다 |
| P5 | **Zeek 전용 필드를 canonical required로 만들지 않는다** | observer 교체 가능성을 유지한다. Zeek 고유값은 `observer_meta` 확장으로 격리 |
| P6 | **알 수 없으면 `unknown`을 허용한다** | enrichment 실패가 event 유실로 이어지면 안 된다. raw fact는 항상 보존 |
| P7 | **Loki label은 low-cardinality만** | label 조합 하나가 stream 하나다. IP/port를 label로 넣으면 Loki가 붕괴한다 |
| P8 | **기존 Application Log의 identity 불일치를 복제하지 않는다** | 현재 `container="leafy-db"` 같은 혼용을 network event로 전파하지 않는다 (#6에서 별도 정규화) |

---

## 3. Architecture Context

### As-Is (현재 repository 실제 상태, 2026-10-04 `feature/network-poc` @ `ba2b2a0`)

```text
leafy-frontend (gicks/leafy-frontend)  --HTTP-->  backend:8080
leafy-backend  (gicks/leafy-backend)   --JDBC-->  db:5432   (leafy-db container, postgres:16)
```

- networks: `leafy-net` (172.18.0.0/16), `mgmt-net` (172.21.0.0/16) — compose에 subnet 미지정, Docker 런타임 할당
- `leafy-backend`는 **두 network에 모두 연결된 multi-homed** 컨테이너 (`eth0`=leafy-net, `eth1`=mgmt-net)
- Network Event 수집 구조는 **존재하지 않는다**
- MinIO, Host PostgreSQL, Tailscale, TRUSTED_PROXIES: **repository 전 branch에 없음** (#4에서 확인)

### Target Architecture (팀원 정의 — target contract로만 사용)

```text
Client -> Tailscale -> Windows Desktop
  -> Leafy Frontend (Nginx container, leafy-frontend)
  -> Leafy Backend  (Spring container, leafy-backend)
  -> PostgreSQL 17  (Windows Host, container 없음, :5432)

Frontend/Nginx -> MinIO container (leafy-minio) -> /files/*
```

| service | container | runtime |
|---|---|---|
| frontend | leafy-frontend | container |
| backend | leafy-backend | container |
| **db** | **null** | **host** |
| minio | leafy-minio | container |

> **Schema는 Target을 기준으로 설계한다.** As-Is(db가 container)도 동일 schema로 표현 가능하다 —
> db의 `dst_container`가 `leafy-db`인지 `null`인지만 달라지며, 이는 schema 변경 없이 enrichment 결과의 차이로 흡수된다.
> 이것이 P3/P4를 지킨 설계의 직접적인 이득이다.

### #4 PoC에서 확정된, schema에 반영해야 할 사실

| # | 사실 | schema 반영 |
|---|---|---|
| F1 | backend netns 공유 observer 하나로 inbound/outbound 모두 관측 가능 | observer 단위 event 생성 → `observer` 필드 필요 |
| F2 | backend multi-homed → `port 8080`만으로 `frontend→backend`와 `prometheus→backend` 구분 불가 | **`network` / `interface` 필드 필수** |
| F3 | Host destination이 Windows host IP가 아닌 **Docker Desktop gateway `192.168.65.254`** 로 관측됨 | `dst_ip`로 service를 추론 불가 → **명시적 host mapping 필요** |
| F4 | `host.docker.internal`이 IPv6(`fdc4:...::254`)를 반환하지만 실제 연결은 IPv4 | **IP 필드는 IPv4/IPv6 모두 수용** |
| F5 | `-i any` 캡처 시 In/Out 방향 정보 제공됨 | `direction` 선택 필드로 수용 |

---

## 4. Canonical Identity Model

Network Event의 endpoint는 **4개 층**으로 표현한다. 각 층은 서로 다른 질문에 답한다.

### Service — *"논리적으로 무엇인가"*

- canonical logical identity. **분석/집계/alert의 기준 키.**
- 배포 형태(container/host/VM)가 바뀌어도 **변하지 않는다.**
- 값 예: `frontend`, `backend`, `db`, `minio`
- **항상 존재해야 한다.** 해석 실패 시 `unknown` (null 아님 — §6 참조)

### Container — *"지금 어느 컨테이너인가"*

- runtime deployment identity. 운영/디버깅 추적용.
- **nullable.** container가 아닌 runtime(host 프로세스, 외부 client)에는 존재하지 않는다.
- 값 예: `leafy-backend`, `leafy-minio`, `null`
- ⚠️ **service 이름을 여기에 넣지 않는다.** (`backend` ≠ `leafy-backend`)

### Runtime — *"어디서 실행되는가"*

- endpoint의 실행 환경 분류. container 존재 여부를 **명시적으로** 알려준다.
- `container` | `host` | `external` | `unknown` (§7.4)

### Observed IP — *"패킷에 실제로 찍힌 주소"*

- **identity가 아니다.** 증거(evidence)다.
- 재기동마다 바뀔 수 있고, Docker Desktop에서는 gateway 주소로 치환될 수 있다 (F3).
- 디버깅·추적·사후 검증용으로 보존하되, **집계 키로 사용하지 않는다.**

> 관계: `service`(안정) → `container`(배포) → `ip`(휘발).
> 질의는 왼쪽을, 증거는 오른쪽을 사용한다.

---

## 5. Canonical Event Schema

`schema_version: "1.0"`

Source 범례: **packet**(캡처에서 직접) / **mapping**(runtime enrichment) / **observer**(observer 자체 정보) / **derived**(다른 필드에서 계산)

### 5.1 공통 (Common)

| Field | Type | Required | Nullable | Source | Description |
|---|---|---|---|---|---|
| `schema_version` | string | ✅ | ❌ | observer | 이 event가 따르는 schema 버전. `"1.0"` |
| `timestamp` | string (RFC3339, UTC, ms) | ✅ | ❌ | packet | connection **시작** 시각. `"2026-10-04T05:08:14.969Z"` |
| `event_type` | enum string | ✅ | ❌ | observer | event 종류. v1.0은 `connection` 만 |
| `observer` | string | ✅ | ❌ | observer | event를 생성한 observer의 논리 이름. 예: `network-observer` |

### 5.2 Source endpoint

| Field | Type | Required | Nullable | Source | Description |
|---|---|---|---|---|---|
| `src_service` | string | ✅ | ❌ | mapping | 출발지 logical service. 해석 실패 시 `"unknown"` |
| `src_container` | string | ✅ | ✅ | mapping | 출발지 container 이름. container runtime이 아니면 `null` |
| `src_runtime` | enum string | ✅ | ❌ | mapping | `container` \| `host` \| `external` \| `unknown` |
| `src_ip` | string (IPv4/IPv6) | ✅ | ❌ | packet | 관측된 출발지 주소 |
| `src_port` | integer (1–65535) | ✅ | ❌ | packet | 관측된 출발지 포트 |

### 5.3 Destination endpoint

| Field | Type | Required | Nullable | Source | Description |
|---|---|---|---|---|---|
| `dst_service` | string | ✅ | ❌ | mapping | 목적지 logical service. 해석 실패 시 `"unknown"` |
| `dst_container` | string | ✅ | ✅ | mapping | 목적지 container 이름. **Host PostgreSQL은 `null`** |
| `dst_runtime` | enum string | ✅ | ❌ | mapping | `container` \| `host` \| `external` \| `unknown` |
| `dst_ip` | string (IPv4/IPv6) | ✅ | ❌ | packet | 관측된 목적지 주소. **host service면 gateway 주소일 수 있음 (F3)** |
| `dst_port` | integer (1–65535) | ✅ | ❌ | packet | 관측된 목적지 포트 |

### 5.4 Network

| Field | Type | Required | Nullable | Source | Description |
|---|---|---|---|---|---|
| `protocol` | enum string | ✅ | ❌ | packet | **전송 계층** 프로토콜. `tcp` \| `udp` \| `icmp` \| `other` |
| `network` | string | ✅ | ❌ | mapping | 논리 network 이름. `leafy-net` \| `mgmt-net` \| `host-bound` \| `unknown` (§8) |
| `interface` | string | ✅ | ✅ | observer | 캡처 지점 interface. 예: `eth0`. 식별 불가 시 `null` |
| `app_protocol` | string | ❌ | ✅ | derived | 추정 응용 프로토콜. `http` \| `postgres` \| `s3` \| `null` (§6.5) |

### 5.5 Connection

| Field | Type | Required | Nullable | Source | Description |
|---|---|---|---|---|---|
| `connection_state` | enum string | ✅ | ❌ | packet | canonical 연결 상태 (§6.3) |
| `duration_ms` | integer (≥0) | ✅ | ✅ | derived | 연결 지속 시간(밀리초). 미완결 연결은 `null` |
| `bytes_sent` | integer (≥0) | ✅ | ✅ | packet | **src → dst** 바이트. 미측정 시 `null` |
| `bytes_received` | integer (≥0) | ✅ | ✅ | packet | **dst → src** 바이트. 미측정 시 `null` |

### 5.6 선택 / 확장 (Optional)

| Field | Type | Required | Nullable | Source | Description |
|---|---|---|---|---|---|
| `direction` | enum string | ❌ | ✅ | observer | observer 관측 지점 기준 `inbound` \| `outbound` (F5) |
| `connection_id` | string | ❌ | ✅ | observer | observer가 부여한 connection 식별자 (§6.6) |
| `request_id` | string | ❌ | ✅ | observer | HTTP-aware observer만 제공. **required 아님** (§11.3) |
| `observer_instance` | string | ❌ | ✅ | observer | observer 복수 배치 시 인스턴스 구분자 |
| `observer_meta` | object | ❌ | ✅ | observer | **observer 고유 필드 격리 공간** (Zeek `uid`, `conn_state` 원본 등) |

> **`observer_meta`가 P5의 핵심 장치다.** Zeek의 `uid`, `history`, 원본 `conn_state` 같은 값은 유용하지만
> canonical 필수 필드가 되면 observer를 교체할 수 없게 된다. 전부 이 객체 안에 둔다.
> 소비자(Pipeline)는 `observer_meta`에 의존하지 않아야 한다.

---

## 6. Field Semantics

### 6.1 `timestamp` — connection **시작** 시각

종료 시각이 아니라 시작 시각이다. 이유: Application Log의 요청 시각과 시간창(window) 정렬을 맞추려면
"언제 시작했는가"가 기준이어야 한다. 종료 시각은 `timestamp + duration_ms`로 유도 가능하다.

### 6.2 `src_service` / `dst_service` — 왜 nullable이 아닌가

`unknown`이라는 **명시적 값**을 쓰고 `null`은 허용하지 않는다.

- `null`은 "필드가 없다"와 "해석에 실패했다"를 구분하지 못한다.
- Loki label은 null을 표현할 수 없다 — label로 쓰려면 문자열이어야 한다.
- `unknown` 비율 자체가 **enrichment 품질 지표**가 된다 (`sum by (dst_service)` 로 바로 측정).

반면 `container`는 **"원래 존재하지 않음"** 이 정상 상태이므로 `null`이 올바르다. 두 필드의 null 정책이 다른 것은 의도된 것이다.

### 6.3 `connection_state` — canonical enum (observer 중립)

| 값 | 의미 |
|---|---|
| `established` | 연결 성립, 관측 시점에 유지 중 |
| `closed` | 정상 종료 (FIN 교환 완료) |
| `reset` | RST로 중단 |
| `rejected` | 연결 시도가 거부됨 (SYN → RST) |
| `timeout` | 응답 없이 만료 (SYN 후 무응답) |
| `attempted` | 시도 관측, 결과 미확정 |
| `unknown` | 판별 불가 |

> **Zeek의 `S0`/`SF`/`REJ`/`RSTO` 등을 그대로 쓰지 않는다.** observer가 자신의 상태값을 위 enum으로 변환할
> 책임을 지고, 원본은 `observer_meta.raw_conn_state`에 보존한다. tcpdump/eBPF observer도 동일 enum을 채운다.
> 이것이 "schema가 Zeek 전용이 되지 않게" 하는 두 번째 장치다.

### 6.4 `bytes_sent` / `bytes_received` — 방향 기준 고정

- `bytes_sent` = **src → dst** 방향 누적 payload 바이트
- `bytes_received` = **dst → src** 방향 누적 payload 바이트
- 기준점은 **event의 src/dst**이지 observer가 아니다. (observer 기준으로 하면 관측 위치에 따라 의미가 뒤집힌다)

total 하나로 합치지 않은 이유: **비대칭 탐지**가 주요 용도다. "평소보다 db에서 backend로 나가는 양이 급증"
같은 신호는 방향이 분리되어야만 보인다. total은 `bytes_sent + bytes_received`로 언제든 유도된다.

### 6.5 `protocol` vs `app_protocol`

- `protocol`은 **전송 계층만** (tcp/udp/icmp). 저cardinality이고 packet에서 확실히 읽힌다 → label로 사용.
- `app_protocol`은 **추정값**이다 (포트 번호 또는 payload 기반). 틀릴 수 있으므로 optional/nullable이고 label이 아니다.
- 두 개를 하나의 `protocol` 필드로 합치면 확실한 사실과 추정이 섞인다 → 분리한다.

### 6.6 `connection_id` — canonical이되 optional

연결 단위 추적에 유용하지만, 모든 observer가 안정적인 ID를 줄 수 있다고 가정할 수 없다.
따라서 canonical 필드로 **자리는 마련하되 required로 만들지 않는다.** Zeek `uid`를 여기에 매핑할 수 있다.
**절대 Loki label로 쓰지 않는다** (연결마다 고유 = cardinality 무한).

---

## 7. Runtime / Identity Mapping

> ⚠️ 이 절은 **매핑 전략 설계**다. 매핑 코드는 #5에서 구현한다.

enrichment는 **observed fact(IP/port)** → **identity(service/container/runtime)** 변환이다.
단일 수단으로는 해결되지 않으므로 **3단계 fallback**으로 설계한다.

### 7.1 Container endpoint — Docker runtime metadata

- 수단: Docker API로 network별 container IP를 조회해 `ip → (service, container)` 테이블 구성
- `service`는 **compose service 이름**을, `container`는 **container 이름**을 사용 (혼동 금지)
- 컨테이너 재생성 시 IP가 바뀌므로 테이블은 **주기적 갱신 또는 Docker event 구독**이 필요
- 결과: `runtime = container`, `container = <이름>`

### 7.2 Host endpoint — **명시적 매핑 필수**

Docker inspect로 **절대 해결되지 않는다** (P4). #4에서 Host destination이 `192.168.65.254`(Docker Desktop
gateway)로 관측됨이 확인되었다 (F3). 이 IP를 조회해도 어떤 container도 나오지 않는다.

→ **설정 기반 명시적 매핑 테이블**이 필요하다. 개념 형태:

```text
host_services:
  - match: { ip: "<host-gateway-addr>", port: 5432 }
    service:   db
    container: null
    runtime:   host
    network:   host-bound
```

- 매칭 키는 `(ip, port)` 조합 — gateway IP 하나에 여러 host service가 달릴 수 있으므로 **port까지 봐야 한다**
- host-gateway 주소는 **플랫폼/환경마다 다르다** → 하드코딩하지 않고 **설정값으로 주입** (#5)
- 이 문서는 특정 IP를 baseline으로 고정하지 않는다

### 7.3 Unknown endpoint — 허용

세 경로 모두 실패하면:

```text
service = "unknown", container = null, runtime = "unknown"
```

**event를 버리지 않는다** (P6). raw fact(IP/port/protocol)는 그대로 보존되므로 사후 분석이 가능하고,
`unknown` 비율로 매핑 테이블의 누락을 감지할 수 있다.

### 7.4 Runtime enum — 4개로 확정한 이유

| 값 | 필요성 |
|---|---|
| `container` | 현재 필수 — frontend/backend/minio |
| `host` | 현재 필수 — Target의 PostgreSQL 17 |
| `external` | **Target Architecture에 실재** — Client가 Tailscale을 거쳐 들어온다. frontend의 peer는 container도 host도 아니다 |
| `unknown` | 매핑 실패를 명시적으로 표현 (P6) |

**추가하지 않은 값들**: `vm`, `k8s_pod`, `serverless` 등은 현재 아키텍처에 존재하지 않는다.
enum을 미리 늘리면 소비자가 처리해야 할 분기만 늘고 검증할 수단이 없다. 필요해지는 시점에
non-breaking하게 추가 가능하다 (§14).

---

## 8. Network / Interface Semantics

### 8.1 해결해야 할 문제 (F2)

`leafy-backend`는 multi-homed다 (`eth0`=leafy-net, `eth1`=mgmt-net). #4에서 실제로 발생한 오염:

```text
frontend(172.18.0.5)   -> backend:8080    # Case 1, application traffic
prometheus(172.21.0.4) -> backend:8080    # management traffic — 포트가 같다!
```

**`dst_port=8080` 필터만으로는 두 트래픽을 구분할 수 없다.** 이는 가설이 아니라 #4에서 실측된 오염이다.

### 8.2 설계 결정

두 개의 분리된 필드를 둔다.

| 필드 | 성격 | 용도 |
|---|---|---|
| `network` | **논리적**, 저cardinality, mapping으로 결정 | **질의/필터 기준** → Loki label |
| `interface` | **물리적**, 관측 지점 종속 | 디버깅/증거 → JSON body |

`interface`를 label로 쓰지 않는 이유: `eth0`/`eth1`은 **관측 위치에 따라 의미가 달라진다.**
backend에서의 `eth0`과 frontend에서의 `eth0`은 다른 network다. 논리적 질의 기준이 될 수 없다.

### 8.3 `network` 값 체계

| 값 | 의미 |
|---|---|
| `leafy-net` | application traffic (PoC 1차 관측 대상) |
| `mgmt-net` | management / observability traffic |
| `host-bound` | container → Windows host service (Target의 db) |
| `unknown` | 판별 불가 |

- compose가 붙이는 prefix(`graduation-project_leafy-net`)는 **제거하고 논리 이름만** 쓴다.
  project 이름이 바뀌어도 schema가 흔들리지 않게 하기 위함이다.
- `host-bound`를 별도 값으로 둔 이유: host 방향 트래픽은 어느 docker network에도 속하지 않지만,
  **application traffic으로 분류되어야 한다.** `unknown`으로 밀어넣으면 Target Case 2가 질의에서 누락된다.

### 8.4 Case 판별 기준 (권고)

```text
Case 1 (frontend -> backend): network="leafy-net" AND src_service="frontend" AND dst_service="backend"
Case 2 (backend -> db):       network="host-bound" AND src_service="backend" AND dst_service="db"
```

→ **port가 아니라 service + network 조합으로 판별한다.**

---

## 9. Timestamp / Duration / Byte Units

### 9.1 Timestamp — **UTC, RFC3339, 밀리초 정밀도**

```text
"2026-10-04T05:08:14.969Z"
```

| 항목 | 결정 | 이유 |
|---|---|---|
| timezone | **UTC** | Loki는 내부적으로 UTC epoch ns, Prometheus도 UTC epoch로 저장한다. Network Event만 KST로 쓰면 **상관분석 때마다 변환이 끼어들고 DST/오프셋 실수의 여지가 생긴다** |
| 형식 | RFC3339 (ISO-8601 호환) | 사람이 읽을 수 있고 파서가 보편적 |
| 정밀도 | **밀리초** | #4 실측 캡처에서 동일 연결의 패킷 간격이 마이크로초 단위였으나(`.969642` → `.969652`), **connection 단위 event**에는 ms로 충분하다. 과도한 정밀도는 저장 비용만 늘린다 |

> **Application Logging이 KST를 쓴다고 해서 Network Event를 KST로 맞추지 않는다.**
> 표시(display) 시점의 timezone 변환은 Grafana가 담당한다. 저장은 UTC로 통일한다.
> 이 차이는 §13에 호환성 항목으로 기록한다.

### 9.2 Duration — **`duration_ms`, 정수 밀리초**

| 후보 | 채택 | 이유 |
|---|---|---|
| seconds (float) | ❌ | Zeek 네이티브 형식이고 Prometheus 관례지만, JSON float는 정밀도 표현이 들쭉날쭉하고 observer마다 자릿수가 달라진다 |
| **milliseconds (integer)** | ✅ | **Application Log의 요청 처리시간이 통상 ms** → 상관분석 시 단위가 일치한다. 정수라 비교/집계가 명확 |

- 단위를 필드명에 박는다(`duration_ms`). 단위 없는 `duration`은 사고의 원인이 된다.
- 트레이드오프: Prometheus는 초 단위가 관례이므로, metric으로 내보낼 일이 생기면 변환이 필요하다. 수용한다.
- 미완결 연결(`established`, `attempted`)은 `null`.

### 9.3 Bytes — **`bytes_sent` / `bytes_received` 분리, 단위는 바이트**

- §6.4 참조. 방향 기준은 event의 src→dst.
- payload 바이트인지 헤더 포함인지는 observer마다 다를 수 있으므로, **#5에서 observer가 어느 쪽을 보고하는지 명시**하도록 한다 (Deferred).

---

## 10. Loki Storage Model

### 10.1 현재 Loki stream 실태 (분석 결과)

repository에서 확인한 **기존 stream 두 종류**:

| 출처 | 설정 위치 | label set |
|---|---|---|
| Application Log | `leafy/fluentd/fluent.conf` | `container`, `source` |
| AIOps LLM 결과 | `aiops/pipeline/main.py` `push_to_loki()` | `job="aiops-llm"`, `container`, `alert`, `threat_level`, `action_risk` |

Pipeline의 조회 방식 (`aiops/pipeline/collector/logs.py:30`):

```python
label_filter = f'{{container="{container}"}}'
```

→ **`container` label 하나로만 조회한다.**

**중요한 함의**: Network Event에 `container` label을 붙이면, 기존 `{container="backend"}` 질의에
network event가 **섞여 들어간다.** Pipeline은 이를 application log로 간주해 LLM 프롬프트에 넣게 된다.
→ Network Event는 **`container` label을 사용하지 않는다.**

### 10.2 Labels (확정)

| Label | 왜 label인가 | 예상 cardinality | Query 용도 |
|---|---|---|---|
| `log_type` | network stream을 기존 stream과 **완전히 분리**하는 최상위 discriminator. 기존 두 stream 모두 이 label이 없으므로 **기존 질의를 전혀 오염시키지 않는다** | **1** (`network`) | `{log_type="network"}` — 전체 network event 조회 |
| `event_type` | event 종류별 분리. v1.0은 1종이나 향후 `http_request`/`dns_query` 추가 시 소비자가 섞이지 않게 함 | 1 → 3 (향후) | `{log_type="network", event_type="connection"}` |
| `src_service` | **핵심 질의 축.** "frontend에서 나간 트래픽" | ~6 (frontend/backend/db/minio/prometheus/unknown) | 서비스별 출발 트래픽 |
| `dst_service` | **핵심 질의 축.** "db로 들어온 트래픽" | ~6 | 서비스별 도착 트래픽 |
| `protocol` | 전송 프로토콜 필터. packet에서 확실히 읽히는 값 | 4 (tcp/udp/icmp/other) | `protocol="tcp"` |
| `network` | **F2의 multi-homed 오염을 label 단에서 차단.** application vs management 분리 | 4 | `network="leafy-net"` |

**이론적 최대 조합**: 1 × 3 × 6 × 6 × 4 × 4 = **1,728 streams**
**현실적 활성 stream**: service 쌍은 실제 통신하는 조합만 존재하므로(frontend→backend, backend→db,
frontend→minio, prometheus→backend 등) **수십 개 수준.** Loki 권장 범위 내에서 안전하다.

### 10.3 Label에서 **제외**한 값과 이유

| 제외 값 | 이유 |
|---|---|
| `src_ip` / `dst_ip` | **unbounded.** 외부 client까지 포함되면 무한. 또한 재기동마다 변해 과거 stream이 좀비로 남는다 |
| `src_port` | ephemeral port — 연결마다 고유. **최악의 cardinality** |
| `dst_port` | src_port보다는 낮지만, `dst_service`가 같은 질의를 더 안정적으로 수행한다. 중복 축 |
| `timestamp` | label이 될 수 없다 (Loki의 시간축과 중복) |
| `connection_id` / `uid` | 연결마다 고유 — 무한 cardinality |
| `container id` / `container name` | §10.1 — **기존 Pipeline 질의와 충돌.** 또한 재생성 시 변경 |
| `src_runtime` / `dst_runtime` | cardinality는 낮으나(4), **`service`에 거의 함수 종속**이다 (db는 항상 host). 질의 가치 대비 stream 수만 ×16 증가 → body로 |
| `interface` | §8.2 — 관측 지점 종속이라 논리적 질의 축이 아니다 |
| `observer` | 현재 1개. 늘어나도 질의 축이 아니라 운영 정보 → body로 |

### 10.4 JSON Body

label에 들어가지 않은 **모든 canonical 필드**는 log line의 JSON body에 담는다.
(label 값도 body에 중복 포함한다 — Loki label은 질의용이고, body는 **event 자체로 완결**되어야 한다.
export·재처리 시 label이 떨어져 나가도 정보가 유실되지 않는다.)

body 주요 필드: `schema_version`, `timestamp`, `src_ip`, `src_port`, `dst_ip`, `dst_port`,
`src_container`, `dst_container`, `src_runtime`, `dst_runtime`, `interface`, `app_protocol`,
`connection_state`, `duration_ms`, `bytes_sent`, `bytes_received`, `direction`, `connection_id`,
`observer`, `observer_instance`, `observer_meta`

> line format은 **JSON**으로 한다. 기존 application log는 fluentd `line_format key_value`를 쓰지만,
> network event는 중첩 구조(`observer_meta`)가 있고 LogQL의 `| json` 파서로 필드 추출이 가능해야 한다.

### 10.5 질의 예시

```logql
# Case 1: frontend -> backend (management traffic 오염 없음)
{log_type="network", src_service="frontend", dst_service="backend", network="leafy-net"}

# Case 2: backend -> Host PostgreSQL
{log_type="network", src_service="backend", dst_service="db", network="host-bound"}

# 연결 실패만
{log_type="network"} | json | connection_state=~"rejected|timeout|reset"

# enrichment 품질 점검
{log_type="network", dst_service="unknown"}
```

---

## 11. Correlation with Application Logs / Metrics

### 11.1 상관 키

| 키 | 적용 방법 | 신뢰도 |
|---|---|---|
| **timestamp / window** | UTC 기준 ±N분 창. Pipeline이 이미 사용하는 방식 (`fetch_around`) | 높음 — **1차 상관 키** |
| **service** | network event의 `src_service`/`dst_service` ↔ application log의 서비스 identity | 높음 (단 §13의 불일치 해소 전제) |
| **container** | network event의 `*_container` ↔ application log의 `container` label | 중간 — host service는 `null`이라 불가 |
| **request_id** | HTTP-aware observer가 제공 시에만 | 낮음/부분적 — §11.3 |

**권고**: `timestamp window + service` 조합을 기본 상관 전략으로 삼는다.
container 기반 상관은 host runtime endpoint(db)에서 작동하지 않으므로 보조 수단으로만 쓴다.

### 11.2 Application `source_ip` ≠ Network `src_ip` (중요)

| | Application Log `source_ip` | Network Event `src_ip` |
|---|---|---|
| 의미 | Trusted Proxy / X-Forwarded-For 처리 후 해석된 **client identity** | packet에서 관측한 **실제 network endpoint** |
| 예 (Target) | Tailscale을 거친 원래 client 주소 | `leafy-frontend`의 컨테이너 IP |
| 성격 | 해석된 값 (신뢰 체인에 의존) | 관측된 사실 |

**두 값은 정상적으로 다르다.** nginx가 proxy하면 backend가 보는 packet의 src는 항상 frontend의 IP지만,
application log의 `source_ip`는 XFF가 가리키는 원래 client다.

→ **같은 필드로 합치거나, 불일치를 이상 징후로 간주하면 안 된다.**
→ Network Event는 **raw observed fact를 표현하는 것이 우선**이다. XFF 해석은 application layer의 책임이다.
→ 두 값을 연결하려면 별도의 correlation 로직이 필요하며, 이는 #7 범위가 아니다 (Deferred).

### 11.3 `request_id` — required로 만들지 않은 이유

L4 packet에는 HTTP request_id가 **존재하지 않는다.** connection 하나에 여러 HTTP 요청이 흐를 수도 있다
(keep-alive). 따라서:

- `request_id`는 **optional / nullable**
- L4 observer는 항상 `null`
- 향후 HTTP-aware observer(예: Zeek `http.log`)가 생기면 `event_type="http_request"` 라는 **별도 event type**으로
  제공하는 것이 자연스럽다 (connection event에 억지로 끼워넣지 않는다)

### 11.4 Metrics 상관

Prometheus와는 **timestamp(UTC) + service label**로 맞춘다. Network Event를 metric으로 변환하는 것
(예: 연결 실패율 recording rule)은 #7 범위가 아니다 (Deferred).

---

## 12. Canonical Event Examples

> ⚠️ 아래 IP는 **문서용 placeholder**다. 실제 runtime 값을 baseline으로 고정하지 않는다 (P2).
> `<HOST_GATEWAY_ADDR>`는 환경마다 다른 Docker Desktop host gateway 주소를 의미한다.

### 12.1 frontend → backend (Case 1)

```json
{
  "schema_version": "1.0",
  "timestamp": "2026-10-04T05:08:14.969Z",
  "event_type": "connection",
  "observer": "network-observer",

  "src_service": "frontend",
  "src_container": "leafy-frontend",
  "src_runtime": "container",
  "src_ip": "10.203.0.10",
  "src_port": 39374,

  "dst_service": "backend",
  "dst_container": "leafy-backend",
  "dst_runtime": "container",
  "dst_ip": "10.203.0.20",
  "dst_port": 8080,

  "protocol": "tcp",
  "network": "leafy-net",
  "interface": "eth0",
  "app_protocol": "http",

  "connection_state": "closed",
  "duration_ms": 5,
  "bytes_sent": 183,
  "bytes_received": 415,

  "direction": "inbound",
  "connection_id": "C1a2b3c4",
  "request_id": null,
  "observer_meta": { "raw_conn_state": "SF" }
}
```

### 12.2 backend → Host PostgreSQL (Case 2) — **container = null**

```json
{
  "schema_version": "1.0",
  "timestamp": "2026-10-04T05:08:35.473Z",
  "event_type": "connection",
  "observer": "network-observer",

  "src_service": "backend",
  "src_container": "leafy-backend",
  "src_runtime": "container",
  "src_ip": "10.203.0.20",
  "src_port": 43780,

  "dst_service": "db",
  "dst_container": null,
  "dst_runtime": "host",
  "dst_ip": "<HOST_GATEWAY_ADDR>",
  "dst_port": 5432,

  "protocol": "tcp",
  "network": "host-bound",
  "interface": "eth0",
  "app_protocol": "postgres",

  "connection_state": "established",
  "duration_ms": null,
  "bytes_sent": 106,
  "bytes_received": 2841,

  "direction": "outbound",
  "connection_id": "C5d6e7f8",
  "request_id": null,
  "observer_meta": { "raw_conn_state": "S1" }
}
```

**이 예시가 보여주는 것:**
- `dst_container: null` + `dst_runtime: "host"` → container 없는 service를 정상 표현
- `dst_ip`가 gateway 주소지만 `dst_service: "db"`로 올바르게 해석됨 → **§7.2의 명시적 host mapping 결과** (F3)
- `duration_ms: null` → connection pool이 유지 중인 미완결 연결

### 12.3 frontend → MinIO

```json
{
  "schema_version": "1.0",
  "timestamp": "2026-10-04T05:09:02.114Z",
  "event_type": "connection",
  "observer": "network-observer",

  "src_service": "frontend",
  "src_container": "leafy-frontend",
  "src_runtime": "container",
  "src_ip": "10.203.0.10",
  "src_port": 51022,

  "dst_service": "minio",
  "dst_container": "leafy-minio",
  "dst_runtime": "container",
  "dst_ip": "10.203.0.30",
  "dst_port": 9000,

  "protocol": "tcp",
  "network": "leafy-net",
  "interface": "eth0",
  "app_protocol": "s3",

  "connection_state": "closed",
  "duration_ms": 42,
  "bytes_sent": 512,
  "bytes_received": 184320,

  "direction": "outbound",
  "connection_id": "C9a0b1c2",
  "request_id": null,
  "observer_meta": { "raw_conn_state": "SF" }
}
```

> MinIO는 현재 repository에 **존재하지 않는다** (§3 As-Is). 이 예시는 Target contract 기준의 설계 예시다.

---

## 13. Compatibility with Existing Application Logs

### 13.1 현재 불일치 (확인된 사실, 이번에 수정하지 않음)

`leafy/fluentd/fluent.conf`는 Docker log tag를 `container` label로 넣는다:

| 컨테이너 | Loki label | 값 | 문제 |
|---|---|---|---|
| leafy-frontend | `container` | `frontend` | **값이 logical service 이름** |
| leafy-backend | `container` | `backend` | **값이 logical service 이름** |
| leafy-db | `container` | `leafy-db` | **값이 container 이름 — 위 둘과 규칙이 다름** |

즉 **label 키 이름(`container`)과 값의 의미(service)가 불일치**하고, `db`만 예외적으로 container 이름을 쓴다.

### 13.2 Network Event의 대응

| 방침 | 내용 |
|---|---|
| **복제하지 않는다** | Network Event는 `service`와 `container`를 **별개 필드로 명확히 분리**한다 (§4). 기존 혼용을 전파하지 않는다 |
| **`container` label을 쓰지 않는다** | §10.1 — 기존 Pipeline의 `{container="..."}` 질의에 network event가 섞이는 것을 방지 |
| **`log_type="network"`로 격리** | 기존 두 stream에는 이 label이 없으므로 **기존 질의는 전혀 영향받지 않는다** |

### 13.3 남는 호환성 과제 (→ #6)

1. **service identity 정규화**: application log의 `leafy-db` → `db`로 정규화되어야 network event의
   `src_service="db"`와 상관분석이 가능하다. **#6 Application Log identity normalization의 책임이다.**
2. **label 키 재명명**: `container` label의 값이 실제로는 service라면 `service` label 추가가 바람직하나,
   `aiops/pipeline/collector/logs.py`와 `main.py`의 질의/푸시가 모두 `container`에 의존하므로 **동시 변경이 필요하다.**
   → #6에서 다룬다. **이번 #7에서는 수정하지 않았다.**
3. **timezone 차이**: Application Log는 KST, Network Event는 UTC(§9.1). Grafana 표시 계층에서 흡수되지만,
   Pipeline이 두 소스를 직접 비교할 때는 **변환이 필요하다.** #6/#5에서 확인 필요.
4. **line format 차이**: application log는 `key_value`, network event는 JSON. LogQL 파서가 다르다(`| logfmt` vs `| json`).

---

## 14. Schema Versioning

### 14.1 전략

- 모든 event에 `schema_version` 필드를 포함한다 (required).
- 형식: `"MAJOR.MINOR"` 문자열. 현재 **`"1.0"`**
- **schema registry 같은 별도 시스템을 만들지 않는다.** 이 문서가 1차 기준이며, 버전 변경 시 이 문서를 갱신한다.

### 14.2 변경 기준

| 종류 | 정의 | 버전 영향 | 예 |
|---|---|---|---|
| **Non-breaking** | 기존 소비자가 수정 없이 계속 동작 | MINOR 증가 (`1.0` → `1.1`) | optional 필드 추가 / enum 값 추가(소비자가 unknown으로 처리 가능한 경우) / 설명 보완 |
| **Breaking** | 기존 소비자가 깨짐 | MAJOR 증가 (`1.0` → `2.0`) | 필드 **삭제** / 필드 **이름 변경** / **타입 변경** / 단위 변경(ms→s) / required↔optional 전환 / nullable 정책 변경 / **Loki label set 변경** |

> **Loki label set 변경을 breaking으로 분류한 이유**: label이 바뀌면 기존 stream과 신규 stream이 분리되어
> 과거 데이터 질의가 깨진다. 필드 추가보다 영향이 크다.

### 14.3 운영 원칙

- 소비자(Pipeline)는 **모르는 필드를 무시**하도록 구현해야 한다 (forward compatibility).
- 소비자는 **모르는 enum 값을 `unknown`처럼 처리**해야 한다.
- MAJOR 변경 시에는 전환 기간 동안 두 버전이 공존할 수 있으므로, `schema_version`으로 분기 가능해야 한다.

---

## 15. Decisions

| # | 항목 | 결정 | 근거 |
|---|---|---|---|
| D1 | identity 모델 | `service` / `container` / `runtime` **3층 분리** | service는 안정, container는 배포 종속, runtime은 분류 (§4) |
| D2 | `service` null 정책 | **not nullable**, 실패 시 `"unknown"` | label 사용 가능 + enrichment 품질 측정 가능 (§6.2) |
| D3 | `container` null 정책 | **nullable** | Host PostgreSQL은 container가 없음 (P3) |
| D4 | runtime enum | `container` / `host` / `external` / `unknown` | 4개면 Target 전부 표현. external은 Tailscale client용 (§7.4) |
| D5 | IP 취급 | observed fact. **identity/집계 키로 사용 금지**, IPv4/IPv6 모두 수용 | P2, F4 |
| D6 | host endpoint 매핑 | **명시적 `(ip, port)` 설정 테이블 필수** | Docker inspect로 해결 불가, gateway 주소로 관측됨 (F3, §7.2) |
| D7 | multi-homed 대응 | `network`(논리, label) + `interface`(물리, body) **분리** | port 필터만으로는 구분 불가 — #4 실측 (F2, §8) |
| D8 | timestamp | **UTC / RFC3339 / ms**, connection **시작** 시각 | Loki·Prometheus 모두 UTC 저장. KST는 표시 계층 (§9.1) |
| D9 | duration | **`duration_ms` 정수 밀리초**, 미완결은 `null` | application log의 처리시간 단위와 일치 (§9.2) |
| D10 | bytes | **`bytes_sent` / `bytes_received` 분리**, 기준은 src→dst | 비대칭 탐지. total은 유도 가능 (§6.4) |
| D11 | connection_state | **canonical enum 7종**, observer 원본은 `observer_meta` | Zeek 종속 차단 (P5, §6.3) |
| D12 | Loki labels | `log_type`, `event_type`, `src_service`, `dst_service`, `protocol`, `network` (**6개**) | 저cardinality + 핵심 질의 축 (§10.2) |
| D13 | `container` label | **사용하지 않음** | 기존 Pipeline `{container="..."}` 질의 오염 방지 (§10.1) |
| D14 | runtime label화 | **하지 않음** (body로) | service에 거의 함수 종속, stream만 ×16 증가 (§10.3) |
| D15 | line format | **JSON** | 중첩 구조 + LogQL `\| json` 파서 (§10.4) |
| D16 | observer 고유 필드 | **`observer_meta` 객체로 격리**, 소비자는 의존 금지 | observer 교체 가능성 유지 (P5) |
| D17 | `request_id` | **optional / nullable**, L4는 항상 null | packet에 존재하지 않음 (§11.3) |
| D18 | app `source_ip` vs net `src_ip` | **의미가 다른 별개 값**, 불일치는 정상 | XFF 해석 vs packet 관측 (§11.2) |
| D19 | versioning | `schema_version` 필드 + MAJOR/MINOR 규칙. registry 미도입 | 과도한 시스템 방지 (§14) |
| D20 | 기존 log 수정 | **하지 않음** | identity 정규화는 #6 책임 (§13.3) |

---

## 16. Deferred Items

이번 #7에서 **확정하지 않은** 항목과 담당 단계.

| 항목 | 담당 |
|---|---|
| Zeek docker-compose 통합, capture interface 실제 설정 | #5 |
| IP → service mapping **구현 코드** 및 테이블 갱신 주기(Docker event 구독 여부) | #5 |
| host-gateway 주소의 **환경별 주입 방식** (설정 파일 / 환경변수) | #5 |
| observer의 bytes 집계 기준(payload only vs 헤더 포함) 명시 | #5 |
| Fluentd 경유 여부 — Observer가 Loki에 직접 push할지, Fluentd를 거칠지 | #5 |
| Loki ingestion 구현 및 `limits_config` 조정 필요 여부 | #5 |
| Application Log identity normalization (`leafy-db` → `db`), `service` label 도입 | #6 |
| Pipeline의 network event 조회 구현 및 LLM 프롬프트 반영 | 후속 |
| Network Event → Prometheus recording rule 변환 | 후속 |
| Application `source_ip` ↔ Network `src_ip` 상관 로직 | 후속 |
| retention 기간 | 후속 |
| Mac capture 최종 결과 (`MAC_TARGET_TRAFFIC_CAPTURE_POC.md` 미존재) | #4 잔여 |
| `event_type` 확장 (`http_request`, `dns_query`) | 필요 시 MINOR |

---

## 17. Acceptance Criteria

- [x] Canonical Network Event 필드 정의 — §5 (공통 4 / src 5 / dst 5 / network 4 / connection 4 / optional 5)
- [x] 각 필드 타입 정의 — §5 전체 표
- [x] Required / Nullable 정의 — §5 전체 표, 정책 근거 §6.2
- [x] service / container / runtime 의미 분리 — §4, D1
- [x] Host service 표현 가능 — §7.2, 예시 §12.2 (`dst_container: null`, `dst_runtime: "host"`)
- [x] IP를 identity로 사용하지 않음 — P2, D5, §4 Observed IP
- [x] multi-homed network/interface 처리 기준 정의 — §8, D7
- [x] IPv4 / IPv6 고려 — §5.2/5.3 타입, F4, D5
- [x] Timestamp / duration / bytes 단위 정의 — §9, D8/D9/D10
- [x] Loki label / JSON body 분리 — §10.2 / §10.4
- [x] High-cardinality label 방지 — §10.3 제외 목록 + §10.2 cardinality 산정
- [x] Existing Application Log compatibility 고려 — §13
- [x] Application source_ip와 Network src_ip 의미 분리 — §11.2, D18
- [x] frontend -> backend example — §12.1
- [x] backend -> Host PostgreSQL example — §12.2
- [x] frontend -> MinIO example — §12.3
- [x] Schema versioning 정의 — §14
- [x] Zeek implementation과 schema 설계 책임 분리 — P5, D11, D16, §16

---

## 18. Final Review (문서 자체 검증)

작성 후 repository를 재확인하여 다음을 점검했다.

| 점검 항목 | 결과 |
|---|---|
| 현재 architecture와 모순되지 않는가 | **OK.** As-Is(db=container)도 `dst_container="leafy-db"`, `dst_runtime="container"`, `network="leafy-net"`로 표현 가능. Target 전환 시 schema 변경 불필요 |
| container-only 환경을 가정하는가 | **아니오.** `container` nullable + `runtime` enum + 명시적 host mapping (§7.2) |
| Host PostgreSQL을 표현할 수 있는가 | **가능.** §12.2에서 실제 JSON으로 제시 |
| 특정 Docker subnet/IP에 종속되는가 | **아니오.** 본문과 예시 모두 placeholder 사용. host-gateway 주소는 설정 주입 (§7.2). `172.18.x`/`192.168.65.254`는 §3의 **As-Is 관측 기록으로만** 등장 |
| Zeek-specific schema가 되었는가 | **아니오.** canonical enum(§6.3) + `observer_meta` 격리(D16). Zeek `uid`/`conn_state`는 전부 확장 영역 |
| Loki high-cardinality 문제가 있는가 | **없음.** label 6개, 이론 최대 1,728 / 실제 수십 stream. IP·port·uid·container 전부 제외 (§10.3) |
| 기존 Pipeline 질의를 깨뜨리는가 | **아니오.** `container` label 미사용 + `log_type="network"`로 격리. 기존 두 stream에는 `log_type`이 없으므로 `{container="..."}` 결과 불변 |
