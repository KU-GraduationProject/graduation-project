# Network Observability Requirements (#3)

> 이 문서는 **구현 문서가 아니라 요구사항 정의 문서**이다.
> Network Observability를 실제로 구현하기 전에 목적 / 범위 / 관측 대상 / 최소 요구 정보 / 성공 조건을 확정하는 것이 목적이다.
>
> - 현재 저장소에는 **Network Log 수집 구조가 존재하지 않는다.** (As-Is)
> - 이 문서는 Zeek 컨테이너 추가, docker-compose 변경, capture 방식 확정을 **포함하지 않는다.**
> - 구현 방식 결정은 `#4 Cross-platform Traffic Capture PoC`, Event Schema 확정은 `#7 Network Event Schema`에서 수행한다.

- 작성 기준일: 2026-09-20
- 기준 저장소 상태: `docker-compose.yml`, `leafy/fluentd/fluent.conf`, `monitoring/prometheus/prometheus.yml`, `leafy/nginx/default.conf` 확인 기준
- 선행 문서: `docs/verification/PRE_IMPLEMENTATION_BASELINE_VERIFICATION.md` (Baseline 검증 완료 전제)

---

## 1. Goal (목적)

### 1.1 왜 Network Observability를 추가하는가

현재 Leafy AIOps 환경은 **Application Log (Loki)** 와 **Metrics (Prometheus)** 두 축으로만 관측된다.
이 두 축은 "서비스 내부에서 무엇이 기록되었는가"와 "리소스/지표가 어떻게 변했는가"는 설명하지만,
**서비스 간(inter-service) 통신에서 실제로 무슨 일이 일어났는가**는 설명하지 못한다.

구체적으로 현재 구조에서 확인하기 어려운 것:

- 어떤 서비스가 어떤 서비스로 실제 연결을 맺었는지 (connection 단위 사실)
- 연결이 정상 종료 / 거부 / 타임아웃 되었는지 (connection state)
- 통신량, 지속 시간 등 트래픽 특성
- Application Log가 아예 남지 않는 실패 (예: 연결 자체가 거부된 경우)

### 1.2 최종 목표

> Leafy 서비스 간 네트워크 트래픽을 Mac / Windows Docker Desktop 환경에서 **가능한 한 동일한 Docker Compose 기반 구조로 관측**하고,
> 이를 이후 **Structured Network Event**로 변환하여 **Loki**와 **AIOps Pipeline**에서 활용할 수 있도록 한다.

즉, 목표는 "Zeek 컨테이너를 띄우는 것"이 아니라
**Application Log + Metrics + Network Context를 함께 조회할 수 있는 관측 기반을 만드는 것**이다.

### 1.3 기대 효과 (As-Is / To-Be)

| 축 | 현재 (As-Is) | 추가 후 (To-Be) |
|---|---|---|
| Application Log | Loki에서 조회 가능 | 유지 |
| Metrics | Prometheus에서 조회 가능 | 유지 |
| Network Context | **없음** | Structured Network Event로 조회 가능 |
| AIOps 분석 입력 | Log + Metrics | Log + Metrics + Network |

---

## 2. Scope (범위)

### 2.1 초기 PoC 범위

초기 PoC는 **다음 두 통신의 관측 가능성 확보**로 한정한다.

```text
Case 1: frontend -> backend
Case 2: backend  -> db
```

### 2.2 Network Observer가 확인해야 할 최소 범위

- 위 두 통신이 **실제로 발생했다는 사실**을 network 수준에서 식별할 수 있어야 한다.
- 각 통신을 **service identity와 연결 가능한 형태**로 표현할 수 있어야 한다.
- 최소 수준의 connection 정보(§6)를 제공할 수 있어야 한다.
- 관측 결과가 **이후 structured event로 변환 가능한 형태**여야 한다. (이 단계에서 변환 구현은 하지 않는다)

### 2.3 지원 대상 플랫폼

- **Mac Docker Desktop**
- **Windows Docker Desktop**

두 환경 모두 지원 대상이며, 어느 한쪽만 동작하는 경우는 PoC 성공으로 보지 않는다.

### 2.4 전제 (Assumption)

현재 Leafy는 완전한 업무 서비스가 아니라 **테스트 / 데모 성격**을 포함한다.
따라서 **runtime business API 또는 실제 business query가 존재하지 않는 것 자체를 요구사항 실패로 간주하지 않는다.**
관측 대상은 "업무 트래픽"이 아니라 "service 간 통신"이다.

---

## 3. Out of Scope (이번 범위 제외)

| 항목 | 처리 방향 |
|---|---|
| Attacker / 공격 트래픽 관측 | 초기 PoC(정상 트래픽) 완료 후 확장 |
| Raw packet (pcap) 장기 저장 | 제외. 장기 보관 대상은 structured event만 고려 |
| LLM fine-tuning | 제외 |
| Remediation 전면 개편 | 제외. 기존 `aiops/remediation` 구조 유지 |
| Alert rule 전면 재설계 | 제외. 기존 Prometheus / Loki rule 유지 |
| 전체 AIOps 리팩터링 | 제외. Pipeline은 이후 확장 대상이며 이번 범위 아님 |
| Network Event Schema 최종 확정 | `#7`에서 수행 |
| Capture 방식 확정 / Zeek 도입 | `#4`, `#5`에서 수행 |

---

## 4. Current Architecture (As-Is)

아래 내용은 현재 `docker-compose.yml` 및 관련 config 파일에서 **확인된 사실**이다.

### 4.1 Docker Network

`docker-compose.yml`에 정의된 네트워크는 2개이다.

| Network | Driver | 역할 |
|---|---|---|
| `leafy-net` | bridge | 애플리케이션 서비스 레이어 (application traffic) |
| `mgmt-net` | bridge | 관리 / 관측 / AIOps 레이어 (management traffic) |

런타임 기준 `leafy-net`은 `graduation-project_leafy-net` 이름으로 생성되며,
subnet `172.18.0.0/16`, gateway `172.18.0.1`로 확인되었다 (Baseline 검증 결과).

> ⚠️ 주의: `docker-compose.yml`에는 subnet / gateway가 **명시되어 있지 않다.**
> `172.18.0.0/16`은 Docker가 런타임에 할당한 값이므로 **고정값으로 취급하면 안 된다.** (§7.2 참고)

### 4.2 서비스별 네트워크 소속

| 서비스 | 컨테이너 | leafy-net | mgmt-net | 분류 |
|---|---|---|---|---|
| `frontend` | `leafy-frontend` | O | - | Application |
| `backend` | `leafy-backend` | O | O | Application (+ metrics 노출) |
| `db` | `leafy-db` | O | - | Application |
| `fluentd` | `fluentd` | O | O | Logging (양쪽 연결) |
| `node-exporter` | `node-exporter` | - | O | Observability |
| `cadvisor` | `cadvisor` | - | O | Observability |
| `nginx-exporter` | `nginx-exporter` | O | O | Observability |
| `postgres-exporter` | `postgres-exporter` | O | O | Observability |
| `prometheus` | `prometheus` | - | O | Observability |
| `alertmanager` | `alertmanager` | - | O | Observability |
| `loki` | `loki` | - | O | Observability |
| `grafana` | `grafana` | - | O | Observability |
| `ollama` | `ollama` | - | O | AIOps |
| `pipeline` | `aiops-pipeline` | - | O | AIOps |
| `remediation` | `aiops-remediation` | - | O | AIOps |

### 4.3 Application traffic vs Management / Observability traffic

**Application traffic (`leafy-net`) — PoC 관측 대상**

```text
frontend(leafy-frontend) --HTTP--> backend:8080      # nginx proxy_pass http://backend:8080
backend(leafy-backend)   --JDBC--> db:5432           # jdbc:postgresql://db:5432/leafy
```

**Management / Observability traffic — PoC 필수 관측 대상 아님**

```text
prometheus -> node-exporter:9100 / cadvisor:8080 / nginx-exporter:9113
prometheus -> postgres-exporter:9187 / pipeline:8000 / backend:8080 (/actuator/prometheus)
pipeline   -> prometheus:9090, loki:3100, ollama:11434, alertmanager:9093, remediation:8001
grafana    -> prometheus, loki
```

주의: `nginx-exporter`, `postgres-exporter`는 `leafy-net`에도 연결되어 있어
`frontend:80`, `db:5432`로 향하는 **관측용 트래픽을 `leafy-net` 안에 발생시킨다.**
따라서 `leafy-net` 트래픽 = application traffic 이라고 단정할 수 없으며, §5의 Case 1 / Case 2를 **service 단위로 구분해서 판정**해야 한다.

**Logging traffic (현재 구조)**

```text
leafy-frontend --(docker fluentd log driver)--> fluentd --> loki
leafy-backend  --(docker fluentd log driver)--> fluentd --> loki
leafy-db       --(docker fluentd log driver)--> fluentd --> loki
```

> ⚠️ 주의: compose의 logging option은 `fluentd-address: "localhost:24224"`이다.
> 즉 컨테이너 로그는 `leafy-net` 내부 DNS가 아니라 **Docker daemon → host published port(24224)** 경로로 전달된다.
> Network Observer가 `leafy-net` 내부만 관측하는 경우 이 logging traffic은 보이지 않을 수 있다.
> 이는 결함이 아니라 **관측 범위를 해석할 때 주의할 점**이다.

### 4.4 현재 Loki application identity (확인된 사실)

`leafy/fluentd/fluent.conf`는 Docker log tag를 `container` label로 부여한다.

| 컨테이너 | Loki label key | 값 |
|---|---|---|
| `leafy-frontend` | `container` | `frontend` |
| `leafy-backend` | `container` | `backend` |
| `leafy-db` | `container` | `leafy-db` |

> ⚠️ 주의 (기존 구조와의 불일치 — **이번 이슈에서 수정하지 않음**):
> - label **키 이름이 `service`가 아니라 `container`** 인데, 실제 값은 logical service 이름(`frontend`, `backend`)이다.
> - `db`만 값이 `leafy-db`로, canonical service name(`db`)과 다르다.
> - `aiops/pipeline`은 Loki를 `{container="..."}` 형태로 조회한다. 따라서 label 키 / 값을 바꾸면 pipeline에 영향을 준다.
> - → Network Event의 label 설계는 이 불일치를 **인지한 상태에서 `#7`에서 결정**해야 한다. 이번 문서는 문제 제기까지만 한다.

### 4.5 Network Log

**현재 Network Log는 존재하지 않는다.**
Network Observability 적용 이전에는 network 수준 이벤트를 수집 · 저장 · 조회하는 구성 요소가 저장소에 없다.

---

## 5. Target Traffic (관측 대상 트래픽)

초기 PoC의 **필수 관측 대상은 정확히 아래 두 개**이다.

| Case | Traffic | 근거 (현재 저장소) |
|---|---|---|
| Case 1 | `frontend -> backend` | `leafy/nginx/default.conf`의 `proxy_pass http://backend:8080` |
| Case 2 | `backend -> db` | `docker-compose.yml`의 `SPRING_DATASOURCE_URL: jdbc:postgresql://db:5432/leafy` |

이 두 통신은 **`#4 Traffic Capture PoC`의 고정 검증 조건(fixed verification condition)** 으로 사용한다.
`#4`에서 capture 방식을 무엇으로 선택하든, **이 두 통신이 관측되지 않으면 PoC는 실패로 판정한다.**

그 외 통신(management / observability / AIOps)은 관측되면 참고 정보로 활용하되, **성공 조건에 포함하지 않는다.**

---

## 6. Required Network Context (최소 요구 정보)

> ⚠️ 이 절은 **최종 스키마가 아니다.** Network Observer가 최소한 제공해야 하는 **정보 요구사항(information requirement)** 만 정의한다.
> 필드 타입, 최종 필드명, Loki label / non-label 구분 등 **최종 설계는 `#7 Network Event Schema`에서 확정한다.**

### 6.1 Connection 정보 (필수 후보)

| 항목 | 설명 | 필요성 |
|---|---|---|
| `timestamp` | 통신 발생 시각 | 필수 — Log / Metrics와 시간축 정렬 |
| `src_ip` | 출발지 IP | 필수 |
| `dst_ip` | 목적지 IP | 필수 |
| `src_port` | 출발지 포트 | 필수 |
| `dst_port` | 목적지 포트 | 필수 — service 추정 보조 |
| `protocol` | 전송 프로토콜 (tcp / udp 등) | 필수 |
| `connection_state` | 연결 상태 / 종료 상태 | 필수 — 실패 통신 식별 |
| `bytes` | 전송량 | 필수 (방향별 분리 여부는 `#7`) |
| `duration` | 연결 지속 시간 | 필수 |

### 6.2 Service Identity 연결 요구사항

Network Event는 **service identity와 연결 가능해야 한다.**
IP / port만으로는 기존 Application Log 및 Metrics와의 상관분석(correlation)이 불가능하다.

최소한 다음 정보로 해석 가능해야 한다.

| 항목 | 예시 |
|---|---|
| `src_service` | `frontend` |
| `src_container` | `leafy-frontend` |
| `dst_service` | `backend` |
| `dst_container` | `leafy-backend` |

이 정보를 **Observer가 직접 생성하든, 후처리 단계에서 매핑하든 무방하다.**
어느 단계에서 어떻게 부여할지는 `#4` / `#7`에서 결정한다.
이번 문서는 **"결과적으로 연결 가능해야 한다"** 는 요구사항만 확정한다.

### 6.3 미확정 사항 (이번 이슈에서 확정하지 않음)

- 필드 이름 / 타입 / 단위
- Loki label로 승격할 필드와 log line body에 남길 필드의 구분
- Event 단위 (connection 단위 vs 요약 단위)
- 보존 기간(retention)

---

## 7. Identity Requirements

### 7.1 service와 container를 구분한다

Docker **container name**과 logical **service name**은 서로 다른 개념이며, 혼용하지 않는다.

```text
service=frontend   container=leafy-frontend
service=backend    container=leafy-backend
service=db         container=leafy-db
```

- `service`: 논리적 서비스 이름. 안정적이며 분석 / 집계의 기준.
- `container`: 실제 Docker 컨테이너 이름. 운영 / 디버깅 추적용.

요구사항: **Network Event는 service와 container를 각각 별도 정보로 표현할 수 있어야 한다.**
(`leafy-backend`를 service 이름으로 쓰거나, `backend`를 container 이름으로 쓰는 혼용을 허용하지 않는다.)

### 7.2 IP를 identity로 고정하지 않는다

`leafy-net`의 컨테이너 IP는 Docker 재생성 / 기동 순서에 따라 변경될 수 있다.
또한 compose 파일에 subnet이 고정되어 있지 않으므로 **대역 자체도 환경에 따라 달라질 수 있다** (§4.1).

요구사항:

- **identity를 IP 값에 고정해서는 안 된다.**
- IP는 "관측된 사실(observed fact)"로 기록하되, service를 식별하는 **키(key)로 사용하지 않는다.**
- IP → service 매핑은 **runtime에 해석 가능한 방식**이어야 한다. (구체적 방식은 `#4`)

### 7.3 기존 Loki identity와의 정합성

§4.4의 기존 불일치(`db` → `leafy-db`, label 키가 `container`)를 고려해야 한다.

- 이번 이슈에서는 **기존 logging 구조를 수정하지 않는다.**
- Network Event의 identity 표기를 기존 Application Log와 어떻게 정합시킬지는 `#7`에서 결정한다.

---

## 8. Traffic Capture Requirements

> ⚠️ 이 절은 **요구조건(requirement)** 만 정의한다. **구현 방식을 확정하지 않는다.**

### 8.1 요구조건

| # | 요구조건 |
|---|---|
| R1 | `frontend -> backend` traffic을 관측할 수 있어야 한다. |
| R2 | `backend -> db` traffic을 관측할 수 있어야 한다. |
| R3 | **Mac Docker Desktop**에서 검증 가능해야 한다. |
| R4 | **Windows Docker Desktop**에서 검증 가능해야 한다. |
| R5 | Leafy application 동작을 크게 변경하지 않아야 한다. (application 코드 / 기능 변경 없음) |
| R6 | 가능한 한 **Docker Compose 기반으로 재현 가능**해야 한다. |
| R7 | Network Observer가 **structured event 생성을 위한 raw traffic visibility**를 확보해야 한다. |

### 8.2 Implementation Candidates (후보 — 확정 아님)

아래는 **검토 대상 후보**일 뿐이며, 어느 것도 정답으로 확정하지 않는다.

| Candidate | 개요 | 확인 필요 사항 (→ #4) |
|---|---|---|
| Docker bridge / interface capture | host 또는 Docker Desktop VM 상의 bridge interface를 직접 capture | Docker Desktop에서 해당 interface 접근 가능 여부 |
| Service network namespace sharing | 대상 서비스의 network namespace를 공유하여 capture | 서비스별 observer 필요 여부, R5 / R6 위반 여부 |
| eBPF | 커널 레벨 관측 | Docker Desktop VM 커널 지원 여부, 필요 권한 |
| Traffic mirroring | 트래픽을 복제하여 별도 관측 | 구성 복잡도, application 영향(R5) |

**선택 기준**: R1–R7을 모두 만족하면서, Mac / Windows 간 구조 차이가 가장 작은 방식.
**최종 선택은 `#4 Cross-platform Traffic Capture PoC`에서 실제 검증 후 결정한다.**

---

## 9. Cross-platform Constraints

Mac / Windows Docker Desktop에서 Linux container network는 **host OS에서 직접 동작하지 않고, Docker Desktop이 관리하는 Linux VM 내부에서 동작**한다.
따라서 일반 Linux Docker 환경과 네트워크 관측 조건이 다를 수 있다.

> 참고: 현재 저장소에도 이미 이 차이에 영향을 받는 구성이 존재한다.
> `node-exporter`의 `pid: host`, `cadvisor`의 `/var/lib/docker` 마운트, `ollama`의 `gpus: all`은
> Docker Desktop에서 host OS가 아닌 **VM 기준으로 동작하거나 제약을 받는다.**
> 이는 이번 이슈의 수정 대상이 아니며, **플랫폼 차이가 실재한다는 근거로만 인용한다.**

### 9.1 요구사항

| # | 요구사항 |
|---|---|
| C1 | **host bridge 직접 capture가 당연히 가능하다고 가정하지 않는다.** Mac / Windows에서 bridge interface는 host OS에 노출되지 않을 수 있다. |
| C2 | **platform별 별도 구현이 필요한지 여부를 `#4`에서 검증한다.** 현 단계에서 "동일하다" / "다르다"로 단정하지 않는다. |
| C3 | **동일 Compose 구조 사용을 우선 목표**로 하되, 실제 capture mechanism은 platform 제약에 따라 다를 수 있음을 허용한다. |
| C4 | platform별 차이가 불가피할 경우, 차이는 **capture 계층에 국한**되어야 하며 Network Event 출력 형태는 동일해야 한다. |

---

## 10. Logging Integration Direction

> ⚠️ 이번 이슈에서 **Network Observer → Loki 연동은 구현하지 않는다.** 방향만 정의한다.

### 10.1 목표 구조 (To-Be)

```text
Application Log:
  Application (frontend / backend / db)
    -> Fluentd
    -> Loki

Network Log:
  Network Traffic
    -> Network Observer
    -> Structured Network Event
    -> Loki

Metrics:
  Exporter (node / cadvisor / nginx / postgres / backend actuator)
    -> Prometheus
```

### 10.2 현재와의 차이

| 경로 | As-Is | To-Be |
|---|---|---|
| Application Log → Fluentd → Loki | 구현됨 | 유지 |
| Exporter → Prometheus | 구현됨 | 유지 |
| Network Traffic → Observer → Loki | **없음** | 추가 예정 (`#5` 이후) |

### 10.3 Pipeline 확장 방향

이후 `aiops/pipeline`은 **Application Logs + Network Logs + Metrics를 함께 조회하는 구조로 확장할 예정**이다.

- 현재 pipeline은 Loki를 `{container="..."}` 기준으로만 조회한다 (§4.4).
- Network Event를 함께 조회하려면 query / label 전략 정리가 필요하다.
- 단, **pipeline 확장은 이번 이슈 및 `#4`의 범위가 아니다** (§3).

---

## 11. PoC Success Criteria

| Environment | Traffic | Success Condition |
|---|---|---|
| Mac Docker Desktop | frontend -> backend | Network Observer에서 해당 통신 확인 |
| Mac Docker Desktop | backend -> db | Network Observer에서 해당 통신 확인 |
| Windows Docker Desktop | frontend -> backend | Network Observer에서 해당 통신 확인 |
| Windows Docker Desktop | backend -> db | Network Observer에서 해당 통신 확인 |

### 11.1 "확인"의 의미 (중요)

성공 조건은 **단순 connectivity 확인이 아니다.**

| 성공으로 인정하지 않음 | 성공으로 인정함 |
|---|---|
| `ping` / `curl`로 연결이 된다는 사실만 확인 | Network Observer가 해당 연결을 **network event 수준으로 관측** |
| 컨테이너가 정상 기동했다는 사실 | src / dst, port, protocol, connection 상태 등 §6 최소 정보를 식별 가능 |
| Application Log에 요청이 남았다는 사실 | 해당 통신을 **service identity와 연결 가능한 형태**로 표현 가능 |

즉 **실제 Network Event 수준의 관측 가능 여부**가 성공 조건이다.

### 11.2 실패로 간주하지 않는 경우

- runtime business API / 실제 business query가 없는 경우 (§2.4)
- management / observability traffic이 관측되지 않는 경우 (§5)
- 관측된 IP가 이전 baseline과 다른 값인 경우 (§7.2)

---

## 12. Acceptance Criteria (#3 완료 조건)

- [ ] Network Observability 목적 정의
- [ ] 초기 관측 대상 traffic 정의
- [ ] Mac / Windows 지원 범위 정의
- [ ] 최소 Network Context 요구사항 정의
- [ ] service / container identity 기준 정의
- [ ] Traffic Capture 요구조건 정의
- [ ] Capture candidate를 구현과 분리
- [ ] Raw packet 장기 저장 제외
- [ ] #4 Traffic Capture PoC 성공 조건 정의
- [ ] #7 Network Event Schema와 책임 범위 분리

---

## 13. Dependency / Next Step

```text
#3 Requirements                          ← 이 문서 (요구사항 확정)
     ↓
#4 Cross-platform Traffic Capture PoC    ← capture 방식 실제 검증 및 선택
     ↓
#7 Network Event Schema                  ← 필드 / 타입 / Loki label 확정
     ↓
#5 Zeek Docker Compose Integration       ← compose 통합 및 구현
```

### 13.1 단계별 책임 범위

| Issue | 책임 | 이 단계에서 다루지 않는 것 |
|---|---|---|
| `#3` | 목적, 범위, 관측 대상, 최소 정보 요구사항, 성공 조건 | 구현 방식, 스키마, compose 변경 |
| `#4` | Mac / Windows capture 가능성 검증 및 방식 선택 | 스키마 확정 |
| `#7` | Network Event Schema, Loki label 설계 | compose 통합 |
| `#5` | Zeek / Observer의 Docker Compose 통합 | — |

### 13.2 이 문서에서 의도적으로 미확정으로 남긴 항목

1. Capture 구현 방식 (§8.2 — 후보만 제시)
2. Network Event 필드명 / 타입 / 단위 (§6.3)
3. Loki label 설계 및 기존 `container` label과의 정합성 처리 (§4.4, §7.3)
4. IP → service 매핑을 수행하는 단계 (§6.2)
5. Network Event 보존 기간 (§6.3)
6. platform별 구현 분기 필요 여부 (§9 C2)
7. Pipeline 확장 방식 (§10.3)
