# Leafy AIOps — Pre-Implementation Baseline Verification Guide

> 목적: Network Observability / Zeek 구현 전에 현재 Leafy AIOps 환경이 기존 Baseline과 동일한지 확인하기 위한 팀 공용 점검 문서이다.  
> 이 문서 하나만 보고 **Claude Code 자동 점검** 또는 **사용자 수동 점검** 중 하나를 수행할 수 있도록 작성한다.

---

## 1. Baseline 기준

이번 Network Observability PoC에서 구현 전에 보장되어야 하는 기준은 다음과 같다.

### Network PoC 대상

```text
Case 1
frontend → backend

Case 2
backend → db
```

단순히 컨테이너가 실행되는 것만으로는 충분하지 않다.

```text
현재 Baseline
- frontend → backend 실제 통신 존재
- backend → db 실제 통신 존재
- Application Log가 Loki에서 조회 가능

구현 후 추가 검증
- frontend → backend Network Event 관측
- backend → db Network Event 관측
```

### Canonical Identity Baseline

```text
frontend
container: leafy-frontend
service: frontend

backend
container: leafy-backend
service: backend

db
container: leafy-db
service: db
```

Application Log의 기존 Loki identity는 다음을 기준으로 한다.

```text
leafy-frontend → frontend
leafy-backend  → backend
leafy-db       → leafy-db
```

### Docker Network Baseline

```text
network
name: graduation-project_leafy-net
driver: bridge
subnet: 172.18.0.0/16
gateway: 172.18.0.1
```

구현 전 `leafy-net`에는 최소한 다음 컨테이너가 연결되어 있어야 한다.

```text
leafy-frontend
leafy-backend
leafy-db
fluentd
```

IP의 마지막 octet은 Docker 재생성/실행 순서에 따라 달라질 수 있으므로 **고정값으로 비교하지 않는다**.  
각 컨테이너가 `172.18.0.0/16` 대역의 서로 다른 실제 IP를 가지고 있는지만 확인한다.

---

## 2. Claude Code에 넣을 Pre-check Prompt

아래 프롬프트를 **Network Observability / Zeek 관련 코드를 수정하기 전에** Claude Code에 그대로 입력한다.

```text
현재 graduation-project 저장소에 대해 Network Observability 구현 전 Baseline 검증만 수행해줘.

중요:
- 기존 source code, docker-compose.yml, monitoring config, logging config, current_info_files의 기존 문서는 수정하지 마.
- 컨테이너/서비스 설정을 바꾸지 마.
- 문제를 발견해도 자동 수정하지 마.
- 유일하게 새로 생성해도 되는 파일은 아래 보고서 파일 하나뿐이야.

생성 파일:
current_info_files/PRE_IMPLEMENTATION_BASELINE_REPORT.md

검증 목적:
현재 실행 환경이 Network Observability 구현 전 Baseline과 동일한지 확인한다.

Baseline 조건:

1. Docker Compose에 다음 서비스가 정의되어 있어야 한다.
   - prometheus
   - fluentd
   - db
   - backend
   - loki
   - node-exporter
   - ollama
   - alertmanager
   - frontend
   - pipeline
   - remediation
   - postgres-exporter
   - cadvisor
   - grafana
   - nginx-exporter

2. Network Observability PoC에 필요한 핵심 Leafy 서비스가 실행 중이어야 한다.
   - leafy-frontend
   - leafy-backend
   - leafy-db
   - leafy-db는 healthy 상태여야 한다.

3. graduation-project_leafy-net을 확인한다.
   예상:
   - driver: bridge
   - subnet: 172.18.0.0/16
   - gateway: 172.18.0.1
   - leafy-frontend, leafy-backend, leafy-db, fluentd가 연결되어 있어야 한다.
   - 각 서비스의 IP는 runtime-assigned 값이므로 마지막 octet을 고정값으로 비교하지 않는다.

4. 실제 Application Traffic Baseline을 확인한다.
   반드시 확인할 통신:
   - frontend → backend
   - backend → db

   단순 ping만으로 PASS 처리하지 마.
   실제 Leafy 기능/API 요청 및 관련 application log를 근거로 판단해.
   자동으로 실제 사용자 동작을 재현하기 어렵다면 해당 항목은 MANUAL REQUIRED로 표시하고,
   사용자가 어떤 기능을 실행하고 어떤 로그를 확인해야 하는지 적어줘.

5. Application Log Baseline을 확인한다.
   Canonical identity:
   - frontend: container=leafy-frontend, service=frontend
   - backend: container=leafy-backend, service=backend
   - db: container=leafy-db, service=db

   기존 Loki application-log identity:
   - leafy-frontend -> frontend
   - leafy-backend -> backend
   - leafy-db -> leafy-db

   Fluentd/Loki 설정을 실제 코드에서 확인하고,
   가능하면 현재 Loki에 저장된 로그도 확인해.
   Loki label key를 추측하지 말고 실제 설정/조회 결과를 기준으로 기록해.

6. 다음 서비스는 Network Traffic Baseline 자체의 필수 PASS 조건은 아니다.
   - nginx-exporter
   - postgres-exporter

   이들이 중지되어 있으면 WARNING으로 기록하되,
   frontend/backend/db Network PoC 자체를 FAIL 처리하지는 마.

7. docker-compose.yml의 `version` obsolete warning은 WARNING으로만 기록하고
   이번 Baseline의 FAIL 원인으로 처리하지 마.

보고서 형식:

# Pre-Implementation Baseline Report (보고서를 작성한 날짜)

## Environment
- OS / Docker environment
- checked at
- git branch
- git commit

## Summary
- Final Status: BASELINE MATCH / PARTIAL MATCH / BASELINE MISMATCH

## Docker Compose
| Check | Expected | Actual | Status | Evidence |

## Leafy Network
| Check | Expected | Actual | Status | Evidence |

## Application Traffic
| Flow | Expected | Actual | Status | Evidence |
| frontend → backend | actual application traffic exists | ... | PASS/FAIL/MANUAL REQUIRED | ... |
| backend → db | actual DB traffic exists | ... | PASS/FAIL/MANUAL REQUIRED | ... |

## Application Log / Loki
| Service | Container | Expected Loki Identity | Actual | Status | Evidence |

## Warnings
- exporter 상태
- version obsolete warning
- 기타 구현 전 참고사항

## Final Comparison
각 Baseline 항목이 기존 기준과 동일한지 하나씩 비교해.

최종 판정 기준:
- 모든 필수 항목 PASS -> BASELINE MATCH
- 자동 확인 불가 항목만 MANUAL REQUIRED이고 실패 증거 없음 -> PARTIAL MATCH
- 필수 서비스/네트워크/통신/로그 중 하나라도 실제 불일치 -> BASELINE MISMATCH

마지막에 다음 문구 중 하나를 명확하게 적어줘.

BASELINE MATCH:
"현재 환경은 Network Observability 구현 전 Baseline과 동일하다. 구현을 시작해도 된다."

PARTIAL MATCH:
"자동 검증만으로 Baseline 전체를 확정할 수 없다. MANUAL REQUIRED 항목 확인 후 구현을 시작한다."

BASELINE MISMATCH:
"현재 환경이 기존 Baseline과 다르다. 구현 전에 불일치 원인을 먼저 해결해야 한다."

중요:
검증이 끝나도 코드를 수정하지 말고,
current_info_files/PRE_IMPLEMENTATION_BASELINE_REPORT.md만 생성해.

파일 위치는 graduation-project\docs\verification\PRE_IMPLEMENTATION_BASELINE\report 에 저장하도록 해.

현재 애플리케이션에 해당 기능 자체가 구현되어 있지 않아
runtime business traffic을 발생시킬 수 없는 경우,
이를 FAIL 또는 MANUAL REQUIRED로 처리하지 말고 N/A로 기록한다.

N/A 판정 시:
- 왜 해당 기능을 검증할 수 없는지 설명
- 대신 현재 확인 가능한 실제 연결/통신 증거를 기록
- 예:
  frontend → backend:
  nginx proxy_pass를 통한 HTTP 요청 확인

  backend → db:
  Hikari connection / Hibernate initialization을 통한
  PostgreSQL 연결 확인
```

---

## 3. Claude Code 실행 후 나와야 하는 결과

Claude Code가 생성한 아래 파일을 확인한다.

```text
current_info_files/PRE_IMPLEMENTATION_BASELINE_REPORT.md
```

### 정상 Baseline이라면 핵심 결과

```text
Final Status: BASELINE MATCH
```

필수 항목은 대략 다음과 같이 나와야 한다.

| 검증 항목 | Baseline 결과 |
|---|---|
| Docker Compose 서비스 정의 | PASS |
| leafy-frontend 실행 | PASS |
| leafy-backend 실행 | PASS |
| leafy-db 실행 | PASS |
| leafy-db health | PASS |
| leafy-net driver | bridge |
| leafy-net subnet | 172.18.0.0/16 |
| leafy-net gateway | 172.18.0.1 |
| frontend의 leafy-net 연결 | PASS |
| backend의 leafy-net 연결 | PASS |
| db의 leafy-net 연결 | PASS |
| fluentd의 leafy-net 연결 | PASS |
| frontend → backend 실제 통신 | PASS 또는 MANUAL REQUIRED |
| backend → db 실제 통신 | PASS 또는 MANUAL REQUIRED |
| frontend Application Log | PASS |
| backend Application Log | PASS |
| db Application Log | PASS |
| Loki Application Log 조회 | PASS |

### 허용되는 Warning

다음은 이번 Network PoC의 Baseline을 깨는 항목으로 보지 않는다.

```text
docker-compose.yml version attribute obsolete
nginx-exporter stopped
postgres-exporter stopped
```

단, 별도 Metrics 작업을 시작하기 전에는 exporter 상태를 다시 확인해야 한다.

### Baseline과 동일하다고 판단하는 기준

```text
BASELINE MATCH
=
Leafy 핵심 서비스 실행 정상
+
leafy-net 구조 정상
+
frontend → backend 통신 정상
+
backend → db 통신 정상
+
기존 Application Log / Loki 흐름 정상
```

Network Event는 아직 구현 전이므로 이 단계에서는 존재하지 않아도 정상이다.

```text
Application Logs  ✅
Network Logs      미구현 상태가 정상
Metrics           기존 Prometheus 구조 유지
```

---

## 4. Claude Code 없이 직접 확인하는 방법

Claude Code를 사용하지 않아도 아래 명령어를 순서대로 실행하여 같은 Baseline을 확인할 수 있다.

### Docker Compose 서비스 정의

```bash
docker compose config --services
```

정상 Baseline에서는 최소 다음 서비스가 확인되어야 한다.

```text
prometheus
fluentd
db
backend
loki
node-exporter
ollama
alertmanager
frontend
pipeline
remediation
postgres-exporter
cadvisor
grafana
nginx-exporter
```

순서는 달라도 무관하다.

---

### Leafy 핵심 서비스 실행

```bash
docker compose up -d db backend frontend
```

예상:

```text
leafy-db        Healthy
leafy-backend   Started / Running
leafy-frontend  Started / Running
```

확인:

```bash
docker compose ps -a
```

필수 Baseline:

```text
leafy-frontend   Up
leafy-backend    Up
leafy-db         Up (...) (healthy)
```

AIOps / Monitoring 주요 서비스도 실행 중인지 함께 확인한다.

```text
aiops-pipeline      Up
aiops-remediation   Up
alertmanager        Up
cadvisor            Up
fluentd             Up
grafana             Up
loki                Up
node-exporter       Up
ollama              Up
prometheus          Up
```

`nginx-exporter`, `postgres-exporter`가 중지되어 있어도 이번 Network PoC Baseline은 진행할 수 있다.

---

### Docker Network 확인

```bash
docker network ls
```

예상:

```text
graduation-project_leafy-net   bridge
graduation-project_mgmt-net    bridge
```

상세 확인:

```bash
docker network inspect graduation-project_leafy-net
```

예상 Baseline:

```text
network
name: graduation-project_leafy-net
driver: bridge
subnet: 172.18.0.0/16
gateway: 172.18.0.1
```

연결 컨테이너:

```text
leafy-frontend
leafy-backend
leafy-db
fluentd
```

각 IP는 다음 형태여야 한다.

```text
frontend
container: leafy-frontend
service: frontend
IP: 172.18.0.x

backend
container: leafy-backend
service: backend
IP: 172.18.0.x

db
container: leafy-db
service: db
IP: 172.18.0.x

fluentd
container: fluentd
service: fluentd
IP: 172.18.0.x
```

`x`의 정확한 값은 고정 Baseline으로 사용하지 않는다.

---

### Application Log 확인

Frontend:

```bash
docker logs --tail 50 leafy-frontend
```

Backend:

```bash
docker logs --tail 50 leafy-backend
```

Database:

```bash
docker logs --tail 50 leafy-db
```

필요하면 실시간으로 확인한다.

```bash
docker logs -f leafy-backend
```

```bash
docker logs -f leafy-db
```

정상 Baseline:

```text
frontend log 발생 확인
backend log 발생 확인
db log 발생 확인
```

로그가 바로 보이지 않는 경우 실제 Leafy 기능을 실행하여 요청을 발생시킨 뒤 다시 확인한다.

---

### frontend → backend 통신 확인

한 터미널에서 실행한다.

```bash
docker logs -f leafy-backend
```

브라우저에서 Leafy의 Backend API를 사용하는 실제 기능을 실행한다.

예:

```text
로그인
사용자 조회
데이터 조회
```

정상 결과:

```text
Frontend 기능 실행
        ↓
Backend 요청 발생
        ↓
leafy-backend log에서 요청 확인

frontend → backend 통신 존재 ✅
```

이 단계에서는 아직 Zeek Network Event가 없어도 정상이다.

---

### backend → db 통신 확인

Backend와 DB 로그를 각각 확인한다.

```bash
docker logs -f leafy-backend
```

```bash
docker logs -f leafy-db
```

DB 조회가 발생하는 Leafy 기능을 실행한다.

정상 결과:

```text
Frontend 기능 실행
        ↓
Backend API
        ↓
PostgreSQL 접근

backend → db 통신 존재 ✅
```

---

### Loki / Grafana Application Log 확인

Grafana에서 다음 경로로 이동한다.

```text
Grafana
→ Explore
→ Data source: Loki
```

실제 Loki Label을 확인하고 각각의 Application Log가 조회되는지 확인한다.

기존 identity Baseline:

```text
leafy-frontend → frontend
leafy-backend  → backend
leafy-db       → leafy-db
```

정상 결과:

```text
frontend Application Log 조회 ✅
backend Application Log 조회  ✅
db Application Log 조회       ✅
```

Loki label 이름은 실제 Fluentd/Loki 설정을 기준으로 사용하며 `tag`, `service`, `container_name` 중 하나라고 임의로 가정하지 않는다.

---

## 5. 최종 체크리스트

구현 시작 전에 아래 상태이면 된다.

```text
Docker Compose 서비스 정의 확인       ✅
Leafy frontend 실행                   ✅
Leafy backend 실행                    ✅
Leafy db 실행 / healthy               ✅

leafy-net 생성                         ✅
leafy-net = bridge                     ✅
subnet = 172.18.0.0/16                 ✅
gateway = 172.18.0.1                   ✅
frontend/backend/db/fluentd 연결        ✅

frontend → backend 실제 통신           ✅
backend → db 실제 통신                 ✅

Frontend Application Log              ✅
Backend Application Log               ✅
DB Application Log                    ✅
Application Log → Loki                ✅

Zeek Network Event                    ⏳ 구현 후 검증
```

최종 상태:

```text
Before Network Observability

Application Logs  ✅
Metrics           기존 구조 유지
Network Logs      아직 없음
```

이 상태를 확인한 뒤 Network Observability 구현을 시작한다.

구현 이후에는 동일한 두 통신을 기준으로 다음 조건을 추가 검증한다.

```text
frontend → backend
통신 존재 ✅
Network Event 관측 ✅

backend → db
통신 존재 ✅
Network Event 관측 ✅
```

---

## 6. Baseline 불일치 시 원칙

Baseline이 다르면 Zeek 구현을 바로 시작하지 않는다.

```text
BASELINE MATCH
→ 구현 시작

PARTIAL MATCH
→ MANUAL REQUIRED 항목 확인
→ 확인 후 구현 시작

BASELINE MISMATCH
→ 기존 환경 문제 해결
→ Baseline 재검증
→ 구현 시작
```

구현 전 문제와 Network Observability 구현으로 새로 발생한 문제를 구분하기 위해 이 절차를 유지한다.
