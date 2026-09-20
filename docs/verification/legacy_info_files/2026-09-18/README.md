# Leafy AIOps 보안 플랫폼

건국대학교 졸업프로젝트 — Docker Compose 기반 LLM 지능형 AIOps 보안 플랫폼

---

## 프로젝트 개요

Leafy 서비스에서 발생하는 보안 위협 및 인프라 장애를 AI(Llama-3.1-8B)로 자동 탐지하고 대응하는 AIOps 플랫폼입니다.

```
공격 발생 → Prometheus/Loki 수집 → AlertManager → Pipeline → LLM 분석 → Remediation 자동 조치 → Slack 알림
```

---

## 시스템 구성

### 데이터 수집 (Exporters)

| 툴 | 역할 | 포트 |
|---|---|---|
| Node Exporter | 호스트 서버 전체 CPU/메모리/디스크 | 9100 |
| cAdvisor | 컨테이너별 리소스 | 8080 |
| Nginx Exporter | 웹서버 요청 수, 응답 코드 | 9113 |
| Postgres Exporter | DB 커넥션 수, 슬로우쿼리 | 9187 |
| Spring Actuator | 백엔드 JVM 상태 (내장) | 8080 |

### 저장소

| 툴 | 역할 | 포트 |
|---|---|---|
| Prometheus | 숫자 메트릭 저장 + 이상 감지 | 9090 |
| Loki | 로그 텍스트 저장 | 3100 |
| Grafana | 시각화 대시보드 | 3000 |

### AIOps 엔진

| 툴 | 역할 | 포트 |
|---|---|---|
| Pipeline | 데이터 수집 + LLM 프롬프트 조립 | 8000 |
| Ollama (Llama-3.1-8B) | 로컬 LLM 추론 | 11434 |
| Remediation Agent | 자동 조치 실행 | 8001 |

---

## 시작하기

### 사전 준비

1. Docker Desktop 설치 및 실행
2. `.env` 파일 생성 (프로젝트 루트에)

```env
DB_PASSWORD=leafy_secret
GRAFANA_PASSWORD=admin
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
JWT_SECRET=<hex 64자리>
JWT_SECRET_KEY=<64자 이상 문자열>
KAKAO_REST_API_KEY=<카카오 API 키>
KAKAO_CLIENT_SECRET=<카카오 시크릿>
KAKAO_MAP_API_KEY=<카카오 맵 키>
AWS_ACCESS_KEY=<AWS 키>
AWS_SECRET_KEY=<AWS 시크릿>
AWS_REGION=ap-northeast-2
CLOUDFRONT_URL=<CloudFront URL>
S3_BUCKET_NAME=<S3 버킷명>
PLANT_ID_API_KEY=<Plant.id 키>
OPEN_WEATHER_API_KEY=<기상청 키>
```

3. SSL 인증서 생성 (frontend용)

```bash
mkdir -p certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/leafy.key \
  -out certs/leafy.crt \
  -subj "/CN=leafy-pr.com"
```

---

### 컨테이너 실행

```bash
# 전체 시스템 시작
docker-compose up -d

# 상태 확인
docker ps

# 로그 확인
docker logs <컨테이너명> --tail 20
```

### 컨테이너 종료

```bash
docker-compose down
```

---

## 접속 주소

| 서비스 | 주소 |
|---|---|
| Leafy 서비스 | https://localhost |
| Grafana | http://localhost:3000 (admin/admin) |
| Prometheus | http://localhost:9090 |
| AlertManager | http://localhost:9093 |
| Pipeline 헬스체크 | http://localhost:8000/health |
| Remediation 헬스체크 | http://localhost:8001/health |

---

## Prometheus로 확인하기

브라우저에서 `http://localhost:9090` 접속

### Alert 룰 확인
```
상단 메뉴 → Alerts
→ 6개 룰 정상 동작 확인
```

### Targets 확인
```
상단 메뉴 → Status → Targets
→ 전부 UP 상태 확인
```

### 주요 쿼리

```promql
# 컨테이너별 CPU
rate(container_cpu_usage_seconds_total{name="leafy-db"}[1m])

# 호스트 전체 CPU
rate(node_cpu_seconds_total{mode!="idle"}[1m])

# DB 커넥션 수
pg_stat_activity_count

# 컨테이너 재시작 감지
container_last_seen{name="leafy-db"}
```

---

## Llama 모델 다운로드

```bash
docker exec -it ollama ollama pull llama3.1:8b
```

> ⚠️ 약 5GB, 시간이 걸립니다.

---

## 공격 시나리오 실행

```bash
# 라이브러리 설치
pip3 install docker psycopg2-binary rich

# 시나리오 폴더 이동
cd scenarios/
```

### 시나리오 1-A — CPU 고갈

```bash
python3 category1_infra/cpu_stress.py
```

Prometheus에서 확인:
```promql
rate(container_cpu_usage_seconds_total{name="leafy-db"}[1m])
```

### 시나리오 1-B — 메모리 누수 (재시작 반복)

```bash
python3 category1_infra/memory_leak.py
```

Prometheus에서 확인:
```promql
container_last_seen{name="leafy-db"}
```

### 시나리오 2-D — DB 브루트포스

```bash
python3 category2_security/brute_force.py
```

### 시나리오 2-A — 시크릿 탈취

```bash
python3 category2_security/secret_dump.py
```

> 모든 시나리오 결과는 `scenarios/logs/anomaly_log.json`에 기록됩니다.

---

## 발표용 CLI 데모

마인크래프트 테마의 AIOps 시나리오 데모 스크립트

```bash
python3 scenarios/cli_demo.py
```

**흐름:**
```
🌸 벚꽃 파티클 (평상시)
→ 크리퍼 접근 (it's coming...)
→ ⚠ ATTACK DETECTED
→ 데이터 수집 스피너
→ LLM 분석 타이핑
→ 자동 조치 실행
→ 💥 컨테이너 폭발
→ 👁 히로빈 등장 (DANGEROUS!!!!!)
→ ✅ 격리 완료 + 시스템 정상화
```

---

## 팀원

| 이름 | 역할 |
|---|---|
| 권준희 | 인프라 & 자동화 엔지니어 |
| 윤기찬 | AI & 데이터 분석 엔지니어 |

---

## 네트워크 구성

```
leafy-net  →  Leafy 서비스 (Frontend, Backend, DB)
mgmt-net   →  AIOps 관리망 (Prometheus, Loki, Pipeline, LLM)
```

외부 공격자는 leafy-net만 접근 가능하며, mgmt-net은 보호됩니다.
