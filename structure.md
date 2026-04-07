# 프로젝트 구조

```
graduation-project/
├── README.md
├── docker-compose.yml
│
├── leafy/
│   ├── db/
│   │   └── init.sql
│   └── fluentd/
│       ├── Dockerfile
│       └── fluent.conf
│
├── monitoring/
│   ├── prometheus/
│   │   ├── prometheus.yml
│   │   └── rules/
│   │       └── alert.rules.yml
│   ├── alertmanager/
│   │   └── alertmanager.yml
│   ├── loki/
│   │   └── loki-config.yml
│   └── grafana/
│       └── provisioning/
│           └── datasources/
│               └── datasources.yml
│
└── aiops/
    ├── pipeline/
    │   ├── Dockerfile
    │   ├── main.py
    │   ├── config.py
    │   ├── requirements.txt
    │   ├── collector/
    │   │   ├── __init__.py
    │   │   ├── metrics.py
    │   │   └── logs.py
    │   └── prompt/
    │       ├── __init__.py
    │       ├── builder.py
    │       └── schemas/
    │           ├── __init__.py
    │           └── llm_output.py
    └── remediation/
        ├── Dockerfile
        ├── main.py
        ├── requirements.txt
        └── actions/
            ├── __init__.py
            ├── container.py
            └── notify.py
```

## 설명

| 디렉토리 | 설명 |
|---|---|
| `leafy/` | 모니터링 대상 서비스 (leafy-net) |
| `leafy/db/` | PostgreSQL 초기화 |
| `leafy/fluentd/` | 로그 수집기 (직접 빌드) |
| `monitoring/` | 수집/저장 레이어 (mgmt-net) |
| `monitoring/prometheus/` | 메트릭 수집 및 AlertManager 룰 |
| `monitoring/alertmanager/` | 알림 라우팅 |
| `monitoring/loki/` | 로그 저장 |
| `monitoring/grafana/` | 대시보드 시각화 |
| `aiops/` | AIOps 핵심 엔진 (mgmt-net) |
| `aiops/pipeline/` | FastAPI 진입점 + Prometheus/Loki 수집 + LLM 프롬프트 |
| `aiops/pipeline/collector/` | metrics.py (Prometheus), logs.py (Loki) 수집 |
| `aiops/pipeline/prompt/` | 프롬프트 조립 및 LLM 출력 스키마 |
| `aiops/remediation/` | Remediation Agent — 자동/승인 분기 대응 |
| `aiops/remediation/actions/` | 컨테이너 재시작/격리, 알림 발송 |
