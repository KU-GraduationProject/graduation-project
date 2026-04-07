graduation-project/
├── README.md
├── docker-compose.yml          # 전체 스택 통합 실행
│
├── leafy/                      # 모니터링 대상 서비스 (leafy-net)
│   ├── db/                     # PostgreSQL
│   │   └── init.sql
│   └── fluentd/                # 로그 수집기 (직접 빌드)
│       ├── Dockerfile
│       └── fluent.conf
│
├── monitoring/                 # 수집/저장 레이어 (mgmt-net)
│   ├── prometheus/
│   │   ├── prometheus.yml
│   │   └── rules/
│   │       └── alert.rules.yml # AlertManager 룰
│   ├── alertmanager/
│   │   └── alertmanager.yml
│   ├── loki/
│   │   └── loki-config.yml
│   └── grafana/
│       └── provisioning/
│           └── datasources/
│               └── datasources.yml
│
└── aiops/                      # AIOps 핵심 엔진 (mgmt-net)
    ├── pipeline/               # Pipeline 모듈
    │   ├── Dockerfile
    │   ├── main.py             # FastAPI 진입점
    │   ├── config.py
    │   ├── requirements.txt
    │   ├── collector/
    │   │   ├── __init__.py
    │   │   ├── metrics.py      # Prometheus 데이터 수집
    │   │   └── logs.py         # Loki 데이터 수집
    │   └── prompt/
    │       ├── __init__.py
    │       ├── builder.py      # 프롬프트 조립 및 LLM 시스템/유저 프롬프트
    │       └── schemas/
    │           ├── __init__.py
    │           └── llm_output.py  # Pydantic LLM 출력 스키마
    └── remediation/            # Remediation Agent
        ├── Dockerfile
        ├── main.py             # FastAPI 진입점 + 분기 로직 (자동 / 승인)
        ├── requirements.txt
        └── actions/
            ├── __init__.py
            ├── container.py    # 컨테이너 재시작/격리
            └── notify.py       # 알림 (승인 요청 / alert only)
