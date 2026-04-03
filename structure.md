graduation-project/
├── README.md
├── docker-compose.yml              # 전체 스택 통합 실행
├── docker-compose.dev.yml          # 개발용 오버라이드 (포트 오픈 등)
│
├── leafy/                          # 모니터링 대상 서비스 (leafy-net)
│   │                               # ※ frontend/backend는 Docker Hub 이미지 사용
│   │                               #   gicks/leafy-frontend:latest
│   │                               #   gicks/leafy-backend:latest
│   ├── db/                         # PostgreSQL
│   │   └── init.sql
│   └── fluentd/                    # 로그 수집기 (직접 빌드)
│
├── monitoring/                     # 수집/저장 레이어 (mgmt-net)
│   ├── prometheus/
│   │   ├── prometheus.yml
│   │   └── rules/
│   │       └── alert.rules.yml     # AlertManager 룰 (느슨한 임계값)
│   ├── alertmanager/
│   │   └── alertmanager.yml
│   ├── loki/
│   │   └── loki-config.yml
│   └── grafana/
│       ├── provisioning/
│       │   ├── datasources/
│       │   └── dashboards/
│       └── dashboards/
│           └── aiops-overview.json
│
├── aiops/                          # AIOps 핵심 엔진 (mgmt-net)
│   ├── pipeline/                   # Pipeline 모듈
│   │   ├── Dockerfile
│   │   ├── main.py                 # FastAPI 진입점
│   │   ├── requirements.txt
│   │   ├── config.py
│   │   ├── collector/
│   │   │   ├── __init__.py
│   │   │   ├── metrics.py          # Prometheus 데이터 수집
│   │   │   └── logs.py             # Loki 데이터 수집
│   │   ├── prompt/
│   │   │   ├── __init__.py
│   │   │   ├── builder.py          # 프롬프트 조립
│   │   │   └── templates/
│   │   │       ├── rca_system.txt  # LLM 시스템 프롬프트
│   │   │       └── rca_user.j2     # Jinja2 유저 프롬프트 템플릿
│   │   └── schemas/
│   │       └── llm_output.py       # Pydantic LLM 출력 스키마
│   │
│   ├── llm/                        # Ollama 설정
│   │   └── Modelfile               # Llama-3.1-8B 커스텀 설정
│   │
│   └── remediation/                # Remediation Agent
│       ├── Dockerfile
│       ├── main.py
│       ├── requirements.txt
│       ├── agent.py                # 분기 로직 (자동 / 승인)
│       └── actions/
│           ├── __init__.py
│           ├── container.py        # 컨테이너 재시작/격리
│           └── notify.py           # Slack 알림
│
├── scenarios/                      # 장애/공격 시나리오 스크립트
│   ├── category1_infra/            # 인프라 장애
│   │   ├── cpu_stress.sh
│   │   ├── memory_leak.sh
│   │   └── disk_fill.sh
│   └── category2_security/         # 보안 위협
│       ├── port_scan.sh
│       ├── slowloris.py
│       └── brute_force.sh
│
├── tests/
│   ├── unit/
│   └── e2e/
│       └── test_rca_flow.py        # 탐지→분석→조치 E2E 테스트
│
└── docs/
    ├── architecture.md
    ├── scenarios.md
    └── prompt-engineering.md
