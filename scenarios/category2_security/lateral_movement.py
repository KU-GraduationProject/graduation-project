"""
Container Lateral Movement — Unauthorized DB Direct Access
시나리오 2-B

[실제 사고 모티브]
- 2024년 BlackCat 랜섬웨어: 훔친 자격증명으로 내부망 횡적 이동
- 2023년 MOVEit 공격: SQL 인젝션 초기 침투 → lateral movement
- MITRE ATT&CK TA0008 Lateral Movement

[실제와의 차이]
- 실제: 취약점 악용 → 컨테이너 침투(초기 침해) → 내부망 피벗
- 우리: 초기 침해 단계 생략, 침해된 컨테이너를 직접 생성해서
        내부망 DB 직접 접속 시도 시뮬레이션

[구현 의도]
- MITRE ATT&CK TA0008의 핵심 행위인
  "정상 경로 우회(frontend→backend→db) + 내부망 직접 접속"을 재현
- 실제 침투 테스트에서도 전제 단계를 가정하고 시뮬레이션하는 방식 사용

[실제 서비스 방어 우회 근거]
- PostgreSQL은 기본적으로 반복 인증 실패 차단 기능 없음
- fail2ban 미설치 → IP 차단 없음
- Docker 네트워크 격리는 존재하지만
  Docker 소켓 접근 권한이 있으면 어느 네트워크에든 컨테이너 연결 가능
  (실제 컨테이너 탈출 이후 시나리오)

탐지 포인트: UnauthorizedDBAccess (Loki Ruler → Alertmanager → Pipeline)
탐지 조건:  leafy-db 로그에 "authentication failed" 2분 내 3회 초과
AIOps 포인트: 비정상 소스 IP + 인증 실패 패턴 → LLM 분석 → ISOLATE 권고
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common.verifier import ScenarioVerifier, VerifyResult

# ── 설정 ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
LOG_PATH      = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "logs", "anomaly_log.json"))

LEAFY_NETWORK  = os.getenv("LEAFY_NETWORK", "graduation-project_leafy-net")
DB_HOST        = os.getenv("DB_HOST_INTERNAL", "leafy-db")
DB_NAME        = os.getenv("DB_NAME", "leafy")

ATTACKER_NAME  = "leafy-attacker-frontend"
POSTGRES_IMAGE = "postgres:15-alpine"

DURATION_SEC   = 300
ATTEMPT_COUNT  = 200

ATTACK_CREDENTIALS = [
    ("attacker", "password"),
    ("admin",    "admin"),
    ("leafy",    "wrongpass"),
    ("root",     "root"),
    ("postgres", "postgres"),
    ("leafy",    "leafy_secret"),
]

RECON_QUERIES = [
    "SELECT current_user, current_database(), version();",
    "SELECT table_name FROM information_schema.tables WHERE table_schema='public';",
    "SELECT count(*) FROM my_plant;",
]


# ── 로그 유틸 ─────────────────────────────────────────────────────────────────
def _load_log() -> list:
    if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) > 0:
        with open(LOG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

def _save_log(records: list) -> None:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)

def record_event(scenario, start, end, status, detail=""):
    records = _load_log()
    records.append({
        "scenario": scenario, "category": "security",
        "start_time": start, "end_time": end,
        "status": status, "detail": detail,
    })
    _save_log(records)
    print(f"[LOG] {scenario} | {status} | {start} → {end}")


# ── 컨테이너 정리 ─────────────────────────────────────────────────────────────
def _cleanup_attacker():
    subprocess.run(
        ["docker", "rm", "-f", ATTACKER_NAME],
        capture_output=True,
    )


# ── 공격 스크립트 생성 ────────────────────────────────────────────────────────
def _build_attack_script() -> str:
    cred_lines = []
    for user, pwd in ATTACK_CREDENTIALS:
        cred_lines.append(
            f'  PGPASSWORD="{pwd}" psql -h {DB_HOST} -U {user} -d {DB_NAME} '
            f'-c "SELECT 1" -t --no-align 2>&1 || true'
        )

    recon_lines = []
    for q in RECON_QUERIES:
        recon_lines.append(
            f'PGPASSWORD="leafy_secret" psql -h {DB_HOST} -U leafy -d {DB_NAME} '
            f'-c "{q}" 2>&1 || true'
        )

    creds_block = "\n".join(cred_lines)
    recon_block = "\n".join(recon_lines)

    return f"""#!/bin/sh
echo "[attacker] 컨테이너 시작: $(hostname)"
echo "[attacker] 타겟: {DB_HOST}:5432 (정상 경로 frontend→backend→db 우회)"

attempt=0
max_attempts={ATTEMPT_COUNT}

while [ $attempt -lt $max_attempts ]; do
  attempt=$((attempt + 1))
  echo "[attacker] 시도 $attempt / $max_attempts"
{creds_block}
  sleep 0.3
done

echo "[attacker] 정찰 쿼리 시도 (인증 성공 시 실행될 법한 쿼리)..."
{recon_block}

echo "[attacker] 완료"
"""


# ── 메인 ──────────────────────────────────────────────────────────────────────
def main():
    scenario = "lateral_movement"

    # ── 1단계: Verifier 초기화 ────────────────────────────────────────────────
    verifier = ScenarioVerifier(
        scenario_name="lateral_movement",
        alert_name="UnauthorizedDBAccess",
        hypothesis=(
            "침해 컨테이너가 leafy-net 내부에서 DB 직접 접속 시도 시 "
            "Loki UnauthorizedDBAccess Alert 발화"
        ),
    )

    verifier.check_steady_state()
    verifier.print_hypothesis()
    verifier.wait_for_alert_inactive(timeout=60, poll_interval=5)
    verifier.start_timer()

    # ── 2단계: 공격 준비 ──────────────────────────────────────────────────────
    print(f"\n[*] 시나리오: Container Lateral Movement")
    print(f"[*] MITRE ATT&CK: TA0008 Lateral Movement")
    print(f"[*] 공격 컨테이너: {ATTACKER_NAME}")
    print(f"[*] 타겟: {DB_HOST}:5432 (frontend→backend→db 정상 경로 우회)")
    print(f"[*] 시도 횟수: {ATTEMPT_COUNT}회 / 자격증명 종류: {len(ATTACK_CREDENTIALS)}개")
    print(f"[*] 사전 정리 중...")

    _cleanup_attacker()
    start_time = datetime.now(timezone.utc).isoformat()
    attack_script = _build_attack_script()

    # ── 3단계: 공격 컨테이너 실행 ─────────────────────────────────────────────
    print(f"\n[*] 공격 컨테이너 기동...")
    print(f"[*] 네트워크: {LEAFY_NETWORK}")

    cmd = [
        "docker", "run",
        "--rm",
        "--name", ATTACKER_NAME,
        "--network", LEAFY_NETWORK,
        POSTGRES_IMAGE,
        "sh", "-c", attack_script,
    ]

    exit_code = 0
    try:
        result = subprocess.run(
            cmd,
            capture_output=False,
            timeout=DURATION_SEC + 30,
        )
        exit_code = result.returncode
    except subprocess.TimeoutExpired:
        print(f"\n[*] 타임아웃 — 컨테이너 강제 종료")
        _cleanup_attacker()
        exit_code = -1
    except KeyboardInterrupt:
        print(f"\n[*] 사용자 중단 — 컨테이너 정리 중...")
        _cleanup_attacker()
        exit_code = -2

    end_time = datetime.now(timezone.utc).isoformat()

    detail = json.dumps({
        "attacker_container": ATTACKER_NAME,
        "network":            LEAFY_NETWORK,
        "target":             f"{DB_HOST}:5432",
        "attempt_count":      ATTEMPT_COUNT,
        "credentials_tried":  len(ATTACK_CREDENTIALS),
        "recon_queries":      len(RECON_QUERIES),
        "exit_code":          exit_code,
        "note": (
            "정상 경로: frontend→backend→db. "
            "비정상: 공격 컨테이너→db 직접 접속. "
            "Loki Ruler가 authentication failed 3회 초과 시 "
            "UnauthorizedDBAccess Alert 발화 → Alertmanager → Pipeline 자동 전송."
        ),
    }, ensure_ascii=False)

    status = "success" if exit_code in (0, -1) else "error"
    record_event(scenario, start_time, end_time, status, detail)

    print(f"\n[*] 공격 완료: exit_code={exit_code}")
    print(f"[*] Loki 확인: {{container=\"leafy-db\"}} |= \"authentication failed\"")
    print(f"[*] Grafana: http://localhost:3000")

    # ── 4단계: Loki 로그 기반 MTTD 측정 ──────────────────────────────────────
    # Loki Ruler → Alertmanager → Pipeline 웹훅은 자동 전송됨
    # verify_loki()는 로그 키워드 감지 시점으로 MTTD 측정
    print("\n[*] Loki 'authentication failed' 탐지 대기 중...")
    mttd = verifier.verify_loki(
        log_query='{container="leafy-db"}',
        keyword="authentication failed",
        timeout=180,
    )

    # ── 5단계: 결과 기록 ──────────────────────────────────────────────────────
    result = VerifyResult(
        success=mttd is not None,
        alert_name="UnauthorizedDBAccess",
        scenario_name="lateral_movement",
        mttd_seconds=mttd,
    )
    verifier.log_result(result)


if __name__ == "__main__":
    main()