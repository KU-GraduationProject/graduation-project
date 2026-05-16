"""
DB Brute Force Attack (Internal Network)
시나리오 2-D

공격 전략 2계층:
  [1] docker exec pg_sleep: 70개 동시 연결 점유 → HighPostgresConnections (>50) alert
  [2] 임시 공격 컨테이너 (TCP): leafy-db:5432 TCP 접속으로 wrong password 반복
      → PostgreSQL 로그에 'FATAL: password authentication failed' 기록 → Loki 수집

탐지 소스:
  - Prometheus: pg_stat_activity_count > 50 (HighPostgresConnections)
  - Loki (container=leafy-db): 반복 인증 실패 패턴

AIOps 포인트: 단순 연결 풀 고갈(N+1)과 반복 인증 실패(브루트포스)를
             Loki 에러 패턴으로 구별
"""

import json
import os
import random
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import sys
import threading
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common.verifier import ScenarioVerifier

# ── 설정 ───────────────────────────────────────────────────────────────────────
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
LOG_PATH     = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "logs", "anomaly_log.json"))

DB_CONTAINER   = os.getenv("DB_CONTAINER", "leafy-db")
DB_NAME        = os.getenv("DB_NAME", "leafy")
DB_USER        = os.getenv("DB_USER", "leafy")
LEAFY_NETWORK  = os.getenv("LEAFY_NETWORK", "graduation-project_leafy-net")
ATTACKER_NAME  = "leafy-brute-attacker"
POSTGRES_IMAGE = "postgres:15-alpine"

HOLD_WORKERS   = 70    # docker exec pg_sleep → pg_stat_activity spike
HOLD_SLEEP_SEC = 1     # 연결 유지 시간
DURATION_SEC   = 120   # 전체 공격 지속 시간(초)
ATTACK_COUNT   = 300   # TCP 인증 실패 시도 횟수


# ── 로그 유틸 ──────────────────────────────────────────────────────────────────
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


# ── 컨테이너 정리 ──────────────────────────────────────────────────────────────
def _cleanup():
    subprocess.run(["docker", "rm", "-f", ATTACKER_NAME], capture_output=True)


# ── 연결 점유 워커 (docker exec, trust auth, pg_sleep) ─────────────────────────
def _hold_connection() -> bool:
    cmd = [
        "docker", "exec", DB_CONTAINER,
        "psql", "-U", DB_USER, "-d", DB_NAME,
        "-c", f"SELECT pg_sleep({HOLD_SLEEP_SEC})",
        "-t", "--no-align",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=HOLD_SLEEP_SEC + 5)
        return r.returncode == 0
    except Exception:
        return False


# ── TCP 인증 실패 공격 (임시 컨테이너, scram-sha-256 auth) ─────────────────────
def _run_tcp_attack():
    """
    임시 컨테이너를 leafy-net에 띄워 TCP로 leafy-db:5432 인증 실패 반복.
    docker exec (unix socket, trust auth)와 달리 TCP 연결은 scram-sha-256 인증 적용.
    PostgreSQL 로그: FATAL: password authentication failed for user "leafy"
    """
    wrong_passwords = [
        "admin", "admin123", "password", "qwerty", "123456",
        "wrongpass", "leafy", "leafy123", "secret", "postgres",
        "letmein", "passw0rd", "12345678", "abc123", "monkey",
    ]

    attempts = " ".join([
        f'PGPASSWORD="{p}" psql -h {DB_CONTAINER} -U {DB_USER} -d {DB_NAME} '
        f'-c "SELECT 1" -t --no-align 2>&1 || true;'
        for p in wrong_passwords
    ])

    script = f"""#!/bin/sh
echo "[brute-attacker] TCP brute force 시작: {DB_CONTAINER}:5432"
attempt=0
while [ $attempt -lt {ATTACK_COUNT} ]; do
  attempt=$((attempt+1))
  {attempts}
  sleep 0.2
done
echo "[brute-attacker] 완료: $attempt 회 시도"
"""

    cmd = [
        "docker", "run", "--rm",
        "--name", ATTACKER_NAME,
        "--network", LEAFY_NETWORK,
        POSTGRES_IMAGE,
        "sh", "-c", script,
    ]
    try:
        subprocess.run(cmd, capture_output=True, timeout=DURATION_SEC + 30)
    except Exception:
        pass
    finally:
        _cleanup()


# ── 메인 ───────────────────────────────────────────────────────────────────────
def main():
    scenario   = "db_bruteforce"
    verifier = ScenarioVerifier(
        scenario_name="db_bruteforce",
        alert_name="HighPostgresConnections",
        hypothesis="DB 브루트포스 공격 중 HighPostgresConnections FIRING",
        steady_state_query='pg_stat_activity_count',
        steady_state_threshold=50.0,
    )
    verifier.check_steady_state()
    verifier.print_hypothesis()
    verifier.check_repeat_interval()
    verifier.start_timer()
    start_time = datetime.now(timezone.utc).isoformat()
    deadline   = time.time() + DURATION_SEC

    print(f"[*] 시나리오: DB Brute Force (내부망 반복 인증 실패)")
    print(f"[*] 연결 점유 ({HOLD_WORKERS}×pg_sleep) → HighPostgresConnections (>50)")
    print(f"[*] TCP 인증 실패 ({ATTACK_COUNT}회) → Loki 'password authentication failed'")
    print(f"[*] 사전 정리...")
    _cleanup()

    # TCP 브루트포스 공격을 백그라운드 스레드로 실행
    attack_thread = threading.Thread(target=_run_tcp_attack, daemon=True)
    attack_thread.start()
    print(f"[*] TCP 공격 컨테이너 기동 중...")
    time.sleep(3)

    # 연결 점유 워커로 pg_stat_activity spike
    print(f"[*] 연결 점유 시작 ({HOLD_WORKERS}개 동시)...")
    total_holds = 0

    with ThreadPoolExecutor(max_workers=HOLD_WORKERS) as pool:
        while time.time() < deadline:
            futures = [pool.submit(_hold_connection) for _ in range(HOLD_WORKERS)]
            for f in futures:
                try:
                    if f.result(timeout=HOLD_SLEEP_SEC + 6):
                        total_holds += 1
                except Exception:
                    pass
            elapsed = int(time.time() - (deadline - DURATION_SEC))
            print(f"  → 연결 점유: {total_holds}회 | 경과: {elapsed}s / {DURATION_SEC}s")

    attack_thread.join(timeout=5)
    end_time = datetime.now(timezone.utc).isoformat()

    detail = json.dumps({
        "hold_connections": total_holds,
        "attack_count":     ATTACK_COUNT,
        "hold_workers":     HOLD_WORKERS,
        "network":          LEAFY_NETWORK,
        "note": "hold(docker exec pg_sleep) + TCP attack(임시 컨테이너, scram-sha-256)",
    }, ensure_ascii=False)

    record_event(scenario, start_time, end_time, "success", detail)
    result = verifier.verify(timeout=180)
    mtta = verifier.verify_mtta(timeout=180)
    result.mtta_seconds = mtta
    result.slack_notified = mtta is not None
    verifier.log_result(result)
    print(f"\n[*] 완료: 연결 점유 {total_holds}회")
    print(f"[*] Loki: container=leafy-db → 'password authentication failed'")
    print(f"[*] Prometheus: HighPostgresConnections alert")


if __name__ == "__main__":
    main()
