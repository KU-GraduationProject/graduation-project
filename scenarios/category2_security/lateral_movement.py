"""
Container Lateral Movement — Unauthorized DB Direct Access
시나리오 2-B

침해된 컨테이너가 정상 경로(frontend→backend→db)를 우회하여
leafy-net 내부에서 leafy-db:5432로 직접 접속을 시도한다.

정상 아키텍처에서 DB에 접근하는 유일한 경로는 leafy-backend 컨테이너이므로,
leafy-backend 이외의 소스 IP에서 오는 PostgreSQL 연결 시도는 이상 신호다.

탐지 소스:
  - Loki (container=leafy-db): connection from host "172.21.0.X" — X가 backend IP가 아님
  - Loki: FATAL: password authentication failed (for user "attacker" etc.)
  - Prometheus: pg_stat_activity_count 소폭 증가

AIOps 포인트: 소스 IP 기반으로 "정상 backend 연결"과 "비인가 lateral move"를 구별
"""

"""
Container Lateral Movement — Unauthorized DB Direct Access
시나리오 2-B

분류: MITRE ATT&CK TA0008 (Lateral Movement)
목표 Alert: UnauthorizedDBAccess (Loki 로그 기반 탐지)
Steady State: leafy-db 접속은 leafy-backend IP에서만 발생
가설: 프론트엔드 컨테이너에서 DB로 직접 연결 시도 시, Loki 탐지 룰에 의해 2분 내 발화
성공 기준: 프로젝트 내부 목표 MTTD < 2분, 정상/비정상 소스 IP 구분 성공

침해된 컨테이너가 정상 경로(frontend→backend→db)를 우회하여...
"""

import json
import os
import subprocess
import time
from datetime import datetime, timezone

# ── 설정 ───────────────────────────────────────────────────────────────────────
SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
LOG_PATH      = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "logs", "anomaly_log.json"))

# 침해 컨테이너가 붙을 네트워크 (Docker Compose 프로젝트명_네트워크명)
LEAFY_NETWORK = os.getenv("LEAFY_NETWORK", "graduation-project_leafy-net")
DB_HOST       = os.getenv("DB_HOST_INTERNAL", "leafy-db")  # Docker 내부 DNS
DB_NAME       = os.getenv("DB_NAME", "leafy")

ATTACKER_NAME = "leafy-attacker-frontend"   # 침해된 프론트엔드를 모사하는 컨테이너 이름
POSTGRES_IMAGE = "postgres:15-alpine"

DURATION_SEC  = 90     # 공격 지속 시간(초)
ATTEMPT_COUNT = 200    # 총 접속 시도 횟수

# 공격자가 시도할 자격증명
ATTACK_CREDENTIALS = [
    ("attacker",  "password"),
    ("admin",     "admin"),
    ("leafy",     "wrongpass"),
    ("root",      "root"),
    ("postgres",  "postgres"),
    ("leafy",     "leafy_secret"),   # 실제 비밀번호 추측 시도
]

# DB 정보 수집 시도 명령 (인증 성공 시 공격자가 실행할 법한 쿼리)
RECON_QUERIES = [
    "SELECT current_user, current_database(), version();",
    "SELECT table_name FROM information_schema.tables WHERE table_schema='public';",
    "SELECT count(*) FROM my_plant;",
]


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


# ── Pipeline 웹훅 전송 ─────────────────────────────────────────────────────────
def _send_pipeline_webhook(payload: dict) -> bool:
    import urllib.request, json
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            "http://localhost:8000/webhook/alert",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=5)
        return True
    except Exception as e:
        print(f"[!] Pipeline 웹훅 전송 실패: {e}")
        return False


# ── 컨테이너 정리 ──────────────────────────────────────────────────────────────
def _cleanup_attacker():
    subprocess.run(
        ["docker", "rm", "-f", ATTACKER_NAME],
        capture_output=True,
    )


# ── 공격 스크립트 생성 (컨테이너 내부에서 실행) ────────────────────────────────
def _build_attack_script() -> str:
    """
    침해 컨테이너 내부에서 실행될 bash 스크립트.
    여러 자격증명으로 반복 접속을 시도하고, 성공 시 정찰 쿼리를 실행한다.
    """
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

    creds_block  = "\n".join(cred_lines)
    recon_block  = "\n".join(recon_lines)

    return f"""#!/bin/sh
echo "[attacker] 컨테이너 시작: $(hostname) / $(cat /etc/hosts | grep $(hostname) | awk '{{print $1}}')"
echo "[attacker] 타겟: {DB_HOST}:5432"

attempt=0
max_attempts={ATTEMPT_COUNT}

while [ $attempt -lt $max_attempts ]; do
  attempt=$((attempt + 1))
  echo "[attacker] 시도 $attempt / $max_attempts"
{creds_block}
  sleep 0.3
done

echo "[attacker] 정찰 쿼리 시도..."
{recon_block}

echo "[attacker] 완료"
"""


# ── 메인 ───────────────────────────────────────────────────────────────────────
def main():
    scenario   = "lateral_movement"
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from common.verifier import ScenarioVerifier, VerifyResult
    verifier = ScenarioVerifier(
        scenario_name="lateral_movement",
        alert_name="LateralMovement",
        hypothesis="비인가 DB 직접 접속 시 Loki에 인증 실패 로그 탐지",
    )
    verifier.check_steady_state()
    verifier.print_hypothesis()
    verifier.start_timer()
    start_time = datetime.now(timezone.utc).isoformat()

    print(f"[*] 시나리오: Container Lateral Movement (비인가 DB 직접 접속)")
    print(f"[*] 공격 컨테이너: {ATTACKER_NAME} (leafy-net 내부망 침투)")
    print(f"[*] 타겟: {DB_HOST}:5432 직접 접속 (backend 우회)")
    print(f"[*] 탐지 포인트: Loki(leafy-db) 비정상 소스 IP + 인증 실패 패턴")
    print(f"[*] 사전 정리 중...")

    _cleanup_attacker()

    attack_script = _build_attack_script()

    print(f"[*] 공격 컨테이너 기동: {ATTACKER_NAME}")
    print(f"[*] 네트워크: {LEAFY_NETWORK}")
    print(f"[*] 공격 시작 (최대 {DURATION_SEC}초)...\n")

    cmd = [
        "docker", "run",
        "--rm",
        "--name", ATTACKER_NAME,
        "--network", LEAFY_NETWORK,
        POSTGRES_IMAGE,
        "sh", "-c", attack_script,
    ]

    result = None
    try:
        result = subprocess.run(
            cmd,
            capture_output=False,   # stdout을 터미널에 바로 출력
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
        "network": LEAFY_NETWORK,
        "target": f"{DB_HOST}:5432",
        "attempt_count": ATTEMPT_COUNT,
        "exit_code": exit_code,
        "credentials_tried": len(ATTACK_CREDENTIALS),
        "recon_queries": len(RECON_QUERIES),
        "note": (
            "정상 아키텍처에서 DB 접근은 leafy-backend만 허용. "
            "Loki에서 비정상 소스 IP 확인 필요."
        ),
    }, ensure_ascii=False)

    status = "success" if exit_code in (0, -1) else "error"
    record_event(scenario, start_time, end_time, status, detail)

    print(f"\n[*] 완료: exit_code={exit_code}")
    print(f"[*] Loki에서 확인: container=leafy-db, 키워드: 'authentication failed' or 'attacker'")
    print(f"[*] 비정상 소스 IP가 leafy-backend IP와 다르면 lateral movement 탐지 성공")
    print(f"[*] Grafana: http://localhost:3000")
    mttd = verifier.verify_loki(
        log_query='{container="leafy-db"}',
        keyword="authentication failed",
        timeout=180,
    )

    mtta = None
    if mttd is not None:
        sent = _send_pipeline_webhook({
            "version": "4",
            "groupKey": "lateral_movement",
            "status": "firing",
            "alerts": [{
                "status": "firing",
                "labels": {"alertname": "LateralMovement", "severity": "critical", "container": "leafy-db"},
                "annotations": {"summary": "컨테이너 간 횡적 이동 탐지", "container": "leafy-db"},
                "startsAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }],
        })
        if sent:
            print("[*] Pipeline 웹훅 전송 완료 (MTTA 측정 시작)")
            mtta = verifier.verify_mtta(timeout=180)

    loki_result = VerifyResult(
        success=mttd is not None,
        alert_name="LateralMovement",
        scenario_name="lateral_movement",
        mttd_seconds=mttd,
        mtta_seconds=mtta,
        slack_notified=mtta is not None,
    )
    verifier.log_result(loki_result)


if __name__ == "__main__":
    main()
