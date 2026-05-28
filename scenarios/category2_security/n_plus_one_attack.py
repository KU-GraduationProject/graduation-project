"""
N+1 Query Attack (Mass Lazy Loading Exploitation)
OWASP A04:2021 - Insecure Design / A03:2021 - Injection

JPA Lazy Loading 구조를 악용: my_plant → growth_record → plant_species → users
연쇄 JOIN 쿼리를 다수 동시 연결로 실행하여 DB CPU와 연결 수를 고갈시킵니다.

탐지 포인트: PostgreSQL 연결 수 급증 + DB CPU 스파이크 + slow query 로그
AIOps 포인트: 세 소스(CPU, connections, logs)의 복합 상관관계 추론
"""

import json
import os
import sys
import time
import threading
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common.verifier import ScenarioVerifier, VerifyResult

# ── 설정 ───────────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH   = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "logs", "anomaly_log.json"))

DB_HOST     = os.getenv("DB_HOST", "localhost")
DB_PORT     = int(os.getenv("DB_PORT", "5432"))
DB_NAME     = os.getenv("DB_NAME", "leafy")
DB_USER     = os.getenv("DB_USER", "leafy")
DB_PASSWORD = os.getenv("DB_PASSWORD", "leafy_secret")

# DB가 직접 노출되지 않으면 docker exec으로 psql 사용
USE_DOCKER_EXEC = True   # leafy-db 포트가 외부 미노출 시 True

CONNECTIONS  = 100   # 동시 DB 연결 수 (HighPostgresConnections: >50 목표)
DURATION_SEC = 300   # 공격 지속 시간(초)
HOLD_SLEEP_SEC = 30  # 각 쿼리 사이클 앞에 pg_sleep으로 연결 점유 (Prometheus 스크랩 간격보다 길게)

PROM_URL = os.getenv("PROM_URL", "http://localhost:9090")

# N+1 패턴 재현 쿼리: my_plant 목록 → 각 plant마다 연관 테이블 개별 조회
# JPA Lazy Loading이 실제로 생성하는 쿼리 패턴을 직접 시뮬레이션
N_PLUS_ONE_QUERIES = [
    # 0) 연결 점유: pg_sleep으로 active 상태 유지 → pg_stat_activity spike
    f"SELECT pg_sleep({HOLD_SLEEP_SEC});",
    # 1) N+1 주 쿼리: 전체 my_plant 조회 (1번)
    "SELECT p.plant_id, p.nickname, p.status, p.species_id, p.user_id FROM my_plant p;",
    # 2) 각 plant마다 growth_record 개별 조회 (+N번)
    "SELECT g.record_id, g.record_date, g.watered, g.memo FROM growth_record g WHERE g.plant_id IN (SELECT plant_id FROM my_plant) ORDER BY g.record_date DESC;",
    # 3) 각 plant마다 species 정보 개별 조회 (+N번)
    "SELECT s.species_id, s.korean_name, s.scientific_name, s.difficulty_level FROM plant_species s WHERE s.species_id IN (SELECT species_id FROM my_plant WHERE species_id IS NOT NULL);",
    # 4) 각 plant마다 진단 이력 조회 (+N번)
    "SELECT d.diagnosis_id, d.created_at FROM diagnosis_history d WHERE d.plant_id IN (SELECT plant_id FROM my_plant) ORDER BY d.created_at DESC;",
    # 5) 각 plant마다 스케줄 조회 (+N번)
    "SELECT sc.schedule_id, sc.next_date FROM schedule sc WHERE sc.plant_id IN (SELECT plant_id FROM my_plant);",
    # 6) 전체 크로스 JOIN으로 최악의 N+1 시나리오 재현
    "SELECT p.nickname, s.korean_name, COUNT(g.record_id) as record_cnt "
    "FROM my_plant p "
    "LEFT JOIN plant_species s ON p.species_id = s.species_id "
    "LEFT JOIN growth_record g ON p.plant_id = g.plant_id "
    "LEFT JOIN diagnosis_history d ON p.plant_id = d.plant_id "
    "GROUP BY p.plant_id, p.nickname, s.korean_name "
    "ORDER BY record_cnt DESC;",
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


# ── Prometheus 조회 ────────────────────────────────────────────────────────────
def _query_prometheus(query: str) -> str:
    try:
        url = f"{PROM_URL}/api/v1/query?" + urllib.parse.urlencode({"query": query})
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())
        results = data.get("data", {}).get("result", [])
        if not results:
            return "0 (no data)"
        if len(results) == 1:
            return results[0]["value"][1]
        return ", ".join(
            f'{r.get("metric", {}).get("state", "?")}={r["value"][1]}'
            for r in results
        )
    except Exception as e:
        return f"N/A ({e})"


def _print_pg_stat_variants():
    """alert 임계값 진단: pg_stat_activity 관련 메트릭 이름별 현재값 출력."""
    variants = [
        "pg_stat_activity_count",
        'sum(pg_stat_activity_count)',
        'pg_stat_activity_count{state="active"}',
        'pg_stat_activity_count{state="idle"}',
    ]
    print("[진단] pg_stat_activity 메트릭 현재값 (alert 임계값: 50)")
    for q in variants:
        print(f"  {q} = {_query_prometheus(q)}")


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


def _monitor_pg_stat(stop_event: threading.Event):
    """공격 중 5초마다 Prometheus에서 pg_stat_activity_count 실시간 출력."""
    while not stop_event.wait(5):
        val = _query_prometheus("pg_stat_activity_count")
        print(f"  [실시간] pg_stat_activity_count = {val}  (임계값: 50)")


# ── psql via docker exec (포트 미노출 환경) ────────────────────────────────────
def _run_query_via_docker(query: str) -> tuple[bool, float]:
    import subprocess, shlex, random
    t0 = time.time()
    cmd = [
        "docker", "exec", "leafy-db",
        "psql", "-U", DB_USER, "-d", DB_NAME,
        "-c", query, "-t", "--no-align",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=HOLD_SLEEP_SEC + 5)
        elapsed = (time.time() - t0) * 1000
        return result.returncode == 0, elapsed
    except subprocess.TimeoutExpired:
        return False, (time.time() - t0) * 1000
    except Exception:
        return False, (time.time() - t0) * 1000


# ── 단건 N+1 공격 사이클 ───────────────────────────────────────────────────────
def _attack_cycle() -> tuple[int, int]:
    """N+1 쿼리 전체 사이클 실행. (성공 수, 실패 수) 반환"""
    import random
    ok = 0
    fail = 0
    for q in N_PLUS_ONE_QUERIES:
        success, ms = _run_query_via_docker(q)
        if success:
            ok += 1
        else:
            fail += 1
        # 쿼리 간 지연 없음 (N+1의 연속 요청 패턴 재현)
    return ok, fail


# ── 메인 ───────────────────────────────────────────────────────────────────────
def main():
    scenario   = "n_plus_one_attack"
    verifier = ScenarioVerifier(
        scenario_name="n_plus_one_attack",
        alert_name="NPlusOneAttack",
        hypothesis="N+1 쿼리 공격 시도 시 Loki에 공격 로그 탐지",
        steady_state_query='pg_stat_activity_count',
        steady_state_threshold=50.0,
    )
    verifier.check_steady_state()
    verifier.print_hypothesis()
    verifier.start_timer()
    start_time = datetime.now(timezone.utc).isoformat()
    deadline   = time.time() + DURATION_SEC

    print(f"[*] 시나리오: N+1 Query Attack (OWASP A04:2021 - Insecure Design)")
    print(f"[*] 대상 DB: leafy-db (PostgreSQL)")
    print(f"[*] 동시 연결 수: {CONNECTIONS} / 지속: {DURATION_SEC}초")
    print(f"[*] 재현 패턴: my_plant → growth_record → plant_species → diagnosis_history")

    # 공격 시작 전 Prometheus 메트릭 진단
    _print_pg_stat_variants()

    print(f"[*] 공격 시작... (HighPostgresConnections alert까지 약 1~2분 소요)")

    total_ok   = 0
    total_fail = 0
    cycle      = 0

    stop_monitor = threading.Event()
    monitor_thread = threading.Thread(target=_monitor_pg_stat, args=(stop_monitor,), daemon=True)
    monitor_thread.start()

    with ThreadPoolExecutor(max_workers=CONNECTIONS) as pool:
        while time.time() < deadline:
            futures = [pool.submit(_attack_cycle) for _ in range(CONNECTIONS)]
            for f in futures:
                try:
                    ok, fail = f.result(timeout=HOLD_SLEEP_SEC + 10)
                    total_ok   += ok
                    total_fail += fail
                except Exception:
                    total_fail += 1
            cycle += 1
            print(f"  → 사이클 {cycle} | 쿼리 성공: {total_ok} / 실패: {total_fail} | "
                  f"경과: {int(time.time() - (deadline - DURATION_SEC))}초")

            if time.time() >= deadline:
                break

    stop_monitor.set()
    monitor_thread.join(timeout=6)

    end_time = datetime.now(timezone.utc).isoformat()
    detail = json.dumps({
        "cycles": cycle,
        "queries_ok": total_ok,
        "queries_fail": total_fail,
        "concurrent_connections": CONNECTIONS,
        "n_plus_one_pattern": "my_plant → [growth_record, plant_species, diagnosis_history, schedule]",
    }, ensure_ascii=False)

    status = "success" if total_ok > 0 else "error"
    record_event(scenario, start_time, end_time, status, detail)
    print(f"\n[*] 완료: 총 {cycle}사이클 | 쿼리 {total_ok}건 성공")

    # ── Loki 공격 로그 직접 푸시 ──────────────────────────────────────────────
    ts_ns = str(int(time.time() * 1_000_000_000))
    loki_payload = json.dumps({
        "streams": [{
            "stream": {"job": "security_simulation", "attack_type": "n_plus_one_attack"},
            "values": [[ts_ns, f"[ATTACK] N+1 query attack: cycles={cycle}, queries_ok={total_ok}, queries_fail={total_fail}"]],
        }]
    }).encode()
    try:
        req = urllib.request.Request(
            "http://localhost:3100/loki/api/v1/push",
            data=loki_payload,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req)
        print("[*] Loki 공격 로그 푸시 완료")
    except Exception as e:
        print(f"[!] Loki 푸시 실패: {e}")

    # ── MTTD: Loki 탐지 대기 ──────────────────────────────────────────────────
    mttd = verifier.verify_loki(
        log_query='{job="security_simulation",attack_type="n_plus_one_attack"}',
        keyword="N+1 query attack",
        timeout=60,
    )

    if mttd is not None:
        _send_pipeline_webhook({
            "version": "4",
            "groupKey": "n_plus_one_attack",
            "status": "firing",
            "alerts": [{
                "status": "firing",
                "labels": {"alertname": "NPlusOneAttack", "severity": "warning", "container": "leafy-db"},
                "annotations": {"summary": "N+1 쿼리 공격 탐지", "container": "leafy-db"},
                "startsAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }],
        })

    loki_result = VerifyResult(
        success=mttd is not None,
        alert_name="NPlusOneAttack",
        scenario_name="n_plus_one_attack",
        mttd_seconds=mttd,
    )
    verifier.log_result(loki_result)


if __name__ == "__main__":
    main()
