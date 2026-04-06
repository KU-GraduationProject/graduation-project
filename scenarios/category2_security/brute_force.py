"""
category2_security/brute_force.py
───────────────────────────────────
psycopg2로 leafy-db에 반복 로그인 실패를 시도하는
브루트포스 공격 시뮬레이션.
시작/종료 시간 및 시도 결과를 anomaly_log.json에 기록한다.
"""

import json
import os
import sys
import time
from datetime import datetime, timezone

try:
    import psycopg2
except ImportError:
    print("[!] psycopg2 가 설치되지 않았습니다. pip install psycopg2-binary 후 재실행하세요.",
          file=sys.stderr)
    sys.exit(1)

# ── 설정 ───────────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH   = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "logs", "anomaly_log.json"))

DB_HOST    = os.environ.get("DB_HOST", "localhost")
DB_PORT    = int(os.environ.get("DB_PORT", 5432))
DB_NAME    = os.environ.get("DB_NAME", "leafy")

# 브루트포스에 사용할 (user, password) 후보 목록
CREDENTIALS = [
    ("leafy",    "wrongpassword"),
    ("postgres", "postgres"),
    ("admin",    "admin"),
    ("root",     "root"),
    ("leafy",    "leafy"),
    ("leafy",    "password"),
    ("leafy",    "123456"),
    ("leafy",    "leafy_secret"),   # 실제 비밀번호: 성공 케이스 포함
]

ATTEMPT_DELAY = 0.5   # 각 시도 사이 대기(초)


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
        "scenario": scenario,
        "category": "security",
        "start_time": start,
        "end_time":   end,
        "status":     status,
        "detail":     detail,
    })
    _save_log(records)
    print(f"[LOG] {scenario} | {status} | {start} → {end}")


# ── 단일 로그인 시도 ───────────────────────────────────────────────────────────
def try_login(user: str, password: str) -> dict:
    result = {"user": user, "password": "***", "success": False, "error": None}
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=user,
            password=password,
            connect_timeout=3,
        )
        conn.close()
        result["success"] = True
        print(f"  [+] 성공: user={user}")
    except psycopg2.OperationalError as e:
        msg = str(e).splitlines()[0]
        result["error"] = msg
        print(f"  [-] 실패: user={user} | {msg}")
    except Exception as e:
        result["error"] = str(e)
        print(f"  [!] 예외: user={user} | {e}")
    return result


# ── 메인 ───────────────────────────────────────────────────────────────────────
def main():
    scenario = "brute_force_db"

    print(f"[*] 시나리오 시작: {scenario}")
    print(f"[*] 대상 DB: {DB_HOST}:{DB_PORT}/{DB_NAME}")
    print(f"[*] 시도 횟수: {len(CREDENTIALS)}회")

    start_time = datetime.now(timezone.utc).isoformat()
    attempts = []
    success_count = 0

    for idx, (user, password) in enumerate(CREDENTIALS, 1):
        print(f"\n[{idx}/{len(CREDENTIALS)}] 시도: user={user}")
        result = try_login(user, password)
        attempts.append(result)
        if result["success"]:
            success_count += 1
        if idx < len(CREDENTIALS):
            time.sleep(ATTEMPT_DELAY)

    end_time = datetime.now(timezone.utc).isoformat()

    total   = len(CREDENTIALS)
    failed  = total - success_count
    status  = "success" if success_count > 0 else "all_failed"

    summary = {
        "total_attempts": total,
        "success":        success_count,
        "failed":         failed,
        "attempts":       attempts,
    }
    detail = json.dumps(summary, ensure_ascii=False)
    record_event(scenario, start_time, end_time, status, detail[:800])

    print(f"\n[*] 시나리오 종료: {scenario}")
    print(f"    총 {total}회 시도 | 성공 {success_count}회 | 실패 {failed}회")


if __name__ == "__main__":
    main()
