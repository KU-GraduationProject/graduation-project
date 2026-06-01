"""
SQL Injection Attempt Detection Scenario
OWASP A03:2021 - Injection / A05:2025 - Injection

[실제 사고 모티브]
- Verizon 2024 DBIR: SQL Injection 포함 웹 앱 공격이 전체 데이터 침해의 26%
- FBI/CISA 2024: SQLi를 "용납할 수 없는 결함"으로 공식 명명
- CVE-2024-49203: Querydsl HQL injection (CVSS 6.9) — ORM도 안전하지 않음
- OWASP 2025 A05: Injection 여전히 Top 5

[실제와의 차이]
- 실제 SQLi: 취약한 코드에 페이로드가 DB 쿼리로 실행됨
- 우리: Spring Boot JPA Prepared Statement로 실제 주입 차단
  → 공격 성공이 아닌 공격 시도 패턴 탐지가 목적

[구현 의도]
- 실제 보안 운영에서 WAF/IDS는 공격 성공 여부와 무관하게
  시도 패턴 자체를 탐지함 (UNION SELECT, OR 1=1 등)
- AIOps도 동일: Nginx 로그의 이상 패턴 → Loki 탐지 → Pipeline 분석
- URL 인코딩 없이 원문 페이로드 전송 → Nginx 로그에 패턴이 그대로 기록
  → security-rules.yml SQLInjectionAttempt 룰 탐지 가능

[실제 서비스 방어 우회 근거]
- nginx/default.conf에 WAF/ModSecurity 없음
- Spring Boot가 요청 자체는 통과시키고 400/403 반환
  → Nginx 로그에 이상 패턴 기록됨

탐지 포인트: SQLInjectionAttempt (Loki Ruler → Alertmanager → Pipeline)
탐지 조건:  {container="frontend"} |~ "union select|or 1=1|drop table|sleep"
AIOps 포인트: 이상 URL 패턴 + 에러율 급등 → LLM 분석 → NOTIFY 권고
"""

import ssl
import json
import os
import time
import urllib.request
import urllib.error
import urllib.parse
import sys
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common.verifier import ScenarioVerifier, VerifyResult

# ── 설정 ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
LOG_PATH    = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "logs", "anomaly_log.json"))

TARGET_BASE  = os.getenv("TARGET_URL", "https://localhost")
WORKERS      = 100
DURATION_SEC = 300

# SQLi 페이로드: URL 인코딩 없이 원문 전송
# → Nginx 로그에 패턴이 그대로 기록되어 Loki 룰 탐지 가능
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
    "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
    "' UNION SELECT null, table_name FROM information_schema.tables--",
    "' AND 1=1--",
    "' AND sleep(3)--",
]

# 공격 대상: 인증 없이 접근 가능한 공개 엔드포인트
SQLI_TARGETS = [
    "/api/v1/my-plants?userId={payload}",
    "/api/v1/schedules?plantId={payload}",
    "/api/dictionary/url?url={payload}",
    "/home?search={payload}",
    "/login/kakao?code={payload}",
]

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode    = ssl.CERT_NONE


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


# ── 단건 SQLi 요청 ────────────────────────────────────────────────────────────
def _send_sqli() -> tuple[int, float]:
    import random
    payload  = random.choice(SQLI_PAYLOADS)
    template = random.choice(SQLI_TARGETS)

    # URL 인코딩 없이 원문 전송 → Nginx 로그에 패턴 그대로 기록
    url = TARGET_BASE + template.format(payload=payload)
    t0  = time.time()
    try:
        req = urllib.request.Request(
            url,
            headers={
                # 실제 SQLi 스캐너 User-Agent → Nginx 로그에 기록
                "User-Agent": "sqlmap/1.7.8#stable",
                # 분산 소스 위장
                "X-Forwarded-For": (
                    f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"
                ),
                "Accept": "application/json",
            },
        )
        r = urllib.request.urlopen(req, context=_ssl_ctx, timeout=8)
        return r.status, (time.time() - t0) * 1000
    except urllib.error.HTTPError as e:
        return e.code, (time.time() - t0) * 1000
    except Exception:
        return 0, (time.time() - t0) * 1000


# ── 메인 ──────────────────────────────────────────────────────────────────────
def main():
    scenario = "sql_injection"

    # ── 1단계: Verifier 초기화 ────────────────────────────────────────────────
    verifier = ScenarioVerifier(
        scenario_name="sql_injection",
        alert_name="SQLInjectionAttempt",
        hypothesis=(
            "SQLi 패턴 페이로드 전송 시 Nginx 로그에 이상 패턴 기록 → "
            "Loki SQLInjectionAttempt Alert 발화"
        ),
    )

    verifier.check_steady_state()
    verifier.print_hypothesis()
    verifier.wait_for_alert_inactive(timeout=60, poll_interval=5)
    verifier.start_timer()

    # ── 2단계: 공격 시작 ──────────────────────────────────────────────────────
    print(f"\n[*] 시나리오: SQL Injection Attempt Detection")
    print(f"[*] 기반: OWASP A03:2021 / A05:2025 Injection")
    print(f"[*] 대상: {TARGET_BASE}")
    print(f"[*] 동시 스레드: {WORKERS} / 지속: {DURATION_SEC}초")
    print(f"[*] ⚠ JPA Prepared Statement로 실제 주입 차단됨")
    print(f"[*] 탐지 목표: Nginx 로그 이상 패턴 → Loki SQLInjectionAttempt 발화")
    print(f"[*] URL 인코딩 없이 원문 페이로드 전송 (Loki 패턴 매칭을 위해)")

    start_time = datetime.now(timezone.utc).isoformat()
    deadline   = time.time() + DURATION_SEC

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
                        error_codes = {
                            k: v for k, v in status_counts.items() if k >= 400
                        }
                        print(f"  → {total}건 | 에러 응답: {error_codes}")
                except Exception:
                    total += 1

    end_time   = datetime.now(timezone.utc).isoformat()
    error_total = sum(v for k, v in status_counts.items() if k >= 400)

    detail = json.dumps({
        "total_requests":   total,
        "error_responses":  error_total,
        "error_rate_pct":   round(error_total / max(total, 1) * 100, 1),
        "status_counts":    status_counts,
        "payloads_used":    len(SQLI_PAYLOADS),
        "encoding":         "none (raw payload for Loki pattern matching)",
        "note": (
            "JPA Prepared Statement로 실제 주입 차단. "
            "Nginx 로그의 이상 패턴을 Loki Ruler가 탐지. "
            "Loki Ruler → Alertmanager → Pipeline 자동 흐름."
        ),
    }, ensure_ascii=False)

    record_event(
        scenario, start_time, end_time,
        "success" if total > 0 else "error",
        detail,
    )
    print(f"\n[*] 완료: 총 {total}건 | 에러 응답 {error_total}건 "
          f"({round(error_total / max(total, 1) * 100, 1)}%)")
    print(f"[*] Grafana 확인: http://localhost:3000")
    print(f"[*] Loki 쿼리: {{container=\"frontend\"}} |~ \"union select|or 1=1\"")

    # ── 3단계: Loki 로그 기반 MTTD 측정 ──────────────────────────────────────
    # Loki Ruler → Alertmanager → Pipeline 웹훅은 자동 전송됨
    # verify_loki()는 Nginx 로그에서 실제 SQLi 패턴 감지 시점으로 MTTD 측정
    print("\n[*] Loki SQLi 패턴 탐지 대기 중...")
    mttd = verifier.verify_loki(
        log_query='{container="frontend"}',
        keyword="union select",   # URL 인코딩 안 된 원문 패턴
        timeout=180,
    )

    # ── 4단계: 결과 기록 ──────────────────────────────────────────────────────
    result = VerifyResult(
        success=mttd is not None,
        alert_name="SQLInjectionAttempt",
        scenario_name="sql_injection",
        mttd_seconds=mttd,
    )
    verifier.log_result(result)


if __name__ == "__main__":
    main()