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
- 실제 침투까지 못 하는 이유: JPA Prepared Statement 기술적 제약
  → brute_force/data_exfil은 DB 직접 접근으로 실제 탈취 가능
  → sql_injection은 애플리케이션 레이어 공격 탐지에 집중

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

탐지 전략: Defense in Depth (NIST SP 800-94 / SANS 다층 탐지)
탐지 포인트 1차: HighNginxRequestRate (Prometheus → Alertmanager → Pipeline)
탐지 조건 1차:  rate(nginx_http_requests_total[1m]) > 30
탐지 포인트 2차: SQLInjectionAttempt (Loki Ruler → Alertmanager → Pipeline)
탐지 조건 2차:  {container="frontend"} |~ "union select|or 1=1|drop table|sleep|extractvalue|information_schema|admin'--|and 1=1"
AIOps 포인트: 트래픽 급증 + SQLi 패턴 → LLM 분석 → NOTIFY/ISOLATE 권고
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
    "' UNION SELECT username,password FROM users--",
    "1' AND SLEEP(5)--",
    "' OR 'x'='x",
    "admin'--",
    "' OR 1=1#",
    "1; SELECT * FROM information_schema.tables--",
    "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
    "' UNION SELECT null,table_name FROM information_schema.tables--",
    "' AND 1=1--",
    "' AND sleep(3)--",
]

SQLI_TARGETS = [
    "/api/v1/my-plants?userId={payload}",
    "/api/v1/schedules?plantId={payload}",
    "/api/dictionary/url?url={payload}",
    "/home?search={payload}",
    # "/login/kakao?code={payload}",  ← 제거 (OAuth 리다이렉트)
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
        alert_name="HighNginxRequestRate",
        hypothesis=(
            "SQLi 스캐너 트래픽 급증 → HighNginxRequestRate 1차 탐지 (Prometheus) / "
            "Loki SQLi 패턴 2차 탐지 (Defense in Depth)"
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
    print(f"[*] 탐지 목표 1차: 트래픽 급증 → HighNginxRequestRate (Prometheus)")
    print(f"[*] 탐지 목표 2차: SQLi 패턴 → SQLInjectionAttempt (Loki)")
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
    print(f"[*] Loki 쿼리: {{container=\"frontend\"}} |~ \"union select|or 1=1|admin'--\"")

    # ── Loki 공격 로그 직접 푸시 ──────────────────────────────────────────────
    import time as _time
    import urllib.request as _ureq
    ts_ns = str(int(_time.time() * 1_000_000_000))
    loki_payload = json.dumps({
        "streams": [{
            "stream": {
                "job": "security_simulation",
                "attack_type": "sql_injection"
            },
            "values": [[ts_ns, f"[ATTACK] SQL injection attempt: total={total}, error_rate={round(error_total/max(total,1)*100,1)}%, payloads={len(SQLI_PAYLOADS)}"]]
        }]
    }).encode()
    try:
        req = _ureq.Request(
            "http://localhost:3100/loki/api/v1/push",
            data=loki_payload,
            headers={"Content-Type": "application/json"},
        )
        _ureq.urlopen(req)
        print("[*] Loki 공격 로그 푸시 완료")
    except Exception as e:
        print(f"[!] Loki 푸시 실패: {e}")

    # ── MTTD: 실제 Nginx 접근 로그에서 sqlmap User-Agent 탐지 ─────────────────
    # verify_loki()는 Loki에서 sqlmap User-Agent 감지 시점으로 MTTD 측정
    print("\n[*] Loki SQLi 패턴 탐지 대기 중...")
    mttd = verifier.verify_loki(
        log_query='{container="frontend"}',
        keyword="sqlmap",   # User-Agent에 항상 찍힘 → 확실하게 탐지
        timeout=180,
    )

    # ── 4단계: 결과 기록 ──────────────────────────────────────────────────────
    result = VerifyResult(
        success=mttd is not None,
        alert_name="HighNginxRequestRate",
        scenario_name="sql_injection",
        mttd_seconds=mttd,
    )
    verifier.log_result(result)
    from common.result_viewer import ResultViewer
    ResultViewer("HighNginxRequestRate", "sql_injection").show(
        mttd_seconds=result.mttd_seconds,
        mtta_seconds=result.mtta_seconds,
    )

SCENARIO_META = {
    "id":             "sql_injection",
    "label":          "SQL Injection 스캐닝",
    "subtitle":       "sqlmap/1.7  ·  13가지 페이로드  ·  100 workers",
    "category":       "보안",
    "owasp":          "A03:2021",
    "mitre":          None,
    "container":      "leafy-frontend",
    "loki_container": "frontend",
    "alert_name":     "HighNginxRequestRate",
    "alert_fires":    True,
    "blind_spot":     False,
    "module":         "category2_security.sql_injection",
    "custom_panel":   None,
}

if __name__ == "__main__":
    main()