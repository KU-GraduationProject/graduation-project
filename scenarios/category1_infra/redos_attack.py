"""
HTTP Flood / CPU Exhaustion Attack (ReDoS 시뮬레이션)
OWASP A05:2021 - Security Misconfiguration

대량 동시 HTTP 요청으로 leafy-frontend(Nginx) 컨테이너 CPU를 고갈시킨다.
백엔드 Spring Security가 모든 API를 OAuth로 보호하므로, 실제 ReDoS 페이로드 대신
Nginx가 처리하는 정적 경로(/home, /)에 100개 이상의 동시 요청을 퍼붓는 방식을 사용.

탐지 포인트: leafy-frontend 컨테이너 CPU 스파이크 → HighCpuUsage alert
AIOps 포인트: 같은 CPU 고갈이라도 컨테이너 식별(frontend vs backend)로 공격 의도 구별
"""

import ssl
import json
import os
import sys
import time
import threading
import urllib.request
import urllib.error
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common.verifier import ScenarioVerifier, VerifyResult

# ── 설정 ───────────────────────────────────────────────────────────────────────
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
LOG_PATH    = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "logs", "anomaly_log.json"))

TARGET_BASE   = os.getenv("TARGET_URL", "https://localhost")
WORKERS       = 300         # 동시 요청 스레드 수 (Nginx CPU spike 목표)
DURATION_SEC  = 120         # 공격 지속 시간(초)

# 공격 대상 엔드포인트 — 인증 없이 Nginx가 직접 처리하는 정적 경로
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
def _send_one(_: str = "") -> tuple[int, float]:
    """Nginx 정적 경로에 HTTP 요청 전송. (status_code, elapsed_ms) 반환"""
    import random
    endpoint = random.choice(TARGET_ENDPOINTS)
    url = f"{TARGET_BASE}{endpoint}"
    t0 = time.time()
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "ReDoSBot/1.0"},
        )
        r = urllib.request.urlopen(req, context=_ssl_ctx, timeout=5)
        return r.status, (time.time() - t0) * 1000
    except urllib.error.HTTPError as e:
        return e.code, (time.time() - t0) * 1000
    except Exception:
        return 0, (time.time() - t0) * 1000


# ── 메인 ───────────────────────────────────────────────────────────────────────
def main():
    import random

    scenario   = "redos_attack"
    # 수정 후
    verifier = ScenarioVerifier(
        scenario_name="redos_attack",
        alert_name="ReDoSAttack",
        hypothesis="ReDoS 공격 시도 시 Loki에 공격 로그 탐지",
    )
    verifier.check_steady_state()
    verifier.print_hypothesis()
    verifier.start_timer()
    start_time = datetime.now(timezone.utc).isoformat()
    deadline   = time.time() + DURATION_SEC

    print(f"[*] 시나리오: ReDoS (OWASP A05:2021 - Security Misconfiguration)")
    print(f"[*] 대상: {TARGET_BASE}")
    print(f"[*] 동시 스레드: {WORKERS} / 지속: {DURATION_SEC}초")
    print(f"[*] 공격 시작... (Prometheus HighCpuUsage 탐지까지 약 1~2분 소요)")

    total = 0
    errors = 0
    slow   = 0   # 응답 500ms 초과

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = []

        while time.time() < deadline:
            futures.append(pool.submit(_send_one))
            # 큐에 쌓인 결과 수집
            if len(futures) >= WORKERS * 2:
                done, futures = futures[:WORKERS], futures[WORKERS:]
                for f in done:
                    try:
                        code, ms = f.result()
                        total += 1
                        if ms > 500:
                            slow += 1
                        if code == 0:
                            errors += 1
                        if total % 100 == 0:
                            print(f"  → {total}건 전송 | 지연(>500ms): {slow}건 | 오류: {errors}건")
                    except Exception:
                        errors += 1

        # 남은 futures 정리
        for f in futures:
            try:
                f.result(timeout=2)
                total += 1
            except Exception:
                errors += 1

    end_time = datetime.now(timezone.utc).isoformat()
    detail = json.dumps({
        "total_requests": total,
        "slow_responses": slow,
        "errors": errors,
        "target_endpoints": TARGET_ENDPOINTS,
        "workers": WORKERS,
    }, ensure_ascii=False)

    status = "success" if total > 0 else "error"
    # 수정 후 — 이렇게 바꿔줘
    record_event(scenario, start_time, end_time, status, detail)
    print(f"\n[*] 완료: 총 {total}건 전송, 지연 응답 {slow}건")
    print(f"[*] Prometheus에서 HighCpuUsage alert 확인: http://localhost:9090/alerts")
    mttd = verifier.verify_loki(
        log_query='{container="frontend"}',
        keyword="ReDoSBot",
        timeout=180,
    )

    mtta = None
    if mttd is not None:
        sent = _send_pipeline_webhook({
            "version": "4",
            "groupKey": "redos_attack",
            "status": "firing",
            "alerts": [{
                "status": "firing",
                "labels": {"alertname": "ReDoSAttack", "severity": "critical", "container": "leafy-backend"},
                "annotations": {"summary": "ReDoS 공격 탐지", "container": "leafy-backend"},
                "startsAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }],
        })
        if sent:
            print("[*] Pipeline 웹훅 전송 완료 (MTTA 측정 시작)")
            mtta = verifier.verify_mtta(timeout=180)

    loki_result = VerifyResult(
        success=mttd is not None,
        alert_name="ReDoSAttack",
        scenario_name="redos_attack",
        mttd_seconds=mttd,
        mtta_seconds=mtta,
        slack_notified=mtta is not None,
    )
    verifier.log_result(loki_result)


if __name__ == "__main__":
    main()
