"""
S1-a — 입력값 공격 (앱까지 통과) (scenarios-v2).

정의(사용자 조건): "앱까지 통과"가 핵심이다. 요청이 nginx 에서 막히지 않고(2xx/비차단)
  앱까지 도달해 앱·nginx 로그에 남는지가 검증 기준이다. 차단된 공격(4xx 다발)은 C-c 쪽이다.

주입: frontend 에 실제 공격형 입력(SQL 인젝션 등)을 검색 파라미터 같은 읽기성 요청에 실어
  다수 전송한다. 앱이 리터럴 문자열로 처리해 2xx 를 돌려주게 한다(DB 변경 없음).
증거: frontend nginx JSON 액세스 로그의 페이로드 + 2xx, 그리고 앱 로그. 자기신고 문자열은 없다 —
  페이로드는 정답/시나리오를 암시하는 문자열이 아니라 실제 공격 입력 그 자체다.
  (어떤 룰로 탐지할지는 룰 작성자 몫 — THREAT_SPEC.md 참조.)

경로(측정 PC 확정): 공개 2xx 경로 `/api/v1/auth/check-login-id`(login_id 파라미터). env(S1A_PATH·S1A_PARAM)로 바꾼다.
  검증 기준은 "nginx 비차단 + 앱 로그 기록"이다.

순수 로직(요청 계획·페이로드)은 단위 테스트, HTTP 실행은 UNVERIFIED.
"""

from __future__ import annotations

import os
import urllib.parse
import urllib.request

from v2 import supervisor

BASE_URL = os.getenv("S1A_BASE_URL", "http://127.0.0.1:80")
TARGET_PATH = os.getenv("S1A_PATH", "/api/v1/auth/check-login-id")   # 측정 PC 확정: 공개 2xx 경로
PARAM = os.getenv("S1A_PARAM", "login_id")

# 실제 SQL 인젝션 공격 입력. 앱은 리터럴 검색어로 처리 → 2xx, DB 불변.
# (정답/시나리오를 암시하는 문자열이 아니라 실제 공격 입력 그 자체다.)
PAYLOADS = [
    "1' OR 1=1 --",
    "x' UNION SELECT null--",
    "a' AND 1=1 --",
    "'; DROP TABLE x--",
    "1 OR 1=1",
    "test' OR 1=1--",
]

# 공격이 일회성이 아닌 "탐지 가능한 프로브 버스트"가 되도록 하는 기본 요청 수.
# (수치 근거는 룰 임계가 아니라 현실적인 자동 스캐닝 볼륨 — THREAT_SPEC/VARIANTS 참조.)
DEFAULT_REQUESTS = 10

# nginx 가 "막지 않음"으로 볼 상태코드. 2xx = 앱 통과. 403/444 등은 nginx 차단으로 본다.
PASS_STATUSES = set(range(200, 300))
BACKGROUND_DEFAULT = False   # S1-a 는 배경 트래픽 기본 OFF


# --------------------------------------------------------------------------- #
# 순수 로직 (단위 테스트 대상)
# --------------------------------------------------------------------------- #

def build_request_urls(count: int = DEFAULT_REQUESTS, base_url: str = BASE_URL,
                       path: str = TARGET_PATH, param: str = PARAM,
                       payloads=PAYLOADS) -> list[str]:
    """count 개의 요청 URL. 페이로드를 순환하며 쿼리 파라미터에 실어 읽기성 GET 으로 만든다."""
    if count < 1:
        raise ValueError("count 는 1 이상")
    urls = []
    for i in range(count):
        p = payloads[i % len(payloads)]
        q = urllib.parse.urlencode({param: p})
        urls.append(f"{base_url}{path}?{q}")
    return urls


def passed_to_app(status: int) -> bool:
    """nginx 차단 없이 앱까지 통과했는가 (2xx)."""
    return status in PASS_STATUSES


# --------------------------------------------------------------------------- #
# HTTP 런타임 (UNVERIFIED — 실행은 측정 PC)
# --------------------------------------------------------------------------- #

def _send(url: str, timeout: float = 5.0) -> int:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def inject(count: int = DEFAULT_REQUESTS, background: bool | None = None,
           traffic_gen_path: str | None = None, traffic_target: str | None = None):
    """요청을 보내고 각 상태코드를 모은다. 통과(2xx) 비율을 요약한다 — Loki 에 쓰지 않는다."""
    bg = None
    if supervisor.background_enabled(BACKGROUND_DEFAULT, background) and traffic_target:
        bg = supervisor.spawn_background_traffic(traffic_gen_path, traffic_target)
    try:
        urls = build_request_urls(count)
        statuses = [_send(u) for u in urls]
        passed = sum(1 for s in statuses if passed_to_app(s))
        print(f"[S1-a] sent={len(urls)} passed_to_app(2xx)={passed} statuses={statuses}", flush=True)
        if passed == 0:
            print("[S1-a] 경고: 2xx 통과 0건 — nginx 차단이거나 경로가 틀림. S1A_PATH 확인 필요.", flush=True)
        return {"sent": len(urls), "passed_to_app": passed, "statuses": statuses}
    finally:
        supervisor.stop_background_traffic(bg)


def dry_run() -> dict:
    """HTTP 없이 요청 계획만. run --dry-run 용."""
    urls = build_request_urls()
    return {"count": len(urls), "sample_urls": urls[:3], "target_path": TARGET_PATH,
            "base_url": BASE_URL, "param": PARAM, "background_default": BACKGROUND_DEFAULT,
            "env": ["S1A_BASE_URL", "S1A_PATH", "S1A_PARAM", "V2_TRAFFIC_GEN"]}


def main():
    inject()


if __name__ == "__main__":
    main()
