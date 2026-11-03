"""
S1-a — 입력값 공격 (앱까지 통과) (scenarios-v2).

정의(사용자 조건): "앱까지 통과"가 핵심이다. 요청이 nginx 에서 막히지 않고(2xx/비차단)
  앱까지 도달해 앱·nginx 로그에 남는지가 검증 기준이다. 차단된 공격(4xx 다발)은 C-c 쪽이다.

주입: frontend 에 주입 패턴 쿼리를 다수 전송한다. 패턴은 검색 파라미터 같은 읽기성 요청에 실어
  보내 앱이 리터럴 문자열로 처리하고 2xx 를 돌려주게 한다(DB 변경 없음).
증거: frontend nginx JSON 액세스 로그의 페이로드 + 2xx. 자기신고 문자열은 없다 —
  탐지는 기존 SQLInjectionAttempt / PathTraversalAttempt 가 액세스 로그의 패턴으로 한다.

미확정(측정 PC): 어떤 경로가 nginx 를 통과해 앱에서 2xx 를 돌려주는지 확정해야 한다.
  기본 경로는 env(S1A_PATH)로 바꾼다. 검증 기준은 "nginx 비차단 + 앱 로그 기록"이다.

순수 로직(요청 계획·페이로드)은 단위 테스트, HTTP 실행은 UNVERIFIED.
"""

from __future__ import annotations

import os
import urllib.parse
import urllib.request

BASE_URL = os.getenv("S1A_BASE_URL", "http://127.0.0.1:80")
TARGET_PATH = os.getenv("S1A_PATH", "/api/plants/search")   # 측정 PC에서 2xx 경로로 확정
PARAM = os.getenv("S1A_PARAM", "q")

# SQLInjectionAttempt 정규식에 매칭되는 공격형 입력. 앱은 리터럴 검색어로 처리 → 2xx, DB 불변.
# (정답/시나리오를 암시하는 문자열이 아니라 실제 공격 입력 그 자체다.)
PAYLOADS = [
    "1' OR 1=1 --",
    "x' UNION SELECT null--",
    "a' AND 1=1 --",
    "'; DROP TABLE x--",
    "1 OR 1=1",
    "test' OR 1=1--",
]

# SQLInjectionAttempt 임계(>5/2m)를 여유 있게 넘기기 위한 총 요청 수.
DEFAULT_REQUESTS = 10

# nginx 가 "막지 않음"으로 볼 상태코드. 2xx = 앱 통과. 403/444 등은 nginx 차단으로 본다.
PASS_STATUSES = set(range(200, 300))


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


def inject(count: int = DEFAULT_REQUESTS):
    """요청을 보내고 각 상태코드를 모은다. 통과(2xx) 비율을 요약한다 — Loki 에 쓰지 않는다."""
    urls = build_request_urls(count)
    statuses = [_send(u) for u in urls]
    passed = sum(1 for s in statuses if passed_to_app(s))
    print(f"[S1-a] sent={len(urls)} passed_to_app(2xx)={passed} statuses={statuses}", flush=True)
    if passed == 0:
        print("[S1-a] 경고: 2xx 통과 0건 — nginx 차단이거나 경로가 틀림. S1A_PATH 확인 필요.", flush=True)
    return {"sent": len(urls), "passed_to_app": passed, "statuses": statuses}


def dry_run() -> dict:
    """HTTP 없이 요청 계획만. run --dry-run 용."""
    urls = build_request_urls()
    return {"count": len(urls), "sample_urls": urls[:3], "target_path": TARGET_PATH}


def main():
    inject()


if __name__ == "__main__":
    main()
