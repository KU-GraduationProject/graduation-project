"""
2차 시나리오 공용 — 시간 패턴(burst/spread/intermittent) 오프셋과 HTTP GET 한 번.

여러 HTTP·네트워크 주입기(S1-b, F1-a, C-b, C-l, S2-b, S2-d, C-j)가 같은 시간 패턴 어휘
(VARIANTS.md §0)를 쓰므로 한 곳에 둔다. 정답 레이블·자기신고 문자열은 다루지 않는다.
"""

from __future__ import annotations

import random
import urllib.error
import urllib.request

TIME_PATTERNS = ("burst", "spread", "intermittent")

# 일반 브라우저 UA(자기신고·스캐너 표식 없음).
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")


def offsets(count: int, duration_seconds: float, pattern: str, seed: int = 0) -> list[float]:
    """count 개 이벤트의 시작 오프셋(초, 오름차순, 0..duration).

    burst        : 앞쪽 10% 구간에 몰림.
    spread       : 전 구간에 고르게(+지터).
    intermittent : 짧은 묶음 3~5개가 쉬는 구간을 사이에 두고 반복.
    """
    if count < 1:
        raise ValueError("count 는 1 이상")
    if duration_seconds <= 0:
        raise ValueError("duration_seconds 는 0 초과")
    if pattern not in TIME_PATTERNS:
        raise ValueError(f"unknown time_pattern: {pattern}")
    rng = random.Random(seed)
    d = float(duration_seconds)
    if pattern == "burst":
        out = [rng.uniform(0, d * 0.1) for _ in range(count)]
    elif pattern == "spread":
        step = d / count
        out = [min(d, (i + rng.uniform(0.0, 1.0)) * step) for i in range(count)]
    else:
        groups = rng.randint(3, 5)
        width = d / groups
        out = [(i % groups) * width + rng.uniform(0, width * 0.2) for i in range(count)]
    return sorted(round(x, 3) for x in out)


def http_get(url: str, timeout: float = 5.0, user_agent: str = BROWSER_UA) -> int:
    """GET 한 번 → 상태 코드(연결 실패는 0). 응답 본문은 읽고 버린다."""
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:  # noqa: BLE001
        return 0


def run_schedule(urls: list[str], offs: list[float], workers: int = 1) -> list[int]:
    """offs 시각에 맞춰 urls 를 GET. workers>1 이면 동시 실행(부하형). 상태 목록 반환. (런타임)"""
    import time
    from concurrent.futures import ThreadPoolExecutor
    t0 = time.time()

    def one(pair):
        url, off = pair
        time.sleep(max(0.0, t0 + off - time.time()))
        return http_get(url)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        return list(ex.map(one, zip(urls, offs)))
