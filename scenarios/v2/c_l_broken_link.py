"""
C-l — 깨진 링크 404 (S1-b 대조, scenarios-v2 2차).

정상 상황: 일반 사용자 브라우저가 지워진 사진·옛 북마크·브라우저 자동 요청(favicon 등) 때문에
  **가끔 없는 경로를 요청**해 404 를 받는다. S1-b 와 같은 4xx 신호지만 저빈도·소수 경로·
  실사용자가 내는 경로뿐이다.

주입: 측정 PC 에서 아래 경로를 저빈도로 GET(일반 UA). 스캐너 사전 경로는 쓰지 않는다.
  (traffic_gen.py --control not-found 와 같은 경로 계열. 이 모듈은 단독 실행용.)
정리: 상태 변화 없음.

강도(대조): 사용자 실수 빈도 — weak=매우 드묾, strong=오래된 링크가 많이 걸린 페이지 수준.
"""

from __future__ import annotations

import os
import uuid

from v2 import supervisor, timing

BASE_URL = os.getenv("CL_BASE_URL", "http://127.0.0.1:80")

MISSING_PATHS = ["/favicon.ico", "/robots.txt", "/apple-touch-icon.png",
                 "/app/main/main_old.html", "/app/profile/settings.html",
                 "/files/journal/<uuid>.jpg", "/files/plants/<uuid>.png"]

# strength → (요청 수, 지속 초): 수 분~수십 분에 걸친 소수 요청
STRENGTH_PROFILE = {"weak": (4, 900), "medium": (10, 900), "strong": (20, 900)}
DEFAULT_STRENGTH = "medium"
BACKGROUND_DEFAULT = True


def plan_requests(strength: str = DEFAULT_STRENGTH, requests: int | None = None,
                  duration_seconds: int | None = None, seed: int = 0) -> dict:
    if strength not in STRENGTH_PROFILE:
        raise ValueError(f"unknown strength: {strength}")
    n, dur = STRENGTH_PROFILE[strength]
    n, dur = requests or n, duration_seconds or dur
    return {"strength": strength, "requests": n, "duration_seconds": dur,
            "offsets": timing.offsets(n, dur, "spread", seed)}


def build_urls(count: int, base_url: str = BASE_URL, seed: int = 0) -> list[str]:
    import random
    rng = random.Random(seed)
    out = []
    for _ in range(count):
        p = rng.choice(MISSING_PATHS)
        out.append(base_url + p.replace("<uuid>", str(uuid.UUID(int=rng.getrandbits(128), version=4))))
    return out


def inject(strength: str = DEFAULT_STRENGTH, requests: int | None = None,
           duration_seconds: int | None = None, seed: int = 0, background: bool | None = None,
           traffic_gen_path: str | None = None, traffic_target: str | None = None):
    plan = plan_requests(strength, requests, duration_seconds, seed)
    bg = None
    if supervisor.background_enabled(BACKGROUND_DEFAULT, background) and traffic_target:
        bg = supervisor.spawn_background_traffic(traffic_gen_path, traffic_target)
    try:
        statuses = timing.run_schedule(build_urls(plan["requests"], seed=seed), plan["offsets"])
        print(f"[C-l] requests={len(statuses)} 404={statuses.count(404)}", flush=True)
        return {"requests": len(statuses), "status_404": statuses.count(404)}
    finally:
        supervisor.stop_background_traffic(bg)


def dry_run() -> dict:
    plan = plan_requests()
    return {"requests": plan["requests"], "duration_seconds": plan["duration_seconds"],
            "paths": MISSING_PATHS, "base_url": BASE_URL, "pair": "s1_b_recon_scan",
            "env": ["CL_BASE_URL", "V2_TRAFFIC_GEN"]}


def main(**kw):
    return inject(**kw)


if __name__ == "__main__":
    main()
