"""
F1-a — CPU 과부하(정상 요청 과다) (scenarios-v2, 2차).

장애 정의: 악성 프로세스가 아니라 **정상 엔드포인트로의 요청이 처리 능력을 넘게 몰려** 서비스
  CPU 가 포화되고 응답이 느려진다(이벤트·마케팅 폭주, 잘못된 클라이언트 재시도 폭주).
  S2-a(컨테이너 안 루프가 CPU 점유)와 원인이 다르다 — 여기서는 nginx 요청량이 같이 폭증하고,
  컨테이너 안에 낯선 프로세스는 없다.
대조: C-b(짧은 정상 부하 스파이크) — 같은 요청 증가지만 짧게 끝나고 포화되지 않는다.

주입: 측정 PC 에서 무거운 정상 GET 엔드포인트에 동시 요청을 지속적으로 보낸다(읽기만).
  엔드포인트는 env(F1A_PATHS) — 측정 PC 에서 가장 무거운 읽기 경로로 확정한다.
정리: 요청을 멈추면 원복. 워치독: 주입기 자체가 duration 뒤 끝나지만, 별도 프로세스로 돌릴 때를
  대비해 최대 시간 뒤 해당 PID 를 끊는다.

강도(현실적인 폭주 규모): 동시 클라이언트 수 weak=8, medium=32, strong=96.
"""

from __future__ import annotations

import os

from v2 import supervisor, timing

BASE_URL = os.getenv("F1A_BASE_URL", "http://127.0.0.1:80")
PATHS = [p for p in os.getenv("F1A_PATHS", "/api/dictionary/url,/index.html").split(",") if p]

STRENGTH_CONCURRENCY = {"weak": 8, "medium": 32, "strong": 96}
DEFAULT_STRENGTH = "medium"
DEFAULT_DURATION_SECONDS = 300
DEFAULT_MAX_SECONDS = 600
BACKGROUND_DEFAULT = True
PER_WORKER_RPS = 5          # 클라이언트당 초당 요청(앱이 느려지면 실제로는 더 낮아진다)


def plan_load(strength: str = DEFAULT_STRENGTH, duration_seconds: int = DEFAULT_DURATION_SECONDS,
              concurrency: int | None = None) -> dict:
    if strength not in STRENGTH_CONCURRENCY:
        raise ValueError(f"unknown strength: {strength}")
    if duration_seconds < 1:
        raise ValueError("duration_seconds 는 1 이상")
    c = concurrency or STRENGTH_CONCURRENCY[strength]
    return {"strength": strength, "concurrency": c, "duration_seconds": duration_seconds,
            "target_requests": c * PER_WORKER_RPS * duration_seconds}


def build_urls(count: int, base_url: str = BASE_URL, paths=None) -> list[str]:
    paths = paths or PATHS
    return [base_url + paths[i % len(paths)] for i in range(count)]


def inject(strength: str = DEFAULT_STRENGTH, duration_seconds: int = DEFAULT_DURATION_SECONDS,
           concurrency: int | None = None, max_seconds: int = DEFAULT_MAX_SECONDS,
           work_dir: str | None = None, background: bool | None = None,
           traffic_gen_path: str | None = None, traffic_target: str | None = None):
    plan = plan_load(strength, duration_seconds, concurrency)
    # 워치독: 세션이 멈춰도 이 프로세스(부하 발생기)를 끊는다 = 부하 종료.
    wd = supervisor.spawn_watchdog(f"kill {os.getpid()} 2>/dev/null; true",
                                   max(max_seconds, duration_seconds + 60), tag="f1a",
                                   work_dir=work_dir)
    bg = None
    if supervisor.background_enabled(BACKGROUND_DEFAULT, background) and traffic_target:
        bg = supervisor.spawn_background_traffic(traffic_gen_path, traffic_target)
    try:
        n = plan["target_requests"]
        offs = [i * duration_seconds / n for i in range(n)]
        statuses = timing.run_schedule(build_urls(n), offs, workers=plan["concurrency"])
        print(f"[F1-a] strength={strength} concurrency={plan['concurrency']} sent={len(statuses)} "
              f"5xx={sum(1 for s in statuses if s >= 500)} fail={statuses.count(0)}", flush=True)
        return {"plan": plan, "sent": len(statuses)}
    finally:
        supervisor.cancel_watchdog(wd)
        supervisor.stop_background_traffic(bg)


def dry_run() -> dict:
    return {"plan": plan_load(), "paths": PATHS, "base_url": BASE_URL,
            "watchdog_max_seconds": DEFAULT_MAX_SECONDS, "pair_control": "c_b_short_load_spike",
            "env": ["F1A_BASE_URL", "F1A_PATHS", "V2_WORK_DIR", "V2_TRAFFIC_GEN"],
            "note": "정상 읽기 GET 만, 요청 중지 = 원복"}


def main(**kw):
    return inject(**kw)


if __name__ == "__main__":
    main()
