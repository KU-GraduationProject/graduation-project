"""
S1-b — 정찰(취약점 스캔) (scenarios-v2, 2차).

위협 정의: 한 출발지가 **존재하지 않는 경로·흔히 알려진 취약 경로**를 짧은 시간에 다수 요청해
  공격 표면을 더듬는다(취약점 스캐너). 대부분 404 등 4xx 로 끝난다. 침투 전 단계라 위험도는 낮다.
대조: C-l(깨진 링크 404) — 같은 4xx 신호지만 일반 사용자의 저빈도 요청.

주입: 측정 PC(한 출발지)에서 아래 경로 목록을 시간 패턴대로 GET. 인젝션 페이로드(SQLi·경로
  조작 문자열)는 넣지 않는다 — 그것은 S1-a 영역이다. UA 는 일반 브라우저(자기신고 없음).
정리: 상태 변화 없음(읽기 요청만) → 원복 불필요.

강도(현실적인 스캐너 속도 기준, 룰 임계 아님):
  strong = 공격적인 자동 스캐너(수백 건을 수십 초에), medium = 기본 설정 스캐너,
  weak = 탐지 회피형 저속 스캔(수십 건을 수 분에 걸쳐).

순수 로직은 단위 테스트, HTTP 실행은 UNVERIFIED (측정 PC).
"""

from __future__ import annotations

import os

from v2 import supervisor, timing

BASE_URL = os.getenv("S1B_BASE_URL", "http://127.0.0.1:80")

# 흔한 스캐너 사전의 일부(관리 콘솔·설정 파일·백업·다른 스택 경로). 인젝션 문자열 없음.
SCAN_PATHS = [
    "/admin", "/administrator/", "/wp-login.php", "/wp-admin/", "/phpmyadmin/", "/pma/",
    "/manager/html", "/console", "/actuator", "/actuator/env", "/server-status",
    "/.git/config", "/config.php", "/backup.zip", "/backup.sql", "/db.sql", "/web.config",
    "/cgi-bin/", "/login.jsp", "/solr/", "/jenkins/", "/api/v1/swagger.json", "/swagger-ui.html",
    "/xmlrpc.php", "/vendor/", "/old/", "/test/", "/temp/", "/install.php", "/setup.php",
]

# strength → (요청 수, 지속 초)
STRENGTH_PROFILE = {"weak": (40, 300), "medium": (150, 90), "strong": (400, 30)}
DEFAULT_STRENGTH = "medium"
DEFAULT_TIME_PATTERN = "burst"
BACKGROUND_DEFAULT = True     # 정상 트래픽 속에 섞인 스캔이 현실적


def plan_scan(strength: str = DEFAULT_STRENGTH, time_pattern: str = DEFAULT_TIME_PATTERN,
              requests: int | None = None, duration_seconds: int | None = None,
              seed: int = 0) -> dict:
    if strength not in STRENGTH_PROFILE:
        raise ValueError(f"unknown strength: {strength}")
    n, dur = STRENGTH_PROFILE[strength]
    n, dur = requests or n, duration_seconds or dur
    return {"strength": strength, "time_pattern": time_pattern, "requests": n,
            "duration_seconds": dur, "offsets": timing.offsets(n, dur, time_pattern, seed)}


def build_urls(count: int, base_url: str = BASE_URL, paths=SCAN_PATHS) -> list[str]:
    """사전을 순환하며 count 개 URL. 한 바퀴를 넘으면 뒤에 숫자 접미사(존재하지 않는 경로)."""
    out = []
    for i in range(count):
        p = paths[i % len(paths)]
        lap = i // len(paths)
        out.append(f"{base_url}{p}" if lap == 0 else f"{base_url}{p.rstrip('/')}{lap}")
    return out


def inject(strength: str = DEFAULT_STRENGTH, time_pattern: str = DEFAULT_TIME_PATTERN,
           requests: int | None = None, duration_seconds: int | None = None, seed: int = 0,
           background: bool | None = None, traffic_gen_path: str | None = None,
           traffic_target: str | None = None):
    plan = plan_scan(strength, time_pattern, requests, duration_seconds, seed)
    bg = None
    if supervisor.background_enabled(BACKGROUND_DEFAULT, background) and traffic_target:
        bg = supervisor.spawn_background_traffic(traffic_gen_path, traffic_target)
    try:
        statuses = timing.run_schedule(build_urls(plan["requests"]), plan["offsets"], workers=4)
        c4 = sum(1 for s in statuses if 400 <= s < 500)
        print(f"[S1-b] strength={strength} pattern={time_pattern} requests={len(statuses)} "
              f"4xx={c4} 2xx={sum(1 for s in statuses if 200 <= s < 300)}", flush=True)
        return {"requests": len(statuses), "status_4xx": c4}
    finally:
        supervisor.stop_background_traffic(bg)


def dry_run() -> dict:
    plan = plan_scan()
    return {"strength": plan["strength"], "requests": plan["requests"],
            "duration_seconds": plan["duration_seconds"], "time_pattern": plan["time_pattern"],
            "sample_paths": SCAN_PATHS[:5], "base_url": BASE_URL,
            "background_default": BACKGROUND_DEFAULT, "env": ["S1B_BASE_URL", "V2_TRAFFIC_GEN"],
            "note": "읽기 GET 만, 인젝션 페이로드 없음, 원복 불필요"}


def main(**kw):
    return inject(**kw)


if __name__ == "__main__":
    main()
