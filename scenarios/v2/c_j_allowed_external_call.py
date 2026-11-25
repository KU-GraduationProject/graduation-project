"""
C-j — 정상 외부 API 호출 (S2-b 대조, scenarios-v2 2차).

정상 상황: 서비스가 **허용 목록 안 목적지**로 소량 호출을 반복한다(식물 인식·날씨 등 외부 API 연동).
  S2-b 와 같은 "소량·반복 외부 연결" 모양이지만 목적지가 인가돼 있어 정상이다.

주입(기본 = sink 모드): backend netns 사이드카에서 **허용 목록에 등록된 우리 소유 sink(sink-a)**
  로 S2-b 와 같은 모양의 소량 호출을 보낸다. 목적지만 다르고 나머지 모양은 S2-b 와 같다 —
  짝 대조의 차이가 목적지 하나뿐이 되게 하려는 것.
  실제 기능 경로(앱의 식물 인식 → 외부 API)는 제3자 호출·API 키·과금이 걸려 이번 범위에서 보류
  (PR "보류" 참고).
정리: 사이드카 종료. 워치독이 최대 시간 뒤 강제 종료한다.
"""

from __future__ import annotations

import os

from v2 import netns, supervisor
from v2.s2b_c2_beacon import beacon_script, plan_beacon

DEST = os.getenv("CJ_DEST", "http://sink-a:8080/")    # 허용 목록 안 우리 소유 sink
DEFAULT_STRENGTH = "medium"
DEFAULT_DURATION_SECONDS = 600
DEFAULT_MAX_SECONDS = 900
BACKGROUND_DEFAULT = True


def inject(strength: str = DEFAULT_STRENGTH, duration_seconds: int = DEFAULT_DURATION_SECONDS,
           interval_seconds: float | None = None, seed: int = 0, dest: str = DEST,
           max_seconds: int = DEFAULT_MAX_SECONDS, work_dir: str | None = None,
           background: bool | None = None, traffic_gen_path: str | None = None,
           traffic_target: str | None = None):
    plan = plan_beacon(strength, duration_seconds, interval_seconds)
    name = netns.sidecar_name()
    wd = supervisor.spawn_watchdog(netns.kill_sh(name), max(max_seconds, duration_seconds + 60),
                                   tag="cj", work_dir=work_dir)
    bg = None
    if supervisor.background_enabled(BACKGROUND_DEFAULT, background) and traffic_target:
        bg = supervisor.spawn_background_traffic(traffic_gen_path, traffic_target)
    netns.start(beacon_script(plan, dest, seed), name)
    print(f"[C-j] interval={plan['interval_seconds']}s duration={duration_seconds}s sidecar={name}",
          flush=True)
    return {"plan": plan, "sidecar": name, "watchdog": wd, "background": bg}


def cleanup(meta: dict | None) -> None:
    meta = meta or {}
    try:
        if meta.get("sidecar"):
            netns.stop(meta["sidecar"])
    finally:
        supervisor.cancel_watchdog(meta.get("watchdog"))
        supervisor.stop_background_traffic(meta.get("background"))


def dry_run() -> dict:
    return {"plan": plan_beacon(), "dest": DEST, "mode": "sink", "pair": "s2_b_c2_beacon",
            "env": ["CJ_DEST", "V2_NET_IMAGE", "V2_BACKEND_CONTAINER", "V2_WORK_DIR"],
            "note": "허용 목록 안 우리 소유 sink 로만. 실제 외부 API 경로는 보류"}


def main(**kw):
    import time
    meta = None
    try:
        meta = inject(**kw)
        time.sleep(meta["plan"]["duration_seconds"])
    finally:
        cleanup(meta)


if __name__ == "__main__":
    main()
