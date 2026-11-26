"""
S2-d — 내부 정찰 (scenarios-v2, 2차).

위협 정의: 침해된 내부 서비스가 **같은 내부망의 다른 서비스 여러 포트**에 연결을 시도해
  무엇이 열려 있는지 더듬는다(내부 포트 스캔). 데이터는 거의 오가지 않고, 짧은 연결 시도·거부가
  여러 목적지·포트로 퍼진다.

주입: backend netns 사이드카에서 내부 서비스 이름 × 포트 목록으로 **TCP connect 만** 시도한다
  (연결되면 곧바로 닫음, 페이로드 없음). 저속(간격) 으로 보낸다. 대상은 env 로 주며 내부 서비스
  이름만 허용한다(IP 하드코딩 없음, 외부 주소 금지).
정리: 사이드카 종료. 상태 변화 없음(connect/close 만).

강도(현실적인 내부 스캔 속도): strong=빠른 전체 스윕, medium=보통, weak=느린 은닉 스캔.
"""

from __future__ import annotations

import json
import os

from v2 import netns, supervisor

# 내부 서비스(compose 서비스 이름) — env 로 바꾼다.
TARGET_HOSTS = [h for h in os.getenv("S2D_HOSTS", "db,minio,frontend,fluentd,cadvisor").split(",") if h]
COMMON_PORTS = [21, 22, 23, 25, 80, 443, 3000, 3306, 5432, 6379, 8080, 8443, 9000, 9090, 9200, 27017]

# strength → (대상 호스트 수 상한, 연결 간격 초)
STRENGTH_PROFILE = {"weak": (2, 3.0), "medium": (4, 0.5), "strong": (99, 0.05)}
DEFAULT_STRENGTH = "medium"
DEFAULT_MAX_SECONDS = 900
BACKGROUND_DEFAULT = True


# 호스트 DB 가 컨테이너 밖(Windows 호스트 PostgreSQL)일 때를 위한 Docker 내부 게이트웨이
# 이름. 이 고정 이름들만 예외로 허용하고, 그 밖의 외부 주소·임의 도메인·IP 는 여전히 금지한다.
INTERNAL_GATEWAY_HOSTS = {"host.docker.internal", "gateway.docker.internal"}


def assert_internal(hosts) -> None:
    """내부 서비스 이름(compose 서비스명)만 허용. 예외: Docker 내부 게이트웨이 고정 이름.
    그 외 점·콜론·슬래시·공백 포함 이름이나 숫자로 시작하는 이름(IP 등)은 외부로 보고 거부."""
    for h in hosts:
        if h in INTERNAL_GATEWAY_HOSTS:
            continue
        if not h or any(c in h for c in ".:/ ") or h[0].isdigit():
            raise ValueError(f"내부 서비스 이름만 허용: {h!r}")


def plan_scan(strength: str = DEFAULT_STRENGTH, hosts=None, ports=None,
              interval_seconds: float | None = None) -> dict:
    if strength not in STRENGTH_PROFILE:
        raise ValueError(f"unknown strength: {strength}")
    max_hosts, iv = STRENGTH_PROFILE[strength]
    hosts = list(hosts if hosts is not None else TARGET_HOSTS)[:max_hosts]
    assert_internal(hosts)
    ports = list(ports if ports is not None else COMMON_PORTS)
    iv = interval_seconds if interval_seconds is not None else iv
    probes = [(h, p) for h in hosts for p in ports]
    return {"strength": strength, "hosts": hosts, "ports": ports, "interval_seconds": iv,
            "probes": len(probes), "est_seconds": round(len(probes) * iv, 1)}


def scan_script(plan: dict, seed: int = 0) -> str:
    cfg = json.dumps({"h": plan["hosts"], "p": plan["ports"], "iv": plan["interval_seconds"],
                      "seed": seed})
    return (
        "import json,random,socket,time\n"
        f"c=json.loads({cfg!r})\n"
        "pr=[(h,p) for h in c['h'] for p in c['p']];random.Random(c['seed']).shuffle(pr)\n"
        "for h,p in pr:\n"
        "    s=socket.socket();s.settimeout(1.0)\n"
        "    try:\n"
        "        s.connect((h,p))\n"
        "    except Exception:\n"
        "        pass\n"
        "    finally:\n"
        "        s.close()\n"
        "    time.sleep(c['iv'])\n"
    )


def inject(strength: str = DEFAULT_STRENGTH, hosts=None, ports=None,
           interval_seconds: float | None = None, seed: int = 0,
           max_seconds: int = DEFAULT_MAX_SECONDS, work_dir: str | None = None,
           background: bool | None = None, traffic_gen_path: str | None = None,
           traffic_target: str | None = None):
    plan = plan_scan(strength, hosts, ports, interval_seconds)
    name = netns.sidecar_name()
    wd = supervisor.spawn_watchdog(netns.kill_sh(name), max(max_seconds, int(plan["est_seconds"]) + 60),
                                   tag="s2d", work_dir=work_dir)
    bg = None
    if supervisor.background_enabled(BACKGROUND_DEFAULT, background) and traffic_target:
        bg = supervisor.spawn_background_traffic(traffic_gen_path, traffic_target)
    netns.start(scan_script(plan, seed), name)
    print(f"[S2-d] strength={strength} hosts={len(plan['hosts'])} probes={plan['probes']} "
          f"est={plan['est_seconds']}s sidecar={name}", flush=True)
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
    return {"plan": plan_scan(), "image": netns.NET_IMAGE, "backend": netns.BACKEND_CONTAINER,
            "env": ["S2D_HOSTS", "V2_NET_IMAGE", "V2_BACKEND_CONTAINER", "V2_WORK_DIR"],
            "note": "TCP connect/close 만, 내부 서비스 이름만(외부·IP 금지)"}


def main(**kw):
    import time
    meta = None
    try:
        meta = inject(**kw)
        time.sleep(meta["plan"]["est_seconds"] + 5)
    finally:
        cleanup(meta)


if __name__ == "__main__":
    main()
