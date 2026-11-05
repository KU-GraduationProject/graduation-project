"""
F2-a — MinIO 중단 (scenarios-v2).

주입: leafy-minio 컨테이너를 멈춰(stop) 오브젝트 스토리지를 사용 불가 상태로 만든다.
정리: 반드시 재기동(start)하고 healthy 가 될 때까지 기다린다.
자동 복구: 세션이 멈춰도 max_seconds 뒤 watchdog 이 `docker start` 로 복구한다(supervisor).

데이터 안전: stop ≠ delete. minio_data 볼륨은 건드리지 않는다. 멈췄다 다시 켤 뿐이다.
자기신고 없음: Loki/pipeline 에 아무것도 쓰지 않는다. 증거는 "minio 가 실제로 멈춰서
      backend 가 남기는 오류"뿐이다.

순수 로직(docker 불필요, 단위 테스트 대상)과 docker 런타임(UNVERIFIED)을 분리한다.
"""

from __future__ import annotations

import os
import time

from v2 import supervisor

MINIO_CONTAINER = os.getenv("F2A_CONTAINER", "leafy-minio")
DEFAULT_DOWN_SECONDS = 120   # backend 가 오류를 충분히 남기도록 유지하는 시간
DEFAULT_MAX_SECONDS = 180    # watchdog 자동 복구 상한(세션이 멈춰도 복구)
BACKGROUND_DEFAULT = True    # F2-a 는 배경 트래픽 기본 ON


# --------------------------------------------------------------------------- #
# 순수 로직
# --------------------------------------------------------------------------- #

def is_healthy(inspect_state: dict) -> bool:
    """`docker inspect` 의 State dict -> 재기동 완료로 볼 수 있는가."""
    if not inspect_state.get("Running"):
        return False
    health = (inspect_state.get("Health") or {}).get("Status")
    if health is None:
        return True
    return health == "healthy"


def watchdog_restore_sh(container_name: str = MINIO_CONTAINER) -> str:
    """watchdog 복구 명령(호스트 sh): minio 재기동."""
    return f"docker start {container_name}"


# --------------------------------------------------------------------------- #
# docker 런타임 (Docker 데몬 필요 — UNVERIFIED)
# --------------------------------------------------------------------------- #

def _client():
    import docker
    return docker.from_env()


def _state(container) -> dict:
    container.reload()
    return container.attrs.get("State", {})


def wait_healthy(container, timeout: int = 120, poll: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        if is_healthy(_state(container)):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(poll)


def inject(down_seconds: int = DEFAULT_DOWN_SECONDS, container_name: str = MINIO_CONTAINER,
           max_seconds: int = DEFAULT_MAX_SECONDS, work_dir: str | None = None,
           background: bool | None = None, traffic_gen_path: str | None = None,
           traffic_target: str | None = None):
    """minio 를 멈추고 down_seconds 유지. watchdog·배경 트래픽을 함께 띄운다."""
    from datetime import datetime, timezone
    wd = supervisor.spawn_watchdog(watchdog_restore_sh(container_name), max_seconds,
                                   tag="f2a", work_dir=work_dir)
    bg = None
    if supervisor.background_enabled(BACKGROUND_DEFAULT, background) and traffic_target:
        bg = supervisor.spawn_background_traffic(traffic_gen_path, traffic_target)

    client = _client()
    container = client.containers.get(container_name)
    t0 = datetime.now(timezone.utc).isoformat()
    print(f"[F2-a] {container_name} stop", flush=True)
    container.stop()
    time.sleep(down_seconds)
    return {"container": container_name, "down_started": t0,
            "down_ended": datetime.now(timezone.utc).isoformat(),
            "watchdog": wd, "background": bg}


def cleanup(meta: dict | None = None, container_name: str = MINIO_CONTAINER,
            timeout: int = 120) -> bool:
    """원복: minio 재기동 후 healthy 확인. watchdog·배경 트래픽도 정리."""
    meta = meta or {}
    container_name = meta.get("container", container_name)
    ok = False
    try:
        client = _client()
        container = client.containers.get(container_name)
        print(f"[F2-a] {container_name} start", flush=True)
        container.start()
        ok = wait_healthy(container, timeout=timeout)
        print(f"[F2-a] healthy={ok}", flush=True)
    finally:
        supervisor.cancel_watchdog(meta.get("watchdog"))
        supervisor.stop_background_traffic(meta.get("background"))
    return ok


def dry_run() -> dict:
    """Docker 없이 중단 계획만. run --dry-run 용."""
    return {"container": MINIO_CONTAINER, "down_seconds": DEFAULT_DOWN_SECONDS,
            "steps": ["stop", f"hold {DEFAULT_DOWN_SECONDS}s", "start", "wait healthy"],
            "watchdog_max_seconds": DEFAULT_MAX_SECONDS, "background_default": BACKGROUND_DEFAULT,
            "env": ["F2A_CONTAINER", "V2_WORK_DIR", "V2_TRAFFIC_GEN"]}


def main():
    meta = None
    recovered = False
    try:
        meta = inject()
        print(f"[F2-a] outage: {meta.get('down_started')}~{meta.get('down_ended')}", flush=True)
    finally:
        recovered = cleanup(meta)
    if not recovered:
        raise SystemExit("[F2-a] minio 재기동/healthy 확인 실패 — 수동 확인 필요")


if __name__ == "__main__":
    main()
