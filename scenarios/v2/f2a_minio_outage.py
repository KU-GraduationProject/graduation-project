"""
F2-a — MinIO 중단 (scenarios-v2).

주입: leafy-minio 컨테이너를 멈춰(stop) 오브젝트 스토리지를 사용 불가 상태로 만든다.
정리: 반드시 재기동(start)하고 healthy 가 될 때까지 기다린다.
      remediation 이 disabled 라 자동 복구가 없으므로 정리 단계가 원복을 책임진다.

데이터 안전: stop ≠ delete. minio_data 볼륨은 건드리지 않는다. 멈췄다 다시 켤 뿐이다.
자기신고 없음: 이 스크립트는 Loki/pipeline 에 아무것도 쓰지 않는다. 증거는 "minio 가 실제로
      멈춰서 backend 가 남기는 오류"뿐이다. 탐지 룰은 측정 PC에서 그 오류 로그를 확인한 뒤
      신설한다(배치 ①에서는 주입·정리만).

순수 로직(docker 불필요, 단위 테스트 대상)과 docker 런타임(UNVERIFIED)을 분리한다.
"""

from __future__ import annotations

import time

MINIO_CONTAINER = "leafy-minio"
DEFAULT_DOWN_SECONDS = 120   # backend 가 오류를 충분히 남기도록 유지하는 시간


# --------------------------------------------------------------------------- #
# 순수 로직
# --------------------------------------------------------------------------- #

def is_healthy(inspect_state: dict) -> bool:
    """
    `docker inspect` 의 State dict -> 재기동 완료로 볼 수 있는가.
    healthcheck 가 있으면 Running 이고 Health.Status == healthy 여야 한다.
    healthcheck 가 없으면 Running 만으로 판단한다.
    """
    if not inspect_state.get("Running"):
        return False
    health = (inspect_state.get("Health") or {}).get("Status")
    if health is None:
        return True
    return health == "healthy"


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


def inject(down_seconds: int = DEFAULT_DOWN_SECONDS, container_name: str = MINIO_CONTAINER):
    """minio 를 멈추고 down_seconds 유지한다. 반환: 중단 시작/종료 시각(ISO)."""
    from datetime import datetime, timezone
    client = _client()
    container = client.containers.get(container_name)
    t0 = datetime.now(timezone.utc).isoformat()
    print(f"[F2-a] {container_name} stop", flush=True)
    container.stop()
    time.sleep(down_seconds)
    return {"container": container_name, "down_started": t0,
            "down_ended": datetime.now(timezone.utc).isoformat()}


def cleanup(container_name: str = MINIO_CONTAINER, timeout: int = 120) -> bool:
    """
    원복: minio 재기동 후 healthy 확인. 사용자 요구 — 정리에 재기동 + 정상 응답 확인 포함.
    앱 레벨 최종 확인(업로드/`/files/` 응답)은 측정 PC에서 한다.
    """
    client = _client()
    container = client.containers.get(container_name)
    print(f"[F2-a] {container_name} start", flush=True)
    container.start()
    ok = wait_healthy(container, timeout=timeout)
    print(f"[F2-a] healthy={ok}", flush=True)
    return ok


def dry_run() -> dict:
    """Docker 없이 중단 계획만. run --dry-run 용."""
    return {"container": MINIO_CONTAINER, "down_seconds": DEFAULT_DOWN_SECONDS,
            "steps": ["stop", f"hold {DEFAULT_DOWN_SECONDS}s", "start", "wait healthy"]}


def main():
    try:
        meta = inject()
        print(f"[F2-a] outage: {meta}", flush=True)
    finally:
        # 중단 주입 중 예외가 나도 반드시 원복을 시도한다.
        recovered = cleanup()
    if not recovered:
        raise SystemExit("[F2-a] minio 재기동/healthy 확인 실패 — 수동 확인 필요")


if __name__ == "__main__":
    main()
