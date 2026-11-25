"""
C-d — 정상 재배포·재시작 (F1-c·F3 대조, scenarios-v2 2차).

정상 상황: 운영자가 **원본 이미지·설정 그대로** 서비스를 한 번 재시작한다(설정 반영·정기 재기동).
  컨테이너가 한 번 내려갔다 올라오고 곧 healthy 로 돌아온다. 반복 재시작(F1-c)이나 기동 실패(F3-a/b)와
  구분돼야 한다.

주입: docker restart 1회. 이미지·명령·환경변수 불변(재생성 아님).
정리: 재시작 후 Running(+healthy) 과 이미지 id 불변을 확인한다. 추가 원복 없음.
안전: 상태 저장 서비스(DB·MinIO)는 대상 금지.
"""

from __future__ import annotations

import os

TARGET = os.getenv("CD_TARGET", "leafy-backend")
FORBIDDEN_TARGETS = ("leafy-db", "leafy-minio")
DEFAULT_WAIT_SECONDS = 120


def assert_target_allowed(target: str) -> None:
    if target in FORBIDDEN_TARGETS:
        raise ValueError(f"대상 금지(상태 저장 서비스): {target}")


def restart_argv(target: str = TARGET) -> list[str]:
    return ["docker", "restart", target]


def verify_same(before: dict, after: dict) -> dict:
    """재시작 전후 이미지·명령·env 가 같은지, 실행 중인지."""
    b, a = before.get("Config", {}), after.get("Config", {})
    st = after.get("State", {})
    health = (st.get("Health") or {}).get("Status")
    return {"image_same": before.get("Image") == after.get("Image"),
            "config_same": (b.get("Cmd"), b.get("Entrypoint"), sorted(b.get("Env") or []))
            == (a.get("Cmd"), a.get("Entrypoint"), sorted(a.get("Env") or [])),
            "running": bool(st.get("Running")), "healthy": health in (None, "healthy")}


def inject(target: str = TARGET, wait_seconds: int = DEFAULT_WAIT_SECONDS):
    import subprocess
    import time

    import docker
    assert_target_allowed(target)
    client = docker.from_env()
    before = client.containers.get(target).attrs
    subprocess.run(restart_argv(target), check=True, stdout=subprocess.DEVNULL)
    deadline = time.time() + wait_seconds
    res = {}
    while time.time() < deadline:
        res = verify_same(before, client.containers.get(target).attrs)
        if res["running"] and res["healthy"]:
            break
        time.sleep(3)
    # env 값은 출력하지 않는다(비밀 포함 가능) — 비교 결과만.
    print(f"[C-d] restart {target}: {res}", flush=True)
    return res


def dry_run() -> dict:
    return {"target": TARGET, "argv": restart_argv(), "pair": ["f1_c_oom_restart", "f3_b_bad_env_config"],
            "env": ["CD_TARGET"], "note": "원본 이미지·설정 그대로 1회 재시작"}


def main(**kw):
    return inject(**kw)


if __name__ == "__main__":
    main()
