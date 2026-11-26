"""
F1-c — OOM 재시작 반복 (scenarios-v2, 2차).

장애 정의: 서비스 메모리 사용이 컨테이너 메모리 한도를 넘어 커널이 프로세스를 죽이고(OOMKilled),
  재시작 정책 때문에 다시 떴다가 또 죽는 **재시작 반복**에 빠진다. F1-b(서서히 누수, 아직 살아 있음)와
  달리 **반복 종료·재시작**이 핵심 증거다.
대조: C-d(정상 재배포·재시작 1회).

주입(권장안 대안): JVM 안에 메모리를 직접 채우는 방법은 OOM killer 가 어느 프로세스를 죽일지
  결정적이지 않다(exec 로 띄운 할당기만 죽고 앱은 멀쩡할 수 있음). 그래서 **메모리 한도를 앱의
  실제 기동 사용량보다 낮게 잠시 내린다**(docker update --memory). 그러면 앱(PID 1)이 기동·동작 중
  한도를 넘어 OOMKilled → restart 정책으로 재기동 → 다시 OOMKilled 가 반복된다.
  이미지·명령·환경변수·볼륨은 그대로다(ddl-auto 영향 없음: 같은 이미지).
정리: 원래 한도(Memory·MemorySwap)를 docker update 로 되돌리고 Running 복귀를 확인한다.
자동 복구: 세션이 멈춰도 max_seconds 뒤 워치독이 원래 한도로 되돌린다.

강도(현실적인 한도 부족 정도): 기동 사용량 대비 한도 비율 weak=0.9, medium=0.75, strong=0.55.
안전: 대상은 상태 비저장 서비스만(DB·MinIO 금지). 한도는 하한(MIN_LIMIT_MIB) 아래로 내리지 않는다.
"""

from __future__ import annotations

import os
import shlex

from v2 import supervisor

TARGET = os.getenv("F1C_TARGET", "leafy-backend")
FORBIDDEN_TARGETS = ("leafy-db", "leafy-minio")
STRENGTH_RATIO = {"weak": 0.9, "medium": 0.75, "strong": 0.55}
DEFAULT_STRENGTH = "medium"
MIN_LIMIT_MIB = 64
DEFAULT_DURATION_SECONDS = 180
DEFAULT_MAX_SECONDS = 300
BACKGROUND_DEFAULT = True
MIB = 1024 * 1024


def assert_target_allowed(target: str) -> None:
    if target in FORBIDDEN_TARGETS:
        raise ValueError(f"대상 금지(상태 저장 서비스): {target}")


def capture_limits(container_attrs: dict) -> dict:
    hc = container_attrs.get("HostConfig", {})
    return {"memory": int(hc.get("Memory") or 0), "memory_swap": int(hc.get("MemorySwap") or 0),
            "restart_policy": (hc.get("RestartPolicy") or {}).get("Name") or ""}


def plan_limit(working_set_bytes: int, strength: str = DEFAULT_STRENGTH) -> int:
    """기동 후 실측 사용량 × 비율 → 새 한도(바이트). 하한 적용."""
    if strength not in STRENGTH_RATIO:
        raise ValueError(f"unknown strength: {strength}")
    if working_set_bytes <= 0:
        raise ValueError("working_set_bytes 실측값 필요")
    return max(MIN_LIMIT_MIB * MIB, int(working_set_bytes * STRENGTH_RATIO[strength]))


def assert_restartable(limits: dict) -> None:
    """재시작 정책이 없으면 '반복'이 안 생기고 서비스가 그냥 죽어 있는다 → 주입 거부."""
    if limits["restart_policy"] in ("", "no"):
        raise ValueError("restart 정책 없음 — OOM 후 재기동이 안 돼 F1-c 주입 금지")
    if limits["memory"] <= 0:
        # docker update 로 '무제한'을 확실히 되돌릴 수 없다 → 원래 한도가 있는 대상만.
        raise ValueError("원래 메모리 한도 없음 — 원복 불확실해 F1-c 주입 금지")


def update_argv(target: str, memory: int, memory_swap: int) -> list[str]:
    """docker update 한도 변경 argv(바이트)."""
    if memory <= 0:
        raise ValueError("memory 는 양수")
    return ["docker", "update", "--memory", str(memory), "--memory-swap", str(memory_swap), target]


def restore_sh(target: str, limits: dict) -> str:
    """워치독 복구(호스트 sh): 원래 한도(Memory·MemorySwap)로 되돌린다."""
    swap = limits["memory_swap"] or limits["memory"]
    return " ".join(shlex.quote(a) for a in update_argv(target, limits["memory"], swap)) + " >/dev/null"


def inject(strength: str = DEFAULT_STRENGTH, target: str = TARGET,
           duration_seconds: int = DEFAULT_DURATION_SECONDS, max_seconds: int = DEFAULT_MAX_SECONDS,
           work_dir: str | None = None, background: bool | None = None,
           traffic_gen_path: str | None = None, traffic_target: str | None = None):
    import subprocess

    import docker
    assert_target_allowed(target)
    c = docker.from_env().containers.get(target)
    limits = capture_limits(c.attrs)
    assert_restartable(limits)
    stats = c.stats(stream=False)
    mem = stats.get("memory_stats", {})
    ws = int(mem.get("usage", 0)) - int((mem.get("stats") or {}).get("inactive_file", 0))
    new = plan_limit(ws, strength)
    wd = supervisor.spawn_watchdog(restore_sh(target, limits), max(max_seconds, duration_seconds + 60),
                                   tag="f1c", work_dir=work_dir)
    bg = None
    if supervisor.background_enabled(BACKGROUND_DEFAULT, background) and traffic_target:
        bg = supervisor.spawn_background_traffic(traffic_gen_path, traffic_target)
    subprocess.run(update_argv(target, new, new), check=True, stdout=subprocess.DEVNULL)
    print(f"[F1-c] strength={strength} working_set={ws // MIB}MiB limit {limits['memory'] // MIB}"
          f"→{new // MIB}MiB duration={duration_seconds}s", flush=True)
    return {"target": target, "limits": limits, "new_limit": new, "watchdog": wd, "background": bg,
            "duration_seconds": duration_seconds}


def cleanup(meta: dict | None) -> None:
    meta = meta or {}
    try:
        if meta.get("target"):
            import subprocess
            subprocess.run(["sh", "-c", restore_sh(meta["target"], meta["limits"])], check=True)
            import docker
            st = docker.from_env().containers.get(meta["target"]).attrs.get("State", {})
            print(f"[F1-c] cleanup: 한도 복원, running={st.get('Running')} "
                  f"restarts 확인 필요(docker inspect RestartCount)", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(f"[F1-c] cleanup 실패(워치독이 복구함): {exc}", flush=True)
    finally:
        supervisor.cancel_watchdog(meta.get("watchdog"))
        supervisor.stop_background_traffic(meta.get("background"))


def dry_run() -> dict:
    return {"target": TARGET, "strength_ratio": STRENGTH_RATIO, "min_limit_mib": MIN_LIMIT_MIB,
            "example_limit_mib_for_400MiB": plan_limit(400 * MIB) // MIB,
            "watchdog_max_seconds": DEFAULT_MAX_SECONDS, "pair_control": "c_d_normal_restart",
            "env": ["F1C_TARGET", "V2_WORK_DIR", "V2_TRAFFIC_GEN"],
            "note": "docker update 로 한도만 임시 하향(이미지·설정 불변), 원래 한도 복원"}


def main(**kw):
    import time
    meta = None
    try:
        meta = inject(**kw)
        time.sleep(meta["duration_seconds"])
    finally:
        cleanup(meta)


if __name__ == "__main__":
    main()
