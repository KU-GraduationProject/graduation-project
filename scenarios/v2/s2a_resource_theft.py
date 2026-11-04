"""
S2-a — 자원 탈취 (채굴형 CPU) (scenarios-v2).

위협 정의: 침해된 프로세스가 CPU 를 지속적으로 점유한다(채굴 등). 서비스는 죽지 않고 살아
  있지만 자원을 빼앗긴다. 증거는 CPU 사용률 상승 + 서비스의 정상 응답 유지다.

주입: backend 컨테이너 안에서 busy 루프를 강도만큼 띄워 CPU 를 점유한다. 각 루프는
  표식 파일이 있는 동안만 돌고, 안전 상한(timeout)으로도 자동 종료된다 → 무한 점유 방지.
정리: 표식 파일을 지우면 루프가 즉시 끝난다(+ 잔여 프로세스 kill 보강).

강도(strength): 동시 busy 루프(≈점유 코어) 수. 근거는 룰 임계가 아니라 현실적인 채굴 부하다:
  weak=한 코어 수준, medium=두 코어, strong=여러 코어.

자기신고 없음: Loki/pipeline 에 아무것도 쓰지 않는다. 표식 파일명은 중립적이며 탐지 입력에
  들어가지 않는다. 증거는 "실제 CPU 점유"뿐이다.

순수 로직(명령 생성)은 단위 테스트, exec 실행은 Docker 필요 — UNVERIFIED (측정 PC).
"""

from __future__ import annotations

BACKEND_CONTAINER = "leafy-backend"
MARKER = "/tmp/s2a_cpu_load"          # cleanup 표식(중립, 탐지 입력 아님)

STRENGTH_WORKERS = {"weak": 1, "medium": 2, "strong": 4}
DEFAULT_STRENGTH = "medium"
DEFAULT_DURATION_SECONDS = 120        # 안전 상한. 이 시간이 지나면 점유가 자동 종료된다.


# --------------------------------------------------------------------------- #
# 순수 로직 (단위 테스트 대상)
# --------------------------------------------------------------------------- #

def plan_load(strength: str = DEFAULT_STRENGTH,
              duration_seconds: int = DEFAULT_DURATION_SECONDS) -> dict:
    """강도 → busy 루프 수와 지속. 알 수 없는 강도는 오류."""
    if strength not in STRENGTH_WORKERS:
        raise ValueError(f"unknown strength: {strength}")
    if duration_seconds < 1:
        raise ValueError("duration_seconds 는 1 이상")
    return {"strength": strength, "workers": STRENGTH_WORKERS[strength],
            "duration_seconds": duration_seconds}


def build_load_command(plan: dict, marker: str = MARKER) -> str:
    """
    plan['workers'] 개의 busy 루프를 백그라운드로 띄우는 sh 본문.
    각 루프는 표식 파일이 있는 동안만 돌고 timeout 으로도 종료된다(이중 안전).
    """
    n, dur = plan["workers"], plan["duration_seconds"]
    return (
        f"touch {marker}\n"
        f"i=0\n"
        f"while [ $i -lt {n} ]; do\n"
        f"  timeout {dur} sh -c \"while [ -f {marker} ]; do :; done\" &\n"
        f"  i=$((i+1))\n"
        f"done\n"
    )


# --------------------------------------------------------------------------- #
# docker 런타임 (UNVERIFIED)
# --------------------------------------------------------------------------- #

def inject(strength: str = DEFAULT_STRENGTH, container_name: str = BACKEND_CONTAINER,
           duration_seconds: int = DEFAULT_DURATION_SECONDS):
    import docker
    container = docker.from_env().containers.get(container_name)
    plan = plan_load(strength, duration_seconds)
    cmd = build_load_command(plan)
    container.exec_run(cmd=["sh", "-c", cmd], detach=True)
    print(f"[S2-a] strength={strength} workers={plan['workers']} "
          f"duration={duration_seconds}s (detached, 자동 종료·표식 정리)", flush=True)
    return plan


def cleanup(container_name: str = BACKEND_CONTAINER, marker: str = MARKER) -> None:
    """표식 제거 → busy 루프 즉시 종료. 잔여 프로세스는 kill 로 보강. 재시작 안 함."""
    try:
        import docker
        container = docker.from_env().containers.get(container_name)
        container.exec_run(cmd=["sh", "-c",
                                f"rm -f {marker}; pkill -f 'while [ -f {marker} ]' 2>/dev/null; true"])
        print(f"[S2-a] cleanup: {marker} 제거, 잔여 루프 종료 시도", flush=True)
    except Exception as exc:
        print(f"[S2-a] cleanup 실패(무시): {exc}", flush=True)


def dry_run() -> dict:
    plan = plan_load()
    return {"plan": plan, "command_preview": build_load_command(plan)[:60] + "..."}


def main():
    try:
        inject()
        import time
        time.sleep(DEFAULT_DURATION_SECONDS)
    finally:
        cleanup()


if __name__ == "__main__":
    main()
