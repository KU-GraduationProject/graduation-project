"""
F1-b — 메모리 압박·누수 (서서히) (scenarios-v2).

위협 정의: 서비스가 회수되지 않는 메모리를 시간에 걸쳐 쌓는다(누수). 누수는 자가 치유되지
  않고 재기동 전까지 유지된다.

강도(strength) = **누수 속도(MiB/분) × 지속 시간(분)**. 목표 사용률은 두지 않는다.
  근거는 실제 메모리 누수 패턴이다:
    - weak   (서서히): 요청마다 작은 객체가 조금씩 남는 누수. 분당 수 MiB 이하로 오래 샌다.
    - medium (중간)  : 캐시·세션이 정리되지 않고 쌓이는 누수. 분당 수 MiB 수준.
    - strong (빠름)  : 큰 버퍼·컬렉션이 계속 커지는 누수. 분당 10MiB 안팎으로 빠르게 쌓인다.
  초 단위로 한계까지 치솟는 급속 누수는 강도가 아니라 별도 형태 변형(fast-spike)으로 다룬다.
  최종 점유량은 강도가 정하지 않는다 — 상한은 아래 OOM 안전 가드가 막는다.

OOM 안전 가드(룰과 무관한 안전장치):
  - 주입 시점의 **실제 working set**(cgroup)을 읽어 남은 여유(OOM 가드까지)를 구한다.
    가정 baseline 은 읽기 실패 시(dry-run) 폴백으로만 쓴다.
  - 시작 가드: working set 을 못 읽거나 이미 OOM 가드(0.94) 이상이면 주입하지 않는다.
  - 상한(cap): 주입량 = min(속도×지속, OOM가드 - 현재). 여유가 있으면 주입량은 항상 > 0.
  - 증가 가드: 증가 중 0.94 에 닿으면 즉시 멈추고 해제(할당기가 cgroup 자가 감시).
  - sh 경로: /dev/shm 여유(df) 부족 시 주입 안 함(exit 3), trap 으로 파일 정리.

할당기 실행 수단 (둘 다 cgroup 자가 감시 + 즉시 해제):
  1순위 python3(컨테이너 내부). 익명 메모리를 늘리며 cgroup(memory.current/memory.max v2,
     usage_in_bytes v1)을 읽어 OOM 가드에 닿으면 즉시 멈추고 해제.
  python3 가 없으면 **sh 할당기**로 실행한다(중단하지 않음):
     dd 로 /dev/shm 에 chunk(4MiB)씩 append → tmpfs(shmem)라 쓴 바이트가 컨테이너 cgroup
     메모리 = working_set 에 잡힌다(page cache 가 아닌 shmem 이라 inactive_file 로 빠지지 않음).
     매 chunk 전에 cgroup 을 읽어 0.94 이상이면 즉시 멈추고 파일 삭제.
     시작 시 추가 필요량이 /dev/shm 여유(df)보다 크면 주입하지 않고 중단(exit 3).
     trap 으로 EXIT/INT/TERM 시 /dev/shm 파일을 반드시 삭제한다.

바이트 산정·가드 판정·할당기 스크립트 생성은 이미지 무관 순수 로직이라 단위 테스트한다.
실제 exec 실행은 Docker 가 필요 — UNVERIFIED (측정 PC).
"""

from __future__ import annotations

import shlex

from v2 import supervisor

MIB = 1024 * 1024
BACKEND_CONTAINER = "leafy-backend"
MEM_LIMIT_BYTES = 512 * MIB
SHM_FILE = "/dev/shm/f1b_leak"

OOM_GUARD_FRACTION = 0.94    # OOM 안전 가드(상한 + 증가 중 자가 감시). 룰과 무관.
ASSUMED_BASELINE_FRACTION = 0.79  # 읽기 실패 시 폴백(기준선 0.76~0.82 중앙값)

DEFAULT_MAX_SECONDS = 600    # watchdog 자동 복구 상한(세션이 멈춰도 복구)
BACKGROUND_DEFAULT = False   # F1-b 는 배경 트래픽 기본 OFF

# 강도 = 누수 속도(MiB/분) × 지속(분). 근거는 실제 누수 패턴(서서히/중간/빠름)이다.
STRENGTH_PROFILE = {
    "weak":   {"rate_mib_per_min": 2, "duration_min": 12},   # 서서히: 작은 객체가 조금씩 남음
    "medium": {"rate_mib_per_min": 5, "duration_min": 10},   # 중간: 캐시·세션 미정리 누적
    "strong": {"rate_mib_per_min": 9, "duration_min": 8},    # 빠름: 큰 버퍼·컬렉션 증가
}
DEFAULT_STRENGTH = "medium"

DEFAULT_STEP_INTERVAL = 15   # 초. 속도를 이 간격의 step 으로 나눠 서서히 늘린다
DEFAULT_HOLD_SECONDS = 420   # 지속 유지(누수는 자가 치유 안 됨). 실험·안전상 유한 구간으로 둔다.
DEFAULT_SH_CHUNK_MIB = 4     # sh 할당기 dd 조각 크기


# --------------------------------------------------------------------------- #
# 순수 로직 (단위 테스트 대상)
# --------------------------------------------------------------------------- #

def should_abort_start(current_ws_bytes: int | None, limit_bytes: int = MEM_LIMIT_BYTES,
                       oom_guard_fraction: float = OOM_GUARD_FRACTION) -> bool:
    """시작 안전 가드: working set 을 못 읽으면 중단, 이미 OOM 가드(0.94) 이상이면 더 올리지 않는다."""
    if current_ws_bytes is None:
        return True
    return (current_ws_bytes / limit_bytes) >= oom_guard_fraction


def shm_has_room(extra_bytes: int, shm_avail_bytes: int) -> bool:
    """sh 할당기 시작 가드: 추가 필요량이 /dev/shm 여유 이하인가."""
    return extra_bytes <= shm_avail_bytes


def plan_allocation(limit_bytes: int = MEM_LIMIT_BYTES,
                    current_ws_bytes: int | None = None,
                    strength: str = DEFAULT_STRENGTH,
                    oom_guard_fraction: float = OOM_GUARD_FRACTION,
                    step_interval: int = DEFAULT_STEP_INTERVAL,
                    hold_seconds: int = DEFAULT_HOLD_SECONDS) -> dict:
    """
    누수 계획. 요청량 = 속도(MiB/분) × 지속(분). 주입량 = min(요청량, OOM가드 - 현재).
    step 은 속도를 step_interval 로 나눈 크기라 ramp 기울기가 곧 누수 속도다.
    현재값이 None 이면 ASSUMED_BASELINE_FRACTION 폴백. 여유가 있으면 주입량 > 0 이고 valid.
    여유가 없으면(현재 ≥ OOM 가드) 주입량 0·invalid — 이 경우는 should_abort_start 가 먼저 막는다.
    """
    if strength not in STRENGTH_PROFILE:
        raise ValueError(f"unknown strength: {strength}")
    if current_ws_bytes is None:
        current_ws_bytes = int(ASSUMED_BASELINE_FRACTION * limit_bytes)
    prof = STRENGTH_PROFILE[strength]
    rate, duration_min = prof["rate_mib_per_min"], prof["duration_min"]

    guard_bytes = int(oom_guard_fraction * limit_bytes)
    headroom = max(0, guard_bytes - current_ws_bytes)
    requested = rate * duration_min * MIB
    extra = min(requested, headroom)

    step_bytes = max(1, int(rate * MIB * step_interval / 60))
    steps = (extra + step_bytes - 1) // step_bytes if extra > 0 else 0
    resulting_fraction = (current_ws_bytes + extra) / limit_bytes
    valid = extra > 0 and resulting_fraction <= oom_guard_fraction
    return {
        "strength": strength, "rate_mib_per_min": rate, "duration_min": duration_min,
        "limit_bytes": limit_bytes, "current_ws_bytes": current_ws_bytes,
        "guard_bytes": guard_bytes, "requested_bytes": requested,
        "extra_bytes": extra, "capped": extra < requested,
        "step_bytes": step_bytes, "steps": steps,
        "step_interval": step_interval, "hold_seconds": hold_seconds,
        "oom_guard_fraction": oom_guard_fraction,
        "resulting_fraction": resulting_fraction, "valid": valid,
    }


def _shq(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def _allocator_py(plan: dict) -> str:
    """컨테이너 내부 python 할당기 소스(익명 메모리 + cgroup 자가 감시)."""
    extra, step = plan["extra_bytes"], plan["step_bytes"]
    interval, hold = plan["step_interval"], plan["hold_seconds"]
    guard = plan["oom_guard_fraction"]
    return (
        "import time\n"
        f"step={step}\ntotal={extra}\ninterval={interval}\nhold={hold}\nguard={guard}\n"
        "def ul():\n"
        "    try:\n"
        "        cur=int(open(\"/sys/fs/cgroup/memory.current\").read())\n"
        "        mx=open(\"/sys/fs/cgroup/memory.max\").read().strip()\n"
        "        lim=None if mx==\"max\" else int(mx)\n"
        "        return cur,lim\n"
        "    except Exception:\n"
        "        pass\n"
        "    try:\n"
        "        cur=int(open(\"/sys/fs/cgroup/memory/memory.usage_in_bytes\").read())\n"
        "        lim=int(open(\"/sys/fs/cgroup/memory/memory.limit_in_bytes\").read())\n"
        "        return cur,lim\n"
        "    except Exception:\n"
        "        return None,None\n"
        "buf=bytearray(); grown=0; hit=False\n"
        "while grown<total:\n"
        "    cur,lim=ul()\n"
        "    if cur and lim and cur/lim>=guard:\n"
        "        hit=True; break\n"
        "    n=min(step,total-grown); buf.extend(b\"x\"*n); grown+=n; time.sleep(interval)\n"
        "if not hit:\n"
        "    time.sleep(hold)\n"
        "del buf\n"
    )


def _allocator_sh(plan: dict, chunk_mib: int = DEFAULT_SH_CHUNK_MIB,
                  shm_file: str = SHM_FILE) -> str:
    """
    컨테이너 내부 sh 할당기 소스. dd 로 /dev/shm 에 chunk 씩 append 하며 cgroup 을 감시한다.
    작은따옴표를 쓰지 않는다(_shq 안전 포장). 정수 비교로 가드(cur*100 >= lim*94)를 판정한다.
    """
    extra = plan["extra_bytes"]
    chunk = chunk_mib * MIB
    # ramp 속도를 python 경로와 맞춘다: step 당 interval → chunk 당 interval*chunk/step.
    per_chunk_interval = max(1, round(plan["step_interval"] * chunk / plan["step_bytes"]))
    hold = plan["hold_seconds"]
    gpct = int(plan["oom_guard_fraction"] * 100)
    return (
        f"F={shm_file}\n"
        "trap \"rm -f $F\" EXIT INT TERM\n"
        "rm -f $F\n"
        f"TOTAL={extra}; CHUNK={chunk}; INTERVAL={per_chunk_interval}; HOLD={hold}; GPCT={gpct}\n"
        # /dev/shm 여유(KiB) 확인 — 추가 필요량보다 작으면 주입 안 하고 중단
        "AVAIL=$(df -kP /dev/shm | tail -1 | tr -s \" \" | cut -d\" \" -f4)\n"
        "NEEDK=$((TOTAL/1024))\n"
        "if [ -z \"$AVAIL\" ] || [ \"$AVAIL\" -lt \"$NEEDK\" ]; then "
        "echo \"[F1-b][sh] /dev/shm room insufficient avail=${AVAIL}KiB need=${NEEDK}KiB\"; exit 3; fi\n"
        "ul() {\n"
        "  if [ -r /sys/fs/cgroup/memory.current ]; then\n"
        "    CUR=$(cat /sys/fs/cgroup/memory.current); MX=$(cat /sys/fs/cgroup/memory.max)\n"
        "    if [ \"$MX\" = \"max\" ]; then LIM=0; else LIM=$MX; fi\n"
        "  elif [ -r /sys/fs/cgroup/memory/memory.usage_in_bytes ]; then\n"
        "    CUR=$(cat /sys/fs/cgroup/memory/memory.usage_in_bytes); LIM=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes)\n"
        "  else CUR=0; LIM=0; fi\n"
        "}\n"
        "GROWN=0; HIT=0\n"
        "while [ $GROWN -lt $TOTAL ]; do\n"
        "  ul\n"
        "  if [ \"$LIM\" -gt 0 ] && [ $((CUR*100)) -ge $((LIM*GPCT)) ]; then HIT=1; break; fi\n"
        "  dd if=/dev/zero bs=$CHUNK count=1 >> $F 2>/dev/null\n"
        "  GROWN=$((GROWN+CHUNK)); sleep $INTERVAL\n"
        "done\n"
        "if [ $HIT -eq 0 ]; then sleep $HOLD; fi\n"
        "rm -f $F\n"
    )


def build_alloc_command(plan: dict) -> str:
    """python3 가 있으면 python 할당기, 없으면 sh 할당기를 고르는 sh -c 본문."""
    py = _shq(_allocator_py(plan))
    sh = _shq(_allocator_sh(plan))
    return (
        "if command -v python3 >/dev/null 2>&1; then "
        f"python3 -c \"$(printf '%s' {py})\"; "
        f"else sh -c \"$(printf '%s' {sh})\"; fi"
    )


# --------------------------------------------------------------------------- #
# docker 런타임 (UNVERIFIED)
# --------------------------------------------------------------------------- #

def current_working_set(container) -> int | None:
    """working_set = usage - inactive_file (룰과 같은 정의). 실패 시 None."""
    try:
        container.reload()
        st = container.stats(stream=False)
        mem = st.get("memory_stats", {})
        usage = mem.get("usage")
        inactive = (mem.get("stats") or {}).get("inactive_file", 0)
        if usage is None:
            return None
        return max(0, usage - inactive)
    except Exception:
        return None


def watchdog_restore_sh(container_name: str = BACKEND_CONTAINER) -> str:
    """watchdog 복구 명령(호스트 sh): 컨테이너 재시작(F1-b 조치 = RESTART). 누수 메모리 회수."""
    return f"docker restart {shlex.quote(container_name)}"


def inject(container_name: str = BACKEND_CONTAINER, strength: str = DEFAULT_STRENGTH,
           max_seconds: int = DEFAULT_MAX_SECONDS, work_dir: str | None = None,
           background: bool | None = None, traffic_gen_path: str | None = None,
           traffic_target: str | None = None):
    import docker
    client = docker.from_env()
    container = client.containers.get(container_name)
    ws = current_working_set(container)
    if should_abort_start(ws):
        raise SystemExit(f"[F1-b] 시작 가드: working set 미측정 또는 이미 OOM 가드 이상 — 주입 중단 (ws={ws})")
    plan = plan_allocation(current_ws_bytes=ws, strength=strength)
    print(f"[F1-b] plan={plan}", flush=True)
    if not plan["valid"]:
        raise SystemExit(f"[F1-b] 안전 설계 실패(valid=False) — 주입 중단. plan={plan}")

    wd = supervisor.spawn_watchdog(watchdog_restore_sh(container_name), max_seconds,
                                   tag="f1b", work_dir=work_dir)
    bg = None
    if supervisor.background_enabled(BACKGROUND_DEFAULT, background) and traffic_target:
        bg = supervisor.spawn_background_traffic(traffic_gen_path, traffic_target)

    # python3 유무는 명령 안에서 분기한다. sh 경로는 /dev/shm 여유를 스스로 확인하고
    # 부족하면 exit 3 로 주입하지 않는다. 두 경로 모두 가드 도달 시 즉시 해제, trap 으로 정리.
    cmd = build_alloc_command(plan)
    container.exec_run(cmd=["sh", "-c", cmd], detach=True)
    print("[F1-b] allocator 실행(detached, cgroup 자가 감시). 가드 도달 시 즉시 해제, 아니면 hold 후 해제.",
          flush=True)
    return {"plan": plan, "container": container_name, "watchdog": wd, "background": bg}


def cleanup(meta: dict | None = None, container_name: str = BACKEND_CONTAINER,
            shm_file: str = SHM_FILE) -> None:
    """정리 보강: sh 경로의 /dev/shm 파일 삭제. watchdog·배경 트래픽도 정리."""
    meta = meta or {}
    container_name = meta.get("container", container_name)
    try:
        import docker
        container = docker.from_env().containers.get(container_name)
        container.exec_run(cmd=["sh", "-c", f"rm -f {shm_file}"])
        print(f"[F1-b] cleanup: {shm_file} 삭제 시도", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(f"[F1-b] cleanup 실패(watchdog 이 복구함): {exc}", flush=True)
    finally:
        supervisor.cancel_watchdog(meta.get("watchdog"))
        supervisor.stop_background_traffic(meta.get("background"))


def dry_run() -> dict:
    """Docker 없이 계획만 계산(폴백 baseline 사용). run --dry-run 용."""
    plan = plan_allocation()
    return {
        "plan": plan,
        "python_allocator_preview": _allocator_py(plan)[:80] + "...",
        "sh_allocator_preview": _allocator_sh(plan)[:80] + "...",
        "watchdog_max_seconds": DEFAULT_MAX_SECONDS,
        "background_default": BACKGROUND_DEFAULT,
        "env": ["V2_WORK_DIR", "V2_TRAFFIC_GEN"],
    }


def main():
    meta = None
    try:
        meta = inject()
    finally:
        cleanup(meta)


if __name__ == "__main__":
    main()
