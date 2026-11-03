"""
F1-b — 메모리 압박·누수 (서서히) (scenarios-v2).

목표(사용자 조건): 현재 룰 HighMemoryUsage(working_set > 0.85, for 5m)에 걸리는 속도로,
  512MiB limit 안에서 OOM 이 나기 전에 경보가 뜨도록 증가율과 상한을 근거와 함께 둔다.

증가량은 **주입 시점의 실제 working set**(cgroup)을 읽어서 정한다. 가정값(baseline)은
  읽기 실패 시 폴백으로만 쓴다.
  - 시작 시 working set 이 0.85(임계) 이상이면 주입하지 않고 중단한다.
  - 증가 중에도 0.94(OOM 가드)에 닿으면 즉시 멈추고 해제한다(할당기가 cgroup 을 자가 감시).

근거(수치):
  - leafy-backend mem_limit = 512 MiB (docker-compose.yml). 룰 임계 = 0.85 → 435.2 MiB.
  - 기준선 측정(backend 평상시 working set) 0.76~0.82. 목표 working_set = 0.88
    (435 < 0.88*512 = 450.6 MiB < 512), OOM 가드 = 0.94 (481.3 MiB).
  - 추가 점유 = target - 현재, 단 (oom_guard - 현재) 로 상한(cap). "서서히": step 씩 interval 초
    간격으로 ramp 후 hold_seconds(≥5m+여유) 유지. ramp 가 급격하면 급속 누수가 되어(미탐 영역)
    for:5m 전에 OOM 위험.

급속 누수(빠른 할당 → for:5m 전 OOM/kill)는 이 룰로는 미탐 — 계획에 명시된 blind spot.

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

MIB = 1024 * 1024
BACKEND_CONTAINER = "leafy-backend"
MEM_LIMIT_BYTES = 512 * MIB
SHM_FILE = "/dev/shm/f1b_leak"

THRESHOLD_FRACTION = 0.85    # 룰 임계
TARGET_FRACTION = 0.88       # 목표 (임계 위, OOM 아래)
OOM_GUARD_FRACTION = 0.94    # 주입 상한 + 증가 중 자가 감시 가드
ASSUMED_BASELINE_FRACTION = 0.79  # 읽기 실패 시 폴백(기준선 0.76~0.82 중앙값)

DEFAULT_STEP_MIB = 16
DEFAULT_STEP_INTERVAL = 15   # 초. ramp 가 급격하지 않도록
DEFAULT_HOLD_SECONDS = 420   # 5분 + 2분 여유 (for:5m 를 넘겨 유지)
DEFAULT_SH_CHUNK_MIB = 4     # sh 할당기 dd 조각 크기


# --------------------------------------------------------------------------- #
# 순수 로직 (단위 테스트 대상)
# --------------------------------------------------------------------------- #

def should_abort_start(current_ws_bytes: int | None, limit_bytes: int = MEM_LIMIT_BYTES,
                       threshold_fraction: float = THRESHOLD_FRACTION) -> bool:
    """시작 가드: working set 을 못 읽거나(안전상 중단) 이미 임계(0.85) 이상이면 주입하지 않는다."""
    if current_ws_bytes is None:
        return True
    return (current_ws_bytes / limit_bytes) >= threshold_fraction


def shm_has_room(extra_bytes: int, shm_avail_bytes: int) -> bool:
    """sh 할당기 시작 가드: 추가 필요량이 /dev/shm 여유 이하인가."""
    return extra_bytes <= shm_avail_bytes


def plan_allocation(limit_bytes: int = MEM_LIMIT_BYTES,
                    current_ws_bytes: int | None = None,
                    target_fraction: float = TARGET_FRACTION,
                    oom_guard_fraction: float = OOM_GUARD_FRACTION,
                    step_mib: int = DEFAULT_STEP_MIB,
                    step_interval: int = DEFAULT_STEP_INTERVAL,
                    hold_seconds: int = DEFAULT_HOLD_SECONDS) -> dict:
    """
    추가로 점유할 바이트와 ramp 일정. extra = target - 현재, cap = oom_guard - 현재 로 상한.
    현재값이 None 이면 ASSUMED_BASELINE_FRACTION 폴백. 결과 working_set 이 임계~OOM가드 사이면 valid.
    """
    if current_ws_bytes is None:
        current_ws_bytes = int(ASSUMED_BASELINE_FRACTION * limit_bytes)
    target_bytes = int(target_fraction * limit_bytes)
    guard_bytes = int(oom_guard_fraction * limit_bytes)

    extra = max(0, target_bytes - current_ws_bytes)
    cap = max(0, guard_bytes - current_ws_bytes)
    extra = min(extra, cap)

    step_bytes = step_mib * MIB
    steps = (extra + step_bytes - 1) // step_bytes if extra > 0 else 0
    resulting_fraction = (current_ws_bytes + extra) / limit_bytes
    valid = (THRESHOLD_FRACTION < resulting_fraction <= oom_guard_fraction) and extra > 0
    return {
        "limit_bytes": limit_bytes, "current_ws_bytes": current_ws_bytes,
        "target_bytes": target_bytes, "guard_bytes": guard_bytes,
        "extra_bytes": extra, "step_bytes": step_bytes, "steps": steps,
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


def inject(container_name: str = BACKEND_CONTAINER):
    import docker
    client = docker.from_env()
    container = client.containers.get(container_name)
    ws = current_working_set(container)
    if should_abort_start(ws):
        raise SystemExit(f"[F1-b] 시작 가드: working set 미측정 또는 이미 임계 이상 — 주입 중단 (ws={ws})")
    plan = plan_allocation(current_ws_bytes=ws)
    print(f"[F1-b] plan={plan}", flush=True)
    if not plan["valid"]:
        raise SystemExit(f"[F1-b] 안전 설계 실패(valid=False) — 주입 중단. plan={plan}")
    # python3 유무는 명령 안에서 분기한다. sh 경로는 /dev/shm 여유를 스스로 확인하고
    # 부족하면 exit 3 로 주입하지 않는다. 두 경로 모두 가드 도달 시 즉시 해제, trap 으로 정리.
    cmd = build_alloc_command(plan)
    container.exec_run(cmd=["sh", "-c", cmd], detach=True)
    print("[F1-b] allocator 실행(detached, cgroup 자가 감시). 가드 도달 시 즉시 해제, 아니면 hold 후 해제.",
          flush=True)
    return plan


def cleanup(container_name: str = BACKEND_CONTAINER, shm_file: str = SHM_FILE) -> None:
    """정리 보강: sh 경로의 /dev/shm 파일을 강제로 삭제한다(trap 이 실패한 경우 대비)."""
    try:
        import docker
        container = docker.from_env().containers.get(container_name)
        container.exec_run(cmd=["sh", "-c", f"rm -f {shm_file}"])
        print(f"[F1-b] cleanup: {shm_file} 삭제 시도", flush=True)
    except Exception as exc:
        print(f"[F1-b] cleanup 실패(무시): {exc}", flush=True)


def dry_run() -> dict:
    """Docker 없이 계획만 계산(폴백 baseline 사용). run --dry-run 용."""
    plan = plan_allocation()
    return {
        "plan": plan,
        "python_allocator_preview": _allocator_py(plan)[:80] + "...",
        "sh_allocator_preview": _allocator_sh(plan)[:80] + "...",
    }


def main():
    inject()


if __name__ == "__main__":
    main()
