"""
scenarios-v2 공용 런타임 보조 — 자동 복구 watchdog + 배경 트래픽.

- **watchdog**: 장애 시나리오가 주입 시 함께 띄우는 **분리 프로세스**. 최대 지속 시간이 지나면
  실행 세션(Claude Code 등)이 멈춰도 **스스로 복구 명령을 실행**한다. 정상 cleanup 이 먼저
  취소 파일을 만들면 **조용히 종료**(exit 0)한다. 복구 실패는 로그 파일에 남긴다.
- **배경 트래픽**: 시나리오 실행 중 정상 트래픽(측정 PC `traffic_gen` 정상 모드)을 함께 돌리는 옵션.
  traffic_gen 경로는 **인자로 받는다**(아직 저장소에 없을 수 있음 — PR #22). 없으면 조용히 건너뛴다.

실제 프로세스 기동/종료는 측정 PC 런타임 — UNVERIFIED. 순수 로직(스크립트·명령 생성, 경로 산정)은 단위 테스트.
"""

from __future__ import annotations

import os
import shlex
import sys
import tempfile


def detached_process_kwargs(platform: str | None = None) -> dict:
    """Independent Python/traffic workers on POSIX and Windows (no host shell)."""
    import subprocess
    if (platform or os.name) == "nt":
        return {"creationflags": (getattr(subprocess, "DETACHED_PROCESS", 0x8)
                                  | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200))}
    return {"start_new_session": True}


# --------------------------------------------------------------------------- #
# watchdog — 순수 로직
# --------------------------------------------------------------------------- #

def build_watchdog_script(restore_sh: str, timeout_seconds: int,
                          cancel_file: str, log_file: str) -> str:
    """최대 timeout_seconds 동안 cancel_file 을 기다리다, 없으면 restore_sh 를 실행하는 sh 스크립트.
    정상 cleanup 이 cancel_file 을 만들면 조용히 종료(exit 0). 복구 실패는 log_file 에 기록."""
    if timeout_seconds < 1:
        raise ValueError("timeout_seconds 는 1 이상")
    if not restore_sh.strip():
        raise ValueError("restore_sh 가 비어 있음")
    cancel_q = shlex.quote(cancel_file)
    log_q = shlex.quote(log_file)
    return (
        "#!/bin/sh\n"
        f"CANCEL={cancel_q}\n"
        f"LOG={log_q}\n"
        f"TIMEOUT={int(timeout_seconds)}\n"
        "i=0\n"
        "while [ $i -lt $TIMEOUT ]; do\n"
        '  if [ -f "$CANCEL" ]; then rm -f "$CANCEL"; exit 0; fi\n'
        "  sleep 1; i=$((i+1))\n"
        "done\n"
        'if [ -f "$CANCEL" ]; then rm -f "$CANCEL"; exit 0; fi\n'
        f"if {restore_sh}; then\n"
        '  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) watchdog restored" >> "$LOG"\n'
        "else\n"
        '  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) watchdog RESTORE FAILED" >> "$LOG"\n'
        "  exit 1\n"
        "fi\n"
    )


def resolve_work_dir(work_dir: str | None = None) -> str:
    """watchdog 산출물 위치(저장소 밖). 인자 > V2_WORK_DIR env > 임시폴더/v2_watchdog."""
    return (work_dir or os.environ.get("V2_WORK_DIR")
            or os.path.join(tempfile.gettempdir(), "v2_watchdog"))


def watchdog_paths(work_dir: str, tag: str) -> dict:
    """watchdog 스크립트·취소 파일·로그 경로."""
    return {"script": os.path.join(work_dir, f"wd_{tag}.sh"),
            "cancel": os.path.join(work_dir, f"wd_{tag}.cancel"),
            "log": os.path.join(work_dir, f"wd_{tag}.log")}


# --------------------------------------------------------------------------- #
# watchdog — 런타임 (UNVERIFIED)
# --------------------------------------------------------------------------- #

def spawn_watchdog(restore_sh: str, timeout_seconds: int, tag: str,
                   work_dir: str | None = None) -> dict:
    """분리 프로세스(새 세션)로 watchdog 기동. 반환 핸들을 cancel_watchdog 에 넘긴다."""
    import subprocess
    wd = resolve_work_dir(work_dir)
    os.makedirs(wd, exist_ok=True)
    paths = watchdog_paths(wd, tag)
    # 이전 취소 파일이 남아 있으면 제거(새 주입).
    try:
        os.remove(paths["cancel"])
    except OSError:
        pass
    with open(paths["script"], "w", encoding="utf-8") as fh:
        fh.write(build_watchdog_script(restore_sh, timeout_seconds,
                                       paths["cancel"], paths["log"]))
    os.chmod(paths["script"], 0o700)
    proc = subprocess.Popen(["sh", paths["script"]], start_new_session=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[watchdog] tag={tag} pid={proc.pid} timeout={timeout_seconds}s "
          f"(세션이 멈춰도 복구). log={paths['log']}", flush=True)
    return {"pid": proc.pid, "tag": tag, **paths}


def cancel_watchdog(handle: dict | None) -> None:
    """정상 cleanup 완료 → 취소 파일 생성(watchdog 조용히 종료). 핸들 없으면 무시."""
    if not handle:
        return
    try:
        open(handle["cancel"], "w", encoding="utf-8").close()
        print(f"[watchdog] tag={handle.get('tag')} 취소(정상 cleanup 완료)", flush=True)
        proc = handle.get("process")
        if proc is not None:
            import subprocess
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass  # It may be finishing a restore query; never kill recovery mid-query.
    except Exception as exc:  # noqa: BLE001
        print(f"[watchdog] 취소 파일 생성 실패(무시): {exc}", flush=True)


# --------------------------------------------------------------------------- #
# 배경 트래픽 — 순수 로직
# --------------------------------------------------------------------------- #

def background_enabled(scenario_default: bool, override: bool | None) -> bool:
    """override 가 주어지면 그것을, 아니면 시나리오 기본값을 쓴다."""
    return scenario_default if override is None else override


def build_traffic_command(traffic_gen_path: str, base_url: str, run_dir: str,
                          control: str = "none", duration: float | None = None) -> list[str]:
    """정상 모드 배경 트래픽 명령(tools/measurement/traffic_gen.py 인터페이스).
    요청·상태(API 실패 포함)는 traffic_gen 이 run_dir/requests.jsonl 에 기록한다."""
    python = sys.executable if os.name == "nt" else "python3"
    cmd = [python, "-I", traffic_gen_path, "--base", base_url, "--dir", run_dir,
           "--control", control]
    if duration is not None:
        cmd += ["--duration", str(duration)]
    return cmd


# --------------------------------------------------------------------------- #
# 배경 트래픽 — 런타임 (UNVERIFIED)
# --------------------------------------------------------------------------- #

def spawn_background_traffic(traffic_gen_path: str | None, base_url: str,
                             run_dir: str | None = None, control: str = "none",
                             duration: float | None = None) -> dict | None:
    """traffic_gen 경로가 없거나 파일이 없으면 조용히 건너뛴다. 요청·API 실패는 run_dir 에 기록."""
    import subprocess
    if not traffic_gen_path or not os.path.exists(traffic_gen_path):
        print(f"[bg] traffic_gen 없음 — 배경 트래픽 생략: {traffic_gen_path}", flush=True)
        return None
    run_dir = run_dir or os.path.join(resolve_work_dir(), "bg_traffic")
    os.makedirs(run_dir, exist_ok=True)
    cmd = build_traffic_command(traffic_gen_path, base_url, run_dir, control, duration)
    proc = subprocess.Popen(cmd, **detached_process_kwargs(),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[bg] 배경 트래픽 시작 pid={proc.pid} base={base_url} dir={run_dir}", flush=True)
    return {"pid": proc.pid, "process": proc, "cmd": cmd, "run_dir": run_dir}


def stop_background_traffic(handle: dict | None) -> None:
    """배경 트래픽 프로세스 그룹 종료. 핸들 없으면 무시."""
    if not handle:
        return
    try:
        import signal
        import subprocess
        proc = handle.get("process")
        if proc is not None and proc.poll() is not None:
            proc.wait()
            return
        if os.name == "nt":
            # Windows has no killpg. Include traffic worker descendants in its shutdown.
            subprocess.run(["taskkill", "/PID", str(handle["pid"]), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=5, check=False)
        else:
            os.killpg(os.getpgid(handle["pid"]), signal.SIGTERM)
        if proc is not None:
            proc.wait(timeout=5)
        print("[bg] 배경 트래픽 종료", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(f"[bg] 배경 트래픽 종료 실패(무시): {exc}", flush=True)
