"""
category1_infra/cpu_stress.py
─────────────────────────────
leafy-backend 컨테이너 안에서 stress-ng(없으면 Python 순수 루프)로
CPU 고갈 시뮬레이션을 실행하고, 시작/종료 시간을 anomaly_log.json에 기록한다.
"""

import docker
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common.verifier import ScenarioVerifier

# ── 경로 설정 ──────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH   = os.path.join(SCRIPT_DIR, "..", "logs", "anomaly_log.json")
LOG_PATH   = os.path.normpath(LOG_PATH)

CONTAINER_NAME = "leafy-backend"
STRESS_DURATION = 300         # 컨테이너 내 스트레스 지속 시간(초)
CPU_WORKERS     = 0           # 0 = 논리 CPU 수만큼 자동
CPU_ALERT_QUERY = 'sum(irate(container_cpu_usage_seconds_total{id=~"/docker/.+",cpu="total"}[30s]))'
CPU_ALERT_THRESHOLD = 0.5


# ── 로그 유틸 ──────────────────────────────────────────────────────────────────
def _load_log() -> list:
    if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) > 0:
        with open(LOG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


def _save_log(records: list) -> None:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)


def record_event(scenario: str, start: str, end: str, status: str, detail: str = "") -> None:
    records = _load_log()
    records.append({
        "scenario": scenario,
        "category": "infra",
        "start_time": start,
        "end_time":   end,
        "status":     status,
        "detail":     detail,
    })
    _save_log(records)
    print(f"[LOG] {scenario} | {status} | {start} → {end}")


# ── 스트레스 명령 선택 ──────────────────────────────────────────────────────────
def _build_stress_cmd(workers: int, duration: int) -> str:
    w = workers if workers > 0 else "$(nproc)"
    # stress-ng 우선, 없으면 dd로 CPU 점유
    # dd if=/dev/zero of=/dev/null: 커널 데이터 복사를 무한 반복해 CPU를 점유.
    # w개의 dd 프로세스를 백그라운드로 띄운 뒤 duration 초 후 모두 종료한다.
    dd_loop = (
        f"PIDS=''; "
        f"for i in $(seq 1 {w}); do "
        f"  dd if=/dev/zero of=/dev/null bs=1M & PIDS=\"$PIDS $!\"; "
        f"done; "
        f"sleep {duration}; "
        f"kill $PIDS 2>/dev/null; "
        f"wait"
    )
    return (
        f"if command -v stress-ng >/dev/null 2>&1; then "
        f"  stress-ng --cpu {w} --timeout {duration}s --metrics-brief; "
        f"elif command -v stress >/dev/null 2>&1; then "
        f"  stress --cpu {w} --timeout {duration}; "
        f"else "
        f"  {dd_loop}; "
        f"fi"
    )


# ── 메인 ───────────────────────────────────────────────────────────────────────
def main():
    scenario = "cpu_stress"
    client = docker.from_env()

    # ── verifier 초기화 ──
    verifier = ScenarioVerifier(
        scenario_name="cpu_stress",
        alert_name="HighCpuUsage",
        hypothesis="cpu_stress 실행 2분 내 HighCpuUsage FIRING",
        steady_state_query=CPU_ALERT_QUERY,
        steady_state_threshold=CPU_ALERT_THRESHOLD,
        metric_label="현재 CPU",
        metric_unit="%",
        metric_scale=100.0,
    )

    # 1단계: Steady State 확인
    verifier.check_steady_state()

    # 2단계: Hypothesis 출력
    verifier.print_hypothesis()

    # repeat_interval 사전 체크
    verifier.check_repeat_interval()
    verifier.wait_for_alert_inactive(timeout=90)

    # 3단계: 타이머 시작
    verifier.start_timer()

    # ── 기존 공격 코드 (그대로) ──
    print(f"[*] 시나리오 시작: {scenario}")
    print(f"[*] 대상 컨테이너: {CONTAINER_NAME}")
    print(f"[*] 스트레스 지속: {STRESS_DURATION}초")

    start_time = datetime.now(timezone.utc).isoformat()

    try:
        container = client.containers.get(CONTAINER_NAME)
    except docker.errors.NotFound:
        end_time = datetime.now(timezone.utc).isoformat()
        record_event(scenario, start_time, end_time, "error",
                     f"컨테이너 '{CONTAINER_NAME}' 를 찾을 수 없습니다.")
        print(f"[!] 컨테이너 '{CONTAINER_NAME}' 없음. 종료.", file=sys.stderr)
        sys.exit(1)

    cmd = _build_stress_cmd(CPU_WORKERS, STRESS_DURATION)
    print(f"[*] exec 명령 전송 중...")

    stress_result = {"status": "running", "output": ""}

    def _run_stress() -> None:
        try:
            exit_code, output = container.exec_run(
                cmd=["sh", "-c", cmd],
                stdout=True,
                stderr=True,
                stream=False,
            )
            output_str = output.decode("utf-8", errors="replace") if output else ""
            stress_result["status"] = "success" if exit_code == 0 else f"exit_code={exit_code}"
            stress_result["output"] = output_str
            print(f"[*] 완료 (exit={exit_code})")
            if output_str.strip():
                print(f"[OUTPUT]\n{output_str.strip()}")
        except Exception as e:
            stress_result["status"] = "error"
            stress_result["output"] = str(e)
            print(f"[!] exec 실패: {e}", file=sys.stderr)

    stress_thread = threading.Thread(target=_run_stress, name="cpu-stress-exec", daemon=True)
    stress_thread.start()

    # 4단계: Alert 발화 확인 + MTTD 측정
    result = verifier.verify(timeout=STRESS_DURATION + 60, poll_interval=3)

    stress_thread.join()
    status = stress_result["status"]
    output_str = stress_result["output"]

    end_time = datetime.now(timezone.utc).isoformat()
    record_event(scenario, start_time, end_time, status, output_str[:500])
    print(f"[*] 시나리오 종료: {scenario}")

    # ── 5단계: 결과 기록 ──
    verifier.log_result(result)
    # ↓ 추가
    from common.result_viewer import ResultViewer
    ResultViewer("HighCpuUsage", "cpu_stress").show(
        mttd_seconds=result.mttd_seconds,
        mtta_seconds=result.mtta_seconds,
    )


SCENARIO_META = {
    "id":             "cpu_stress",
    "label":          "CPU 스트레스",
    "subtitle":       "dd/stress-ng로 leafy-backend CPU 고갈",
    "category":       "인프라",
    "owasp":          None,
    "mitre":          None,
    "container":      "leafy-backend",
    "loki_container": "backend",
    "alert_name":     "HighCpuUsage",
    "alert_fires":    True,
    "blind_spot":     False,
    "module":         "category1_infra.cpu_stress",
    "custom_panel":   None,
}

if __name__ == "__main__":
    main()
