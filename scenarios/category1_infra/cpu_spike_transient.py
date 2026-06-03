"""
category1_infra/cpu_spike_transient.py
────────────────────────────────────────
절반 코어(nproc/2)만 60초 동안 부하를 줘 CPU를 급등시킨 뒤 자연 해소시키는 시나리오.
서비스는 계속 응답 중 → RESTART 대신 THROTTLE이 적합한 케이스를 재현한다.

[cpu_stress.py와의 차이]
- cpu_stress:          전체 코어 × 300초 → RESTART 케이스
- cpu_spike_transient: 절반 코어 × 60초  → THROTTLE 케이스 (급등 후 자연 회복)

[구현 의도]
- HighCpuUsage 경보는 동일하게 발화
- 부하 지속 시간이 짧고 서비스는 응답 중 → LLM이 재시작보다 자원 제한을 선택해야 함
- Few-shot 예제: THROTTLE + action_risk=medium 생성 목적

탐지 포인트: HighCpuUsage (Prometheus → AlertManager → Pipeline)
탐지 조건:  sum by(name)(irate(cpu_total[30s])) > 0.5 for 30s
AIOps 포인트: CPU 급등 + 서비스 생존 + 단기 패턴 → THROTTLE 권고
"""

import docker
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common.verifier import ScenarioVerifier, VerifyResult

# ── 설정 ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH   = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "logs", "anomaly_log.json"))

CONTAINER_NAME      = "leafy-backend"
STRESS_DURATION     = 60       # 60초만 부하 (cpu_stress는 300초)
CPU_ALERT_QUERY     = 'sum(irate(container_cpu_usage_seconds_total{id=~"/docker/.+",cpu="total"}[30s]))'
CPU_ALERT_THRESHOLD = 0.5


# ── 로그 유틸 ─────────────────────────────────────────────────────────────────
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
        "scenario": scenario, "category": "infra",
        "start_time": start, "end_time": end,
        "status": status, "detail": detail,
    })
    _save_log(records)
    print(f"[LOG] {scenario} | {status} | {start} → {end}")


# ── 스트레스 명령 (절반 코어) ──────────────────────────────────────────────────
def _build_stress_cmd(duration: int) -> str:
    """
    전체 코어의 절반만 사용 — CPU 급등하지만 다른 프로세스에 여유 코어 남아있음.
    이 패턴이 THROTTLE 케이스의 핵심: 완전 고갈이 아니라 제한이 적합한 상황.
    """
    # $(( $(nproc) / 2 + 1 )): 최소 1개 보장 (단일 코어 환경 대응)
    half_w = "$(( $(nproc) / 2 + 1 ))"
    dd_loop = (
        f"PIDS=''; "
        f"for i in $(seq 1 {half_w}); do "
        f"  dd if=/dev/zero of=/dev/null bs=1M & PIDS=\"$PIDS $!\"; "
        f"done; "
        f"sleep {duration}; "
        f"kill $PIDS 2>/dev/null; "
        f"wait"
    )
    return (
        f"if command -v stress-ng >/dev/null 2>&1; then "
        f"  stress-ng --cpu {half_w} --timeout {duration}s --metrics-brief; "
        f"else "
        f"  {dd_loop}; "
        f"fi"
    )


# ── 메인 ──────────────────────────────────────────────────────────────────────
def main():
    scenario = "cpu_spike_transient"
    client   = docker.from_env()

    verifier = ScenarioVerifier(
        scenario_name="cpu_spike_transient",
        alert_name="HighCpuUsage",
        hypothesis=(
            "절반 코어 60초 CPU 부하 → HighCpuUsage 발화 → "
            "서비스 생존 확인 → THROTTLE 권고 패턴 생성"
        ),
        steady_state_query=CPU_ALERT_QUERY,
        steady_state_threshold=CPU_ALERT_THRESHOLD,
        metric_label="현재 CPU",
        metric_unit="%",
        metric_scale=100.0,
    )

    verifier.check_steady_state()
    verifier.print_hypothesis()
    verifier.check_repeat_interval()
    verifier.wait_for_alert_inactive(timeout=90)
    verifier.start_timer()

    print(f"\n[*] 시나리오: CPU Spike (Transient) — THROTTLE 케이스")
    print(f"[*] 대상: {CONTAINER_NAME}")
    print(f"[*] 부하: 절반 코어({STRESS_DURATION}초) — 급등 후 자연 해소")
    print(f"[*] 의도: 서비스 생존 + CPU 급등 → LLM이 THROTTLE 선택")

    start_time = datetime.now(timezone.utc).isoformat()

    try:
        container = client.containers.get(CONTAINER_NAME)
    except docker.errors.NotFound:
        end_time = datetime.now(timezone.utc).isoformat()
        record_event(scenario, start_time, end_time, "error",
                     f"컨테이너 '{CONTAINER_NAME}' 없음")
        print(f"[!] 컨테이너 '{CONTAINER_NAME}' 없음. 종료.", file=sys.stderr)
        sys.exit(1)

    cmd = _build_stress_cmd(STRESS_DURATION)
    stress_result = {"status": "running", "output": ""}

    def _run_stress() -> None:
        try:
            exit_code, output = container.exec_run(
                cmd=["sh", "-c", cmd],
                stdout=True, stderr=True, stream=False,
            )
            output_str = output.decode("utf-8", errors="replace") if output else ""
            stress_result["status"] = "success" if exit_code == 0 else f"exit_code={exit_code}"
            stress_result["output"] = output_str
            print(f"[*] stress 완료 (exit={exit_code})")
        except Exception as e:
            stress_result["status"] = "error"
            stress_result["output"] = str(e)
            print(f"[!] exec 실패: {e}", file=sys.stderr)

    stress_thread = threading.Thread(target=_run_stress, name="cpu-transient-exec", daemon=True)
    stress_thread.start()

    # timeout = STRESS_DURATION(60s) + Alert 탐지 버퍼(60s)
    result = verifier.verify(timeout=STRESS_DURATION + 60, poll_interval=3)

    stress_thread.join()
    end_time = datetime.now(timezone.utc).isoformat()
    record_event(scenario, start_time, end_time,
                 stress_result["status"], stress_result["output"][:500])
    print(f"[*] 시나리오 종료: {scenario}")

    verifier.log_result(result)
    from common.result_viewer import ResultViewer
    ResultViewer("HighCpuUsage", "cpu_spike_transient").show(
        mttd_seconds=result.mttd_seconds,
        mtta_seconds=result.mtta_seconds,
    )


SCENARIO_META = {
    "id":             "cpu_spike_transient",
    "label":          "CPU 급등 (일시적)",
    "subtitle":       "절반 코어 60초 dd  ·  서비스 생존  ·  THROTTLE 케이스",
    "category":       "인프라",
    "owasp":          None,
    "mitre":          None,
    "container":      "leafy-backend",
    "loki_container": "backend",
    "alert_name":     "HighCpuUsage",
    "alert_fires":    True,
    "blind_spot":     False,
    "module":         "category1_infra.cpu_spike_transient",
    "custom_panel":   None,
}

if __name__ == "__main__":
    main()
