"""
category1_infra/false_positive_cpu.py
───────────────────────────────────────
35초 CPU 버스트를 발생시켜 HighCpuUsage를 FIRING시킨 뒤
부하를 제거하고 CPU가 정상화된 상태에서 Pipeline에 경보 웹훅을 전송.
Pipeline이 메트릭을 재조회할 때 CPU는 이미 정상 → NONE 케이스.

[실제 사고 모티브]
- cAdvisor scrape lag으로 인한 순간 스파이크 오탐 (30s irate 윈도우 특성)
- Prometheus evaluation interval(5s)과 부하 발생 타이밍의 우연한 겹침
- JVM GC pause, Spring Boot warmup 등에 의한 일시적 CPU 급등 후 즉시 복구

[구현 방식]
- 절반 코어로 35초 부하 → for:30s 충족으로 FIRING 발생
- 부하 제거 + 10초 대기 후 Pipeline에 HighCpuUsage 웹훅 직접 전송
- Pipeline이 메트릭 수집 시 CPU는 이미 정상 → LLM이 NONE 판단해야 함

[NONE 판단 근거 (LLM 관점)]
- Alert: HighCpuUsage FIRING
- 메트릭: cpu_usage latest=0.05 (정상), peak=2.1 (과거)
- 로그: 에러/경고 없음, 정상 요청 처리 중
→ "자연 해소된 일시적 스파이크 — 조치 불필요"

탐지 포인트: HighCpuUsage (수동 웹훅 전송)
AIOps 포인트: 경보 수신 시 메트릭 이미 정상 + 로그 무이상 → NONE 권고
"""

import docker
import json
import os
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common.verifier import ScenarioVerifier, VerifyResult

# ── 설정 ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH   = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "logs", "anomaly_log.json"))

CONTAINER_NAME      = "leafy-backend"
STRESS_DURATION     = 35       # for:30s 충족 + 5s 여유
COOLDOWN_SECONDS    = 10       # 부하 제거 후 CPU 정상화 대기
CPU_ALERT_QUERY     = 'sum(irate(container_cpu_usage_seconds_total{id=~"/docker/.+",cpu="total"}[30s]))'
CPU_ALERT_THRESHOLD = 0.5
PIPELINE_WEBHOOK    = os.getenv("PIPELINE_URL", "http://localhost:8000") + "/webhook/alert"


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


def _send_false_positive_webhook() -> bool:
    """
    CPU가 이미 정상으로 돌아온 뒤 Pipeline에 HighCpuUsage 경보를 직접 전송.
    Pipeline이 메트릭 재조회 시 CPU는 이미 정상 → LLM이 NONE 판단해야 함.
    """
    payload = {
        "version": "4",
        "groupKey": "false_positive_cpu",
        "status": "firing",
        "alerts": [{
            "status": "firing",
            "labels": {
                "alertname": "HighCpuUsage",
                "severity":  "warning",
                "container": "leafy-backend",
            },
            "annotations": {
                "summary":   "컨테이너 CPU 사용률 50% 초과",
                "container": "leafy-backend",
            },
            "startsAt": datetime.now(timezone.utc).isoformat(),
        }],
    }
    try:
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(
            PIPELINE_WEBHOOK, data=data,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=5)
        print(f"[*] Pipeline 웹훅 전송 완료 (CPU 이미 정상 상태)")
        return True
    except Exception as e:
        print(f"[!] Pipeline 웹훅 전송 실패: {e}")
        return False


# ── 메인 ──────────────────────────────────────────────────────────────────────
def main():
    scenario = "false_positive_cpu"
    client   = docker.from_env()

    verifier = ScenarioVerifier(
        scenario_name="false_positive_cpu",
        alert_name="HighCpuUsage",
        hypothesis=(
            f"{STRESS_DURATION}초 CPU 버스트 → 부하 제거 → CPU 정상화 후 경보 전송 → "
            "LLM 재조회 시 CPU 정상 + 로그 무이상 → NONE 판단"
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

    print(f"\n[*] 시나리오: False Positive CPU — NONE 케이스")
    print(f"[*] 대상: {CONTAINER_NAME}")
    print(f"[*] 방법: {STRESS_DURATION}초 CPU 버스트 → 정상화 후 수동 웹훅")
    print(f"[*] 의도: Pipeline 수신 시 CPU=정상 → LLM이 NONE 선택")

    start_time = datetime.now(timezone.utc).isoformat()

    try:
        container = client.containers.get(CONTAINER_NAME)
    except docker.errors.NotFound:
        end_time = datetime.now(timezone.utc).isoformat()
        record_event(scenario, start_time, end_time, "error",
                     f"컨테이너 '{CONTAINER_NAME}' 없음")
        print(f"[!] 컨테이너 '{CONTAINER_NAME}' 없음. 종료.", file=sys.stderr)
        sys.exit(1)

    # 절반 코어 × 35초 → for:30s 충족 → FIRING 유발 → 즉시 부하 제거
    half_w = "$(( $(nproc) / 2 + 1 ))"
    cmd = (
        f"PIDS=''; "
        f"for i in $(seq 1 {half_w}); do "
        f"  dd if=/dev/zero of=/dev/null bs=1M & PIDS=\"$PIDS $!\"; "
        f"done; "
        f"sleep {STRESS_DURATION}; "
        f"kill $PIDS 2>/dev/null; wait"
    )

    stress_result = {"status": "running"}

    def _run_stress() -> None:
        try:
            exit_code, _ = container.exec_run(
                cmd=["sh", "-c", cmd],
                stdout=True, stderr=True, stream=False,
            )
            stress_result["status"] = "success" if exit_code == 0 else f"exit={exit_code}"
            print(f"[*] CPU 버스트 완료 (exit={exit_code}) — CPU 정상화 중...")
        except Exception as e:
            stress_result["status"] = "error"
            print(f"[!] exec 실패: {e}", file=sys.stderr)

    stress_thread = threading.Thread(target=_run_stress, daemon=True)
    stress_thread.start()

    # 버스트 완료 대기
    print(f"[*] {STRESS_DURATION}초 CPU 버스트 실행 중...")
    stress_thread.join(timeout=STRESS_DURATION + 10)

    # CPU 정상화 대기
    print(f"[*] CPU 정상화 대기 중 ({COOLDOWN_SECONDS}초)...")
    time.sleep(COOLDOWN_SECONDS)

    # Pipeline에 오탐 경보 수동 전송 (CPU는 이미 정상)
    print("[*] Pipeline에 오탐 경보 직접 전송 (CPU 이미 정상 상태)...")
    webhook_sent = _send_false_positive_webhook()

    end_time = datetime.now(timezone.utc).isoformat()
    record_event(scenario, start_time, end_time,
                 "success" if webhook_sent else "partial",
                 json.dumps({
                     "stress_status": stress_result["status"],
                     "webhook_sent":  webhook_sent,
                     "note": "CPU normalized before Pipeline webhook — LLM should respond NONE",
                 }, ensure_ascii=False))

    print(f"\n[*] 완료: CPU 정상화 후 Pipeline 경보 전송됨")
    print(f"[*] 이상적인 LLM 응답: action_type=NONE, confidence=high")
    print(f"[*] 근거: cpu_usage latest≈정상, 로그 무이상 → 일시적 스파이크 자연 해소")

    result = VerifyResult(
        success=webhook_sent,
        alert_name="HighCpuUsage",
        scenario_name="false_positive_cpu",
        mttd_seconds=None,   # MTTD 측정 대상 아님 (NONE 케이스)
    )
    verifier.log_result(result)
    from common.result_viewer import ResultViewer
    ResultViewer("HighCpuUsage", "false_positive_cpu").show(
        mttd_seconds=result.mttd_seconds,
        mtta_seconds=result.mtta_seconds,
    )


SCENARIO_META = {
    "id":             "false_positive_cpu",
    "label":          "CPU 오탐 (False Positive)",
    "subtitle":       f"35초 버스트 → 정상화 후 경보 전송  ·  NONE 케이스",
    "category":       "인프라",
    "owasp":          None,
    "mitre":          None,
    "container":      "leafy-backend",
    "loki_container": "backend",
    "alert_name":     "HighCpuUsage",
    "alert_fires":    False,
    "blind_spot":     False,
    "module":         "category1_infra.false_positive_cpu",
    "custom_panel":   None,
}

if __name__ == "__main__":
    main()
