"""
category1_infra/memory_leak.py
───────────────────────────────
leafy-backend 컨테이너를 90초 주기로 강제 재시작(kill → start)하여
OOM/메모리 누수 상황을 시뮬레이션한다.
시작/종료 시간을 anomaly_log.json에 기록한다.
"""

import docker
import json
import os
import platform
import sys
import time
from datetime import datetime, timezone
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common.verifier import ScenarioVerifier, VerifyResult

# ── 설정 ───────────────────────────────────────────────────────────────────────
SCRIPT_DIR     = os.path.dirname(os.path.abspath(__file__))
LOG_PATH       = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "logs", "anomaly_log.json"))

CONTAINER_NAME = "leafy-backend"  # 메모리 누수 → OOMKill 시뮬레이션 대상
RESTART_COUNT  = 3        # 재시작 반복 횟수
CYCLE_SECONDS  = 90       # 재시작 주기(초)


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



# ── 메인 ───────────────────────────────────────────────────────────────────────
def main():
    scenario = "memory_leak_restart"
    client = docker.from_env()
    # ── verifier 초기화 ──
    verifier = ScenarioVerifier(
        scenario_name="memory_leak",
        alert_name="memory_leak",
        hypothesis="컨테이너 강제 재시작 시 Loki에 재시작 로그 탐지",
    )

    verifier.check_steady_state()
    verifier.print_hypothesis()
    verifier.check_repeat_interval()
    verifier.start_timer()
    print(f"[*] 시나리오 시작: {scenario}")
    print(f"[*] 대상 컨테이너: {CONTAINER_NAME}")
    print(f"[*] 재시작 횟수: {RESTART_COUNT}회 / 주기: {CYCLE_SECONDS}초")

    start_time = datetime.now(timezone.utc).isoformat()

    try:
        container = client.containers.get(CONTAINER_NAME)
    except docker.errors.NotFound:
        end_time = datetime.now(timezone.utc).isoformat()
        record_event(scenario, start_time, end_time, "error",
                     f"컨테이너 '{CONTAINER_NAME}' 를 찾을 수 없습니다.")
        print(f"[!] 컨테이너 '{CONTAINER_NAME}' 없음. 종료.", file=sys.stderr)
        sys.exit(1)

    events = []
    final_status = "success"

    for i in range(1, RESTART_COUNT + 1):
        cycle_start = datetime.now(timezone.utc).isoformat()
        print(f"\n[{i}/{RESTART_COUNT}] 컨테이너 강제 재시작 시도... ({cycle_start})")

        try:
            # 재시작 전 running 상태 대기 (최대 60초)
            wait_deadline = time.time() + 60
            while time.time() < wait_deadline:
                container.reload()
                if container.status == "running":
                    break
                print(f"  → 현재 상태: {container.status}, running 대기 중...")
                time.sleep(3)
            else:
                container.reload()

            state_before = container.status

            container.restart(timeout=0)   # 즉시 강제 재시작
            print(f"  → 강제 재시작 완료 (이전 상태: {state_before})")

            time.sleep(3)

            container.reload()
            state_after = container.status
            print(f"  → 재시작 후 상태: {state_after}")

            events.append({
                "cycle": i,
                "cycle_start": cycle_start,
                "state_before": state_before,
                "state_after":  state_after,
            })

        except docker.errors.APIError as e:
            print(f"  [!] API 오류: {e}", file=sys.stderr)
            events.append({"cycle": i, "cycle_start": cycle_start, "error": str(e)})
            final_status = "partial_error"

        # 마지막 사이클이 아니면 대기
        if i < RESTART_COUNT:
            print(f"  → 다음 재시작까지 {CYCLE_SECONDS}초 대기...")
            time.sleep(CYCLE_SECONDS)

    end_time = datetime.now(timezone.utc).isoformat()
    detail = json.dumps(events, ensure_ascii=False)
    record_event(scenario, start_time, end_time, final_status, detail[:800])
    print(f"\n[*] 시나리오 종료: {scenario}")

    # ── 4단계: Alert 발화 확인 ──
    if platform.system() == "Windows":
        mttd = verifier.verify_loki(
            log_query='{container="backend"}',
            keyword="started",
            timeout=180,
        )
        loki_result = VerifyResult(
            success=mttd is not None,
            alert_name="memory_leak",
            scenario_name="memory_leak",
            mttd_seconds=mttd,
        )
        verifier.log_result(loki_result)
    else:
        verifier_prom = ScenarioVerifier(
            scenario_name="memory_leak",
            alert_name="ContainerRestarted",
            hypothesis="컨테이너 강제 재시작 시 ContainerRestarted 즉시 FIRING",
            steady_state_query='changes(container_start_time_seconds{id=~"/docker/.+"}[5m])',
            steady_state_threshold=1.0,
        )
        result = verifier_prom.verify(timeout=60)
        mtta = verifier_prom.verify_mtta(timeout=180)
        result.mtta_seconds = mtta
        result.slack_notified = mtta is not None
        verifier_prom.log_result(result)


if __name__ == "__main__":
    main()
