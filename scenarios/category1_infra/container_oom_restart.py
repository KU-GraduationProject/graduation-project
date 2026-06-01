"""
category1_infra/container_oom_restart.py
─────────────────────────────────────────
[시나리오 설명]
실제 사고 모티브:
  - Datadog 2024: 40% 조직에서 주기적 OOMKilled 발생
  - 2025년 3월 인시던트: JVM 힙 설정 오류 → 재시작 37회 반복
    → 요청 88% 영향, p99 레이턴시 461ms → 9424ms, 매출 손실

실제와의 차이:
  - 실제: 힙 메모리 점진적 증가 → OOM Kill → 재시작
  - 우리: leafy-backend JVM 내부 코드 수정 불가
    → OOM Kill의 결과인 컨테이너 반복 재시작을 직접 주입

구현 의도:
  - AIOps가 탐지해야 하는 신호는 메모리 수치가 아니라
    컨테이너 반복 재시작 패턴
  - 실제 사고에서도 운영자가 처음 감지하는 신호는
    컨테이너 재시작이므로 탐지 패턴은 동일함

탐지 포인트: ContainerRestarted Alert (Prometheus)
AIOps 포인트: container_start_time_seconds 변화 감지
              → LLM 분석 → NOTIFY/RESTART 액션
"""

import docker
import json
import os
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common.verifier import ScenarioVerifier, VerifyResult

# ── 설정 ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR     = os.path.dirname(os.path.abspath(__file__))
LOG_PATH       = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "logs", "anomaly_log.json"))

CONTAINER_NAME = "leafy-backend"
RESTART_COUNT  = 4       # 재시작 반복 횟수
CYCLE_SECONDS  = 30      # 재시작 주기(초) — 90초에서 단축, Alert 발화 확인 후 다음 사이클


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
        "scenario":   scenario,
        "category":   "infra",
        "start_time": start,
        "end_time":   end,
        "status":     status,
        "detail":     detail,
    })
    _save_log(records)
    print(f"[LOG] {scenario} | {status} | {start} → {end}")


# ── 메인 ──────────────────────────────────────────────────────────────────────
def main():
    scenario = "container_oom_restart"
    client   = docker.from_env()

    # ── 1단계: Verifier 초기화 ─────────────────────────────────────────────────
    verifier = ScenarioVerifier(
        scenario_name="container_oom_restart",
        alert_name="ContainerRestarted",
        hypothesis=(
            "leafy-backend 컨테이너 반복 재시작 시 "
            "ContainerRestarted Alert 발화 및 AIOps 탐지"
        ),
        steady_state_query=(
            'changes(container_start_time_seconds'
            '{id=~"/docker/.+"}[5m])'
        ),
        steady_state_threshold=1.0,
        metric_label="컨테이너 재시작 횟수 (5분)",
        metric_unit="회",
        metric_scale=1.0,
    )

    verifier.check_steady_state()
    verifier.print_hypothesis()

    # ── 이전 Alert resolve 대기 ────────────────────────────────────────────────
    verifier.wait_for_alert_inactive(timeout=60, poll_interval=5)

    verifier.start_timer()

    # ── 2단계: 컨테이너 존재 확인 ─────────────────────────────────────────────
    print(f"\n[*] 시나리오: {scenario}")
    print(f"[*] 대상: {CONTAINER_NAME} / 재시작 {RESTART_COUNT}회 / 주기 {CYCLE_SECONDS}초")
    print(f"[*] 모티브: OOM Kill → 컨테이너 반복 재시작 패턴 주입")

    start_time = datetime.now(timezone.utc).isoformat()

    try:
        container = client.containers.get(CONTAINER_NAME)
    except docker.errors.NotFound:
        end_time = datetime.now(timezone.utc).isoformat()
        record_event(scenario, start_time, end_time, "error",
                     f"컨테이너 '{CONTAINER_NAME}' 없음")
        print(f"[!] 컨테이너 '{CONTAINER_NAME}' 없음. 종료.", file=sys.stderr)
        sys.exit(1)

    # ── 3단계: 반복 재시작 ────────────────────────────────────────────────────
    events      = []
    final_status = "success"

    for i in range(1, RESTART_COUNT + 1):
        cycle_start = datetime.now(timezone.utc).isoformat()
        print(f"\n[{i}/{RESTART_COUNT}] 컨테이너 재시작 시도... ({cycle_start})")

        try:
            # running 상태 대기 (최대 60초)
            wait_deadline = time.time() + 60
            while time.time() < wait_deadline:
                container.reload()
                if container.status == "running":
                    break
                print(f"  → 현재 상태: {container.status}, running 대기 중...")
                time.sleep(3)

            state_before = container.status
            container.restart(timeout=0)   # 즉시 강제 재시작 (SIGKILL)
            print(f"  → 재시작 완료 (이전 상태: {state_before})")

            time.sleep(3)
            container.reload()
            state_after = container.status
            print(f"  → 재시작 후 상태: {state_after}")

            events.append({
                "cycle":        i,
                "cycle_start":  cycle_start,
                "state_before": state_before,
                "state_after":  state_after,
            })

        except docker.errors.APIError as e:
            print(f"  [!] Docker API 오류: {e}", file=sys.stderr)
            events.append({"cycle": i, "cycle_start": cycle_start, "error": str(e)})
            final_status = "partial_error"

        if i < RESTART_COUNT:
            print(f"  → 다음 재시작까지 {CYCLE_SECONDS}초 대기...")
            time.sleep(CYCLE_SECONDS)

    end_time = datetime.now(timezone.utc).isoformat()
    record_event(scenario, start_time, end_time, final_status,
                 json.dumps(events, ensure_ascii=False)[:800])
    print(f"\n[*] 재시작 주입 완료: {RESTART_COUNT}회")

    # ── 4단계: Prometheus Alert 발화 기반 MTTD 측정 ───────────────────────────
    print("\n[*] ContainerRestarted Alert 발화 대기 중...")
    result = verifier.verify(timeout=120, poll_interval=5)

    # ── 5단계: 결과 기록 ──────────────────────────────────────────────────────
    verifier.log_result(result)


if __name__ == "__main__":
    main()