"""
category1_infra/memory_pressure_early.py
─────────────────────────────────────────
/dev/shm(tmpfs)에 파일을 생성해 컨테이너 메모리 사용량을 점진적으로 올리는 시나리오.
OOM kill 없이 메모리 압박 초기 단계를 재현 → THROTTLE 케이스.

[memory_leak.py와의 차이]
- memory_leak:          컨테이너 강제 kill/restart 반복 → RESTART 케이스
- memory_pressure_early: 메모리를 서서히 올리고 OOM 없이 유지 → THROTTLE 케이스

[구현 방식]
- /dev/shm 은 tmpfs(RAM 기반 파일시스템)이므로 파일 생성 = 메모리 직접 점유
- 50MB씩 4회 → 200MB 점유 후 120초 유지
- HighMemoryUsage 발화 조건: memory_usage / spec_limit > 0.7 for 1m
  → docker-compose.yml에 mem_limit이 설정된 경우에만 작동
  → 없는 경우: ContainerRestarted 알림이 아닌 메트릭 기반 확인 필요

[한계]
- leafy-backend에 메모리 제한(mem_limit)이 없으면 HighMemoryUsage 미발화
- 이 경우 시나리오는 메모리 사용 패턴만 생성하고 LLM 분석용 Few-shot 예제로 활용

탐지 포인트: HighMemoryUsage (Prometheus → AlertManager → Pipeline)
탐지 조건:  memory_usage_bytes / spec_memory_limit_bytes > 0.7 for 1m
AIOps 포인트: 메모리 점진 상승 + OOM 없음 + 서비스 응답 중 → THROTTLE 권고
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
MEM_CHUNK_MB        = 50     # 한 번에 점유할 /dev/shm 파일 크기(MB)
MEM_CHUNKS          = 4      # 총 반복 횟수 → 200MB
MEM_HOLD_SECONDS    = 120    # 점유 후 유지 시간 (for: 1m 충족용)
# HighMemoryUsage: memory / limit > 0.7. limit 없으면 이 쿼리는 결과 없음.
MEM_ALERT_QUERY = (
    "max(container_memory_usage_bytes{id=~\"/docker/.+\"} "
    "/ container_spec_memory_limit_bytes{id=~\"/docker/.+\"} "
    "* on(id) group_left(name) container_name_info)"
)
MEM_ALERT_THRESHOLD = 0.7


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


# ── 메인 ──────────────────────────────────────────────────────────────────────
def main():
    scenario = "memory_pressure_early"
    client   = docker.from_env()

    verifier = ScenarioVerifier(
        scenario_name="memory_pressure_early",
        alert_name="HighMemoryUsage",
        hypothesis=(
            "/dev/shm 메모리 점진 할당 → HighMemoryUsage(70%) 발화 → "
            "OOM 없이 서비스 생존 → THROTTLE 권고 패턴 생성"
        ),
        steady_state_query=MEM_ALERT_QUERY,
        steady_state_threshold=MEM_ALERT_THRESHOLD,
        metric_label="메모리 사용률",
        metric_unit="%",
        metric_scale=100.0,
    )

    verifier.check_steady_state()
    verifier.print_hypothesis()
    verifier.wait_for_alert_inactive(timeout=90, poll_interval=5)
    verifier.start_timer()

    print(f"\n[*] 시나리오: Memory Pressure (Early Stage) — THROTTLE 케이스")
    print(f"[*] 대상: {CONTAINER_NAME}")
    print(f"[*] 방법: /dev/shm에 {MEM_CHUNK_MB}MB × {MEM_CHUNKS}회 = {MEM_CHUNK_MB*MEM_CHUNKS}MB 점유")
    print(f"[*] 의도: 메모리 점진 상승 + OOM 없음 → LLM이 THROTTLE 선택")
    print(f"[*] 주의: HighMemoryUsage는 mem_limit 설정 시에만 발화")

    start_time = datetime.now(timezone.utc).isoformat()

    try:
        container = client.containers.get(CONTAINER_NAME)
    except docker.errors.NotFound:
        end_time = datetime.now(timezone.utc).isoformat()
        record_event(scenario, start_time, end_time, "error",
                     f"컨테이너 '{CONTAINER_NAME}' 없음")
        print(f"[!] 컨테이너 '{CONTAINER_NAME}' 없음. 종료.", file=sys.stderr)
        sys.exit(1)

    # /dev/shm(tmpfs)에 dd로 파일 생성 → RAM 직접 점유
    # 50MB씩 4개 파일 생성 후 MEM_HOLD_SECONDS초 대기 → 일괄 삭제
    total_mb = MEM_CHUNK_MB * MEM_CHUNKS
    cmd = (
        f"mkdir -p /dev/shm/mem_pressure && "
        f"for i in $(seq 1 {MEM_CHUNKS}); do "
        f"  dd if=/dev/zero of=/dev/shm/mem_pressure/chunk_$i bs=1M count={MEM_CHUNK_MB} 2>/dev/null; "
        f"  echo '[MEMORY_PRESSURE] chunk_'$i'_allocated_{MEM_CHUNK_MB}MB'; "
        f"done && "
        f"echo '[MEMORY_PRESSURE] total_{total_mb}MB_allocated_holding_{MEM_HOLD_SECONDS}s' && "
        f"sleep {MEM_HOLD_SECONDS} && "
        f"rm -rf /dev/shm/mem_pressure && "
        f"echo '[MEMORY_PRESSURE] released'"
    )

    result_data = {"status": "running", "output": ""}

    def _run_mem() -> None:
        try:
            exit_code, output = container.exec_run(
                cmd=["sh", "-c", cmd],
                stdout=True, stderr=True, stream=False,
            )
            out_str = output.decode("utf-8", errors="replace") if output else ""
            result_data["status"] = "success" if exit_code == 0 else f"exit={exit_code}"
            result_data["output"] = out_str
            print(f"[*] 메모리 할당/해제 완료 (exit={exit_code})")
        except Exception as e:
            result_data["status"] = "error"
            result_data["output"] = str(e)
            print(f"[!] exec 실패: {e}", file=sys.stderr)

    mem_thread = threading.Thread(target=_run_mem, daemon=True)
    mem_thread.start()

    # HighMemoryUsage: for: 1m → timeout 더 넉넉히
    result = verifier.verify(timeout=MEM_HOLD_SECONDS + 90, poll_interval=5)

    mem_thread.join()
    end_time = datetime.now(timezone.utc).isoformat()
    record_event(scenario, start_time, end_time,
                 result_data["status"], result_data["output"][:500])
    print(f"[*] 시나리오 종료: {scenario}")

    verifier.log_result(result)
    from common.result_viewer import ResultViewer
    ResultViewer("HighMemoryUsage", "memory_pressure_early").show(
        mttd_seconds=result.mttd_seconds,
        mtta_seconds=result.mtta_seconds,
    )


SCENARIO_META = {
    "id":             "memory_pressure_early",
    "label":          "메모리 압박 (초기 단계)",
    "subtitle":       "/dev/shm 200MB 점유 → OOM 없음  ·  THROTTLE 케이스",
    "category":       "인프라",
    "owasp":          None,
    "mitre":          None,
    "container":      "leafy-backend",
    "loki_container": "backend",
    "alert_name":     "HighMemoryUsage",
    "alert_fires":    True,
    "blind_spot":     False,
    "module":         "category1_infra.memory_pressure_early",
    "custom_panel":   None,
}

if __name__ == "__main__":
    main()
