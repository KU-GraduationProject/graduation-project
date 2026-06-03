"""
category2_security/container_escape_attempt.py
────────────────────────────────────────────────
침해된 컨테이너에서 호스트 파일시스템 접근·docker.sock 마운트 확인 등
컨테이너 탈출 시도 패턴을 재현하는 시나리오. 즉각 PAUSE 케이스.

[실제 사고 모티브]
- CVE-2019-5736 (runc 취약점): /proc/1/fd/ 경유 호스트 runc 덮어쓰기
- CVE-2024-21626 (runc CWPP 회피): workdir 조작으로 호스트 파일 노출
- docker.sock 마운트 오용: 내부에서 새 컨테이너 생성 → 호스트 탈출

[suspicious_process_exec.py와의 차이]
- suspicious_process_exec: C2 연결 + 환경변수 탈취 (내부 공격)
- container_escape_attempt: 호스트 파일시스템 + docker.sock 접근 (탈출 시도)
  → 호스트 전체가 위험에 처할 수 있어 즉각 PAUSE가 더 적합

[로그 기록 방식]
- /proc/1/fd/1 경유 → backend 컨테이너 로그 → Fluentd → Loki
- 키워드: 'container_escape_attempt'

탐지 포인트: ContainerEscapeAttempt (Loki Ruler → Alertmanager → Pipeline)
탐지 조건:  {container="backend"} |~ "container_escape_attempt" 2분 내 발생
AIOps 포인트: 탈출 시도 패턴 → 호스트 전파 차단 목적 즉각 PAUSE
"""

import docker
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common.verifier import ScenarioVerifier, VerifyResult

# ── 설정 ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR     = os.path.dirname(os.path.abspath(__file__))
LOG_PATH       = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "logs", "anomaly_log.json"))
CONTAINER_NAME = "leafy-backend"

# 각 명령은 /proc/1/fd/1에 'container_escape_attempt' 키워드를 기록
# ContainerEscapeAttempt 룰: {container="backend"} |~ "container_escape_attempt"
ESCAPE_COMMANDS = [
    # 1. 호스트 파일시스템 접근 시도 (/proc/1/root → 호스트 / 마운트)
    (
        "echo '[ATTACK] container_escape_attempt host_fs_access' > /proc/1/fd/1 && "
        "( ls /proc/1/root/etc/ > /dev/null 2>&1 && "
        "  echo '[ATTACK] container_escape_attempt host_fs_ACCESSIBLE' > /proc/1/fd/1 || "
        "  echo '[ATTACK] container_escape_attempt host_fs_blocked' > /proc/1/fd/1 )"
    ),
    # 2. docker.sock 마운트 확인 (소켓 있으면 docker API로 새 컨테이너 생성 가능)
    (
        "echo '[ATTACK] container_escape_attempt docker_sock_probe' > /proc/1/fd/1 && "
        "( test -S /var/run/docker.sock && "
        "  echo '[ATTACK] container_escape_attempt docker_sock_MOUNTED_CRITICAL' > /proc/1/fd/1 || "
        "  echo '[ATTACK] container_escape_attempt docker_sock_not_found' > /proc/1/fd/1 )"
    ),
    # 3. 스케줄러/커널 정보 접근 (커널 버전 정보 수집)
    (
        "echo '[ATTACK] container_escape_attempt kernel_info_probe' > /proc/1/fd/1 && "
        "( head -1 /proc/sched_debug 2>/dev/null > /dev/null && "
        "  echo '[ATTACK] container_escape_attempt sched_debug_readable' > /proc/1/fd/1 || "
        "  uname -r > /dev/null 2>&1 && "
        "  echo '[ATTACK] container_escape_attempt kernel_version_collected' > /proc/1/fd/1 || "
        "  echo '[ATTACK] container_escape_attempt kernel_probe_blocked' > /proc/1/fd/1 )"
    ),
    # 4. 네임스페이스 정보 수집 (탈출 가능한 ns 탐색)
    (
        "echo '[ATTACK] container_escape_attempt namespace_recon' > /proc/1/fd/1 && "
        "ls -la /proc/1/ns/ 2>/dev/null | head -5 > /dev/null && "
        "echo '[ATTACK] container_escape_attempt ns_list_collected' > /proc/1/fd/1 || true"
    ),
]


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
        "scenario": scenario, "category": "security",
        "start_time": start, "end_time": end,
        "status": status, "detail": detail,
    })
    _save_log(records)
    print(f"[LOG] {scenario} | {status} | {start} → {end}")


# ── 메인 ──────────────────────────────────────────────────────────────────────
def main():
    scenario = "container_escape_attempt"
    client   = docker.from_env()

    verifier = ScenarioVerifier(
        scenario_name="container_escape_attempt",
        alert_name="ContainerEscapeAttempt",
        hypothesis=(
            "호스트 fs + docker.sock + ns 탈출 시도 → "
            "Loki ContainerEscapeAttempt 발화 → 즉각 PAUSE 권고 패턴 생성"
        ),
    )

    verifier.check_steady_state()
    verifier.print_hypothesis()
    verifier.wait_for_alert_inactive(timeout=60, poll_interval=5)
    verifier.start_timer()

    print(f"\n[*] 시나리오: Container Escape Attempt — PAUSE 케이스")
    print(f"[*] MITRE ATT&CK: T1611 Escape to Host")
    print(f"[*] CVE 참조: CVE-2019-5736 (runc), CVE-2024-21626")
    print(f"[*] 모델: Assumed Breach")
    print(f"[*] 대상: {CONTAINER_NAME}")
    print(f"[*] PAUSE 근거: 호스트 전파 가능성 → 프로세스 동결로 즉각 차단")

    start_time = datetime.now(timezone.utc).isoformat()

    try:
        container = client.containers.get(CONTAINER_NAME)
    except docker.errors.NotFound:
        end_time = datetime.now(timezone.utc).isoformat()
        record_event(scenario, start_time, end_time, "error",
                     f"컨테이너 '{CONTAINER_NAME}' 없음")
        print(f"[!] 컨테이너 '{CONTAINER_NAME}' 없음. 종료.", file=sys.stderr)
        sys.exit(1)

    results     = []
    any_success = False

    for cmd in ESCAPE_COMMANDS:
        # 첫 번째 '[ATTACK] ...' 부분만 레이블로 추출
        try:
            label = cmd.split("'")[1]
        except IndexError:
            label = cmd[:60]
        print(f"\n[>] 탈출 시도: {label}")
        try:
            exit_code, output = container.exec_run(
                cmd=["sh", "-c", cmd],
                stdout=True, stderr=True, stream=False,
            )
            raw = output.decode("utf-8", errors="replace") if output else ""
            any_success = True
            is_blocked = "blocked" in raw.lower() or "not_found" in raw.lower()
            status_str = "BLOCKED" if is_blocked else "ATTEMPTED"
            print(f"  → {status_str} (exit={exit_code})")
            print(f"  → backend 로그에 'container_escape_attempt' 기록됨")
            results.append({"attempt": label, "exit_code": exit_code, "status": status_str})
        except docker.errors.APIError as e:
            print(f"  [!] API 오류: {e}", file=sys.stderr)
            results.append({"attempt": label, "error": str(e)})

    end_time = datetime.now(timezone.utc).isoformat()
    record_event(scenario, start_time, end_time,
                 "success" if any_success else "failed",
                 json.dumps(results, ensure_ascii=False)[:800])

    print(f"\n[*] 탈출 시도 시퀀스 완료. Loki 탐지 대기 중...")
    print(f"[*] Loki 쿼리: {{container=\"backend\"}} |~ \"container_escape_attempt\"")

    mttd = verifier.verify_loki(
        log_query='{container="backend"}',
        keyword="container_escape_attempt",
        timeout=120,
    )

    result = VerifyResult(
        success=mttd is not None,
        alert_name="ContainerEscapeAttempt",
        scenario_name="container_escape_attempt",
        mttd_seconds=mttd,
    )
    verifier.log_result(result)
    from common.result_viewer import ResultViewer
    ResultViewer("ContainerEscapeAttempt", "container_escape_attempt").show(
        mttd_seconds=result.mttd_seconds,
        mtta_seconds=result.mtta_seconds,
    )


SCENARIO_META = {
    "id":             "container_escape_attempt",
    "label":          "컨테이너 탈출 시도",
    "subtitle":       "host_fs + docker.sock + ns 탐색  ·  PAUSE 케이스",
    "category":       "보안",
    "owasp":          "A05:2021",
    "mitre":          "T1611",
    "container":      "leafy-backend",
    "loki_container": "backend",
    "alert_name":     "ContainerEscapeAttempt",
    "alert_fires":    True,
    "blind_spot":     False,
    "module":         "category2_security.container_escape_attempt",
    "custom_panel":   None,
}

if __name__ == "__main__":
    main()
