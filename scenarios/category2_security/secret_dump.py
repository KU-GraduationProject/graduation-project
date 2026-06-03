"""
category2_security/secret_dump.py
───────────────────────────────────
leafy-backend 컨테이너 내부에서 환경변수 덤프를 시도하는
공격 시나리오 시뮬레이션.

[실제 사고 모티브]
- 컨테이너 침해 후 공격자가 환경변수에서
  DB 패스워드, JWT 시크릿, API 키 등을 탈취하는 패턴
- MITRE ATT&CK T1552.001: Credentials in Files
- 실제 사례: Docker 컨테이너 탈출 후 env 덤프로
  클라우드 크레덴셜 탈취 (2024년 다수 사례)

[실제와의 차이]
- 실제: 취약점으로 컨테이너 침투 후 내부에서 실행
- 우리: Docker 소켓 접근으로 docker exec 실행
  (컨테이너 탈출 이후 단계를 Assumed Breach로 가정)

[로그 기록 방식]
- docker exec stdout은 Fluentd가 수집 안 함
- /proc/1/fd/1 (PID 1의 stdout) 으로 강제 출력
  → backend 컨테이너 로그에 기록 → Fluentd → Loki

탐지 포인트: SecretDumpAttempt (Loki Ruler → Alertmanager → Pipeline)
탐지 조건:  {container="backend"} |= "printenv" 2분 내 발생
AIOps 포인트: 환경변수 덤프 패턴 → LLM 분석 → ISOLATE 권고
"""

import docker
import json
import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common.verifier import ScenarioVerifier, VerifyResult

# ── 설정 ──────────────────────────────────────────────────────────────────────
SCRIPT_DIR     = os.path.dirname(os.path.abspath(__file__))
LOG_PATH       = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "logs", "anomaly_log.json"))

CONTAINER_NAME = "leafy-backend"

SENSITIVE_PATTERNS = re.compile(
    r"(PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL|PWD|AUTH|PRIVATE)",
    re.IGNORECASE,
)

# /proc/1/fd/1 으로 강제 출력 → backend 컨테이너 로그 → Fluentd → Loki
# "printenv" 키워드가 로그에 찍혀야 SecretDumpAttempt 룰 탐지 가능
DUMP_COMMANDS = [
    "echo '[ATTACK] printenv executed' > /proc/1/fd/1 && printenv",
    "echo '[ATTACK] env dump' > /proc/1/fd/1 && env",
    "echo '[ATTACK] environ dump' > /proc/1/fd/1 "
    "&& cat /proc/1/environ | tr '\\0' '\\n'",
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
        "scenario": scenario,
        "category": "security",
        "start_time": start,
        "end_time":   end,
        "status":     status,
        "detail":     detail,
    })
    _save_log(records)
    print(f"[LOG] {scenario} | {status} | {start} → {end}")


# ── 환경변수 마스킹 ────────────────────────────────────────────────────────────
def mask_sensitive(raw: str) -> str:
    masked_lines = []
    for line in raw.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            if SENSITIVE_PATTERNS.search(key):
                masked_lines.append(f"{key}=***MASKED***")
            else:
                masked_lines.append(line)
        else:
            masked_lines.append(line)
    return "\n".join(masked_lines)


# ── 메인 ──────────────────────────────────────────────────────────────────────
def main():
    scenario = "secret_dump"
    client   = docker.from_env()

    # ── 1단계: Verifier 초기화 ────────────────────────────────────────────────
    verifier = ScenarioVerifier(
        scenario_name="secret_dump",
        alert_name="SecretDumpAttempt",
        hypothesis=(
            "침해 컨테이너 내부에서 printenv 실행 시 "
            "backend 로그에 패턴 기록 → Loki SecretDumpAttempt Alert 발화"
        ),
    )

    verifier.check_steady_state()
    verifier.print_hypothesis()
    verifier.wait_for_alert_inactive(timeout=60, poll_interval=5)
    verifier.start_timer()

    # ── 2단계: 컨테이너 존재 확인 ─────────────────────────────────────────────
    print(f"\n[*] 시나리오: Secret Dump (환경변수 탈취)")
    print(f"[*] MITRE ATT&CK: T1552.001 Credentials in Files")
    print(f"[*] 모델: Assumed Breach (컨테이너 침해 완료 가정)")
    print(f"[*] 대상: {CONTAINER_NAME}")
    print(f"[*] 탐지 목표: Loki SecretDumpAttempt")
    print(f"[*] 로그 기록: /proc/1/fd/1 → Fluentd → Loki")

    start_time = datetime.now(timezone.utc).isoformat()

    try:
        container = client.containers.get(CONTAINER_NAME)
    except docker.errors.NotFound:
        end_time = datetime.now(timezone.utc).isoformat()
        record_event(scenario, start_time, end_time, "error",
                     f"컨테이너 '{CONTAINER_NAME}' 없음")
        print(f"[!] 컨테이너 '{CONTAINER_NAME}' 없음. 종료.", file=sys.stderr)
        sys.exit(1)

    # ── 3단계: 환경변수 덤프 시도 ─────────────────────────────────────────────
    results     = []
    any_success = False

    for cmd in DUMP_COMMANDS:
        print(f"\n[>] 명령 실행: {cmd.split('&&')[0].strip()}")
        try:
            exit_code, output = container.exec_run(
                cmd=["sh", "-c", cmd],
                stdout=True,
                stderr=True,
                stream=False,
            )
            raw     = output.decode("utf-8", errors="replace") if output else ""
            masked  = mask_sensitive(raw)
            success = exit_code == 0

            if success:
                any_success = True
                var_count = len([l for l in raw.splitlines() if "=" in l])
                print(f"  → 성공 (exit=0) | 환경변수 {var_count}개 노출됨 [값 마스킹됨]")
                print(f"  → backend 로그에 'printenv' 키워드 기록됨 → Loki 탐지 대기")
            else:
                print(f"  → 실패 (exit={exit_code})")

            results.append({
                "command":       cmd.split("&&")[-1].strip(),
                "exit_code":     exit_code,
                "success":       success,
                "output_masked": masked[:300],
            })

        except docker.errors.APIError as e:
            print(f"  [!] API 오류: {e}", file=sys.stderr)
            results.append({"command": cmd, "error": str(e)})

    end_time     = datetime.now(timezone.utc).isoformat()
    final_status = "success" if any_success else "failed"
    record_event(scenario, start_time, end_time, final_status,
                 json.dumps(results, ensure_ascii=False)[:800])

    print(f"\n[*] 덤프 완료: {'성공' if any_success else '실패'}")
    print(f"[*] Loki 확인: {{container=\"backend\"}} |= \"printenv\"")

    # ── 4단계: Loki 로그 기반 MTTD 측정 ──────────────────────────────────────
    print("\n[*] Loki 'printenv' 패턴 탐지 대기 중...")
    mttd = verifier.verify_loki(
        log_query='{container="backend"}',
        keyword="printenv",
        timeout=120,
    )

    # ── 5단계: 결과 기록 ──────────────────────────────────────────────────────
    result = VerifyResult(
        success=mttd is not None,
        alert_name="SecretDumpAttempt",
        scenario_name="secret_dump",
        mttd_seconds=mttd,
    )
    verifier.log_result(result)
    from common.result_viewer import ResultViewer
    ResultViewer("SecretDumpAttempt", "secret_dump").show(
        mttd_seconds=result.mttd_seconds,
        mtta_seconds=result.mtta_seconds,
    )

    print(f"\n[*] 시나리오 종료: {scenario}")


if __name__ == "__main__":
    main()