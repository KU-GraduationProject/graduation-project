"""
category2_security/secret_dump.py
───────────────────────────────────
leafy-backend 컨테이너 내부에서 환경변수 덤프를 시도하는
공격 시나리오 시뮬레이션.
실제 값은 마스킹하여 로그에 기록하고, 시작/종료 시간을 anomaly_log.json에 남긴다.
"""

import docker
import json
import os
import re
import sys
from datetime import datetime, timezone

# ── 설정 ───────────────────────────────────────────────────────────────────────
SCRIPT_DIR     = os.path.dirname(os.path.abspath(__file__))
LOG_PATH       = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "logs", "anomaly_log.json"))

CONTAINER_NAME = "leafy-backend"

# 민감 키워드 (값을 마스킹할 환경변수 이름 패턴)
SENSITIVE_PATTERNS = re.compile(
    r"(PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL|PWD|AUTH|PRIVATE)",
    re.IGNORECASE,
)

# 덤프 시도 명령 목록 (공격자가 실제로 시도할 법한 명령들)
DUMP_COMMANDS = [
    "env",
    "cat /proc/1/environ | tr '\\0' '\\n'",
    "printenv",
]


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
    """민감 키워드가 포함된 환경변수 값을 *** 로 치환한다."""
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


# ── 메인 ───────────────────────────────────────────────────────────────────────
def main():
    scenario = "secret_dump"
    client = docker.from_env()

    print(f"[*] 시나리오 시작: {scenario}")
    print(f"[*] 대상 컨테이너: {CONTAINER_NAME}")
    print(f"[*] 시도 명령 수: {len(DUMP_COMMANDS)}개")

    start_time = datetime.now(timezone.utc).isoformat()

    try:
        container = client.containers.get(CONTAINER_NAME)
    except docker.errors.NotFound:
        end_time = datetime.now(timezone.utc).isoformat()
        record_event(scenario, start_time, end_time, "error",
                     f"컨테이너 '{CONTAINER_NAME}' 를 찾을 수 없습니다.")
        print(f"[!] 컨테이너 '{CONTAINER_NAME}' 없음. 종료.", file=sys.stderr)
        sys.exit(1)

    results = []
    any_success = False

    for cmd in DUMP_COMMANDS:
        print(f"\n[>] 명령 실행: {cmd}")
        try:
            exit_code, output = container.exec_run(
                cmd=["sh", "-c", cmd],
                stdout=True,
                stderr=True,
                stream=False,
            )
            raw = output.decode("utf-8", errors="replace") if output else ""
            masked = mask_sensitive(raw)
            success = exit_code == 0

            if success:
                any_success = True
                var_count = len([l for l in raw.splitlines() if "=" in l])
                print(f"  → 성공 (exit=0) | 환경변수 {var_count}개 노출됨 [값 마스킹됨]")
            else:
                print(f"  → 실패 (exit={exit_code})")

            results.append({
                "command":   cmd,
                "exit_code": exit_code,
                "success":   success,
                "output_masked": masked[:300],
            })

        except docker.errors.APIError as e:
            print(f"  [!] API 오류: {e}", file=sys.stderr)
            results.append({"command": cmd, "error": str(e)})

    end_time = datetime.now(timezone.utc).isoformat()
    final_status = "success" if any_success else "failed"
    detail = json.dumps(results, ensure_ascii=False)
    record_event(scenario, start_time, end_time, final_status, detail[:800])
    print(f"\n[*] 시나리오 종료: {scenario} | 환경변수 덤프 {'성공' if any_success else '실패'}")


if __name__ == "__main__":
    main()
