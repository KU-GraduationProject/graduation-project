"""
LLM 출력 허용 값의 단일 정의.

출력 스키마(schemas/llm_output.py), Ollama format 스키마, v2 프롬프트, 주기 스캔 프롬프트,
수동 승인 제안(schemas/remediation_plan.py)이 모두 여기서 가져간다. Remediation 정책 파일
(aiops/policy/remediation_policy.yml)에 같은 이름이 정의돼 있는지는 tests/test_action_types.py
가 확인한다 — 두 서비스는 빌드 컨텍스트가 달라 같은 파일을 import 할 수 없기 때문이다.

허용 목록은 Notion「remediation 모듈 수정방안」의 action_type별 조치 위험도 표 1차 범위다.
이름을 허용한다고 실행기가 생기지는 않는다 — 실행 여부는 Controller 정책이 정한다.
  - 2차 조치(BLOCK_EGRESS, REVOKE_SESSION, DISABLE_FEATURE 등)는 LLM 이 고를 수 없다.
  - 정책 선행 단계(CAPTURE, BACKUP_DB)와 사람 요청(UNLOCK_ACCOUNT, ENABLE_FEATURE)도 고를 수 없다.
  - SCALE 은 실행기가 없어(remediation_policy.yml unsupported) 고를 수 없다.
"""

# 1차 조치 10개. 순서는 프롬프트 표기 순서다.
ACTION_TYPES = ("NONE", "NOTIFY", "THROTTLE", "RESTART", "PAUSE", "ISOLATE",
                "KILL_SESSIONS", "LOCK_ACCOUNT", "RECREATE", "ROLLBACK")

# 시스템을 바꾸지 않는 조치 — 대상이 없어야 한다.
NO_TARGET_ACTIONS = ("NONE", "NOTIFY")

# 조치 대상은 고정 목록이 아니다. Remediation 실행기는 경보의 관측 identity target 하나만 받으므로
# (docs/llm/REMEDIATION_INTERFACE.md §3) 프롬프트마다 "관측 target + 증거에 있는 계정" 을 후보로 만든다.
# 어느 서비스에 어떤 조치가 허용되는지는 Remediation 이 정한다 — 여기서 다시 정의하지 않는다.
TARGET_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"

# 계정 대상(LOCK_ACCOUNT)은 "account:<관측된 계정 ID>" 로 쓴다. 실제 잠글 수 있는 계정은
# Controller 의 운영자 allowlist(remediation-app-api account_allowlist)가 다시 제한한다.
# 로그에서 온 값이라 신뢰하지 않는다 — 이 형식이 아니면 후보로 쓰지 않는다.
ACCOUNT_TARGET_PREFIX = "account:"
ACCOUNT_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$"
# 출력 스키마의 대상 형식: 관측 target 이름 또는 account:<id>. 이 밖의 문자열(공백·경로·제어문자)은 분석 무효다.
TARGET_PATTERN = r"^(?:account:[A-Za-z0-9][A-Za-z0-9_-]{0,127}|[A-Za-z0-9][A-Za-z0-9_.-]{0,127})$"

INCIDENT_CLASSES = ("attack", "failure", "benign")

THREAT_LEVELS = ("low", "medium", "high", "critical")
