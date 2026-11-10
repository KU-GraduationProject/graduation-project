"""
LLM 출력 허용 값의 단일 정의.

출력 스키마(schemas/llm_output.py), Ollama format 스키마, v2 프롬프트, 주기 스캔 프롬프트가
모두 여기서 가져간다. Remediation 정책 파일(aiops/policy/remediation_policy.yml)의
actions 키와 같은지는 tests/test_action_types.py 가 확인한다 — 두 서비스는 빌드
컨텍스트가 달라 같은 파일을 import 할 수 없기 때문이다.

SCALE 은 실행기가 없어(remediation_policy.yml unsupported) LLM 이 고를 수 없다.
"""

# 실행 가능한 조치 6개. 순서는 프롬프트 표기 순서다.
ACTION_TYPES = ("NONE", "NOTIFY", "THROTTLE", "RESTART", "PAUSE", "ISOLATE")

# 시스템을 바꾸지 않는 조치 — 대상이 없어야 한다.
NO_TARGET_ACTIONS = ("NONE", "NOTIFY")

# 조치 대상이 될 수 있는 컨테이너 (remediation-agent allowlist: backend/frontend/minio)
ACTION_TARGETS = ("leafy-backend", "leafy-frontend", "leafy-minio")

INCIDENT_CLASSES = ("attack", "failure", "benign")

THREAT_LEVELS = ("low", "medium", "high", "critical")
