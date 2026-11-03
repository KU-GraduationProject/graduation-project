r"""
scenarios-v2 정답 레이블 — 단일 소스 (one place only).

왜 여기 한 곳인가 (사용자 계획 §지킬 원칙):
  정답(threat_level / expected_action / ideal / targets)은 평가 측에만 둔다.
  주입 스크립트·탐지기·LLM 프롬프트·로그·컨테이너명·경로·헤더에는 넣지 않는다.
  준희의 network_runner.py 가 RunSpec.should_alert 를 GT 전용으로 쓰는 것과 같은 규율이다.

필드:
  id                      : 시나리오 식별자
  label                   : 사람이 읽는 이름 (프롬프트에 넣지 않는다)
  threat_level            : low | medium | high | critical  (평가 정답)
  expected_action         : 현재 대체 조치. 반드시 정책 6개 중 하나
                            (NONE|NOTIFY|THROTTLE|RESTART|PAUSE|ISOLATE,
                             aiops/policy/remediation_policy.yml)
  expected_action_ideal   : 이상적 조치. 정책에 아직 없는 조치일 수 있으며
                            평가 메타(라벨)로만 쓰고 실행 경로에 넣지 않는다.
  targets                 : 조치 대상 (컨테이너/계정/경로 등 서술)
  module                  : 주입 스크립트 (in-repo). 외부 도구는 external_tool 로.
  external_tool           : 저장소 밖 도구 경로 참조 (측정 PC D:\develop\leafy-baseline\tools\).
                            나중에 측정 PC 세션에서 저장소로 옮긴다.
  detection               : 발화할 탐지 룰 이름(들). None=음성 대조(발화 없음이 정답).
  batch                   : 구현 배치 (1|2|3)

정책 6개 조치만 expected_action 에 허용한다. 모듈 로드 시 검증한다.
"""

from __future__ import annotations

POLICY_ACTIONS = ("NONE", "NOTIFY", "THROTTLE", "RESTART", "PAUSE", "ISOLATE")

# 배치 ① — 주입·정리 구현 대상
SCENARIO_REGISTRY_V2 = [
    {
        "id": "s1_a_input_attack",
        "label": "입력값 공격 (앱까지 통과)",
        "threat_level": "critical",
        "expected_action": "NOTIFY",        # WAF 경로차단 조치가 없어 알림으로 대체
        "expected_action_ideal": "BLOCK_PATH",
        "targets": ["nginx 경로"],
        "module": "v2.s1a_input_attack",
        "external_tool": None,
        "detection": ["SQLInjectionAttempt", "PathTraversalAttempt"],
        "batch": 1,
    },
    {
        "id": "s1_c_login_bruteforce",
        "label": "인증 공격 (로그인 대입)",
        "threat_level": "medium",
        "expected_action": "NOTIFY",        # 계정잠금 조치가 없어 알림으로 대체
        "expected_action_ideal": "LOCK_ACCOUNT",
        "targets": ["공격 대상 계정"],
        "module": "v2.s1c_login_bruteforce",
        "external_tool": None,
        "detection": ["LoginBruteForce"],   # 신설 룰 (security-rules.yml)
        "batch": 1,
    },
    {
        "id": "f1_b_memory_leak",
        "label": "메모리 압박·누수 (서서히)",
        "threat_level": "medium",
        "expected_action": "RESTART",
        "expected_action_ideal": "RESTART",
        "targets": ["leafy-backend"],
        "module": "v2.f1b_memory_leak",
        "external_tool": None,
        "detection": ["HighMemoryUsage"],
        "batch": 1,
    },
    {
        "id": "f2_a_minio_outage",
        "label": "MinIO 중단",
        "threat_level": "medium",
        "expected_action": "RESTART",
        "expected_action_ideal": "RESTART",
        "targets": ["leafy-minio"],
        "module": "v2.f2a_minio_outage",
        "external_tool": None,
        # F2-a A안: minio 를 prometheus 수집 대상으로 만들고 up==0 으로 탐지(MinioDown).
        "detection": ["MinioDown"],
        "batch": 1,
    },
]

# 배치 ②·③ 항목(S2-a / F2-c / F3-a / S2-c / C-a / C-c / C-e / C-g / C-n)은
# 각 배치에서 이 리스트에 append 한다. 정답 레이블의 단일 소스는 이 파일로 유지한다.


def _validate(registry=SCENARIO_REGISTRY_V2) -> None:
    ids = set()
    for row in registry:
        if row["id"] in ids:
            raise ValueError(f"중복 id: {row['id']}")
        ids.add(row["id"])
        if row["expected_action"] not in POLICY_ACTIONS:
            raise ValueError(
                f"{row['id']}: expected_action={row['expected_action']} 은 정책 6개에 없다 "
                f"{POLICY_ACTIONS}")
        if row.get("module") and row.get("external_tool"):
            raise ValueError(f"{row['id']}: module 과 external_tool 을 동시에 둘 수 없다")


_validate()
