r"""
scenarios-v2 정답 레이블 — 단일 소스 (one place only).

왜 여기 한 곳인가 (사용자 계획 §지킬 원칙):
  정답(threat_level / expected_action / ideal / targets)은 평가 측에만 둔다.
  주입 스크립트·탐지기·LLM 프롬프트·로그·컨테이너명·경로·헤더에는 넣지 않는다.
  준희의 network_runner.py 가 RunSpec.should_alert 를 GT 전용으로 쓰는 것과 같은 규율이다.

역할 분리: 탐지 룰은 팀원(룰 작성자)이 소유한다. 이 레지스트리는 **룰 이름을 담지 않는다**.
  대신 증거가 남는 채널(evidence)만 기록한다 — 어떤 룰로 탐지할지는 THREAT_SPEC.md 를 받은
  룰 작성자가 정한다. 시나리오 강도는 룰 임계가 아니라 위협 정의로 정한다(VARIANTS.md).

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
  evidence                : 증거가 남는 관측 채널(app_log|nginx_log|metric|network).
                            어떤 룰로 탐지할지는 적지 않는다(룰 작성자 몫, THREAT_SPEC.md).
  batch                   : 구현 배치 (1|2|3)

정책 6개 조치만 expected_action 에 허용한다. 모듈 로드 시 검증한다.
"""

from __future__ import annotations

import importlib

POLICY_ACTIONS = ("NONE", "NOTIFY", "THROTTLE", "RESTART", "PAUSE", "ISOLATE")
EVIDENCE_CHANNELS = ("app_log", "nginx_log", "metric", "network")

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
        "evidence": ["nginx_log", "app_log"],
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
        "evidence": ["app_log"],
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
        "evidence": ["metric"],
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
        # 증거: minio 가 실제로 멈춰 backend 가 남기는 오류 로그 + minio 가용성 메트릭.
        "evidence": ["app_log", "metric"],
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
        for ch in row.get("evidence", []):
            if ch not in EVIDENCE_CHANNELS:
                raise ValueError(
                    f"{row['id']}: evidence={ch} 은 채널 {EVIDENCE_CHANNELS} 에 없다")
        if row.get("module") and row.get("external_tool"):
            raise ValueError(f"{row['id']}: module 과 external_tool 을 동시에 둘 수 없다")


_HELDOUT_MODULES = ("v2.heldout", "v2.heldout.variant_specs")


def load_heldout_specs():
    """
    평가용 변형 스펙을 선택적으로 읽는다. scenarios/v2/heldout/ 는 .gitignore 대상이라
    저장소에 없는 것이 기본이다 — 없으면 조용히 None. 정답 레이블은 여기서 읽지 않는다.
    (heldout 모듈 자체가 다른 이유로 import 에 실패하면 숨기지 않고 그대로 올린다.)
    """
    try:
        variant_specs = importlib.import_module("v2.heldout.variant_specs")
    except ModuleNotFoundError as e:
        if e.name in _HELDOUT_MODULES:
            return None
        raise
    return getattr(variant_specs, "HELDOUT_VARIANT_SPECS", None)


_validate()
HELDOUT_VARIANT_SPECS = load_heldout_specs()
