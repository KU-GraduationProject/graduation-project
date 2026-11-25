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
  incident_class          : attack | failure | benign  (평가 정답. benign = 정상 활동·오탐)
  threat_level            : low | medium | high | critical  (평가 정답)
  expected_action         : 현재 대체 조치. 반드시 LLM 허용 조치 10개 중 하나
                            (aiops/pipeline/schemas/actions.py ACTION_TYPES 와 같다)
  expected_action_ideal   : 이상적 조치. 정책에 아직 없는 조치일 수 있으며
                            평가 메타(라벨)로만 쓰고 실행 경로에 넣지 않는다.
  targets                 : 조치 대상 (컨테이너/계정/경로 등 서술)
  module                  : 주입 스크립트 (in-repo). 외부 도구는 external_tool 로.
  external_tool           : 저장소 밖 도구 경로 참조 (측정 PC D:\develop\leafy-baseline\tools\).
                            나중에 측정 PC 세션에서 저장소로 옮긴다.
  evidence                : 증거가 남는 관측 채널(app_log|nginx_log|metric|network).
                            어떤 룰로 탐지할지는 적지 않는다(룰 작성자 몫, THREAT_SPEC.md).
  reuse                   : 팀원 네트워크 시나리오 재사용 식별자(net_s2|net_ca). 코드 미수정.
  notes                   : 실행 시 유의/검증 메모(선택).
  batch                   : 구현 배치 (1|2|3 = 1차, 4 = 2차 A군)
  attack_id               : (선택) MITRE ATT&CK 기법 ID (v19.2 기준 확인). 장애·대조는 None.
  pair                    : (선택, 대조 전용) 같은 탐지 신호를 내는 짝 공격·장애 id 목록.

  external_tool 기준 경로: 측정 PC D:\develop\leafy-baseline\tools\ (값은 파일명만 적는다).

정책 6개 조치만 expected_action 에 허용한다. 모듈 로드 시 검증한다.
"""

from __future__ import annotations

import importlib
import re

# LLM 이 고를 수 있는 조치 (aiops/pipeline/schemas/actions.py ACTION_TYPES, Notion 1차 범위)
POLICY_ACTIONS = ("NONE", "NOTIFY", "THROTTLE", "RESTART", "PAUSE", "ISOLATE",
                  "KILL_SESSIONS", "LOCK_ACCOUNT", "RECREATE", "ROLLBACK")
INCIDENT_CLASSES = ("attack", "failure", "benign")
EVIDENCE_CHANNELS = ("app_log", "nginx_log", "metric", "network")

# 배치 ① — 주입·정리 구현 대상
SCENARIO_REGISTRY_V2 = [
    {
        "id": "s1_a_input_attack",
        "label": "입력값 공격 (앱까지 통과)",
        "incident_class": "attack",
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
        "incident_class": "attack",
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
        "incident_class": "failure",
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
        "incident_class": "failure",
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
    # 배치 ② — 주입·정리 구현 대상
    {
        "id": "s2_a_resource_theft",
        "label": "자원 탈취 (채굴형 CPU)",
        "incident_class": "attack",
        "threat_level": "high",
        "expected_action": "THROTTLE",      # 서비스 생존 → 스로틀
        "expected_action_ideal": "RECREATE",
        "targets": ["leafy-backend"],
        "module": "v2.s2a_resource_theft",
        "external_tool": None,
        "evidence": ["metric", "app_log"],
        "batch": 2,
    },
    {
        "id": "f2_c_db_pool_exhaustion",
        "label": "DB 연결 한도 고갈",
        "incident_class": "failure",
        "threat_level": "high",
        "expected_action": "NOTIFY",          # 점유 세션 종료가 이상 조치(backend 재시작 아님)
        "expected_action_ideal": "KILL_SESSIONS",
        "targets": ["점유 중인 DB 세션"],
        "module": "v2.f2c_db_pool_exhaustion",
        "external_tool": None,
        "evidence": ["metric", "app_log"],
        "batch": 2,
    },
    {
        "id": "f3_a_bad_image_deploy",
        "label": "잘못된 이미지 배포",
        "incident_class": "failure",
        "threat_level": "high",
        "expected_action": "NOTIFY",         # 롤백 조치가 없어 알림으로 대체
        "expected_action_ideal": "ROLLBACK",
        "targets": ["배포 서비스"],
        "module": "v2.f3a_bad_image_deploy",
        "external_tool": None,
        "evidence": ["metric", "app_log"],
        "batch": 2,
    },
    # 배치 ③ — 재사용/외부도구 대조·반출 (코드 미구현, 레지스트리 등록만)
    {
        "id": "s2_c_data_exfil",
        "label": "데이터 반출 (비인가 목적지)",
        "incident_class": "attack",
        "threat_level": "critical",
        "expected_action": "ISOLATE",
        "expected_action_ideal": "ISOLATE",
        "targets": ["leafy-backend"],
        "module": None,
        "external_tool": None,
        "reuse": "net_s2",                   # 팀원 네트워크 시나리오 재사용(코드 미수정)
        "evidence": ["network"],
        "batch": 3,
    },
    {
        "id": "c_a_authorized_transfer",
        "label": "인가 목적지 대량 전송",
        "incident_class": "benign",
        "threat_level": "low",
        "expected_action": "NONE",
        "expected_action_ideal": "NONE",
        "targets": [],
        "module": None,
        "external_tool": None,
        "reuse": "net_ca",                   # 팀원 네트워크 시나리오 재사용(코드 미수정)
        "evidence": ["network"],
        "batch": 3,
    },
    {
        "id": "c_g_jvm_normal_memory",
        "label": "JVM 평상시 메모리",
        "incident_class": "benign",
        "threat_level": "low",
        "expected_action": "NONE",
        "expected_action_ideal": "NONE",
        "targets": [],
        "module": None,
        "external_tool": "traffic_gen.py --control none",
        "evidence": ["metric"],
        "batch": 3,
    },
    {
        "id": "c_n_aiops_self_load",
        "label": "AIOps 자체 부하 (모델 다운로드)",
        "incident_class": "benign",
        "threat_level": "low",
        "expected_action": "NONE",
        "expected_action_ideal": "NONE",
        "targets": [],
        "module": None,
        "external_tool": "replay_rule.py (+ 모델 pull)",
        "evidence": ["network"],
        "batch": 3,
    },
    {
        "id": "c_c_blocked_attack",
        "label": "이미 차단된 공격 (4xx 다발)",
        "incident_class": "attack",   # 막혔어도 공격 시도다(정상 활동 아님)
        "threat_level": "low",
        "expected_action": "NOTIFY",
        "expected_action_ideal": "NOTIFY",
        "targets": [],
        "module": None,
        "external_tool": "traffic_gen.py (차단되는 요청)",
        "evidence": ["nginx_log"],
        "notes": "요청이 실제 4xx 로 막히는지 확인(controls.all_blocked_4xx) + 자기신고 문자열 점검(controls.has_self_report_markers).",
        "batch": 3,
    },
    {
        "id": "c_e_password_mistype",
        "label": "비밀번호 오입력",
        "incident_class": "benign",
        "threat_level": "low",
        "expected_action": "NONE",
        "expected_action_ideal": "NONE",
        "targets": [],
        "module": None,
        "external_tool": "traffic_gen.py --control wrong-password",
        "evidence": ["app_log"],
        "batch": 3,
    },
    # 2차 A군 — 주입·정리 구현 (batch 4)
    {
        "id": "s1_b_recon_scan",
        "label": "정찰 (취약점 스캔)",
        "incident_class": "attack",
        "threat_level": "low",
        "expected_action": "NOTIFY",
        "expected_action_ideal": "NOTIFY",
        "targets": ["스캔 출발지"],
        "module": "v2.s1b_recon_scan",
        "external_tool": None,
        "evidence": ["nginx_log"],
        "attack_id": "T1595.002",
        "batch": 4,
    },
    {
        "id": "s2_b_c2_beacon",
        "label": "외부 통제 서버 연결 (C2 비컨)",
        "incident_class": "attack",
        "threat_level": "high",
        "expected_action": "ISOLATE",
        "expected_action_ideal": "BLOCK_EGRESS",
        "targets": ["leafy-backend"],
        "module": "v2.s2b_c2_beacon",
        "external_tool": None,
        "evidence": ["network"],
        "attack_id": "T1071.001",
        "batch": 4,
    },
    {
        "id": "s2_d_internal_recon",
        "label": "내부 정찰 (내부 포트 스캔)",
        "incident_class": "attack",
        "threat_level": "medium",
        "expected_action": "ISOLATE",
        "expected_action_ideal": "ISOLATE",
        "targets": ["leafy-backend"],
        "module": "v2.s2d_internal_recon",
        "external_tool": None,
        "evidence": ["network"],
        "attack_id": "T1046",
        "batch": 4,
    },
    {
        "id": "s2_e_db_bulk_read",
        "label": "DB 대량 조회",
        "incident_class": "attack",
        "threat_level": "high",
        "expected_action": "ISOLATE",
        "expected_action_ideal": "ISOLATE+KILL_SESSIONS",
        "targets": ["조회 세션", "출발 서비스"],
        "module": "v2.s2e_db_bulk_read",
        "external_tool": None,
        "evidence": ["metric", "app_log"],
        "attack_id": "T1213.006",
        "batch": 4,
        "notes": "app_log 증거는 DB 로그 수집 여부에 달림(측정 PC 확인).",
    },
    {
        "id": "f1_a_cpu_overload",
        "label": "CPU 과부하 (정상 요청 과다)",
        "incident_class": "failure",
        "threat_level": "medium",
        "expected_action": "THROTTLE",
        "expected_action_ideal": "THROTTLE",
        "targets": ["leafy-backend"],
        "module": "v2.f1a_cpu_overload",
        "external_tool": None,
        "evidence": ["metric", "nginx_log"],
        "attack_id": None,
        "batch": 4,
    },
    {
        "id": "f1_c_oom_restart",
        "label": "OOM 재시작 반복",
        "incident_class": "failure",
        "threat_level": "medium",
        "expected_action": "RESTART",
        "expected_action_ideal": "RESTART",
        "targets": ["leafy-backend"],
        "module": "v2.f1c_oom_restart",
        "external_tool": None,
        "evidence": ["metric"],
        "attack_id": None,
        "batch": 4,
    },
    {
        "id": "f3_b_bad_env_config",
        "label": "잘못된 설정 (환경변수) 배포",
        "incident_class": "failure",
        "threat_level": "high",
        "expected_action": "NOTIFY",
        "expected_action_ideal": "ROLLBACK",
        "targets": ["배포 서비스"],
        "module": "v2.f3b_bad_env_config",
        "external_tool": None,
        "evidence": ["metric", "app_log"],
        "attack_id": None,
        "batch": 4,
    },
    {
        "id": "c_b_short_load_spike",
        "label": "짧은 정상 부하 스파이크",
        "incident_class": "benign",
        "threat_level": "low",
        "expected_action": "NONE",
        "expected_action_ideal": "NONE",
        "targets": [],
        "module": "v2.c_b_short_load_spike",
        "external_tool": None,
        "evidence": ["metric"],
        "attack_id": None,
        "batch": 4,
        "pair": ["f1_a_cpu_overload", "s2_a_resource_theft"],
    },
    {
        "id": "c_d_normal_restart",
        "label": "정상 재배포·재시작",
        "incident_class": "benign",
        "threat_level": "low",
        "expected_action": "NONE",
        "expected_action_ideal": "NONE",
        "targets": [],
        "module": "v2.c_d_normal_restart",
        "external_tool": None,
        "evidence": ["metric"],
        "attack_id": None,
        "batch": 4,
        "pair": ["f1_c_oom_restart", "f3_a_bad_image_deploy", "f3_b_bad_env_config"],
    },
    {
        "id": "c_h_admin_backup",
        "label": "정상 관리 작업 (백업)",
        "incident_class": "benign",
        "threat_level": "low",
        "expected_action": "NONE",
        "expected_action_ideal": "NONE",
        "targets": [],
        "module": "v2.c_h_admin_backup",
        "external_tool": None,
        "evidence": ["metric"],
        "attack_id": None,
        "batch": 4,
        "pair": ["f2_c_db_pool_exhaustion", "s2_e_db_bulk_read"],
    },
    {
        "id": "c_j_allowed_external_call",
        "label": "정상 외부 API 호출 (허용 목적지)",
        "incident_class": "benign",
        "threat_level": "low",
        "expected_action": "NONE",
        "expected_action_ideal": "NONE",
        "targets": [],
        "module": "v2.c_j_allowed_external_call",
        "external_tool": None,
        "evidence": ["network"],
        "attack_id": None,
        "batch": 4,
        "pair": ["s2_b_c2_beacon"],
    },
    {
        "id": "c_l_broken_link",
        "label": "깨진 링크 404",
        "incident_class": "benign",
        "threat_level": "low",
        "expected_action": "NONE",
        "expected_action_ideal": "NONE",
        "targets": [],
        "module": "v2.c_l_broken_link",
        "external_tool": None,
        "evidence": ["nginx_log"],
        "attack_id": None,
        "batch": 4,
        "pair": ["s1_b_recon_scan"],
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
                f"{row['id']}: expected_action={row['expected_action']} 은 LLM 허용 조치에 없다 "
                f"{POLICY_ACTIONS}")
        for ch in row.get("evidence", []):
            if ch not in EVIDENCE_CHANNELS:
                raise ValueError(
                    f"{row['id']}: evidence={ch} 은 채널 {EVIDENCE_CHANNELS} 에 없다")
        if row.get("incident_class") not in INCIDENT_CLASSES:
            raise ValueError(f"{row['id']}: incident_class={row.get('incident_class')} 은 "
                             f"{INCIDENT_CLASSES} 에 없다")
        if row.get("module") and row.get("external_tool"):
            raise ValueError(f"{row['id']}: module 과 external_tool 을 동시에 둘 수 없다")
        aid = row.get("attack_id")
        if aid is not None and not re.fullmatch(r"T\d{4}(\.\d{3})?|TODO", aid):
            raise ValueError(f"{row['id']}: attack_id 형식 오류: {aid}")
        if aid and row["incident_class"] != "attack":
            raise ValueError(f"{row['id']}: attack_id 는 attack 행에만")
    for row in registry:
        for other in row.get("pair", []):
            if row["incident_class"] != "benign":
                raise ValueError(f"{row['id']}: pair 는 대조(benign) 행에만")
            if other not in ids:
                raise ValueError(f"{row['id']}: pair 대상 없음: {other}")


_HELDOUT_MODULES = ("v2.heldout", "v2.heldout.variant_specs")


def load_heldout_specs():
    """
    평가용 변형 스펙을 선택적으로 읽는다. scenarios/v2/heldout/ 는 .gitignore 대상이라
    저장소에 없는 것이 기본이다 — 없으면 조용히 None. 정답 레이블은 여기서 읽지 않는다.
    (heldout 모듈 자체가 다른 이유로 import 에 실패하면 숨기지 않고 그대로 올린다.)
    """
    try:
        variant_specs = importlib.import_module("v2.heldout.variant_specs")
    except ImportError as e:
        # heldout 패키지/모듈이 없을 때만 조용히 건너뛴다(폴더 부재, sys.modules None 포함).
        # 다른 모듈이 없어서 난 오류는 숨기지 않고 그대로 올린다.
        if getattr(e, "name", None) in _HELDOUT_MODULES or getattr(e, "name", None) is None:
            return None
        raise
    return getattr(variant_specs, "HELDOUT_VARIANT_SPECS", None)


_validate()
HELDOUT_VARIANT_SPECS = load_heldout_specs()
