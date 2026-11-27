"""
LLM 이 고른 조치 대상의 후처리 검증.

대상은 입력 증거에 실제로 나온 값만 허용한다. 프롬프트 조립(prompt/builder_v2.py)이 증거 ID 별로
"이 항목에 나온 대상 값" 을 target_values 로 넘기고, LLM 은 action_targets 와 그 근거 ID
(target_evidence) 를 낸다. 맞지 않으면 대상을 비우고 NOTIFY 로 낮춰 사람에게 넘긴다 —
분석 자체는 유효하므로 analysis_status 는 valid 로 두고 target_validation=downgraded 와 사유를 남긴다.

서비스별 허용 조치(runtime·service)는 Remediation 코드가 정한다. 여기서는 중복 정의하지 않고,
"관측 target 과 같은가 / 계정이 증거에 있는가" 만 본다. 형식(인젝션 형태 문자열)은 출력 스키마
단계에서 분석 무효로 막는다(schemas/llm_output.ActionTarget).

사유 코드: target_count, account_target_required, account_target_not_allowed,
target_evidence_missing, target_not_in_evidence
(프롬프트에 없는 증거 ID 인용은 evidence 와 같이 분석 무효 unknown_evidence:<id> 다.)
"""

from __future__ import annotations

from schemas.actions import ACCOUNT_TARGET_PREFIX, NO_TARGET_ACTIONS


def candidates(target_values: dict) -> list[str]:
    """증거에 나온 대상 값 전체 (순서 유지, 중복 제거). 출력 스키마 enum 과 프롬프트 후보 목록에 쓴다."""
    return list(dict.fromkeys(v for values in target_values.values() for v in values))


def _check(action: str, targets: list, target_evidence: list, target_values: dict) -> str | None:
    if len(targets) != 1:
        return "target_count"
    target = targets[0]
    is_account = target.startswith(ACCOUNT_TARGET_PREFIX)
    if action == "LOCK_ACCOUNT" and not is_account:
        return "account_target_required"
    if action != "LOCK_ACCOUNT" and is_account:
        return "account_target_not_allowed"
    if not target_evidence:
        return "target_evidence_missing"
    if not any(target in target_values.get(i, ()) for i in target_evidence):
        return "target_not_in_evidence"
    return None


def validate_targets(result, target_values: dict):
    """LLMAnalysisResult -> 검증 결과가 반영된 LLMAnalysisResult (예외 없음)."""
    if result.action_type in NO_TARGET_ACTIONS:
        return result.model_copy(update={"action_targets": [], "target_evidence": [],
                                         "target_validation": "not_applicable"})
    reason = _check(result.action_type, result.action_targets,
                    list(dict.fromkeys(result.target_evidence)), target_values)
    if reason is None:
        return result.model_copy(update={"target_evidence": list(dict.fromkeys(result.target_evidence)),
                                         "target_validation": "validated"})
    return result.model_copy(update={
        "proposed_action": result.action_type, "action_type": "NOTIFY",
        "action_targets": [], "target_evidence": [],
        "target_validation": "downgraded", "target_reason": reason,
    })
