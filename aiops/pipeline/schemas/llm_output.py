"""
LLM 분석 결과 스키마와 엄격 검증.

이전에는 모든 필드에 기본값이 있어, 잘리거나 깨진 응답이 NONE/medium/0.0 으로 조용히
채워져 정상 판단처럼 처리됐다. 이제:
  - LLM 이 내야 하는 필드는 기본값이 없다. 빠지거나 enum 밖이면 검증 실패다.
  - 실패한 응답은 analysis_status=invalid + invalid_reasons 로 남기고, 조치는
    NOTIFY("분석 실패 — 사람 확인") 로 둔다. NONE 으로 바꾸지 않는다.
  - Ollama 에는 output_schema() 를 format 으로 넘겨 형식을 강제한다.

LLM 은 관측과 추천만 한다. 위험도·승인·자동 실행 여부는 Remediation 정책 엔진이 정한다
(aiops/policy/remediation_policy.yml). 정책 엔진이 쓰는 action_type / action_targets /
threat_level / confidence 의 이름·의미는 바꾸지 않는다.

invalid 사유 코드: truncated, parse_error, missing_field:<f>, invalid_enum:<f>,
invalid_type:<f>, unknown_evidence:<id>
"""

from __future__ import annotations

import json
import math
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from schemas.actions import ACTION_TARGETS, ACTION_TYPES, INCIDENT_CLASSES, NO_TARGET_ACTIONS, THREAT_LEVELS

ROOT_CAUSE_MAX = 400
MAX_EVIDENCE = 5

ActionType = Literal[ACTION_TYPES]
ActionTarget = Literal[ACTION_TARGETS]
IncidentClass = Literal[INCIDENT_CLASSES]
ThreatLevel = Literal[THREAT_LEVELS]

# LLM 이 내는 필드 (output_schema 의 required 와 같다)
LLM_FIELDS = ("root_cause", "incident_class", "action_type", "action_targets",
              "threat_level", "evidence", "confidence")


class LLMAnalysisResult(BaseModel):
    """
    LLM 필드는 기본값이 없다. analysis_status / invalid_reasons 는 파서가 채우는
    pipeline 메타데이터다 (LLM 이 보내도 무시하고 파서가 덮어쓴다).
    """
    model_config = ConfigDict(extra="ignore")

    root_cause: str = Field(max_length=ROOT_CAUSE_MAX)
    incident_class: IncidentClass
    action_type: ActionType
    action_targets: list[ActionTarget]
    threat_level: ThreatLevel
    evidence: list[str] = Field(max_length=MAX_EVIDENCE)   # 프롬프트 증거 ID
    confidence: float = Field(ge=0.0, le=1.0)               # 기록용. 자동 실행 근거 아님

    analysis_status: Literal["valid", "invalid"] = "valid"
    invalid_reasons: list[str] = []

    @classmethod
    def invalid(cls, reasons: list[str], detail: str = "") -> "LLMAnalysisResult":
        """
        분석 실패 결과. 사람에게 알리는 경로(NOTIFY, 대상 없음)로 보낸다.
        incident_class 는 알 수 없으므로 None. threat_level 은 사람이 확인해야 하는
        상태라 medium(긴급도 elevated) 으로 둔다 — analysis_status 로 실패가 드러난다.
        """
        text = "분석 실패 — 수동 확인 필요 (" + ", ".join(reasons) + ")"
        if detail:
            text += f": {detail}"
        return cls.model_construct(
            root_cause=text[:ROOT_CAUSE_MAX], incident_class=None, action_type="NOTIFY",
            action_targets=[], threat_level="medium", evidence=[], confidence=0.0,
            analysis_status="invalid", invalid_reasons=list(reasons))


def output_schema(evidence_ids: list[str] | None = None) -> dict:
    """Ollama /api/chat format 에 넘기는 JSON 스키마. 증거 ID 를 알면 enum 으로 제한한다."""
    evidence_item = {"type": "string"}
    if evidence_ids:
        evidence_item = {"type": "string", "enum": list(evidence_ids)}
    return {
        "type": "object",
        "properties": {
            "root_cause": {"type": "string", "maxLength": ROOT_CAUSE_MAX},
            "incident_class": {"type": "string", "enum": list(INCIDENT_CLASSES)},
            "action_type": {"type": "string", "enum": list(ACTION_TYPES)},
            "action_targets": {"type": "array", "items": {"type": "string", "enum": list(ACTION_TARGETS)}},
            "threat_level": {"type": "string", "enum": list(THREAT_LEVELS)},
            "evidence": {"type": "array", "items": evidence_item, "maxItems": MAX_EVIDENCE},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        },
        "required": list(LLM_FIELDS),
        "additionalProperties": False,
    }


def _reason(err: dict) -> str:
    field = str(err["loc"][0]) if err.get("loc") else "?"
    kind = err.get("type", "")
    if kind == "missing":
        return f"missing_field:{field}"
    if kind in ("literal_error", "enum"):
        return f"invalid_enum:{field}"
    return f"invalid_type:{field}"


def truncation_reason(done_reason: str | None, prompt_eval_count: int | None,
                      num_ctx: int, num_predict: int) -> bool:
    """
    출력이 num_predict 에서 끊겼거나(done_reason=length), 입력이 num_ctx 에 근접해
    (출력 여유 num_predict 미만) Ollama 가 입력 앞부분을 잘랐을 수 있으면 True.
    """
    if done_reason == "length":
        return True
    return prompt_eval_count is not None and prompt_eval_count >= num_ctx - num_predict


def parse_analysis(content: str | None, *, evidence_ids: list[str] | None,
                   done_reason: str | None = None, prompt_eval_count: int | None = None,
                   num_ctx: int = 4096, num_predict: int = 400) -> LLMAnalysisResult:
    """
    LLM 응답 본문 -> LLMAnalysisResult. 실패하면 invalid 결과를 돌려준다 (예외 없음).
    evidence_ids 가 None 이면(legacy 프롬프트: ID 없음) evidence 를 ID 로 검사하지 않는다.
    """
    reasons = []
    if truncation_reason(done_reason, prompt_eval_count, num_ctx, num_predict):
        reasons.append("truncated")

    try:
        raw = json.loads(content or "")
    except (TypeError, ValueError):
        return LLMAnalysisResult.invalid(reasons + ["parse_error"])
    if not isinstance(raw, dict):
        return LLMAnalysisResult.invalid(reasons + ["parse_error"])
    raw = {k: v for k, v in raw.items() if k not in ("analysis_status", "invalid_reasons")}

    # 숫자가 아닌 confidence(문자열·bool·NaN)를 0.0 등으로 메우지 않는다
    conf = raw.get("confidence")
    if "confidence" in raw and (isinstance(conf, bool) or not isinstance(conf, (int, float))
                                or not math.isfinite(conf)):
        reasons.append("invalid_type:confidence")
        raw.pop("confidence")

    try:
        result = LLMAnalysisResult.model_validate(raw)
    except ValidationError as e:
        reasons.extend(_reason(err) for err in e.errors())
        result = None

    if result is not None and evidence_ids is not None:
        known = set(evidence_ids)
        reasons.extend(f"unknown_evidence:{i}" for i in result.evidence if i not in known)

    if result is None or reasons:
        # 같은 필드가 두 번 잡히지 않게 (confidence 를 뺀 뒤 missing 으로 다시 잡힘)
        reasons = [r for r in reasons if not (r == "missing_field:confidence"
                                               and "invalid_type:confidence" in reasons)]
        return LLMAnalysisResult.invalid(list(dict.fromkeys(reasons)))

    # NONE·NOTIFY 는 시스템을 바꾸지 않으므로 대상이 있어도 의미가 없다 — 비운다
    updates = {"evidence": list(dict.fromkeys(result.evidence))}
    if result.action_type in NO_TARGET_ACTIONS:
        updates["action_targets"] = []
    return result.model_copy(update=updates)
