from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Any, Literal
# ── 파일 상단 import 바로 아래에 추가 ──
_KNOWN_CONTAINERS = [
    "leafy-backend", "leafy-frontend", "leafy-db",
    "aiops-pipeline", "aiops-remediation", "ollama",
]

def _extract_container_from_text(text: str) -> list[str]:
    return [c for c in _KNOWN_CONTAINERS if c in text]

class LLMAnalysisResult(BaseModel):
    """
    LLM(Llama-3.1)이 출력해야 할 JSON 구조.
    Remediation Agent가 이 스키마를 기반으로 분기 처리.
    """
    root_cause: str = Field(
        default="분석 실패 — 수동 확인 필요",
        description="Root cause summary (2-3 sentences)"
    )
    
    # ★ action을 구조화 필드로 분리
    action_type: Literal["RESTART", "ISOLATE", "SCALE", "PAUSE", "THROTTLE", "NOTIFY", "NONE"] = Field(
        default="NONE",
        description="Action type for automated remediation"
    )
    action_targets: list[str] = Field(
        default=[],
        description="Target container names (e.g. ['leafy-backend'])"
    )
    action_description: str = Field(
        default="manual investigation required",
        description="Human-readable action description"
    )
    
    threat_level: Literal["low", "medium", "high", "critical"] = Field(default="medium")
    action_risk: Literal["low", "medium", "high"] = Field(default="medium")
    evidence: list[str] = Field(default=[])
    confidence: float = Field(default=0.0)

    # ─── Validators ────────────────────────────────
    # ★ 이거 추가 (맨 위 validator로)
    @model_validator(mode="before")
    @classmethod
    def handle_legacy_action(cls, values: Any) -> Any:
        if not isinstance(values, dict):
            return values
        if not values.get("action_type") and values.get("action"):
            action_text = str(values["action"]).lower()
            if "restart" in action_text:
                values["action_type"] = "RESTART"
            elif "isolate" in action_text or "block" in action_text:
                values["action_type"] = "ISOLATE"
            elif "scale" in action_text:
                values["action_type"] = "SCALE"
            elif "pause" in action_text or "freeze" in action_text:
                values["action_type"] = "PAUSE"
            elif "throttle" in action_text or "limit" in action_text or "quota" in action_text:
                values["action_type"] = "THROTTLE"
            elif "notify" in action_text or "alert" in action_text:
                values["action_type"] = "NOTIFY"
            else:
                values["action_type"] = "NONE"
            # ✅ Fix: 버그 4
            extracted = _extract_container_from_text(action_text)
            if extracted:
                values.setdefault("action_targets", extracted)
            values.setdefault("action_description", values["action"])
        return values
    
    @field_validator("action_type", mode="before")
    @classmethod
    def normalize_action_type(cls, v: Any) -> str:
        if v is None:
            return "NONE"
        s = str(v).upper().strip()
        return s if s in ("RESTART", "ISOLATE", "SCALE", "PAUSE", "THROTTLE", "NOTIFY", "NONE") else "NONE"
    
    @field_validator("action_targets", mode="before")
    @classmethod
    def coerce_action_targets(cls, v: Any) -> list[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [v] if v else []
        if isinstance(v, list):
            return [str(item) for item in v if item]
        return []

    @field_validator("evidence", mode="before")
    @classmethod
    def coerce_evidence(cls, v: Any) -> list[str]:
        if not isinstance(v, list):
            return []
        result = []
        for item in v:
            if isinstance(item, str):
                result.append(item)
            elif isinstance(item, dict):
                parts = [f"{k}: {val}" for k, val in item.items()]
                result.append(", ".join(parts))
            else:
                result.append(str(item))
        return result

    @field_validator("confidence", mode="before")
    @classmethod
    def coerce_confidence(cls, v: Any) -> float:
        if v is None:
            return 0.0
        try:
            return max(0.0, min(1.0, float(v)))
        except (TypeError, ValueError):
            return 0.0

    @field_validator("root_cause", "action_description", mode="before")
    @classmethod
    def coerce_str_field(cls, v: Any, info: Any) -> str:
        _defaults = {
            "root_cause": "분석 실패 — 수동 확인 필요",
            "action_description": "manual investigation required",
        }
        if v is None or v == "":
            return _defaults.get(info.field_name, "")
        if not isinstance(v, str):
            v = str(v)
        return v[:500]

    @field_validator("threat_level", mode="before")
    @classmethod
    def normalize_threat_level(cls, v: Any) -> str:
        if v is None:
            return "medium"
        s = str(v).lower().strip()
        return s if s in ("low", "medium", "high", "critical") else "medium"

    @field_validator("action_risk", mode="before")
    @classmethod
    def normalize_action_risk(cls, v: Any) -> str:
        if v is None:
            return "medium"
        s = str(v).lower().strip()
        return s if s in ("low", "medium", "high") else "medium"