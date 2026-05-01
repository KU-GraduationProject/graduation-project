from pydantic import BaseModel, Field, field_validator
from typing import Any, Literal


class LLMAnalysisResult(BaseModel):
    """
    LLM(Llama-3.1)이 출력해야 할 JSON 구조.
    Remediation Agent가 이 스키마를 기반으로 분기 처리.
    """

    root_cause: str = Field(
        description="Root cause summary (2-3 sentences)"
    )
    action: str = Field(
        description="Recommended remediation action (e.g. 'restart container leafy-backend')"
    )
    threat_level: Literal["low", "medium", "high", "critical"] = Field(
        description="Threat severity: low/medium/high/critical"
    )
    action_risk: Literal["low", "medium", "high"] = Field(
        description="Action risk: low=auto-execute, medium=approval recommended, high=admin approval required"
    )
    evidence: list[str] = Field(
        default=[],
        description="Supporting evidence list (metric values, log patterns, etc.)"
    )
    confidence: float = Field(
        ge=0.0, le=1.0,
        description="Analysis confidence 0.0~1.0"
    )

    @field_validator("evidence", mode="before")
    @classmethod
    def coerce_evidence(cls, v: Any) -> list[str]:
        """LLM이 evidence를 dict나 혼합 타입으로 반환할 경우 string으로 변환"""
        if not isinstance(v, list):
            return []
        result = []
        for item in v:
            if isinstance(item, str):
                result.append(item)
            elif isinstance(item, dict):
                # {'cpu_usage': 'peak=13.5'} → 'cpu_usage: peak=13.5'
                parts = [f"{k}: {val}" for k, val in item.items()]
                result.append(", ".join(parts))
            else:
                result.append(str(item))
        return result

    @field_validator("threat_level", mode="before")
    @classmethod
    def normalize_threat_level(cls, v: Any) -> str:
        if isinstance(v, str):
            v = v.lower().strip()
            if v not in ("low", "medium", "high", "critical"):
                return "medium"
        return v

    @field_validator("action_risk", mode="before")
    @classmethod
    def normalize_action_risk(cls, v: Any) -> str:
        if isinstance(v, str):
            v = v.lower().strip()
            if v not in ("low", "medium", "high"):
                return "medium"
        return v
