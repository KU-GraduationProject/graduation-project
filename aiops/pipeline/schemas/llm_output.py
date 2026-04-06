from pydantic import BaseModel, Field
from typing import Literal

class LLMAnalysisResult(BaseModel):
    """
    LLM(Llama-3.1)이 출력해야 할 JSON 구조.
    Remediation Agent가 이 스키마를 기반으로 분기 처리.
    """

    root_cause: str = Field(
        description="장애/이상의 근본 원인 요약 (한국어, 2~3문장)"
    )
    action: str = Field(
        description="권장 조치 명령 (예: 'restart container leafy-backend')"
    )
    threat_level: Literal["low", "medium", "high", "critical"] = Field(
        description="위협 심각도: low/medium/high/critical"
    )
    action_risk: Literal["low", "medium", "high"] = Field(
        description="조치 위험도: low=즉시 자동실행 가능, medium=승인 권장(threat_level에 따라 분기), high=관리자 승인 필요"
    )
    evidence: list[str] = Field(
        default=[],
        description="판단 근거 목록 (메트릭 수치, 로그 패턴 등)"
    )
    confidence: float = Field(
        ge=0.0, le=1.0,
        description="분석 신뢰도 0.0~1.0"
    )
