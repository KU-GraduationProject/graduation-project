"""Typed RCA recommendations for manual proposal handoff, never command generation.

Controller images independently validate this wire contract and bind actual operator
configuration. LLM-supplied URLs, SQL, commands, policies and health checks are forbidden.
"""
from __future__ import annotations

from datetime import datetime, timezone
import math
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from schemas.actions import ACTION_TYPES, NO_TARGET_ACTIONS

# LLM 이 고를 수 있는 조치 중 시스템을 바꾸는 것. 수동 승인 제안으로만 보낸다.
FORWARD_ACTIONS = frozenset(ACTION_TYPES) - frozenset(NO_TARGET_ACTIONS)
CONTAINER_ACTIONS = frozenset({"RESTART", "PAUSE", "ISOLATE", "THROTTLE", "ROLLBACK", "RECREATE"})
IDENTITY_FIELDS = ("site", "service", "source", "runtime", "target")
REQUIRED_FIELDS = ("root_cause", "action_type", "action_targets", "threat_level", "evidence", "confidence")
RESOURCE = r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$"


class PlanError(ValueError):
    pass


class StrictParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class NoParameters(StrictParameters):
    pass


class SessionsParameters(StrictParameters):
    operation: Literal["terminate_idle_sessions", "cancel_long_queries"]
    min_age_seconds: int | None = Field(default=None, ge=1, le=86400)
    max_sessions: int | None = Field(default=None, ge=1, le=20)


class RollbackParameters(StrictParameters):
    version: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class ReasonParameters(StrictParameters):
    reason: str | None = Field(default=None, min_length=1, max_length=256)

    @field_validator("reason")
    @classmethod
    def no_controls(cls, value):
        if value is not None and any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("control_character")
        return value


class AccountParameters(ReasonParameters):
    account_id: str = Field(pattern=RESOURCE)


class LockParameters(AccountParameters):
    duration_seconds: int = Field(ge=1, le=86400)


PARAMETERS = {"KILL_SESSIONS": SessionsParameters, "ROLLBACK": RollbackParameters,
              "LOCK_ACCOUNT": LockParameters}


def typed_parameters(action, parameters):
    if not isinstance(parameters, dict):
        raise PlanError("invalid_action_parameters")
    if action not in FORWARD_ACTIONS:
        if parameters:
            raise PlanError("unsupported_action_parameters")
        return {}
    try:
        return PARAMETERS.get(action, NoParameters).model_validate(parameters).model_dump(exclude_none=True)
    except ValidationError:
        raise PlanError("invalid_action_parameters") from None


def _raw_errors(values):
    errors = []
    if any(k not in values for k in REQUIRED_FIELDS):
        errors.append("missing_required_analysis_fields")
    if not isinstance(values.get("root_cause"), str) or not values.get("root_cause", "").strip():
        errors.append("invalid_root_cause")
    if values.get("action_type") not in ACTION_TYPES:
        errors.append("invalid_action_type")
    targets = values.get("action_targets")
    if not isinstance(targets, list) or any(not isinstance(t, str) or not t or t != t.strip() for t in targets):
        errors.append("invalid_action_targets")
    if values.get("threat_level") not in {"low", "medium", "high", "critical"}:
        errors.append("invalid_threat_level")
    evidence = values.get("evidence")
    if not isinstance(evidence, list) or any(not isinstance(e, str) or not e.strip() for e in evidence):
        errors.append("invalid_evidence")
    confidence = values.get("confidence")
    if type(confidence) not in (int, float) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
        errors.append("invalid_confidence")
    return errors


def _incident(alert, identity, identity_status):
    if identity_status != "resolved" or not identity.complete:
        raise PlanError("observation_identity_not_verified")
    canonical = {k: getattr(identity, k) for k in IDENTITY_FIELDS}
    if any(not isinstance(v, str) or not v.strip() or v != v.strip()
           or v.lower() in {"unknown", "none", "n/a", "stdout", "stderr"} for v in canonical.values()):
        raise PlanError("observation_identity_not_verified")
    fingerprint = alert.fingerprint
    if not isinstance(fingerprint, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", fingerprint):
        raise PlanError("incident_fingerprint_required")
    try:
        timestamp = datetime.fromisoformat(alert.startsAt.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError()
        starts = timestamp.astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError, AttributeError, OverflowError):
        raise PlanError("incident_starts_at_required") from None
    return canonical, {"fingerprint": fingerprint, "starts_at": starts}


def build_proposal(alert, result, identity, identity_status, min_confidence=0.8):
    """Return one manually approved wire proposal for the observed target.

    LLM 은 무엇을(action_type)·어디에(action_targets)만 정한다. 실행 세부값(잠금 시간, 세션
    정리 방식 등)과 다단계 계획은 LLM 출력에 없다 — 세부값이 필요한 조치는 아직 제안하지 않는다.
    """
    if not math.isfinite(min_confidence) or not .8 <= min_confidence <= 1:
        raise PlanError("invalid_proposal_confidence_setting")
    if result.analysis_status != "valid":
        raise PlanError("invalid_analysis")
    canonical, incident = _incident(alert, identity, identity_status)
    step = result.model_dump()
    if _raw_errors(step):
        raise PlanError("invalid_analysis")
    action = step["action_type"]
    if action not in FORWARD_ACTIONS:
        raise PlanError("unsupported_forward_action")
    if step["confidence"] < min_confidence:
        raise PlanError("low_confidence")
    if not step["evidence"]:
        raise PlanError("analysis_evidence_required")
    if step["action_targets"] != [canonical["target"]]:
        raise PlanError("action_targets_do_not_match_observation")
    if action in CONTAINER_ACTIONS and canonical["runtime"] != "container":
        raise PlanError("unsupported_action_runtime")
    if action == "KILL_SESSIONS" and (canonical["runtime"] not in {"host", "container"} or canonical["service"] != "db"):
        raise PlanError("postgres_identity_required")
    parameters = typed_parameters(action, {})
    analysis = {k: step[k] for k in REQUIRED_FIELDS}
    analysis.update(action_parameters=parameters, analysis_status="valid",
                    action_description="manual review required")
    wire = {"version": 1, "action_type": action, "targets": [canonical["target"]],
            "parameters": parameters, "identity": canonical, "incident": incident}
    return {"analysis": analysis, "plan": wire}
