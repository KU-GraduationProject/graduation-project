"""Typed RCA recommendations for manual proposal handoff, never command generation.

Controller images independently validate this wire contract and bind actual operator
configuration. LLM-supplied URLs, SQL, commands, policies and health checks are forbidden.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import math
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from schemas.actions import RECOMMENDED_ACTIONS

FORWARD_ACTIONS = frozenset({"RESTART", "PAUSE", "ISOLATE", "THROTTLE", "KILL_SESSIONS",
                             "ROLLBACK", "RECREATE", "LOCK_ACCOUNT", "REVOKE_SESSION", "DISABLE_FEATURE"})
CONTAINER_ACTIONS = frozenset({"RESTART", "PAUSE", "ISOLATE", "THROTTLE", "ROLLBACK", "RECREATE"})
IDENTITY_FIELDS = ("site", "service", "source", "runtime", "target")
REQUIRED_FIELDS = ("root_cause", "action_type", "action_targets", "threat_level", "evidence", "confidence")
STEP_FIELDS = frozenset({"action_type", "action_targets", "action_parameters", "action_description",
                         "threat_level", "evidence", "confidence"})
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


class FeatureParameters(ReasonParameters):
    feature_id: str = Field(pattern=RESOURCE)


PARAMETERS = {"KILL_SESSIONS": SessionsParameters, "ROLLBACK": RollbackParameters,
              "LOCK_ACCOUNT": LockParameters, "REVOKE_SESSION": AccountParameters,
              "DISABLE_FEATURE": FeatureParameters}


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
    if values.get("action_type") not in RECOMMENDED_ACTIONS:
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


def sanitize_llm_recommendation(raw):
    """Retain informational compatibility while preventing coercion from authorizing action.

    Rejected parameter values are discarded before history, Loki or notifications see
    them. Only fixed reason codes are kept; unknown command/credential keys are not.
    """
    values = dict(raw)
    errors = _raw_errors(values)
    if values.get("analysis_status") == "invalid":
        errors.append("previously_invalid_analysis")
    try:
        values["action_parameters"] = typed_parameters(values.get("action_type"), values.get("action_parameters", {}))
    except PlanError as exc:
        values["action_parameters"] = {}
        errors.append(str(exc))
    raw_steps = values.get("remediation_steps", [])
    steps = []
    if not isinstance(raw_steps, list) or len(raw_steps) > 3:
        errors.append("invalid_remediation_steps")
    else:
        for step in raw_steps:
            if (not isinstance(step, dict) or set(step) - STEP_FIELDS
                    or "action_type" not in step or "action_targets" not in step):
                errors.append("invalid_remediation_step")
                continue
            merged = {k: values.get(k) for k in REQUIRED_FIELDS}
            merged["action_description"] = values.get("action_description", "manual review required")
            merged.update(step)
            step_errors = _raw_errors(merged)
            try:
                merged["action_parameters"] = typed_parameters(merged["action_type"], step.get("action_parameters", {}))
            except PlanError as exc:
                merged["action_parameters"] = {}
                step_errors.append(str(exc))
            if step_errors:
                errors.extend(step_errors)
            else:
                steps.append(merged)
    values["remediation_steps"] = steps if not errors else []
    values["analysis_status"] = "invalid" if errors else "valid"
    values["analysis_errors"] = sorted(set(errors))
    return values


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


def build_proposals(alert, result, identity, identity_status, min_confidence=0.8):
    """Return one-to-three independently approved, same-target wire proposals."""
    if not math.isfinite(min_confidence) or not .8 <= min_confidence <= 1:
        raise PlanError("invalid_proposal_confidence_setting")
    if result.analysis_status != "valid":
        raise PlanError("invalid_analysis")
    canonical, incident = _incident(alert, identity, identity_status)
    parent = result.model_dump()
    steps = result.remediation_steps or [parent]
    if not 1 <= len(steps) <= 3:
        raise PlanError("invalid_remediation_steps")
    if result.remediation_steps:
        for key in ("action_type", "action_targets", "action_parameters", "threat_level", "confidence"):
            if steps[0].get(key) != parent.get(key):
                raise PlanError("first_step_analysis_mismatch")
    proposals, seen = [], set()
    for step in steps:
        if _raw_errors(step):
            raise PlanError("invalid_remediation_step")
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
        parameters = typed_parameters(action, step.get("action_parameters", {}))
        duplicate = json.dumps([action, parameters], sort_keys=True, separators=(",", ":"))
        if duplicate in seen:
            raise PlanError("duplicate_remediation_step")
        seen.add(duplicate)
        analysis = {k: step[k] for k in REQUIRED_FIELDS}
        analysis.update(action_parameters=parameters, analysis_status="valid",
                        action_description=step.get("action_description", "manual review required"))
        wire = {"version": 1, "action_type": action, "targets": [canonical["target"]],
                "parameters": parameters, "identity": canonical, "incident": incident}
        proposals.append({"analysis": analysis, "plan": wire})
    return proposals
