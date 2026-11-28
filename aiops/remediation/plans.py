"""Strict manual-proposal wire contract; separate from executable operator plans."""
from datetime import datetime, timezone
import hashlib
import json
import math
import store
from executor.managed_registry import ACTIONS as MANAGED_ACTIONS

FORWARD_ACTIONS = frozenset({"RESTART", "PAUSE", "ISOLATE", "THROTTLE", "KILL_SESSIONS", "ROLLBACK",
                            "RECREATE", "LOCK_ACCOUNT", "REVOKE_SESSION", "DISABLE_FEATURE"}) | MANAGED_ACTIONS
ANALYSIS_KEYS = frozenset({"action_type", "action_targets", "action_parameters", "action_description", "root_cause", "threat_level", "evidence", "confidence", "analysis_status"})


def timestamp(value):
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            raise ValueError()
        return dt.astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError, OverflowError):
        raise ValueError("invalid_plan_incident_time") from None


def normalized_analysis(analysis):
    if not isinstance(analysis, dict) or set(analysis) - ANALYSIS_KEYS:
        raise ValueError("invalid_plan_analysis_fields")
    result = dict(analysis)
    action = result.get("action_type")
    targets = result.get("action_targets")
    confidence = result.get("confidence")
    parameters = result.get("action_parameters", {})
    if (not isinstance(action, str) or action.upper() not in FORWARD_ACTIONS
            or not isinstance(targets, list) or not targets or any(not isinstance(t, str) or not t or t != t.strip() for t in targets)
            or len(set(targets)) != len(targets) or not isinstance(parameters, dict)
            or isinstance(confidence, bool) or not isinstance(confidence, (int,float))
            or not math.isfinite(confidence) or not .8 <= confidence <= 1
            or result.get("threat_level") not in {"low", "medium", "high", "critical"}
            or not isinstance(result.get("root_cause"), str) or not result["root_cause"].strip()
            or not isinstance(result.get("evidence"), list) or not result["evidence"]
            or any(not isinstance(e, str) or not e.strip() for e in result["evidence"])
            or result.get("analysis_status", "valid") != "valid"):
        raise ValueError("invalid_manual_plan_analysis")
    result.update(action_type=action.upper(), action_targets=sorted(targets), action_parameters=parameters)
    json.dumps(result, allow_nan=False)
    return result


def validate_wire(plan, alert, analysis):
    if (not isinstance(plan, dict) or set(plan) != {"version","action_type","targets","parameters","identity","incident"}
            or type(plan.get("version")) is not int or plan["version"] != 1):
        raise ValueError("invalid_manual_plan_schema")
    analysis = normalized_analysis(analysis)
    _, identity = store.incident_key(alert)
    incident = plan["incident"]
    if (not isinstance(incident, dict) or set(incident) != {"fingerprint","starts_at"}
            or not isinstance(plan["targets"], list) or any(not isinstance(t,str) for t in plan["targets"])
            or plan["action_type"] != analysis["action_type"] or sorted(plan["targets"]) != analysis["action_targets"]
            or plan["parameters"] != analysis["action_parameters"] or plan["identity"] != identity
            or incident["fingerprint"] != alert.get("fingerprint")
            or timestamp(incident["starts_at"]) != timestamp(alert.get("startsAt"))
            or analysis["action_targets"] != [identity["target"]]):
        raise ValueError("manual_plan_content_mismatch")
    return {"version":1,"action_type":analysis["action_type"],"targets":analysis["action_targets"],
            "parameters":analysis["action_parameters"],"identity":identity,
            "incident":{"fingerprint":incident["fingerprint"],"starts_at":timestamp(incident["starts_at"])}}


def validate_steps(steps, alert):
    if not isinstance(steps, list) or not 1 <= len(steps) <= 3:
        raise ValueError("plan_requires_one_to_three_steps")
    result=[]
    seen=set()
    for step in steps:
        if not isinstance(step, dict) or set(step) != {"analysis","plan"}:
            raise ValueError("invalid_plan_step")
        analysis=normalized_analysis(step["analysis"])
        wire=validate_wire(step["plan"],alert,analysis)
        key=json.dumps(wire,sort_keys=True,separators=(",",":"),allow_nan=False)
        if key in seen:
            raise ValueError("duplicate_remediation_step")
        seen.add(key)
        result.append({"analysis":analysis,"plan":wire})
    return result


def digest(steps):
    return hashlib.sha256(json.dumps([s["plan"] for s in steps],sort_keys=True,separators=(",",":"),allow_nan=False).encode()).hexdigest()
