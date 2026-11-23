"""
AIOps Remediation Agent (Final Version)
분석 결과 수신 → 다중 타겟(Array)에 대해 명시적 조치 실행

[수정] POST /slack/action 엔드포인트에 source 분기 추가
       - source="periodic_log_scan"  → 주기적 로그 스캔에서 온 승인
       - source="llm_health_check"   → LLM 헬스체크에서 온 승인
       - source="alert_triggered"    → 기존 alert 기반 승인 (기본값)
"""
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, StrictBool, ConfigDict
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import asyncio
import json
import logging
import os
import time
import urllib.parse
import re
import httpx
import evidence as evidence_mod
import recovery as recovery_mod
import store as store_mod
import plans as plans_mod
import service_verification as service_verification_mod
from actions.notify import Notifier
from executor.base import RECOVERY_ACTION, DisabledExecutor, ExecutionResult
from executor.local_docker import LocalDockerExecutor
from executor.remote import RemoteExecutor
from executor.identity import IdentityError, bind_targets, validate_bindings
from executor.router import route_action
from executor.extended import ExtendedExecutorRouter, is_extended_executor, select_executor
from policy.engine import load_engine
from policy.schema import (
    AUTO_EXECUTE_CANDIDATE,
    AWAITING_APPROVAL,
    BLOCKED,
    NO_ACTION,
    NOTIFY,
)
from security.replay import ReplayGuard
from security.service_auth import SIGNATURE_HEADER as SERVICE_SIGNATURE_HEADER
from security.service_auth import verify_service_request
from security.slack_signature import SIGNATURE_HEADER as SLACK_SIGNATURE_HEADER
from security.slack_signature import verify_slack_request
from slack_socket import SlackSettings, SocketModeRuntime

logging.basicConfig(level=logging.INFO)
# HTTPX INFO includes full webhook/response URLs, which are bearer credentials.
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)
LOKI_URL = os.getenv("LOKI_URL", "http://loki:3100")

# ─── 인증 (Phase 0) ──────────────────────────────────────
# 두 엔드포인트 모두 서명을 요구한다. 키가 없으면 요청을 거부한다 (fail closed) —
# 설정 누락을 "인증 없이 실행"으로 처리하면 안전장치가 의미를 잃는다.
SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET", "")
REMEDIATION_API_KEY = os.getenv("REMEDIATION_API_KEY", "")

_replay_guard = ReplayGuard()
slack_settings = SlackSettings.from_env()
slack_socket = None

# docker   : 로컬 Docker SDK로 조치를 실행한다 (기존 all-in-one docker-compose.yml)
# disabled : 조치를 실행하지 않는다. AIOps 단독 배포에서는 Leafy가 다른 PC에 있어 로컬 Docker 조치가 대상에 닿지 않고,
#            같은 이름의 로컬 컨테이너(남은 leafy-* 또는 AIOps 자신)를 건드릴 위험만 있다. 원격 조치 경로가 생기기 전까지 쓴다.
#            판단·알림·승인 기록은 그대로 남기고, 실행 결과는 SKIPPED로 기록한다.
REMEDIATION_MODE = os.getenv("REMEDIATION_MODE", "disabled")
if REMEDIATION_MODE not in ("docker", "disabled", "remote", "extended"):
    raise ValueError(f"REMEDIATION_MODE must be docker, remote, extended or disabled: {REMEDIATION_MODE!r}")

notifier = Notifier()

# 정책 엔진 (Phase 1). 로드에 실패하면 모든 조치를 차단하는 엔진이 돌아온다.
policy_engine = load_engine()

# 실행기 (Phase 2). disabled 모드에서는 Docker 를 아예 건드리지 않는다.
# 격리 대상/보존 네트워크는 정책 파일이 정하고, 실제 이름은 실행기가 inspect 로 읽는다.
_net_policy = getattr(policy_engine.config, "networks", None) \
    if hasattr(policy_engine, "config") else None
executor = (
    LocalDockerExecutor(
        isolate_networks=getattr(_net_policy, "isolate", ()),
        preserve_networks=getattr(_net_policy, "preserve", ()),
    )
    if REMEDIATION_MODE == "docker" else DisabledExecutor()
)
if REMEDIATION_MODE == "remote":
    executor = RemoteExecutor.from_env()
if REMEDIATION_MODE == "extended":
    # Docker primitives remain disabled unless their existing mode is explicitly selected.
    docker_mode = os.getenv("REMEDIATION_EXTENDED_DOCKER_MODE", "disabled")
    if docker_mode == "remote":
        docker_executor = RemoteExecutor.from_env()
    elif docker_mode == "docker":
        docker_executor = LocalDockerExecutor(
            isolate_networks=getattr(_net_policy, "isolate", ()),
            preserve_networks=getattr(_net_policy, "preserve", ()))
    elif docker_mode == "disabled":
        docker_executor = DisabledExecutor()
    else:
        raise ValueError("REMEDIATION_EXTENDED_DOCKER_MODE must be disabled, docker or remote")
    executor = ExtendedExecutorRouter(docker_executor=docker_executor)
# 하위 호환: 기존 테스트·코드가 "조치 실행기가 있는지" 를 이 이름으로 본다.
container_actions = executor if REMEDIATION_MODE == "docker" else None

# 조치 레코드 저장소 (멱등성·TTL·MTTR). 파일에 영속화해 재시작을 견딘다.
record_store = store_mod.RecordStore()
record_store.load()
record_store.reconcile_interrupted()
if not record_store.check_writable():
    logger.error("[Remediation] 상태 저장 불가 — 되돌려야 하는 조치(격리/동결/쿼터)는 "
                 "차단된다 (REMEDIATION_STATE_DIR 확인)")

# TTL 복구 스캐너 — 주기적으로 만료된 조치를 처리한다.
#   auto             : 자동 복구 (THROTTLE -> UNTHROTTLE)
#   require_approval : 자동 복구하지 않고 복구 승인을 요청한다 (ISOLATE/PAUSE)
TTL_SCAN_INTERVAL_SEC = float(os.getenv("REMEDIATION_TTL_SCAN_SEC", "60"))
ttl_scanner = None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """
    TTL 복구 스캐너를 기동한다. disabled 모드에서도 돌지만 실행기가 아무것도 하지
    않으므로 조치는 일어나지 않는다 (만료 레코드가 없으면 조용히 쉰다).
    """
    global ttl_scanner, slack_socket
    task = None
    if TTL_SCAN_INTERVAL_SEC > 0:
        ttl_scanner = recovery_mod.TtlScanner(
            record_store, executor, interval_sec=TTL_SCAN_INTERVAL_SEC,
            on_event=_on_ttl_event)
        task = asyncio.create_task(ttl_scanner.run())
        logger.info("[Recovery] TTL 스캐너 시작 (%.0fs 주기)", TTL_SCAN_INTERVAL_SEC)
    else:
        logger.info("[Recovery] TTL 스캐너 비활성 (REMEDIATION_TTL_SCAN_SEC<=0)")
    try:
        if slack_settings.transport == "socket_mode":
            slack_socket = SocketModeRuntime(slack_settings, handle_socket_action)
            await slack_socket.start()
        yield
    finally:
        if ttl_scanner is not None:
            ttl_scanner.stop()
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        if slack_socket is not None:
            await slack_socket.close()
            slack_socket = None


app = FastAPI(title="AIOps Remediation", version="0.1.0", lifespan=lifespan)
logger.info(f"[Remediation] REMEDIATION_MODE={REMEDIATION_MODE}")
# 키 값은 찍지 않는다. 설정 여부만 남겨 fail closed 상태를 운영자가 바로 알 수 있게 한다.
logger.info(
    "[Remediation] auth: SLACK_SIGNING_SECRET=%s REMEDIATION_API_KEY=%s",
    "set" if SLACK_SIGNING_SECRET else "MISSING (/slack/action 전부 거부)",
    "set" if REMEDIATION_API_KEY else "MISSING (/action 전부 거부)",
)


class ActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alert: dict = Field(default_factory=dict)
    analysis: dict = Field(default_factory=dict)
    operation: str | None = None
    force_manual: StrictBool = False
    plan: dict | None = None
    plan_steps: list | None = None
    replan_of: str | None = None
    reason: str | None = None
    identity: dict | None = None  # Informational legacy /notify envelope only.
    identity_status: str | None = None


class AdvanceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation: str
    previous_remediation_id: str


class RecoveryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation: str
    remediation_id: str
    reason: str


class ServiceVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation: str
    remediation_id: str


def _planned_executor(selected, action):
    return is_extended_executor(selected) or (isinstance(selected, RemoteExecutor)
                                             and action in {"ROLLBACK", "RECREATE"})




class RemoteReconcileRequest(BaseModel):
    operation: str
    remediation_id: str
    retry: bool = False


# ─── 인증 게이트 ─────────────────────────────────────────

async def _push_auth_denied(endpoint: str, reason: str, signature: str | None) -> None:
    """인증 거부를 감사 로그에 남긴다. 서명 원문은 남기지 않는다(앞 12자만)."""
    logger.warning(f"[Auth] 거부: endpoint={endpoint} reason={reason}")
    await _push_soc_event("aiops-remediation", {
        "event":       "auth_denied",
        "endpoint":    endpoint,
        "reason":      reason,
        "signature_prefix": (signature or "")[:12],
        "status":      "DENIED",
    })


async def _push_policy_decision(alert: dict, decision, source: str) -> None:
    """
    정책 판단과 근거를 감사 로그에 남긴다. 조치 실행 기록(auto_remediation /
    manual_approval_executed)과는 별개 이벤트다 — 판단과 실행을 구분해 기록한다.
    """
    body = {
        "event":  "policy_decision",
        "alert":  alert.get("labels", {}).get("alertname", "unknown"),
        "source": source,
        "status": decision.outcome,
        **decision.as_dict(),
    }
    logger.info(
        "[Policy] %s: action=%s risk=%s threat=%s(%s) outcome=%s approval=%s exec_now=%s",
        source, decision.action_type, decision.action_risk, decision.threat_level,
        decision.urgency, decision.outcome, decision.requires_approval,
        decision.executable_now,
    )
    await _push_soc_event("aiops-remediation", body)


async def require_service_auth(request: Request) -> None:
    """
    /action 서명 검증. 거부 시 401 을 올려 핸들러에 들어가지 않게 한다 —
    조치 실행 코드는 핸들러 안에만 있으므로 여기서 막히면 Docker 호출이 없다.
    """
    body = await request.body()
    signature = request.headers.get(SERVICE_SIGNATURE_HEADER)
    ok, reason = verify_service_request(body, request.headers, REMEDIATION_API_KEY)
    if ok and not _replay_guard.remember(signature or ""):
        ok, reason = False, "replayed_signature"
    if not ok:
        await _push_auth_denied("/action", reason, signature)
        raise HTTPException(status_code=401, detail="unauthorized")


# ─── 기존 엔드포인트 ─────────────────────────────────────

@app.get("/health")
async def health():
    slack = (await slack_socket.health() if slack_socket is not None else
             {"transport": slack_settings.transport, "connected": False,
              "status": "not_started" if slack_settings.transport == "socket_mode" else slack_settings.transport})
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat(), "slack": slack}


@app.post("/service/verify", dependencies=[Depends(require_service_auth)])
async def verify_service(request: ServiceVerifyRequest):
    if request.operation != "verify_service":
        raise HTTPException(400, "verification_operation_required")
    record = record_store.get(request.remediation_id)
    if record is None:
        raise HTTPException(404, "stored_remediation_required")
    record = await asyncio.to_thread(service_verification_mod.verify_record, record_store, record)
    if not record_store.writable:
        raise HTTPException(503, "record_store_unavailable")
    await _push_record(record, "service_verification_checked")
    return {"remediation_id": record.remediation_id, "record_state": record.state,
            "service_verification": record.service_verification, "timings": record.timings()}


@app.post("/remote/reconcile", dependencies=[Depends(require_service_auth)])
async def reconcile_remote(request: RemoteReconcileRequest):
    # This endpoint can only revisit an already approved durable record.
    # The operation marker is signed in the body (Phase 0 HMAC does not bind paths).
    if request.operation != "reconcile_remote":
        raise HTTPException(400, "remote_reconciliation_unavailable")
    record = record_store.get(request.remediation_id)
    if record is None or record.executor_name != "remote":
        raise HTTPException(404, "unknown_remote_record")
    selected = select_executor(record.action_type, executor)
    if not isinstance(selected, RemoteExecutor):
        raise HTTPException(400, "remote_reconciliation_unavailable")
    from executor.remote_sync import reconcile
    record = await asyncio.to_thread(reconcile, record_store, selected, record)
    if record is None or not record_store.writable:
        raise HTTPException(503, "record_store_unavailable")
    if request.retry:
        # A missing response does not prove the Agent did not mutate Docker.
        # Reconciliation is read-only; uncertain commands are never resent here.
        raise HTTPException(409, "uncertain_execution_requires_manual_review")
    return record.as_dict()


def _expires_at(requested_at=None):
    base = (datetime.fromisoformat(requested_at) if requested_at
            else datetime.now(timezone.utc))
    return (base + timedelta(seconds=slack_settings.approval_ttl)).isoformat()


@app.post("/notify", dependencies=[Depends(require_service_auth)])
async def notify_only(request: ActionRequest):
    """Authenticated RCA notification. No policy branch, record, or execution."""
    if request.operation != "notify_only":
        raise HTTPException(400, "notify_only_operation_required")
    dispatch = await notifier.send_alert_only(request.alert, request.analysis)
    await _push_slack_status(request.alert, request.analysis, dispatch, "alert_only")
    return {"status": "notification_only", "dispatch": dispatch}


def _approval_plan_summary(record):
    summaries = []
    for target, binding in record.target_bindings.items():
        line = {"target": target, "executor": record.executor_name}
        if record.executor_name == "postgres":
            line["criteria"] = binding.get("parameters", record.action_parameters)
            sessions = binding.get("sessions", [])
            line["selected_pids"] = [row.get("pid") for row in sessions]
            line["session_count"] = len(sessions)
        elif record.action_type in {"ROLLBACK", "RECREATE"}:
            line["action"] = binding.get("action_type")
            line["image_id"] = binding.get("chosen_spec", {}).get("image_id")
            line["previous_container"] = binding.get("pre_snapshot", {}).get("container_id")
            if record.action_type == "ROLLBACK":
                line["version"] = binding.get("operator_config", {}).get("rollback", {}).get("version")
                backup = binding.get("backup_evidence") or {}
                line["backup"] = {k: backup.get(k) for k in ("database_id", "verified_at")}
        else:
            line["resource"] = binding.get("resource_id", record.action_parameters.get("account_id", record.action_parameters.get("feature_id")))
        summaries.append(line)
    return summaries


def _extension_parameters(action, parameters):
    """Reject unknown/nested command or credential fields before durable storage."""
    allowed = {
        "KILL_SESSIONS": {"operation", "min_age_seconds", "max_sessions"},
        "RECREATE": set(), "ROLLBACK": {"version"},
        "LOCK_ACCOUNT": {"account_id", "duration_seconds", "reason"},
        "REVOKE_SESSION": {"account_id", "reason"},
        "DISABLE_FEATURE": {"feature_id", "reason"},
        "UNLOCK_ACCOUNT": {"account_id", "reason"},
        "ENABLE_FEATURE": {"feature_id", "reason"},
    }
    if action not in allowed:
        # Legacy explicit Docker requests historically carry an audit reason;
        # it is hashed and never forwarded as a command. Strict RCA plans use {}.
        if set(parameters) - {"reason"} or any(not isinstance(v, str) or len(v) > 256 for v in parameters.values()):
            raise ValueError("unsupported_action_parameters")
        return
    if set(parameters) - allowed[action]:
        raise ValueError("unsupported_extension_parameter")
    for key, value in parameters.items():
        if key in {"min_age_seconds", "max_sessions", "duration_seconds"}:
            bound = 20 if key == "max_sessions" else 86400
            if type(value) is not int or not 1 <= value <= bound:
                raise ValueError("invalid_extension_parameter")
        elif key in {"account_id", "feature_id", "version"}:
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
                raise ValueError("invalid_extension_resource_id")
        elif key == "reason":
            if not isinstance(value, str) or not 1 <= len(value) <= 256 or any(c in value for c in ("\r", "\n")):
                raise ValueError("invalid_extension_reason")
        elif key == "operation" and value not in {"terminate_idle_sessions", "cancel_long_queries"}:
            raise ValueError("invalid_postgres_operation")


def _existing_response(record, decision):
    return {"status": "existing", "remediation_id": record.remediation_id,
            "record_state": record.state, "record": record.as_dict(),
            "policy": decision.as_dict()}


@app.post("/plans/advance", dependencies=[Depends(require_service_auth)])
async def advance_plan(request: AdvanceRequest):
    if request.operation != "advance_plan":
        raise HTTPException(400, "advance_operation_required")
    previous = record_store.get(request.previous_remediation_id)
    if previous is None:
        raise HTTPException(404, "stored_remediation_required")
    if not record_store.execution_confirmed(previous) or previous.superseded_by or previous.recovery_request_id:
        raise HTTPException(409, "previous_execution_not_verified_or_plan_changed")
    index = previous.plan_step + 1
    try:
        steps = plans_mod.validate_steps(previous.plan_steps, previous.alert_context)
        if index >= len(steps):
            raise ValueError("no_next_stage")
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    step = steps[index]
    return await _propose_action(ActionRequest(operation="propose_manual_action", force_manual=True,
        alert=previous.alert_context, analysis=step["analysis"], plan=step["plan"]),
        previous=previous, link_kind="advance", steps=steps, step_index=index)


@app.post("/recovery/request", dependencies=[Depends(require_service_auth)])
async def request_app_recovery(request: RecoveryRequest):
    if request.operation != "request_recovery":
        raise HTTPException(400, "recovery_request_operation_required")
    if (not request.reason.strip() or len(request.reason) > 256
            or any(ord(c) < 32 for c in request.reason)):
        raise HTTPException(422, "explicit_recovery_reason_required")
    previous = record_store.get(request.remediation_id)
    if previous is None:
        raise HTTPException(404, "stored_remediation_required")
    restore = {"LOCK_ACCOUNT": "UNLOCK_ACCOUNT", "DISABLE_FEATURE": "ENABLE_FEATURE"}.get(previous.action_type)
    if not restore or not record_store.execution_confirmed(previous) or previous.superseded_by or previous.next_step_id:
        raise HTTPException(409, "verified_app_parent_required")
    if not previous.alert_context:
        raise HTTPException(409, "parent_incident_context_required")
    resource_key = "account_id" if restore == "UNLOCK_ACCOUNT" else "feature_id"
    parameters = {resource_key: previous.action_parameters.get(resource_key), "reason": request.reason}
    analysis = {"action_type": restore, "action_targets": list(previous.targets),
                "action_parameters": parameters, "confidence": 1.0, "threat_level": previous.threat_level,
                "root_cause": "Operator requested restoration of a verified application action",
                "action_description": request.reason, "evidence": ["verified_parent:" + previous.remediation_id]}
    return await _propose_action(ActionRequest(operation="internal_recovery", force_manual=True,
        alert=previous.alert_context, analysis=analysis), previous=previous,
        link_kind="recovery", internal_recovery=True)


@app.post("/action", dependencies=[Depends(require_service_auth)])
async def execute_action(request: ActionRequest):
    return await _propose_action(request)


async def _propose_action(request, previous=None, link_kind=None, steps=None,
                          step_index=0, internal_recovery=False):
    """Propose an incident-bound action; the policy remains execution authority."""
    if request.operation not in (None, "propose_action", "propose_manual_action", "propose_plan", "replan_action", "internal_recovery"):
        raise HTTPException(400, "action_operation_mismatch")
    analysis, alert = request.analysis, request.alert
    manual_intent = request.operation in {"propose_manual_action", "propose_plan", "replan_action"}
    if request.operation == "internal_recovery" and not internal_recovery:
        raise HTTPException(400, "internal_operation_forbidden")
    if analysis.get("action_type") in {"UNLOCK_ACCOUNT", "ENABLE_FEATURE"} and not internal_recovery:
        raise HTTPException(409, "restoration_requires_verified_parent_request")
    try:
        if manual_intent:
            if not request.force_manual:
                raise ValueError("manual_intent_required")
            if request.operation == "propose_plan":
                steps = plans_mod.validate_steps(request.plan_steps, alert)
                analysis = steps[0]["analysis"]
            else:
                analysis = plans_mod.normalized_analysis(analysis)
                plans_mod.validate_wire(request.plan, alert, analysis)
            if request.operation == "replan_action":
                if (not request.replan_of or not isinstance(request.reason, str)
                        or not 1 <= len(request.reason.strip()) <= 256
                        or any(ord(c) < 32 for c in request.reason)):
                    raise ValueError("explicit_replan_parent_and_reason_required")
                previous = record_store.get(request.replan_of)
                if previous is None:
                    raise HTTPException(404, "stored_remediation_required")
                link_kind = "replan"
            if steps is None:
                steps = [{"analysis": analysis, "plan": request.plan}]
            for step in steps:
                step_analysis = step["analysis"]
                _extension_parameters(step_analysis["action_type"], step_analysis.get("action_parameters", {}))
                step_decision = policy_engine.decide_from_analysis(step_analysis)
                allowed, reason = policy_engine.execution_allowed(step_decision.action_type, step_decision.targets)
                if not allowed or step_decision.outcome == BLOCKED:
                    raise ValueError("plan_step_blocked_by_policy:" + (step_decision.blocked_reason or reason))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    await _push_soc_event("aiops-timeline", {
        "event": "remediation_decision_started",
        "alert": alert.get("labels", {}).get("alertname", "unknown"),
        "action_type": analysis.get("action_type", "NONE"),
        "targets": analysis.get("action_targets", []),
    })
    decision = policy_engine.decide_from_analysis(analysis)
    if manual_intent or internal_recovery or request.force_manual:
        if decision.outcome == AUTO_EXECUTE_CANDIDATE:
            decision = replace(decision, outcome=AWAITING_APPROVAL, requires_approval=True,
                               executable_now=False, notify="approval_request",
                               reasons=decision.reasons + ("explicit_manual_plan",))
    await _push_policy_decision(alert, decision, source="action")
    if decision.outcome in (BLOCKED, NO_ACTION, NOTIFY):
        dispatch = await notifier.send_alert_only(alert, analysis)
        await _push_slack_status(alert, analysis, dispatch, "alert_only")
        return {"status": "blocked" if decision.outcome == BLOCKED else "notified",
                "reason": decision.blocked_reason, "policy": decision.as_dict()}

    try:
        key, identity = store_mod.incident_key(alert)
        parameters = analysis.get("action_parameters", analysis.get("parameters", {}))
        if not isinstance(parameters, dict):
            raise ValueError("invalid_action_parameters")
        _extension_parameters(decision.action_type, parameters)
        digest = store_mod.action_hash(decision.action_type, list(decision.targets),
                                       decision.ttl_seconds, decision.recovery_mode,
                                       parameters)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None

    selected = select_executor(decision.action_type, executor)
    remote_manual = isinstance(selected, RemoteExecutor)
    manual = decision.requires_approval or remote_manual or is_extended_executor(selected) or manual_intent or internal_recovery or request.force_manual
    record = store_mod.RemediationRecord(
        remediation_id=record_store.new_id(), incident_key=key, action_hash=digest,
        identity=identity, action_parameters=parameters,
        alertname=alert.get("labels", {}).get("alertname", "unknown"),
        action_type=decision.action_type, targets=list(decision.targets),
        action_risk=decision.action_risk, threat_level=decision.threat_level,
        requires_approval=manual, ttl_seconds=decision.ttl_seconds,
        recovery_mode=decision.recovery_mode, source="alert_triggered",
        alert_active_at=alert["startsAt"], executor_name=selected.name,
        alert_context=alert, plan_steps=steps or [],
        plan_hash=plans_mod.digest(steps) if steps else None, plan_step=step_index,
        plan_id=(previous.plan_id or previous.remediation_id) if previous else None,
        replan_reason=request.reason if link_kind == "replan" else None,
    )
    try:
        if previous is not None:
            record, created = record_store.create_linked(record, previous.remediation_id, link_kind)
        else:
            record, created = record_store.get_or_create_incident(record)
    except store_mod.IncidentConflict as exc:
        raise HTTPException(409, str(exc)) from None
    if record is None or not record_store.writable:
        raise HTTPException(503, "record_store_unavailable")
    if not created:
        return _existing_response(record, decision)

    allowed, reason = route_action(decision.action_type, identity.get("runtime"), selected)
    if allowed and getattr(selected, "changes_system", True):
        try:
            if _planned_executor(selected, record.action_type):
                bindings = await asyncio.to_thread(selected.plan_record, identity, record.targets,
                                                   record.action_type, record.action_parameters)
            else:
                bindings = await asyncio.to_thread(bind_targets, identity, record.targets, selected)
            if record_store.update(record.remediation_id, target_bindings=bindings) is None:
                raise HTTPException(503, "record_store_unavailable")
        except IdentityError as exc:
            allowed, reason = False, str(exc)
        except (ValueError, RuntimeError) as exc:
            allowed, reason = False, "executor_preflight_rejected:" + type(exc).__name__
    if not allowed:
        if record_store.update(record.remediation_id, state=store_mod.BLOCKED,
                               results=[{"blocked_reason": reason}]) is None:
            raise HTTPException(503, "record_store_unavailable")
        dispatch = await notifier.send_alert_only(alert, analysis)
        await _push_slack_status(alert, analysis, dispatch, "alert_only")
        return {"status": "blocked", "reason": reason, "remediation_id": record.remediation_id,
                "record_state": store_mod.BLOCKED, "policy": decision.as_dict()}

    service_plan = service_verification_mod.plan_record(record)
    if record_store.update(record.remediation_id, service_verification=service_plan) is None:
        raise HTTPException(503, "record_store_unavailable")
    if manual:
        requested = store_mod.utcnow()
        if record_store.update_if_state(record.remediation_id, store_mod.PROPOSED,
                state=store_mod.AWAITING_APPROVAL, approval_requested_at=requested,
                approval_expires_at=_expires_at(requested), service_verification=service_plan) is None:
            raise HTTPException(503, "record_store_unavailable")
        approval_analysis = dict(analysis)
        if _planned_executor(selected, record.action_type):
            approval_analysis["approval_parameters"] = record.action_parameters
            approval_analysis["approval_plan"] = _approval_plan_summary(record)
        approval_analysis["approval_stage"] = {"step": record.plan_step + 1,
            "total": len(record.plan_steps) or 1, "revision": record.revision,
            "recovery_of": record.recovery_of, "supersedes_id": record.supersedes_id,
            "service_verification": service_plan.get("state")}
        if record.recovery_of:
            approval_analysis["app_recovery"] = True
        dispatch = await notifier.send_approval_request(alert, approval_analysis,
                                                       remediation_id=record.remediation_id)
        await _push_slack_status(alert, analysis, dispatch, "approval_request")
        await _push_record(record_store.get(record.remediation_id), "approval_requested")
        return {"status": "pending_approval", "remediation_id": record.remediation_id,
                "reasons": list(decision.reasons) + (["remote_manual_approval_required"] if remote_manual else []),
                "policy": decision.as_dict(), "dispatch": dispatch,
                "plan_id": record.plan_id or record.remediation_id, "step": record.plan_step}
    if decision.outcome != AUTO_EXECUTE_CANDIDATE or not decision.executable_now:
        record_store.update(record.remediation_id, state=store_mod.BLOCKED)
        return {"status": "auto_execution_deferred", "remediation_id": record.remediation_id,
                "policy": decision.as_dict()}
    results, state = await _perform(record, record.targets, record.action_type)
    for res in results:
        await _push_remediation_status(alert, analysis, res.target, record.action_type, res.summary())
    if decision.notify == "post_action":
        dispatch = await notifier.send_alert_only(alert, analysis)
        await _push_slack_status(alert, analysis, dispatch, "alert_only")
    return {"status": {store_mod.VERIFIED: "executed", store_mod.SKIPPED: "skipped",
                       store_mod.UNKNOWN: "unknown", store_mod.BLOCKED: "blocked"}.get(state, "failed"),
            "remediation_id": record.remediation_id, "record_state": state,
            "results": [r.as_dict() for r in results], "policy": decision.as_dict()}


# ─── Slack Interactive Components 콜백 ───────────────────

@app.post("/slack/action")
async def slack_interactive_action(request: Request):
    """
    Slack 버튼 클릭 시 호출되는 엔드포인트.

    source 필드로 출처 구분:
      alert_triggered  → 기존 alert 기반 승인 (기본값)
      periodic_log_scan → 주기적 로그 스캔에서 온 승인
      llm_health_check  → LLM 헬스체크에서 온 승인
    """
    # Socket Mode payloads are accepted only from our outbound SDK connection.
    # Keeping this URL accessible must never bypass the Socket Mode trust boundary.
    if slack_settings.transport != "http":
        return JSONResponse(status_code=410, content={"error": "http_interactivity_disabled"})
    # 0. Slack 서명 검증 — 파싱·실행보다 먼저. 거부되면 조치 코드에 닿지 않는다.
    body = await request.body()
    slack_signature = request.headers.get(SLACK_SIGNATURE_HEADER)
    ok, reason = verify_slack_request(body, request.headers, SLACK_SIGNING_SECRET)
    if ok and not _replay_guard.remember(slack_signature or ""):
        ok, reason = False, "replayed_signature"
    if not ok:
        await _push_auth_denied("/slack/action", reason, slack_signature)
        return JSONResponse(status_code=401, content={"error": "unauthorized"})

    # 1. Slack payload 파싱
    params = urllib.parse.parse_qs(body.decode("utf-8"))
    raw_payload = params.get("payload", [None])[0]

    if not raw_payload:
        return JSONResponse(status_code=400, content={"error": "No payload"})

    try:
        slack_payload = json.loads(raw_payload)
    except json.JSONDecodeError:
        return JSONResponse(status_code=400, content={"error": "Invalid payload JSON"})

    return await handle_slack_action(slack_payload)


async def handle_socket_action(payload):
    response = await handle_slack_action(payload, socket_mode=True)
    logger.info("[Slack Socket] action result HTTP-equivalent=%s", response.status_code)
    return response


async def handle_slack_action(slack_payload, socket_mode=False):
    """Same workspace/channel, stored plan, expiry, and CAS rules on both transports."""
    if not isinstance(slack_payload, dict):
        return JSONResponse(status_code=400, content={"error": "invalid_payload"})
    team, channel, user = (slack_payload.get(k) for k in ("team", "channel", "user"))
    if (slack_payload.get("type") != "block_actions" or
            not slack_settings.team_id or not slack_settings.channel_id or
            not isinstance(team, dict) or team.get("id") != slack_settings.team_id or
            not isinstance(channel, dict) or channel.get("id") != slack_settings.channel_id or
            not isinstance(user, dict) or not isinstance(user.get("id"), str) or not user["id"]):
        return JSONResponse(status_code=403, content={"error": "slack_channel_not_allowed"})
    actions = slack_payload.get("actions")
    if not isinstance(actions, list) or len(actions) != 1 or not isinstance(actions[0], dict):
        return JSONResponse(status_code=400, content={"error": "invalid_actions"})
    action = actions[0]
    action_id = action.get("action_id")
    if action_id not in ("approve_action", "reject_action", "approve_recovery"):
        return JSONResponse(status_code=400, content={"error": "unknown_action"})
    try:
        data = json.loads(action.get("value"))
        if (not isinstance(data, dict) or not isinstance(data.get("action_type"), str) or
                not isinstance(data.get("action_targets"), list) or
                any(not isinstance(t, str) for t in data["action_targets"])):
            raise ValueError()
    except (ValueError, TypeError):
        return JSONResponse(status_code=400, content={"error": "invalid_action_value"})
    rid = data.get("remediation_id")
    record = record_store.get(rid) if isinstance(rid, str) and rid else None
    if record is None:
        # Legacy buttons cannot manufacture an executable incident. An operator
        # must submit a fresh complete incident to issue a new approval request.
        return JSONResponse(status_code=404, content={"error": "stored_remediation_required",
                                                     "new_approval_required": True})
    if (record.alertname != data.get("alertname") or record.action_type != data["action_type"].upper()
            or sorted(record.targets) != sorted(data["action_targets"])):
        return JSONResponse(status_code=409, content={"error": "stored_action_mismatch"})
    app_recovery = bool(record.recovery_of and record.action_type in {"UNLOCK_ACCOUNT", "ENABLE_FEATURE"})
    if app_recovery and action_id == "approve_action":
        return JSONResponse(status_code=409, content={"error": "app_recovery_approval_button_required"})
    recovering = action_id == "approve_recovery" and not app_recovery
    if not store_mod.approval_valid(record, recovery=recovering):
        if not recovering:
            record_store.expire_approval(rid)
        return JSONResponse(status_code=409, content={"error": "approval_expired"})
    response_url = slack_payload.get("response_url", "")
    try:
        if not isinstance(response_url, str):
            raise ValueError()
        parsed = urllib.parse.urlsplit(response_url)
        if response_url and (parsed.scheme != "https" or parsed.hostname not in (
                "hooks.slack.com", "hooks.slack-gov.com") or parsed.username or parsed.password or
                parsed.port not in (None, 443) or not parsed.path.startswith("/actions/")):
            raise ValueError()
    except ValueError:
        return JSONResponse(status_code=400, content={"error": "invalid_response_url"})
    if not record_store.writable:
        return JSONResponse(status_code=503, content={"error": "record_store_unavailable"})
    user_id = user["id"]
    if action_id == "reject_action":
        if not record_store.mark_rejected(rid, user_id):
            return JSONResponse(status_code=409 if record_store.writable else 503,
                                content={"error": "approval_no_longer_pending"})
        await _push_record(record_store.get(rid), "manual_approval_rejected")
        await _update_slack_message(response_url, f":no_entry: *거부됨* (by `{user_id}`) | `{record.action_type}`")
        return JSONResponse(status_code=200, content={"status": "rejected"})
    if recovering:
        if record.state not in (store_mod.RECOVERY_PENDING, store_mod.RECOVERY_APPROVAL_REQUIRED):
            return JSONResponse(status_code=409, content={"error": "recovery_not_eligible"})
        saved = record_store.update(rid, recovery_approved_by=user_id)
        if saved is None:
            return JSONResponse(status_code=503, content={"error": "record_store_unavailable"})
        selected = select_executor(saved.action_type, executor)
        results, state = await asyncio.to_thread(recovery_mod.recover, record_store, selected,
                                                saved, user_id, True)
        await _push_record(record_store.get(rid), "recovery_completed", state)
        return JSONResponse(status_code=200, content={"status": "recovery_" + state.lower(),
                                                     "results": [r.summary() for r in results]})
    allowed, reason = policy_engine.execution_allowed(record.action_type, record.targets)
    if not allowed:
        return JSONResponse(status_code=409, content={"error": reason})
    approved = record_store.mark_approved(rid, user_id)
    if approved is None:
        return JSONResponse(status_code=409 if record_store.writable else 503,
                            content={"error": "approval_no_longer_pending"})
    results, state = await _perform(approved, approved.targets, approved.action_type)
    summaries = [r.summary() for r in results] or [f"Not executed: {record.action_type} ({state})"]
    for res in results:
        await _push_soc_event("aiops-timeline", {
            "event": "manual_approval_executed", "alert": record.alertname,
            "target": res.target, "action_type": record.action_type,
            "approved_by": user_id, "source": record.source,
            "status": _result_status(res.summary()), "result": res.summary(),
            "remediation_id": rid, "verified": res.verified,
        })
    await _update_slack_message(response_url, f"*승인 처리* (by `{user_id}`) | `{record.action_type}` | `{state}`")
    return JSONResponse(status_code=200, content={"status": "approved", "record_state": state,
                                                 "results": summaries})


async def _update_slack_message(response_url: str, text: str) -> None:
    if not response_url:
        logger.warning("[Slack Action] response_url 없음 — 메시지 업데이트 스킵")
        return
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(
                response_url,
                json={"replace_original": True, "text": text},
                headers={"Content-Type": "application/json"},
            )
        logger.info("[Slack Action] 메시지 업데이트 완료")
    except Exception as e:
        logger.warning("[Slack Action] 메시지 업데이트 실패 (%s)", type(e).__name__)


# ─── 헬퍼 함수 ───────────────────────────────────────────

async def _run_executor(action: str, target: str, target_evidence: dict, selected_executor=None):
    """
    실행기를 블로킹하지 않게 호출한다 (Docker SDK 는 동기 호출이다).
    반환은 ExecutionResult — 조치 뒤 상태를 재조회해 확인한 결과다.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, (selected_executor or executor).execute, action, target, target_evidence)


def _result_status(result: str) -> str:
    if result.startswith("UNKNOWN"):
        return "UNKNOWN"
    if result.startswith("Blocked:"):
        return "BLOCKED"
    if result.startswith("Success"):
        return "SUCCESS"
    return "SKIPPED" if result.startswith("Skipped:") else "FAILED"


# ─── Phase 2: 증거 → 실행 → 검증 → 기록 → 복구 일정 ─────────────────────────

async def _on_ttl_event(record, results, state) -> None:
    """TTL 스캐너가 처리한 결과를 감사 로그에 남긴다."""
    updated = record_store.get(record.remediation_id) or record
    await _push_record(updated, "service_recovered" if state == "SERVICE_RECOVERED" else "ttl_recovery_processed", state)
    if state == store_mod.RECOVERY_APPROVAL_REQUIRED:
        requested = store_mod.utcnow()
        record_store.update(updated.remediation_id,
                            recovery_approval_requested_at=requested,
                            recovery_approval_expires_at=_expires_at(requested))
        if record_store.writable:
            await notifier.send_recovery_request(record_store.get(updated.remediation_id))
        # 자동 복구 금지 조치 — 사람에게 복구 승인을 요청한다.
        await _push_soc_event("aiops-timeline", {
            "event": "recovery_approval_required", "status": state,
            "alert": updated.alertname, "action_type": updated.action_type,
            "remediation_id": updated.remediation_id,
            "targets": list(updated.targets),
        })


async def _push_record(record, event: str, status: str | None = None) -> None:
    """조치 레코드 상태와 시간 지표를 감사 로그에 남긴다 (기존 job 라벨 유지)."""
    body = {"event": event, "status": status or record.state,
            **recovery_mod.timings_event(record)}
    await _push_soc_event("aiops-remediation", body)


async def _perform(record, decision_targets, action_type: str,
                   approved_by: str | None = None) -> tuple[list, str]:
    """
    한 조치를 끝까지 수행한다: 멱등성 선점 → 증거 보존 → 실행 → 검증 → 복구 일정.

    반환: (ExecutionResult 목록, 최종 레코드 상태).
    같은 remediation_id 로 두 번 들어오면 두 번째는 실행하지 않고 이전 결과를 돌려준다.
    """
    selected = select_executor(action_type, executor)
    if (record.executor_name and record.executor_name != selected.name
            and getattr(selected, "changes_system", True)):
        return [], store_mod.BLOCKED
    rid = record.remediation_id
    approved_by = record.approved_by or approved_by
    if record.action_type != action_type or sorted(record.targets) != sorted(decision_targets):
        return [], store_mod.BLOCKED
    if isinstance(selected, RemoteExecutor):
        allowed, _ = policy_engine.execution_allowed(action_type, decision_targets)
        if not allowed or not approved_by:
            record_store.update(rid, state=store_mod.BLOCKED,
                                results=[{"blocked_reason": "remote_requires_policy_and_manual_approval"}])
            return [], store_mod.BLOCKED

    # ① 멱등성 — 실행 권리를 선점한다. 이미 처리된 조치면 재실행하지 않는다.
    claimed, why = record_store.claim_execution(rid)
    if not claimed:
        existing = record_store.get(rid) or record
        logger.info("[Remediation] 중복 실행 방지: %s (%s)", rid, why)
        await _push_soc_event("aiops-remediation", {
            "event": "duplicate_execution_suppressed", "status": existing.state,
            "remediation_id": rid, "alert": existing.alertname,
            "action_type": existing.action_type, "reason": why,
        })
        return [], existing.state

    allowed, reason = route_action(action_type, record.identity.get("runtime"), selected)
    if allowed and getattr(selected, "changes_system", True):
        if _planned_executor(selected, action_type):
            reason = await asyncio.to_thread(selected.validate_record, record)
        else:
            reason = await asyncio.to_thread(validate_bindings, record, selected)
        allowed = reason is None
    if not allowed:
        record_store.update(rid, state=store_mod.BLOCKED,
                            results=[{"blocked_reason": reason}])
        return [], store_mod.BLOCKED

    record_store.update(rid, approved_by=approved_by, executor_name=selected.name)
    if not record_store.writable:
        return [], store_mod.BLOCKED

    # ② 증거 보존 — 되돌릴 수 없는 격리·동결을 막는 게이트
    if _planned_executor(selected, action_type):
        # plan_record contains only sanitized immutable preapproval evidence.
        target_evidence = {"executor": selected.name, "targets": record.target_bindings,
                           "collected_at": store_mod.utcnow()}
        block_reason = None
    else:
        target_evidence, block_reason = await asyncio.get_event_loop().run_in_executor(
            None, evidence_mod.gate, selected, record_store, rid, action_type,
            list(decision_targets))
    if block_reason:
        record_store.update(rid, state=store_mod.BLOCKED, evidence=target_evidence,
                            results=[{"blocked_reason": block_reason}])
        logger.warning("[Remediation] 증거 보존 실패로 차단: %s — %s", action_type, block_reason)
        await _push_soc_event("aiops-remediation", {
            "event": "evidence_gate_blocked", "status": "BLOCKED",
            "remediation_id": rid, "alert": record.alertname,
            "action_type": action_type, "reason": block_reason,
            "targets": list(decision_targets),
        })
        return [], store_mod.BLOCKED
    record_store.update(rid, evidence=target_evidence)
    if not record_store.writable:
        return [], store_mod.BLOCKED

    # ③ 실행 + ④ 검증 (실행기가 상태를 재조회해 확인한다)
    results = []
    for target in decision_targets:
        current = record_store.get(rid)
        if (not record_store.writable or current is None or current.state != store_mod.EXECUTING):
            return results, store_mod.BLOCKED
        if current.requires_approval and not store_mod.approval_valid(current):
            record_store.update(rid, state=store_mod.EXPIRED)
            return results, store_mod.EXPIRED
        try:
            if isinstance(selected, RemoteExecutor) or is_extended_executor(selected):
                result = await asyncio.to_thread(selected.execute_record, current, target, approved_by)
            else:
                ev = dict(evidence_mod.for_target(target_evidence, target))
                ev["target_binding"] = current.target_bindings.get(target)
                if current.requires_approval:
                    ev["approval_expires_at"] = current.approval_expires_at
                result = await _run_executor(action_type, target, ev, selected)
        except Exception as exc:
            # An exception after dispatch does not prove that Docker did not run.
            result = ExecutionResult(action_type, target, store_mod.UNKNOWN,
                                     detail="execution_result_unconfirmed:" + type(exc).__name__)
        results.append(result)
        if record_store.update(rid, results=[r.as_dict() for r in results]) is None:
            return results, store_mod.UNKNOWN

    all_ok = bool(results) and all(r.ok for r in results)
    any_skipped = any(r.status == store_mod.SKIPPED for r in results)

    if all_ok:
        state = store_mod.VERIFIED
        saved = record_store.update(rid, state=state, action_verified_at=store_mod.utcnow(),
                                    results=[r.as_dict() for r in results])
    elif any(r.status == "UNKNOWN" for r in results):
        state = store_mod.UNKNOWN
        saved = record_store.update(rid, state=state, results=[r.as_dict() for r in results])
    elif any_skipped:
        # disabled 모드 — 실행하지 않았다. 성공으로 표시하지 않는다.
        state = store_mod.SKIPPED
        saved = record_store.update(rid, state=state, results=[r.as_dict() for r in results])
    else:
        state = store_mod.FAILED
        saved = record_store.update(rid, state=state, results=[r.as_dict() for r in results])
    if saved is None or not record_store.writable:
        return results, store_mod.UNKNOWN

    # ⑤ 복구 일정 — 검증된 조치에만 TTL 을 건다 (실행 안 된 것은 되돌릴 것도 없다)
    current = record_store.get(rid) or record
    if state == store_mod.VERIFIED and RECOVERY_ACTION.get(action_type):
        scheduled = recovery_mod.schedule(record_store, current, record.ttl_seconds,
                                          record.recovery_mode)
        if scheduled is None or not record_store.writable:
            return results, store_mod.UNKNOWN
        current = record_store.get(rid) or current

    if isinstance(selected, RemoteExecutor):
        from executor.remote_sync import reconcile
        current = await asyncio.to_thread(reconcile, record_store, selected, current)
        if current is None or not record_store.writable:
            return results, store_mod.UNKNOWN

    await _push_record(current, "remediation_executed", current.state)
    # 반환하는 state 는 '이번 실행의 결과' 다. 레코드 상태는 복구 일정이 걸리면
    # RECOVERY_PENDING 으로 바뀌므로 둘을 섞지 않는다.
    return results, state


async def _push_soc_event(job: str, event: dict) -> None:
    ts_ns = str(int(time.time() * 1_000_000_000))
    body  = {"timestamp": datetime.utcnow().isoformat() + "Z", **event}
    labels = {
        "job":    job,
        "event":  str(event.get("event", "unknown")),
        "status": str(event.get("status", "unknown")),
    }
    if event.get("alert"):
        labels["alert"] = str(event["alert"])
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(
                f"{LOKI_URL}/loki/api/v1/push",
                json={"streams": [{"stream": labels, "values": [[ts_ns, json.dumps(body, ensure_ascii=False)]]}]},
                headers={"Content-Type": "application/json"},
            )
    except Exception as e:
        logger.warning(f"[SOC Loki] push failed: {e}")


async def _push_remediation_status(
    alert: dict, analysis: dict, target: str, action_type: str, result: str
) -> None:
    status     = _result_status(result)
    alert_name = alert.get("labels", {}).get("alertname", "unknown")
    await _push_soc_event("aiops-remediation", {
        "event":        "auto_remediation",
        "alert":        alert_name,
        "target":       target,
        "action_type":  action_type,
        "status":       status,
        "result":       result,
        "threat_level": analysis.get("threat_level", "unknown"),
        "confidence":   analysis.get("confidence", 0.0),
    })
    await _push_soc_event("aiops-timeline", {
        "event":       "auto_remediation_completed",
        "alert":       alert_name,
        "target":      target,
        "action_type": action_type,
        "status":      status,
        "message":     result,
    })


async def _push_slack_status(
    alert: dict, analysis: dict, dispatch: dict, notification_type: str
) -> None:
    status     = dispatch.get("status", "FAILED")
    sent       = status == "SUCCESS"
    alert_name = alert.get("labels", {}).get("alertname", "unknown")
    await _push_soc_event("aiops-slack", {
        "event":               "slack_notification",
        "alert":               alert_name,
        "status":              status,
        "slack_status":        status,
        "slack_response_code": dispatch.get("response_code"),
        "slack_response_text": dispatch.get("response_text", ""),
        "slack_dispatched_at": dispatch.get("dispatched_at"),
        "notification_type":   notification_type,
        "threat_level":        analysis.get("threat_level", "unknown"),
        "confidence":          analysis.get("confidence", 0.0),
        "channel":             slack_settings.channel_id or "unconfigured",
    })
    await _push_soc_event("aiops-timeline", {
        "event":               "slack_notification_sent" if sent else "slack_notification_skipped",
        "alert":               alert_name,
        "status":              status,
        "slack_response_code": dispatch.get("response_code"),
        "slack_response_text": dispatch.get("response_text", ""),
        "notification_type":   notification_type,
    })
