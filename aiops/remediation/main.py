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
from pydantic import BaseModel
from datetime import datetime
import asyncio
import json
import logging
import os
import time
import urllib.parse
import httpx
import evidence as evidence_mod
import recovery as recovery_mod
import store as store_mod
from actions.notify import Notifier
from executor.base import RECOVERY_ACTION, DisabledExecutor
from executor.local_docker import LocalDockerExecutor
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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
LOKI_URL = os.getenv("LOKI_URL", "http://loki:3100")

# ─── 인증 (Phase 0) ──────────────────────────────────────
# 두 엔드포인트 모두 서명을 요구한다. 키가 없으면 요청을 거부한다 (fail closed) —
# 설정 누락을 "인증 없이 실행"으로 처리하면 안전장치가 의미를 잃는다.
SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET", "")
REMEDIATION_API_KEY = os.getenv("REMEDIATION_API_KEY", "")

_replay_guard = ReplayGuard()

# docker   : 로컬 Docker SDK로 조치를 실행한다 (기존 all-in-one docker-compose.yml)
# disabled : 조치를 실행하지 않는다. AIOps 단독 배포에서는 Leafy가 다른 PC에 있어 로컬 Docker 조치가 대상에 닿지 않고,
#            같은 이름의 로컬 컨테이너(남은 leafy-* 또는 AIOps 자신)를 건드릴 위험만 있다. 원격 조치 경로가 생기기 전까지 쓴다.
#            판단·알림·승인 기록은 그대로 남기고, 실행 결과는 SKIPPED로 기록한다.
REMEDIATION_MODE = os.getenv("REMEDIATION_MODE", "disabled")
if REMEDIATION_MODE not in ("docker", "disabled"):
    raise ValueError(f"REMEDIATION_MODE must be docker or disabled: {REMEDIATION_MODE!r}")

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
    global ttl_scanner
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
        yield
    finally:
        if ttl_scanner is not None:
            ttl_scanner.stop()
        if task is not None:
            task.cancel()


app = FastAPI(title="AIOps Remediation", version="0.1.0", lifespan=lifespan)
logger.info(f"[Remediation] REMEDIATION_MODE={REMEDIATION_MODE}")
# 키 값은 찍지 않는다. 설정 여부만 남겨 fail closed 상태를 운영자가 바로 알 수 있게 한다.
logger.info(
    "[Remediation] auth: SLACK_SIGNING_SECRET=%s REMEDIATION_API_KEY=%s",
    "set" if SLACK_SIGNING_SECRET else "MISSING (/slack/action 전부 거부)",
    "set" if REMEDIATION_API_KEY else "MISSING (/action 전부 거부)",
)


class ActionRequest(BaseModel):
    alert: dict
    analysis: dict


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
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


@app.post("/action", dependencies=[Depends(require_service_auth)])
async def execute_action(request: ActionRequest):
    """
    분석 결과 수신 → 정책 엔진이 집행을 결정한다 (Phase 1).

    이전에는 LLM 이 보낸 action_risk 와 confidence 로 직접 분기해, LLM 이 위험도를
    낮게 쓰면 승인 없이 조치가 실행됐다. 지금은 위험도·승인·자동 실행 가능 여부를
    정책 엔진이 정하고 LLM 의 action_risk 는 기록만 한다.
    """
    analysis = request.analysis
    alert    = request.alert

    action_type    = str(analysis.get("action_type", "NONE")).upper()
    action_targets = analysis.get("action_targets", [])
    threat_level   = analysis.get("threat_level", "medium")
    confidence     = analysis.get("confidence", 0.0)

    logger.info(
        f"[Remediation] Start processing: "
        f"Type={action_type}, Targets={action_targets}, Confidence={confidence}"
    )
    await _push_soc_event("aiops-timeline", {
        "event":       "remediation_decision_started",
        "alert":       alert.get("labels", {}).get("alertname", "unknown"),
        "action_type": action_type,
        "targets":     action_targets,
        "threat_level": threat_level,
        "confidence":  confidence,
    })

    decision = policy_engine.decide_from_analysis(analysis)
    await _push_policy_decision(alert, decision, source="action")

    alertname = alert.get("labels", {}).get("alertname", "unknown")
    # MTTR 기준점: 경보 발생 시각 (Alertmanager startsAt). 없으면 수신 시각.
    alert_active_at = alert.get("startsAt") or store_mod.utcnow()
    record = None
    if decision.performs_action:
        record = store_mod.RemediationRecord(
            remediation_id=record_store.new_id(),
            alertname=alertname, action_type=decision.action_type,
            targets=list(decision.targets), action_risk=decision.action_risk,
            threat_level=decision.threat_level,
            requires_approval=decision.requires_approval,
            ttl_seconds=decision.ttl_seconds, recovery_mode=decision.recovery_mode,
            source="alert_triggered", alert_active_at=alert_active_at,
        )
        record_store.create(record)

    # ① 정책 차단 — 미지원·미정의 조치 (fail closed)
    if decision.outcome == BLOCKED:
        slack_dispatch = await notifier.send_alert_only(alert, analysis)
        await _push_slack_status(alert, analysis, slack_dispatch, "alert_only")
        return {"status": "blocked", "reason": decision.blocked_reason,
                "policy": decision.as_dict()}

    # ② 실행할 조치가 없음 (NONE) 또는 알림만 (NOTIFY)
    if decision.outcome in (NO_ACTION, NOTIFY):
        slack_dispatch = await notifier.send_alert_only(alert, analysis)
        await _push_slack_status(alert, analysis, slack_dispatch, "alert_only")
        return {"status": "notified", "message": f"Action {action_type} performs no change.",
                "policy": decision.as_dict()}

    # ③ 승인 필요 — high risk 는 confidence·critical 과 무관하게 항상 여기로 온다
    if decision.outcome == AWAITING_APPROVAL:
        rid = record.remediation_id if record else None
        if record:
            record_store.update(rid, state=store_mod.AWAITING_APPROVAL,
                                approval_requested_at=store_mod.utcnow())
        # 승인 버튼에 remediation_id 를 실어 보낸다 — 중복 승인이 한 건으로 합쳐진다.
        slack_dispatch = await notifier.send_approval_request(
            alert, analysis, remediation_id=rid)
        await _push_slack_status(alert, analysis, slack_dispatch, "approval_request")
        if record:
            await _push_record(record_store.get(rid) or record, "approval_requested")
        return {"status": "pending_approval", "reasons": list(decision.reasons),
                "remediation_id": rid, "policy": decision.as_dict()}

    # ④ 자동 실행 후보 — 정책 조건은 충족했다. 실제 실행은 execution_allowed 가 정한다.
    if decision.outcome == AUTO_EXECUTE_CANDIDATE:
        if not decision.executable_now:
            # 정책상 후보이지만 지금 실행할 수는 없다 (실행기·복구 미비 등).
            # "후보"와 "실행 가능"을 구분해 기록한다 — 성공으로 표시하지 않는다.
            if record:
                record_store.update(record.remediation_id, state=store_mod.BLOCKED)
            slack_dispatch = await notifier.send_alert_only(alert, analysis)
            await _push_slack_status(alert, analysis, slack_dispatch, "alert_only")
            return {"status": "auto_execution_deferred",
                    "reasons": list(decision.reasons), "policy": decision.as_dict()}

        # 승인 없이 실행되는 경로이지만, 증거 보존·검증·TTL 복구는 승인 경로와 같다.
        results, state = await _perform(record, decision.targets, action_type)
        for res in results:
            await _push_remediation_status(alert, analysis, res.target,
                                           action_type, res.summary())
        # 정책이 사후 알림을 요구하면 보낸다 (THROTTLE: notify=post_action)
        if decision.notify == "post_action":
            slack_dispatch = await notifier.send_alert_only(alert, analysis)
            await _push_slack_status(alert, analysis, slack_dispatch, "alert_only")
        status = {store_mod.VERIFIED: "executed", store_mod.SKIPPED: "skipped",
                  store_mod.BLOCKED: "blocked"}.get(state, "failed")
        return {"status": status, "remediation_id": record.remediation_id if record else None,
                "record_state": state,
                "results": [r.as_dict() for r in results], "policy": decision.as_dict()}

    # 도달하지 않아야 하는 분기 — 열어 두지 않고 차단한다.
    logger.error(f"[Policy] 처리되지 않은 outcome: {decision.outcome}")
    return {"status": "blocked", "reason": "unhandled_policy_outcome",
            "policy": decision.as_dict()}


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

    # 2. action 정보 추출
    actions = slack_payload.get("actions", [])
    if not actions:
        return JSONResponse(status_code=400, content={"error": "No actions in payload"})

    action       = actions[0]
    action_id    = action.get("action_id", "")
    raw_value    = action.get("value", "{}")
    response_url = slack_payload.get("response_url", "")
    user_name    = slack_payload.get("user", {}).get("name", "unknown")

    try:
        action_data = json.loads(raw_value)
    except json.JSONDecodeError:
        return JSONResponse(status_code=400, content={"error": "Invalid action value JSON"})

    alertname      = action_data.get("alertname", "unknown")
    action_type    = action_data.get("action_type", "NONE").upper()
    action_targets = action_data.get("action_targets", [])
    # [NEW] source 필드로 출처 구분
    source         = action_data.get("source", "alert_triggered")
    # [Phase 2] 멱등성 키. 과거 메시지·주기 스캔 버튼에는 없으므로, 없으면 경보·조치·
    # 대상에서 결정적으로 유도해 같은 승인이 한 건으로 합쳐지게 한다.
    remediation_id = action_data.get("remediation_id") or \
        store_mod.derive_id(alertname, action_type, action_targets)

    logger.info(
        f"[Slack Action] id={action_id}, user={user_name}, "
        f"alert={alertname}, type={action_type}, targets={action_targets}, source={source}"
    )

    # 출처별 로그 레이블
    source_label = {
        "periodic_log_scan": "정기 로그 스캔",
        "llm_health_check":  "LLM 헬스체크",
        "alert_triggered":   "Alert 기반",
    }.get(source, source)

    # 3. 승인 / 거부 분기
    if action_id == "approve_action":
        results = []

        # 승인되었어도 정책의 실행 게이트를 통과해야 실행한다. 자동 경로와 같은
        # 함수를 쓰므로 "한쪽 경로에서만 실행 가능한 조치"가 생기지 않는다.
        allowed, exec_reason = policy_engine.execution_allowed(action_type, action_targets)
        if not allowed:
            logger.warning(
                f"[Policy] 승인됐지만 실행하지 않는다: {action_type} — {exec_reason}")

        if allowed:
            # 레코드가 없으면(과거 메시지·주기 스캔) 승인 시점에 만든다.
            policy = policy_engine.config.actions.get(action_type) \
                if hasattr(policy_engine, "config") else None
            record, _is_new = record_store.get_or_create(store_mod.RemediationRecord(
                remediation_id=remediation_id, alertname=alertname,
                action_type=action_type, targets=list(action_targets),
                requires_approval=True, source=source,
                ttl_seconds=getattr(policy, "ttl_seconds", None),
                recovery_mode=getattr(policy, "recovery_mode", "none"),
                state=store_mod.AWAITING_APPROVAL,
                approval_requested_at=store_mod.utcnow(),
            ))
            # 상태를 APPROVED 로 덮지 않는다 — 이미 실행된 조치가 다시 실행 권리를
            # 얻으면 중복 실행이 된다. 전이 조건은 store 가 판단한다.
            record = record_store.mark_approved(remediation_id, user_name) or record

            exec_results, state = await _perform(record, record.targets, action_type,
                                                 approved_by=user_name)
            if exec_results:
                for res in exec_results:
                    results.append(res.summary())
                    await _push_soc_event("aiops-timeline", {
                        "event":       "manual_approval_executed",
                        "alert":       alertname,
                        "target":      res.target,
                        "action_type": action_type,
                        "approved_by": user_name,
                        "source":      source,       # [NEW] 출처 기록
                        "status":      _result_status(res.summary()),
                        "result":      res.summary(),
                        "remediation_id": remediation_id,
                        "verified":    res.verified,
                    })
            else:
                # 중복 승인 또는 증거 게이트 차단 — 실행하지 않았다.
                results = [f"Not executed: {action_type} ({state})"]
                await _push_soc_event("aiops-timeline", {
                    "event":       "manual_approval_logged",
                    "alert":       alertname,
                    "action_type": action_type,
                    "approved_by": user_name,
                    "source":      source,
                    "status":      state,
                    "remediation_id": remediation_id,
                })
        else:
            # 실행하지 않은 이유를 사람이 읽을 수 있게 남긴다 (이전에는 "auto-handler
            # 없음" 으로만 기록돼 왜 실행되지 않았는지 알 수 없었다).
            results = [f"Not executed: {action_type} blocked by policy ({exec_reason})"]
            await _push_soc_event("aiops-timeline", {
                "event":       "manual_approval_logged",
                "alert":       alertname,
                "action_type": action_type,
                "approved_by": user_name,
                "source":      source,
                "status":      "LOGGED",
                "policy_block_reason": exec_reason,
                "remediation_id": remediation_id,
            })

        result_text = "\n".join(f"• {r}" for r in results)
        await _update_slack_message(
            response_url,
            f":white_check_mark: *승인됨* (by `{user_name}`) — {source_label}\n"
            f"Alert: `{alertname}` | 조치: `{action_type}`\n"
            f"{result_text}"
        )
        return JSONResponse(status_code=200, content={"status": "approved", "results": results})

    elif action_id == "approve_recovery":
        # TTL 만료로 복구 승인을 요청한 조치를 사람이 승인했다.
        # ISOLATE/PAUSE 는 이 경로로만 복구된다 (TTL 만으로 자동 복구하지 않는다).
        record = record_store.get(remediation_id)
        if record is None:
            return JSONResponse(status_code=404,
                                content={"error": "unknown_remediation_id"})
        if (record.action_type != action_type or sorted(record.targets) != sorted(action_targets)
                or record.state not in (store_mod.RECOVERY_PENDING,
                                        store_mod.RECOVERY_APPROVAL_REQUIRED)):
            return JSONResponse(status_code=409, content={"error": "recovery_not_eligible"})
        results, state = await asyncio.get_event_loop().run_in_executor(
            None, recovery_mod.recover, record_store, executor, record, user_name, True)
        summaries = [r.summary() for r in results] or [f"Not recovered ({state})"]
        updated = record_store.get(remediation_id) or record
        await _push_record(updated, "recovery_completed", updated.state)
        await _push_soc_event("aiops-timeline", {
            "event":       "recovery_approved",
            "alert":       alertname,
            "action_type": action_type,
            "approved_by": user_name,
            "remediation_id": remediation_id,
            "status":      state,
            "results":     summaries,
            "mttr_sec":    updated.timings().get("mttr_sec"),
        })
        await _update_slack_message(
            response_url,
            f":arrows_counterclockwise: *복구 승인됨* (by `{user_name}`)\n"
            f"조치: `{action_type}` | 상태: `{state}`\n"
            + "\n".join(f"• {s}" for s in summaries)
        )
        return JSONResponse(status_code=200,
                            content={"status": "recovery_" + state.lower(),
                                     "results": summaries})

    elif action_id == "reject_action":
        await _push_soc_event("aiops-timeline", {
            "event":       "manual_approval_rejected",
            "alert":       alertname,
            "action_type": action_type,
            "rejected_by": user_name,
            "source":      source,       # [NEW] 출처 기록
            "status":      "REJECTED",
        })
        await _update_slack_message(
            response_url,
            f":no_entry: *거부됨* (by `{user_name}`) — {source_label}\n"
            f"Alert: `{alertname}` | 조치: `{action_type}` — 수동 조사 필요"
        )
        return JSONResponse(status_code=200, content={"status": "rejected"})

    else:
        logger.warning(f"[Slack Action] 알 수 없는 action_id: {action_id}")
        return JSONResponse(status_code=400, content={"error": f"Unknown action_id: {action_id}"})


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
        logger.warning(f"[Slack Action] 메시지 업데이트 실패: {e}")


# ─── 헬퍼 함수 ───────────────────────────────────────────

async def _run_executor(action: str, target: str, target_evidence: dict):
    """
    실행기를 블로킹하지 않게 호출한다 (Docker SDK 는 동기 호출이다).
    반환은 ExecutionResult — 조치 뒤 상태를 재조회해 확인한 결과다.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, executor.execute, action, target, target_evidence)


def _result_status(result: str) -> str:
    if result.startswith("Success"):
        return "SUCCESS"
    return "SKIPPED" if result.startswith("Skipped:") else "FAILED"


# ─── Phase 2: 증거 → 실행 → 검증 → 기록 → 복구 일정 ─────────────────────────

async def _on_ttl_event(record, results, state) -> None:
    """TTL 스캐너가 처리한 결과를 감사 로그에 남긴다."""
    updated = record_store.get(record.remediation_id) or record
    await _push_record(updated, "ttl_recovery_processed", state)
    if state == store_mod.RECOVERY_APPROVAL_REQUIRED:
        await notifier.send_recovery_request(updated)
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
    rid = record.remediation_id

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

    record_store.update(rid, approved_by=approved_by)

    # ② 증거 보존 — 되돌릴 수 없는 격리·동결을 막는 게이트
    target_evidence, block_reason = await asyncio.get_event_loop().run_in_executor(
        None, evidence_mod.gate, executor, record_store, rid, action_type,
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
        results.append(await _run_executor(
            action_type, target, evidence_mod.for_target(target_evidence, target)))

    all_ok = bool(results) and all(r.ok for r in results)
    any_skipped = any(r.status == store_mod.SKIPPED for r in results)

    if all_ok:
        state = store_mod.VERIFIED
        record_store.update(rid, state=state, action_verified_at=store_mod.utcnow(),
                            results=[r.as_dict() for r in results])
    elif any_skipped:
        # disabled 모드 — 실행하지 않았다. 성공으로 표시하지 않는다.
        state = store_mod.SKIPPED
        record_store.update(rid, state=state, results=[r.as_dict() for r in results])
    else:
        state = store_mod.FAILED
        record_store.update(rid, state=state, results=[r.as_dict() for r in results])

    # ⑤ 복구 일정 — 검증된 조치에만 TTL 을 건다 (실행 안 된 것은 되돌릴 것도 없다)
    current = record_store.get(rid) or record
    if state == store_mod.VERIFIED and RECOVERY_ACTION.get(action_type):
        recovery_mod.schedule(record_store, current, record.ttl_seconds,
                              record.recovery_mode)
        current = record_store.get(rid) or current

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
        "channel":             "#leafy-alert",
    })
    await _push_soc_event("aiops-timeline", {
        "event":               "slack_notification_sent" if sent else "slack_notification_skipped",
        "alert":               alert_name,
        "status":              status,
        "slack_response_code": dispatch.get("response_code"),
        "slack_response_text": dispatch.get("response_text", ""),
        "notification_type":   notification_type,
    })
