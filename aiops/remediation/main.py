"""
AIOps Remediation Agent (Final Version)
분석 결과 수신 → 다중 타겟(Array)에 대해 명시적 조치 실행

[수정] POST /slack/action 엔드포인트에 source 분기 추가
       - source="periodic_log_scan"  → 주기적 로그 스캔에서 온 승인
       - source="llm_health_check"   → LLM 헬스체크에서 온 승인
       - source="alert_triggered"    → 기존 alert 기반 승인 (기본값)
"""
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
from actions.container import ContainerActions
from actions.notify import Notifier
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
REMEDIATION_MODE = os.getenv("REMEDIATION_MODE", "docker")
if REMEDIATION_MODE not in ("docker", "disabled"):
    raise ValueError(f"REMEDIATION_MODE must be docker or disabled: {REMEDIATION_MODE!r}")

app = FastAPI(title="AIOps Remediation", version="0.1.0")

container_actions = ContainerActions() if REMEDIATION_MODE == "docker" else None
notifier = Notifier()

# 정책 엔진 (Phase 1). 로드에 실패하면 모든 조치를 차단하는 엔진이 돌아온다.
policy_engine = load_engine()
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
        slack_dispatch = await notifier.send_approval_request(alert, analysis)
        await _push_slack_status(alert, analysis, slack_dispatch, "approval_request")
        return {"status": "pending_approval", "reasons": list(decision.reasons),
                "policy": decision.as_dict()}

    # ④ 자동 실행 후보 — 정책 조건은 충족했다. 실제 실행은 execution_allowed 가 정한다.
    if decision.outcome == AUTO_EXECUTE_CANDIDATE:
        if not decision.executable_now:
            # Phase 1: TTL 자동 복구가 없어 되돌릴 수 없으므로 실행하지 않는다.
            # "정책상 후보"와 "실행 가능"을 구분해 기록한다 — 성공으로 표시하지 않는다.
            slack_dispatch = await notifier.send_alert_only(alert, analysis)
            await _push_slack_status(alert, analysis, slack_dispatch, "alert_only")
            return {"status": "auto_execution_deferred",
                    "reasons": list(decision.reasons), "policy": decision.as_dict()}

        execution_results = []
        for target in decision.targets:
            res = await _execute(action_type, target)
            execution_results.append(res)
            await _push_remediation_status(alert, analysis, target, action_type, res)
        return {"status": "executed" if container_actions else "skipped",
                "results": execution_results, "policy": decision.as_dict()}

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
            for target in action_targets:
                res = await _execute(action_type, target)
                results.append(res)
                await _push_soc_event("aiops-timeline", {
                    "event":       "manual_approval_executed",
                    "alert":       alertname,
                    "target":      target,
                    "action_type": action_type,
                    "approved_by": user_name,
                    "source":      source,       # [NEW] 출처 기록
                    "status":      _result_status(res),
                    "result":      res,
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
            })

        result_text = "\n".join(f"• {r}" for r in results)
        await _update_slack_message(
            response_url,
            f":white_check_mark: *승인됨* (by `{user_name}`) — {source_label}\n"
            f"Alert: `{alertname}` | 조치: `{action_type}`\n"
            f"{result_text}"
        )
        return JSONResponse(status_code=200, content={"status": "approved", "results": results})

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

async def _execute(action_type: str, target: str) -> str:
    if container_actions is None:
        logger.warning(f"[Remediation] REMEDIATION_MODE=disabled — {action_type} {target} 실행하지 않음")
        return f"Skipped: {action_type} {target} not executed (REMEDIATION_MODE=disabled, 원격 조치 미구현)"
    if not target:
        return "Error: No target container name"
    loop = asyncio.get_event_loop()
    try:
        if action_type == "RESTART":
            await loop.run_in_executor(None, container_actions.restart, target)
            return f"Success: {target} restarted."
        elif action_type == "ISOLATE":
            await loop.run_in_executor(None, container_actions.isolate, target)
            return f"Success: {target} isolated from network."
        elif action_type == "PAUSE":
            await loop.run_in_executor(None, container_actions.pause, target)
            return f"Success: {target} paused (forensic preservation)."
        elif action_type == "THROTTLE":
            await loop.run_in_executor(None, container_actions.throttle, target)
            return f"Success: {target} throttled (cpu_quota=50%)."
        else:
            return f"Skip: No handler for {action_type}"
    except Exception as e:
        logger.error(f"[Execution Error] {action_type} on {target}: {e}")
        return f"Fail: {target} ({str(e)})"


def _result_status(result: str) -> str:
    if result.startswith("Success"):
        return "SUCCESS"
    return "SKIPPED" if result.startswith("Skipped:") else "FAILED"


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