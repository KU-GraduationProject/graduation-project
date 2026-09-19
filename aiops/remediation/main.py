"""
AIOps Remediation Agent (Final Version)
분석 결과 수신 → 다중 타겟(Array)에 대해 명시적 조치 실행

[수정] POST /slack/action 엔드포인트에 source 분기 추가
       - source="periodic_log_scan"  → 주기적 로그 스캔에서 온 승인
       - source="llm_health_check"   → LLM 헬스체크에서 온 승인
       - source="alert_triggered"    → 기존 alert 기반 승인 (기본값)
"""
from fastapi import FastAPI, Request
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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
LOKI_URL = os.getenv("LOKI_URL", "http://loki:3100")

app = FastAPI(title="AIOps Remediation", version="0.1.0")

container_actions = ContainerActions()
notifier = Notifier()


class ActionRequest(BaseModel):
    alert: dict
    analysis: dict


# ─── 기존 엔드포인트 ─────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


@app.post("/action")
async def execute_action(request: ActionRequest):
    """분석 결과 수신 → 신뢰도와 위험도에 따른 실행 분기"""
    analysis = request.analysis
    alert    = request.alert

    action_type    = analysis.get("action_type", "NONE").upper()
    action_targets = analysis.get("action_targets", [])
    action_risk    = analysis.get("action_risk", "medium")
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

    # 자동 실행 (저위험 + 고신뢰)
    if action_risk == "low" and confidence >= 0.7:
        if action_type in ["RESTART", "ISOLATE", "PAUSE", "THROTTLE"]:
            if not action_targets:
                slack_dispatch = await notifier.send_approval_request(alert, analysis)
                await _push_slack_status(alert, analysis, slack_dispatch, "approval_request")
                return {"status": "pending_approval", "message": "No targets specified."}
            execution_results = []
            for target in action_targets:
                res = await _execute(action_type, target)
                execution_results.append(res)
                await _push_remediation_status(alert, analysis, target, action_type, res)
            return {"status": "executed", "results": execution_results}
        else:
            slack_dispatch = await notifier.send_alert_only(alert, analysis)
            await _push_slack_status(alert, analysis, slack_dispatch, "alert_only")
            return {"status": "notified", "message": f"Action {action_type} is not auto-enabled."}

    elif action_risk == "low" and confidence < 0.7:
        slack_dispatch = await notifier.send_approval_request(alert, analysis)
        await _push_slack_status(alert, analysis, slack_dispatch, "approval_request")
        return {"status": "pending_approval", "message": "Low confidence analysis."}

    elif action_risk == "medium":
        if threat_level == "low":
            slack_dispatch = await notifier.send_alert_only(alert, analysis)
            await _push_slack_status(alert, analysis, slack_dispatch, "alert_only")
            return {"status": "notified", "message": "Medium risk, low threat: notification sent."}
        else:
            slack_dispatch = await notifier.send_approval_request(alert, analysis)
            await _push_slack_status(alert, analysis, slack_dispatch, "approval_request")
            return {"status": "pending_approval", "message": "Approval required for medium risk."}

    else:  # High risk
        slack_dispatch = await notifier.send_approval_request(alert, analysis)
        await _push_slack_status(alert, analysis, slack_dispatch, "approval_request")
        return {"status": "pending_approval", "message": "High-risk action requires manual intervention."}


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
    # 1. Slack payload 파싱
    body = await request.body()
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

        if action_type in ("RESTART", "ISOLATE") and action_targets:
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
                    "status":      "SUCCESS" if res.startswith("Success") else "FAILED",
                    "result":      res,
                })
        else:
            results = [f"action_type={action_type} — auto-handler 없음, 로그만 기록"]
            await _push_soc_event("aiops-timeline", {
                "event":       "manual_approval_logged",
                "alert":       alertname,
                "action_type": action_type,
                "approved_by": user_name,
                "source":      source,
                "status":      "LOGGED",
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
    status     = "SUCCESS" if result.startswith("Success:") else "FAILED"
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