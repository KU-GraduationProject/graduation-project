"""
AIOps Remediation Agent
분석 결과 수신 → 자동 조치 실행 또는 승인 요청
"""

from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
import logging

from actions.container import ContainerActions
from actions.notify import Notifier

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="AIOps Remediation", version="0.1.0")

container_actions = ContainerActions()
notifier = Notifier()


class ActionRequest(BaseModel):
    alert: dict
    analysis: dict


@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


@app.post("/action")
async def execute_action(request: ActionRequest):
    """분석 결과 수신 → action_risk에 따라 자동 실행 or 승인 요청"""
    analysis = request.analysis
    alert = request.alert
    action_risk = analysis.get("action_risk", "high")
    action = analysis.get("action", "")

    threat_level = analysis.get("threat_level", "high")
    logger.info(f"[Remediation] action_risk={action_risk}, threat_level={threat_level}, action={action}")
    logger.info(f"[Remediation] root_cause={analysis.get('root_cause', 'N/A')}")

    if action_risk == "low":
        result = _execute(action, alert)
        return {"status": "executed", "result": result}
    elif action_risk == "medium":
        if threat_level == "low":
            notifier.send_alert_only(alert, analysis)
            return {"status": "alert_only", "message": "Medium-risk action with low threat: notified only"}
        else:
            notifier.send_approval_request(alert, analysis)
            return {"status": "pending_approval", "message": "Medium-risk action logged for manual review"}
    else:  # high
        notifier.send_approval_request(alert, analysis)
        return {"status": "pending_approval", "message": "High-risk action logged for manual review"}


def _execute(action: str, alert: dict) -> str:
    container_name = alert.get("labels", {}).get("container", "")
    action_lower = action.lower()

    try:
        if "restart" in action_lower:
            target = _extract_container(action) or container_name
            container_actions.restart(target)
            return f"Restarted container: {target}"
        elif "isolate" in action_lower:
            target = _extract_container(action) or container_name
            container_actions.isolate(target)
            return f"Isolated container: {target}"
        else:
            logger.info(f"[Remediation] No automated handler for: {action}")
            return f"No handler for: {action}"
    except Exception as e:
        logger.error(f"[Remediation] Action failed: {e}")
        return f"Failed: {e}"


def _extract_container(action: str) -> str | None:
    known = ["leafy-frontend", "leafy-backend", "leafy-db", "frontend", "backend", "db"]
    for name in known:
        if name in action:
            return name
    return None
