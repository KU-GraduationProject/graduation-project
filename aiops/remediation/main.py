"""
AIOps Remediation Agent (Final Version)
분석 결과 수신 → 다중 타겟(Array)에 대해 명시적 조치 실행
"""
from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
import asyncio  # ✅ Fix: 버그 1
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
    """분석 결과 수신 → 신뢰도와 위험도에 따른 실행 분기"""
    analysis = request.analysis
    alert = request.alert
    
    # 1. Pipeline에서 약속된 규격으로 데이터 추출
    action_type    = analysis.get("action_type", "NONE").upper()
    action_targets = analysis.get("action_targets", []) # ★ 리스트(배열) 형태
    action_risk    = analysis.get("action_risk", "medium")
    threat_level   = analysis.get("threat_level", "medium")
    confidence     = analysis.get("confidence", 0.0)

    logger.info(f"[Remediation] Start processing: Type={action_type}, Targets={action_targets}, Confidence={confidence}")

    # 2. 자동 실행 로직 (저위험 + 고신뢰)
    if action_risk == "low" and confidence >= 0.7:
        if action_type in ["RESTART", "ISOLATE"]:
            # ✅ Fix: 버그 2 — 빈 targets이면 오탐 방지
            if not action_targets:
                await notifier.send_approval_request(alert, analysis)
                return {"status": "pending_approval", "message": "No targets specified."}
            execution_results = []
            for target in action_targets:
                res = await _execute(action_type, target)  # ✅ Fix: 버그 1 — await 추가
                execution_results.append(res)
            return {"status": "executed", "results": execution_results}
        else:
            # SCALE이나 기타 조치는 아직 자동화 핸들러가 없으므로 알림 처리
            await notifier.send_alert_only(alert, analysis)
            return {"status": "notified", "message": f"Action {action_type} is not auto-enabled."}

    # 3. 신뢰도 부족 또는 위험도 높음 -> 승인 절차 (Human-in-the-loop)
    elif action_risk == "low" and confidence < 0.7:
        await notifier.send_approval_request(alert, analysis)
        return {"status": "pending_approval", "message": "Low confidence analysis."}

    elif action_risk == "medium":
        if threat_level == "low":
            await notifier.send_alert_only(alert, analysis)
            return {"status": "notified", "message": "Medium risk, low threat: notification sent."}
        else:
            await notifier.send_approval_request(alert, analysis)
            return {"status": "pending_approval", "message": "Approval required for medium risk."}

    else: # High risk
        await notifier.send_approval_request(alert, analysis)
        return {"status": "pending_approval", "message": "High-risk action requires manual intervention."}

async def _execute(action_type: str, target: str) -> str:  # ✅ Fix: 버그 1 — async로 변경
    """Docker SDK를 이용한 실제 조치 수행"""
    if not target:
        return "Error: No target container name"

    loop = asyncio.get_event_loop()
    try:
        if action_type == "RESTART":
            await loop.run_in_executor(None, container_actions.restart, target)  # ✅ Fix: 버그 1
            return f"Success: {target} restarted."
        elif action_type == "ISOLATE":
            await loop.run_in_executor(None, container_actions.isolate, target)  # ✅ Fix: 버그 1
            return f"Success: {target} isolated from network."
        else:
            return f"Skip: No handler for {action_type}"
    except Exception as e:
        logger.error(f"[Execution Error] {action_type} on {target}: {e}")
        return f"Fail: {target} ({str(e)})"
