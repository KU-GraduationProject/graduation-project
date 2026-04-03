"""
AIOps Pipeline Module
AlertManager 웹훅 수신 → 데이터 수집 → 프롬프트 조립 → LLM 호출 → 결과 반환
"""

from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from datetime import datetime
import logging

from collector.metrics import MetricsCollector
from collector.logs import LogsCollector
from prompt.builder import PromptBuilder
from schemas.llm_output import LLMAnalysisResult
import httpx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="AIOps Pipeline", version="0.1.0")


# ─── AlertManager 웹훅 스키마 ───────────────────────────
class AlertLabel(BaseModel):
    alertname: str
    severity: str | None = None
    container: str | None = None
    instance: str | None = None

class Alert(BaseModel):
    status: str          # "firing" | "resolved"
    labels: AlertLabel
    startsAt: str
    endsAt: str | None = None
    annotations: dict = {}

class AlertManagerWebhook(BaseModel):
    version: str
    groupKey: str
    status: str
    alerts: list[Alert]


# ─── 설정 ───────────────────────────────────────────────
from config import settings

metrics_collector = MetricsCollector(settings.prometheus_url)
logs_collector    = LogsCollector(settings.loki_url)
prompt_builder    = PromptBuilder()


# ─── 엔드포인트 ─────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


@app.post("/webhook/alert")
async def receive_alert(payload: AlertManagerWebhook, background_tasks: BackgroundTasks):
    """AlertManager에서 이상 감지 웹훅 수신 → 비동기 분석 시작"""
    firing_alerts = [a for a in payload.alerts if a.status == "firing"]
    if not firing_alerts:
        return {"message": "resolved alerts, skip"}

    background_tasks.add_task(analyze_alerts, firing_alerts)
    return {"message": f"{len(firing_alerts)} alert(s) queued for analysis"}


async def analyze_alerts(alerts: list[Alert]):
    """핵심 파이프라인: 수집 → 프롬프트 → LLM → Remediation 전달"""
    for alert in alerts:
        try:
            logger.info(f"[Pipeline] 분석 시작: {alert.labels.alertname}")

            # 1. 이상 시점 전후 N분 데이터 수집
            alert_time = datetime.fromisoformat(alert.startsAt.replace("Z", "+00:00"))
            metrics = await metrics_collector.fetch_around(
                container=alert.labels.container,
                alert_time=alert_time,
                window_minutes=5,
            )
            logs = await logs_collector.fetch_around(
                container=alert.labels.container,
                alert_time=alert_time,
                window_minutes=5,
            )

            # 2. 프롬프트 조립
            prompt = prompt_builder.build(
                alert=alert,
                metrics=metrics,
                logs=logs,
            )

            # 3. LLM 호출 (Ollama)
            result: LLMAnalysisResult = await call_llm(prompt)
            logger.info(f"[Pipeline] LLM 분석 완료: {result.model_dump()}")

            # 4. Remediation Agent에 전달
            await forward_to_remediation(alert, result)

        except Exception as e:
            logger.error(f"[Pipeline] 분석 실패 ({alert.labels.alertname}): {e}")


async def call_llm(prompt: dict) -> LLMAnalysisResult:
    """Ollama API 호출 → JSON 파싱"""
    async with httpx.AsyncClient(timeout=120) as client:
        response = await client.post(
            f"{settings.ollama_url}/api/chat",
            json={
                "model": settings.llm_model,
                "messages": [
                    {"role": "system", "content": prompt["system"]},
                    {"role": "user",   "content": prompt["user"]},
                ],
                "format": "json",
                "stream": False,
            },
        )
        response.raise_for_status()
        content = response.json()["message"]["content"]
        import json
        raw = json.loads(content)
        return LLMAnalysisResult(**raw)


async def forward_to_remediation(alert: Alert, result: LLMAnalysisResult):
    """Remediation Agent에 분석 결과 전달"""
    async with httpx.AsyncClient(timeout=30) as client:
        await client.post(
            f"{settings.remediation_url}/action",
            json={
                "alert": alert.model_dump(),
                "analysis": result.model_dump(),
            },
        )
