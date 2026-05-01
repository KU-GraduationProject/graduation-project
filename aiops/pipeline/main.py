"""
AIOps Pipeline Module
AlertManager 웹훅 수신 → 데이터 수집 → 프롬프트 조립 → LLM 호출 → 결과 반환
"""

from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from datetime import datetime
from collections import deque
import json
import logging

import httpx

from collector.metrics import MetricsCollector
from collector.logs import LogsCollector
from prompt.builder import PromptBuilder
from schemas.llm_output import LLMAnalysisResult

_DOCKER_UDS = "/var/run/docker.sock"


def _resolve_container_name(raw: str | None) -> str | None:
    """
    cAdvisor container annotation은 '/docker/<full_id>' 형태로 온다.
    Docker socket REST API로 실제 컨테이너 이름(e.g. 'leafy-backend')으로 변환.
    """
    if not raw:
        return None
    if not raw.startswith("/docker/"):
        return raw  # 이미 이름 형태
    cid = raw[len("/docker/"):]
    try:
        with httpx.Client(
            transport=httpx.HTTPTransport(uds=_DOCKER_UDS),
            timeout=3,
        ) as client:
            resp = client.get(f"http://localhost/containers/{cid}/json")
            if resp.status_code == 200:
                name = resp.json().get("Name", "").lstrip("/")
                return name or raw
    except Exception:
        pass
    return raw

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="AIOps Pipeline", version="0.1.0")

# 최근 분석 결과 저장 (최대 20건)
analysis_history: deque = deque(maxlen=20)


# ─── AlertManager 웹훅 스키마 ───────────────────────────
class AlertLabel(BaseModel):
    alertname: str
    severity: str | None = None
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


import re as _re

_SERVICE_PREFIXES = ["leafy-", "aiops-", "graduation-project-"]

def _extract_service(name: str) -> str:
    """컨테이너 이름에서 서비스명 추출 (scale replica 번호 제거)."""
    s = name
    for prefix in _SERVICE_PREFIXES:
        if s.startswith(prefix):
            s = s[len(prefix):]
            break
    return _re.sub(r"-\d+$", "", s)


@app.get("/metrics", response_class=PlainTextResponse)
async def prometheus_metrics():
    """컨테이너 ID → 이름/서비스 매핑을 Prometheus 텍스트 포맷으로 노출"""
    name_lines: list[str] = [
        "# HELP container_name_info Container ID to name mapping",
        "# TYPE container_name_info gauge",
    ]
    count_map: dict[str, int] = {}
    try:
        with httpx.Client(
            transport=httpx.HTTPTransport(uds=_DOCKER_UDS), timeout=3
        ) as client:
            resp = client.get("http://localhost/containers/json")
            for c in resp.json():
                cid  = c.get("Id", "")
                name = (c.get("Names") or [""])[0].lstrip("/")
                if not (cid and name):
                    continue
                service = _extract_service(name)
                name_lines.append(
                    f'container_name_info{{id="/docker/{cid}",name="{name}",service="{service}"}} 1'
                )
                count_map[service] = count_map.get(service, 0) + 1
    except Exception as e:
        logger.warning(f"[metrics] Docker socket 조회 실패: {e}")

    count_lines = [
        "# HELP container_service_count Running container count per service",
        "# TYPE container_service_count gauge",
    ]
    for svc, cnt in sorted(count_map.items()):
        count_lines.append(f'container_service_count{{service="{svc}"}} {cnt}')

    return "\n".join(name_lines + [""] + count_lines) + "\n"


@app.get("/results/latest")
async def get_latest_result():
    """가장 최근 LLM 분석 결과 반환 (데모용)"""
    if not analysis_history:
        return {"status": "pending", "message": "아직 분석 결과 없음"}
    return {"status": "ok", "data": analysis_history[-1]}


@app.get("/results")
async def get_all_results():
    """최근 분석 결과 전체 목록 반환"""
    return {"status": "ok", "count": len(analysis_history), "data": list(analysis_history)}


@app.get("/debug/alerts")
async def debug_alerts():
    """Prometheus 발화 중인 alert 목록 조회 (Pipeline 경유)"""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{settings.prometheus_url}/api/v1/alerts")
            data = resp.json()
        firing = [
            a for a in data.get("data", {}).get("alerts", [])
            if a.get("state") == "firing"
        ]
        return {"status": "ok", "alerts": firing}
    except Exception as e:
        return {"status": "error", "alerts": [], "message": str(e)}


@app.get("/debug/metrics")
async def debug_metrics(container: str = ""):
    """호스트에서 직접 Prometheus에 접근할 수 없을 때 Pipeline 경유로 현재 메트릭 조회"""
    from datetime import timezone
    alert_time = datetime.now(timezone.utc)
    try:
        data = await metrics_collector.fetch_around(
            container=container if container else None,
            alert_time=alert_time,
            window_minutes=2,
        )
        # 각 메트릭의 최신값만 추출
        snapshot = {}
        for key, series_list in data.items():
            latest = None
            for series in series_list:
                vals = series.get("values", [])
                if vals:
                    latest = vals[-1]["v"]
            snapshot[key] = latest
        return {"status": "ok", "container": container, "snapshot": snapshot}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.get("/debug/logs")
async def debug_logs(container: str = "", lines: int = 15):
    """호스트에서 직접 Loki에 접근할 수 없을 때 Pipeline 경유로 최근 로그 조회"""
    from datetime import timezone
    alert_time = datetime.now(timezone.utc)
    try:
        data = await logs_collector.fetch_around(
            container=container if container else None,
            alert_time=alert_time,
            window_minutes=5,
        )
        recent = sorted(data, key=lambda x: x["ts"], reverse=True)[:lines]
        log_lines = [
            {
                "timestamp": datetime.fromtimestamp(e["ts"]).strftime("%H:%M:%S"),
                "message": e["line"],
            }
            for e in reversed(recent)
        ]
        return {"status": "ok", "container": container, "logs": log_lines}
    except Exception as e:
        return {"status": "error", "message": str(e)}


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
            container_raw = alert.annotations.get("container")
            container = _resolve_container_name(container_raw)
            logger.info(f"[Pipeline] container annotation={container_raw!r} → resolved={container!r}")
            metrics = await metrics_collector.fetch_around(
                container=container,
                alert_time=alert_time,
                window_minutes=5,
            )
            logs = await logs_collector.fetch_around(
                container=container,
                alert_time=alert_time,
                window_minutes=5,
            )

            # 2. 프롬프트 조립
            prompt = prompt_builder.build(
                alert=alert,
                metrics=metrics,
                logs=logs,
                container_name=container,
            )

            # 3. LLM 호출 (Ollama)
            result: LLMAnalysisResult = await call_llm(prompt)
            logger.info(f"[Pipeline] LLM 분석 완료: {result.model_dump()}")

            # 4. 결과 저장 (데모 폴링용)
            entry = {
                "timestamp": datetime.utcnow().isoformat(),
                "alert_name": alert.labels.alertname,
                "container": container or "unknown",
                "result": result.model_dump(),
            }
            analysis_history.append(entry)

            # 5. Loki에 LLM 결과 푸시 (Grafana 대시보드용)
            await push_to_loki(entry)

            # 6. Remediation Agent에 전달
            await forward_to_remediation(alert, result)

        except Exception as e:
            logger.error(f"[Pipeline] 분석 실패 ({alert.labels.alertname}): {e}")


async def push_to_loki(entry: dict) -> None:
    """LLM 분석 결과를 Loki에 구조화된 로그로 푸시 (Grafana 대시보드용)"""
    import time
    ts_ns = str(int(time.time() * 1_000_000_000))
    result = entry.get("result", {})
    payload = {
        "streams": [{
            "stream": {
                "job": "aiops-llm",
                "container": entry.get("container", "unknown"),
                "alert": entry.get("alert_name", "unknown"),
                "threat_level": result.get("threat_level", "unknown"),
                "action_risk": result.get("action_risk", "unknown"),
            },
            "values": [[ts_ns, json.dumps(entry, ensure_ascii=False)]]
        }]
    }
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(
                f"{settings.loki_url}/loki/api/v1/push",
                json=payload,
                headers={"Content-Type": "application/json"},
            )
        logger.info(f"[Pipeline] Loki 푸시 완료: {entry['alert_name']} / {entry['container']}")
    except Exception as e:
        logger.warning(f"[Pipeline] Loki 푸시 실패 (무시): {e}")


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
