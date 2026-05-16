

"""
AIOps Pipeline Module
AlertManager 웹훅 수신 → 데이터 수집 → 프롬프트 조립 → LLM 호출 → 결과 반환
"""

from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ValidationError  # ✅ Fix: 버그 3
from datetime import datetime
from collections import deque
import json
import asyncio
import logging
import httpx
import time
import re as _re
_DOCKER_UDS = "/var/run/docker.sock"
from collector.metrics import MetricsCollector
from collector.logs import LogsCollector
from prompt.builder import PromptBuilder
from schemas.llm_output import LLMAnalysisResult
from config import settings


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="AIOps Pipeline", version="0.1.0")

# 최근 분석 결과 저장 (최대 20건)
analysis_history: deque = deque(maxlen=20)

# ─── 중복 Alert 필터 ────────────────────────────────────
DEDUP_WINDOW_SEC = 300
_recent_alerts: dict[str, float] = {}

# ─── AlertManager 웹훅 스키마 ───────────────────────────
class AlertLabel(BaseModel):
    alertname: str
    severity: str | None = None
    instance: str | None = None
    container: str | None = None

class Alert(BaseModel):
    status: str
    labels: AlertLabel
    startsAt: str
    endsAt: str | None = None
    annotations: dict = {}

class AlertManagerWebhook(BaseModel):
    version: str
    groupKey: str
    status: str
    alerts: list[Alert]

# ─── 의존성 주입 ─────────────────────────────────────────
metrics_collector = MetricsCollector(settings.prometheus_url)
logs_collector    = LogsCollector(settings.loki_url)
prompt_builder    = PromptBuilder()

_SERVICE_PREFIXES = ["leafy-", "aiops-", "graduation-project-"]

def _extract_service(name: str) -> str:
    s = name
    for prefix in _SERVICE_PREFIXES:
        if s.startswith(prefix):
            s = s[len(prefix):]
            break
    return _re.sub(r"-\d+$", "", s)


# ─── 엔드포인트 ─────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}

@app.get("/metrics", response_class=PlainTextResponse)
async def prometheus_metrics():
    """컨테이너 ID → 이름/서비스 매핑을 Prometheus 텍스트 포맷으로 노출 (비동기화 완료)"""
    name_lines: list[str] = [
        "# HELP container_name_info Container ID to name mapping",
        "# TYPE container_name_info gauge",
    ]
    count_map: dict[str, int] = {}
    try:
        async with httpx.AsyncClient(
            transport=httpx.AsyncHTTPTransport(uds=_DOCKER_UDS), timeout=3
        ) as client:
            resp = await client.get("http://localhost/containers/json")
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

# (참고: /results, /debug 등 기타 GET 엔드포인트들은 기존 코드 그대로 사용하면 됨)

@app.post("/webhook/alert")
async def receive_alert(payload: AlertManagerWebhook, background_tasks: BackgroundTasks):
    """AlertManager에서 이상 감지 웹훅 수신 → 비동기 분석 시작"""
    firing_alerts = [a for a in payload.alerts if a.status == "firing"]
    if not firing_alerts:
        return {"message": "resolved alerts, skip"}

    background_tasks.add_task(analyze_alerts, firing_alerts)
    return {"message": f"{len(firing_alerts)} alert(s) queued for analysis"}


# ─── 핵심 파이프라인 (초경량화 완료) ──────────────────────

async def analyze_alerts(alerts: list[Alert]):
    now = time.time()
    expired = [k for k, ts in _recent_alerts.items() if now - ts > DEDUP_WINDOW_SEC * 2]
    for k in expired:
        del _recent_alerts[k]

    for alert in alerts:
        # ★ 핵심 개선: 복잡한 Docker Socket ID 변환 없이, 웹훅에서 바로 직관적인 이름을 꺼내 씀
        container_name = alert.annotations.get("container") or alert.labels.container

        dedup_key = f"{alert.labels.alertname}:{container_name or 'unknown'}"
        last_seen = _recent_alerts.get(dedup_key)
        if last_seen is not None and now - last_seen < DEDUP_WINDOW_SEC:
            logger.info(f"[Pipeline] 중복 Alert 스킵: {dedup_key}")
            continue
        _recent_alerts[dedup_key] = now

        try:
            logger.info(f"[Pipeline] 분석 시작: {alert.labels.alertname} | 대상: {container_name}")
            alert_time = datetime.fromisoformat(alert.startsAt.replace("Z", "+00:00"))

            if not container_name or container_name == "unknown":
                logger.warning(f"[Pipeline] 컨테이너 정보 없음, LLM 스킵: {alert.labels.alertname}")
                
                fallback_result = LLMAnalysisResult(
                    root_cause="컨테이너 정보 없음 — 수동 확인 필요",
                    action_type="NONE",
                    action_targets=[],           # ← 수정
                    action_description="manual investigation required",  # ← 수정
                    threat_level="medium",
                    action_risk="high",
                    evidence=[],
                    confidence=0.0,
                )
                entry = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "alert_name": alert.labels.alertname,
                    "container": "unknown",
                    "result": fallback_result.model_dump(),
                }
                analysis_history.append(entry)
                try: await push_to_loki(entry)
                except Exception: pass
                try: await forward_to_remediation(alert, fallback_result)
                except Exception: pass
                continue

            # 1. 메트릭/로그 수집 (더 이상 container_id 파라미터가 필요 없음!)
            metrics = await metrics_collector.fetch_around(
                container=container_name,
                alert_time=alert_time,
                window_minutes=5,
            )
            logs = await logs_collector.fetch_around(
                container=container_name,
                alert_time=alert_time,
                window_minutes=5,
            )

            # 2. 프롬프트 조립
            prompt = prompt_builder.build(
                alert=alert,
                metrics=metrics,
                logs=logs,
                container_name=container_name,
            )

            # 3. LLM 호출
            result: LLMAnalysisResult = await call_llm(prompt)
            logger.info(f"[Pipeline] LLM 분석 완료: {result.model_dump()}")

            # 4. 결과 저장
            entry = {
                "timestamp": datetime.utcnow().isoformat(),
                "alert_name": alert.labels.alertname,
                "container": container_name,
                "result": result.model_dump(),
            }
            analysis_history.append(entry)

            # 5. Loki 푸시 & 6. Remediation 전달
            await push_to_loki(entry)
            await forward_to_remediation(alert, result)

        except Exception as e:
            logger.error(f"[Pipeline] 분석 실패 ({alert.labels.alertname}): {e}")
            try:
                fallback_result = LLMAnalysisResult(
                    root_cause="LLM 분석/파싱 실패 — 수동 확인 필요",
                    action_type="NONE",
                    action_targets=[],           # ← 수정
                    action_description="manual investigation required",  # ← 수정
                    threat_level="medium",
                    action_risk="high",
                    evidence=[],
                    confidence=0.0,
                )
                await forward_to_remediation(alert, fallback_result)
            except Exception as fe:
                logger.error(f"[Pipeline] fallback 전달 실패: {fe}")


async def push_to_loki(entry: dict) -> None:
    """LLM 분석 결과를 Loki에 구조화된 로그로 푸시 (Grafana 대시보드용)"""
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
    """Ollama API 호출 → JSON 파싱 (최대 2회 시도)"""
    last_raw: str | None = None

    for attempt in range(2):
        user_content = prompt["user"]
        if attempt == 1:
            user_content += "\n\nYou MUST respond with valid JSON only. No markdown, no explanation."

        try:
            async with httpx.AsyncClient(timeout=settings.llm_timeout) as client:
                response = await client.post(
                    f"{settings.ollama_url}/api/chat",
                    json={
                        "model": settings.llm_model,
                        "messages": [
                            {"role": "system", "content": prompt["system"]},
                            {"role": "user",   "content": user_content},
                        ],
                        "format": "json",
                        "stream": False,
                    },
                )
                response.raise_for_status()
                last_raw = response.json()["message"]["content"]
                raw = json.loads(last_raw)
                return LLMAnalysisResult(**raw)
        except (httpx.TimeoutException, httpx.HTTPStatusError) as e:
            logger.error(f"[Pipeline] LLM 호출 실패 (시도 {attempt + 1}/2): {e}")
        except json.JSONDecodeError as e:
            logger.error(f"[Pipeline] JSON 파싱 실패 (시도 {attempt + 1}/2): {e} | 원본: {last_raw!r}")
        except ValidationError as e:  # ✅ Fix: 버그 3 — pydantic 스키마 불일치 처리
            logger.error(f"[Pipeline] LLM 응답 스키마 불일치 (시도 {attempt + 1}/2): {e}")

        if attempt == 0:
            await asyncio.sleep(5)

    # 2회 모두 실패 → Loki에 원본 응답 기록 후 fallback 반환
    ts_ns = str(int(time.time() * 1_000_000_000))
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(
                f"{settings.loki_url}/loki/api/v1/push",
                json={
                    "streams": [{
                        "stream": {"job": "aiops-llm-error"},
                        "values": [[ts_ns, json.dumps({"raw_response": last_raw}, ensure_ascii=False)]],
                    }]
                },
                headers={"Content-Type": "application/json"},
            )
    except Exception as e:
        logger.warning(f"[Pipeline] LLM 에러 Loki 푸시 실패 (무시): {e}")

    return LLMAnalysisResult(
        root_cause="LLM 응답 파싱 실패 — 수동 확인 필요",
        action_type="NONE",
        action_targets=[],           # ← 수정
        action_description="manual investigation required",  # ← 수정
        threat_level="medium",
        action_risk="high",
        evidence=[],
        confidence=0.0,
    )

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
