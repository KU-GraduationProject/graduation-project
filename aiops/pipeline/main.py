"""
AIOps Pipeline Module
AlertManager 웹훅 수신 → 데이터 수집 → 프롬프트 조립 → LLM 호출 → 결과 반환

[추가] 백그라운드 태스크 2개
  1. periodic_log_check()   — 10분마다 앱 로그 이상탐지 (Alert 없어도 동작)
  2. periodic_llm_health()  — 5분마다 LLM 분석 결과 품질 모니터링
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ValidationError
from datetime import datetime, timezone
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

# ─── 중복 Alert 필터 ────────────────────────────────────
DEDUP_WINDOW_SEC = 300
_recent_alerts: dict[str, float] = {}

# ─── 주기적 스캔 중복 알림 방지 캐시 ───────────────────
# 같은 이상을 1시간 내 재전송 안 함
_periodic_alert_cache: dict[str, float] = {}
PERIODIC_CACHE_TTL = 3600  # 1시간

# 최근 분석 결과 저장 (최대 20건)
analysis_history: deque = deque(maxlen=20)


# ─── 백그라운드 태스크 ───────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """서버 시작 시 백그라운드 태스크 실행, 종료 시 정리"""
    task1 = asyncio.create_task(periodic_log_check())
    task2 = asyncio.create_task(periodic_llm_health())
    logger.info("[Periodic] 백그라운드 태스크 시작: log_check(10분), llm_health(5분)")
    yield
    task1.cancel()
    task2.cancel()
    logger.info("[Periodic] 백그라운드 태스크 종료")


app = FastAPI(title="AIOps Pipeline", version="0.1.0", lifespan=lifespan)


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
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}

@app.get("/metrics", response_class=PlainTextResponse)
async def prometheus_metrics():
    """컨테이너 ID → 이름/서비스 매핑을 Prometheus 텍스트 포맷으로 노출"""
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


@app.post("/webhook/alert")
async def receive_alert(payload: AlertManagerWebhook, background_tasks: BackgroundTasks):
    """AlertManager에서 이상 감지 웹훅 수신 → 비동기 분석 시작"""
    firing_alerts = [a for a in payload.alerts if a.status == "firing"]
    if not firing_alerts:
        return {"message": "resolved alerts, skip"}

    background_tasks.add_task(analyze_alerts, firing_alerts)
    return {"message": f"{len(firing_alerts)} alert(s) queued for analysis"}


# ─── 핵심 파이프라인 ──────────────────────────────────────

async def _resolve_top_cpu_container() -> str | None:
    query = 'topk(1, sum(irate(container_cpu_usage_seconds_total{id=~"/docker/.+",cpu="total"}[30s])) by (name))'
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(
                f"{settings.prometheus_url}/api/v1/query",
                params={"query": query},
            )
            data = resp.json()
            results = data.get("data", {}).get("result", [])
            if results:
                return results[0].get("metric", {}).get("name")
    except Exception as e:
        logger.warning(f"[Pipeline] top CPU container 조회 실패: {e}")
    return None


async def analyze_alerts(alerts: list[Alert]):
    now = time.time()
    expired = [k for k, ts in _recent_alerts.items() if now - ts > DEDUP_WINDOW_SEC * 2]
    for k in expired:
        del _recent_alerts[k]

    for alert in alerts:
        container_name = alert.annotations.get("container") or alert.labels.container

        dedup_key = f"{alert.labels.alertname}:{container_name}" \
            if container_name and container_name != "unknown" \
            else alert.labels.alertname
        last_seen = _recent_alerts.get(dedup_key)
        if last_seen is not None and now - last_seen < DEDUP_WINDOW_SEC:
            logger.info(f"[Pipeline] 중복 Alert 스킵: {dedup_key}")
            continue
        _recent_alerts[dedup_key] = now

        try:
            if alert.labels.alertname == "HighCpuUsage" and (not container_name or container_name == "unknown"):
                container_name = await _resolve_top_cpu_container()
                logger.info(f"[Pipeline] HighCpuUsage container 자동 조회: {container_name}")

            logger.info(f"[Pipeline] 분석 시작: {alert.labels.alertname} | 대상: {container_name}")
            alert_time = datetime.fromisoformat(alert.startsAt.replace("Z", "+00:00"))

            # [FIX] 컨테이너 없음 → Loki 기록만, Slack/Remediation 스킵
            if not container_name or container_name == "unknown":
                logger.warning(f"[Pipeline] 컨테이너 정보 없음, 스킵: {alert.labels.alertname}")
                fallback_result = LLMAnalysisResult(
                    root_cause="컨테이너 정보 없음 — 수동 확인 필요",
                    action_type="NONE",
                    action_targets=[],
                    action_description="manual investigation required",
                    threat_level="medium",
                    action_risk="high",
                    evidence=[],
                    confidence=0.0,
                )
                entry = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "alert_name": alert.labels.alertname,
                    "container": "unknown",
                    "result": fallback_result.model_dump(),
                }
                analysis_history.append(entry)
                try:
                    await push_to_loki(entry)
                except Exception:
                    pass
                continue

            logger.info(f"[Pipeline] LLM 분석 시작: {alert.labels.alertname} / {container_name}")

            # 1. 메트릭/로그 수집
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
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "alert_name": alert.labels.alertname,
                "container": container_name,
                "result": result.model_dump(),
            }
            analysis_history.append(entry)

            # 5. Loki 푸시
            await push_to_loki(entry)

            # [FIX] LLM 파싱 실패 fallback이면 remediation 스킵 → Slack 노이즈 차단
            if result.confidence == 0.0 and result.action_type == "NONE":
                logger.warning(
                    f"[Pipeline] LLM 파싱 실패 fallback — remediation 스킵: "
                    f"{alert.labels.alertname} / {container_name}"
                )
                continue

            # 6. Remediation 전달 (여기서 Slack 전송됨)
            await forward_to_remediation(alert, result)

        except Exception as e:
            logger.error(f"[Pipeline] 분석 실패 ({alert.labels.alertname}): {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# 백그라운드 태스크 1 — 주기적 앱 로그 이상탐지
# ═══════════════════════════════════════════════════════════════════════════════

# 주기적 스캔용 시스템 프롬프트
PERIODIC_SCAN_SYSTEM_PROMPT = """You are an AIOps security analyst. Analyze recent container logs and detect anomalies. Respond in JSON only.

SCHEMA:
{
  "is_healthy": true/false,
  "issues": ["<issue description>", ...],
  "affected_containers": ["<container name>", ...],
  "recommendation": "<one sentence action>",
  "action_type": "<RESTART|ISOLATE|SCALE|NOTIFY|NONE>",
  "action_targets": ["<container name>", ...],
  "threat_level": "<low|medium|high|critical>",
  "action_risk": "<low|medium|high>",
  "confidence": <0.0-1.0>
}

DETECTION CRITERIA:
- ERROR/FATAL logs > 20 in 10 minutes → application issue
- authentication failed > 3 → brute force attempt
- sqlmap/union select/or 1=1 keyword → SQLi attack
- OOM/OutOfMemory keyword → memory issue
- If logs are normal → is_healthy: true, action_type: NONE
"""

async def periodic_log_check() -> None:
    """
    10분마다 leafy-backend/frontend/db 로그를 조회하여 이상 감지.
    Alert 없어도 동작 — AlertManager가 못 잡는 이상 탐지 목적.

    근거: NIST SP 800-137 Continuous Monitoring
    """
    # 서버 시작 직후 바로 실행하지 않고 1분 대기 (시스템 안정화)
    await asyncio.sleep(60)

    while True:
        try:
            logger.info("[Periodic] 앱 로그 이상탐지 스캔 시작")
            now_ts = time.time()
            window_sec = 600  # 10분

            # 모니터링 대상 컨테이너 (Fluentd tag 기준)
            targets = ["backend", "frontend", "leafy-db"]

            for container in targets:
                try:
                    # Loki에서 최근 10분 로그 조회
                    logs = await _fetch_loki_logs(container, window_sec)
                    if not logs:
                        continue

                    # 1차 필터: 키워드 기반 빠른 체크
                    all_lines = " ".join(l.get("line", "") for l in logs).lower()
                    has_issue = (
                        all_lines.count("error") > 20
                        or all_lines.count("fatal") > 5
                        or all_lines.count("authentication failed") > 3
                        or any(kw in all_lines for kw in ["sqlmap", "union select", "or 1=1"])
                        or all_lines.count("outofmemory") > 0
                    )

                    if not has_issue:
                        continue

                    # 2차: LLM 분석
                    log_summary = "\n".join(
                        f"[{l.get('labels', {}).get('container', '?')}] {l.get('line', '')[:200]}"
                        for l in logs[:50]
                    )
                    prompt = {
                        "system": PERIODIC_SCAN_SYSTEM_PROMPT,
                        "user": (
                            f"Container: {container}\n"
                            f"Time window: last 10 minutes\n"
                            f"Log count: {len(logs)}\n\n"
                            f"=== LOGS ===\n{log_summary}\n\n"
                            f"Analyze and respond with JSON only."
                        ),
                    }

                    raw_result = await _call_llm_raw(prompt)
                    if not raw_result:
                        continue

                    is_healthy = raw_result.get("is_healthy", True)
                    if is_healthy:
                        continue

                    # 이상 감지 → 중복 캐시 체크
                    issues = raw_result.get("issues", [])
                    issue_key = f"periodic_log:{container}:{raw_result.get('threat_level', 'unknown')}"
                    last_sent = _periodic_alert_cache.get(issue_key, 0)
                    if now_ts - last_sent < PERIODIC_CACHE_TTL:
                        logger.info(f"[Periodic] 중복 알림 스킵: {issue_key}")
                        continue

                    _periodic_alert_cache[issue_key] = now_ts

                    # Slack 버튼 알림 전송
                    await send_periodic_slack(
                        issue_key=issue_key,
                        container=container,
                        issues=issues,
                        raw_result=raw_result,
                        source="periodic_log_scan",
                    )
                    logger.warning(f"[Periodic] 이상 감지 → Slack 전송: {container} / {issues}")

                except Exception as e:
                    logger.error(f"[Periodic] 컨테이너 {container} 스캔 실패: {e}")

        except Exception as e:
            logger.error(f"[Periodic] 앱 로그 스캔 전체 실패: {e}")

        await asyncio.sleep(600)  # 10분 대기


# ═══════════════════════════════════════════════════════════════════════════════
# 백그라운드 태스크 2 — LLM 분석 결과 품질 모니터링 (헬스체크)
# ═══════════════════════════════════════════════════════════════════════════════

PERIODIC_LLM_HEALTH_PROMPT = """You are an AIOps system health analyst. Review recent LLM analysis results and determine if the AIOps system itself is healthy. Respond in JSON only.

SCHEMA:
{
  "is_healthy": true/false,
  "issues": ["<issue description>", ...],
  "recommendation": "<one sentence>",
  "severity": "<low|medium|high>"
}

DETECTION CRITERIA:
- confidence=0.0 appears 3+ times → LLM parsing failure loop
- threat_level=high/critical appears 2+ times → ongoing attack
- Same container appears 3+ times → unresolved issue
- action_type=NONE dominates → LLM not making decisions
"""

async def periodic_llm_health() -> None:
    """
    5분마다 Loki {job="aiops-llm"} 결과를 조회하여 LLM 자체 상태 모니터링.

    탐지 대상:
    - LLM 파싱 실패 반복 (confidence=0.0 연속)
    - 시스템 위험 신호 (threat_level=high/critical 연속)
    - 특정 컨테이너 반복 이상 (미해결 문제 지속)

    근거: NIST SP 800-137 — 모니터링 시스템 자체도 모니터링 대상
    """
    await asyncio.sleep(120)  # 2분 대기 후 시작

    while True:
        try:
            logger.info("[Periodic] LLM 헬스체크 시작")
            now_ts = time.time()
            window_sec = 300  # 5분

            # Loki에서 최근 5분 LLM 분석 결과 조회
            entries = await _fetch_loki_aiops_results(window_sec)
            if not entries:
                logger.info("[Periodic] LLM 헬스체크: 최근 분석 결과 없음")
                await asyncio.sleep(300)
                continue

            # 1차 필터
            low_confidence = sum(1 for e in entries if e.get("result", {}).get("confidence", 1.0) == 0.0)
            high_threat    = sum(1 for e in entries if e.get("result", {}).get("threat_level") in ("high", "critical"))
            container_counts: dict[str, int] = {}
            for e in entries:
                c = e.get("container", "unknown")
                container_counts[c] = container_counts.get(c, 0) + 1
            repeated_container = [c for c, cnt in container_counts.items() if cnt >= 3]

            has_issue = (
                low_confidence >= 3
                or high_threat >= 2
                or len(repeated_container) > 0
            )

            if not has_issue:
                logger.info("[Periodic] LLM 헬스체크: 정상")
                await asyncio.sleep(300)
                continue

            # 2차: LLM 분석
            summary = json.dumps(entries[:20], ensure_ascii=False)
            prompt = {
                "system": PERIODIC_LLM_HEALTH_PROMPT,
                "user": (
                    f"Recent LLM analysis results (last 5 minutes, {len(entries)} entries):\n\n"
                    f"{summary}\n\n"
                    f"Quick stats:\n"
                    f"- Low confidence (0.0): {low_confidence} cases\n"
                    f"- High/critical threat: {high_threat} cases\n"
                    f"- Repeated containers: {repeated_container}\n\n"
                    f"Analyze and respond with JSON only."
                ),
            }

            raw_result = await _call_llm_raw(prompt)
            if not raw_result:
                await asyncio.sleep(300)
                continue

            is_healthy = raw_result.get("is_healthy", True)
            if is_healthy:
                logger.info("[Periodic] LLM 헬스체크: LLM 정상 판단")
                await asyncio.sleep(300)
                continue

            # 이상 감지 → 중복 캐시 체크
            issue_key = f"llm_health:{raw_result.get('severity', 'unknown')}"
            last_sent = _periodic_alert_cache.get(issue_key, 0)
            if now_ts - last_sent < PERIODIC_CACHE_TTL:
                logger.info(f"[Periodic] LLM 헬스 중복 알림 스킵")
                await asyncio.sleep(300)
                continue

            _periodic_alert_cache[issue_key] = now_ts

            # Slack 버튼 알림 전송
            await send_periodic_slack(
                issue_key=issue_key,
                container="aiops-pipeline",
                issues=raw_result.get("issues", []),
                raw_result={
                    "is_healthy":     False,
                    "action_type":    "NOTIFY",
                    "action_targets": ["aiops-pipeline"],
                    "threat_level":   raw_result.get("severity", "medium"),
                    "action_risk":    "medium",
                    "confidence":     0.8,
                    "recommendation": raw_result.get("recommendation", ""),
                },
                source="llm_health_check",
            )
            logger.warning(f"[Periodic] LLM 헬스 이상 감지 → Slack 전송")

        except Exception as e:
            logger.error(f"[Periodic] LLM 헬스체크 실패: {e}")

        await asyncio.sleep(300)  # 5분 대기


# ═══════════════════════════════════════════════════════════════════════════════
# 주기적 스캔 헬퍼 함수
# ═══════════════════════════════════════════════════════════════════════════════

async def _fetch_loki_logs(container: str, window_sec: int) -> list[dict]:
    """Loki에서 특정 컨테이너의 최근 N초 로그 조회"""
    try:
        end_ns   = int(time.time() * 1_000_000_000)
        start_ns = end_ns - int(window_sec * 1_000_000_000)
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{settings.loki_url}/loki/api/v1/query_range",
                params={
                    "query":     f'{{container="{container}"}}',
                    "start":     start_ns,
                    "end":       end_ns,
                    "limit":     200,
                    "direction": "forward",
                },
            )
            data = resp.json()
            results = []
            for stream in data.get("data", {}).get("result", []):
                labels = stream.get("stream", {})
                for ts_ns, line in stream.get("values", []):
                    results.append({"ts": ts_ns, "line": line, "labels": labels})
            return results
    except Exception as e:
        logger.warning(f"[Periodic] Loki 로그 조회 실패 ({container}): {e}")
        return []


async def _fetch_loki_aiops_results(window_sec: int) -> list[dict]:
    """Loki {job='aiops-llm'}에서 최근 N초 LLM 분석 결과 조회"""
    try:
        end_ns   = int(time.time() * 1_000_000_000)
        start_ns = end_ns - int(window_sec * 1_000_000_000)
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{settings.loki_url}/loki/api/v1/query_range",
                params={
                    "query":     '{job="aiops-llm"}',
                    "start":     start_ns,
                    "end":       end_ns,
                    "limit":     50,
                    "direction": "forward",
                },
            )
            data = resp.json()
            entries = []
            for stream in data.get("data", {}).get("result", []):
                for ts_ns, line in stream.get("values", []):
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        pass
            return entries
    except Exception as e:
        logger.warning(f"[Periodic] Loki aiops-llm 조회 실패: {e}")
        return []


async def _call_llm_raw(prompt: dict) -> dict | None:
    """주기적 스캔 전용 LLM 호출 — 결과를 dict로 반환"""
    try:
        async with httpx.AsyncClient(timeout=settings.llm_timeout) as client:
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
            raw = response.json()["message"]["content"]
            return json.loads(raw)
    except Exception as e:
        logger.error(f"[Periodic] LLM 호출 실패: {e}")
        return None


async def send_periodic_slack(
    issue_key: str,
    container: str,
    issues: list[str],
    raw_result: dict,
    source: str,
) -> None:
    """
    주기적 스캔 이상 감지 시 Slack Block Kit 버튼 알림 전송.
    source 필드를 버튼 value에 포함 → remediation이 출처 구분 가능.
    """
    if not settings.slack_webhook_url:
        logger.debug("[Periodic] SLACK_WEBHOOK_URL 미설정, 스킵")
        return

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    threat_level  = raw_result.get("threat_level", "unknown")
    action_type   = raw_result.get("action_type", "NOTIFY")
    action_targets = raw_result.get("action_targets", [container])
    confidence    = raw_result.get("confidence", 0.0)
    recommendation = raw_result.get("recommendation", "-")

    # 버튼 value — source 포함하여 remediation이 출처 구분
    action_payload = json.dumps({
        "alertname":      issue_key,
        "action_type":    action_type,
        "action_targets": action_targets,
        "source":         source,  # "periodic_log_scan" | "llm_health_check"
    }, ensure_ascii=False)

    source_label = {
        "periodic_log_scan": "🔍 정기 로그 스캔",
        "llm_health_check":  "🤖 LLM 헬스체크",
    }.get(source, source)

    issue_text = "\n".join(f"• {i}" for i in issues) if issues else "N/A"

    payload = {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f":rotating_light: *[APPROVAL REQUIRED]* `{container}` — {source_label}",
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*발생 시각*\n{timestamp}"},
                    {"type": "mrkdwn", "text": f"*Threat Level*\n{threat_level}"},
                    {"type": "mrkdwn", "text": f"*Confidence*\n{confidence:.2f}"},
                    {"type": "mrkdwn", "text": f"*Container*\n{container}"},
                    {"type": "mrkdwn", "text": f"*권고 조치*\n{recommendation}"},
                    {"type": "mrkdwn", "text": f"*Issues*\n{issue_text}"},
                ],
            },
            {"type": "divider"},
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ Approve", "emoji": True},
                        "style": "primary",
                        "action_id": "approve_action",
                        "value": action_payload,
                        "confirm": {
                            "title": {"type": "plain_text", "text": "조치를 승인하시겠습니까?"},
                            "text": {
                                "type": "mrkdwn",
                                "text": (
                                    f"*{action_type}* 조치를 실행합니다.\n"
                                    f"대상: `{'`, `'.join(action_targets) if action_targets else 'N/A'}`\n"
                                    f"출처: {source_label}"
                                ),
                            },
                            "confirm": {"type": "plain_text", "text": "승인"},
                            "deny":    {"type": "plain_text", "text": "취소"},
                        },
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "❌ Reject", "emoji": True},
                        "style": "danger",
                        "action_id": "reject_action",
                        "value": action_payload,
                    },
                ],
            },
        ]
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                settings.slack_webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                logger.info(f"[Periodic] Slack 전송 완료: {issue_key}")
            else:
                logger.error(f"[Periodic] Slack 전송 실패: {resp.status_code} {resp.text}")
    except Exception as e:
        logger.error(f"[Periodic] Slack 전송 예외: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# 기존 헬퍼 함수 (변경 없음)
# ═══════════════════════════════════════════════════════════════════════════════

async def push_to_loki(entry: dict) -> None:
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
        await push_timeline_event("llm_analysis_completed", {
            "alert": entry.get("alert_name", "unknown"),
            "container": entry.get("container", "unknown"),
            "threat_level": result.get("threat_level", "unknown"),
            "confidence": result.get("confidence", 0.0),
            "recommended_action": result.get("action_type", "NONE"),
            "status": "COMPLETED",
        })
    except Exception as e:
        logger.warning(f"[Pipeline] Loki 푸시 실패 (무시): {e}")


async def push_timeline_event(event: str, fields: dict) -> None:
    ts_ns = str(int(time.time() * 1_000_000_000))
    body = {
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "event": event,
        **fields,
    }
    labels = {
        "job": "aiops-timeline",
        "event": event,
        "status": str(fields.get("status", "INFO")),
    }
    if fields.get("alert"):
        labels["alert"] = str(fields["alert"])
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(
                f"{settings.loki_url}/loki/api/v1/push",
                json={"streams": [{"stream": labels, "values": [[ts_ns, json.dumps(body, ensure_ascii=False)]]}]},
                headers={"Content-Type": "application/json"},
            )
    except Exception as e:
        logger.warning(f"[Pipeline] timeline Loki push failed: {e}")


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
        except ValidationError as e:
            logger.error(f"[Pipeline] LLM 응답 스키마 불일치 (시도 {attempt + 1}/2): {e}")

        if attempt == 0:
            await asyncio.sleep(5)

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
        action_targets=[],
        action_description="manual investigation required",
        threat_level="medium",
        action_risk="high",
        evidence=[],
        confidence=0.0,
    )


async def forward_to_remediation(alert: Alert, result: LLMAnalysisResult):
    """Remediation Agent에 분석 결과 전달 → 여기서 Slack 전송 결정됨"""
    async with httpx.AsyncClient(timeout=30) as client:
        await client.post(
            f"{settings.remediation_url}/action",
            json={
                "alert": alert.model_dump(),
                "analysis": result.model_dump(),
            },
        )