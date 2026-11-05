"""pipeline 이 경보 분석 때 LLM 에 보낸 프롬프트를 같은 코드로 다시 만든다 (pipeline 은 프롬프트를 저장하지 않는다).

pipeline 컨테이너 안에서 실행한다 (코드 경로 /app, 조회만 한다):
    docker exec -i aiops-pipeline python - < recon_prompt.py  (stdin 앞부분이 아니라 환경변수로 입력)
    입력: 환경변수 RECON_INPUT = {"alert": <Alertmanager 경보 dict>, "analysis_time": "<ISO, 분석 시작 로그 시각>"}

main.analyze_alerts 의 1~2단계(메트릭·로그·네트워크 수집 → prompt_builder.build)를 그대로 따른다.
차이: 로그 조회 끝 시각을 analysis_time 으로 자른다(원래 호출 시점에는 그 뒤 로그가 아직 없었다).
로그 조회는 direction=forward, limit=200 이라 구간 앞쪽부터 채워지므로 끝 시각을 잘라도 대개 결과가 같다.
"""
import asyncio
import json
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, "/app")
import main  # noqa: E402  (FastAPI 앱 객체만 만들고 lifespan 은 돌지 않는다)
from correlation import CorrelationContext, resolve_service  # noqa: E402


async def run(inp):
    alert = main.Alert(**inp["alert"])
    container_name = alert.annotations.get("container") or alert.labels.container
    alert_time = datetime.fromisoformat(alert.startsAt.replace("Z", "+00:00"))
    analysis_time = datetime.fromisoformat(inp["analysis_time"].replace("Z", "+00:00"))
    metrics = await main.metrics_collector.fetch_around(container=container_name, alert_time=alert_time, window_minutes=5)
    service, runtime = await resolve_service(container_name, target_map=main._target_map)
    ctx = CorrelationContext.around(service, alert_time, timedelta(minutes=5), container_name=container_name, runtime=runtime)
    ctx_clip = CorrelationContext(service=ctx.service, start=ctx.start, end=min(ctx.end, analysis_time), anchor=ctx.anchor,
                                  container_name=container_name, runtime=runtime)
    logs = await main.logs_collector.fetch(ctx_clip)
    network = await main.network_collector.fetch(ctx_clip)
    prompt = main.prompt_builder.build(alert=alert, metrics=metrics, logs=logs, container_name=container_name, network=network)
    return {
        "container_name": container_name, "service": service,
        "log_window": [ctx_clip.start.isoformat(), ctx_clip.end.isoformat()],
        "logs_fetched": len(logs),
        "logs_first_ts": logs[0]["ts"] if logs else None, "logs_last_ts": logs[-1]["ts"] if logs else None,
        "network_events": len(network.events),
        "prompt": prompt,
    }


print(json.dumps(asyncio.run(run(json.loads(os.environ["RECON_INPUT"]))), ensure_ascii=False, default=str))
