"""
Loki에서 Application Log 수집.

canonical service 기준으로 조회한다 ({service="backend"}).
legacy {container="..."} 조회는 쓰지 않는다 — correlation.py 참고.
"""

import httpx

from correlation import CorrelationContext, service_log_selector


class LogsCollector:
    def __init__(self, loki_url: str, transport: httpx.AsyncBaseTransport | None = None):
        self.url = loki_url
        self._transport = transport

    async def fetch(self, ctx: CorrelationContext, limit: int = 200,
                    direction: str = "forward") -> list[dict]:
        """
        ctx.service의 [ctx.start, ctx.end] 구간 로그 수집. 반환은 항상 시각 오름차순.
        direction=backward 면 limit 에 걸려도 최신 줄이 남는다 (v2 경보 분석).
        """

        # service를 모르면 조회하지 않는다 (잘못된 identity로 엉뚱한 로그를 가져오지 않기 위해)
        if not ctx.service:
            return []

        async with httpx.AsyncClient(timeout=30, transport=self._transport) as client:
            resp = await client.get(
                f"{self.url}/loki/api/v1/query_range",
                params={
                    "query": service_log_selector(ctx.service),
                    "start": ctx.start_ns,
                    "end":   ctx.end_ns,
                    "limit": limit,
                    "direction": direction,
                },
            )
            data = resp.json()

        return self._parse_streams(data)

    def _parse_streams(self, data: dict) -> list[dict]:
        """Loki streams 응답을 [{"ts": ..., "line": ...}] 형태로 변환"""
        logs = []
        for stream in data.get("data", {}).get("result", []):
            labels = stream.get("stream", {})
            for ts_ns, line in stream.get("values", []):
                logs.append({
                    "ts":     int(ts_ns) / 1e9,
                    "labels": labels,
                    "line":   line,
                })
        logs.sort(key=lambda x: x["ts"])
        return logs
