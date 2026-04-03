"""
Loki에서 이상 시점 전후 N분 로그 수집.
컨테이너 태그 필터 적용.
"""

import httpx
from datetime import datetime, timedelta


class LogsCollector:
    def __init__(self, loki_url: str):
        self.url = loki_url

    async def fetch_around(
        self,
        container: str | None,
        alert_time: datetime,
        window_minutes: int = 5,
        limit: int = 200,
    ) -> list[dict]:
        """이상 시점 ±window 범위 로그 수집"""
        start_ns = int((alert_time - timedelta(minutes=window_minutes)).timestamp() * 1e9)
        end_ns   = int((alert_time + timedelta(minutes=window_minutes)).timestamp() * 1e9)

        label_filter = f'{{container="{container}"}}' if container else '{}'

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.url}/loki/api/v1/query_range",
                params={
                    "query": label_filter,
                    "start": start_ns,
                    "end":   end_ns,
                    "limit": limit,
                    "direction": "forward",
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
