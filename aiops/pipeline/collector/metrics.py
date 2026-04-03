"""
Prometheus에서 이상 시점 전후 N분 메트릭 수집.
cAdvisor로 컨테이너별 수치를 특정해 LLM 원인 추론 정확도를 높인다.
"""

import httpx
from datetime import datetime, timedelta


class MetricsCollector:
    def __init__(self, prometheus_url: str):
        self.url = prometheus_url

    async def fetch_around(
        self,
        container: str | None,
        alert_time: datetime,
        window_minutes: int = 5,
    ) -> dict:
        """이상 시점 ±window_minutes 범위의 주요 메트릭 수집"""
        start = alert_time - timedelta(minutes=window_minutes)
        end   = alert_time + timedelta(minutes=window_minutes)

        # 컨테이너 필터 (cAdvisor)
        label = f'{{container_label_com_docker_compose_service="{container}"}}' if container else ""

        queries = {
            "cpu_usage":    f'rate(container_cpu_usage_seconds_total{label}[1m])',
            "memory_usage": f'container_memory_usage_bytes{label}',
            "memory_limit": f'container_spec_memory_limit_bytes{label}',
            "net_rx_bytes": f'rate(container_network_receive_bytes_total{label}[1m])',
            "net_tx_bytes": f'rate(container_network_transmit_bytes_total{label}[1m])',
            "host_cpu":     'avg(rate(node_cpu_seconds_total{mode!="idle"}[1m]))',
            "host_mem":     'node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes',
        }

        results = {}
        async with httpx.AsyncClient(timeout=30) as client:
            for name, query in queries.items():
                resp = await client.get(
                    f"{self.url}/api/v1/query_range",
                    params={
                        "query": query,
                        "start": start.timestamp(),
                        "end":   end.timestamp(),
                        "step":  "15s",
                    },
                )
                data = resp.json()
                results[name] = self._parse_range(data)

        return results

    def _parse_range(self, data: dict) -> list[dict]:
        """Prometheus range query 응답을 [{"t": timestamp, "v": value}] 형태로 변환"""
        out = []
        for result in data.get("data", {}).get("result", []):
            metric_labels = result.get("metric", {})
            values = [
                {"t": float(ts), "v": float(val)}
                for ts, val in result.get("values", [])
            ]
            out.append({"labels": metric_labels, "values": values})
        return out
