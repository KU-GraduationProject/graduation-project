"""
Prometheus에서 이상 시점 전후 N분 메트릭 수집.
macOS Docker Desktop에서 cAdvisor는 container_label_* 를 내보내지 않으므로
Docker SDK로 컨테이너 ID를 조회해 id 레이블 필터로 전환한다.
"""

import subprocess
import httpx
from datetime import datetime, timedelta


def _get_container_id(container_name: str) -> str | None:
    """docker inspect 로 컨테이너 전체 ID 조회"""
    try:
        result = subprocess.check_output(
            ["docker", "inspect", container_name, "--format", "{{.Id}}"],
            timeout=3, text=True, stderr=subprocess.DEVNULL,
        )
        return result.strip()
    except Exception:
        return None


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

        # cAdvisor는 id=/docker/<full_id> 형태만 지원 → 컨테이너 ID로 필터
        if container:
            cid = _get_container_id(container)
            if cid:
                label = f'{{id="/docker/{cid}",cpu="total"}}'
                net_label = f'{{id="/docker/{cid}"}}'
            else:
                # ID 조회 실패 시 전체 개별 컨테이너 대상
                label = '{id=~"/docker/.+",cpu="total"}'
                net_label = '{id=~"/docker/.+"}'
        else:
            label = '{id=~"/docker/.+",cpu="total"}'
            net_label = '{id=~"/docker/.+"}'

        mem_label = label.replace(',cpu="total"', '')
        queries = {
            "cpu_usage":    f'rate(container_cpu_usage_seconds_total{label}[1m])',
            "memory_usage": f'container_memory_usage_bytes{mem_label}',
            "memory_limit": f'container_spec_memory_limit_bytes{mem_label}',
            "net_rx_bytes": f'rate(container_network_receive_bytes_total{net_label}[1m])',
            "net_tx_bytes": f'rate(container_network_transmit_bytes_total{net_label}[1m])',
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
