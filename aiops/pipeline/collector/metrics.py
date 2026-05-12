"""
Prometheus에서 이상 시점 전후 N분 메트릭 수집.
macOS Docker Desktop에서 cAdvisor는 container_label_* 를 내보내지 않으므로
Docker SDK로 컨테이너 ID를 조회해 id 레이블 필터로 전환한다.
"""

# ❌ 삭제: import subprocess
import httpx
import logging
from datetime import datetime, timedelta
logger = logging.getLogger(__name__)


async def _get_container_id(container_name: str) -> str | None:
    """Docker Unix socket으로 컨테이너 ID 조회"""
    try:
        async with httpx.AsyncClient(
            transport=httpx.AsyncHTTPTransport(uds="/var/run/docker.sock"),
            base_url="http://docker",  # UDS 사용 시 hostname은 무시됨
            timeout=3,
        ) as client:
            resp = await client.get(f"/containers/{container_name}/json")
            if resp.status_code == 200:
                return resp.json().get("Id")
    except Exception as e:
        logger.debug(f"[_get_container_id] 실패: {e}")
        return None
    return None


class MetricsCollector:
    def __init__(self, prometheus_url: str):
        self.url = prometheus_url

    async def fetch_around(
        self,
        container: str | None,
        alert_time: datetime,
        window_minutes: int = 5,
        container_id: str | None = None,   # ← 추가
    ) -> dict:
        """이상 시점 ±window_minutes 범위의 주요 메트릭 수집"""
        start = alert_time - timedelta(minutes=window_minutes)
        end   = alert_time + timedelta(minutes=window_minutes)

        # ← 여기 추가
        label = None
        net_label = None
        # cAdvisor는 id=/docker/<full_id> 형태만 지원 → 컨테이너 ID로 필터
        if container_id:
            cid = container_id             # ← ID 직접 사용
        elif container:
            cid = await _get_container_id(container)  # ← fallback
        else:
            cid = None
        if cid:
            label = f'{{id="/docker/{cid}",cpu="total"}}'
            net_label = f'{{id="/docker/{cid}"}}'
        else:
            # ID 조회 실패 시 호스트 메트릭만 수집
            logger.warning(f"[MetricsCollector] 컨테이너 ID 조회 실패: {container}")
            label = None
            net_label = None

        if label:
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
        else:
            # 컨테이너 특정 불가 → 호스트 메트릭만 수집
            queries = {
                "host_cpu": 'avg(rate(node_cpu_seconds_total{mode!="idle"}[1m]))',
                "host_mem": 'node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes',
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