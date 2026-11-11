"""Prometheus evidence from explicit site/job/instance bindings. No local Docker fallback."""
import math
from datetime import datetime
import httpx
from correlation import CorrelationContext
from identity import MetricEvidence, matches, selector


class MetricsCollector:
    def __init__(self, prometheus_url: str, transport: httpx.AsyncBaseTransport | None = None):
        self.url = prometheus_url
        self._transport = transport

    async def fetch_around(self, container: str | None, alert_time: datetime,
                           window_minutes: int = 5, container_id: str | None = None,
                           ctx: CorrelationContext | None = None) -> dict:
        # Legacy signature is accepted but names/ids alone cannot establish the observation site.
        scope = ctx.binding.metrics if ctx and ctx.binding else {}
        report = {"backend": "prometheus", "identity": ctx.identity.to_dict() if ctx and ctx.identity else {},
                  "selector": scope, "queries": {}}
        if not ctx or not ctx.identity or not ctx.identity.complete or not scope:
            return MetricEvidence(status="scope_unavailable",
                                  reason="source_unknown" if not ctx or not ctx.binding else "collector_unmapped", **report)
        runtime = ctx.identity.runtime
        profile = ctx.binding.metrics_profile
        report["metrics_profile"] = profile
        report["unsupported_metrics"] = []
        s = selector(scope)
        query_scopes = {}
        if runtime == "container":
            cpu = selector({**scope, "cpu": "total"})
            queries = {
                "cpu_usage": f'rate(container_cpu_usage_seconds_total{cpu}[1m])',
                "memory_usage": f'container_memory_usage_bytes{s}',
                "memory_limit": f'container_spec_memory_limit_bytes{s}',
                "net_rx_bytes": f'rate(container_network_receive_bytes_total{s}[1m])',
                "net_tx_bytes": f'rate(container_network_transmit_bytes_total{s}[1m])',
            }
            if profile == "gc-telemetry-v1":
                # This producer exports working set and RX only. Missing TX is
                # unsupported, never a zero or a query against a different PC.
                del queries["memory_usage"]
                del queries["net_tx_bytes"]
                queries["memory_working_set"] = f'container_memory_working_set_bytes{s}'
                stable_scope = {k: v for k, v in scope.items() if k != "id"}
                stable = selector(stable_scope)
                for name, metric in (("restart_count", "aiops_docker_container_restarts_total"),
                                     ("started_at_seconds", "aiops_docker_container_started_at_seconds")):
                    queries[name] = metric + stable
                    query_scopes[name] = stable_scope
                report["unsupported_metrics"] = ["memory_usage", "net_tx_bytes"]
        else:
            # Host OS context, never container evidence or proof of PostgreSQL process usage.
            cpu = s[:-1] + ',mode!="idle"}'
            queries = {
                "host_cpu": f'avg by (job,instance) (rate(node_cpu_seconds_total{cpu}[1m]))',
                "host_mem": f'node_memory_MemAvailable_bytes{s} / node_memory_MemTotal_bytes{s}',
            }
        results, states = {}, {}
        async with httpx.AsyncClient(timeout=30, transport=self._transport) as client:
            for name, query in queries.items():
                report["queries"][name] = {"query": query, "scope": runtime}
                try:
                    resp = await client.get(f"{self.url}/api/v1/query_range", params={
                        "query": query, "start": ctx.start.timestamp(), "end": ctx.end.timestamp(), "step": "15s"})
                    resp.raise_for_status()
                    data = resp.json()
                    if data.get("status") != "success":
                        states[name] = "api_error"
                        continue
                    if data["data"]["resultType"] != "matrix":
                        raise ValueError("invalid metric response")
                    expected = query_scopes.get(name, {k: scope[k] for k in ("job", "instance")} if name == "host_cpu" else scope)
                    if not all(matches(row["metric"], expected) for row in data["data"]["result"]):
                        states[name] = "source_mismatch"
                        continue
                    results[name] = self._parse_range(data)
                    states[name] = "partial" if data.get("warnings") or data.get("infos") else "ok" if results[name] else "empty"
                except httpx.HTTPError:
                    states[name] = "api_error"
                except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
                    states[name] = "invalid_response"
        good = [v for v in states.values() if v in ("ok", "empty")]
        status = "ok" if len(good) == len(states) and any(results.values()) else "empty" if len(good) == len(states) else "partial" if good else next(iter(states.values()))
        return MetricEvidence(results, status=status, query_status=states,
                              series_labels={k: [s["labels"] for s in rows] for k, rows in results.items()}, **report)

    def _parse_range(self, data: dict) -> list[dict]:
        out = []
        for row in data["data"]["result"]:
            values = [{"t": float(t), "v": float(v)} for t, v in row["values"]]
            if any(not math.isfinite(p["v"]) for p in values):
                raise ValueError("nonfinite metric")
            out.append({"labels": row["metric"], "values": values})
        return out
