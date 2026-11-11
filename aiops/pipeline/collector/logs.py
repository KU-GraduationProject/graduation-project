"""Application logs restricted to a verified observation binding; never widen selectors."""
import httpx
from correlation import CorrelationContext
from identity import LogEvidence, matches, selector


class LogsCollector:
    def __init__(self, loki_url: str, transport: httpx.AsyncBaseTransport | None = None):
        self.url = loki_url
        self._transport = transport

    async def fetch(self, ctx: CorrelationContext, limit: int = 200) -> list[dict]:
        scope = ctx.binding.logs if ctx.binding else {}
        report = {"backend": "loki", "identity": ctx.identity.to_dict() if ctx.identity else {},
                  "selector": scope, "limit": limit}
        if not ctx.identity or not ctx.identity.complete or not scope:
            return LogEvidence(status="scope_unavailable",
                               reason="source_unknown" if not ctx.binding else "collector_unmapped", **report)
        try:
            async with httpx.AsyncClient(timeout=30, transport=self._transport) as client:
                # Exact match series proves the required labels exist for this source and time window.
                resp = await client.get(f"{self.url}/loki/api/v1/series", params={
                    "match[]": selector(scope), "start": ctx.start_ns, "end": ctx.end_ns})
                resp.raise_for_status()
                data = resp.json()
                if data.get("status") != "success" or not isinstance(data.get("data"), list):
                    raise ValueError("invalid series response")
                if not data["data"]:
                    return LogEvidence(status="scope_unavailable", reason="no_matching_series", **report)
                if not all(matches(labels, scope) for labels in data["data"]):
                    return LogEvidence(status="source_mismatch", **report)
                resp = await client.get(f"{self.url}/loki/api/v1/query_range", params={
                    "query": selector(scope), "start": ctx.start_ns, "end": ctx.end_ns,
                    "limit": limit, "direction": "forward"})
                resp.raise_for_status()
                data = resp.json()
                if data.get("status") != "success" or data["data"]["resultType"] != "streams":
                    raise ValueError("invalid logs response")
                if not all(matches(s["stream"], scope) for s in data["data"]["result"]):
                    return LogEvidence(status="source_mismatch", **report)
                report["stream_labels"] = [s["stream"] for s in data["data"]["result"]]
                logs = self._parse_streams(data)
                logs = [row for row in logs if ctx.start.timestamp() <= row["ts"] <= ctx.end.timestamp()]
                return LogEvidence(logs, status="truncated" if len(logs) >= limit else "ok" if logs else "empty", **report)
        except httpx.HTTPError:
            return LogEvidence(status="api_error", **report)
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
            return LogEvidence(status="invalid_response", **report)

    def _parse_streams(self, data: dict) -> list[dict]:
        logs = [{"ts": int(ts) / 1e9, "labels": stream["stream"], "line": line}
                for stream in data["data"]["result"] for ts, line in stream["values"]]
        return sorted(logs, key=lambda x: x["ts"])
