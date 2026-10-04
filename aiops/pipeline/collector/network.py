"""
Loki에서 Network Event 조회 (#10).

CorrelationContext의 service + time window로, 그 service가 src 또는 dst인
Canonical Network Event v1.0을 가져와 NetworkContext로 반환한다.

Network Context는 supplementary / best-effort다.
  - events가 비어 있어도 "network 문제가 없다"는 뜻이 아니다.
    (Zeek은 connection 종료 시점에 기록하므로 long-lived connection은 창에서 빠질 수 있고,
     observer stale-netns 같은 known limitation도 있다)
  - 조회 실패는 errors에 남기고 예외를 던지지 않는다. Application Log RCA를 막지 않기 위해서다.

event는 NETWORK_EVENT_SCHEMA.md의 canonical dict를 그대로 둔다 (재정의하지 않는다).
"""

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime

import httpx

from correlation import CorrelationContext, network_event_selectors, to_instant

# 이 consumer가 이해하는 schema MAJOR. MINOR 변경은 non-breaking이므로 허용한다. (§14)
SUPPORTED_SCHEMA_MAJOR = "1"


@dataclass(frozen=True)
class NetworkContext:
    """
    service    : 조회 기준 canonical service
    start/end  : 조회 구간 (UTC instant)
    events     : canonical event dict, timestamp 오름차순, 중복 제거됨
    errors     : 조회가 불완전했던 이유 (비어 있지 않으면 events는 일부만일 수 있다)
    skipped    : 파싱/검증에 실패해 버린 event 수
    truncated  : Loki limit에 걸려 일부가 잘렸을 수 있음
    """

    service: str | None
    start: datetime
    end: datetime
    events: tuple[dict, ...] = ()
    errors: tuple[str, ...] = ()
    skipped: int = 0
    truncated: bool = False

    @property
    def query_complete(self) -> bool:
        """
        Loki 조회가 오류/잘림 없이 끝났는지만 뜻한다.
        True + events 0건이어도 "traffic이 없었다"는 뜻이 아니다.
        (예: backend가 db와 long-lived connection을 유지 중이어도 db context는 0건일 수 있다)
        """
        return not self.errors and not self.truncated


class NetworkCollector:
    def __init__(self, loki_url: str, transport: httpx.AsyncBaseTransport | None = None):
        self.url = loki_url
        self._transport = transport

    async def fetch(self, ctx: CorrelationContext, limit: int = 500) -> NetworkContext:
        """ctx.service가 src 또는 dst인 Network Event를 [ctx.start, ctx.end]에서 조회. 예외를 던지지 않는다."""
        empty = NetworkContext(service=ctx.service, start=ctx.start, end=ctx.end)
        if not ctx.service:
            return empty

        try:
            selectors = network_event_selectors(ctx.service)
            async with httpx.AsyncClient(timeout=10, transport=self._transport) as client:
                results = await asyncio.gather(
                    *(self._query(client, sel, ctx, limit) for sel in selectors),
                    return_exceptions=True,
                )
        except Exception as e:  # selector 검증 실패 등 — RCA를 막지 않는다
            return NetworkContext(service=ctx.service, start=ctx.start, end=ctx.end,
                                  errors=(f"network context unavailable: {e!r}",))

        lines, errors, truncated = [], [], False
        for sel, res in zip(selectors, results):
            if isinstance(res, BaseException):
                errors.append(f"{sel}: {res!r}")
                continue
            lines.extend(res)
            truncated = truncated or len(res) >= limit

        events, skipped = self._parse(lines, ctx)
        return NetworkContext(
            service=ctx.service, start=ctx.start, end=ctx.end,
            events=tuple(events), errors=tuple(errors),
            skipped=skipped, truncated=truncated,
        )

    async def _query(self, client, selector: str, ctx: CorrelationContext, limit: int) -> list[str]:
        resp = await client.get(
            f"{self.url}/loki/api/v1/query_range",
            params={
                "query": selector,
                "start": ctx.start_ns,
                "end":   ctx.end_ns,
                "limit": limit,
                "direction": "forward",
            },
        )
        resp.raise_for_status()
        streams = resp.json()["data"]["result"]
        return [line for stream in streams for _, line in stream.get("values", [])]

    def _parse(self, lines: list[str], ctx: CorrelationContext) -> tuple[list[dict], int]:
        seen, events, skipped = set(), [], 0
        for line in lines:
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("not an object")
                if str(event.get("schema_version", "")).split(".")[0] != SUPPORTED_SCHEMA_MAJOR:
                    raise ValueError(f"unsupported schema_version {event.get('schema_version')!r}")
                instant = to_instant(event["timestamp"])
                src, dst = event["src_service"], event["dst_service"]
            except (ValueError, TypeError, KeyError):
                skipped += 1
                continue

            # Loki가 label/시간으로 이미 걸렀지만, 결과를 그대로 믿지 않고 한 번 더 확인한다.
            if ctx.service not in (src, dst) or not ctx.contains(instant):
                continue

            key = self._dedup_key(event)
            if key in seen:  # src==dst==service인 event는 두 query 모두에 나온다
                continue
            seen.add(key)
            events.append((instant, event))

        events.sort(key=lambda pair: pair[0])
        return [event for _, event in events], skipped

    @staticmethod
    def _dedup_key(event: dict):
        """connection_id 우선. 없으면 연결 시작 시각 + observed 5-tuple (같은 순간의 같은 연결)."""
        if event.get("connection_id"):
            return ("id", event["connection_id"])
        return ("tuple", event.get("timestamp"), event.get("protocol"),
                event.get("src_ip"), event.get("src_port"),
                event.get("dst_ip"), event.get("dst_port"))
