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

from identity import matches
from dataclasses import dataclass, field
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
    provenance: dict = field(default_factory=dict)

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
        scope = ctx.binding.network if ctx.binding else {}
        provenance = {"backend": "loki-network", "identity": ctx.identity.to_dict() if ctx.identity else {},
                      "observer": scope}
        if not ctx.service or not ctx.identity or not ctx.identity.complete or not scope:
            return NetworkContext(service=ctx.service, start=ctx.start, end=ctx.end,
                                  errors=("scope_unavailable",),
                                  provenance={**provenance, "status": "scope_unavailable"})

        try:
            base = network_event_selectors(ctx.service)
            selectors = tuple(sel + " | json | " + " and ".join(
                f"{k}={json.dumps(v)}" for k, v in scope.items()) for sel in base)
            provenance["queries"] = selectors
            async with httpx.AsyncClient(timeout=10, transport=self._transport) as client:
                results = await asyncio.gather(
                    *(self._query(client, sel, ctx, limit) for sel in selectors),
                    return_exceptions=True,
                )
        except Exception as e:  # selector 검증 실패 등 — RCA를 막지 않는다
            return NetworkContext(service=ctx.service, start=ctx.start, end=ctx.end,
                                  errors=("api_error",), provenance={**provenance, "status": "api_error"})

        lines, errors, truncated = [], [], False
        for sel, res in zip(selectors, results):
            if isinstance(res, BaseException):
                errors.append("api_error")
                continue
            lines.extend(res)
            truncated = truncated or len(res) >= limit

        events, skipped = self._parse(lines, ctx)
        return NetworkContext(
            service=ctx.service, start=ctx.start, end=ctx.end,
            events=tuple(events), errors=tuple(errors),
            skipped=skipped, truncated=truncated,
            provenance={**provenance, "status": "partial" if errors or truncated or skipped else "ok" if events else "empty",
                        "accepted_events": len(events), "skipped": skipped, "truncated": truncated},
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
        data = resp.json()
        if data.get("status") != "success" or data["data"]["resultType"] != "streams":
            raise ValueError("invalid network response")
        streams = data["data"]["result"]
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

            if ctx.identity:
                scope = ctx.binding.network if ctx.binding else {}
                if not scope or not matches(event, scope):
                    skipped += 1
                    continue
                sides = [side for side in ("src", "dst") if event.get(side + "_service") == ctx.service]
                if not any(event.get(side + "_runtime") == ctx.identity.runtime
                           and (event.get(side + "_target") or (event.get(side + "_container") if ctx.identity.runtime == "container" else None)) == ctx.identity.target for side in sides):
                    skipped += 1
                    continue

            key = (event.get("observer"), event.get("observer_instance"), self._dedup_key(event))
            if key in seen:  # src==dst==service인 event는 두 query 모두에 나온다
                continue
            seen.add(key)
            events.append((instant, event))

        events.sort(key=lambda pair: pair[0])
        return [event for _, event in events], skipped

    @staticmethod
    def _dedup_key(event: dict):
        """
        같은 이벤트 중복(두 selector 모두에 걸린 src==dst==service 등)만 제거한다.

        event_type 을 키에 포함해, 같은 connection_id 라도 최종(connection)과 조기
        (connection_threshold) 이벤트는 서로 다른 이벤트로 보존한다. (P6: 둘은 의미가
        다르므로 dedup 으로 지우면 안 된다. 바이트 중복 집계 방지는 소비자 쪽에서 한다.)
        """
        event_type = event.get("event_type") or "connection"
        if event.get("connection_id"):
            return ("id", event_type, event["connection_id"])
        return ("tuple", event_type, event.get("timestamp"), event.get("protocol"),
                event.get("src_ip"), event.get("src_port"),
                event.get("dst_ip"), event.get("dst_port"))
