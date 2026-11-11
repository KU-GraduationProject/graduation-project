"""
경보를 일으킨 룰의 식·시간 창·임계값과 경보 시점(startsAt) 값 조회.

Prometheus 는 /api/v1/rules, Loki ruler 는 같은 형식의 /prometheus/api/v1/rules 로 룰을 준다.
룰 식을 "좌변 비교연산자 임계값" 으로 나눈 뒤 좌변을 startsAt 시각에 instant 쿼리한다.

조회는 best-effort 다. 실패하면 예외를 던지지 않고 error 에 사유를 남긴다 —
프롬프트는 이를 "값 조회 실패" 로 밝힌다 (빈 값을 정상처럼 보이게 하지 않는다).
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, asdict
from datetime import datetime

import httpx

_DURATION = re.compile(r"(\d+(?:\.\d+)?)(ms|s|m|h|d|w|y)")
_UNIT_SECONDS = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800, "y": 31536000}
_RANGE = re.compile(r"\[\s*((?:\d+(?:\.\d+)?(?:ms|s|m|h|d|w|y))+)\s*(?::[^\]]*)?\]")
_COMPARE = re.compile(r"(>=|<=|==|!=|>|<)\s*(?:bool\s+)?(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)")


@dataclass(frozen=True)
class RuleContext:
    name: str
    source: str | None = None          # prometheus | loki
    expr: str | None = None
    for_seconds: float | None = None
    range_seconds: float | None = None
    op: str | None = None
    threshold: float | None = None
    value: float | None = None         # 좌변의 startsAt 시점 값
    error: str | None = None           # 룰·값 조회 실패 사유

    @property
    def window_seconds(self) -> float | None:
        """룰이 보는 시간 창 = 범위 선택자 + for. 둘 다 모르면 None."""
        if self.range_seconds is None and self.for_seconds is None:
            return None
        return (self.range_seconds or 0) + (self.for_seconds or 0)

    def as_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "RuleContext":
        return cls(**{k: d[k] for k in cls.__dataclass_fields__ if k in d})


def parse_duration(text: str) -> float | None:
    """'1m30s' -> 90.0. 형식이 아니면 None."""
    parts = _DURATION.findall(text or "")
    if not parts or "".join(n + u for n, u in parts) != text:
        return None
    return sum(float(n) * _UNIT_SECONDS[u] for n, u in parts)


def max_range_seconds(expr: str) -> float | None:
    """식 안의 범위 선택자([5m], [30s]) 중 가장 긴 것."""
    values = [parse_duration(m) for m in _RANGE.findall(expr or "")]
    values = [v for v in values if v is not None]
    return max(values) if values else None


def split_threshold(expr: str) -> tuple[str, str, float] | None:
    """
    최상위(괄호·중괄호·대괄호·문자열 밖) 첫 비교식을 찾아 (좌변, 연산자, 임계값).
    'sum(...) > 0.5 and on(name) x' 처럼 뒤에 집합 연산이 붙어도 첫 비교만 본다.
    """
    depth, quote, i = 0, None, 0
    while i < len(expr):
        ch = expr[i]
        if quote:
            if ch == "\\" and quote != "`":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif depth == 0 and ch in "<>=!":
            m = _COMPARE.match(expr, i)
            if m:
                return expr[:i].strip(), m.group(1), float(m.group(2))
        i += 1
    return None


def _find_rule(data: dict, name: str) -> dict | None:
    for group in (data.get("data") or {}).get("groups") or []:
        for rule in group.get("rules") or []:
            if rule.get("name") == name and rule.get("type", "alerting") == "alerting":
                return rule
    return None


def _pick_series(result: list, alert_labels: dict) -> float | None:
    """경보 라벨과 겹치는 라벨이 모두 같은 시계열의 값. 하나뿐이면 그 값."""
    def matches(metric):
        common = set(metric) & set(alert_labels)
        return all(metric[k] == alert_labels[k] for k in common)

    candidates = [r for r in result if matches(r.get("metric") or {})]
    if not candidates and len(result) == 1:
        candidates = result
    if not candidates:
        return None
    return float(candidates[0]["value"][1])


class RulesCollector:
    def __init__(self, prometheus_url: str, loki_url: str,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.prometheus_url = prometheus_url
        self.loki_url = loki_url
        self._transport = transport

    async def fetch(self, alertname: str, alert_labels: dict, starts_at: datetime) -> RuleContext:
        try:
            async with httpx.AsyncClient(timeout=10, transport=self._transport) as client:
                return await self._fetch(client, alertname, alert_labels, starts_at)
        except Exception as e:  # 조회 실패가 RCA 를 막지 않는다
            return RuleContext(name=alertname, error=f"rule lookup failed: {e!r}"[:200])

    async def _fetch(self, client, alertname, alert_labels, starts_at) -> RuleContext:
        sources = (("prometheus", f"{self.prometheus_url}/api/v1/rules"),
                   ("loki", f"{self.loki_url}/prometheus/api/v1/rules"))
        responses = await asyncio.gather(
            *(client.get(url, params={"type": "alert"}) for _, url in sources),
            return_exceptions=True)
        rule, source = None, None
        for (name, _), resp in zip(sources, responses):
            if isinstance(resp, BaseException) or resp.status_code != 200:
                continue
            rule = _find_rule(resp.json(), alertname)
            if rule:
                source = name
                break
        if rule is None:
            return RuleContext(name=alertname, error="rule not found in Prometheus/Loki rules API")

        expr = rule.get("query") or ""
        base = dict(name=alertname, source=source, expr=expr,
                    for_seconds=float(rule.get("duration") or 0),
                    range_seconds=max_range_seconds(expr))
        split = split_threshold(expr)
        if split is None:
            return RuleContext(**base, error="threshold not found in rule expression")
        lhs, op, threshold = split
        base.update(op=op, threshold=threshold)

        if source == "prometheus":
            resp = await client.get(f"{self.prometheus_url}/api/v1/query",
                                    params={"query": lhs, "time": starts_at.timestamp()})
        else:
            resp = await client.get(f"{self.loki_url}/loki/api/v1/query",
                                    params={"query": lhs, "time": int(starts_at.timestamp() * 1e9)})
        if resp.status_code != 200:
            return RuleContext(**base, error=f"value query HTTP {resp.status_code}")
        value = _pick_series((resp.json().get("data") or {}).get("result") or [], alert_labels)
        if value is None:
            return RuleContext(**base, error="no series matching alert labels at startsAt")
        return RuleContext(**base, value=value)
