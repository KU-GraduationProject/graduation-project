"""
경보를 일으킨 룰의 식·시간 창·임계값과 경보 시점(startsAt) 값 조회.

Prometheus 는 /api/v1/rules, Loki ruler 는 같은 형식의 /prometheus/api/v1/rules 로 룰을 준다.

룰팩(M5) 형태 처리:
  - 같은 alertname 이 여러 룰(대상별 분할, rulepack_target 라벨)일 수 있다 → 룰의 고정 라벨이
    경보 라벨과 모두 같은 룰을 고른다. 고를 수 없으면 실패로 남긴다(엉뚱한 룰 값을 쓰지 않는다).
  - `(a > x) or (b > y)`, `a >= 2 or b >= 2`, `a > x and on(name) info` 처럼 비교가 여러 개이거나
    괄호 안에 있을 수 있다 → 값은 룰 식 전체를 startsAt 에 평가해 얻는다(PromQL/LogQL 비교는
    조건을 만족한 시계열의 좌변 값을 돌려준다). 임계값은 `or` 갈래마다 최상위 비교를 모은다.
  - 서브쿼리 [10m:5s]·offset·keep_firing_for·그룹 평가 주기(interval)를 기록한다.
조회는 best-effort 다. 실패하면 예외 대신 error 에 사유를 남기고, 프롬프트는 "value lookup failed" 로 밝힌다.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import asdict, dataclass
from datetime import datetime

import httpx

_DURATION = re.compile(r"(\d+(?:\.\d+)?)(ms|s|m|h|d|w|y)")
_UNIT_SECONDS = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800, "y": 31536000}
_RANGE = re.compile(r"\[\s*((?:\d+(?:\.\d+)?(?:ms|s|m|h|d|w|y))+)\s*(?::\s*((?:\d+(?:\.\d+)?(?:ms|s|m|h|d|w|y))+))?\s*\]")
_COMPARE = re.compile(r"(>=|<=|==|!=|>|<)\s*(?:bool\s+)?(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)(?![\w.])")


@dataclass(frozen=True)
class RuleContext:
    name: str
    source: str | None = None          # prometheus | loki
    expr: str | None = None
    for_seconds: float | None = None
    range_seconds: float | None = None  # 가장 긴 범위 선택자(서브쿼리 포함)
    ranges: tuple = ()                  # 식 안의 범위 선택자 원문 ("30s", "10m:5s")
    conditions: tuple = ()              # ((연산자, 임계값), ...) — or 갈래별 최상위 비교
    keep_firing_seconds: float | None = None
    eval_interval_seconds: float | None = None
    value: float | None = None          # 룰 식의 startsAt 시점 값
    error: str | None = None            # 룰·값 조회 실패 사유

    @property
    def op(self) -> str | None:
        return self.conditions[0][0] if len(self.conditions) == 1 else None

    @property
    def threshold(self) -> float | None:
        return self.conditions[0][1] if len(self.conditions) == 1 else None

    @property
    def window_seconds(self) -> float | None:
        """룰이 보는 시간 창 = 가장 긴 범위 선택자 + for. 둘 다 모르면 None."""
        if self.range_seconds is None and self.for_seconds is None:
            return None
        return (self.range_seconds or 0) + (self.for_seconds or 0)

    def as_dict(self) -> dict:
        d = asdict(self)
        d["ranges"], d["conditions"] = list(self.ranges), [list(c) for c in self.conditions]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "RuleContext":
        kw = {k: d[k] for k in cls.__dataclass_fields__ if k in d}
        kw["ranges"] = tuple(kw.get("ranges") or ())
        kw["conditions"] = tuple(tuple(c) for c in kw.get("conditions") or ())
        # 이전 픽스처 형식(op/threshold 한 쌍) 호환
        if not kw["conditions"] and d.get("op") is not None and d.get("threshold") is not None:
            kw["conditions"] = ((d["op"], float(d["threshold"])),)
        return cls(**kw)


def parse_duration(text) -> float | None:
    """'1m30s' -> 90.0. 숫자(초)도 받는다. 형식이 아니면 None."""
    if isinstance(text, (int, float)):
        return float(text)
    parts = _DURATION.findall(text or "")
    if not parts or "".join(n + u for n, u in parts) != text:
        return None
    return sum(float(n) * _UNIT_SECONDS[u] for n, u in parts)


def range_selectors(expr: str) -> list[str]:
    """식 안의 범위 선택자 원문 (중복 제거, 순서 유지). 서브쿼리는 '10m:5s'."""
    return list(dict.fromkeys(r + (":" + step if step else "") for r, step in _RANGE.findall(expr or "")))


def max_range_seconds(expr: str) -> float | None:
    """식 안의 범위 선택자([5m], 서브쿼리 [10m:5s]의 10m) 중 가장 긴 것."""
    values = [parse_duration(r) for r, _ in _RANGE.findall(expr or "")]
    values = [v for v in values if v is not None]
    return max(values) if values else None


def _scan_top_level(expr: str):
    """(위치, 문자, 깊이) — 문자열 안은 건너뛴다."""
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
        yield i, ch, depth
        i += 1


def _split_or(expr: str) -> list[str]:
    parts, last = [], 0
    for i, ch, depth in _scan_top_level(expr):
        if depth == 0 and expr.startswith("or", i) and (i == 0 or not (expr[i - 1].isalnum() or expr[i - 1] == "_")) \
                and (i + 2 >= len(expr) or not (expr[i + 2].isalnum() or expr[i + 2] == "_")):
            parts.append(expr[last:i])
            last = i + 2
    parts.append(expr[last:])
    return [p.strip() for p in parts if p.strip()]


def _strip_parens(expr: str) -> str:
    """식 전체를 감싸는 괄호 한 겹을 벗긴다 ('(a) and (b)' 는 그대로)."""
    expr = expr.strip()
    while expr.startswith("(") and expr.endswith(")"):
        closes_at_end = all(not (depth == 0 and i < len(expr) - 1)
                            for i, ch, depth in _scan_top_level(expr) if ch == ")")
        if not closes_at_end:
            break
        expr = expr[1:-1].strip()
    return expr


def split_threshold(expr: str) -> tuple[str, str, float] | None:
    """최상위 첫 비교식 (좌변, 연산자, 임계값). 'a > 0.5 and on(name) b' 는 a, >, 0.5."""
    for i, ch, depth in _scan_top_level(expr):
        if depth == 0 and ch in "<>=!":
            m = _COMPARE.match(expr, i)
            if m:
                return expr[:i].strip(), m.group(1), float(m.group(2))
    return None


def conditions(expr: str) -> tuple:
    """`or` 갈래마다 (괄호를 벗긴 뒤) 최상위 비교의 (연산자, 임계값). 중복 제거, 순서 유지."""
    out = []
    for branch in _split_or(expr or ""):
        split = split_threshold(_strip_parens(branch))
        if split and (split[1], split[2]) not in out:
            out.append((split[1], split[2]))
    return tuple(out)


def _subset(rule_labels: dict, alert_labels: dict) -> bool:
    return all(alert_labels.get(k) == v for k, v in (rule_labels or {}).items())


def _find_rule(data: dict, name: str, alert_labels: dict):
    """(rule, group, 같은 이름 룰 수). 고정 라벨이 경보와 맞는 룰이 정확히 하나일 때만 rule 을 준다."""
    named = []
    for group in (data.get("data") or {}).get("groups") or []:
        for rule in group.get("rules") or []:
            if rule.get("name") == name and rule.get("type", "alerting") == "alerting":
                named.append((rule, group))
    hits = [(r, g) for r, g in named if _subset(r.get("labels"), alert_labels)]
    if len(hits) == 1:
        return hits[0][0], hits[0][1], len(named)
    return None, None, len(named) if not hits else -len(hits)


def _pick_series(result: list, alert_labels: dict) -> float | None:
    """경보 라벨과 겹치는 라벨이 모두 같은 시계열의 값. 하나뿐이면 그 값."""
    def matches(metric):
        common = set(metric) & set(alert_labels)
        return all(metric[k] == alert_labels[k] for k in common)

    candidates = [r for r in result if matches(r.get("metric") or {})]
    if not candidates and len(result) == 1:
        candidates = result
    if len(candidates) != 1:
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
            return RuleContext(name=alertname, error=f"rule lookup failed: {type(e).__name__}")

    async def _fetch(self, client, alertname, alert_labels, starts_at) -> RuleContext:
        sources = (("prometheus", f"{self.prometheus_url}/api/v1/rules"),
                   ("loki", f"{self.loki_url}/prometheus/api/v1/rules"))
        responses = await asyncio.gather(
            *(client.get(url, params={"type": "alert"}) for _, url in sources),
            return_exceptions=True)
        rule = group = source = None
        ambiguous = 0
        for (name, _), resp in zip(sources, responses):
            if isinstance(resp, BaseException) or resp.status_code != 200:
                continue
            found, grp, count = _find_rule(resp.json(), alertname, alert_labels)
            if found:
                rule, group, source = found, grp, name
                break
            if count:
                ambiguous = count
        if rule is None:
            if ambiguous > 0:
                reason = f"{ambiguous} rules named {alertname}, none match alert labels"
            elif ambiguous < 0:
                reason = f"{-ambiguous} rules named {alertname} match alert labels (ambiguous)"
            else:
                reason = "rule not found in Prometheus/Loki rules API"
            return RuleContext(name=alertname, error=reason)

        expr = rule.get("query") or ""
        base = dict(name=alertname, source=source, expr=expr,
                    for_seconds=parse_duration(rule.get("duration") or 0),
                    range_seconds=max_range_seconds(expr), ranges=tuple(range_selectors(expr)),
                    conditions=conditions(expr),
                    keep_firing_seconds=parse_duration(rule.get("keepFiringFor") or 0) or None,
                    eval_interval_seconds=parse_duration(group.get("interval")) if group.get("interval") else None)

        # 룰 식 전체를 평가한다 — 비교는 조건을 만족한 시계열의 좌변 값을 돌려준다
        if source == "prometheus":
            resp = await client.get(f"{self.prometheus_url}/api/v1/query",
                                    params={"query": expr, "time": starts_at.timestamp()})
        else:
            resp = await client.get(f"{self.loki_url}/loki/api/v1/query",
                                    params={"query": expr, "time": int(starts_at.timestamp() * 1e9)})
        if resp.status_code != 200:
            return RuleContext(**base, error=f"value query HTTP {resp.status_code}")
        result = (resp.json().get("data") or {}).get("result") or []
        if not result:
            return RuleContext(**base, error="rule expression returned no series at startsAt")
        value = _pick_series(result, alert_labels)
        if value is None:
            return RuleContext(**base, error=f"{len(result)} series at startsAt, none uniquely match alert labels")
        return RuleContext(**base, value=value)
