"""
S2/C-a 네트워크 경보 검증기 (Step 4 / P5).

세 단계를 "독립적으로" 검증한다 (각 단계 성공/실패를 따로 기록):
  A. Loki Ruler FIRING   — LogQL 규칙이 실제로 firing 으로 전이했는가
  B. Alertmanager 수신    — 그 경보가 Alertmanager 에 도달했는가
  C. 전달(AIOps/Slack)    — 파이프라인/Slack 으로 전달되었는가

설계 원칙 (사용자 계획 §P5):
  - 이전 실행의 경보와 섞이지 않도록 occurrence 를 t0(이번 실행 송신 시작) 이후의
    activeAt/startsAt 로만 선택한다.
  - MTTD = t2 - t0.  t2 = Loki Ruler 가 firing 으로 "전이한 시각(activeAt)" 이며,
    polling 으로 처음 "관측한 시각" 과 구분한다. Alertmanager group_wait 은 MTTD 에
    넣지 않는다 (B 단계는 전달 확인용, 측정 기준 아님).
  - Ground Truth 는 평가 측에만 둔다 — 이 검증기는 탐지기/LLM 입력을 만들지 않는다.

기존 scenarios/common/verifier.py(Prometheus 경보 검증, Rich TUI)는 건드리지 않는다.
이 모듈은 네트워크 시나리오 전용이며 순수 stdlib 로 단독 테스트 가능하다. HTTP 호출은
얇은 래퍼이고, 판정 로직(파싱·occurrence 선택·MTTD)은 순수 함수로 분리했다.
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone

# Loki 는 ruler API 를 Prometheus 호환 경로로 노출한다.
LOKI_URL = os.getenv("LOKI_URL", "http://localhost:3100")
ALERTMANAGER_URL = os.getenv("ALERTMANAGER_URL", "http://localhost:9093")

ACC_ALERT = "UnauthorizedDataTransfer"
EARLY_ALERT = "UnauthorizedTransferEarly"
DEFAULT_ALERTS = (ACC_ALERT, EARLY_ALERT)


# --------------------------------------------------------------------------- #
# 시각 파싱
# --------------------------------------------------------------------------- #

def parse_ts(value) -> datetime | None:
    """RFC3339 (Z 또는 offset, 분수초 허용) -> aware UTC datetime. 실패 시 None."""
    if value in (None, "", "0001-01-01T00:00:00Z"):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    s = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
# 파싱된 경보 모델
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class RulerAlert:
    alertname: str
    state: str                 # "firing" | "pending" | "inactive"
    active_at: datetime | None  # firing 으로 전이한 시각 (MTTD t2)
    labels: dict


@dataclass(frozen=True)
class AmAlert:
    alertname: str
    starts_at: datetime | None
    state: str                 # "active" | "suppressed" | ...
    labels: dict


def parse_ruler_alerts(obj: dict) -> list[RulerAlert]:
    """Prometheus/Loki-ruler /api/v1/alerts 응답 -> RulerAlert 목록."""
    out = []
    for a in (((obj or {}).get("data") or {}).get("alerts") or []):
        labels = a.get("labels") or {}
        out.append(RulerAlert(
            alertname=labels.get("alertname", ""),
            state=(a.get("state") or "").lower(),
            active_at=parse_ts(a.get("activeAt")),
            labels=labels,
        ))
    return out


def parse_am_alerts(arr) -> list[AmAlert]:
    """Alertmanager v2 /api/v2/alerts 응답 -> AmAlert 목록."""
    out = []
    for a in (arr or []):
        labels = a.get("labels") or {}
        status = a.get("status") or {}
        out.append(AmAlert(
            alertname=labels.get("alertname", ""),
            starts_at=parse_ts(a.get("startsAt")),
            state=(status.get("state") or "").lower(),
            labels=labels,
        ))
    return out


# --------------------------------------------------------------------------- #
# occurrence 선택 (이전 실행과 격리)
# --------------------------------------------------------------------------- #

def select_firing_occurrence(alerts: list[RulerAlert], alertnames, since: datetime
                             ) -> RulerAlert | None:
    """since(t0) 이후 firing 으로 전이한, 대상 alertname 의 경보 중 가장 이른 것."""
    names = set(alertnames)
    cands = [a for a in alerts
             if a.alertname in names and a.state == "firing"
             and a.active_at is not None and a.active_at >= since]
    return min(cands, key=lambda a: a.active_at) if cands else None


def select_am_occurrence(alerts: list[AmAlert], alertnames, since: datetime
                         ) -> AmAlert | None:
    names = set(alertnames)
    cands = [a for a in alerts
             if a.alertname in names and a.starts_at is not None and a.starts_at >= since]
    return min(cands, key=lambda a: a.starts_at) if cands else None


def is_any_firing(alerts: list[RulerAlert], alertnames) -> bool:
    names = set(alertnames)
    return any(a.alertname in names and a.state == "firing" for a in alerts)


def compute_mttd(t0: datetime, firing_active_at: datetime | None) -> float | None:
    """MTTD = t2 - t0 (초). firing 전이 시각이 없으면 None. 음수면 0으로 보정."""
    if firing_active_at is None or t0 is None:
        return None
    return max(0.0, (firing_active_at - t0).total_seconds())


# --------------------------------------------------------------------------- #
# 단계 결과
# --------------------------------------------------------------------------- #

@dataclass
class StageResult:
    name: str
    ok: bool
    detail: str = ""
    observed_at: str | None = None   # 이 단계를 polling 으로 처음 관측한 시각(ISO)


@dataclass
class NetworkVerifyResult:
    t0: str | None
    stages: dict = field(default_factory=dict)   # name -> StageResult
    firing_active_at: str | None = None          # t2 (전이 시각)
    first_observed_at: str | None = None         # polling 으로 처음 본 시각 (≠ t2)
    mttd_seconds: float | None = None

    @property
    def all_ok(self) -> bool:
        return bool(self.stages) and all(s.ok for s in self.stages.values())

    def as_dict(self) -> dict:
        return {
            "t0": self.t0,
            "firing_active_at": self.firing_active_at,
            "first_observed_at": self.first_observed_at,
            "mttd_seconds": self.mttd_seconds,
            "all_ok": self.all_ok,
            "stages": {k: vars(v) for k, v in self.stages.items()},
        }


# --------------------------------------------------------------------------- #
# 판정 (순수) — fetch 한 데이터로 세 단계를 독립 평가
# --------------------------------------------------------------------------- #

def evaluate_stages(t0: datetime, ruler_alerts, am_alerts, delivery_ok: bool,
                    delivery_detail: str, alertnames=DEFAULT_ALERTS,
                    now_iso: str | None = None) -> NetworkVerifyResult:
    """세 단계를 독립적으로 평가. HTTP 없이 데이터만으로 동작(테스트 가능)."""
    now_iso = now_iso or datetime.now(timezone.utc).isoformat()

    firing = select_firing_occurrence(ruler_alerts, alertnames, t0)
    stage_a = StageResult(
        "loki_ruler_firing", firing is not None,
        detail=(f"{firing.alertname} firing @ {firing.active_at.isoformat()}"
                if firing else "대상 경보의 t0 이후 firing 전이 없음"),
        observed_at=now_iso,
    )

    am = select_am_occurrence(am_alerts, alertnames, t0)
    stage_b = StageResult(
        "alertmanager_received", am is not None,
        detail=(f"{am.alertname} @ {am.starts_at.isoformat()} ({am.state})"
                if am else "Alertmanager 에 t0 이후 해당 경보 없음"),
        observed_at=now_iso,
    )

    stage_c = StageResult("delivery", delivery_ok, detail=delivery_detail, observed_at=now_iso)

    result = NetworkVerifyResult(t0=t0.isoformat() if t0 else None)
    result.stages = {s.name: s for s in (stage_a, stage_b, stage_c)}
    if firing:
        result.firing_active_at = firing.active_at.isoformat()
        result.first_observed_at = now_iso
        result.mttd_seconds = compute_mttd(t0, firing.active_at)
    return result


def _loki_entries(obj, since: datetime):
    """Loki query_range 응답 -> (labels, ts_ns, line) 반복. since 이전 항목은 버린다."""
    since_ns = int(since.timestamp() * 1e9) if since else 0
    for stream in ((obj or {}).get("data") or {}).get("result") or []:
        labels = stream.get("stream") or {}
        for ts_ns, line in stream.get("values") or []:
            try:
                if int(ts_ns) < since_ns:
                    continue
            except (TypeError, ValueError):
                continue
            yield labels, int(ts_ns), line


def parse_delivery(llm_obj, slack_obj, alertnames=DEFAULT_ALERTS,
                   since: datetime | None = None) -> tuple[bool, str]:
    """
    Stage C 판정 (순수).
      ok = t0 이후 대상 경보에 대해 pipeline 이 RCA 를 실제 수행해 {job="aiops-llm"} 에 남겼는가.
      pipeline 은 container 가 비었거나 "unknown" 이면 RCA 를 건너뛰고 fallback 만 남기므로
      그 항목은 전달로 치지 않는다 (규칙 annotations.container 누락의 증상).
      Slack({job="aiops-slack"}) 상태는 detail 에만 기록한다 (webhook 미설정 환경도 있음).
    """
    names = set(alertnames)
    rca, skipped = [], 0
    for labels, _ts, line in _loki_entries(llm_obj, since):
        if labels.get("alert") not in names:
            continue
        try:
            entry = json.loads(line)
        except (TypeError, ValueError):
            continue
        container = entry.get("container") or labels.get("target_container")
        if not container or container == "unknown":
            skipped += 1
        else:
            rca.append((labels.get("alert"), container))

    slack_status = []
    for labels, _ts, line in _loki_entries(slack_obj, since):
        try:
            entry = json.loads(line)
        except (TypeError, ValueError):
            continue
        if entry.get("event") != "slack_notification":
            continue
        alert = entry.get("alert_name") or entry.get("alert") or labels.get("alert")
        if alert in names:
            slack_status.append(entry.get("slack_status") or entry.get("status") or "?")

    parts = []
    if rca:
        alert, container = rca[-1]
        parts.append(f"RCA {len(rca)}건 ({alert} → {container})")
    if skipped:
        parts.append(f"RCA 건너뜀 {skipped}건 (container 없음/unknown)")
    if not rca and not skipped:
        parts.append("t0 이후 대상 경보의 RCA 결과 없음")
    parts.append("slack=" + (",".join(slack_status) if slack_status else "기록 없음"))
    return (bool(rca), "; ".join(parts))


# --------------------------------------------------------------------------- #
# HTTP 래퍼 + 폴링 (런타임 — Loki/Alertmanager 필요, UNVERIFIED)
# --------------------------------------------------------------------------- #

class NetworkScenarioVerifier:
    def __init__(self, loki_url: str = LOKI_URL, alertmanager_url: str = ALERTMANAGER_URL,
                 alertnames=DEFAULT_ALERTS):
        self.loki_url = loki_url.rstrip("/")
        self.am_url = alertmanager_url.rstrip("/")
        self.alertnames = tuple(alertnames)

    def _get_json(self, url: str, timeout: float = 5.0):
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read())

    def fetch_ruler_alerts(self) -> list[RulerAlert]:
        # Loki ruler 는 Prometheus 호환 경로로 경보를 노출한다
        return parse_ruler_alerts(self._get_json(f"{self.loki_url}/prometheus/api/v1/alerts"))

    def fetch_am_alerts(self) -> list[AmAlert]:
        return parse_am_alerts(self._get_json(f"{self.am_url}/api/v2/alerts"))

    def _query_range(self, query: str, since: datetime) -> dict:
        params = urllib.parse.urlencode({
            "query": query, "start": int(since.timestamp() * 1e9),
            "limit": 50, "direction": "forward",
        })
        return self._get_json(f"{self.loki_url}/loki/api/v1/query_range?{params}")

    def fetch_delivery(self, since: datetime) -> tuple[bool, str]:
        """
        전달 증거: pipeline 이 Loki 에 직접 push 하는 {job="aiops-llm"}(RCA 결과)와
        remediation 의 {job="aiops-slack"}(Slack 전송 상태)를 t0 이후로 조회한다.
        판정은 parse_delivery (순수 함수).
        """
        alert_re = "|".join(self.alertnames)
        try:
            llm = self._query_range(f'{{job="aiops-llm", alert=~"{alert_re}"}}', since)
        except Exception as exc:
            return (False, f"aiops-llm 조회 실패: {exc!r}")
        try:
            slack = self._query_range(f'{{job="aiops-slack", alert=~"{alert_re}"}}', since)
        except Exception:
            slack = None   # Slack 은 부가 정보 — 조회 실패해도 RCA 판정은 유지
        return parse_delivery(llm, slack, self.alertnames, since)

    def verify(self, t0: datetime, timeout: int = 120, poll_interval: int = 5
               ) -> NetworkVerifyResult:
        """t0 이후 세 단계를 폴링하며 평가한다. Stage A(firing)가 뜨면 즉시 확정."""
        deadline = time.monotonic() + timeout
        last = None
        while True:
            ruler = self._safe(self.fetch_ruler_alerts, [])
            am = self._safe(self.fetch_am_alerts, [])
            delivery_ok, delivery_detail = self._safe(lambda: self.fetch_delivery(t0),
                                                      (False, "n/a"))
            last = evaluate_stages(t0, ruler, am, delivery_ok, delivery_detail, self.alertnames)
            if last.stages["loki_ruler_firing"].ok or time.monotonic() >= deadline:
                return last
            time.sleep(poll_interval)

    def wait_ruler_inactive(self, timeout: int = 90, poll_interval: int = 5) -> bool:
        """실험 간 쿨다운: 대상 경보가 더 이상 firing 이 아닐 때까지 기다린다."""
        deadline = time.monotonic() + timeout
        while True:
            ruler = self._safe(self.fetch_ruler_alerts, [])
            if not is_any_firing(ruler, self.alertnames):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(poll_interval)

    @staticmethod
    def _safe(fn, default):
        try:
            return fn()
        except Exception:
            return default
