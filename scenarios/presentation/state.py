"""Event driven presentation state. No progress or timing is inferred from animation."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import sqlite3
import uuid

IDENTITY_KEYS = ("site", "service", "source", "runtime", "target")
STAGES = ("장애 발생", "탐지", "RCA", "Slack 승인 대기", "조치", "복구 검증")
TERMINAL = {"COMPLETED", "FAILED", "REJECTED", "EXPIRED", "CANCELLED", "NO_ALERT", "NO_ACTION"}


def instant(value):
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt.timestamp() if dt.tzinfo else None
    except (ValueError, TypeError, OverflowError):
        return None


def now():
    return datetime.now(timezone.utc).isoformat()


def delta(start, end):
    a, b = instant(start), instant(end)
    return b - a if a is not None and b is not None and b >= a else None


def exact_identity(left, right):
    return all(isinstance(left.get(k), str) and left[k] and left[k] == right.get(k)
               for k in IDENTITY_KEYS)


def incident_matches(alert, identity, fault_at):
    return (exact_identity(alert.get("labels", {}), identity)
            and bool(alert.get("fingerprint"))
            and delta(fault_at, alert.get("startsAt")) is not None)


@dataclass
class Run:
    scenario_id: str
    identity: dict
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    started_at: str = field(default_factory=now)
    fault_at: str | None = None
    detected_at: str | None = None
    recovered_at: str | None = None
    approval_requested_at: str | None = None
    approval_ended_at: str | None = None
    action_started_at: str | None = None
    action_verified_at: str | None = None
    status: str = "RUNNING"
    stage: str = "장애 발생"
    reason: str = "주입기 시작 대기"
    incident: dict = field(default_factory=dict)
    context: dict = field(default_factory=dict)
    rca: dict = field(default_factory=dict)
    record: dict = field(default_factory=dict)
    remediation_id: str | None = None
    slack_url: str | None = None
    events: list = field(default_factory=list)

    def event(self, message):
        if not self.events or self.events[-1]["message"] != message:
            self.events.append({"at": now(), "message": message})
            self.events = self.events[-100:]

    def fail(self, stage, reason, status="FAILED"):
        self.stage, self.reason, self.status = stage, reason, status
        self.event(f"{status} · {stage} · {reason}")

    def attach_contexts(self, contexts):
        if self.incident or self.status in TERMINAL:
            return
        candidates = {}
        for ctx in contexts:
            alert = ctx.get("alert", {})
            if (incident_matches(alert, self.identity, self.fault_at or self.started_at)
                    and delta(self.fault_at or self.started_at, ctx.get("received_at")) is not None):
                candidates[(alert["fingerprint"], alert["startsAt"])] = ctx
        if len(candidates) > 1:
            self.fail("탐지", "동일 대상에 여러 새 사건이 있어 자동 연결할 수 없습니다")
        elif candidates:
            self.context = next(iter(candidates.values()))
            self.incident = self.context["alert"]
            self.detected_at = self.context["received_at"]
            self.stage, self.reason = "RCA", "실제 Pipeline 경보 수신 확인 · LLM 분석 대기"
            self.event(f"탐지 · {self.detected_at}")

    def attach_rca(self, entries):
        if not self.incident or self.rca or self.status in TERMINAL:
            return
        entries = [e for e in entries if exact_identity(e.get("identity", {}), self.identity)
                   and e.get("alert_fingerprint") == self.incident["fingerprint"]
                   and instant(e.get("alert_starts_at")) == instant(self.incident["startsAt"])
                   and delta(self.detected_at, e.get("timestamp")) is not None]
        if not entries:
            return
        self.rca = min(entries, key=lambda e: instant(e["timestamp"]))
        self.remediation_id = self.rca.get("remediation_id")
        self.event("RCA · LLM 분석 결과 수신")
        if self.rca.get("result", {}).get("analysis_status") == "invalid":
            self.fail("RCA", ", ".join(self.rca["result"].get("invalid_reasons", [])))
        elif not self.remediation_id:
            if self.rca.get("result", {}).get("action_type") in {"NONE", "NOTIFY"}:
                self.fail("RCA", "LLM 권고 · " + self.rca["result"]["action_type"] + " · 조치/복구 표본 없음", "NO_ACTION")
            else:
                self.fail("RCA", "실행 가능한 승인 요청 없음: " + str(self.rca.get("handoff_status", "unknown")))
        else:
            self.stage, self.reason = "Slack 승인 대기", "기존 HITL 레코드 확인 중"

    def attach_record(self, record):
        if self.status in TERMINAL:
            return
        alert = record.get("alert_context", {})
        if (record.get("remediation_id") != self.remediation_id
                or not exact_identity(record.get("identity", {}), self.identity)
                or alert.get("fingerprint") != self.incident.get("fingerprint")
                or instant(alert.get("startsAt")) != instant(self.incident.get("startsAt"))):
            self.fail("조치", "remediation 사건 식별자 불일치")
            return
        self.record = record
        self.slack_url = record.get("slack_message_url")
        for key in ("approval_requested_at", "action_started_at", "action_verified_at"):
            setattr(self, key, record.get(key))
        state = record.get("state", "UNKNOWN")
        self.approval_ended_at = record.get("approved_at") or record.get("rejected_at")
        if state == "EXPIRED":
            self.approval_ended_at = record.get("approval_expires_at")
        self.event(f"조치 모듈 · {state}")
        if state in {"REJECTED", "EXPIRED"}:
            self.fail("Slack 승인 대기", "승인 거절" if state == "REJECTED" else "승인 시간 초과", state)
            return
        if state in {"FAILED", "BLOCKED", "SKIPPED", "UNKNOWN", "NEEDS_REVIEW",
                     "RECOVERY_FAILED", "RECOVERY_UNKNOWN", "SUPERSEDED"}:
            self.fail("조치", json.dumps(record.get("results") or state, ensure_ascii=False))
            return
        if state == "AWAITING_APPROVAL":
            if record.get("slack_dispatch_status") in {"FAILED", "SKIPPED"}:
                self.fail("Slack 승인 대기", "Slack 승인 메시지 전송 실패")
            elif instant(record.get("approval_expires_at")) is not None and instant(now()) >= instant(record["approval_expires_at"]):
                self.approval_ended_at = record["approval_expires_at"]
                self.fail("Slack 승인 대기", "승인 시간 초과", "EXPIRED")
            else:
                self.stage, self.reason = "Slack 승인 대기", "Slack에서 Approve 또는 Reject를 선택하세요"
            return
        if state in {"APPROVED", "EXECUTING"}:
            self.stage, self.reason = "조치", "기존 실행기에서 승인된 조치 수행 중"
            return
        verification = record.get("service_verification", {})
        self.stage, self.reason = "복구 검증", str(verification.get("reason") or verification.get("state", "대기"))
        if verification.get("state") in {"UNCONFIGURED", "BLOCKED", "TIMEOUT"}:
            self.fail("복구 검증", self.reason)
        elif (verification.get("state") == "RECOVERED" and record.get("service_recovered_at")
              and record.get("approved_at") and record.get("action_verified_at")
              and record.get("results")
              and all(r.get("status") == "SUCCESS" and r.get("verified") is True for r in record["results"])
              and delta(self.fault_at or self.started_at, record["approved_at"]) is not None
              and delta(record["approved_at"], record.get("action_started_at")) is not None
              and delta(record.get("action_started_at"), record["action_verified_at"]) is not None
              and delta(record["action_verified_at"], record["service_recovered_at"]) is not None):
            self.recovered_at = record["service_recovered_at"]
            self.status, self.reason = "COMPLETED", "Health + fresh Prometheus 연속 검증 통과"
            self.event(f"COMPLETED · {self.recovered_at}")
        elif verification.get("state") == "RECOVERED":
            self.fail("복구 검증", "검증된 실행 결과 또는 이벤트 시각 순서가 유효하지 않습니다")

    def timings(self):
        return {"ttd": delta(self.fault_at, self.detected_at),
                "ttr": delta(self.fault_at, self.recovered_at),
                "approval": delta(self.approval_requested_at, self.approval_ended_at or now()),
                "action": delta(self.action_started_at, self.action_verified_at)}


class History:
    """One row per real run; polling never adds samples. Only event times count."""
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute("CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, scenario TEXT, identity TEXT, body TEXT)")

    def save(self, run):
        self.db.execute("INSERT OR REPLACE INTO runs VALUES (?,?,?,?)",
                        (run.run_id, run.scenario_id, json.dumps(run.identity, sort_keys=True), json.dumps(asdict(run))))
        self.db.commit()

    def summary(self, run=None):
        rows = (self.db.execute("SELECT body FROM runs WHERE scenario=? AND identity=?",
                               (run.scenario_id, json.dumps(run.identity, sort_keys=True)))
                if run else self.db.execute("SELECT body FROM runs"))
        samples = [json.loads(r[0]) for r in rows]
        out = {}
        for metric, end in (("mttd", "detected_at"), ("mttr", "recovered_at")):
            values = [v for r in samples if (v := delta(r.get("fault_at"), r.get(end))) is not None and math.isfinite(v)]
            out[metric] = (sum(values) / len(values) if values else None, len(values))
        return out
