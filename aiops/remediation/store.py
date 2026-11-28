r"""
조치 레코드 저장소 (Phase 2) — 멱등성·TTL·MTTR 의 근거.

왜 파일에 쓰는가
  멱등성과 TTL 복구는 프로세스 메모리에 두면 재시작 때 사라진다. 그러면 같은 승인이
  두 번 실행되거나, 격리해 둔 컨테이너를 복구할 근거(원래 IP·alias·쿼터)를 잃는다.
  작은 JSON 파일 하나로 충분하므로 DB 를 끌어오지 않는다.

쓰기는 임시 파일 + os.replace 로 원자적으로 한다 — 쓰다가 죽어도 반쪽 파일이 남지
않는다. 동시 접근은 프로세스 내 Lock 으로 막는다(단일 인스턴스 전제, Phase 3 에서
다중 인스턴스가 되면 공유 저장소로 바꿔야 한다).

상태 기계
    PROPOSED -> AWAITING_APPROVAL -> APPROVED -> EXECUTING -> VERIFIED | FAILED
                                 \-> REJECTED
    VERIFIED -> RECOVERY_PENDING -> RECOVERING -> RECOVERED | RECOVERY_FAILED
    BLOCKED (정책/증거/실행기 거부)
"""

from __future__ import annotations

import json
import copy
import hashlib
import logging
import os
import tempfile
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

STATE_DIR_ENV = "REMEDIATION_STATE_DIR"
DEFAULT_STATE_DIR = "/app/state"
STATE_FILE = "remediation_records.json"

# 상태
PROPOSED = "PROPOSED"
AWAITING_APPROVAL = "AWAITING_APPROVAL"
APPROVED = "APPROVED"
EXECUTING = "EXECUTING"
VERIFIED = "VERIFIED"
FAILED = "FAILED"
BLOCKED = "BLOCKED"
REJECTED = "REJECTED"
EXPIRED = "EXPIRED"
SUPERSEDED = "SUPERSEDED"
SKIPPED = "SKIPPED"
RECOVERY_PENDING = "RECOVERY_PENDING"
RECOVERY_APPROVAL_REQUIRED = "RECOVERY_APPROVAL_REQUIRED"
RECOVERING = "RECOVERING"
RECOVERED = "RECOVERED"
RECOVERY_FAILED = "RECOVERY_FAILED"
NEEDS_REVIEW = "NEEDS_REVIEW"
UNKNOWN = "UNKNOWN"
RECOVERY_UNKNOWN = "RECOVERY_UNKNOWN"

# 조치가 끝나 더 이상 실행하지 않아야 하는 상태 (멱등성 판정용)
TERMINAL_EXECUTION_STATES = (
    EXECUTING, VERIFIED, FAILED, BLOCKED, SKIPPED, REJECTED, EXPIRED, SUPERSEDED,
    RECOVERY_PENDING, RECOVERY_APPROVAL_REQUIRED, RECOVERING, RECOVERED,
    RECOVERY_FAILED, NEEDS_REVIEW, UNKNOWN, RECOVERY_UNKNOWN,
)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_ts(value) -> float | None:
    if not value:
        return None
    try:
        text = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(text).timestamp()
    except (ValueError, TypeError, OverflowError):
        return None


IDENTITY_FIELDS = ("site", "service", "source", "runtime", "target")


def incident_key(alert: dict) -> tuple[str, dict]:
    """Durable incident identity; never substitute receipt time for startsAt."""
    labels = alert.get("labels")
    if not isinstance(labels, dict):
        raise ValueError("incident_identity_required")
    identity = {k: labels.get(k) for k in IDENTITY_FIELDS}
    if any(not isinstance(v, str) or not v.strip() for v in identity.values()):
        raise ValueError("incident_identity_required")
    fingerprint = alert.get("fingerprint")
    if not isinstance(fingerprint, str) or not fingerprint.strip():
        raise ValueError("incident_fingerprint_required")
    try:
        start = datetime.fromisoformat(str(alert.get("startsAt", "")).replace("Z", "+00:00"))
        if start.tzinfo is None:
            raise ValueError("timezone required")
        start = start.astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError, OverflowError):
        raise ValueError("incident_starts_at_required") from None
    key = {"identity": identity, "fingerprint": fingerprint, "startsAt": start}
    return hashlib.sha256(json.dumps(key, sort_keys=True, separators=(",", ":")).encode()).hexdigest(), identity


def action_hash(action_type, targets, ttl_seconds=None, recovery_mode=None, parameters=None):
    """Canonical action content, separate from the incident key."""
    value = {"action_type": str(action_type).upper(), "targets": sorted(targets),
             "ttl_seconds": ttl_seconds, "recovery_mode": recovery_mode or "none",
             "parameters": parameters or {}}
    try:
        body = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError):
        raise ValueError("invalid_action_parameters") from None
    return hashlib.sha256(body.encode()).hexdigest()


class IncidentConflict(ValueError):
    """The incident already has a different proposed action."""


def approval_valid(record, now=None, recovery=False):
    now = time.time() if now is None else now
    requested = _parse_ts(record.recovery_approval_requested_at if recovery else record.approval_requested_at)
    expires = _parse_ts(record.recovery_approval_expires_at if recovery else record.approval_expires_at)
    return (requested is not None and expires is not None and requested <= now < expires
            and 0 < expires - requested <= 86400)


def derive_id(alertname: str, action_type: str, targets) -> str:
    """
    remediation_id 를 만들 수 없을 때(과거 Slack 메시지 등) 쓰는 결정적 ID.
    같은 경보·조치·대상이면 같은 ID 가 되어 중복 승인이 한 건으로 합쳐진다.
    """
    import hashlib
    key = "|".join([str(alertname or "unknown"), str(action_type or "NONE").upper(),
                    ",".join(sorted(str(t) for t in (targets or ())))])
    return "d" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:31]


@dataclass
class RemediationRecord:
    remediation_id: str
    alertname: str
    action_type: str
    targets: list = field(default_factory=list)
    state: str = PROPOSED
    action_risk: str | None = None
    threat_level: str | None = None
    requires_approval: bool = False
    ttl_seconds: int | None = None
    recovery_mode: str | None = None       # auto | require_approval | none
    approved_by: str | None = None
    rejected_by: str | None = None
    rejected_at: str | None = None
    source: str | None = None
    executor_name: str | None = None
    recovery_approved_by: str | None = None
    recovery_approval_requested_at: str | None = None
    recovery_approval_expires_at: str | None = None
    evidence: dict = field(default_factory=dict)
    results: list = field(default_factory=list)
    recovery_results: list = field(default_factory=list)
    # MTTR·서비스 복구 시간 계산용 타임스탬프
    alert_active_at: str | None = None
    approval_requested_at: str | None = None
    approval_expires_at: str | None = None
    approved_at: str | None = None
    action_started_at: str | None = None
    action_verified_at: str | None = None
    recovery_due_at: str | None = None
    recovery_started_at: str | None = None
    recovery_verified_at: str | None = None
    created_at: str = field(default_factory=utcnow)
    updated_at: str = field(default_factory=utcnow)
    incident_key: str | None = None
    action_hash: str | None = None
    identity: dict = field(default_factory=dict)
    target_bindings: dict = field(default_factory=dict)
    action_parameters: dict = field(default_factory=dict)
    revision: int = 1
    supersedes_id: str | None = None
    superseded_by: str | None = None
    replan_reason: str | None = None
    plan_id: str | None = None
    plan_step: int = 0
    plan_steps: list = field(default_factory=list)
    plan_hash: str | None = None
    predecessor_id: str | None = None
    next_step_id: str | None = None
    recovery_of: str | None = None
    recovery_request_id: str | None = None
    alert_context: dict = field(default_factory=dict)
    service_verification: dict = field(default_factory=dict)
    service_recovered_at: str | None = None
    slack_message_url: str | None = None
    slack_dispatch_status: str | None = None
    # Pipeline RCA 의 사건 분류 (attack|failure|benign). 보안 사고 ISOLATE 의 DB 백업 판단에 쓴다.
    incident_class: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)

    # ── 파생 시간 지표 ────────────────────────────────────────────────────────
    def mttr(self) -> float | None:
        """
        MTTR = t_action_verified - t_alert_activeAt (노션: 조치를 취할 때까지의 시간, MTTD 는 Pipeline).
        t_action_verified 는 조치 효과를 '상태 재조회로 확인한' 시각이며 호출 성공 시각이 아니다.
        """
        return _delta(self.alert_active_at, self.action_verified_at)

    def time_to_service_recovery(self) -> float | None:
        """
        경보 발생 → 서비스 복구 확인. Health·Prometheus 연속 검증을 통과한 시각만 쓴다 (MTTR 과 구분).
        조치 효과나 Docker 설정 원복만으로는 기록되지 않는다.
        """
        return _delta(self.alert_active_at, self.service_recovered_at)

    def approval_latency(self) -> float | None:
        return _delta(self.approval_requested_at, self.approved_at)

    def action_duration(self) -> float | None:
        return _delta(self.action_started_at, self.action_verified_at)

    def recovery_duration(self) -> float | None:
        return _delta(self.recovery_started_at, self.recovery_verified_at)

    def timings(self) -> dict:
        return {
            "alert_active_at": self.alert_active_at,
            "approval_requested_at": self.approval_requested_at,
            "approved_at": self.approved_at,
            "action_started_at": self.action_started_at,
            "action_verified_at": self.action_verified_at,
            "recovery_due_at": self.recovery_due_at,
            "recovery_started_at": self.recovery_started_at,
            "recovery_verified_at": self.recovery_verified_at,
            "service_recovered_at": self.service_recovered_at,
            "restore_duration_sec": _round(_delta(self.action_started_at, self.service_recovered_at)),
            "approval_latency_sec": _round(self.approval_latency()),
            "action_duration_sec": _round(self.action_duration()),
            "recovery_duration_sec": _round(self.recovery_duration()),
            "mttr_sec": _round(self.mttr()),
            "service_recovery_sec": _round(self.time_to_service_recovery()),
        }


def _delta(start, end) -> float | None:
    a, b = _parse_ts(start), _parse_ts(end)
    if a is None or b is None:
        return None
    return b - a


def _round(value):
    return None if value is None else round(value, 3)


def jsonable(value):
    """
    JSON 으로 쓸 수 있는 형태로 바꾼다. 모르는 타입은 문자열로 남긴다.

    감사 레코드는 이 파일이 유일한 영속 근거다. 증거 스냅샷에 Docker SDK 가 준
    예상 밖의 타입이 섞여도 기록이 깨지면 안 된다 (깨지면 멱등성·복구 근거를 잃는다).
    """
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [jsonable(v) for v in value]
    return str(value)


class RecordStore:
    """조치 레코드의 영속 저장소. 프로세스 재시작 후에도 상태가 남는다."""

    def __init__(self, path: str | None = None):
        self.path = path or os.path.join(
            os.getenv(STATE_DIR_ENV, DEFAULT_STATE_DIR), STATE_FILE)
        self._lock = threading.RLock()
        self._records: dict = {}
        self._loaded = False
        self._writable = True
        self._load_error = False

    # ── 영속화 ────────────────────────────────────────────────────────────────
    def load(self) -> None:
        with self._lock:
            self._records = {}
            self._loaded = True
            if not os.path.isfile(self.path):
                return
            try:
                with open(self.path, "r", encoding="utf-8") as fh:
                    raw = json.load(fh)
            except (OSError, json.JSONDecodeError) as exc:
                # 상태 파일이 깨졌다 — 멱등성 근거를 잃었으므로 크게 남긴다.
                logger.error("[Store] 상태 파일을 읽을 수 없다 (%s): %s", self.path, exc)
                self._load_error = True
                self._writable = False
                return
            if not isinstance(raw, dict) or not isinstance(raw.get("records"), dict):
                self._load_error = True
                self._writable = False
                return
            for rid, body in (raw.get("records") or {}).items():
                try:
                    self._records[rid] = RemediationRecord(**body)
                except TypeError as exc:
                    self._load_error = True
                    self._writable = False
                    logger.warning("[Store] 레코드 건너뜀 %s: %s", rid, exc)
            logger.info("[Store] 레코드 %d건 복원: %s", len(self._records), self.path)

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.load()

    def _flush(self) -> None:
        if self._load_error:
            self._writable = False
            return
        payload = jsonable({"version": 1, "saved_at": utcnow(),
                            "records": {rid: r.as_dict()
                                        for rid, r in self._records.items()}})
        directory = os.path.dirname(self.path) or "."
        try:
            os.makedirs(directory, exist_ok=True)
            # 원자적 교체 — 쓰다가 죽어도 반쪽 파일이 남지 않는다.
            fd, tmp = tempfile.mkstemp(prefix=".remediation_", dir=directory)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh, ensure_ascii=False, indent=2)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, self.path)
                # Persist the directory entry as well as file bytes before a
                # successful claim can release a Docker command. Windows has
                # no portable directory fsync; production Controller is Linux.
                if os.name != "nt":
                    dir_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                    try:
                        os.fsync(dir_fd)
                    finally:
                        os.close(dir_fd)
            except Exception:
                if os.path.exists(tmp):
                    os.unlink(tmp)
                raise
        except OSError as exc:
            if self._writable:
                logger.error("[Store] 상태를 저장할 수 없다 (%s): %s — 재시작 후 "
                             "멱등성·TTL 복구 근거가 사라진다", self.path, exc)
                self._writable = False

    @property
    def writable(self) -> bool:
        """저장이 가능한지. 불가하면 위험한 조치를 막는 근거가 된다."""
        return self._writable

    def check_writable(self) -> bool:
        """실제로 한 번 써 보고 저장 가능 여부를 갱신한다."""
        with self._lock:
            self._ensure_loaded()
            self._writable = True
            self._flush()
            return self._writable

    # ── 조회·생성 ─────────────────────────────────────────────────────────────
    def get(self, remediation_id: str):
        with self._lock:
            self._ensure_loaded()
            return self._records.get(remediation_id)

    def all(self) -> list:
        with self._lock:
            self._ensure_loaded()
            return list(self._records.values())

    def new_id(self) -> str:
        return uuid.uuid4().hex

    def _persist_change(self, before) -> bool:
        self._flush()
        if not self._writable:
            # Never acknowledge an in-memory transition that was not durable.
            self._records = before
            return False
        return True

    def create(self, record: RemediationRecord):
        with self._lock:
            self._ensure_loaded()
            if not self._writable or record.remediation_id in self._records:
                return None
            before = copy.deepcopy(self._records)
            self._records[record.remediation_id] = record
            return record if self._persist_change(before) else None

    def get_or_create(self, record: RemediationRecord):
        with self._lock:
            self._ensure_loaded()
            existing = self._records.get(record.remediation_id)
            if existing is not None:
                return existing, False
            created = self.create(record)
            return created, created is not None

    def get_or_create_incident(self, record: RemediationRecord):
        """Ordinary retransmission never creates an implicit revision or stage."""
        with self._lock:
            self._ensure_loaded()
            if not record.incident_key or not record.action_hash:
                raise ValueError("incident_and_action_hash_required")
            incident = [r for r in self._records.values() if r.incident_key == record.incident_key]
            for existing in sorted(incident, key=lambda r:r.revision, reverse=True):
                if (not existing.superseded_by and existing.action_hash == record.action_hash
                        and existing.plan_hash == record.plan_hash and existing.recovery_of is None):
                    return existing, False
            if incident:
                raise IncidentConflict("incident_action_conflict")
            created = self.create(record)
            return created, created is not None

    @staticmethod
    def execution_confirmed(record):
        return bool(record and record.state in (VERIFIED, RECOVERED, RECOVERY_PENDING, RECOVERY_APPROVAL_REQUIRED)
                    and record.action_verified_at and record.results
                    and all(r.get("status") == "SUCCESS" and r.get("verified") is True for r in record.results))

    def create_linked(self, record, previous_id, kind):
        """Persist a manual revision/next-stage/recovery and its link atomically."""
        with self._lock:
            self._ensure_loaded()
            previous = self._records.get(previous_id)
            if previous is None or previous.incident_key != record.incident_key:
                raise IncidentConflict("linked_incident_mismatch")
            if kind not in ("replan", "advance", "recovery"):
                raise ValueError("invalid_record_link")
            field = {"replan":"superseded_by", "advance":"next_step_id", "recovery":"recovery_request_id"}[kind]
            existing = self._records.get(getattr(previous, field))
            if existing:
                if existing.action_hash != record.action_hash or existing.plan_hash != record.plan_hash:
                    raise IncidentConflict("linked_action_conflict")
                return existing, False
            if not self._writable:
                return None, False
            unsafe = (EXECUTING, RECOVERING, UNKNOWN, RECOVERY_UNKNOWN, NEEDS_REVIEW)
            if previous.state in unsafe or previous.superseded_by:
                raise IncidentConflict("previous_execution_unresolved_or_superseded")
            if any(getattr(previous, f) for f in ("superseded_by", "next_step_id", "recovery_request_id") if f != field):
                raise IncidentConflict("later_plan_or_recovery_already_exists")
            if kind in ("advance", "recovery") and not self.execution_confirmed(previous):
                raise IncidentConflict("previous_execution_not_verified")
            if kind == "replan" and previous.next_step_id:
                raise IncidentConflict("later_stage_already_exists")
            if kind == "advance" and (not previous.plan_steps or record.plan_step != previous.plan_step + 1
                                      or record.plan_step >= len(previous.plan_steps)):
                raise IncidentConflict("invalid_next_plan_stage")
            if kind == "recovery" and previous.next_step_id:
                raise IncidentConflict("later_stage_already_exists")
            before = copy.deepcopy(self._records)
            record.requires_approval = True
            record.revision = 1 + max((r.revision for r in self._records.values()
                                     if r.incident_key == record.incident_key), default=0)
            if kind == "replan":
                record.supersedes_id = previous_id
                if previous.state in (PROPOSED, AWAITING_APPROVAL, APPROVED):
                    previous.state = SUPERSEDED
            elif kind == "advance":
                record.predecessor_id = previous_id
            else:
                record.recovery_of = previous_id
            setattr(previous, field, record.remediation_id)
            previous.updated_at = utcnow()
            self._records[record.remediation_id] = record
            if not self._persist_change(before):
                return None, False
            return record, True

    def update(self, remediation_id: str, **fields):
        with self._lock:
            self._ensure_loaded()
            record = self._records.get(remediation_id)
            if record is None or not self._writable:
                return None
            if any(key not in record.__dataclass_fields__ for key in fields):
                raise ValueError("unknown_record_field")
            before = copy.deepcopy(self._records)
            for key, value in fields.items():
                setattr(record, key, value)
            record.updated_at = utcnow()
            return record if self._persist_change(before) else None

    def expire_approval(self, remediation_id: str, now=None) -> bool:
        with self._lock:
            self._ensure_loaded()
            record = self._records.get(remediation_id)
            if record is None or record.state not in (AWAITING_APPROVAL, APPROVED):
                return False
            if approval_valid(record, now):
                return False
            return self.update(remediation_id, state=EXPIRED) is not None

    def mark_approved(self, remediation_id: str, approved_by: str):
        """Only one pending approval/rejection transition may win."""
        with self._lock:
            self._ensure_loaded()
            record = self._records.get(remediation_id)
            if record is None or record.state != AWAITING_APPROVAL or not approved_by:
                return None
            if record.predecessor_id and not self.execution_confirmed(self._records.get(record.predecessor_id)):
                return None
            if not approval_valid(record):
                self.expire_approval(remediation_id)
                return None
            return self.update(remediation_id, state=APPROVED,
                               approved_by=approved_by, approved_at=utcnow())

    def update_if_state(self, remediation_id, expected_state, **fields):
        with self._lock:
            self._ensure_loaded()
            record = self._records.get(remediation_id)
            if record is None or record.state != expected_state:
                return record
            return self.update(remediation_id, **fields)

    def mark_rejected(self, remediation_id: str, rejected_by: str) -> bool:
        with self._lock:
            self._ensure_loaded()
            record = self._records.get(remediation_id)
            if record is None or record.state != AWAITING_APPROVAL:
                return False
            if not approval_valid(record):
                self.expire_approval(remediation_id)
                return False
            return self.update(remediation_id, state=REJECTED,
                               rejected_by=rejected_by, rejected_at=utcnow()) is not None

    def claim_execution(self, remediation_id: str) -> tuple[bool, str]:
        """Persist execution ownership; manual paths also require live approval."""
        with self._lock:
            self._ensure_loaded()
            if not self._writable:
                return False, "store_not_writable"
            record = self._records.get(remediation_id)
            if record is None:
                return False, "unknown_remediation_id"
            if record.state in TERMINAL_EXECUTION_STATES:
                return False, f"already_{record.state.lower()}"
            if record.superseded_by:
                return False, "record_superseded"
            if record.predecessor_id and not self.execution_confirmed(self._records.get(record.predecessor_id)):
                return False, "previous_execution_not_verified"
            if record.recovery_of and not self.execution_confirmed(self._records.get(record.recovery_of)):
                return False, "recovery_origin_not_verified"
            if record.requires_approval:
                if record.state != APPROVED or not record.approved_by or not record.approved_at:
                    return False, "valid_approval_required"
                if not approval_valid(record):
                    self.expire_approval(remediation_id)
                    return False, "approval_expired"
            elif record.state != PROPOSED:
                return False, "automatic_proposal_required"
            saved = self.update(remediation_id, state=EXECUTING, action_started_at=utcnow())
            return bool(saved), "claimed" if saved else "store_not_writable"

    def claim_recovery(self, remediation_id, approved=False):
        with self._lock:
            self._ensure_loaded()
            record = self._records.get(remediation_id)
            if not self._writable or record is None:
                return False
            if record.state not in (RECOVERY_PENDING, RECOVERY_APPROVAL_REQUIRED):
                return False
            if record.recovery_mode == "require_approval":
                if not approved or not record.recovery_approved_by or not approval_valid(record, recovery=True):
                    return False
            return self.update(remediation_id, state=RECOVERING,
                               recovery_started_at=utcnow()) is not None

    def reconcile_interrupted(self):
        """Never retry uncertain mutations or discard orphaned recovery evidence."""
        with self._lock:
            self._ensure_loaded()
            changed = []
            for record in self._records.values():
                if record.state in (EXECUTING, RECOVERING) or (
                    record.state == FAILED and record.evidence
                ):
                    record.state = NEEDS_REVIEW
                    changed.append(record.remediation_id)
                elif record.state == VERIFIED and record.recovery_mode not in (None, "none"):
                    record.state = RECOVERY_APPROVAL_REQUIRED
                    changed.append(record.remediation_id)
            if changed:
                self._flush()
                logger.error("[Store] manual reconciliation required: %s", changed)
            return changed

    # ── TTL ───────────────────────────────────────────────────────────────────
    def due_recoveries(self, now: float | None = None) -> list:
        """TTL 이 지난 레코드. 복구 대기 상태만 대상으로 한다."""
        now = time.time() if now is None else now
        out = []
        for record in self.all():
            if record.state != RECOVERY_PENDING:
                continue
            due = _parse_ts(record.recovery_due_at)
            if due is not None and due <= now:
                out.append(record)
        return out
