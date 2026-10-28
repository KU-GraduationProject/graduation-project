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
SKIPPED = "SKIPPED"
RECOVERY_PENDING = "RECOVERY_PENDING"
RECOVERY_APPROVAL_REQUIRED = "RECOVERY_APPROVAL_REQUIRED"
RECOVERING = "RECOVERING"
RECOVERED = "RECOVERED"
RECOVERY_FAILED = "RECOVERY_FAILED"
NEEDS_REVIEW = "NEEDS_REVIEW"

# 조치가 끝나 더 이상 실행하지 않아야 하는 상태 (멱등성 판정용)
TERMINAL_EXECUTION_STATES = (
    EXECUTING, VERIFIED, FAILED, BLOCKED, SKIPPED, REJECTED,
    RECOVERY_PENDING, RECOVERY_APPROVAL_REQUIRED, RECOVERING, RECOVERED,
    RECOVERY_FAILED, NEEDS_REVIEW,
)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_ts(value) -> float | None:
    if not value:
        return None
    try:
        text = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


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
    source: str | None = None
    evidence: dict = field(default_factory=dict)
    results: list = field(default_factory=list)
    recovery_results: list = field(default_factory=list)
    # MTTR 계산용 타임스탬프
    alert_active_at: str | None = None
    approval_requested_at: str | None = None
    approved_at: str | None = None
    action_started_at: str | None = None
    action_verified_at: str | None = None
    recovery_due_at: str | None = None
    recovery_started_at: str | None = None
    recovery_verified_at: str | None = None
    created_at: str = field(default_factory=utcnow)
    updated_at: str = field(default_factory=utcnow)

    def as_dict(self) -> dict:
        return asdict(self)

    # ── 파생 시간 지표 ────────────────────────────────────────────────────────
    def time_to_contain(self) -> float | None:
        """경보 발생 → 조치 검증 완료. '조치 완료까지의 시간' (MTTR 과 구분)."""
        return _delta(self.alert_active_at, self.action_verified_at)

    def mttr(self) -> float | None:
        """
        MTTR = t_recovered - t_alert_activeAt.
        t_recovered 는 복구를 '상태 재조회로 확인한' 시각이며 호출 성공 시각이 아니다.
        """
        return _delta(self.alert_active_at, self.recovery_verified_at)

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
            "approval_latency_sec": _round(self.approval_latency()),
            "action_duration_sec": _round(self.action_duration()),
            "time_to_contain_sec": _round(self.time_to_contain()),
            "recovery_duration_sec": _round(self.recovery_duration()),
            "mttr_sec": _round(self.mttr()),
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

    def create(self, record: RemediationRecord) -> RemediationRecord:
        with self._lock:
            self._ensure_loaded()
            self._records[record.remediation_id] = record
            self._flush()
            return record

    def get_or_create(self, record: RemediationRecord) -> tuple[RemediationRecord, bool]:
        """이미 있으면 그것을 돌려준다. 반환: (레코드, 새로 만들었는가)."""
        with self._lock:
            self._ensure_loaded()
            existing = self._records.get(record.remediation_id)
            if existing is not None:
                return existing, False
            self._records[record.remediation_id] = record
            self._flush()
            return record, True

    def update(self, remediation_id: str, **fields):
        with self._lock:
            self._ensure_loaded()
            record = self._records.get(remediation_id)
            if record is None:
                return None
            for key, value in fields.items():
                setattr(record, key, value)
            record.updated_at = utcnow()
            self._flush()
            return record

    def mark_approved(self, remediation_id: str, approved_by: str):
        """
        승인 사실을 기록한다. 이미 실행에 들어간(또는 끝난) 레코드의 상태는 되돌리지
        않는다 — 상태를 APPROVED 로 덮으면 두 번째 승인이 다시 실행 권리를 얻는다.
        """
        with self._lock:
            self._ensure_loaded()
            record = self._records.get(remediation_id)
            if record is None:
                return None
            record.approved_by = approved_by
            record.approved_at = record.approved_at or utcnow()
            if record.state in (PROPOSED, AWAITING_APPROVAL):
                record.state = APPROVED
            record.updated_at = utcnow()
            self._flush()
            return record

    # ── 멱등성 ────────────────────────────────────────────────────────────────
    def claim_execution(self, remediation_id: str) -> tuple[bool, str]:
        """
        이 조치를 실행할 권리를 '선점' 한다. 반환: (선점 성공, 사유).

        같은 remediation_id 로 두 번째 승인이 와도 False 가 돌아간다 — 실행은 한 번뿐이다.
        선점과 상태 전이를 같은 Lock 안에서 처리하므로 동시 요청에도 한쪽만 통과한다.
        """
        with self._lock:
            self._ensure_loaded()
            if not self._writable:
                return False, "store_not_writable"
            record = self._records.get(remediation_id)
            if record is None:
                return False, "unknown_remediation_id"
            if record.state in TERMINAL_EXECUTION_STATES:
                return False, f"already_{record.state.lower()}"
            record.state = EXECUTING
            record.action_started_at = utcnow()
            record.updated_at = record.action_started_at
            self._flush()
            return self._writable, "claimed" if self._writable else "store_not_writable"

    def claim_recovery(self, remediation_id, approved=False):
        with self._lock:
            self._ensure_loaded()
            record = self._records.get(remediation_id)
            if not self._writable or record is None:
                return False
            if record.state not in (RECOVERY_PENDING, RECOVERY_APPROVAL_REQUIRED):
                return False
            if record.recovery_mode == "require_approval" and not approved:
                return False
            record.state = RECOVERING
            record.recovery_started_at = utcnow()
            self._flush()
            return self._writable

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
