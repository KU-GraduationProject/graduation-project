"""
증거·상태 보존 (Phase 2).

조치 전에 "되돌리는 데 필요한 것"과 "나중에 조사할 때 필요한 것"을 모아 둔다.
  - 컨테이너 ID·이름·이미지
  - Docker 네트워크 ID·이름·IP·alias
  - CPU·메모리 제한값
  - 조치 전 상태(running/paused/started_at)
  - remediation_id 와 수집 시각

보존에 실패하면 되돌릴 수 없는 격리·동결이 되므로 그런 조치는 실행하지 않는다.
증거는 조치 레코드와 함께 영속 저장되고(store.py), 재시작 후 복구에 쓰인다.
"""

from __future__ import annotations

import logging

from executor.base import ExecutorError
from executor.local_docker import restorable
from store import utcnow

logger = logging.getLogger(__name__)

# 이 조치들은 되돌리기 위해 조치 전 상태가 반드시 필요하다.
EVIDENCE_REQUIRED_ACTIONS = ("ISOLATE", "PAUSE", "THROTTLE")
# 격리는 네트워크 IP·alias 까지 있어야 복구 가능하다.
RESTORABLE_REQUIRED_ACTIONS = ("ISOLATE",)


class EvidenceError(RuntimeError):
    """증거를 보존할 수 없다 — 위험한 조치를 차단하는 근거."""


def collect(executor, remediation_id: str, action_type: str, targets) -> dict:
    """
    대상별 상태를 수집해 증거 묶음을 만든다. 수집 실패 시 EvidenceError.
    """
    targets = [t for t in (targets or ()) if t]
    if not targets:
        raise EvidenceError("no_targets_to_snapshot")

    snapshots = {}
    for target in targets:
        try:
            snap = executor.snapshot(target)
        except ExecutorError as exc:
            raise EvidenceError(f"snapshot_failed:{target}:{exc}") from exc
        except Exception as exc:
            raise EvidenceError(f"snapshot_error:{target}:{type(exc).__name__}:{exc}") from exc
        snapshots[target] = snap

    return {
        "remediation_id": remediation_id,
        "action_type": str(action_type).upper(),
        "collected_at": utcnow(),
        "executor": getattr(executor, "name", "unknown"),
        "targets": snapshots,
    }


def verify_usable(evidence: dict, action_type: str) -> tuple[bool, str]:
    """
    모은 증거로 이 조치를 되돌릴 수 있는지 검사한다.
    반환: (사용 가능, 사유).
    """
    action = str(action_type).upper()
    targets = (evidence or {}).get("targets") or {}
    if not targets:
        return False, "evidence_missing_targets"

    for target, snap in targets.items():
        if not snap.get("available", False):
            return False, f"evidence_unavailable:{target}"
        if not snap.get("container_id"):
            return False, f"evidence_missing_container_id:{target}"
        if action in RESTORABLE_REQUIRED_ACTIONS:
            ok, why = restorable(snap)
            if not ok:
                return False, f"{why}:{target}"
        if action == "THROTTLE" and "cpu_quota" not in (snap.get("resources") or {}):
            return False, f"evidence_missing_resources:{target}"
    return True, "ok"


def requires_evidence(action_type: str) -> bool:
    return str(action_type).upper() in EVIDENCE_REQUIRED_ACTIONS


def for_target(evidence: dict, target: str) -> dict:
    """실행기에 넘길 대상 1개의 증거."""
    return ((evidence or {}).get("targets") or {}).get(target) or {}


def gate(executor, store, remediation_id: str, action_type: str, targets):
    """
    조치 전 증거 게이트. 반환: (증거 dict, 차단 사유 또는 None).

    저장소에 쓸 수 없으면 가역 조치를 차단한다 — 재시작하면 복구 근거가 사라져
    격리를 되돌릴 수 없게 된다.
    """
    action = str(action_type).upper()
    if getattr(executor, "evidence_at_agent", False):
        return {}, None
    if not requires_evidence(action):
        return {}, None
    if not getattr(executor, "changes_system", True):
        # 실행기가 아무것도 바꾸지 않는다 (disabled) — 보존할 상태가 없다.
        # 게이트를 통과시켜, 실행하지 않은 이유가 '모드' 로 일관되게 기록되게 한다.
        return {}, None

    if store is not None and not store.writable:
        return {}, "evidence_store_not_writable"

    try:
        evidence = collect(executor, remediation_id, action, targets)
    except EvidenceError as exc:
        return {}, str(exc)

    ok, why = verify_usable(evidence, action)
    if not ok:
        return evidence, why
    return evidence, None
