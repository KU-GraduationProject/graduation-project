"""
TTL 복구와 MTTR 기록 (Phase 2).

조치를 되돌리는 주체. 정책이 정한 recovery_mode 에 따라 다르게 동작한다.

    auto              — TTL 만료 시 자동 복구 (THROTTLE: 원래 CPU 쿼터로 원복)
    require_approval  — TTL 만료 시 자동 복구하지 않고 복구 승인을 요청한다
    none              — 복구 대상이 아니다 (RESTART)

ISOLATE 가 require_approval 인 이유: 공격이 진행 중이라면 TTL 만료 자동 재연결은
공격을 재개시킨다. 격리는 사람이 "이제 풀어도 된다" 고 판단해야 풀린다.

복구도 실행과 같은 규칙을 따른다 — 상태를 다시 조회해 확인되지 않으면 성공으로
기록하지 않는다. MTTR 은 복구를 '확인한' 시각으로만 계산한다.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone

import evidence as evidence_mod
import store as store_mod
from executor.base import RECOVERY_ACTION, SUCCESS

logger = logging.getLogger(__name__)

AUTO = "auto"
REQUIRE_APPROVAL = "require_approval"
NONE = "none"


def recovery_due_at(ttl_seconds: int | None, now: float | None = None) -> str | None:
    if not ttl_seconds:
        return None
    base = datetime.now(timezone.utc) if now is None else \
        datetime.fromtimestamp(now, timezone.utc)
    return (base + timedelta(seconds=ttl_seconds)).isoformat()


def schedule(store, record, ttl_seconds: int | None, recovery_mode: str | None,
             now: float | None = None):
    """
    조치 검증 후 복구 일정을 건다. TTL 이 없거나 복구 대상이 아니면 아무것도 하지 않는다.
    """
    mode = (recovery_mode or NONE)
    if mode == NONE or not ttl_seconds:
        return store.update(record.remediation_id, recovery_mode=mode)
    return store.update(
        record.remediation_id,
        state=store_mod.RECOVERY_PENDING,
        recovery_mode=mode,
        ttl_seconds=ttl_seconds,
        recovery_due_at=recovery_due_at(ttl_seconds, now),
    )


def recover(store, executor, record, approved_by: str | None = None,
            force: bool = False) -> tuple[list, str]:
    """
    복구를 실행한다. 반환: (ExecutionResult 목록, 최종 상태).

    force=True 는 '사람이 복구를 승인했다' 는 뜻이다. require_approval 조치는
    force 없이는 복구되지 않는다 (TTL 만료만으로 자동 재연결하지 않는다).
    """
    mode = record.recovery_mode or NONE
    recovery_action = RECOVERY_ACTION.get(str(record.action_type).upper())

    if recovery_action is None:
        store.update(record.remediation_id, recovery_mode=NONE)
        return [], store_mod.RECOVERED   # 되돌릴 것이 없다 (RESTART 등)

    if not getattr(executor, "changes_system", True):
        return [], record.state
    if record.executor_name == "remote" and executor.name != "remote":
        return [], record.state  # Never recover a PC 2 action using PC 1 Docker.
    if executor.name == "remote" and record.executor_name != "remote":
        return [], record.state
    if executor.name == "remote" and not force:
        # Agent owns THROTTLE TTL. PC 1 only polls it; isolation still needs approval.
        if mode == REQUIRE_APPROVAL and record.state == store_mod.RECOVERY_PENDING:
            store.update(record.remediation_id, state=store_mod.RECOVERY_APPROVAL_REQUIRED)
        return [], record.state
    if record.state not in (store_mod.RECOVERY_PENDING, store_mod.RECOVERY_APPROVAL_REQUIRED):
        return [], record.state

    if mode == REQUIRE_APPROVAL and not force:
        # 자동 복구하지 않는다. 승인 요청 상태로 바꾸고 멈춘다.
        store.update(record.remediation_id,
                     state=store_mod.RECOVERY_APPROVAL_REQUIRED)
        logger.info("[Recovery] %s %s: TTL 만료 — 자동 복구하지 않고 재승인 요청",
                    record.action_type, record.targets)
        return [], store_mod.RECOVERY_APPROVAL_REQUIRED

    if not store.claim_recovery(record.remediation_id, approved=force):
        return [], record.state
    store.update(record.remediation_id, state=store_mod.RECOVERING,
                 recovery_started_at=store_mod.utcnow(),
                 recovery_approved_by=approved_by,
                 approved_by=record.approved_by or approved_by)

    results = []
    for target in record.targets:
        target_evidence = evidence_mod.for_target(record.evidence, target)
        if executor.name == "remote":
            results.append(executor.execute_record(record, target, approved_by, recovery_action))
        else:
            results.append(executor.execute(recovery_action, target, target_evidence))

    if any(r.status == "UNKNOWN" for r in results):
        store.update(record.remediation_id, state=store_mod.RECOVERY_UNKNOWN,
                     recovery_results=[r.as_dict() for r in results])
        return results, store_mod.RECOVERY_UNKNOWN

    all_ok = bool(results) and all(r.status == SUCCESS and r.verified for r in results)
    if all_ok:
        verified_at = store_mod.utcnow()
        if executor.name == "remote":
            timestamps = [r.after.get("remote", {}).get("recovery_verified_at") for r in results]
            if all(timestamps):
                verified_at = executor.iso(max(timestamps))
        store.update(record.remediation_id, state=store_mod.RECOVERED,
                     recovery_verified_at=verified_at,
                     recovery_results=[r.as_dict() for r in results])
        return results, store_mod.RECOVERED

    # 확인되지 않은 복구는 성공으로 기록하지 않는다. recovery_verified_at 을
    # 비워 두므로 MTTR 도 계산되지 않는다 (없는 값을 만들지 않는다).
    store.update(record.remediation_id, state=store_mod.RECOVERY_FAILED,
                 recovery_results=[r.as_dict() for r in results])
    return results, store_mod.RECOVERY_FAILED


def run_due(store, executor, now: float | None = None) -> list:
    """
    TTL 이 지난 레코드를 처리한다. 반환: (레코드, 결과목록, 상태) 목록.
    auto 는 복구하고, require_approval 은 승인 요청 상태로만 바꾼다.
    """
    processed = []
    if executor.name == "remote":
        from executor.remote_sync import reconcile
        for record in store.all():
            if record.executor_name == "remote" and record.state not in (store_mod.RECOVERED, store_mod.SKIPPED, store_mod.BLOCKED):
                reconcile(store, executor, record)
    for record in store.due_recoveries(now=now):
        results, state = recover(store, executor, record)
        processed.append((record, results, state))
    return processed


class TtlScanner:
    """
    주기적으로 TTL 을 확인하는 백그라운드 루프. 실행은 run_due 가 하고, 이 클래스는
    간격과 예외 처리만 담당한다 (테스트는 run_due 를 직접 호출한다).
    """

    def __init__(self, store, executor, interval_sec: float = 60.0, on_event=None):
        self.store = store
        self.executor = executor
        self.interval_sec = interval_sec
        self.on_event = on_event
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    async def run(self) -> None:
        import asyncio
        while not self._stop:
            try:
                for record, results, state in await asyncio.to_thread(run_due, self.store, self.executor):
                    logger.info("[Recovery] TTL 처리: %s %s -> %s",
                                record.action_type, record.targets, state)
                    if self.on_event is not None:
                        await self.on_event(record, results, state)
            except Exception as exc:   # 루프가 죽으면 복구가 영구히 멈춘다
                logger.error("[Recovery] TTL 스캔 실패 (계속): %s", exc)
            await asyncio.sleep(self.interval_sec)


def timings_event(record) -> dict:
    """감사 로그용 시간 지표 묶음."""
    return {
        "remediation_id": record.remediation_id,
        "alert": record.alertname,
        "action_type": record.action_type,
        "targets": list(record.targets),
        "state": record.state,
        **record.timings(),
    }


def now_ts() -> float:
    return time.time()
