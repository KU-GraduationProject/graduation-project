"""F2-c: verified ordinary connection rejection, hold, and run-scoped recovery.

Docker socket and Windows Host TCP use the same lifecycle. See F2C_RUNTIME.md.
Only existing sessions are opened/closed; no data, schema, or server settings change.
"""
from __future__ import annotations

import os
import secrets
import time

from v2 import supervisor
from v2.f2c_runtime import Psql, RuntimeFailure, Target, spawn_watchdog, stop_clients

DEFAULT_STRENGTH = "medium"
DEFAULT_MAX_SECONDS = 420
BACKGROUND_DEFAULT = True
RECOVER_SLACK = 2
RECOVERY_BUDGET = 20
STRENGTH_PROFILE = {
    "weak": {"fill_fraction": 0.9, "open_interval_s": 1.0, "hold_seconds": 180},
    "medium": {"fill_fraction": 1.0, "open_interval_s": 0.5, "hold_seconds": 240},
    "strong": {"fill_fraction": 1.0, "open_interval_s": 0.1, "hold_seconds": 360},
}


def usable_slots(max_conn: int, reserved: int, current: int,
                 reserved_connections: int = 0) -> int:
    """Return ordinary slots left after both reserves and the observer-free count."""
    return max_conn - reserved - reserved_connections - current


def target_for_strength(usable: int, strength: str = DEFAULT_STRENGTH) -> int:
    """Choose a nonnegative fill target within usable slots; reject unknown strengths."""
    if strength not in STRENGTH_PROFILE:
        raise ValueError("unknown strength")
    return max(0, int(usable * STRENGTH_PROFILE[strength]["fill_fraction"]))


def rejection_expected(strength: str = DEFAULT_STRENGTH) -> bool:
    """Return whether the strength requires rejection rather than pressure alone."""
    if strength not in STRENGTH_PROFILE:
        raise ValueError("unknown strength")
    return STRENGTH_PROFILE[strength]["fill_fraction"] >= 1.0


def should_abort(usable: int, min_slots: int = 1) -> bool:
    """Report whether too few ordinary slots remain to start the injection."""
    return usable < min_slots


def reserved_untouched(total_now: int, max_conn: int, reserved: int,
                       reserved_connections: int = 0) -> bool:
    """Check an observer-free session count against the ordinary connection limit."""
    return total_now <= max_conn - reserved - reserved_connections


def connections_recovered(after: int, baseline: int, slack: int = RECOVER_SLACK) -> bool:
    """Compare counts with a baseline; this check alone does not prove recovery."""
    return after <= baseline + slack


def hold_seconds_for(strength: str = DEFAULT_STRENGTH) -> int:
    """Return the strength's default hold duration or reject an unknown strength."""
    if strength not in STRENGTH_PROFILE:
        raise ValueError("unknown strength")
    return STRENGTH_PROFILE[strength]["hold_seconds"]


def new_run_id() -> str:
    """Generate a random 128-bit ID to distinguish this run's sessions and worker."""
    return secrets.token_hex(16)


def run_mark(run_id: str) -> str:
    """Prefix a run ID for session marking and reject unsafe identifier characters."""
    from v2.f2c_runtime import identifier
    return identifier(f"connhold-{run_id}")


def _budget(meta: dict) -> None:
    """Require a live worker and enough remaining time for a full hold and recovery."""
    _watchdog_alive(meta)
    if time.monotonic() + meta["hold_seconds"] + RECOVERY_BUDGET >= meta["deadline"]:
        raise RuntimeFailure("insufficient watchdog budget for the complete hold interval")


def _watchdog_alive(meta: dict) -> None:
    """Fail if the tracked recovery worker exits before normal cleanup."""
    proc = (meta.get("watchdog") or {}).get("process")
    if proc is not None and proc.poll() is not None:
        raise RuntimeFailure("recovery worker exited before cleanup")


def _verified(meta: dict) -> dict:
    """Return the occupancy snapshot only if owned counts and login outcome match.

    Medium/strong also require the global ordinary limit to be reached; a login
    error alone cannot establish cluster exhaustion. Weak requires acceptance.
    """
    _watchdog_alive(meta)
    snapshot = meta["db"].snapshot(meta["mark"])
    if snapshot["owned"] != meta["held"] or snapshot["total"] > meta["ordinary_limit"]:
        raise RuntimeFailure("session occupancy changed or reserved capacity is in use")
    expected = "rejected" if rejection_expected(meta["strength"]) else "accepted"
    actual = meta["db"].probe(meta["mark"])
    if actual != expected:
        raise RuntimeFailure("ordinary connection outcome not verified")
    if expected == "rejected" and snapshot["total"] < meta["ordinary_limit"]:
        raise RuntimeFailure("connection rejected without verified cluster slot exhaustion")
    return snapshot


def inject(strength: str = DEFAULT_STRENGTH, hold_seconds: int | None = None,
           max_seconds: int | None = None, work_dir: str | None = None,
           background: bool | None = None, traffic_gen_path: str | None = None,
           traffic_target: str | None = None, traffic_run_dir: str | None = None,
           target: Target | None = None):
    """Open and verify run-owned sessions on the explicitly confirmed test target.

    Start an independent recovery worker before opening any holder. Return the
    metadata needed by hold and cleanup; this function does not wait through the
    hold interval. On any exception, attempt cleanup of partially opened sessions
    and retain the worker if recovery cannot be verified.
    """
    if strength not in STRENGTH_PROFILE:
        raise ValueError("unknown strength")
    if max_seconds is None:
        max_seconds = int(os.environ.get("F2C_MAX_SECONDS", DEFAULT_MAX_SECONDS))
    hold_seconds = hold_seconds_for(strength) if hold_seconds is None else hold_seconds
    if (not isinstance(hold_seconds, int) or hold_seconds < 1
            or max_seconds <= hold_seconds + RECOVERY_BUDGET):
        raise ValueError("hold_seconds must fit within max_seconds and the recovery budget")
    # Even API callers supplying a Target must explicitly authorize that exact target.
    target = target or Target.from_env()
    if os.environ.get("F2C_CONFIRM_TARGET") != target.confirmation:
        raise RuntimeFailure("F2C_CONFIRM_TARGET must match the selected test cluster")
    mark = run_mark(new_run_id())
    db = Psql(target)
    info = db.preflight(mark)
    baseline = db.snapshot(mark)["total"]  # Observer excludes its own transient backend.
    limit = info["max_conn"] - info["super_reserved"] - info["reserved"]
    usable = limit - baseline
    if should_abort(usable):
        raise RuntimeFailure("no ordinary slots available before injection")
    goal = target_for_strength(usable, strength)
    if goal < 1:
        raise RuntimeFailure("no sessions in this pressure plan")
    meta = {"db": db, "mark": mark, "strength": strength, "baseline": baseline,
            "ordinary_limit": limit, "held": 0, "clients": [], "watchdog": None,
            "background": None, "hold_seconds": hold_seconds,
            "deadline": time.monotonic() + max_seconds, "rejection_confirmed": False}
    try:
        _budget(meta)
        # The independently running recovery worker must be ready BEFORE opening any holder.
        meta["watchdog"] = spawn_watchdog(target, mark, max_seconds, work_dir)
        if supervisor.background_enabled(BACKGROUND_DEFAULT, background) and traffic_target:
            meta["background"] = supervisor.spawn_background_traffic(
                traffic_gen_path, traffic_target, run_dir=traffic_run_dir, duration=max_seconds)
        for _ in range(goal):
            _budget(meta)
            before = db.snapshot(mark)
            if before["total"] >= limit:
                break  # Concurrent ordinary traffic used a slot; never enter a reserve.
            proc = db.start_holder(mark, max_seconds)
            meta["clients"].append(proc)  # Track immediately, including partial failures.
            until = time.monotonic() + 10
            while True:
                now = db.snapshot(mark)
                if now["owned"] == meta["held"] + 1:
                    meta["held"] += 1
                    meta["last_open_at"] = time.monotonic()
                    break
                if proc.poll() is not None or time.monotonic() >= until:
                    raise RuntimeFailure("session client did not establish the expected connection")
                time.sleep(0.1)
            time.sleep(STRENGTH_PROFILE[strength]["open_interval_s"])
        if not meta["held"]:
            raise RuntimeFailure("no run-owned sessions were established")
        _budget(meta)
        meta["snapshot"] = _verified(meta)
        _budget(meta)
        meta["verified_at"] = time.monotonic()
        meta["hold_started_at"] = max(meta["last_open_at"], meta["verified_at"])
        meta["rejection_confirmed"] = rejection_expected(strength)
        print(f"[F2-c] held={meta['held']} total={meta['snapshot']['total']} "
              f"ordinary_limit={limit} rejection_confirmed={meta['rejection_confirmed']} "
              f"mark={mark} hold={hold_seconds}s", flush=True)
        return meta
    except BaseException:
        cleanup(meta)
        raise


def hold(meta: dict) -> None:
    """Maintain and periodically recheck the fault for the full verified hold time.

    Raise RuntimeFailure if occupancy, the ordinary login outcome, or recovery
    readiness changes. Record elapsed time only after the entire hold completes.
    """
    until = meta["hold_started_at"] + meta["hold_seconds"]
    while time.monotonic() < until:
        if time.monotonic() + RECOVERY_BUDGET >= meta["deadline"]:
            raise RuntimeFailure("watchdog deadline reached before hold completed")
        time.sleep(min(5, max(0, until - time.monotonic())))
        _verified(meta)  # Fail if an early session exit or a successful new login breaks the fault.
    meta["hold_completed"] = True
    meta["hold_elapsed_seconds"] = time.monotonic() - meta["hold_started_at"]


def cleanup(meta: dict | None = None) -> bool:
    """Attempt run-scoped recovery, stop tracked clients, and report verification.

    Return True only when restore confirms no owned sessions and a successful
    ordinary login. Cancel the watchdog only on that verified recovery; otherwise
    leave it available to retry. Missing metadata authorizes no session cleanup.
    """
    if not meta:
        return False  # No run ID means no termination is authorized.
    recovered = False
    try:
        for _ in range(3):
            try:
                if meta["db"].restore(meta["mark"]):
                    recovered = True
                    break
            except Exception:
                pass
            time.sleep(0.2)
    finally:
        stop_clients(meta.get("clients", []))
        if recovered:
            supervisor.cancel_watchdog(meta.get("watchdog"))
        supervisor.stop_background_traffic(meta.get("background"))
    print(f"[F2-c] cleanup mark={meta['mark']} recovered={recovered} "
          f"watchdog_retained={not recovered}", flush=True)
    return recovered


def dry_run() -> dict:
    """Describe transport choices and success criteria without opening connections."""
    return {"modes": ["docker (local socket)", "host (TCP, Windows supported)"],
            "usable_formula": "max_connections - reserved_connections - superuser_reserved_connections - current_without_observer",
            "strength_profile": STRENGTH_PROFILE, "restart_backend": False,
            "success": "verified occupancy + ordinary login outcome + complete hold + recovery",
            "target": "explicit F2C target and cluster ID confirmation required; see F2C_RUNTIME.md"}


def main(**kwargs) -> int:
    """Run injection, the full hold, and cleanup while returning a meaningful code.

    Return 0 for verified exhaustion and recovery, 3 for weak pressure only, 130
    for interruption, or 1 for failed validation/recovery. Print only safe errors.
    """
    meta = None
    recovered = False
    try:
        meta = inject(**kwargs)
        hold(meta)
    except KeyboardInterrupt:
        print("[F2-c] interrupted", flush=True)
        return 130
    except RuntimeFailure as exc:
        print(f"[F2-c] FAIL: {exc}", flush=True)
        return 1
    except Exception:
        print("[F2-c] FAIL: target, injection or hold could not be verified; see F2C_RUNTIME.md", flush=True)
        return 1
    finally:
        if meta is not None:
            recovered = cleanup(meta)
    if not recovered:
        return 1
    result = "PASS" if meta["rejection_confirmed"] else "PRESSURE_ONLY (no rejection)"
    print(f"[F2-c] {result} hold_elapsed={meta['hold_elapsed_seconds']:.1f}s", flush=True)
    return 0 if meta["rejection_confirmed"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
