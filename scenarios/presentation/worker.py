"""Run on the Leafy Docker host. Reuse inject/cleanup; retain its safety watchdog.

JSON events go to stdout; injector output goes to stderr. The parent requests
cleanup with one line on stdin. EOF/crash also cleans up. No GT enters telemetry.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import importlib
import json
from pathlib import Path
import queue
import sys
import threading

from .state import now

SCENARIOS = Path(__file__).resolve().parents[1]
if str(SCENARIOS) not in sys.path:
    sys.path.insert(0, str(SCENARIOS))


def emit(kind, **data):
    print(json.dumps({"event": kind, "at": now(), **data}, ensure_ascii=False), flush=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("scenario")
    p.add_argument("--hold", type=int, default=900)
    args = p.parse_args()
    if not 60 <= args.hold <= 1800:
        p.error("hold must be 60..1800 seconds")
    from v2.registry import SCENARIO_REGISTRY_V2
    row = next((r for r in SCENARIO_REGISTRY_V2 if r["id"] == args.scenario), None)
    if not row or not row.get("module"):
        p.error("scenario is external or unavailable")
    mod = importlib.import_module(row["module"])
    meta = None
    try:
        # Detached lifecycle adapters are deliberately explicit. Generic main()
        # remains untouched and owns cleanup for all other repository scenarios.
        if args.scenario in {"s2_a_resource_theft", "f1_b_memory_leak", "f2_a_minio_outage"}:
            kwargs = {"max_seconds": args.hold + 60}
            if args.scenario == "s2_a_resource_theft":
                kwargs["duration_seconds"] = args.hold
            if args.scenario == "f2_a_minio_outage":
                kwargs["down_seconds"] = 0
            with redirect_stdout(sys.stderr):
                meta = mod.inject(**kwargs)
            # Actual injector acknowledgement, never parent process launch time.
            emit("injected", basis="inject() acknowledged")
            done = queue.Queue()
            threading.Thread(target=lambda: done.put(sys.stdin.readline()), daemon=True).start()
            try:
                done.get(timeout=args.hold)
            except queue.Empty:
                emit("safety_timeout")
        else:
            emit("unmeasured_started", basis="scenario owns lifecycle; no injection timestamp hook")
            # Existing synchronous main() functions keep their own finally blocks.
            # An explicit stop/EOF delivers KeyboardInterrupt on the main thread.
            def interrupt_on_stop():
                sys.stdin.readline()
                import _thread
                _thread.interrupt_main()
            threading.Thread(target=interrupt_on_stop, daemon=True).start()
            with redirect_stdout(sys.stderr):
                from v2.run import run
                code = run(args.scenario, dry_run=False)
            if code:
                emit("failed", reason=f"scenario exit {code}")
                return code
            emit("scenario_finished")
    except BaseException as exc:
        # Only type, no SDK exception text (may contain credentials).
        emit("failed", reason=type(exc).__name__)
        return 1
    finally:
        if meta is not None:
            try:
                with redirect_stdout(sys.stderr):
                    ok = mod.cleanup(meta)
                emit("cleanup", ok=ok is not False)
            except BaseException as exc:
                emit("cleanup", ok=False, reason=type(exc).__name__)
    return 0


if __name__ == "__main__":
    sys.exit(main())
