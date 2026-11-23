"""Phase entry points the DAGs call (Track D). Pure functions over a store + RunContext.

Bronze writes a plan record per incident (which plan id, binding set and window this run used),
so the Silver and Gold phases can derive the same coverage ids without re-planning. Silver and
Gold rebuild a coverage only when its input manifest set changed (03 §4: same inputs = no-op).
Pointers move only after every build of the phase committed (02 §4.1 step 4).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from bronze import acquire as bronze_acquire
from bronze.plan import plan_incident
from contracts.canonical import fmt_ts
from contracts.runtime import RunContext, from_env
from gold.build import build_gold as gold_build, plan_gold
from silver.build import build_silver as silver_build, plan_silver
from storage import lineage_writer
from storage.manifest import manifest_by_id, move_pointer
from storage.store import LocalFsStore

DEFAULT_FIXTURE = Path(__file__).resolve().parents[3] / "docs/data-platform/examples/db-connection-limit"


def fixture_dir() -> Path:
    return Path(os.environ.get("DP_FIXTURE_DIR", DEFAULT_FIXTURE))


def store() -> LocalFsStore:
    return LocalFsStore()


def load_request(conf: dict | None = None) -> dict:
    """`dag_run.conf` is the IncidentRequest; without one the Mock fixture request is used."""
    return conf or json.loads((fixture_dir() / "00_incident_request.json").read_text("utf-8"))


def bindings_raw() -> str:
    """Same OBSERVATION_BINDINGS JSON as the Pipeline (env), else a file (DP_BINDINGS_PATH / fixture)."""
    if os.environ.get("OBSERVATION_BINDINGS"):
        return os.environ["OBSERVATION_BINDINGS"]
    path = Path(os.environ.get("DP_BINDINGS_PATH", fixture_dir() / "01_bindings.json"))
    return path.read_text("utf-8")


def airflow_run(context, params: dict | None = None) -> RunContext:
    """RunContext of the running Airflow task instance (map_index -1 is normalized to null)."""
    ti = context["ti"]
    run = from_env("airflow", dag_id=ti.dag_id, airflow_run_id=ti.run_id, task_id=ti.task_id,
                   try_number=ti.try_number, map_index=getattr(ti, "map_index", None), params=params or {})
    run.require_clean()
    return run


# ---- Phase 1: Bronze ---------------------------------------------------------------------

def plan(request: dict, lake: LocalFsStore, run: RunContext) -> dict[str, list[dict]]:
    items = plan_incident(request, bindings_raw())
    if not items:
        raise ValueError("empty acquisition plan")
    first = items[0]
    lake.write_plan({"plan_id": first["plan_id"], "incident_id": first["incident_id"],
                     "binding_set": first["binding_set"],
                     "plan_binding_sha256": first["plan_binding_sha256"], "window_start": first["window_start"],
                     "window_end": first["window_end"], "request": request, "updated_at": fmt_ts(run.now()),
                     "run_id": run.run_id})
    lineage_writer.write_run(lake, run, "success")
    grouped = {"loki": [], "prometheus": []}
    for item in items:
        grouped[item["source_system"]].append(item)
    return grouped


def label(item: dict) -> str:
    return f"{item['scope_role']}:{item['stream_class']}:{item['query_name']}"


def acquire(item: dict, lake: LocalFsStore, run: RunContext, transport=None) -> dict:
    try:
        result = bronze_acquire.acquire(item, lake, run, transport=transport)
    except Exception:
        lineage_writer.write_run(lake, run, "failed")
        raise
    bronze_acquire.record_run(lake, run, [result])
    return result


def summarize(results: list[dict]) -> dict:
    if not results:
        raise RuntimeError("no Bronze acquisition committed")
    statuses = sorted({r["build_status"] for r in results})
    return {"acquisitions": len(results), "reused": sum(r["status"] == "reused" for r in results),
            "by_status": {s: sum(r["build_status"] == s for r in results) for s in statuses}}


# ---- Phase 2: Silver ---------------------------------------------------------------------

def silver_todo(lake: LocalFsStore) -> list[dict]:
    return [todo for p in lake.plans() for todo in plan_silver(lake, p)]


def build_silver(todo: dict, lake: LocalFsStore, run: RunContext) -> dict:
    try:
        result = silver_build(todo["dataset"], todo["coverage"], todo["inputs"], lake, run)
    except Exception:
        lineage_writer.write_run(lake, run, "failed")
        raise
    lineage_writer.write_run(lake, run, "success")
    return result


def update_silver_pointers(results: list[dict], lake: LocalFsStore, run: RunContext) -> list[dict]:
    pointers = [move_pointer(lake, manifest_by_id(lake, r["manifest_id"]), r["dataset"], run) for r in results]
    lineage_writer.write_run(lake, run, "success")
    return pointers


# ---- Phase 3: Gold -----------------------------------------------------------------------

def gold_todo(lake: LocalFsStore) -> list[dict]:
    return [todo for p in lake.plans() if (todo := plan_gold(lake, p))]


def build_gold(todo: dict, lake: LocalFsStore, run: RunContext) -> dict:
    try:
        result = gold_build(todo["incident"], todo["silver_inputs"], todo["acquisitions"], lake, run)
    except Exception:
        lineage_writer.write_run(lake, run, "failed")
        raise
    lineage_writer.write_run(lake, run, "success")
    return result


def update_gold_pointers(results: list[dict], lake: LocalFsStore, run: RunContext) -> list[dict]:
    pointers = [move_pointer(lake, manifest_by_id(lake, r["manifest_id"]), "gold.incident", run) for r in results]
    lineage_writer.write_run(lake, run, "success")
    return pointers


def run_all(request: dict, lake: LocalFsStore, make_run, transport=None) -> dict:
    """Bronze -> Silver -> Gold in one process (tests and local CLI). `make_run(task_id)` -> RunContext."""
    grouped = plan(request, lake, make_run("plan"))
    bronze = [acquire(item, lake, make_run(f"acquire:{label(item)}"), transport)
              for items in grouped.values() for item in items]
    silver = [build_silver(t, lake, make_run(f"build_silver:{t['dataset']}")) for t in silver_todo(lake)]
    update_silver_pointers(silver, lake, make_run("update_silver"))
    gold = [build_gold(t, lake, make_run("build_gold")) for t in gold_todo(lake)]
    update_gold_pointers(gold, lake, make_run("update_gold"))
    incident = next(item["incident_id"] for items in grouped.values() for item in items)
    return {"bronze": bronze, "silver": silver, "gold": gold, "incident_id": incident}
