"""Loader for the STEP 0 fixture (docs/data-platform/examples). Reads in place; never copies."""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

FIXTURE_DIR = Path(os.environ.get("DP_FIXTURE_DIR", Path(__file__).resolve().parents[3]
                                  / "docs/data-platform/examples/db-connection-limit"))
FIXTURE_SHA = "0" * 40


def jsonl(name: str) -> list[dict]:
    text = (FIXTURE_DIR / name).read_text("utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def load_json(name: str):
    return json.loads((FIXTURE_DIR / name).read_text("utf-8"))


def request() -> dict:
    return load_json("00_incident_request.json")


def bindings_raw() -> str:
    return (FIXTURE_DIR / "01_bindings.json").read_text("utf-8")


def manifests() -> list[dict]:
    return jsonl("50_manifests.jsonl")


def runs() -> dict:
    return {r["run_id"]: r for r in jsonl("40_lineage_run.jsonl")}


def ts(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


class Clock:
    """Deterministic clock: returns `start`, then advances by `step` per call."""

    def __init__(self, start: str | datetime, step_ms: int = 10):
        self.now = ts(start) if isinstance(start, str) else start
        self.step = timedelta(milliseconds=step_ms)

    def __call__(self) -> datetime:
        current = self.now
        self.now = current + self.step
        return current


class SeqClock:
    """Returns the given instants in order, then repeats the last one."""

    def __init__(self, *instants):
        self.instants = [ts(i) if isinstance(i, str) else i for i in instants]

    def __call__(self) -> datetime:
        return self.instants.pop(0) if len(self.instants) > 1 else self.instants[0]


class Hex:
    """Deterministic 8-hex suffixes, taken from a list first (to reproduce fixture build ids)."""

    def __init__(self, values=()):
        self.values = list(values)
        self.n = 0

    def __call__(self) -> str:
        if self.values:
            return self.values.pop(0)
        self.n += 1
        return f"{self.n:08x}"


def run_context(run: dict | None = None, clock=None, hex8=None, **overrides):
    """RunContext for a fixture run (40_lineage_run.jsonl) or a test run."""
    from contracts.runtime import RunContext
    fields = dict(orchestrator="test", dag_id="test", airflow_run_id="t", task_id="t", try_number=1,
                  git_sha=FIXTURE_SHA)
    if run:
        fields.update(orchestrator=run["orchestrator"], dag_id=run["dag_id"], airflow_run_id=run["airflow_run_id"],
                      task_id=run["task_id"], try_number=run["try_number"], map_index=run["map_index"],
                      code_version=run["code_version"], git_sha=run["git_sha"], git_dirty=run["git_dirty"])
    fields.update(overrides)
    return RunContext(clock=clock or Clock("2026-11-10T03:20:00.000000Z"), hex8=hex8 or Hex(), **fields)


DATASET_FILE = {
    "bronze.acquisition": "10_bronze_acquisition.jsonl", "bronze.loki_entry": "11_bronze_loki_entry.jsonl",
    "bronze.prometheus_sample": "12_bronze_prometheus_sample.jsonl", "silver.db_log": "20_silver_db_log.jsonl",
    "silver.app_log": "21_silver_app_log.jsonl", "silver.network_event": "22_silver_network_event.jsonl",
    "silver.metric_point": "23_silver_metric_point.jsonl", "silver.alert_event": "24_silver_alert_event.jsonl",
    "silver.rca_result": "25_silver_rca_result.jsonl", "silver.quarantine": "26_silver_quarantine.jsonl",
    "silver.transport_issue": "27_silver_transport_issue.jsonl", "gold.incident": "30_gold_incident.jsonl",
    "gold.incident_channel": "31_gold_incident_channel.jsonl", "gold.evidence_log": "32_gold_evidence_log.jsonl",
    "gold.evidence_metric": "33_gold_evidence_metric.jsonl",
    "gold.evidence_network_flow": "34_gold_evidence_network_flow.jsonl", "gold.rca_link": "35_gold_rca_link.jsonl",
    "bronze.scenario_run_entry": "14_bronze_scenario_run_entry.jsonl", "silver.scenario_run": "28_silver_scenario_run.jsonl",
    "gold.scenario_link": "36_gold_scenario_link.jsonl", "lineage.edge": "41_lineage_edge.jsonl",
}


def build_rows(dataset: str, build_id: str) -> list[dict]:
    """Rows of one fixture build (README convention for which column names the build)."""
    key = ("acquisition_id" if dataset.startswith("bronze.") else
           "child_version" if dataset == "lineage.edge" else "_dataset_version")
    return [row for row in jsonl(DATASET_FILE[dataset]) if row.get(key) == build_id]


def manifest(build_id: str) -> dict:
    return next(m for m in manifests() if m["build_id"] == build_id)


def commit_fixture_build(store, build_id: str) -> dict:
    """Write a fixture build's rows and commit its manifest unchanged (Track B/C inputs)."""
    m = manifest(build_id)
    for output in m["outputs"]:
        for file in output["files"]:
            size, digest = store.write_rows(file["path"], build_rows(output["dataset"], build_id))
            if (size, digest) != (file["bytes"], file["sha256"]):
                raise ValueError(f"{build_id} {output['dataset']}: fixture rows do not match manifest")
    store.commit_manifest(m)
    return m


def plan_record() -> dict:
    """The plan record the Bronze phase writes for the fixture incident."""
    acq = jsonl("10_bronze_acquisition.jsonl")[0]
    shas = sorted({a["binding_sha256"] for a in jsonl("10_bronze_acquisition.jsonl") if a["binding_sha256"]})
    from contracts.canonical import plan_binding_sha256
    return {"plan_id": acq["plan_id"], "incident_id": acq["incident_id"], "binding_set": shas,
            "plan_binding_sha256": plan_binding_sha256(shas), "window_start": acq["window_start"],
            "window_end": acq["window_end"], "request": request()}


FIRST_RUN = "run_22372c8e8c3b3db431ba"
REPROCESS_RUN = "run_f3d9e6a440dc7050c738"


def build_time(build_id: str) -> datetime:
    """`sb_20261110T032010Z_…` -> the instant encoded in the id (task start)."""
    return datetime.strptime(build_id.split("_")[1], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)


REPLACED = ("sb_20261110T032010Z_62bad93f", "gb_20261110T032015Z_edd1b412")


def main_dataset(manifest: dict) -> str:
    return next(o["dataset"] for o in manifest["outputs"] if o["dataset"] not in ("lineage.edge", "silver.quarantine"))


def replay_silver(store, build_id: str):
    """Rebuild one fixture Silver build with its own run/build id and move its pointer."""
    from silver.build import build_silver, coverage, coverage_inputs
    from storage.manifest import move_pointer
    want = manifest(build_id)
    dataset = main_dataset(want)
    cov = coverage(dataset, plan_record())
    run = run_context(runs()[want["run_id"]], clock=SeqClock(runs()[want["run_id"]]["started_at"], build_time(build_id),
                                                                 want["created_at"]),
                      hex8=Hex([build_id[-8:]]))
    result = build_silver(dataset, cov, coverage_inputs(store, cov), store, run)
    built = store.read_manifest("silver", result["build_id"])
    move_pointer(store, built, dataset, run)
    return built


def replay_gold(store, build_id: str):
    from gold.build import build_gold, plan_gold
    from storage.manifest import move_pointer
    want = manifest(build_id)
    todo = plan_gold(store, plan_record())
    incident_rows = build_rows("gold.incident", build_id)
    built_at = incident_rows[0]["built_at"] if incident_rows else want["created_at"]
    run = run_context(runs()[want["run_id"]], clock=SeqClock(runs()[want["run_id"]]["started_at"], build_time(build_id),
                                                                 built_at, want["created_at"]),
                      hex8=Hex([build_id[-8:]]))
    result = build_gold(todo["incident"], todo["silver_inputs"], todo["acquisitions"], store, run)
    built = store.read_manifest("gold", result["build_id"])
    move_pointer(store, built, "gold.incident", run)
    return built


def replay_fixture(store):
    """The whole fixture history: 03:20 build (Bronze 10 -> Silver 7 -> Gold), 03:40 db_log reprocess."""
    for m in manifests():
        if m["layer"] == "bronze" and m["run_id"] == FIRST_RUN:
            commit_fixture_build(store, m["build_id"])
    for m in manifests():
        if m["layer"] == "silver" and m["run_id"] == "run_4069680f5feed7639ed0":
            replay_silver(store, m["build_id"])
    first_gold = replay_gold(store, "gb_20261110T032015Z_edd1b412")
    commit_fixture_build(store, "acq_20261110T034000Z_e240baaa")
    replay_silver(store, "sb_20261110T034042Z_c4d90e9a")
    current_gold = replay_gold(store, "gb_20261110T034045Z_124c3f4f")
    return first_gold, current_gold
