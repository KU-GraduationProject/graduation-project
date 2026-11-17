"""Phase entry points backed by the STEP 0 Mock fixture.

Each function stands in for a Track A/B/C entry point (docs/data-platform/05 §4).
It replays the committed fixture build instead of computing it, so the DAGs run
end to end before the tiering logic exists. Replace one phase at a time: keep the
signature, return the same dict, and the DAG does not change.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from orchestration.lake import LocalLake

DEFAULT_FIXTURE = Path(__file__).resolve().parents[3] / "docs/data-platform/examples/db-connection-limit"

DATASET_FILE = {
    "bronze.acquisition": "10_bronze_acquisition.jsonl",
    "bronze.loki_entry": "11_bronze_loki_entry.jsonl",
    "bronze.prometheus_sample": "12_bronze_prometheus_sample.jsonl",
    "silver.db_log": "20_silver_db_log.jsonl",
    "silver.app_log": "21_silver_app_log.jsonl",
    "silver.network_event": "22_silver_network_event.jsonl",
    "silver.metric_point": "23_silver_metric_point.jsonl",
    "silver.alert_event": "24_silver_alert_event.jsonl",
    "silver.rca_result": "25_silver_rca_result.jsonl",
    "silver.quarantine": "26_silver_quarantine.jsonl",
    "silver.transport_issue": "27_silver_transport_issue.jsonl",
    "gold.incident": "30_gold_incident.jsonl",
    "gold.incident_channel": "31_gold_incident_channel.jsonl",
    "gold.evidence_log": "32_gold_evidence_log.jsonl",
    "gold.evidence_metric": "33_gold_evidence_metric.jsonl",
    "gold.evidence_network_flow": "34_gold_evidence_network_flow.jsonl",
    "gold.rca_link": "35_gold_rca_link.jsonl",
    "lineage.edge": "41_lineage_edge.jsonl",
}


def fixture_dir() -> Path:
    return Path(os.environ.get("DP_FIXTURE_DIR", DEFAULT_FIXTURE))


def _jsonl(name: str) -> list[dict]:
    text = (fixture_dir() / name).read_text("utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _build_rows(dataset: str, build_id: str) -> list[dict]:
    key = "acquisition_id" if dataset.startswith("bronze.") else (
        "child_version" if dataset == "lineage.edge" else "_dataset_version")
    return [row for row in _jsonl(DATASET_FILE[dataset]) if row.get(key) == build_id]


def _manifest(build_id: str) -> dict:
    return next(m for m in _jsonl("50_manifests.jsonl") if m["build_id"] == build_id)


def _commit_build(build_id: str, lake: LocalLake) -> dict:
    """Write every output file of a fixture build, then commit its manifest."""
    manifest = _manifest(build_id)
    outputs = [(o, f, _build_rows(o["dataset"], build_id)) for o in manifest["outputs"] for f in o["files"]]
    if any(f["rows"] and not rows for _, f, rows in outputs):
        # Superseded builds keep only their manifest in the fixture (README).
        return {"build_id": build_id, "layer": manifest["layer"], "status": "skipped_not_in_fixture"}
    for output, file, rows in outputs:
        if lake.write_rows(file["path"], rows) != (file["bytes"], file["sha256"]):
            raise ValueError(f"{build_id} {output['dataset']}: rows do not match manifest hash")
    lake.commit_manifest(manifest)
    return {"build_id": build_id, "layer": manifest["layer"], "status": "committed",
            "build_status": manifest["build_status"], "rows": sum(len(r) for _, _, r in outputs)}


def load_request(conf: dict | None = None) -> dict:
    return conf or json.loads((fixture_dir() / "00_incident_request.json").read_text("utf-8"))


def plan_incident(request: dict) -> dict[str, list[dict]]:
    """Track A `plan_incident`: acquisition plan items grouped by source system."""
    plan_id = f"incident:{request['expected_incident_id']}"
    items = {"loki": [], "prometheus": []}
    for row in _jsonl(DATASET_FILE["bronze.acquisition"]):
        if row["plan_id"] == plan_id:
            items[row["source_system"]].append({key: row[key] for key in (
                "acquisition_id", "source_system", "stream_class", "scope_role", "query_name")})
    return items


def acquire(item: dict, lake: LocalLake) -> dict:
    """Track A `acquire`: one acquisition -> Bronze files + manifest."""
    return _commit_build(item["acquisition_id"], lake)


def _layer_builds(layer: str) -> list[dict]:
    """Builds of one layer in commit order, labelled by their main dataset."""
    return [{"build_id": m["build_id"],
             "dataset": next(o["dataset"] for o in m["outputs"] if o["dataset"] != "lineage.edge")}
            for m in _jsonl("50_manifests.jsonl") if m["layer"] == layer]


def silver_builds() -> list[dict]:
    return _layer_builds("silver")


def build_silver(build_id: str, lake: LocalLake) -> dict:
    """Track B `build_silver`."""
    return _commit_build(build_id, lake)


def gold_builds() -> list[dict]:
    return _layer_builds("gold")


def build_gold(build_id: str, lake: LocalLake) -> dict:
    """Track C `build_gold`."""
    return _commit_build(build_id, lake)


def update_pointers(layer: str, lake: LocalLake) -> list[str]:
    """Move `current` pointers only to manifests already committed (02 §4.1 step 4)."""
    pointers = json.loads((fixture_dir() / "51_current_pointers.json").read_text("utf-8"))
    written = []
    for pointer in (p for p in pointers if p["layer"] == layer):
        if not lake.manifest_path(layer, pointer["build_id"]).exists():
            raise FileNotFoundError(f"pointer target not committed: {pointer['manifest_id']}")
        written.append(str(lake.write_pointer(pointer)))
    return written
