"""`dp_validate` checks over committed lake state (docs/data-platform/05 §5 Track D).

Each check returns a list of error strings; an empty list means PASS.
"""
from __future__ import annotations

import json

from orchestration.lake import LocalLake, sha256

DATA_BUCKETS = ("lake-bronze", "lake-silver", "lake-gold")

# Primary key column of each lineage parent dataset (docs/data-platform/01 §2·§3).
PRIMARY_KEY = {
    "bronze.loki_entry": "bronze_id", "bronze.prometheus_sample": "bronze_id",
    "silver.app_log": "log_id", "silver.db_log": "db_log_id",
    "silver.network_event": "network_event_id", "silver.metric_point": "metric_point_id",
    "silver.alert_event": "alert_event_id", "silver.rca_result": "rca_id",
    "silver.transport_issue": "transport_issue_id", "silver.quarantine": "quarantine_id",
}


def check_manifests(lake: LocalLake) -> list[str]:
    """Every file a committed manifest lists exists with the recorded rows, bytes and sha256."""
    errors = []
    for manifest in lake.manifests():
        build = manifest["build_id"]
        if manifest["status"] != "committed":
            errors.append(f"{build}: status {manifest['status']}")
        for output in manifest["outputs"]:
            for file in output["files"]:
                path = lake.data_path(file["path"])
                if not path.exists():
                    errors.append(f"{build} {output['dataset']}: missing {path.name}")
                    continue
                data = path.read_bytes()
                rows = lake.read_rows(file["path"])
                if (len(rows), len(data), sha256(data)) != (file["rows"], file["bytes"], file["sha256"]):
                    errors.append(f"{build} {output['dataset']}: rows/bytes/sha256 differ from manifest")
    return errors


def check_pointers(lake: LocalLake) -> list[str]:
    """Each current pointer targets a committed manifest that produced its dataset."""
    errors = []
    for pointer in lake.pointers():
        path = lake.manifest_path(pointer["layer"], pointer["build_id"])
        if not path.exists():
            errors.append(f"pointer {pointer['dataset']}: {pointer['manifest_id']} not committed")
            continue
        manifest = json.loads(path.read_text("utf-8"))
        if pointer["dataset"] not in {o["dataset"] for o in manifest["outputs"]}:
            errors.append(f"pointer {pointer['dataset']}: {manifest['manifest_id']} has no such output")
    return errors


def check_lineage(lake: LocalLake) -> list[str]:
    """DQ-L01 subset: every edge's parent row exists in a committed parent build."""
    manifests = {m["build_id"]: m for m in lake.manifests()}
    keys: dict[tuple[str, str], set[str]] = {}

    def parent_keys(dataset: str, build_id: str) -> set[str] | None:
        if (dataset, build_id) not in keys:
            manifest = manifests.get(build_id)
            files = [f for o in (manifest or {}).get("outputs", []) if o["dataset"] == dataset for f in o["files"]]
            if not files:
                return None
            column = PRIMARY_KEY[dataset]
            keys[(dataset, build_id)] = {r[column] for f in files for r in lake.read_rows(f["path"])}
        return keys[(dataset, build_id)]

    errors = []
    for manifest in manifests.values():
        for output in (o for o in manifest["outputs"] if o["dataset"] == "lineage.edge"):
            for file in output["files"]:
                for edge in lake.read_rows(file["path"]):
                    if edge["child_version"] != manifest["build_id"]:
                        errors.append(f"edge {edge['edge_id']}: child_version is not its build")
                    found = parent_keys(edge["parent_dataset"], edge["parent_version"])
                    if found is None:
                        errors.append(f"edge {edge['edge_id']}: parent build {edge['parent_version']} not committed")
                    elif edge["parent_key"] not in found:
                        errors.append(f"edge {edge['edge_id']}: parent key missing in {edge['parent_dataset']}")
    return errors


def find_orphans(lake: LocalLake) -> list[str]:
    """Data files no committed manifest references (02 §4.1 step 1 failure). Warning only."""
    referenced = {lake.data_path(f["path"]) for m in lake.manifests() for o in m["outputs"] for f in o["files"]}
    files = [p for bucket in DATA_BUCKETS for p in (lake.root / bucket).rglob("*") if p.is_file()]
    return [str(p.relative_to(lake.root)) for p in files if p not in referenced]


def summarize(results: dict[str, list[str]], orphans: list[str]) -> dict:
    errors = [f"[{name}] {e}" for name, items in results.items() for e in items]
    report = {"status": "failed" if errors else "passed", "errors": errors, "orphans": orphans,
              "checks": {name: ("FAIL" if items else "PASS") for name, items in results.items()}}
    if errors:
        raise ValueError("dp_validate failed:\n" + "\n".join(errors))
    return report
