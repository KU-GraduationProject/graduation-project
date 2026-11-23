"""`trace`: Gold/Silver row -> Silver -> Bronze rows -> acquisition, query, scope and run (03 §6).

The walk is pinned to versions: it starts at one build and follows only the edges whose
`child_version` is the version its parent was used at, so rebuilt rows do not mix (03 §6).
`integrity` implements DQ-L01 (03 §7) over committed manifests.
"""
from __future__ import annotations

from collections import defaultdict

from storage.manifest import output_rows
from storage.store import LocalFsStore

PK = {"bronze.loki_entry": "bronze_id", "bronze.prometheus_sample": "bronze_id", "silver.app_log": "log_id",
      "silver.db_log": "db_log_id", "silver.network_event": "network_event_id",
      "silver.metric_point": "metric_point_id", "silver.alert_event": "alert_event_id",
      "silver.rca_result": "rca_id", "silver.transport_issue": "transport_issue_id",
      "silver.quarantine": "quarantine_id"}


class Lake:
    """Committed-manifest view of the store (never lists data prefixes)."""

    def __init__(self, store: LocalFsStore):
        self.store = store
        self.manifests = {m["build_id"]: m for m in store.manifests()}
        self.edges_by_child = defaultdict(list)
        for m in self.manifests.values():
            for e in output_rows(store, m, "lineage.edge"):
                self.edges_by_child[(e["child_dataset"], e["child_key"], e["child_version"])].append(e)
        self.runs = {r["run_id"]: r for r in store.runs()}
        self._rows = {}

    def rows(self, dataset: str, build_id: str) -> dict:
        if (dataset, build_id) not in self._rows:
            manifest = self.manifests.get(build_id)
            rows = output_rows(self.store, manifest, dataset) if manifest else []
            self._rows[(dataset, build_id)] = {r[PK[dataset]]: r for r in rows} if dataset in PK else {}
        return self._rows[(dataset, build_id)]

    def acquisition(self, acquisition_id: str) -> dict | None:
        manifest = self.manifests.get(acquisition_id)
        return output_rows(self.store, manifest, "bronze.acquisition")[0] if manifest else None


def trace(store: LocalFsStore, dataset: str, key: str, version: str | None = None) -> dict:
    """LineageGraph: {"root", "edges", "bronze": [...], "acquisitions": {...}, "runs": {...}}."""
    lake = Lake(store)
    if version is None:  # newest build that holds the key
        versions = [v for (d, k, v) in lake.edges_by_child if d == dataset and k == key]
        if not versions:
            raise KeyError(f"no lineage for {dataset} {key}")
        version = max(versions, key=lambda v: (lake.manifests[v]["created_at"], v))
    walked, frontier, bronze = [], [(dataset, key, version, 0)], []
    seen = set()
    while frontier:
        child_dataset, child_key, child_version, depth = frontier.pop(0)
        for e in lake.edges_by_child.get((child_dataset, child_key, child_version), []):
            if e["edge_id"] in seen:
                continue
            seen.add(e["edge_id"])
            walked.append({**e, "depth": depth + 1})
            if e["parent_dataset"].startswith("bronze."):
                row = lake.rows(e["parent_dataset"], e["parent_version"]).get(e["parent_key"])
                bronze.append({"dataset": e["parent_dataset"], "bronze_id": e["parent_key"],
                               "acquisition_id": e["parent_version"], "row": row})
            else:
                frontier.append((e["parent_dataset"], e["parent_key"], e["parent_version"], depth + 1))
    acquisitions = {}
    for b in bronze:
        acq = lake.acquisition(b["acquisition_id"])
        if acq:
            acquisitions[acq["acquisition_id"]] = {k: acq[k] for k in (
                "source_system", "api", "stream_class", "query_name", "query_text", "scope_role", "scope_identity",
                "scope_selector", "binding_sha256", "status", "raw_pages", "raw_sha256", "run_id")}
    run_ids = {lake.manifests[e["child_version"]]["run_id"] for e in walked} | {a["run_id"] for a in acquisitions.values()}
    return {"root": {"dataset": dataset, "key": key, "version": version}, "edges": walked, "bronze": bronze,
            "acquisitions": acquisitions, "runs": {r: lake.runs.get(r) for r in sorted(run_ids)}}


def _inputs_chain(lake: Lake, build_id: str) -> set[str]:
    out, stack = set(), [build_id]
    while stack:
        manifest = lake.manifests.get(stack.pop())
        if not manifest:
            continue
        for mid in manifest["inputs"]:
            parent = mid.removeprefix("mf_")
            if parent not in out:
                out.add(parent)
                stack.append(parent)
    return out


def integrity(store: LocalFsStore, require_runs: bool = True) -> list[str]:
    """DQ-L01: every rule of 03 §7. Empty list = PASS."""
    lake = Lake(store)
    errors = []
    current = {p["build_id"] for p in store.pointers()}
    for build_id, manifest in lake.manifests.items():
        layer = manifest["layer"]
        edges = output_rows(store, manifest, "lineage.edge")
        children = {(e["child_dataset"], e["child_key"]) for e in edges}
        chain = _inputs_chain(lake, build_id)
        for e in edges:
            if e["child_version"] != build_id:
                errors.append(f"{build_id}: edge {e['edge_id']} child_version is not its build")
            if e["parent_version"] not in chain:
                errors.append(f"{build_id}: edge {e['edge_id']} parent {e['parent_version']} outside inputs chain")
            elif e["parent_dataset"] in PK and e["parent_key"] not in lake.rows(e["parent_dataset"], e["parent_version"]):
                errors.append(f"{build_id}: edge {e['edge_id']} parent row missing in {e['parent_dataset']}")
        for output in manifest["outputs"]:
            dataset = output["dataset"]
            if dataset == "lineage.edge" or layer == "bronze":
                continue
            for row in output_rows(store, manifest, dataset):
                key = (row[PK[dataset]] if dataset in PK else
                       f"{row['incident_id']}:{row['rca_id']}" if dataset == "gold.rca_link" else
                       row["incident_id"] if dataset in ("gold.incident",) else row.get("evidence_id"))
                if dataset == "gold.incident_channel":
                    continue  # channel rows are summaries, not derived records (03 §7 lists evidence/incident/link)
                if (dataset, key) not in children:
                    errors.append(f"{build_id}: {dataset} {key} has no parent edge")
        if layer == "silver" and build_id in current:
            explained = {(e["parent_version"], e["parent_key"]) for e in edges}
            for mid in manifest["inputs"]:
                parent = lake.manifests.get(mid.removeprefix("mf_"))
                for out in (parent or {}).get("outputs", []):
                    if out["dataset"] in ("bronze.loki_entry", "bronze.prometheus_sample"):
                        for row in output_rows(store, parent, out["dataset"]):
                            if (parent["build_id"], row["bronze_id"]) not in explained:
                                errors.append(f"{build_id}: bronze {row['bronze_id']} has no Silver child")
        run = lake.runs.get(manifest["run_id"])
        if require_runs and run is None:
            errors.append(f"{build_id}: run {manifest['run_id']} not recorded")
        if run and (len(run["git_sha"]) != 40 or any(c not in "0123456789abcdef" for c in run["git_sha"])):
            errors.append(f"{build_id}: run git_sha is not 40 hex")
    return errors
