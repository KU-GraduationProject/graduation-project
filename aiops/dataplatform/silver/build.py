"""`build_silver`: one coverage's committed Bronze acquisitions -> one Silver build (05 §4 Track B).

A coverage is (dataset, plan_id, binding set, acquisition window) — 01 §1.1 `coverage_id`. Its
input is the union of every committed acquisition of that plan and window whose binding belongs
to the plan run's binding set (or is null, for global streams) — 02 §7. Rows sharing a Silver
PK are merged into one row; every parent stays as a `normalized_from` edge (DQ-S01).
"""
from __future__ import annotations

from contracts import canonical, enums, schemas
from contracts.runtime import RunContext
from silver.normalize import NORMALIZERS, Normalized, Quarantine
from storage import lineage_writer, paths
from storage.manifest import commit_build, flag_counts, manifest_by_id, output_rows, ref
from storage.store import LocalFsStore

PK = {"silver.db_log": "db_log_id", "silver.app_log": "log_id", "silver.network_event": "network_event_id",
      "silver.metric_point": "metric_point_id", "silver.alert_event": "alert_event_id",
      "silver.rca_result": "rca_id", "silver.transport_issue": "transport_issue_id",
      "silver.quarantine": "quarantine_id"}


# ---- coverage ----------------------------------------------------------------------------

def coverage(dataset: str, plan: dict) -> dict:
    return {"dataset": dataset, "plan_id": plan["plan_id"], "incident_id": plan["incident_id"],
            "plan_binding_sha256": plan["plan_binding_sha256"], "binding_set": plan["binding_set"],
            "window_start": plan["window_start"], "window_end": plan["window_end"],
            "coverage_id": canonical.coverage_id(dataset, plan["plan_id"], plan["plan_binding_sha256"],
                                                 plan["window_start"], plan["window_end"])}


def acquisition_rows(store: LocalFsStore) -> list[tuple[dict, dict]]:
    """(manifest, acquisition row) of every committed Bronze build, oldest request first."""
    out = [(m, output_rows(store, m, "bronze.acquisition")[0]) for m in store.manifests("bronze")]
    return sorted(out, key=lambda pair: (pair[1]["requested_at"], pair[1]["acquisition_id"]))


def coverage_inputs(store: LocalFsStore, cov: dict, streams=None) -> list[str]:
    streams = streams or enums.SILVER_SOURCES[cov["dataset"]]
    allowed = set(cov["binding_set"])
    return [m["manifest_id"] for m, a in acquisition_rows(store)
            if a["plan_id"] == cov["plan_id"] and a["window_start"] == cov["window_start"]
            and a["window_end"] == cov["window_end"] and a["stream_class"] in streams
            and (a["binding_sha256"] is None or a["binding_sha256"] in allowed)]


def plan_silver(store: LocalFsStore, plan: dict) -> list[dict]:
    """Coverages of one incident plan whose input set differs from their current build (else no-op)."""
    todo = []
    for dataset in enums.SILVER_DATASETS:
        cov = coverage(dataset, plan)
        inputs = coverage_inputs(store, cov)
        pointer = store.read_pointer("silver", dataset=dataset, coverage_id=cov["coverage_id"])
        if pointer:
            built = store.read_manifest("silver", pointer["build_id"])
            if built and built["inputs"] == inputs:
                continue
        todo.append({"dataset": dataset, "coverage": cov, "inputs": inputs})
    return todo


# ---- build -------------------------------------------------------------------------------

def _parents(store: LocalFsStore, inputs: list[str]):
    """(acquisition row, bronze row) in input order then bronze_id order."""
    for manifest_id in inputs:
        manifest = manifest_by_id(store, manifest_id)
        acq = output_rows(store, manifest, "bronze.acquisition")[0]
        dataset = "bronze.loki_entry" if acq["source_system"] == "loki" else "bronze.prometheus_sample"
        for row in output_rows(store, manifest, dataset):
            yield acq, dataset, row


def _merge(dataset: str, group: list[tuple[Normalized, dict]]) -> tuple[dict, set]:
    first, _ = group[0]
    values, flags = dict(first.values), set().union(*(n.flags for n, _ in group))
    acqs = [a for _, a in group]
    if dataset == "silver.metric_point":
        closed = [(n, a) for n, a in group if a["window_closed"]] or group
        chosen, _ = max(closed, key=lambda pair: (pair[1]["requested_at"], pair[1]["acquisition_id"]))
        values["value"] = chosen.values["value"]
        if len({repr(n.values["value"]) for n, _ in group}) > 1:
            flags.add("value_revised")
    if len(group) > 1:
        flags.add("duplicate")
    statuses = {a["status"] for a in acqs}
    if statuses <= {"partial", "truncated"}:
        flags.add("partial_acquisition")
    if statuses == {"source_mismatch"}:
        flags.add("source_mismatch")
    if not any(a["window_closed"] for a in acqs):
        flags.add("window_open")
    return values, flags


def build_silver(dataset: str, coverage: dict, inputs: list[str], store: LocalFsStore, run: RunContext) -> dict:
    normalize = NORMALIZERS[dataset]
    build_id = run.new_build_id("sb")
    groups: dict[str, list] = {}
    quarantined: dict[str, dict] = {}
    for acq, parent_dataset, row in _parents(store, inputs):
        try:
            norm = normalize(row, acq)
        except Quarantine as q:
            qid = canonical.quarantine_id(row["record_key"], dataset, q.reason)
            entry = quarantined.setdefault(qid, {"row": {
                "quarantine_id": qid, "first_bronze_id": row["bronze_id"], "record_key": row["record_key"],
                "target_dataset": dataset, "reason_code": q.reason, "detail": q.detail,
                "acquired_at": acq["requested_at"], "_schema_version": schemas.SCHEMA_VERSION,
                "_dataset_version": build_id, "_run_id": run.run_id}, "parents": []})
            entry["parents"].append((parent_dataset, row["bronze_id"], acq["acquisition_id"]))
            continue
        probe = {**norm.values, "_schema_version": "1.0", "_dataset_version": build_id, "_run_id": run.run_id,
                 "_quality_flags": [], "_dup_count": 1, "_first_acquired_at": acq["requested_at"],
                 "_last_acquired_at": acq["requested_at"]}
        errors = schemas.check_row(dataset, schemas.project(dataset, probe))
        if errors:
            qid = canonical.quarantine_id(row["record_key"], dataset, "invalid_value")
            entry = quarantined.setdefault(qid, {"row": {
                "quarantine_id": qid, "first_bronze_id": row["bronze_id"], "record_key": row["record_key"],
                "target_dataset": dataset, "reason_code": "invalid_value", "detail": errors[0][:200],
                "acquired_at": acq["requested_at"], "_schema_version": schemas.SCHEMA_VERSION,
                "_dataset_version": build_id, "_run_id": run.run_id}, "parents": []})
            entry["parents"].append((parent_dataset, row["bronze_id"], acq["acquisition_id"]))
            continue
        groups.setdefault(norm.pk, []).append((norm, acq, parent_dataset, row))

    rows, edges = [], []
    for pk, group in sorted(groups.items(), key=lambda kv: kv[1][0][0].order):
        values, flags = _merge(dataset, [(n, a) for n, a, _, _ in group])
        acquired = sorted(a["requested_at"] for _, a, _, _ in group)
        rows.append(schemas.project(dataset, {
            **values, "_schema_version": schemas.SCHEMA_VERSION, "_dataset_version": build_id,
            "_run_id": run.run_id, "_quality_flags": sorted(flags), "_dup_count": len(group),
            "_first_acquired_at": acquired[0], "_last_acquired_at": acquired[-1]}))
        for _, acq, parent_dataset, row in group:
            edges.append(lineage_writer.edge(dataset, pk, build_id, parent_dataset, row["bronze_id"],
                                             acq["acquisition_id"], "normalized_from", run.run_id))
    quarantine_rows = [q["row"] for q in quarantined.values()]
    for q in quarantined.values():
        for parent_dataset, bronze, acquisition in q["parents"]:
            edges.append(lineage_writer.edge("silver.quarantine", q["row"]["quarantine_id"], build_id,
                                             parent_dataset, bronze, acquisition, "quarantined_from", run.run_id))

    event_date = paths.date_of(coverage["window_start"])
    outputs = [(dataset, paths.silver_file(dataset, build_id, event_date), rows)]
    if quarantine_rows:
        outputs.append(("silver.quarantine", paths.silver_file("silver.quarantine", build_id, event_date),
                        quarantine_rows))
    outputs.append(("lineage.edge", paths.edge_file(build_id), edges))
    previous = store.read_pointer("silver", dataset=dataset, coverage_id=coverage["coverage_id"])
    manifest = commit_build(
        store, run, layer="silver", build_id=build_id, plan_id=coverage["plan_id"],
        incident_id=coverage["incident_id"], coverage_id=coverage["coverage_id"], build_status="ok",
        inputs=list(inputs), outputs=outputs,
        quality={"flag_counts": flag_counts(rows), "quarantined": len(quarantine_rows),
                 "skipped": len(quarantine_rows)},
        supersedes=previous["manifest_id"] if previous else None, created_at=run.now())
    return {**ref(manifest), "dataset": dataset, "coverage_id": coverage["coverage_id"]}


def check_coverage(store: LocalFsStore, manifest: dict) -> list[str]:
    """DQ-S01/S02 over one committed Silver build: every input Bronze row explains exactly once."""
    dataset = next(o["dataset"] for o in manifest["outputs"] if o["dataset"] not in ("lineage.edge",
                                                                                     "silver.quarantine"))
    errors = []
    keys = [r[PK[dataset]] for r in output_rows(store, manifest, dataset)]
    if len(keys) != len(set(keys)):
        errors.append(f"{manifest['build_id']}: duplicate {PK[dataset]} (DQ-S02)")
    explained = {(e["parent_version"], e["parent_key"]) for e in output_rows(store, manifest, "lineage.edge")}
    for acq, _, row in _parents(store, manifest["inputs"]):
        if (acq["acquisition_id"], row["bronze_id"]) not in explained:
            errors.append(f"{manifest['build_id']}: bronze row {row['bronze_id']} has no Silver child (DQ-S01)")
    return errors
