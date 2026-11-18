"""`lineage.edge` / `lineage.run` record serialization (03 §2-§3). Each Track produces its own edges."""
from __future__ import annotations

from contracts.canonical import edge_id, fmt_ts
from contracts.runtime import RunContext
from storage import paths
from storage.store import LocalFsStore


def edge(child_dataset, child_key, child_version, parent_dataset, parent_key, parent_version, relation,
         run_id) -> dict:
    return {"edge_id": edge_id(child_dataset, child_key, child_version, parent_dataset, parent_key, parent_version),
            "child_dataset": child_dataset, "child_key": child_key, "child_version": child_version,
            "parent_dataset": parent_dataset, "parent_key": parent_key, "parent_version": parent_version,
            "relation": relation, "run_id": run_id, "_schema_version": "1.0"}


def write_run(store: LocalFsStore, run: RunContext, status: str) -> dict:
    """Record the task attempt that produced (or failed to produce) builds."""
    record = run.run_record(status, ended_at=run.now())
    store.write_run(paths.run_file(record["run_id"], fmt_ts(run.started_at)), record)
    return record
