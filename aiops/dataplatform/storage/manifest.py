"""Manifest commit protocol (02 §4) and current pointers.

Readers never list prefixes: they read only files a committed manifest names. A build writes its
data and lineage edge files first, then the manifest (= commit). A failure before the manifest
leaves invisible orphans that `dp_validate` reports.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime

from contracts import schemas
from contracts.canonical import fmt_ts
from contracts.runtime import RunContext
from storage.store import LocalFsStore

LAYER_KIND = {"bronze": "acquisition", "silver": "silver_build", "gold": "gold_build"}


def ref(manifest: dict) -> dict:
    """`ManifestRef` handed between phases (XCom-safe)."""
    return {"manifest_id": manifest["manifest_id"], "layer": manifest["layer"], "build_id": manifest["build_id"],
            "build_status": manifest["build_status"], "status": manifest["status"]}


def flag_counts(rows) -> dict:
    counts = Counter(flag for row in rows for flag in row.get("_quality_flags", []))
    return dict(sorted(counts.items()))


def validate_rows(dataset: str, rows: list[dict]) -> None:
    """BLOCK: a row that breaks its column contract is never committed."""
    for row in rows:
        errors = schemas.check_row(dataset, row)
        if errors:
            raise ValueError("; ".join(errors[:5]))


def commit_build(store: LocalFsStore, run: RunContext, *, layer: str, build_id: str, plan_id: str,
                 incident_id: str | None, coverage_id: str | None, build_status: str, inputs: list[str],
                 outputs: list[tuple[str, str, list[dict]]], quality: dict, supersedes: str | None,
                 created_at: datetime) -> dict:
    """Write every output file, then the manifest. `outputs` = [(dataset, uri, rows)] in manifest order."""
    entries = []
    for dataset, uri, rows in outputs:
        validate_rows(dataset, rows)
        size, digest = store.write_rows(uri, rows)
        entries.append({"dataset": dataset, "schema_version": schemas.SCHEMA_VERSION, "rows": len(rows),
                        "files": [{"path": uri, "rows": len(rows), "bytes": size, "sha256": digest}]})
    manifest = {
        "manifest_id": f"mf_{build_id}", "manifest_schema_version": "1.0", "layer": layer, "build_id": build_id,
        "build_kind": LAYER_KIND[layer], "plan_id": plan_id, "incident_id": incident_id,
        "coverage_id": coverage_id, "status": "committed", "build_status": build_status,
        "created_at": fmt_ts(created_at), "run_id": run.run_id, "code_version": run.code_version,
        "git_sha": run.git_sha, "git_dirty": run.git_dirty, "inputs": list(inputs), "outputs": entries,
        "quality": quality, "supersedes": supersedes,
    }
    store.commit_manifest(manifest)
    return manifest


def output_rows(store: LocalFsStore, manifest: dict, dataset: str) -> list[dict]:
    return [row for o in manifest["outputs"] if o["dataset"] == dataset
            for f in o["files"] for row in store.read_rows(f["path"])]


def manifest_by_id(store: LocalFsStore, manifest_id: str) -> dict:
    build_id = manifest_id.removeprefix("mf_")
    layer = "bronze" if build_id.startswith("acq_") else "silver" if build_id.startswith("sb_") else "gold"
    manifest = store.read_manifest(layer, build_id)
    if manifest is None:
        raise FileNotFoundError(f"manifest not committed: {manifest_id}")
    return manifest


def pointer_for(manifest: dict, dataset: str, previous: dict | None, run: RunContext) -> dict:
    pointer = {"layer": manifest["layer"], "dataset": dataset}
    if manifest["layer"] == "gold":
        pointer["incident_id"] = manifest["incident_id"]
    else:
        pointer["coverage_id"] = manifest["coverage_id"]
    pointer.update({"build_id": manifest["build_id"], "manifest_id": manifest["manifest_id"],
                    "previous_build_id": previous["build_id"] if previous else None,
                    "updated_at": fmt_ts(run.now()), "run_id": run.run_id})
    return pointer


def current(store: LocalFsStore, manifest: dict, dataset: str) -> dict | None:
    if manifest["layer"] == "gold":
        return store.read_pointer("gold", incident_id=manifest["incident_id"])
    return store.read_pointer(manifest["layer"], dataset=dataset, coverage_id=manifest["coverage_id"])


def move_pointer(store: LocalFsStore, manifest: dict, dataset: str, run: RunContext) -> dict:
    """Step 4: point `current` at a committed manifest. Only moves forward in commit order."""
    if store.read_manifest(manifest["layer"], manifest["build_id"]) is None:
        raise FileNotFoundError(f"pointer target not committed: {manifest['manifest_id']}")
    previous = current(store, manifest, dataset)
    if previous and previous["build_id"] == manifest["build_id"]:
        return previous
    if previous:
        prev_manifest = store.read_manifest(manifest["layer"], previous["build_id"])
        if prev_manifest and (prev_manifest["created_at"], prev_manifest["build_id"]) > (
                manifest["created_at"], manifest["build_id"]):
            return previous  # a newer committed build already holds the pointer
    pointer = pointer_for(manifest, dataset, previous, run)
    store.write_pointer(pointer)
    return pointer
