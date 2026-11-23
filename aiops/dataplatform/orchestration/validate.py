"""`dp_validate` checks over committed lake state (docs/data-platform/05 §5 Track D).

Each check returns a list of error strings; an empty list means PASS.
"""
from __future__ import annotations

import json

from contracts.canonical import sha256_bytes
from lineage.trace import integrity
from silver.build import check_coverage
from storage.manifest import output_rows
from storage.store import LocalFsStore


def check_manifests(lake: LocalFsStore) -> list[str]:
    """Every file a committed manifest lists exists with the recorded rows, bytes and sha256 (DQ-B02)."""
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
                if (len(rows), len(data), sha256_bytes(data)) != (file["rows"], file["bytes"], file["sha256"]):
                    errors.append(f"{build} {output['dataset']}: rows/bytes/sha256 differ from manifest")
    return errors


def check_raw_pages(lake: LocalFsStore) -> list[str]:
    """DQ-B02: every raw page of a committed acquisition exists and its uncompressed sha256 matches."""
    errors = []
    for manifest in lake.manifests("bronze"):
        acq = output_rows(lake, manifest, "bronze.acquisition")[0]
        if acq["row_count"] != sum(o["rows"] for o in manifest["outputs"] if o["dataset"] != "bronze.acquisition"):
            errors.append(f"{acq['acquisition_id']}: row_count differs from manifest rows")
        for uri, digest in zip(acq["raw_pages"], acq["raw_sha256"]):
            if not lake.data_path(uri).exists():
                errors.append(f"{acq['acquisition_id']}: raw page missing {uri}")
            elif sha256_bytes(lake.get_raw(uri)) != digest:
                errors.append(f"{acq['acquisition_id']}: raw page sha256 differs {uri}")
    return errors


def check_pointers(lake: LocalFsStore) -> list[str]:
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


def check_silver(lake: LocalFsStore) -> list[str]:
    """DQ-S01/S02 on the current Silver builds."""
    current = {p["build_id"] for p in lake.pointers() if p["layer"] == "silver"}
    return [e for m in lake.manifests("silver") if m["build_id"] in current for e in check_coverage(lake, m)]


def check_lineage(lake: LocalFsStore, require_runs: bool = True) -> list[str]:
    """DQ-L01 (03 §7): parent edges, inputs chain, Bronze rows explained, runs recorded with git sha."""
    return integrity(lake, require_runs=require_runs)


def find_orphans(lake: LocalFsStore) -> list[str]:
    """Data files no committed manifest references (02 §4.1 step 1 failure). Warning only, never deleted."""
    referenced = {lake.data_path(f["path"]) for m in lake.manifests() for o in m["outputs"] for f in o["files"]}
    for manifest in lake.manifests("bronze"):
        referenced |= {lake.data_path(uri) for uri in output_rows(lake, manifest, "bronze.acquisition")[0]["raw_pages"]}
    return [str(p.relative_to(lake.root)) for p in lake.data_files() if p not in referenced]


def run_checks(lake: LocalFsStore, require_runs: bool = True) -> dict[str, list[str]]:
    return {"manifests": check_manifests(lake), "raw_pages": check_raw_pages(lake), "pointers": check_pointers(lake),
            "silver": check_silver(lake), "lineage": check_lineage(lake, require_runs)}


def summarize(results: dict[str, list[str]], orphans: list[str]) -> dict:
    errors = [f"[{name}] {e}" for name, items in results.items() for e in items]
    report = {"status": "failed" if errors else "passed", "errors": errors, "orphans": orphans,
              "checks": {name: ("FAIL" if items else "PASS") for name, items in results.items()}}
    if errors:
        raise ValueError("dp_validate failed:\n" + "\n".join(errors))
    return report
