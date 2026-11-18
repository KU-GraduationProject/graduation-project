"""`LocalFsStore`: the 02 §3 key layout under a local root (DEC-03, MinIO adapter later).

Data files (`*.parquet` keys) hold the fixture convention bytes — canonical JSON rows joined by
newline — stored as `*.jsonl` (DEC-02: Parquet codec is added once pyarrow is approved). Raw
pages keep their `.json.gz` key; gzip uses mtime=0 so the stored bytes are reproducible, and
`raw_sha256` is always taken over the uncompressed body (01 §2.1).
"""
from __future__ import annotations

import gzip
import json
import os
from pathlib import Path

from contracts.canonical import canonical_json, rows_bytes, sha256_bytes

DATA_BUCKETS = ("lake-bronze", "lake-silver", "lake-gold")


class LocalFsStore:
    def __init__(self, root: str | Path | None = None):
        self.root = Path(root or os.environ.get("DP_LAKE_ROOT", ".lake"))

    # ---- object keys ----------------------------------------------------------------
    def data_path(self, uri: str) -> Path:
        """`s3://lake-silver/v1/x.parquet` -> `<root>/lake-silver/v1/x.jsonl`."""
        path = self.root / uri.removeprefix("s3://")
        return path.with_suffix(".jsonl") if path.suffix == ".parquet" else path

    def _write_new(self, path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, path)

    # ---- data files -----------------------------------------------------------------
    def write_rows(self, uri: str, rows: list[dict]) -> tuple[int, str]:
        data = rows_bytes(rows)
        path = self.data_path(uri)
        if path.exists() and path.read_bytes() != data:
            raise FileExistsError(f"refusing to overwrite data file with different content: {uri}")
        self._write_new(path, data)
        return len(data), sha256_bytes(data)

    def read_rows(self, uri: str) -> list[dict]:
        data = self.data_path(uri).read_bytes()
        return [json.loads(line) for line in data.split(b"\n") if line]

    def put_raw(self, uri: str, body: bytes) -> None:
        self._write_new(self.data_path(uri), gzip.compress(body, mtime=0))

    def get_raw(self, uri: str) -> bytes:
        return gzip.decompress(self.data_path(uri).read_bytes())

    def data_files(self) -> list[Path]:
        return [p for bucket in DATA_BUCKETS for p in sorted((self.root / bucket).rglob("*"))
                if p.is_file() and not p.name.endswith(".tmp")]

    # ---- manifests (commit point, 02 §4.1 step 3) --------------------------------------
    def manifest_path(self, layer: str, build_id: str) -> Path:
        return self.root / "lake-meta" / "manifests" / layer / f"{build_id}.json"

    def commit_manifest(self, manifest: dict) -> Path:
        path = self.manifest_path(manifest["layer"], manifest["build_id"])
        if path.exists():
            raise FileExistsError(f"manifest already committed: {manifest['manifest_id']}")
        self._write_new(path, json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"))
        return path

    def read_manifest(self, layer: str, build_id: str) -> dict | None:
        path = self.manifest_path(layer, build_id)
        return json.loads(path.read_text("utf-8")) if path.exists() else None

    def manifests(self, layer: str | None = None) -> list[dict]:
        folder = self.root / "lake-meta" / "manifests"
        pattern = f"{layer}/*.json" if layer else "*/*.json"
        found = [json.loads(p.read_text("utf-8")) for p in folder.glob(pattern)]
        return sorted(found, key=lambda m: (m["created_at"], m["build_id"]))

    # ---- current pointers (02 §4.1 step 4) ---------------------------------------------
    def pointer_path(self, pointer: dict) -> Path:
        base = self.root / "lake-meta" / "current" / pointer["layer"]
        if pointer["layer"] == "gold":
            return base / f"{pointer['incident_id']}.json"
        return base / pointer["dataset"] / f"{pointer['coverage_id']}.json"

    def write_pointer(self, pointer: dict) -> Path:
        path = self.pointer_path(pointer)
        self._write_new(path, json.dumps(pointer, ensure_ascii=False, indent=2).encode("utf-8"))
        return path

    def read_pointer(self, layer: str, dataset: str | None = None, coverage_id: str | None = None,
                     incident_id: str | None = None) -> dict | None:
        path = self.pointer_path({"layer": layer, "dataset": dataset, "coverage_id": coverage_id,
                                  "incident_id": incident_id})
        return json.loads(path.read_text("utf-8")) if path.exists() else None

    def pointers(self) -> list[dict]:
        folder = self.root / "lake-meta" / "current"
        return [json.loads(p.read_text("utf-8")) for p in sorted(folder.rglob("*.json"))]

    # ---- lineage.run (written by each task, outside build manifests) -----------------------
    def write_run(self, uri: str, record: dict) -> None:
        self._write_new(self.data_path(uri), canonical_json(record))

    def runs(self) -> list[dict]:
        folder = self.root / "lake-meta" / "lineage" / "v1" / "run"
        return [json.loads(p.read_bytes()) for p in sorted(folder.rglob("*.jsonl"))]

    # ---- incident plans (implementation record: which plan/binding set a run used) ---------
    def plan_path(self, incident_id: str) -> Path:
        return self.root / "lake-meta" / "plans" / f"{incident_id}.json"

    def write_plan(self, plan: dict) -> Path:
        path = self.plan_path(plan["incident_id"])
        self._write_new(path, json.dumps(plan, ensure_ascii=False, indent=2).encode("utf-8"))
        return path

    def read_plan(self, incident_id: str) -> dict | None:
        path = self.plan_path(incident_id)
        return json.loads(path.read_text("utf-8")) if path.exists() else None

    def plans(self) -> list[dict]:
        folder = self.root / "lake-meta" / "plans"
        return [json.loads(p.read_text("utf-8")) for p in sorted(folder.glob("*.json"))]
