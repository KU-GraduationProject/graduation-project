"""Local lake store used by the orchestration stubs.

Same key layout as docs/data-platform/02 §3 under a local root. STEP 0.5
`storage/` replaces this module; until then data files hold the fixture
convention bytes (canonical JSON rows joined by newline), not Parquet.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


def canonical_json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def rows_bytes(rows: list[dict]) -> bytes:
    return b"\n".join(canonical_json(row) for row in rows)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class LocalLake:
    def __init__(self, root: str | Path | None = None):
        self.root = Path(root or os.environ.get("DP_LAKE_ROOT", ".lake"))

    def data_path(self, uri: str) -> Path:
        """`s3://lake-silver/v1/x.parquet` -> `<root>/lake-silver/v1/x.jsonl`."""
        relative = uri.removeprefix("s3://")
        return self.root / Path(relative).with_suffix(".jsonl")

    def manifest_path(self, layer: str, build_id: str) -> Path:
        return self.root / "lake-meta" / "manifests" / layer / f"{build_id}.json"

    def pointer_path(self, pointer: dict) -> Path:
        base = self.root / "lake-meta" / "current" / pointer["layer"]
        if pointer["layer"] == "gold":
            return base / f"{pointer['incident_id']}.json"
        return base / pointer["dataset"] / f"{pointer['coverage_id']}.json"

    def write_rows(self, uri: str, rows: list[dict]) -> tuple[int, str]:
        data = rows_bytes(rows)
        path = self.data_path(uri)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return len(data), sha256(data)

    def commit_manifest(self, manifest: dict) -> Path:
        """Writing the manifest is the commit point (02 §4.1 step 3)."""
        path = self.manifest_path(manifest["layer"], manifest["build_id"])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), "utf-8")
        return path

    def write_pointer(self, pointer: dict) -> Path:
        path = self.pointer_path(pointer)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(pointer, ensure_ascii=False, indent=2), "utf-8")
        return path

    def manifests(self) -> list[dict]:
        folder = self.root / "lake-meta" / "manifests"
        return [json.loads(p.read_text("utf-8")) for p in sorted(folder.glob("*/*.json"))]

    def pointers(self) -> list[dict]:
        folder = self.root / "lake-meta" / "current"
        return [json.loads(p.read_text("utf-8")) for p in sorted(folder.rglob("*.json"))]

    def read_rows(self, uri: str) -> list[dict]:
        data = self.data_path(uri).read_bytes()
        return [json.loads(line) for line in data.split(b"\n") if line]
