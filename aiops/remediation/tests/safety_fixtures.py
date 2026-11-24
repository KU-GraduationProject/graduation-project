"""Synthetic identities and operator bindings shared by guarded safety tests."""
import json
import os
from pathlib import Path
from unittest.mock import patch

IDENTITY = {"site": "gc", "service": "backend", "source": "gc-host",
            "runtime": "container", "target": "leafy-backend"}
CID = "a" * 64
IMAGE_ID = "sha256:" + "b" * 64
LABELS = {"io.leafy.remediation": "workload", "com.docker.compose.project": "leafy-test",
          "com.docker.compose.service": "backend"}
ACTIONS = ["RESTART", "PAUSE", "UNPAUSE", "THROTTLE", "UNTHROTTLE", "ISOLATE", "RECONNECT"]


def local_binding(identity=None, doc=None):
    identity = dict(identity or IDENTITY)
    doc = doc or {}
    return {"identity": identity, "executor": "local_docker", "agent_id": "local-test",
            "agent_url": "", "container": {"container_id": doc.get("Id", CID),
                "image_id": doc.get("Image", IMAGE_ID),
                "labels": dict(doc.get("Config", {}).get("Labels", LABELS)),
                "actions": ACTIONS,
                "isolate_networks": ["leafy-net"], "preserve_networks": ["mgmt-net", "aiops-net"]}}


def configure_local_binding(case, directory, doc=None):
    path = Path(directory) / "target-bindings.json"
    path.write_text(json.dumps({"version": 1, "bindings": [local_binding(doc=doc)]}), encoding="utf-8")
    env = patch.dict(os.environ, {"REMEDIATION_TARGET_BINDINGS_PATH": str(path)})
    env.start()
    case.addCleanup(env.stop)
    return path


def enrich_doc(doc):
    doc["Id"] = CID
    doc["Image"] = IMAGE_ID
    doc["Config"]["Labels"] = dict(LABELS)
    return doc


def fake_db_backup(remediation_id):
    """선행 단계 DB 백업(#53)의 테스트 대역. pg_dump 를 실행하지 않고 검증된 manifest 모양만 돌려준다."""
    return {"manifest_path": f"/fixture/backups/{remediation_id}.json", "sha256": "0" * 64, "bytes": 1024,
            "database_id": "0:leafy", "verified_at": "2026-11-11T01:00:00+00:00", "restore_list_verified": True}
