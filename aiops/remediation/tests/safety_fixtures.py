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
