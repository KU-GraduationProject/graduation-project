"""In-process HMAC/SQLite transport tests; native effects and Docker are fake."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
import httpx

from agent.api import create_app
from agent.contract import ManagedCommand, ManagedPlanRequest
from agent.ledger import Ledger
from agent.service import AgentService
from executor.base import ExecutorError, succeeded
from executor.managed import check_record, seal_plan
from executor.remote import RemoteExecutor
from security.agent_auth import headers
import store
from tests.test_remote_agent import config, FakeDocker, inspect_doc, BUSINESS, MGMT, CID, IMAGE, IDENTITY, AGENT_ID, KEY, TARGET

PARAMETERS = {"destination_ip": "192.0.2.9", "destination_port": 8443, "protocol": "tcp", "flow_id": "fixture-flow"}


class StubManaged:
    name = "egress"
    def __init__(self, fake):
        self.fake, self.changed, self.invalid_identity = fake, False, False
        self.dispatched = 0
    def plan_record(self, identity, targets, action, parameters):
        ident = {**identity, "source": "other"} if self.invalid_identity else identity
        plan = seal_plan({"executor": self.name, "identity": ident, "target": identity["target"],
            "action_type": action, "parameters": parameters, "operator_config": {"labels": self.fake.doc["Config"]["Labels"]},
            "pre_snapshot": {"container_id": CID, "image_id": IMAGE, "version": 2 if self.changed else 1}})
        return {identity["target"]: plan}
    def validate_record(self, record):
        fresh = self.plan_record(record.identity, record.targets, record.action_type, record.action_parameters)
        return None if fresh == record.target_bindings else "stub_plan_changed"
    def execute_record(self, record, target, approved_by=None):
        check_record(record, self.name)
        self.dispatched += 1
        self.fake.calls.append(("managed", target))
        return succeeded(record.action_type, target, "fake_rule_verified", after={"owned_rule_verified": True})


class ManagedTransportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cfg = config()
        self.cfg.targets[TARGET].actions.extend(["BLOCK_EGRESS", "UNBLOCK_EGRESS"])
        self.doc = inspect_doc({BUSINESS: {"ip": "10.210.0.7"}, MGMT: {"ip": "10.211.0.7"}}, cid=CID)
        self.doc["Image"] = IMAGE; self.doc["Config"]["Labels"] = self.cfg.targets[TARGET].labels
        self.fake = FakeDocker(self.doc)
        self.native = StubManaged(self.fake)
        self.ledger = Ledger(str(self.root / "agent.sqlite3"))
        self.service = AgentService(self.cfg, self.ledger, mode="live", client_factory=Mock(return_value=self.fake),
                                    managed_executors={"BLOCK_EGRESS": self.native, "UNBLOCK_EGRESS": self.native})
        self.agent = TestClient(create_app(self.service, KEY)); self.addCleanup(self.agent.close)
        self.remote = RemoteExecutor("https://pc2.test.ts.net", KEY, client=self.agent, managed_enabled=True)
        binding = {"identity": IDENTITY, "executor": "remote", "agent_id": AGENT_ID,
                   "agent_url": self.remote.base_url, "container": self.cfg.targets[TARGET].model_dump(exclude_none=True)}
        self.binding_path = self.root / "bindings.json"
        self.binding_path.write_text(json.dumps({"version": 1, "bindings": [binding]}))
        patcher = patch.dict(os.environ, {"REMEDIATION_TARGET_BINDINGS_PATH": str(self.binding_path)})
        patcher.start(); self.addCleanup(patcher.stop)

    def approved_record(self, rid="managed-fixture"):
        binding = self.remote.plan_record(IDENTITY, [TARGET], "BLOCK_EGRESS", PARAMETERS)
        now = time.time()
        return SimpleNamespace(remediation_id=rid, action_type="BLOCK_EGRESS", action_parameters=deepcopy(PARAMETERS),
            identity=deepcopy(IDENTITY), targets=[TARGET], target_bindings=binding, evidence={"targets": binding},
            state="EXECUTING", executor_name="remote", requires_approval=True, approved_by="fixture-operator",
            incident_key="d" * 64, action_hash=store.action_hash("BLOCK_EGRESS", [TARGET], None, "none", PARAMETERS),
            ttl_seconds=None, recovery_mode="none",
            approval_requested_at=datetime.fromtimestamp(now - 2, timezone.utc).isoformat(),
            approved_at=datetime.fromtimestamp(now - 1, timezone.utc).isoformat(),
            action_started_at=datetime.fromtimestamp(now - .1, timezone.utc).isoformat(),
            approval_expires_at=datetime.fromtimestamp(now + 240, timezone.utc).isoformat())

    def signed_post(self, path, payload, auth=None):
        body = json.dumps(payload).encode()
        return self.agent.post(path, content=body, headers=auth or headers(KEY, "POST", path, body))

    def stored_request(self, rec): return self.ledger.get(rec.remediation_id, TARGET)["request"]

    def test_manual_signed_execution_verified_and_duplicate_does_not_redispatch(self):
        rec = self.approved_record()
        result = self.remote.execute_record(rec, TARGET, rec.approved_by)
        self.assertTrue(result.ok, result)
        self.assertEqual(self.native.dispatched, 1)
        self.assertEqual(self.ledger.get(rec.remediation_id, TARGET)["state"], "SUCCESS")
        self.assertTrue(self.remote.execute_record(rec, TARGET, rec.approved_by).ok)
        self.assertEqual(self.native.dispatched, 1)

    def test_feature_gate_and_disabled_agent_have_no_local_fallback(self):
        self.remote.supports_managed = False
        with self.assertRaises(ExecutorError): self.approved_record()
        self.assertEqual(self.native.dispatched, 0)
        self.remote.supports_managed = True; self.service.mode = "disabled"
        with self.assertRaises(ExecutorError): self.approved_record()
        self.assertEqual(self.native.dispatched, 0)
        self.assertEqual(self.fake.calls, [])

    def test_plan_identity_mismatch_is_rejected_by_controller(self):
        self.native.invalid_identity = True
        with self.assertRaises(ExecutorError): self.approved_record()
        self.assertEqual(self.native.dispatched, 0)

    def test_response_loss_queries_ledger_without_resending_write(self):
        rec = self.approved_record(); request = self.agent.request; writes = []
        def lose(method, url, **kwargs):
            response = request(method, url, **kwargs)
            if method == "POST" and str(url).endswith("/v1/managed/executions"):
                writes.append(str(url)); raise httpx.ReadTimeout("fixture lost response")
            return response
        with patch.object(self.agent, "request", side_effect=lose):
            result = self.remote.execute_record(rec, TARGET, rec.approved_by)
        self.assertTrue(result.ok, result)
        self.assertEqual(len(writes), 1)
        self.assertEqual(self.native.dispatched, 1)

    def test_replayed_hmac_and_changed_same_rid_payload_never_execute_twice(self):
        rec = self.approved_record(); self.assertTrue(self.remote.execute_record(rec, TARGET).ok)
        command = self.stored_request(rec)
        path = "/v1/managed/executions"; body = json.dumps(command).encode()
        auth = headers(KEY, "POST", path, body)
        self.assertEqual(self.agent.post(path, content=body, headers=auth).status_code, 200)
        self.assertEqual(self.agent.post(path, content=body, headers=auth).status_code, 401)
        changed = deepcopy(command); changed["parameters"]["destination_port"] = 9443
        native = {k: v for k, v in changed["plan"].items() if k != "plan_digest"}
        native["parameters"] = changed["parameters"]; changed["plan"] = seal_plan(native)
        changed["approval"]["action_hash"] = store.action_hash("BLOCK_EGRESS", [TARGET], None, "none", changed["parameters"])
        self.assertEqual(self.signed_post(path, changed).status_code, 409)
        self.assertEqual(self.native.dispatched, 1)

    def test_expired_or_mismatched_approval_actor_is_rejected(self):
        rec = self.approved_record(); self.assertTrue(self.remote.execute_record(rec, TARGET).ok)
        command = self.stored_request(rec)
        for changes in ("expires", "actor", "blank-actor"):
            bad = deepcopy(command); bad["remediation_id"] = "invalid-" + changes
            bad["authorization"]["decision_id"] = bad["remediation_id"]
            bad["authorization"]["approval_id"] = hashlib.sha256(("execute:" + bad["remediation_id"]).encode()).hexdigest()
            if changes == "expires": bad["expires_at"] = int(time.time()) - 1
            elif changes == "actor": bad["authorization"]["approved_by"] = "intruder"
            else:
                bad["authorization"]["approved_by"] = " "
                bad["approval"]["approved_by"] = " "
            self.assertEqual(self.signed_post("/v1/managed/executions", bad).status_code, 403)
        self.assertEqual(self.native.dispatched, 1)

    def test_replaced_container_after_plan_blocks_without_native_write(self):
        rec = self.approved_record(); self.fake.doc["Image"] = "sha256:" + "c" * 64
        result = self.remote.execute_record(rec, TARGET)
        self.assertEqual(result.status, "BLOCKED", result)
        self.assertEqual(self.native.dispatched, 0)

    def test_native_state_changed_after_plan_is_blocked_in_ledger(self):
        rec = self.approved_record(); self.native.changed = True
        result = self.remote.execute_record(rec, TARGET)
        self.assertEqual(result.status, "BLOCKED", result)
        self.assertEqual(self.native.dispatched, 0)
        self.assertEqual(self.ledger.get(rec.remediation_id, TARGET)["state"], "BLOCKED")

    def test_status_mismatched_parameters_or_digest_is_rejected(self):
        rec = self.approved_record(); self.assertTrue(self.remote.execute_record(rec, TARGET).ok)
        original = self.ledger.get(rec.remediation_id, TARGET)
        for kind in ("parameters", "digest", "actor"):
            doc = deepcopy(original)
            if kind == "parameters": doc["request"]["parameters"]["destination_port"] = 9443
            elif kind == "digest": doc["request"]["plan"]["plan_digest"] = "0" * 64
            else: doc["request"]["authorization"]["approved_by"] = "intruder"
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.remote.verify_managed_status(doc, rec, TARGET)

    def test_unsupported_host_action_and_unsigned_plan_fail_before_native_io(self):
        payload = {"action_type": "RESTART_HOST_SVC", "target": TARGET, "identity": IDENTITY, "agent_id": AGENT_ID,
                   "expected_target": {k: getattr(self.cfg.targets[TARGET], k) for k in ("container_id", "image_id", "labels")}, "parameters": {}}
        self.assertEqual(self.signed_post("/v1/managed/plans", payload).status_code, 422)
        self.assertEqual(self.agent.post("/v1/managed/plans", json=payload).status_code, 401)
        self.assertEqual(self.native.dispatched, 0)


if __name__ == "__main__": unittest.main()
