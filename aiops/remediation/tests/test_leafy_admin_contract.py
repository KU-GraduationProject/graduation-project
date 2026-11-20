"""Leafy companion backend paths/DTO contract through the real HTTPS adapter."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import httpx
import yaml
import store as states
from executor.app_api import AppApiExecutor


class LeafyAdminContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "leafy-admin.yml"
        example = Path(__file__).resolve().parents[3] / "deploy/aiops-pc/remediation-app-api.leafy.example.yml"
        self.config = yaml.safe_load(example.read_text())
        row = self.config["targets"]["leafy-backend"]
        row.pop("token_file")
        row["token_env"] = "FIXTURE_LEAFY_ADMIN_JWT"
        row["base_url"] = "https://backend.fixture.invalid"
        self.identity = row["identity"]
        self.path.write_text(yaml.safe_dump(self.config))
        env = patch.dict(os.environ, {"FIXTURE_LEAFY_ADMIN_JWT": "fixture-admin-access-token"})
        env.start()
        self.addCleanup(env.stop)
        self.version = 0
        self.locked, self.revoked, self.enabled = False, False, True
        self.operation = {"action": "NONE", "idempotency_key": ""}
        self.expiry = None
        self.calls = []
        self.client = httpx.Client(transport=httpx.MockTransport(self.handle))
        self.addCleanup(self.client.close)
        self.executor = AppApiExecutor(client=self.client, config_path=str(self.path))

    def handle(self, request):
        self.calls.append(request)
        is_account = "/accounts/" in request.url.path
        resource_id = "123" if is_account else "diagnosis"
        self.assertEqual(request.headers["Authorization"], "Bearer fixture-admin-access-token")
        if request.method == "POST":
            self.assertEqual(request.headers["If-Match"], str(self.version))
            body = json.loads(request.content)
            self.assertEqual(body["target"], "leafy-backend")
            self.assertEqual(body["account_id" if is_account else "feature_id"], resource_id)
            if request.url.path.endswith("/lock"):
                self.assertIs(type(body["duration_seconds"]), int)
                self.locked = True
                self.expiry = (datetime.now(timezone.utc) + timedelta(seconds=body["duration_seconds"])).isoformat()
                action = "LOCK_ACCOUNT"
            elif request.url.path.endswith("/revoke-sessions"):
                self.revoked = True
                action = "REVOKE_SESSION"
            elif request.url.path.endswith("/disable"):
                self.enabled = False
                action = "DISABLE_FEATURE"
            elif request.url.path.endswith("/unlock"):
                self.locked = False
                action = "UNLOCK_ACCOUNT"
            elif request.url.path.endswith("/enable"):
                self.enabled = True
                action = "ENABLE_FEATURE"
            else:
                self.fail("unrecognized Leafy mutation path")
            self.version += 1
            self.operation = {"action": action, "idempotency_key": request.headers["Idempotency-Key"]}
        else:
            self.assertEqual(request.method, "GET")
            self.assertEqual(request.url.path, "/api/admin/remediation/" + ("accounts/123" if is_account else "features/diagnosis"))
        return httpx.Response(200, json={"target": "leafy-backend", "resource": {"id": resource_id, "role": "USER" if is_account else None},
            "version": str(self.version), "locked": self.locked, "lock_expires_at": self.expiry,
            "sessions_revoked": self.revoked, "auth_version": int(self.revoked),
            "enabled": self.enabled, "last_operation": self.operation})

    def execute(self, action, parameters):
        target = "leafy-backend"
        plans = self.executor.plan_record(self.identity, [target], action, parameters)
        now = datetime.now(timezone.utc)
        record = SimpleNamespace(remediation_id="leafy-contract-record", action_type=action,
            action_parameters=parameters, identity=deepcopy(self.identity), targets=[target],
            executor_name="app_api", requires_approval=True, state="EXECUTING", approved_by="UTEST",
            incident_key="a"*64, ttl_seconds=None, recovery_mode="none",
            action_hash=states.action_hash(action,[target],None,"none",parameters),
            approval_requested_at=(now-timedelta(seconds=2)).isoformat(),
            approved_at=(now-timedelta(seconds=1)).isoformat(), action_started_at=now.isoformat(),
            approval_expires_at=(now+timedelta(seconds=60)).isoformat(),
            target_bindings=plans,evidence={"targets":deepcopy(plans)})
        if action in {"UNLOCK_ACCOUNT", "ENABLE_FEATURE"}:
            record.recovery_of = "verified-parent-fixture"
        result = self.executor.execute_record(record,target,"UTEST")
        self.assertTrue(result.ok, result)
        self.assertEqual(len([r for r in self.calls if r.method == "POST"]),1)
        return result

    def test_leafy_bounded_account_lock_contract(self):
        self.execute("LOCK_ACCOUNT",{"account_id":"123","duration_seconds":300})
        self.assertTrue(self.locked)

    def test_leafy_session_revocation_contract(self):
        self.execute("REVOKE_SESSION",{"account_id":"123"})
        self.assertTrue(self.revoked)

    def test_leafy_feature_gate_contract(self):
        self.execute("DISABLE_FEATURE",{"feature_id":"diagnosis"})
        self.assertFalse(self.enabled)

    def test_leafy_explicit_unlock_contract(self):
        self.locked = True
        self.execute("UNLOCK_ACCOUNT", {"account_id":"123", "reason":"reviewed recovery"})
        self.assertFalse(self.locked)

    def test_leafy_explicit_enable_feature_contract(self):
        self.enabled = False
        self.execute("ENABLE_FEATURE", {"feature_id":"diagnosis", "reason":"reviewed recovery"})
        self.assertTrue(self.enabled)
