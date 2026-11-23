"""Actual httpx calls against a synthetic admin contract, never a live Leafy service."""
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

from executor.app_api import AppApiError, AppApiExecutor
import store as store_mod

IDENTITY = {"site": "fixture-gc", "service": "backend", "source": "fixture-docker",
            "runtime": "container", "target": "fixture-backend"}


def config():
    def readback(path, state, account=True):
        return {"path": path, "target_field": "target", "resource_field": "resource.id",
                "action_field": "last_operation.action", "version_field": "version",
                "role_field": "resource.role" if account else None, "state_fields": state,
                "idempotency_field": "last_operation.idempotency_key"}
    lock_read = readback("/fixture/accounts/{resource_id}", {"locked": True})
    lock_read["expires_at_field"] = "lock_expires_at"
    return {"version": 1, "targets": {"fixture-backend": {
        "identity": IDENTITY, "api_contract_verified": True,
        "contract_source": "synthetic-test-contract-only", "base_url": "https://admin.fixture.invalid",
        "token_env": "FIXTURE_APP_API_TOKEN", "timeout_seconds": 5,
        "account_allowlist": ["acct-1"], "feature_allowlist": ["feature-1"],
        "allowed_account_roles": ["USER"], "actions": {
            "LOCK_ACCOUNT": {"method": "POST", "path": "/fixture/accounts/{resource_id}/lock",
                "body": {"target": "{target}", "account_id": "{resource_id}",
                         "duration_seconds": "{duration_seconds}", "expires_at": "{expires_at}",
                         "reason": "{reason}"}, "readback": lock_read},
            "REVOKE_SESSION": {"method": "DELETE", "path": "/fixture/accounts/{resource_id}/sessions",
                "body": {"target": "{target}", "account_id": "{resource_id}", "reason": "{reason}"},
                "readback": readback("/fixture/accounts/{resource_id}", {"sessions_active": 0})},
            "DISABLE_FEATURE": {"method": "PATCH", "path": "/fixture/features/{resource_id}",
                "body": {"target": "{target}", "feature_id": "{resource_id}", "enabled": False},
                "readback": readback("/fixture/features/{resource_id}", {"enabled": False}, account=False)},
        }}}}


class AdminFixture:
    def __init__(self):
        self.requests = []
        self.role = "USER"
        self.version = "v1"
        self.locked = False
        self.enabled = True
        self.sessions = 3
        self.operation = {"action": "NONE", "idempotency_key": ""}
        self.expiry = None
        self.write_error = None
        self.readback_error = None
        self.mutation_status = 200
        self.post_wrong_action = False
        self.post_wrong_resource = False
        self.expiry_override = None

    @property
    def mutations(self):
        return [r for r in self.requests if r.method != "GET"]

    def __call__(self, request):
        self.requests.append(request)
        account = "/accounts/" in request.url.path
        resource = "acct-1" if account else "feature-1"
        if request.method == "GET":
            if self.version != "v1" and self.readback_error:
                raise self.readback_error
            return httpx.Response(200, json={"target": "fixture-backend",
                "resource": {"id": "wrong-resource" if self.version != "v1" and self.post_wrong_resource else resource,
                             "role": self.role}, "version": self.version,
                "locked": self.locked, "enabled": self.enabled, "sessions_active": self.sessions,
                "lock_expires_at": self.expiry, "last_operation": self.operation})
        if self.write_error:
            raise self.write_error
        if self.mutation_status != 200:
            return httpx.Response(self.mutation_status, headers={"Location": "https://evil.fixture.invalid/steal"})
        body = json.loads(request.content)
        if request.url.path.endswith("/lock"):
            action = "LOCK_ACCOUNT"
            self.locked = True
            self.expiry = self.expiry_override or body["expires_at"]
        elif request.url.path.endswith("/sessions"):
            action = "REVOKE_SESSION"
            self.sessions = 0
        else:
            action = "DISABLE_FEATURE"
            self.enabled = False
        self.version = "v2"
        self.operation = {"action": "WRONG_ACTION" if self.post_wrong_action else action,
                          "idempotency_key": request.headers["Idempotency-Key"]}
        return httpx.Response(200, json={"accepted": True})


class AppApiExecutorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "app-api.json"
        self.config = config()
        self.save()
        self.fixture = AdminFixture()
        self.client = httpx.Client(transport=httpx.MockTransport(self.fixture), follow_redirects=True)
        self.addCleanup(self.client.close)
        self.executor = AppApiExecutor(client=self.client, config_path=str(self.path))
        token = patch.dict(os.environ, {"FIXTURE_APP_API_TOKEN": "fixture-secret-token"})
        token.start()
        self.addCleanup(token.stop)

    def save(self):
        self.path.write_text(json.dumps(self.config), encoding="utf-8")

    def record(self, action="LOCK_ACCOUNT", parameters=None):
        if parameters is None:
            parameters = ({"feature_id": "feature-1"} if action == "DISABLE_FEATURE" else {"account_id": "acct-1"})
            if action == "LOCK_ACCOUNT":
                parameters["duration_seconds"] = 300
        plans = self.executor.plan_record(IDENTITY, [IDENTITY["target"]], action, parameters)
        now = datetime.now(timezone.utc)
        return SimpleNamespace(remediation_id="fixture-app-record", identity=deepcopy(IDENTITY),
            targets=[IDENTITY["target"]], action_type=action, action_parameters=parameters,
            target_bindings=plans, requires_approval=True, state="EXECUTING", approved_by="UTEST",
            executor_name="app_api", incident_key="a" * 64, ttl_seconds=None, recovery_mode="none",
            action_hash=store_mod.action_hash(action, [IDENTITY["target"]], None, "none", parameters),
            evidence={"targets": deepcopy(plans)},
            approval_requested_at=(now - timedelta(seconds=3)).isoformat(),
            approved_at=(now - timedelta(seconds=2)).isoformat(),
            action_started_at=(now - timedelta(seconds=1)).isoformat(),
            approval_expires_at=(now + timedelta(minutes=5)).isoformat())

    def execute(self, record):
        return self.executor.execute_record(record, IDENTITY["target"], "UTEST")

    def test_lock_sends_real_https_method_body_auth_conditional_and_idempotency_headers(self):
        record = self.record()
        self.assertNotIn("fixture-secret-token", json.dumps(record.target_bindings))
        result = self.execute(record)
        self.assertTrue(result.ok, result.detail)
        self.assertEqual(len(self.fixture.mutations), 1)
        request = self.fixture.mutations[0]
        self.assertEqual(str(request.url), "https://admin.fixture.invalid/fixture/accounts/acct-1/lock")
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.headers["Authorization"], "Bearer fixture-secret-token")
        self.assertEqual(request.headers["If-Match"], "v1")
        self.assertEqual(len(request.headers["Idempotency-Key"]), 64)
        body = json.loads(request.content)
        self.assertEqual(body["duration_seconds"], 300)
        self.assertEqual(body["account_id"], "acct-1")
        self.assertEqual(body["target"], "fixture-backend")
        self.assertNotIn("fixture-secret-token", json.dumps(result.as_dict()))

    def test_revoke_and_disable_use_individually_configured_contracts(self):
        for action, method, endpoint in (("REVOKE_SESSION", "DELETE", "/fixture/accounts/acct-1/sessions"),
                                         ("DISABLE_FEATURE", "PATCH", "/fixture/features/feature-1")):
            with self.subTest(action=action):
                self.fixture.version = "v1"
                result = self.execute(self.record(action))
                self.assertTrue(result.ok, result.detail)
                request = self.fixture.mutations[-1]
                self.assertEqual((request.method, request.url.path), (method, endpoint))

    def test_timeout_after_write_is_unknown_and_never_retried(self):
        record = self.record()
        self.fixture.write_error = httpx.ReadTimeout("synthetic timeout")
        result = self.execute(record)
        self.assertEqual(result.status, "UNKNOWN")
        self.assertEqual(len(self.fixture.mutations), 1)
        record.state = "UNKNOWN"
        self.assertEqual(self.execute(record).status, "BLOCKED")
        self.assertEqual(len(self.fixture.mutations), 1)

    def test_failed_post_readback_is_unknown_even_when_http_write_succeeded(self):
        record = self.record()
        self.fixture.readback_error = httpx.ReadTimeout("synthetic readback timeout")
        self.assertEqual(self.execute(record).status, "UNKNOWN")
        self.assertTrue(self.fixture.locked)
        self.assertEqual(len(self.fixture.mutations), 1)

    def test_status_200_without_exact_resource_action_and_state_is_never_success(self):
        for flag in ("post_wrong_action", "post_wrong_resource"):
            with self.subTest(flag=flag):
                self.fixture.version = "v1"
                self.fixture.locked = False
                record = self.record()
                setattr(self.fixture, flag, True)
                self.assertEqual(self.execute(record).status, "UNKNOWN")
                setattr(self.fixture, flag, False)

    def test_redirect_does_not_forward_admin_secret(self):
        record = self.record()
        self.fixture.mutation_status = 307
        self.assertEqual(self.execute(record).status, "UNKNOWN")
        self.assertEqual(len(self.fixture.mutations), 1)
        self.assertTrue(all(r.url.host == "admin.fixture.invalid" for r in self.fixture.requests))

    def test_config_or_resource_version_change_invalidates_approval(self):
        record = self.record()
        self.config["targets"]["fixture-backend"]["base_url"] = "https://other.fixture.invalid"
        self.save()
        self.assertIn("contract_changed", self.executor.validate_record(record))
        self.assertEqual(self.execute(record).status, "BLOCKED")
        self.assertEqual(self.fixture.mutations, [])
        self.config = config()
        self.save()
        self.fixture.version = "changed-version"
        self.assertIn("resource_changed", self.executor.validate_record(record))
        self.assertEqual(self.execute(record).status, "BLOCKED")

    def test_changed_parameters_or_identity_cannot_reuse_approved_plan(self):
        record = self.record()
        record.action_parameters["duration_seconds"] = 600
        self.assertEqual(self.execute(record).status, "BLOCKED")
        record.action_parameters["duration_seconds"] = 300
        record.identity["site"] = "other-pc"
        self.assertEqual(self.execute(record).status, "BLOCKED")
        self.assertEqual(self.fixture.mutations, [])

    def test_manual_approval_state_actor_and_expiry_are_mandatory(self):
        record = self.record()
        for attribute, value in (("state", "APPROVED"), ("requires_approval", False),
                                 ("approved_by", "OTHER"), ("approved_at", None),
                                 ("approval_expires_at", "2020-01-01T00:00:00Z")):
            old = getattr(record, attribute)
            setattr(record, attribute, value)
            self.assertEqual(self.execute(record).status, "BLOCKED", attribute)
            setattr(record, attribute, old)
        self.assertEqual(self.fixture.mutations, [])

    def test_lock_expiry_must_be_backend_enforced_and_bounded(self):
        record = self.record()
        self.fixture.expiry_override = (datetime.now(timezone.utc) + timedelta(days=100)).isoformat()
        self.assertEqual(self.execute(record).status, "UNKNOWN")
        self.assertEqual(len(self.fixture.mutations), 1)

    def test_slow_preflight_cannot_outlive_approval_then_mutate(self):
        record = self.record()
        original = self.fixture.__call__
        def handler(request):
            response = original(request)
            if request.method == "GET":
                record.approval_expires_at = "2020-01-01T00:00:00Z"
            return response
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            self.executor._client = client
            self.assertEqual(self.execute(record).status, "BLOCKED")
        self.assertEqual(self.fixture.mutations, [])

    def test_missing_durable_evidence_incident_executor_and_action_hash_are_blocked(self):
        record = self.record()
        for attribute, value in (("evidence", {}), ("incident_key", None),
                                 ("executor_name", "docker"), ("action_hash", "wrong")):
            old = getattr(record, attribute)
            setattr(record, attribute, value)
            self.assertEqual(self.execute(record).status, "BLOCKED", attribute)
            setattr(record, attribute, old)
        record.approved_at = (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()
        self.assertEqual(self.execute(record).status, "BLOCKED")
        self.assertEqual(self.fixture.mutations, [])

    def test_protected_or_unapproved_role_never_reaches_mutation(self):
        for role in ("ADMIN", "ROLE_ADMIN", "SUPER_ADMIN", "OWNER", "SERVICE", "not-allowlisted-role"):
            self.fixture.role = role
            with self.assertRaises(AppApiError):
                self.record()
        self.assertEqual(self.fixture.mutations, [])

    def test_unallowlisted_and_path_injection_resources_make_no_http_calls(self):
        for resource in ("other-account", "../admin", "admin", "acct-1/other", "acct%2Fadmin", "https://evil.invalid"):
            with self.assertRaises(AppApiError):
                self.record(parameters={"account_id": resource, "duration_seconds": 300})
        self.assertEqual(self.fixture.requests, [])

    def test_unsupported_parameters_cannot_supply_origin_path_token_or_shell(self):
        for key in ("base_url", "path", "token", "command", "method"):
            with self.assertRaises(AppApiError):
                self.record(parameters={"account_id": "acct-1", "duration_seconds": 300, key: "arbitrary"})
        self.assertEqual(self.fixture.requests, [])

    def test_dangerous_origin_path_or_template_configuration_is_rejected(self):
        original = deepcopy(self.config)
        mutations = [
            lambda r: r.update(base_url="http://admin.fixture.invalid"),
            lambda r: r.update(base_url="https://user:pass@admin.fixture.invalid"),
            lambda r: r.update(base_url="https://169.254.169.254"),
            lambda r: r.update(base_url="https://localhost"),
            lambda r: r.update(base_url="https://admin.fixture.invalid/other-origin"),
            lambda r: r["actions"]["LOCK_ACCOUNT"].update(path="//evil.fixture.invalid/steal"),
            lambda r: r["actions"]["LOCK_ACCOUNT"].update(path="/fixture/../admin"),
            lambda r: r["actions"]["LOCK_ACCOUNT"].update(path="/fixture/{reason}"),
            lambda r: r["actions"]["LOCK_ACCOUNT"]["body"].update(secret="{resource_id.__class__}"),
            lambda r: r.update(api_contract_verified=False),
            lambda r: r.update(allowed_account_roles=["ADMIN"]),
            lambda r: r.update(allowed_account_roles=["ROLE_ADMIN"]),
            lambda r: r.update(allowed_account_roles=[" ADMIN "]),
            lambda r: r.update(account_allowlist=["admin"]),
        ]
        for mutate in mutations:
            self.config = deepcopy(original)
            mutate(self.config["targets"]["fixture-backend"])
            self.save()
            with self.assertRaises(AppApiError):
                self.record()
        self.assertEqual(self.fixture.requests, [])

    def test_missing_secret_never_sends_request_and_secret_file_can_be_used(self):
        with patch.dict(os.environ, {"FIXTURE_APP_API_TOKEN": ""}):
            with self.assertRaises(AppApiError):
                self.record()
        self.assertEqual(self.fixture.requests, [])
        secret = Path(self.temp.name) / "token"
        secret.write_text("fixture-file-secret", encoding="utf-8")
        row = self.config["targets"]["fixture-backend"]
        row.pop("token_env")
        row["token_file"] = str(secret)
        self.save()
        self.assertTrue(self.execute(self.record()).ok)
        self.assertEqual(self.fixture.mutations[-1].headers["Authorization"], "Bearer fixture-file-secret")

    def test_already_applied_state_does_not_extend_lock_or_send_redundant_write(self):
        self.fixture.locked = True
        with self.assertRaisesRegex(AppApiError, "already_present"):
            self.record()
        self.assertEqual(self.fixture.mutations, [])

    def test_lock_requires_explicit_positive_bounded_duration(self):
        for duration in (None, False, 0, -1, 86401, "300"):
            with self.assertRaises(AppApiError):
                self.record(parameters={"account_id": "acct-1", "duration_seconds": duration})
        self.assertEqual(self.fixture.requests, [])

    def test_plan_requires_exact_single_observation_target(self):
        for targets in ([], ["wrong-target"], ["fixture-backend", "other-target"]):
            with self.assertRaises(AppApiError):
                self.executor.plan_record(IDENTITY, targets, "LOCK_ACCOUNT", {"account_id": "acct-1", "duration_seconds": 300})
        self.assertEqual(self.fixture.requests, [])
