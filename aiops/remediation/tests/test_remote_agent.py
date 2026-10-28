"""All HTTP is in-process; all Docker objects are FakeDocker. Run with isolated runner."""
from concurrent.futures import ThreadPoolExecutor
import copy
import json
import os
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
import httpx

from agent.api import create_app, InstanceLock
from agent.contract import AgentConfig, Command
from agent.ledger import Conflict, Ledger
from agent.service import AgentService, Denied
from executor.remote import RemoteExecutor
from executor.remote_sync import reconcile
from security.agent_auth import headers
import store
from tests.test_executor import BUSINESS, MGMT, FakeDocker, inspect_doc

KEY = "agent-test-key-" + "1" * 40
CID = "a" * 64
IMAGE = "sha256:" + "b" * 64
TARGET = "leafy-backend"


def config():
    return AgentConfig.model_validate({"controller_id": "pc1", "targets": {TARGET: {
        "container_id": CID, "image_id": IMAGE,
        "labels": {"io.leafy.remediation": "workload", "com.docker.compose.service": "backend",
                   "com.docker.compose.project": "leafy-test"},
        "actions": ["RESTART", "PAUSE", "ISOLATE", "THROTTLE", "UNPAUSE", "RECONNECT", "UNTHROTTLE"],
        "isolate_networks": ["leafy-net"], "preserve_networks": ["mgmt-net"]}}})


def command(action="ISOLATE", rid="r1", **kw):
    reversible = action in ("ISOLATE", "PAUSE", "THROTTLE")
    values = {"remediation_id": rid, "action_type": action, "target": TARGET,
              "authorization": {"decision_id": rid, "approval_id": "approval:" + rid,
                                "approved_by": "operator", "kind": "manual"},
              "expires_at": int(time.time()) + 120,
              "ttl_seconds": 60 if reversible else None,
              "recovery_mode": ("auto" if action == "THROTTLE" else "require_approval") if reversible else "none"}
    values.update(kw)
    return Command.model_validate(values)


def setup_case(case, **flags):
    case.tmp = tempfile.TemporaryDirectory()
    case.addCleanup(case.tmp.cleanup)
    case.path = os.path.join(case.tmp.name, "agent.sqlite3")
    case.doc = inspect_doc({BUSINESS: {"ip": "10.210.0.7", "aliases": ["backend", "leafy-backend"]},
                           MGMT: {"ip": "10.211.0.7"}}, cid=CID)
    case.doc["Image"] = IMAGE
    case.doc["Config"]["Labels"] = dict(config().targets[TARGET].labels)
    case.fake = FakeDocker(case.doc, **flags)
    case.fake.restart_effect = lambda: case.doc["State"].update(StartedAt="new-start")
    case.factory = Mock(return_value=case.fake)
    case.ledger = Ledger(case.path)
    case.service = AgentService(config(), case.ledger, mode="live", client_factory=case.factory)
    case.client = TestClient(create_app(case.service, KEY))
    case.addCleanup(case.client.close)


def send(case, cmd=None, path="/v1/executions", body=None, header_changes=None, **header_kw):
    body = body if body is not None else (cmd or command()).model_dump_json().encode()
    auth = headers(KEY, "POST", path, body, **header_kw)
    auth.update(header_changes or {})
    return case.client.post(path, content=body, headers=auth)


class AuthenticationTest(unittest.TestCase):
    def setUp(self):
        setup_case(self)

    def test_valid_hmac_executes_and_verifies(self):
        response = send(self)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["execution"]["verified"])
        self.assertEqual(len(self.fake.calls), 1)

    def test_bad_signatures_never_reach_docker_sdk(self):
        for changes in ({"x-agent-signature": "v0=" + "0" * 64}, {"x-agent-signature": "bad"},
                        {"x-agent-controller": "intruder"}, {"x-agent-nonce": "not-a-nonce"},
                        {"x-agent-timestamp": "nan"}, {"x-agent-timestamp": "inf"}):
            self.assertEqual(send(self, header_changes=changes).status_code, 401)
        self.factory.assert_not_called()
        self.assertEqual(self.fake.calls, [])
        self.assertEqual(self.ledger.all(), [])

    def test_old_and_future_timestamps(self):
        for now in (time.time()-120, time.time()+120):
            self.assertEqual(send(self, now=now).status_code, 401)
        self.factory.assert_not_called()

    def test_body_and_route_bound_to_signature(self):
        body = command().model_dump_json().encode()
        auth = headers(KEY, "POST", "/v1/executions", body)
        self.assertEqual(self.client.post("/v1/executions", content=body+b" ", headers=auth).status_code, 401)
        self.assertEqual(self.client.post("/v1/recoveries", content=body, headers=auth).status_code, 401)
        self.factory.assert_not_called()

    def test_method_bound_to_signature(self):
        path = "/v1/executions/r1/leafy-backend"
        auth = headers(KEY, "POST", path, b"")
        self.assertEqual(self.client.get(path, headers=auth).status_code, 401)
        self.factory.assert_not_called()

    def test_nonce_replay_survives_restart(self):
        cmd = command("RESTART")
        body = cmd.model_dump_json().encode()
        auth = headers(KEY, "POST", "/v1/executions", body)
        self.assertEqual(self.client.post("/v1/executions", content=body, headers=auth).status_code, 200)
        other = AgentService(config(), Ledger(self.path), "live", self.factory)
        with TestClient(create_app(other, KEY)) as client:
            self.assertEqual(client.post("/v1/executions", content=body, headers=auth).status_code, 401)
        self.assertEqual(self.fake.calls, ["restart"])

    def test_key_unset_and_short_fail_closed(self):
        for secret in ("", "short"):
            self.client = TestClient(create_app(self.service, secret))
            self.assertEqual(send(self).status_code, 401)
            self.client.close()
        self.factory.assert_not_called()

    def test_nonce_persistence_failure_blocks_sdk(self):
        with patch.object(self.ledger, "remember_nonce", side_effect=OSError("disk")):
            self.assertEqual(send(self).status_code, 503)
        self.factory.assert_not_called()

    def test_health_never_uses_docker(self):
        self.assertEqual(self.client.get("/healthz").status_code, 200)
        self.factory.assert_not_called()

    def test_status_requires_auth(self):
        self.assertEqual(self.client.get("/v1/executions/r1/leafy-backend").status_code, 401)
        self.factory.assert_not_called()


class AuthorizationTest(unittest.TestCase):
    def setUp(self):
        setup_case(self)

    def test_unlisted_and_management_targets_blocked(self):
        for target in ("random", "aiops-pipeline", "aiops-remediation", "remediation-agent", "postgres"):
            self.assertEqual(send(self, command(target=target)).status_code, 403)
        self.factory.assert_not_called()

    def test_even_explicitly_registered_management_container_denied(self):
        self.service.config.targets["aiops-remediation"] = config().targets[TARGET]
        self.assertEqual(send(self, command(target="aiops-remediation")).status_code, 403)
        self.factory.assert_not_called()

    def test_high_risk_requires_manual_and_auto_throttle_is_disabled(self):
        for action in ("RESTART", "PAUSE", "ISOLATE", "THROTTLE"):
            cmd = command(action)
            cmd.authorization.kind = "policy"
            self.assertEqual(send(self, cmd).status_code, 403)
        self.factory.assert_not_called()

    def test_expired_request_and_excessive_lifetime(self):
        for expiry in (int(time.time())-1, int(time.time())+1000):
            self.assertEqual(send(self, command(expires_at=expiry)).status_code, 403)
        self.factory.assert_not_called()

    def test_unknown_action_and_extra_docker_options(self):
        values = command().model_dump()
        for changes in ({"action_type": "EXEC"}, {"docker_options": {"privileged": True}}):
            self.assertEqual(send(self, body=json.dumps({**values, **changes}).encode()).status_code, 422)
        self.factory.assert_not_called()

    def test_no_direct_recovery_without_original_evidence(self):
        cmd = command("RECONNECT")
        self.assertEqual(send(self, cmd).status_code, 403)
        self.assertEqual(send(self, cmd, path="/v1/recoveries").status_code, 409)
        self.factory.assert_not_called()

    def test_action_allowlist_independent_of_controller(self):
        self.service.config.targets[TARGET].actions = ["RESTART"]
        self.assertEqual(send(self).status_code, 403)
        self.factory.assert_not_called()

    def test_isolate_cannot_request_automatic_reconnect(self):
        self.assertEqual(send(self, command(recovery_mode="auto")).status_code, 403)
        self.factory.assert_not_called()

    def test_name_alone_is_insufficient(self):
        for field, value in (("Id", "c"*64), ("Image", "sha256:"+"d"*64), ("Name", "/other")):
            original = self.doc[field]
            self.doc[field] = value
            result = send(self, command("RESTART", rid=field)).json()
            self.assertFalse(result["execution"]["verified"])
            self.assertEqual(result["state"], "BLOCKED")
            self.doc[field] = original
        self.assertEqual(self.fake.calls, [])

    def test_runtime_labels_and_privileges_verified(self):
        self.doc["Config"]["Labels"]["com.docker.compose.project"] = "attacker"
        self.assertEqual(send(self).json()["state"], "BLOCKED")
        self.assertEqual(self.fake.calls, [])

    def test_disabled_never_constructs_sdk(self):
        self.service.mode = "disabled"
        self.assertEqual(send(self).json()["state"], "SKIPPED")
        self.factory.assert_not_called()


class IdempotencyTest(unittest.TestCase):
    def setUp(self):
        setup_case(self)

    def test_duplicate_http_delivery_runs_once(self):
        first = send(self, command("RESTART")).json()
        second = send(self, command("RESTART")).json()
        self.assertEqual(first, second)
        self.assertEqual(self.fake.calls, ["restart"])

    def test_success_survives_agent_restart(self):
        self.service.execute(command("RESTART"))
        other = AgentService(config(), Ledger(self.path), "live", self.factory)
        self.assertEqual(other.execute(command("RESTART"))["state"], "SUCCESS")
        self.assertEqual(self.fake.calls, ["restart"])

    def test_simultaneous_duplicate_claims_only_one_mutation(self):
        cmd = command("RESTART")
        with ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(lambda _: self.service.execute(cmd), range(12)))
        self.assertEqual(self.fake.calls, ["restart"])

    def test_same_id_different_payload_conflicts(self):
        self.service.execute(command("RESTART"))
        self.assertEqual(send(self, command("PAUSE")).status_code, 409)
        self.assertEqual(self.fake.calls, ["restart"])

    def test_target_with_unresolved_action_rejects_new_id(self):
        self.service.execute(command())
        self.assertEqual(send(self, command("RESTART", rid="new")).status_code, 409)
        self.assertEqual(len(self.fake.calls), 1)

    def test_crash_after_claim_never_reexecutes(self):
        cmd = command("RESTART")
        self.ledger.claim(cmd)
        other = AgentService(config(), Ledger(self.path), "live", self.factory)
        other.reconcile_interrupted()
        self.assertEqual(other.execute(cmd)["state"], "UNKNOWN")
        self.factory.assert_not_called()

    def test_evidence_persistence_failure_never_mutates(self):
        original = self.ledger.save
        def fail_evidence(record, release=False):
            if record["evidence"] and record["state"] == "EXECUTING":
                raise OSError("disk full")
            return original(record, release)
        with patch.object(self.ledger, "save", side_effect=fail_evidence):
            self.assertEqual(self.service.execute(command())["state"], "UNKNOWN")
        self.assertEqual(self.fake.calls, [])

    def test_process_lock_prevents_second_instance(self):
        lock = InstanceLock(self.path + ".lock")
        try:
            with self.assertRaises(OSError):
                InstanceLock(self.path + ".lock")
        finally:
            lock.close()

    def test_corrupt_sqlite_fails_closed(self):
        path = os.path.join(self.tmp.name, "corrupt.sqlite3")
        with open(path, "wb") as f:
            f.write(b"corrupt database")
        with self.assertRaises(Exception):
            Ledger(path)
        self.factory.assert_not_called()

    def test_unresolved_recovery_never_reexecutes_after_restart(self):
        self.service.execute(command())
        self.ledger.claim_recovery(command("RECONNECT"))
        restarted = AgentService(config(), Ledger(self.path), "live", self.factory)
        restarted.reconcile_interrupted()
        result = restarted.recover(command("RECONNECT"))
        self.assertEqual(result["recovery_state"], "UNKNOWN")
        self.assertEqual(len(self.fake.calls), 1)

    def test_recovery_does_not_touch_another_remediation_lease(self):
        record = self.service.execute(command())
        # Simulate an operation proven not to have mutated, with its lease released.
        self.ledger.save(record, release=True)
        self.ledger.claim(command("RESTART", rid="new-owner"))
        with self.assertRaises(Conflict):
            self.service.recover(command("RECONNECT"))
        self.assertEqual(len(self.fake.calls), 1)


class RecoveryTest(unittest.TestCase):
    def setUp(self):
        setup_case(self)

    def test_reconnect_preserves_ip_alias_and_management_path(self):
        initial = copy.deepcopy(self.doc["NetworkSettings"]["Networks"])
        self.service.execute(command())
        self.assertIn(MGMT, self.doc["NetworkSettings"]["Networks"])
        self.assertNotIn(BUSINESS, self.doc["NetworkSettings"]["Networks"])
        response = send(self, command("RECONNECT"), path="/v1/recoveries")
        result = response.json()
        self.assertTrue(result["recovery"]["verified"])
        actual = self.doc["NetworkSettings"]["Networks"][BUSINESS]
        self.assertEqual(actual["IPAddress"], initial[BUSINESS]["IPAddress"])
        self.assertEqual(actual["Aliases"], initial[BUSINESS]["Aliases"])
        self.assertEqual(result["observation"], "awaiting_zeek_subnet_rediscovery")
        self.assertEqual(self.doc["NetworkSettings"]["Networks"][MGMT], initial[MGMT])

    def test_duplicate_recovery_and_restart_preserve_idempotency(self):
        self.service.execute(command())
        self.service.recover(command("RECONNECT"))
        other = AgentService(config(), Ledger(self.path), "live", self.factory)
        other.recover(command("RECONNECT"))
        self.assertEqual(len(self.fake.calls), 2)

    def test_recovery_requires_new_manual_attestation(self):
        self.service.execute(command())
        cmd = command("RECONNECT")
        cmd.authorization.kind = "policy"
        self.assertEqual(send(self, cmd, path="/v1/recoveries").status_code, 403)
        self.assertEqual(len(self.fake.calls), 1)

    def test_isolate_and_pause_ttl_never_auto_recover(self):
        for action in ("ISOLATE", "PAUSE"):
            # Separate fixture target lease for each subcase.
            record = self.service.execute(command(action, rid=action))
            record["deadline"] = time.time()-1
            self.ledger.save(record)
            count = len(self.fake.calls)
            self.service.tick()
            self.assertEqual(len(self.fake.calls), count)
            self.service.recover(command("RECONNECT" if action == "ISOLATE" else "UNPAUSE", rid=action))

    def test_throttle_restores_original_period_quota_without_pc1(self):
        self.doc["HostConfig"].update(CpuQuota=120000, CpuPeriod=200000)
        record = self.service.execute(command("THROTTLE"))
        self.assertEqual(record["state"], "SUCCESS")
        record["deadline"] = time.time()-1
        self.ledger.save(record)
        other = AgentService(config(), Ledger(self.path), "live", self.factory)
        other.tick()
        self.assertEqual(self.doc["HostConfig"]["CpuQuota"], 120000)
        self.assertEqual(self.doc["HostConfig"]["CpuPeriod"], 200000)
        self.assertEqual(self.ledger.get("r1", TARGET)["recovery_state"], "SUCCESS")

    def test_verification_failure_is_not_success(self):
        self.fake.disconnect_applies = False
        result = self.service.execute(command())
        self.assertEqual(result["state"], "FAILED")
        self.assertFalse(result["execution"]["verified"])
        self.assertIsNone(result["verified_at"])
        self.assertTrue(result["evidence"])

    def test_failed_reconnect_does_not_set_recovered_timestamp(self):
        self.service.execute(command())
        self.fake.connect_ip = "10.210.0.99"
        result = self.service.recover(command("RECONNECT"))
        self.assertEqual(result["recovery_state"], "FAILED")
        self.assertIsNone(result["recovery_verified_at"])

    def test_replaced_container_cannot_be_recovered(self):
        self.service.execute(command())
        self.doc["Id"] = "c"*64
        result = self.service.recover(command("RECONNECT"))
        self.assertFalse(result["recovery"]["verified"])
        self.assertEqual(len(self.fake.calls), 1)

    def test_disabled_preserves_recovery_claim(self):
        self.service.execute(command())
        self.service.mode = "disabled"
        self.service.recover(command("RECONNECT"))
        self.assertIsNone(self.ledger.get("r1", TARGET)["recovery_state"])
        self.service.mode = "live"
        self.assertTrue(self.service.recover(command("RECONNECT"))["recovery"]["verified"])

    def test_network_id_replacement_is_not_reconnected(self):
        self.service.execute(command())
        from tests.test_executor import FakeNetwork
        original = FakeNetwork.__init__
        def replaced(obj, fake, name):
            original(obj, fake, name)
            obj.id = "replacement-id"
        with patch.object(FakeNetwork, "__init__", replaced):
            result = self.service.recover(command("RECONNECT"))
        self.assertEqual(result["recovery_state"], "BLOCKED")
        self.assertEqual(len(self.fake.calls), 1)

    def test_nanocpu_mode_fails_closed_without_mutation(self):
        self.doc["HostConfig"]["NanoCpus"] = 1_000_000_000
        self.assertEqual(self.service.execute(command("THROTTLE"))["state"], "BLOCKED")
        self.assertEqual(self.fake.calls, [])

    def test_missing_recovery_permission_blocks_initial_action(self):
        self.service.config.targets[TARGET].actions.remove("UNTHROTTLE")
        with self.assertRaises(Denied):
            self.service.execute(command("THROTTLE"))
        self.factory.assert_not_called()

    def test_preexisting_pause_is_not_claimed_for_later_unpause(self):
        self.doc["State"].update(Paused=True)
        self.assertEqual(self.service.execute(command("PAUSE"))["state"], "BLOCKED")
        self.assertEqual(self.fake.calls, [])

    def test_throttle_cannot_relax_an_existing_lower_cpu_limit(self):
        self.doc["HostConfig"].update(CpuQuota=20000, CpuPeriod=100000)
        self.assertEqual(self.service.execute(command("THROTTLE"))["state"], "BLOCKED")
        self.assertEqual(self.fake.calls, [])

    def test_partial_unknown_execution_can_be_manually_recovered(self):
        cmd = command()
        record, _ = self.ledger.claim(cmd)
        executor = self.service.executor(TARGET, config().targets[TARGET])
        record["evidence"] = executor.snapshot(CID)
        self.ledger.save(record)
        executor.execute("ISOLATE", CID, record["evidence"])
        # Simulate power loss before saving the result.
        self.service.reconcile_interrupted()
        self.assertEqual(self.service.execute(cmd)["state"], "UNKNOWN")
        self.assertTrue(self.service.recover(command("RECONNECT"))["recovery"]["verified"])
        self.assertEqual(len(self.fake.calls), 2)

    def test_live_docker_calls_always_use_immutable_container_id(self):
        seen = []
        original = FakeDocker._Containers.get
        def get(collection, target):
            seen.append(target)
            return original(collection, target)
        with patch.object(FakeDocker._Containers, "get", get):
            self.service.execute(command("PAUSE"))
            self.service.recover(command("UNPAUSE"))
        self.assertTrue(seen)
        self.assertEqual(set(seen), {CID})

    def test_before_deadline_and_disabled_scanner_do_not_restore(self):
        self.service.execute(command("THROTTLE"))
        self.service.tick()
        self.assertEqual(len(self.fake.calls), 1)
        record = self.ledger.get("r1", TARGET)
        record["deadline"] = time.time()-1
        self.ledger.save(record)
        self.service.mode = "disabled"
        self.service.tick()
        self.assertEqual(len(self.fake.calls), 1)

    def test_ttl_failure_for_one_record_does_not_starve_others(self):
        record = self.service.execute(command("THROTTLE"))
        record["deadline"] = time.time()-1
        second = {**record, "remediation_id": "other"}
        with patch.object(self.ledger, "all", return_value=[record, second]):
            with patch.object(self.service, "recover", side_effect=[Denied("removed rule"), {}]) as recover:
                self.service.tick()
                self.assertEqual(recover.call_count, 2)


class RemoteExecutorTest(unittest.TestCase):
    def setUp(self):
        setup_case(self)
        self.timeout_after_post = False
        self.timeout_before_post = False
        self.offline = False
        self.requests = []
        def transport(request):
            self.requests.append((request.method, request.url.path))
            if self.offline or (self.timeout_before_post and request.method == "POST"):
                raise httpx.ReadTimeout("offline", request=request)
            response = self.client.request(request.method, request.url.path,
                                           content=request.content, headers=request.headers)
            if self.timeout_after_post and request.method == "POST":
                raise httpx.ReadTimeout("reply lost", request=request)
            return httpx.Response(response.status_code, content=response.content, request=request)
        self.http = httpx.Client(transport=httpx.MockTransport(transport))
        self.addCleanup(self.http.close)
        self.remote = RemoteExecutor("https://pc2.test.ts.net", KEY, client=self.http)
        self.record = store.RemediationRecord("r1", "alert", "ISOLATE", targets=[TARGET],
                                             approved_by="operator", ttl_seconds=60,
                                             recovery_mode="require_approval", executor_name="remote")

    def test_reply_lost_queries_status_without_reexecuting(self):
        self.timeout_after_post = True
        result = self.remote.execute_record(self.record, TARGET)
        self.assertTrue(result.ok)
        self.assertEqual(len(self.fake.calls), 1)
        self.assertEqual([method for method, _ in self.requests], ["POST", "GET"])

    def test_unknown_during_outage_then_safe_same_id_retry(self):
        self.offline = True
        self.assertEqual(self.remote.execute_record(self.record, TARGET).status, "UNKNOWN")
        self.assertEqual(self.fake.calls, [])
        self.offline = False
        self.assertTrue(self.remote.execute_record(self.record, TARGET).ok)
        self.assertTrue(self.remote.execute_record(self.record, TARGET).ok)
        self.assertEqual(len(self.fake.calls), 1)

    def test_timeout_before_delivery_and_404_stays_unknown(self):
        self.timeout_before_post = True
        self.assertEqual(self.remote.execute_record(self.record, TARGET).status, "UNKNOWN")
        self.assertEqual(self.fake.calls, [])

    def test_missing_approved_record_context_is_blocked(self):
        result = self.remote.execute("RESTART", TARGET, {})
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(self.requests, [])

    def test_no_plaintext_or_public_origin(self):
        for url in ("http://pc2.test.ts.net", "https://example.com", "https://pc2.test.ts.net/path",
                    "https://user@pc2.test.ts.net"):
            with self.assertRaises(ValueError):
                RemoteExecutor(url, KEY, client=self.http)

    def test_unverified_success_and_wrong_identity_are_rejected(self):
        self.remote.execute_record(self.record, TARGET)
        doc = self.ledger.get("r1", TARGET)
        doc["execution"]["verified"] = False
        self.assertEqual(self.remote.result_from_status(doc, "ISOLATE", TARGET, "r1").status, "UNKNOWN")
        doc["target"] = "other"
        with self.assertRaises(ValueError):
            self.remote.result_from_status(doc, "ISOLATE", TARGET, "r1")

    def test_remote_recovery_uses_agent_evidence_and_mttr(self):
        s = store.RecordStore(os.path.join(self.tmp.name, "pc1.json"))
        self.record.alert_active_at = "2026-10-29T00:00:00+00:00"
        s.create(self.record)
        self.remote.execute_record(self.record, TARGET)
        reconcile(s, self.remote, self.record)
        self.assertEqual(s.get("r1").state, store.RECOVERY_PENDING)
        self.assertTrue(s.get("r1").evidence["targets"][TARGET]["container_id"])
        self.assertIsNone(s.get("r1").mttr())
        self.assertTrue(self.remote.execute_record(self.record, TARGET, "operator", "RECONNECT").ok)
        reconcile(s, self.remote, self.record)
        self.assertEqual(s.get("r1").state, store.RECOVERED)
        self.assertIsNotNone(s.get("r1").mttr())

    def test_controller_does_not_recover_remote_record_using_local_docker(self):
        import recovery
        s = store.RecordStore(os.path.join(self.tmp.name, "pc1.json"))
        self.record.state = store.RECOVERY_PENDING
        s.create(self.record)
        local = Mock(name="local")
        local.name = "local_docker"
        local.changes_system = True
        recovery.recover(s, local, self.record, "operator", True)
        local.execute.assert_not_called()

    def test_stale_status_cannot_overwrite_newer_controller_transition(self):
        s = store.RecordStore(os.path.join(self.tmp.name, "pc1.json"))
        s.create(self.record)
        self.remote.execute_record(self.record, TARGET)
        original = self.remote.status
        def status(rid, target):
            doc = original(rid, target)
            s.update(rid, state=store.RECOVERED)
            return doc
        with patch.object(self.remote, "status", side_effect=status):
            reconcile(s, self.remote, self.record)
        self.assertEqual(self.record.state, store.RECOVERED)

    def test_conflicting_payload_is_not_reported_as_cached_success(self):
        self.assertTrue(self.remote.execute_record(self.record, TARGET).ok)
        self.record.ttl_seconds = 120
        self.assertEqual(self.remote.execute_record(self.record, TARGET).status, "BLOCKED")
        self.assertEqual(len(self.fake.calls), 1)

    def test_disabled_agent_reconciles_as_skipped(self):
        s = store.RecordStore(os.path.join(self.tmp.name, "pc1.json"))
        s.create(self.record)
        self.service.mode = "disabled"
        self.assertEqual(self.remote.execute_record(self.record, TARGET).status, "SKIPPED")
        reconcile(s, self.remote, self.record)
        self.assertEqual(self.record.state, store.SKIPPED)
        self.factory.assert_not_called()
