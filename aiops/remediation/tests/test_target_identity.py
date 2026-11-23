"""Verified observation/Agent/container bindings, using fake inspect and in-process HTTP."""
import copy
from datetime import datetime, timezone
import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from executor.base import DisabledExecutor
from executor.identity import IdentityError, bind_targets, validate_bindings
from executor.local_docker import LocalDockerExecutor
import evidence
from tests.test_executor import FakeDocker, inspect_doc
from tests import test_remote_agent as fixtures


class LocalBindingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "bindings.json")
        self.binding = fixtures.target_binding("local_docker")
        self.write([self.binding])
        env = patch.dict(os.environ, {"REMEDIATION_TARGET_BINDINGS_PATH": self.path})
        env.start()
        self.addCleanup(env.stop)
        self.doc = inspect_doc(cid=fixtures.CID)
        self.doc["Image"] = fixtures.IMAGE
        self.doc["Config"]["Labels"] = dict(self.binding["container"]["labels"])
        self.fake = FakeDocker(self.doc)
        self.executor = LocalDockerExecutor(client=self.fake)

    def write(self, bindings):
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "bindings": bindings}, fh)

    def record(self):
        return SimpleNamespace(identity=dict(fixtures.IDENTITY), targets=[fixtures.TARGET],
                               action_type="RESTART", target_bindings={fixtures.TARGET: self.binding})

    def test_bind_is_readonly_and_validation_reuses_exact_identity(self):
        bound = bind_targets(fixtures.IDENTITY, [fixtures.TARGET], self.executor)
        self.assertEqual(bound, {fixtures.TARGET: self.binding})
        self.assertIsNone(validate_bindings(self.record(), self.executor))
        self.assertEqual(self.fake.calls, [])

    def test_unknown_host_wrong_target_and_wrong_pc_never_mutate(self):
        for identity in ({**fixtures.IDENTITY, "source": "UNKNOWN"},
                         {**fixtures.IDENTITY, "runtime": "host"},
                         {**fixtures.IDENTITY, "site": "another-pc"}):
            with self.assertRaises(IdentityError):
                bind_targets(identity, [fixtures.TARGET], self.executor)
        with self.assertRaises(IdentityError):
            bind_targets(fixtures.IDENTITY, ["other"], self.executor)
        self.assertEqual(self.fake.calls, [])

    def test_replacement_image_and_label_require_reapproval(self):
        for key, replacement in (("Id", "c" * 64), ("Image", "sha256:" + "d" * 64)):
            original = self.doc[key]
            self.doc[key] = replacement
            self.assertIsNotNone(validate_bindings(self.record(), self.executor))
            result = self.executor.execute("RESTART", fixtures.TARGET, {"target_binding": self.binding})
            self.assertEqual(result.status, "BLOCKED")
            self.doc[key] = original
        self.doc["Config"]["Labels"]["com.docker.compose.project"] = "changed"
        self.assertIsNotNone(validate_bindings(self.record(), self.executor))
        self.assertEqual(self.fake.calls, [])

    def test_config_change_duplicate_and_ambiguous_source_fail_closed(self):
        changed = copy.deepcopy(self.binding)
        changed["container"]["actions"].remove("RESTART")
        self.write([changed])
        self.assertIsNotNone(validate_bindings(self.record(), self.executor))
        self.write([self.binding, self.binding])
        with self.assertRaises(IdentityError):
            bind_targets(fixtures.IDENTITY, [fixtures.TARGET], self.executor)
        other = copy.deepcopy(self.binding)
        other["identity"]["target"] = "leafy-frontend"
        other["identity"]["service"] = "frontend"
        other["container"]["labels"]["com.docker.compose.service"] = "frontend"
        other["agent_id"] = "other-agent"
        self.write([self.binding, other])
        with self.assertRaises(IdentityError):
            bind_targets(fixtures.IDENTITY, [fixtures.TARGET], self.executor)
        self.assertEqual(self.fake.calls, [])

    def test_disabled_does_not_need_binding_or_inspect(self):
        self.assertEqual(bind_targets({}, [], DisabledExecutor()), {})

    def test_actual_mutation_uses_whole_id_and_timeout_is_unknown(self):
        targets = []
        original = FakeDocker._Containers.get
        def get(collection, target):
            targets.append(target)
            return original(collection, target)
        self.fake.restart_effect = lambda: self.doc["State"].update(StartedAt="new")
        with patch.object(FakeDocker._Containers, "get", get):
            result = self.executor.execute("RESTART", fixtures.TARGET, {"target_binding": self.binding})
        self.assertTrue(result.ok)
        self.assertEqual(set(targets), {fixtures.CID})
        def lost():
            raise TimeoutError("reply lost after mutation")
        self.fake.restart_effect = lost
        self.assertEqual(self.executor.execute("RESTART", fixtures.TARGET,
                         {"target_binding": self.binding}).status, "UNKNOWN")

    def test_restart_captures_preoperation_state_without_env_or_raw_logs(self):
        self.doc["Config"]["Env"] = ["PASSWORD=do-not-store-this"]
        self.doc["LogOutput"] = "private-raw-log-do-not-store"
        snapshot, reason = evidence.gate(self.executor, SimpleNamespace(writable=True),
                                         "restart-record", "RESTART", [fixtures.TARGET])
        self.assertIsNone(reason)
        before = snapshot["targets"][fixtures.TARGET]
        self.assertEqual(before["container_id"], fixtures.CID)
        self.assertEqual(before["image_id"], fixtures.IMAGE)
        self.assertEqual(before["state"]["started_at"], self.doc["State"]["StartedAt"])
        self.assertIn("networks", before)
        self.assertIn("resources", before)
        saved = json.dumps(snapshot)
        self.assertNotIn("do-not-store", saved)
        self.assertNotIn("Env", saved)
        self.assertEqual(self.fake.calls, [])
        with patch.object(self.executor, "snapshot", side_effect=RuntimeError("unavailable")):
            _, reason = evidence.gate(self.executor, SimpleNamespace(writable=True),
                                      "restart-record", "RESTART", [fixtures.TARGET])
        self.assertIsNotNone(reason)
        self.assertEqual(self.fake.calls, [])

    def test_slow_pinned_inspect_cannot_execute_after_approval_deadline(self):
        now = 1000
        original = FakeDocker._Containers.get
        def slow_get(collection, target):
            nonlocal now
            now = 1006
            return original(collection, target)
        expiry = datetime.fromtimestamp(1005, timezone.utc).isoformat()
        with patch("executor.local_docker.time.time", side_effect=lambda: now), \
             patch.object(FakeDocker._Containers, "get", slow_get):
            result = self.executor.execute("RESTART", fixtures.TARGET,
                {"target_binding": self.binding, "approval_expires_at": expiry})
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(self.fake.calls, [])


class AgentIdentityTest(unittest.TestCase):
    def setUp(self):
        fixtures.setup_case(self)

    def test_missing_legacy_identity_wire_command_rejected(self):
        body = fixtures.command().model_dump()
        for field in ("identity", "agent_id", "approved_target"):
            altered = {k: v for k, v in body.items() if k != field}
            self.assertEqual(fixtures.send(self, body=json.dumps(altered).encode()).status_code, 422)
        self.factory.assert_not_called()

    def test_wrong_pc_agent_and_approved_target_denied_before_docker(self):
        commands = [fixtures.command(identity={**fixtures.IDENTITY, "site": "another-pc"}),
                    fixtures.command(agent_id="another-agent"),
                    fixtures.command(approved_target={**fixtures.command().approved_target.model_dump(),
                                                      "container_id": "c" * 64})]
        for cmd in commands:
            self.assertEqual(fixtures.send(self, cmd).status_code, 403)
        self.factory.assert_not_called()

    def test_placeholder_identity_remains_denied_even_if_operator_config_is_bad(self):
        self.service.config.site = "UNKNOWN"
        cmd = fixtures.command(identity={**fixtures.IDENTITY, "site": "UNKNOWN"})
        self.assertEqual(fixtures.send(self, cmd).status_code, 403)
        self.factory.assert_not_called()

    def test_allowlist_refresh_cannot_apply_old_approval_to_new_container(self):
        self.service.config.targets[fixtures.TARGET].container_id = "c" * 64
        self.doc["Id"] = "c" * 64
        self.assertEqual(fixtures.send(self).status_code, 403)
        self.factory.assert_not_called()

    def test_authenticated_preapproval_snapshot_has_zero_mutations(self):
        from security.agent_auth import headers
        path = "/v1/targets/" + fixtures.TARGET
        self.assertEqual(self.client.get(path).status_code, 401)
        response = self.client.get(path, headers=headers(fixtures.KEY, "GET", path, b""))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["identity"], fixtures.IDENTITY)
        self.assertEqual(response.json()["container_id"], fixtures.CID)
        self.assertEqual(response.json()["image_id"], fixtures.IMAGE)
        self.assertEqual(self.fake.calls, [])

    def test_approval_expiring_during_evidence_collection_never_mutates(self):
        from agent.service import PinnedDockerExecutor
        cmd = fixtures.command("RESTART", expires_at=int(fixtures.time.time()) + 5)
        now = cmd.expires_at - 1
        original = PinnedDockerExecutor.snapshot
        def delayed(executor, target):
            nonlocal now
            snapshot = original(executor, target)
            now = cmd.expires_at + 1
            return snapshot
        with patch("agent.service.time.time", side_effect=lambda: now), \
             patch.object(PinnedDockerExecutor, "snapshot", delayed):
            result = self.service.execute(cmd)
        self.assertEqual(result["state"], "BLOCKED")
        self.assertEqual(self.fake.calls, [])
        self.assertTrue(result["evidence"])
