"""Signed Controller -> actual DeploymentExecutor -> FakeDocker -> durable result."""
import json
import os
import time
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from executor.base import DisabledExecutor
from executor.extended import ExtendedExecutorRouter
from tests import test_deployment_executor as deployment_fixture
from tests.safety_fixtures import fake_db_backup
from tests import test_phase2_integration as controller_fixture


class ActualDeploymentControllerTest(unittest.TestCase):
    def setUp(self):
        self.fixture = deployment_fixture.DeploymentExecutorTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.executor.clock = time.time
        self.main = controller_fixture.load_main("disabled", os.path.join(self.fixture.tmp.name, "controller"))
        self.main.executor = ExtendedExecutorRouter({"deployment": self.fixture.executor})
        self.main.db_backup_runner = fake_db_backup  # 선행 단계 DB 백업(#53)은 모의로
        self.main.notifier.send_approval_request = AsyncMock(return_value={})
        self.main.notifier.send_alert_only = AsyncMock(return_value={})
        for name in ("_push_soc_event", "_update_slack_message"):
            hook = patch.object(self.main, name, new=AsyncMock())
            hook.start()
            self.addCleanup(hook.stop)
        self.client = TestClient(self.main.app)
        self.addCleanup(self.client.close)

    post_action = controller_fixture.Phase2Base.post_action
    post_slack = controller_fixture.Phase2Base.post_slack

    def propose(self, action="RECREATE", parameters=None, indent=None):
        payload = json.loads(controller_fixture.analysis_body(action))
        payload["operation"] = "propose_action"
        payload["alert"]["labels"].update(self.fixture.identity)
        payload["alert"]["fingerprint"] = "actual-deployment-" + action
        payload["analysis"]["action_targets"] = [self.fixture.identity["target"]]
        payload["analysis"]["action_parameters"] = parameters or {}
        return self.post_action(json.dumps(payload, indent=indent).encode())

    def approve(self, action, rid, nonce=0):
        form = controller_fixture.approve_form(action, rid, targets=[self.fixture.identity["target"]])
        return self.post_slack(form, nonce=nonce)

    def test_actual_recreate_persists_approval_and_full_evidence_before_first_docker_mutation(self):
        proposal = self.propose()
        self.assertEqual(proposal.status_code, 200, proposal.text)
        self.assertEqual(proposal.json()["status"], "pending_approval")
        rid = proposal.json()["remediation_id"]
        self.assertEqual(self.fixture.fake.calls, [])
        binding = self.main.record_store.get(rid).target_bindings[self.fixture.identity["target"]]
        self.assertEqual(binding["chosen_spec"]["image_id"], deployment_fixture.CURRENT)
        checks = []
        original = deployment_fixture.Container.update
        case = self
        def check_durable_before_update(container, **kwargs):
            with open(case.main.record_store.path, encoding="utf-8") as fh:
                persisted = json.load(fh)["records"][rid]
            case.assertEqual(persisted["state"], "EXECUTING")
            case.assertEqual(persisted["executor_name"], "deployment")
            case.assertEqual(persisted["approved_by"], "UTEST")
            case.assertTrue(persisted["incident_key"])
            case.assertTrue(persisted["action_hash"])
            case.assertEqual(persisted["evidence"]["targets"], persisted["target_bindings"])
            case.assertNotIn("secret-never-persist", json.dumps(persisted))
            checks.append("durable-before-mutation")
            return original(container, **kwargs)
        with patch.object(deployment_fixture.Container, "update", check_durable_before_update):
            approved = self.approve("RECREATE", rid)
        self.assertEqual(approved.status_code, 200, approved.text)
        self.assertEqual(approved.json()["record_state"], "VERIFIED")
        self.assertEqual(checks, ["durable-before-mutation"])
        record = self.main.record_store.get(rid)
        self.assertEqual(record.results[0]["after"]["container_id"], deployment_fixture.NEW)
        self.assertEqual(record.results[0]["after"]["old_container_id"], deployment_fixture.OLD)
        self.assertTrue(record.results[0]["after"]["requires_rebinding"])
        count = len(self.fixture.fake.calls)
        self.assertEqual(self.approve("RECREATE", rid, nonce=1).status_code, 409)
        retransmit = self.propose(indent=1)  # Different authenticated bytes, same canonical incident/action.
        self.assertEqual(retransmit.json()["status"], "existing")
        self.assertEqual(retransmit.json()["remediation_id"], rid)
        self.assertEqual(len(self.fixture.fake.calls), count)

    def test_actual_frontend_rollback_summary_and_result_use_configured_default_version(self):
        self.fixture.configure("frontend")
        self.fixture.executor.clock = time.time
        self.main.executor = ExtendedExecutorRouter({"deployment": self.fixture.executor})
        proposed = self.propose("ROLLBACK")
        self.assertEqual(proposed.json()["status"], "pending_approval", proposed.text)
        rid = proposed.json()["remediation_id"]
        analysis = self.main.notifier.send_approval_request.await_args.args[1]
        summary = analysis["approval_plan"][0]
        self.assertEqual(summary["version"], "known-good-v1")
        self.assertEqual(summary["image_id"], deployment_fixture.ROLLBACK)
        self.assertEqual(summary["previous_container"], deployment_fixture.OLD)
        self.assertNotIn("secret-never-persist", json.dumps(analysis))
        approved = self.approve("ROLLBACK", rid)
        self.assertEqual(approved.json()["record_state"], "VERIFIED", approved.text)
        result = self.main.record_store.get(rid).results[0]
        self.assertEqual(result["after"]["image_id"], deployment_fixture.ROLLBACK)
        self.assertTrue(result["verified"])

    def test_actual_partial_creation_stays_unknown_across_record_reload_and_redelivery(self):
        proposed = self.propose()
        rid = proposed.json()["remediation_id"]
        self.fixture.fake.create_timeout = True
        approved = self.approve("RECREATE", rid)
        self.assertEqual(approved.json()["record_state"], "UNKNOWN", approved.text)
        record = self.main.record_store.get(rid)
        self.assertIsNone(record.action_verified_at)
        self.assertEqual(record.results[0]["after"]["new_container_id"], None)
        self.assertIn(deployment_fixture.OLD, self.fixture.fake.docs)
        self.assertIn(deployment_fixture.NEW, self.fixture.fake.docs)
        restored = self.main.store_mod.RecordStore(self.main.record_store.path)
        restored.load()
        restored.reconcile_interrupted()
        self.assertEqual(restored.get(rid).state, "UNKNOWN")
        count = len(self.fixture.fake.calls)
        self.assertEqual(self.approve("RECREATE", rid, nonce=1).status_code, 409)
        self.assertEqual(self.propose(indent=1).json()["status"], "existing")
        self.assertEqual(len(self.fixture.fake.calls), count)

    def test_private_environment_change_after_proposal_revokes_actual_deployment(self):
        proposal = self.propose()
        rid = proposal.json()["remediation_id"]
        with open(self.fixture.secret_path, "w", encoding="utf-8") as fh:
            fh.write('{}')
        approved = self.approve("RECREATE", rid)
        self.assertEqual(approved.json()["record_state"], "BLOCKED", approved.text)
        self.assertEqual(self.fixture.fake.calls, [])

    def test_disabled_controller_never_runs_actual_deployment_preflight(self):
        self.main.executor = DisabledExecutor()
        with patch.object(self.fixture.fake.images, "get", side_effect=AssertionError("must not inspect Docker")):
            proposal = self.propose()
            self.assertEqual(proposal.json()["status"], "pending_approval", proposal.text)
            rid = proposal.json()["remediation_id"]
            approved = self.approve("RECREATE", rid)
        self.assertEqual(approved.json()["record_state"], "SKIPPED", approved.text)
        self.assertEqual(self.fixture.fake.calls, [])
