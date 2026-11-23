"""PC1 Controller -> authenticated PC2 Agent -> real deployment adapter -> FakeDocker.

Both HTTP apps, SQLite ledger and JSON records run locally in process. This is
not a two-PC/network/Docker deployment acceptance test.
"""
import json
import os
from pathlib import Path
import time
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
import httpx

from agent.api import create_app
from agent.contract import AgentConfig
from agent.ledger import Ledger
from agent.service import AgentService
from executor.extended import ExtendedExecutorRouter
from executor.remote import RemoteExecutor
from security.agent_auth import headers
from tests import test_extended_deployment_flow as controller_fixture
from tests import test_deployment_executor as fixture

KEY = "deployment-test-agent-key-" + "x" * 40
URL = "https://pc2.fixture.ts.net"


class RemoteDeploymentFlowTests(unittest.TestCase):
    def setUp(self):
        controller_fixture.ActualDeploymentControllerTest.setUp(self)
        identity = self.fixture.identity
        labels = self.fixture.rule["labels"]
        self.agent_config = AgentConfig.model_validate({"controller_id":"pc1", "agent_id":"pc2-agent",
            "site":identity["site"], "source":identity["source"], "targets":{identity["target"]:{
                "container_id":fixture.OLD, "image_id":fixture.CURRENT, "labels":labels,
                "actions":["RECREATE", "ROLLBACK"]}}})
        self.ledger = Ledger(os.path.join(self.fixture.tmp.name, "agent.sqlite3"))
        # 증거 보존(CAPTURE) 읽기 전용 조회도 같은 FakeDocker 를 쓴다.
        self.service = AgentService(self.agent_config, self.ledger, mode="live", deployment_executor=self.fixture.executor,
                                    client_factory=lambda: self.fixture.fake)
        self.agent = TestClient(create_app(self.service, KEY))
        self.addCleanup(self.agent.close)
        path = Path(self.fixture.tmp.name) / "bindings.json"
        path.write_text(json.dumps({"version":1,"bindings":[{"identity":identity,"executor":"remote",
            "agent_id":"pc2-agent","agent_url":URL,"container":self.agent_config.targets[identity["target"]].model_dump()}]}))
        env = patch.dict(os.environ, {"REMEDIATION_TARGET_BINDINGS_PATH":str(path)})
        env.start()
        self.addCleanup(env.stop)
        self.remote = RemoteExecutor(URL, KEY, client=self.agent, deployment_enabled=True)
        self.main.executor = ExtendedExecutorRouter(docker_executor=self.remote)

    post_action = controller_fixture.ActualDeploymentControllerTest.post_action
    post_slack = controller_fixture.ActualDeploymentControllerTest.post_slack
    propose = controller_fixture.ActualDeploymentControllerTest.propose
    approve = controller_fixture.ActualDeploymentControllerTest.approve

    def test_remote_plan_manual_approval_durable_agent_claim_then_sdk_effect_verification(self):
        response = self.propose()
        self.assertEqual(response.json()["status"], "pending_approval", response.text)
        rid = response.json()["remediation_id"]
        self.assertEqual(self.fixture.fake.calls, [])
        self.assertEqual(self.ledger.all(), [])
        evidence_checks = []
        original = fixture.Container.update
        def before_mutation(container, **kwargs):
            persisted = self.ledger.get(rid, self.fixture.identity["target"])
            self.assertEqual(persisted["state"], "EXECUTING")
            self.assertTrue(persisted["evidence"]["plan_digest"])
            self.assertEqual(persisted["request"]["authorization"]["kind"], "manual")
            self.assertNotIn("secret-never-persist", json.dumps(persisted))
            evidence_checks.append("durable")
            return original(container, **kwargs)
        with patch.object(fixture.Container, "update", before_mutation):
            approved = self.approve("RECREATE", rid)
        self.assertEqual(approved.json()["record_state"], "VERIFIED", approved.text)
        self.assertEqual(evidence_checks, ["durable"])
        record = self.main.record_store.get(rid)
        self.assertEqual(record.executor_name, "remote")
        self.assertTrue(record.results[0]["verified"])
        self.assertEqual(record.results[0]["after"]["container_id"], fixture.NEW)
        self.assertIsNone(record.time_to_service_recovery())
        count = len(self.fixture.fake.calls)
        self.assertEqual(self.approve("RECREATE", rid, nonce=1).status_code, 409)
        self.assertEqual(self.propose(indent=1).json()["remediation_id"], rid)
        self.assertEqual(len(self.fixture.fake.calls), count)

    def test_response_loss_queries_agent_ledger_without_resending_deployment(self):
        rid = self.propose().json()["remediation_id"]
        request = self.agent.request
        writes = []
        def lose_response(method, url, **kwargs):
            response = request(method, url, **kwargs)
            if method == "POST" and str(url).endswith("/v1/deployments"):
                writes.append(url)
                raise httpx.ReadTimeout("fixture response lost after Agent finished")
            return response
        with patch.object(self.agent, "request", side_effect=lose_response):
            approved = self.approve("RECREATE", rid)
        self.assertEqual(approved.json()["record_state"], "VERIFIED", approved.text)
        self.assertEqual(len(writes), 1)
        self.assertEqual(len([c for c in self.fixture.fake.calls if c[0] == "create"]), 1)

    def test_partial_deployment_remains_unknown_after_agent_restart_and_controller_reconcile(self):
        rid = self.propose().json()["remediation_id"]
        self.fixture.fake.create_timeout = True
        approved = self.approve("RECREATE", rid)
        self.assertEqual(approved.json()["record_state"], "UNKNOWN", approved.text)
        self.service.reconcile_interrupted()
        from executor.remote_sync import reconcile
        record = self.main.record_store.get(rid)
        reconcile(self.main.record_store, self.remote, record)
        self.assertEqual(record.state, "UNKNOWN")
        self.assertIsNone(record.time_to_service_recovery())
        count = len(self.fixture.fake.calls)
        self.assertEqual(self.approve("RECREATE", rid, nonce=1).status_code, 409)
        self.assertEqual(len(self.fixture.fake.calls), count)

    def test_extended_controller_reconciliation_endpoint_only_queries_the_selected_remote_agent(self):
        rid = self.propose().json()["remediation_id"]
        self.fixture.fake.create_timeout = True
        self.approve("RECREATE",rid)
        from tests.test_endpoint_auth import API_KEY
        from security import signing, service_auth
        body=json.dumps({"operation":"reconcile_remote","remediation_id":rid,"retry":False}).encode()
        ts=str(int(time.time()))
        count=len(self.fixture.fake.calls)
        response=self.client.post("/remote/reconcile",content=body,headers={"Content-Type":"application/json",
            service_auth.TIMESTAMP_HEADER:ts,service_auth.SIGNATURE_HEADER:signing.sign(API_KEY,ts,body)})
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json()["state"],"UNKNOWN")
        self.assertEqual(len(self.fixture.fake.calls),count)

    def test_agent_auth_replay_payload_mismatch_and_cached_command_never_repeat_sdk_calls(self):
        rid = self.propose().json()["remediation_id"]
        self.approve("RECREATE", rid)
        command = self.ledger.get(rid, self.fixture.identity["target"])["request"]
        body = json.dumps(command).encode()
        path = "/v1/deployments"
        auth = headers(KEY, "POST", path, body)
        count = len(self.fixture.fake.calls)
        self.assertEqual(self.agent.post(path, content=body, headers=auth).status_code, 200)
        self.assertEqual(self.agent.post(path, content=body, headers=auth).status_code, 401)
        self.assertEqual(self.agent.post(path, content=body + b" ", headers=auth).status_code, 401)
        command["plan"]["chosen_spec"]["command"] = ["changed"]
        body = json.dumps(command).encode()
        self.assertEqual(self.agent.post(path, content=body, headers=headers(KEY,"POST",path,body)).status_code, 403)
        self.assertEqual(len(self.fixture.fake.calls), count)

    def test_container_replacement_after_remote_plan_blocks_before_any_sdk_mutation(self):
        rid = self.propose().json()["remediation_id"]
        self.fixture.fake.docs[fixture.OLD]["Image"] = fixture.ROLLBACK
        approved = self.approve("RECREATE", rid)
        self.assertEqual(approved.json()["record_state"], "BLOCKED", approved.text)
        self.assertEqual(self.fixture.fake.calls, [])

    def test_disabled_agent_and_remote_capability_opt_in_never_run_deployment(self):
        self.service.mode = "disabled"
        result = self.propose()
        self.assertEqual(result.json()["status"], "blocked", result.text)
        self.assertEqual(self.fixture.fake.calls, [])
        self.assertEqual(self.ledger.all(), [])
        self.remote.supports_deployment = False
        self.assertIs(self.main.executor.for_action("RECREATE"),self.remote)
        from executor.router import route_action
        self.assertFalse(route_action("RECREATE", "container", self.remote)[0])
