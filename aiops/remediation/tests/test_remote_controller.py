"""Signed Pipeline -> policy -> signed Slack -> RemoteExecutor -> in-memory Agent."""
import json
import os
import time
from unittest.mock import AsyncMock, patch

import httpx
from fastapi.testclient import TestClient

from executor.remote import RemoteExecutor
from security import service_auth, signing
from tests import test_phase2_integration as phase2
from tests import test_remote_agent as agent_tests
import unittest


class RemoteControllerTest(unittest.TestCase):
    def setUp(self):
        agent_tests.setup_case(self)
        self.agent_client = self.client
        self.offline = False
        self.post_offline = False
        def transport(request):
            if self.offline or (self.post_offline and request.method == "POST"):
                raise httpx.ReadTimeout("offline", request=request)
            response = self.agent_client.request(request.method, request.url.path,
                                                 content=request.content, headers=request.headers)
            return httpx.Response(response.status_code, content=response.content, request=request)
        self.http = httpx.Client(transport=httpx.MockTransport(transport))
        self.addCleanup(self.http.close)
        self.main = phase2.load_main("disabled", os.path.join(self.tmp.name, "pc1"))
        self.main.executor = RemoteExecutor("https://pc2.test.ts.net", agent_tests.KEY, client=self.http)
        self.events = []
        async def record(job, event):
            self.events.append(event)
        for name, replacement in (("_push_soc_event", record), ("_update_slack_message", AsyncMock())):
            p = patch.object(self.main, name, replacement)
            p.start()
            self.addCleanup(p.stop)
        self.main.notifier.send_approval_request = AsyncMock(return_value={})
        self.main.notifier.send_recovery_request = AsyncMock(return_value={})
        self.client = TestClient(self.main.app)
        self.addCleanup(self.client.close)

    post_action = phase2.Phase2Base.post_action
    post_slack = phase2.Phase2Base.post_slack

    def propose_approve(self, action="ISOLATE"):
        response = self.post_action(phase2.analysis_body(action))
        self.assertEqual(response.json()["status"], "pending_approval")
        rid = response.json()["remediation_id"]
        self.assertEqual(self.fake.calls, [])
        self.post_slack(phase2.approve_form(action, rid))
        return self.main.record_store.get(rid)

    def sync(self, record, retry=False):
        body = json.dumps({"operation": "reconcile_remote", "remediation_id": record.remediation_id,
                           "retry": retry}).encode()
        ts = str(int(time.time()))
        return self.client.post("/remote/reconcile", content=body, headers={
            service_auth.TIMESTAMP_HEADER: ts,
            service_auth.SIGNATURE_HEADER: signing.sign(phase2.API_KEY, ts, body),
            "content-type": "application/json"})

    def test_policy_and_slack_approval_execute_once_remotely(self):
        record = self.propose_approve()
        self.assertEqual(record.state, "RECOVERY_PENDING")
        self.assertEqual(record.executor_name, "remote")
        self.assertEqual(record.evidence["targets"][agent_tests.TARGET]["container_id"], agent_tests.CID)
        self.post_slack(phase2.approve_form("ISOLATE", record.remediation_id), nonce=1)
        self.assertEqual(len(self.fake.calls), 1)

    def test_forged_pipeline_or_slack_never_reaches_agent(self):
        self.client.post("/action", content=phase2.analysis_body("ISOLATE"))
        self.client.post("/slack/action", content=phase2.approve_form("ISOLATE"))
        self.factory.assert_not_called()

    def test_unknown_is_not_logged_as_failed_and_can_be_retried(self):
        self.offline = True
        record = self.propose_approve()
        self.assertEqual(record.state, "UNKNOWN")
        self.assertIsNone(record.action_verified_at)
        executions = [e for e in self.events if e.get("event") == "manual_approval_executed"]
        self.assertEqual(executions[0]["status"], "UNKNOWN")
        self.offline = False
        self.assertEqual(self.sync(record, retry=True).status_code, 200)
        self.assertEqual(record.state, "RECOVERY_PENDING")
        self.assertEqual(len(self.fake.calls), 1)

    def test_ttl_marks_isolate_for_approval_then_signed_recovery_restores(self):
        record = self.propose_approve()
        import recovery
        processed = recovery.run_due(self.main.record_store, self.main.executor, now=time.time()+10000)
        self.assertEqual(processed[0][2], "RECOVERY_APPROVAL_REQUIRED")
        self.assertEqual(len(self.fake.calls), 1)
        result = self.post_slack(phase2.approve_form("ISOLATE", record.remediation_id,
                                                  action_id="approve_recovery"), nonce=1)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(record.state, "RECOVERED")
        self.assertEqual(len(self.fake.calls), 2)
        self.assertIsNotNone(record.mttr())

    def test_throttle_policy_candidate_still_requires_manual_approval(self):
        record = self.propose_approve("THROTTLE")
        self.assertEqual(record.state, "RECOVERY_PENDING")
        self.assertTrue(record.requires_approval)
        self.assertEqual(len(self.fake.calls), 1)

    def test_mismatched_approval_cannot_change_original_action(self):
        response = self.post_action(phase2.analysis_body("ISOLATE"))
        rid = response.json()["remediation_id"]
        self.post_slack(phase2.approve_form("RESTART", rid))
        self.factory.assert_not_called()

    def test_recovery_timeout_before_delivery_retains_intent_for_retry(self):
        record = self.propose_approve()
        self.post_offline = True
        self.post_slack(phase2.approve_form("ISOLATE", record.remediation_id,
                                          action_id="approve_recovery"), nonce=1)
        # GET can reach the agent, but original execution success is not recovery success.
        self.assertEqual(record.state, "RECOVERY_UNKNOWN")
        self.post_offline = False
        self.sync(record, retry=True)
        self.assertEqual(record.state, "RECOVERED")
        self.assertEqual(len(self.fake.calls), 2)

    def test_remote_configuration_never_creates_local_docker_client(self):
        with patch.dict(os.environ, {"REMEDIATION_AGENT_URL": "https://pc2.test.ts.net",
                                    "AGENT_HMAC_KEY": agent_tests.KEY}):
            with patch("docker.from_env") as docker_factory:
                module = phase2.load_main("remote", os.path.join(self.tmp.name, "pc1-other"))
                self.assertEqual(module.executor.name, "remote")
                docker_factory.assert_not_called()
                module.executor.client.close()
