"""Authenticated proposals, revisions, ordered stages and app recovery approvals."""
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
import json
import time
from unittest.mock import AsyncMock, patch

from executor.extended import ExtendedExecutorRouter
from tests.test_extended_controller import FamilyFixture
from tests.test_phase2_integration import Phase2Base, analysis_body, approve_form, API_KEY
from security import service_auth, signing


def proposal(action="THROTTLE"):
    body = json.loads(analysis_body(action, threat_level="medium"))
    body["operation"] = "propose_manual_action"
    body["force_manual"] = True
    body["analysis"].update(root_cause="Observed CPU saturation", evidence=["fixture CPU metric"],
                            action_parameters={}, analysis_status="valid")
    body["plan"] = wire(body["alert"], body["analysis"])
    return body


def wire(alert, analysis):
    return {"version": 1, "action_type": analysis["action_type"],
            "targets": analysis["action_targets"], "parameters": analysis["action_parameters"],
            "identity": {k: alert["labels"][k] for k in ("site", "service", "source", "runtime", "target")},
            "incident": {"fingerprint": alert["fingerprint"], "starts_at": alert["startsAt"]}}


class IntegratedPlanTests(Phase2Base):
    def setUp(self):
        super().setUp()
        self.sequence = 0
        self.main.notifier.send_approval_request = AsyncMock(return_value={"sent": True})
        self.main.notifier.send_alert_only = AsyncMock(return_value={"sent": True})
        self.addCleanup(self.client.close)

    def post(self, body, endpoint="/action"):
        self.sequence += 1
        raw = json.dumps(body, indent=self.sequence % 5).encode()
        ts = str(int(time.time()) - self.sequence)
        return self.client.post(endpoint, content=raw, headers={"Content-Type": "application/json",
            service_auth.TIMESTAMP_HEADER: ts, service_auth.SIGNATURE_HEADER: signing.sign(API_KEY, ts, raw)})

    def test_manual_pipeline_throttle_never_runs_before_approval(self):
        response = self.post(proposal())
        self.assertEqual(response.json()["status"], "pending_approval", response.text)
        rid = response.json()["remediation_id"]
        self.assertTrue(self.record(rid).requires_approval)
        self.assertEqual(self.docker_actions(), [])
        self.assertEqual(self.post_slack(approve_form("THROTTLE", rid)).status_code, 200)
        self.assertEqual(len(self.docker_actions()), 1)
        self.assertIsNone(self.record(rid).mttr())

    def test_manual_wire_tampering_unsupported_parameters_and_missing_intent_block(self):
        body = proposal()
        body["plan"]["identity"]["site"] = "other-pc"
        self.assertEqual(self.post(body).status_code, 422)
        body = proposal()
        body["force_manual"] = False
        self.assertEqual(self.post(body).status_code, 422)
        body = proposal()
        body["analysis"]["action_parameters"] = {"command": "arbitrary"}
        body["plan"]["parameters"] = body["analysis"]["action_parameters"]
        self.assertEqual(self.post(body).status_code, 422)
        self.assertEqual(self.docker_actions(), [])
        self.assertEqual(self.main.record_store.all(), [])

    def test_replan_of_expired_request_creates_fresh_approval_and_old_click_stays_blocked(self):
        body = proposal("RESTART")
        first = self.post(body).json()["remediation_id"]
        self.main.record_store.update(first, state="EXPIRED")
        body.update(operation="replan_action", replan_of=first, reason="Refreshed target inspection")
        replanned = self.post(body)
        self.assertEqual(replanned.status_code, 200, replanned.text)
        second = replanned.json()["remediation_id"]
        self.assertNotEqual(first, second)
        self.assertEqual(self.record(second).supersedes_id, first)
        self.assertEqual(self.record(second).state, "AWAITING_APPROVAL")
        self.assertIsNone(self.record(second).approved_by)
        self.assertEqual(self.post_slack(approve_form("RESTART", first)).status_code, 409)
        self.assertEqual(self.post(body).json()["remediation_id"], second)
        self.assertEqual(self.docker_actions(), [])

    def test_replan_supersedes_pending_request_atomically_and_preserves_history_on_reload(self):
        body = proposal("RESTART")
        first = self.post(body).json()["remediation_id"]
        body["analysis"]["action_type"] = "ISOLATE"
        body["plan"] = wire(body["alert"], body["analysis"])
        body.update(operation="replan_action", replan_of=first, reason="Operator reviewed updated RCA")
        second = self.post(body).json()["remediation_id"]
        self.assertEqual(self.record(first).state, "SUPERSEDED")
        restored = self.main.store_mod.RecordStore(self.main.record_store.path)
        restored.load()
        self.assertEqual(restored.get(first).superseded_by, second)
        self.assertEqual(self.post_slack(approve_form("RESTART", first)).status_code, 409)
        self.assertEqual(self.docker_actions(), [])

    def test_unresolved_result_cannot_be_replanned_or_advanced(self):
        for state in ("UNKNOWN", "EXECUTING", "RECOVERY_UNKNOWN", "NEEDS_REVIEW"):
            body = proposal("RESTART")
            body["alert"]["fingerprint"] += state
            body["plan"] = wire(body["alert"], body["analysis"])
            first = self.post(body).json()["remediation_id"]
            self.main.record_store.update(first, state=state)
            body.update(operation="replan_action", replan_of=first, reason="No blind retry")
            self.assertEqual(self.post(body).status_code, 409)
            self.assertEqual(self.post({"operation":"advance_plan", "previous_remediation_id":first},
                                       "/plans/advance").status_code, 409)
        self.assertEqual(self.docker_actions(), [])

    def test_steps_never_auto_advance_and_every_stage_requires_its_own_approval(self):
        body = proposal("THROTTLE")
        second = deepcopy(body["analysis"])
        second["action_type"] = "RESTART"
        body.update(operation="propose_plan", plan_steps=[{"analysis":body["analysis"], "plan":body["plan"]},
            {"analysis":second, "plan":wire(body["alert"], second)}])
        first = self.post(body).json()["remediation_id"]
        advance = {"operation":"advance_plan", "previous_remediation_id":first}
        self.assertEqual(self.post(advance, "/plans/advance").status_code, 409)
        self.post_slack(approve_form("THROTTLE", first))
        self.assertEqual(len(self.main.record_store.all()), 1)
        self.assertEqual(len(self.docker_actions()), 1)
        response = self.post(advance, "/plans/advance")
        self.assertEqual(response.status_code, 200, response.text)
        next_id = response.json()["remediation_id"]
        self.assertNotEqual(first, next_id)
        self.assertEqual(self.record(next_id).plan_step, 1)
        self.assertIsNone(self.record(next_id).approved_by)
        self.assertEqual(len(self.docker_actions()), 1)
        self.assertEqual(self.post(advance, "/plans/advance").json()["remediation_id"], next_id)
        self.post_slack(approve_form("RESTART", next_id), nonce=1)
        self.assertEqual(self.docker_actions().count("restart"), 1)
        self.assertEqual(self.post({"operation":"advance_plan", "previous_remediation_id":next_id},
                                   "/plans/advance").status_code, 409)

    def test_new_control_endpoints_require_auth_and_operation_binding(self):
        for path, data in (("/plans/advance", {"operation":"advance_plan", "previous_remediation_id":"x"}),
                           ("/recovery/request", {"operation":"request_recovery", "remediation_id":"x", "reason":"review"}),
                           ("/service/verify", {"operation":"verify_service", "remediation_id":"x"})):
            self.assertEqual(self.client.post(path, json=data).status_code, 401)
            data["operation"] = "notify_only"
            self.assertEqual(self.post(data, path).status_code, 400)

    def test_app_restoration_uses_stored_resource_separate_plan_and_recovery_approval(self):
        app = FamilyFixture("app_api", self)
        self.main.executor = ExtendedExecutorRouter({"app_api":app})
        body = proposal("LOCK_ACCOUNT")
        body["analysis"]["action_parameters"] = {"account_id":"fixture-user", "duration_seconds":60}
        body["plan"] = wire(body["alert"], body["analysis"])
        first = self.post(body).json()["remediation_id"]
        request = {"operation":"request_recovery", "remediation_id":first, "reason":"Incident reviewed"}
        self.assertEqual(self.post(request, "/recovery/request").status_code, 409)
        self.post_slack(approve_form("LOCK_ACCOUNT", first))
        response = self.post(request, "/recovery/request")
        self.assertEqual(response.status_code, 200, response.text)
        restored_id = response.json()["remediation_id"]
        record = self.record(restored_id)
        self.assertEqual(record.recovery_of, first)
        self.assertEqual(record.action_type, "UNLOCK_ACCOUNT")
        self.assertEqual(record.action_parameters["account_id"], "fixture-user")
        self.assertEqual(app.calls, ["LOCK_ACCOUNT"])
        self.assertEqual(self.post_slack(approve_form("UNLOCK_ACCOUNT", restored_id), nonce=1).status_code, 409)
        approved = self.post_slack(approve_form("UNLOCK_ACCOUNT", restored_id, action_id="approve_recovery"), nonce=2)
        self.assertEqual(approved.status_code, 200, approved.text)
        self.assertEqual(record.state, "VERIFIED")
        self.assertEqual(app.calls, ["LOCK_ACCOUNT", "UNLOCK_ACCOUNT"])
        self.assertIsNone(record.mttr())

    def test_direct_restore_without_parent_is_rejected_even_with_valid_service_signature(self):
        body = json.loads(analysis_body("ENABLE_FEATURE"))
        self.assertEqual(self.post(body).status_code, 409)
        body["operation"] = "internal_recovery"
        self.assertEqual(self.post(body).status_code, 400)
        self.assertEqual(self.docker_actions(), [])

    def test_concurrent_replan_requests_create_one_durable_revision(self):
        first = self.post(proposal("RESTART")).json()["remediation_id"]
        parent = self.record(first)
        def replan(_):
            child = self.main.store_mod.RemediationRecord(self.main.record_store.new_id(),parent.alertname,parent.action_type,
                incident_key=parent.incident_key, action_hash=parent.action_hash, plan_hash=parent.plan_hash)
            return self.main.record_store.create_linked(child,first,"replan")
        with ThreadPoolExecutor(max_workers=4) as threads:
            results = list(threads.map(replan,range(4)))
        self.assertEqual(sum(created for _,created in results),1)
        self.assertEqual(len({record.remediation_id for record,_ in results}),1)
        self.assertEqual(len(self.main.record_store.all()),2)
        self.assertEqual(parent.state,"SUPERSEDED")
        self.assertEqual(self.docker_actions(),[])
