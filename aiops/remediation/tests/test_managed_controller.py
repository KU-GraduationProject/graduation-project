"""Signed Controller proposal -> durable plan -> Slack approval -> adapter.

Fake side effects only. Actual adapters have separate fake-IO boundary suites.
"""
from copy import deepcopy
import json
import time
from unittest.mock import patch

from executor.base import succeeded
from executor.extended import ExtendedExecutorRouter
from executor.managed import check_record, seal_plan
from executor.managed_registry import ACTIONS, RESTORE_ACTIONS
from tests.test_policy_integration import PolicyEndpointBase, IDENTITY, slack_approve_form, API_KEY
from tests.test_response_profiles import proposal
from security import service_auth, signing


class Adapter:
    name = "egress"
    changes_system = True

    def __init__(self): self.calls = []; self.changed = False
    def plan_record(self, identity, targets, action, parameters):
        return {identity["target"]: seal_plan({"executor": self.name, "identity": identity, "target": identity["target"],
            "action_type": action, "parameters": parameters, "operator_config": {"fixture": True}, "pre_snapshot": {"id": "fixture"}})}
    def validate_record(self, record): return "fixture_changed" if self.changed else None
    def execute_record(self, record, target, approved_by=None):
        check_record(record, self.name)
        self.calls.append(record.action_type)
        return succeeded(record.action_type, target, "fixture_verified")
    def capture_record(self, record, target): return {"log_lines": [], "processes": []}


class ManagedControllerTests(PolicyEndpointBase):
    def setUp(self):
        super().setUp()
        self.adapter = Adapter()
        self.main.executor = ExtendedExecutorRouter({"BLOCK_EGRESS": self.adapter, "UNBLOCK_EGRESS": self.adapter}, self.main.executor)
        p = patch.object(self.main.capture_mod, "preserve", return_value={"fixture": "captured"})
        p.start(); self.addCleanup(p.stop)

    def approve_form(self, *args, **kwargs):
        return self.post_slack(slack_approve_form(*args, **kwargs).replace("UnauthorizedDataTransfer", "V2RepeatedExternalConnections"))

    def body(self, ip="192.0.2.80"):
        p = proposal(action="BLOCK_EGRESS")
        p["alert"]["labels"].update(v2_dst_ip=ip, v2_dst_port="8080", v2_protocol="tcp")
        params = {"destination_ip": ip, "destination_port": 8080, "protocol": "tcp", "flow_id": p["alert"]["fingerprint"]}
        p["analysis"]["action_parameters"] = params
        p["plan"]["parameters"] = deepcopy(params)
        return p

    def post_signed(self, path, payload):
        body = json.dumps(payload).encode(); ts = str(int(time.time()))
        return self.client.post(path, content=body, headers={service_auth.TIMESTAMP_HEADER: ts,
            service_auth.SIGNATURE_HEADER: signing.sign(API_KEY, ts, body), "Content-Type": "application/json"})

    def test_observed_destination_proposal_approval_and_parent_only_unblock(self):
        p = self.body()
        r = self.post_action(json.dumps(p).encode())
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["status"], "pending_approval")
        rid = r.json()["remediation_id"]
        self.assertEqual(self.adapter.calls, [])
        a = self.approve_form("BLOCK_EGRESS", remediation_id=rid)
        self.assertEqual(a.status_code, 200, a.text)
        self.assertEqual(a.json()["record_state"], "VERIFIED", a.text)
        self.assertEqual(self.adapter.calls, ["BLOCK_EGRESS"])
        restored = self.post_signed("/recovery/request", {"operation": "request_recovery", "remediation_id": rid, "reason": "Verified incident resolved"})
        self.assertEqual(restored.status_code, 200, restored.text)
        child = restored.json()["remediation_id"]
        record = self.main.record_store.get(child)
        self.assertEqual(record.action_parameters, {"parent_id": rid})
        self.assertEqual(record.recovery_of, rid)
        a = self.approve_form("UNBLOCK_EGRESS", remediation_id=child, action_id="approve_recovery")
        self.assertEqual(a.status_code, 200, a.text)
        self.assertEqual(a.json()["record_state"], "VERIFIED", a.text)
        self.assertEqual(self.adapter.calls, ["BLOCK_EGRESS", "UNBLOCK_EGRESS"])

    def test_changed_or_guessed_destination_refused_before_record(self):
        for field, value in (("destination_ip", "198.51.100.81"), ("destination_port", 443), ("protocol", "udp"), ("flow_id", "different-incident")):
            p = self.body(); p["analysis"]["action_parameters"][field] = value; p["plan"]["parameters"][field] = value
            r = self.post_action(json.dumps(p).encode())
            self.assertEqual(r.status_code, 422, r.text)
        self.assertEqual(self.adapter.calls, [])

    def test_destination_rotation_and_no_kernel_values_from_llm(self):
        for ip in ("192.0.2.101", "198.51.100.27", "203.0.113.42"):
            p = self.body(ip)
            self.main.record_store = self.main.store_mod.RecordStore(self.tmp.name + "/" + ip + ".json")
            r = self.post_action(json.dumps(p).encode())
            self.assertEqual(r.status_code, 200, r.text)
        p = self.body(); p["analysis"]["action_parameters"]["command"] = "iptables -F"
        p["plan"]["parameters"]["command"] = "iptables -F"
        self.assertEqual(self.post_action(json.dumps(p).encode()).status_code, 422)
        self.assertEqual(self.adapter.calls, [])

    def test_legacy_and_direct_restore_cannot_enter_managed_execution(self):
        p = self.body(); p.pop("operation"); p.pop("plan")
        self.assertEqual(self.post_action(json.dumps(p).encode()).status_code, 422)
        p = self.body(); p["analysis"]["action_type"] = "UNBLOCK_EGRESS"; p["plan"]["action_type"] = "UNBLOCK_EGRESS"
        self.assertEqual(self.post_action(json.dumps(p).encode()).status_code, 409)
        for variant in ("block_egress", " BLOCK_EGRESS ", "unblock_egress", " UNBLOCK_EGRESS "):
            p = self.body(); p.pop("operation"); p.pop("plan")
            p["analysis"]["action_type"] = variant
            result = self.post_action(json.dumps(p).encode())
            self.assertIn(result.status_code, (409, 422), result.text)
        self.assertEqual(self.adapter.calls, [])

    def test_changed_preapproval_state_blocks_without_adapter_mutation(self):
        r = self.post_action(json.dumps(self.body()).encode())
        self.adapter.changed = True
        a = self.approve_form("BLOCK_EGRESS", remediation_id=r.json()["remediation_id"])
        self.assertEqual(a.status_code, 200, a.text)
        self.assertEqual(a.json()["record_state"], "BLOCKED", a.text)
        self.assertEqual(self.adapter.calls, [])

    def test_new_managed_actions_always_require_manual_approval(self):
        for action in ACTIONS:
            policy = self.main.policy_engine.config.actions[action]
            self.assertTrue(policy.requires_approval, action)
            self.assertFalse(policy.auto_execute, action)
        self.assertTrue(RESTORE_ACTIONS <= ACTIONS)

    def test_database_promotion_and_parent_rollback_use_separate_controller_approvals(self):
        self.adapter.name = "database_promotion"
        self.main.executor = ExtendedExecutorRouter({"PROMOTE_RESTORED_DB": self.adapter,
            "ROLLBACK_DB_PROMOTION": self.adapter}, self.main.executor)
        p = proposal(name="UnauthorizedDataTransfer", action="PROMOTE_RESTORED_DB")
        params = {"source_record_id": "verified-restore-fixture", "confirm_database": "leafy", "allow_data_loss": True}
        p["analysis"]["action_parameters"] = params
        p["plan"]["parameters"] = deepcopy(params)
        r = self.post_action(json.dumps(p).encode())
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["status"], "pending_approval", r.text)
        rid = r.json()["remediation_id"]
        a = self.post_slack(slack_approve_form("PROMOTE_RESTORED_DB", remediation_id=rid))
        self.assertEqual(a.json()["record_state"], "VERIFIED", a.text)
        self.assertEqual(self.adapter.calls, ["PROMOTE_RESTORED_DB"])
        r = self.post_signed("/recovery/request", {"operation": "request_recovery", "remediation_id": rid,
            "reason": "Operator reviewed data loss and requests original DB restoration"})
        self.assertEqual(r.status_code, 200, r.text)
        child = r.json()["remediation_id"]
        self.assertEqual(self.main.record_store.get(child).action_parameters, {"parent_id": rid})
        self.assertEqual(self.adapter.calls, ["PROMOTE_RESTORED_DB"])
        a = self.post_slack(slack_approve_form("ROLLBACK_DB_PROMOTION", remediation_id=child, action_id="approve_recovery"))
        self.assertEqual(a.json()["record_state"], "VERIFIED", a.text)
        self.assertEqual(self.adapter.calls, ["PROMOTE_RESTORED_DB", "ROLLBACK_DB_PROMOTION"])
