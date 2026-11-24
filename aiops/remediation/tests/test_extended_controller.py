"""Cross-family Controller approval/plan/dispatch boundary under isolated IO."""
import asyncio
import copy
import json
import time
import unittest
from unittest.mock import AsyncMock, patch

from executor.base import ExecutionResult, succeeded
from executor.extended import ExtendedExecutorRouter
from tests.test_phase2_integration import Phase2Base, analysis_body, approve_form


class FamilyFixture:
    changes_system = True

    def __init__(self, name, case):
        self.name, self.case = name, case
        self.plans, self.calls = [], []
        self.changed = False
        self.uncertain = False

    def plan_record(self, identity, targets, action_type, parameters):
        self.plans.append(action_type)
        return {identity["target"]: {"executor": self.name, "identity": identity,
                "action_type": action_type, "parameters": parameters, "plan_digest": "fixture-plan",
                "sessions": [{"pid": 123, "backend_start": "2026-11-11T00:00:00Z"}]}}

    def capture_record(self, record, target):
        return {"log_lines": [], "processes": []}

    def validate_record(self, record):
        return "resource_changed_reapproval_required" if self.changed else None

    def execute_record(self, record, target, approved_by):
        # Inspect bytes on disk rather than trusting an in-memory transition.
        with open(self.case.main.record_store.path, encoding="utf-8") as fh:
            durable = json.load(fh)["records"][record.remediation_id]
        self.case.assertEqual(durable["state"], "EXECUTING")
        self.case.assertEqual(durable["approved_by"], approved_by)
        self.case.assertEqual(durable["executor_name"], self.name)
        self.case.assertEqual(durable["evidence"]["targets"][target], durable["target_bindings"][target])
        self.calls.append(record.action_type)
        if self.uncertain:
            return ExecutionResult(record.action_type, target, "UNKNOWN", detail="fixture_delivery_unknown")
        return succeeded(record.action_type, target, "fixture_effect_verified")


class ExtendedControllerTests(Phase2Base):
    def setUp(self):
        super().setUp()
        self.families = {name: FamilyFixture(name, self) for name in ("postgres", "deployment", "app_api")}
        self.configured = ExtendedExecutorRouter(self.families, docker_executor=self.main.executor)
        self.main.executor = self.configured
        self.main.db_backup_runner = lambda rid: {"manifest_path": "/fixture", "sha256": "0" * 64}

    def propose(self, action="KILL_SESSIONS"):
        payload = json.loads(analysis_body(action))
        payload["operation"] = "propose_action"
        if action == "KILL_SESSIONS":
            target = "leafy-db"
            payload["alert"]["labels"].update(service="db", runtime="host", target=target)
            payload["analysis"]["action_targets"] = [target]
            payload["analysis"]["action_parameters"] = {}  # 세션 정리 방식은 정책이 채운다
        elif action == "LOCK_ACCOUNT":
            payload["analysis"]["action_parameters"] = {"account_id": "test-user"}  # 잠금 시간은 정책이 채운다
        payload["alert"]["fingerprint"] += "-" + action
        response = self.post_action(json.dumps(payload).encode())
        self.assertEqual(response.status_code, 200, response.text)
        return response, payload["analysis"]["action_targets"]

    def approve(self, action, rid, targets, nonce=0):
        return self.post_slack(approve_form(action, rid, targets=targets), nonce=nonce)

    def test_db_plan_is_approved_and_durable_before_real_dispatch_boundary(self):
        proposal, targets = self.propose()
        rid = proposal.json()["remediation_id"]
        self.assertEqual(proposal.json()["status"], "pending_approval")
        self.assertEqual(self.record(rid).executor_name, "postgres")
        self.assertEqual(self.families["postgres"].calls, [])
        response = self.approve("KILL_SESSIONS", rid, targets)
        self.assertEqual(response.json()["record_state"], "VERIFIED")
        self.assertEqual(self.families["postgres"].calls, ["KILL_SESSIONS"])
        self.assertEqual(self.docker_actions(), [])

    def test_each_family_routes_without_swapping_global_executor(self):
        async def approve_all(payloads):
            return await asyncio.gather(*(self.main.handle_socket_action(p) for p in payloads))
        import urllib.parse
        payloads = []
        for action in ("KILL_SESSIONS", "RECREATE", "LOCK_ACCOUNT"):
            proposal, targets = self.propose(action)
            form = approve_form(action, proposal.json()["remediation_id"], targets=targets)
            payloads.append(json.loads(urllib.parse.parse_qs(form)["payload"][0]))
        results = asyncio.run(approve_all(payloads))
        self.assertTrue(all(result.status_code == 200 for result in results))
        self.assertEqual(self.families["postgres"].calls, ["KILL_SESSIONS"])
        self.assertEqual(self.families["deployment"].calls, ["RECREATE"])
        self.assertEqual(self.families["app_api"].calls, ["LOCK_ACCOUNT"])
        self.assertIs(self.main.executor, self.configured)

    def test_expired_or_rejected_extension_never_dispatches(self):
        first, targets = self.propose()
        rid = first.json()["remediation_id"]
        response = self.post_slack(approve_form("KILL_SESSIONS", rid, targets=targets, action_id="reject_action"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.approve("KILL_SESSIONS", rid, targets, nonce=1).status_code, 409)
        self.assertEqual(self.families["postgres"].calls, [])

    def test_changed_resource_after_approval_plan_blocks_dispatch(self):
        first, targets = self.propose()
        rid = first.json()["remediation_id"]
        self.families["postgres"].changed = True
        response = self.approve("KILL_SESSIONS", rid, targets)
        self.assertEqual(response.json()["record_state"], "BLOCKED")
        self.assertEqual(self.families["postgres"].calls, [])

    def test_uncertain_extension_cannot_be_approved_again(self):
        first, targets = self.propose()
        rid = first.json()["remediation_id"]
        self.families["postgres"].uncertain = True
        self.assertEqual(self.approve("KILL_SESSIONS", rid, targets).json()["record_state"], "UNKNOWN")
        self.assertEqual(self.approve("KILL_SESSIONS", rid, targets, nonce=1).status_code, 409)
        self.assertEqual(self.families["postgres"].calls, ["KILL_SESSIONS"])

    def test_policy_fills_execution_parameters_for_rca_proposals(self):
        lock, _ = self.propose("LOCK_ACCOUNT")
        self.assertEqual(self.record(lock.json()["remediation_id"]).action_parameters,
                         {"account_id": "test-user", "duration_seconds": 1800})
        kill, _ = self.propose("KILL_SESSIONS")
        self.assertEqual(self.record(kill.json()["remediation_id"]).action_parameters,
                         {"operation": "terminate_idle_sessions"})

    def test_request_cannot_override_policy_owned_parameters(self):
        for action, parameters in (("KILL_SESSIONS", {"operation": "cancel_long_queries"}),
                                   ("LOCK_ACCOUNT", {"account_id": "test-user", "duration_seconds": 60})):
            payload = json.loads(analysis_body(action))
            if action == "KILL_SESSIONS":
                payload["alert"]["labels"].update(service="db", runtime="host", target="leafy-db")
                payload["analysis"]["action_targets"] = ["leafy-db"]
            payload["analysis"]["action_parameters"] = parameters
            response = self.post_action(json.dumps(payload).encode())
            with self.subTest(action=action):
                self.assertEqual(response.status_code, 422)
                self.assertEqual(response.json()["detail"], "policy_owned_action_parameter")
        self.assertEqual(self.main.record_store.all(), [])

    def test_approval_message_contains_actual_parameters_and_selected_sessions(self):
        with patch.object(self.main.notifier, "send_approval_request", new=AsyncMock(return_value={})) as notice:
            proposal, _ = self.propose()
        analysis = notice.await_args.args[1]
        self.assertEqual(analysis["approval_parameters"], {"operation": "terminate_idle_sessions"})
        self.assertEqual(analysis["approval_plan"][0]["selected_pids"], [123])
        self.assertEqual(self.families["postgres"].calls, [])

    def test_missing_resource_config_is_blocked_before_approval(self):
        self.main.executor = ExtendedExecutorRouter()
        first, _ = self.propose()
        self.assertEqual(first.json()["status"], "blocked")
        self.assertEqual(self.docker_actions(), [])

    def test_unsupported_command_or_secret_fields_are_never_persisted(self):
        payload = json.loads(analysis_body("KILL_SESSIONS"))
        payload["analysis"]["action_parameters"] = {"password": "do-not-store", "sql": "do-not-store"}
        response = self.post_action(json.dumps(payload).encode())
        self.assertEqual(response.status_code, 422)
        self.assertEqual(self.main.record_store.all(), [])
        self.assertEqual(self.families["postgres"].plans, [])

    def test_disabled_mode_has_no_database_or_api_preflight(self):
        from executor.base import DisabledExecutor
        self.main.executor = DisabledExecutor()
        first, targets = self.propose()
        response = self.approve("KILL_SESSIONS", first.json()["remediation_id"], targets)
        self.assertEqual(response.json()["record_state"], "SKIPPED")
        self.assertTrue(all(not f.plans and not f.calls for f in self.families.values()))
