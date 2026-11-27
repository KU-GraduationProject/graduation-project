"""RCA planning and actual signed HTTP handoff over MockTransport; no real LLM/API."""
import json
import unittest
from unittest.mock import patch

import httpx
import main
from identity import ObservationIdentity
from schemas.llm_output import parse_analysis
from schemas.remediation_plan import build_proposal, PlanError
from security.service_auth import SIGNATURE_HEADER, TIMESTAMP_HEADER, sign

IDENTITY = {"site":"gc", "service":"backend", "source":"pc2", "runtime":"container", "target":"leafy-backend"}


def raw():
    return {"root_cause":"Observed CPU saturation", "incident_class":"failure", "action_type":"THROTTLE",
            "action_targets":["leafy-backend"], "target_evidence":[], "threat_level":"medium", "confidence":.9,
            "evidence":["CPU > threshold"]}


def parsed(value):
    return parse_analysis(json.dumps(value), evidence_ids=None)


def alert():
    return main.Alert(status="firing", startsAt="2026-11-12T00:00:00Z", fingerprint="fixture-incident",
        labels=main.AlertLabel(alertname="HighCPU", **IDENTITY))


class ManualApprovalHandoffTests(unittest.IsolatedAsyncioTestCase):
    async def send(self, analysis=None, answer=None, error=False, identity_status="resolved", notice=True,
                   auto=False):
        seen = []
        async def handler(request):
            seen.append(request)
            if error:
                raise httpx.ReadTimeout("fixture timeout")
            return httpx.Response(200, json=answer or {"status":"pending_approval", "remediation_id":"fixture-rid",
                                                       "dispatch":{"sent":True}})
        original = httpx.AsyncClient
        with patch.object(main.settings, "remediation_notification_enabled", notice), \
             patch.object(main.settings, "remediation_approval_enabled", True), \
             patch.object(main.settings, "remediation_auto_execute_enabled", auto), \
             patch.object(main.settings, "remediation_api_key", "fixture-api-key"), \
             patch.object(main.httpx, "AsyncClient", side_effect=lambda **kw: original(transport=httpx.MockTransport(handler), **kw)):
            status = await main.forward_to_remediation(alert(), parsed(analysis or raw()),
                                                        ObservationIdentity(**IDENTITY), identity_status)
        return seen, status

    async def test_valid_rca_creates_typed_manual_proposal_even_when_notify_only_disabled(self):
        seen, result = await self.send(notice=False)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].url.path, "/action")
        body = json.loads(seen[0].content)
        self.assertEqual(body["operation"], "propose_manual_action")
        self.assertIs(body["force_manual"], True)
        self.assertEqual(body["plan"]["identity"], IDENTITY)
        self.assertEqual(body["plan"]["parameters"], {})
        self.assertEqual(seen[0].headers[SIGNATURE_HEADER], sign("fixture-api-key", seen[0].headers[TIMESTAMP_HEADER], seen[0].content))
        self.assertTrue(result["remediation_dispatched"])
        self.assertTrue(result["approval_notification_dispatched"])
        self.assertFalse(result["execution_attempted"])

    async def test_invalid_low_confidence_future_or_restore_action_stays_informational(self):
        for mutation in ({"confidence":.79}, {"confidence":"0.95"}, {"action_type":"BACKUP_DB"},
                         {"action_type":"ENABLE_FEATURE"}, {"action_type":"REVOKE_SESSION"},
                         {"action_targets":["other-pc"]}, {"evidence":[]}):
            value = raw()
            value.update(mutation)
            seen, result = await self.send(value)
            self.assertEqual(len(seen), 1)
            self.assertEqual(seen[0].url.path, "/notify")
            self.assertFalse(result["remediation_dispatched"])

    async def test_unresolved_source_cannot_open_approval_path(self):
        seen, result = await self.send(identity_status="identity_conflict")
        self.assertEqual(seen[0].url.path, "/notify")
        self.assertFalse(result["remediation_dispatched"])

    async def test_ambiguous_delivery_never_falls_back_to_another_action_request(self):
        seen, result = await self.send(error=True)
        self.assertEqual(len(seen), 1)
        self.assertEqual(result["handoff_status"], "approval_proposal_unconfirmed")
        self.assertFalse(result["remediation_dispatched"])

    async def test_http_200_without_pending_record_does_not_claim_approval_created(self):
        seen, result = await self.send(answer={"status":"executed"})
        self.assertEqual(len(seen), 1)
        self.assertEqual(result["handoff_status"], "approval_proposal_not_accepted")

    async def test_llm_execution_details_and_plans_are_never_forwarded(self):
        value = raw()
        value["action_parameters"] = {"command": "arbitrary"}
        value["remediation_steps"] = [{"action_type": "RECREATE", "action_targets": ["leafy-backend"]}]
        seen, _ = await self.send(value)
        self.assertEqual(len(seen), 1)
        body = json.loads(seen[0].content)
        self.assertEqual(body["operation"], "propose_manual_action")
        self.assertEqual(body["plan"]["parameters"], {})
        self.assertNotIn("plan_steps", body)
        self.assertNotIn("arbitrary", seen[0].content.decode())

    def test_lock_account_targets_an_observed_account_and_leaves_duration_to_policy(self):
        value = raw()
        value.update(action_type="LOCK_ACCOUNT", action_targets=["account:fixture-user"])
        proposal = build_proposal(alert(), parsed(value), ObservationIdentity(**IDENTITY), "resolved")
        self.assertEqual(proposal["plan"]["targets"], [IDENTITY["target"]])
        self.assertEqual(proposal["plan"]["parameters"], {"account_id": "fixture-user"})
        self.assertEqual(proposal["analysis"]["action_targets"], [IDENTITY["target"]])
        for targets in (["leafy-backend"], ["account:a", "account:b"], ["account:fixture-user", "leafy-backend"]):
            value["action_targets"] = targets
            with self.subTest(targets=targets), self.assertRaises(PlanError):
                build_proposal(alert(), parsed(value), ObservationIdentity(**IDENTITY), "resolved")

    def test_account_targets_are_only_for_lock_account(self):
        value = raw()
        value["action_targets"] = ["account:fixture-user"]
        with self.assertRaises(PlanError):
            build_proposal(alert(), parsed(value), ObservationIdentity(**IDENTITY), "resolved")

    def test_kill_sessions_targets_the_observed_database_without_llm_parameters(self):
        db = dict(IDENTITY, service="db", runtime="host", target="leafy-db")
        db_alert = main.Alert(status="firing", startsAt="2026-11-12T00:00:00Z", fingerprint="fixture-db",
                              labels=main.AlertLabel(alertname="DbPoolExhausted", **db))
        value = raw()
        value.update(action_type="KILL_SESSIONS", action_targets=["leafy-db"])
        proposal = build_proposal(db_alert, parsed(value), ObservationIdentity(**db), "resolved")
        self.assertEqual(proposal["plan"]["targets"], ["leafy-db"])
        self.assertEqual(proposal["plan"]["parameters"], {})

    def test_malformed_account_targets_are_invalid_analysis(self):
        for target in ("account:", "account:bad id", "account:../x", "user:fixture"):
            value = raw()
            value.update(action_type="LOCK_ACCOUNT", action_targets=[target])
            with self.subTest(target=target):
                model = parsed(value)
                self.assertEqual(model.analysis_status, "invalid")
                self.assertIn("invalid_enum:action_targets", model.invalid_reasons)

    async def test_auto_flag_sends_rca_operation_and_reports_execution(self):
        seen, result = await self.send(auto=True, answer={"status": "executed", "remediation_id": "fixture-rid"})
        body = json.loads(seen[0].content)
        self.assertEqual(body["operation"], "propose_rca_action")
        self.assertNotIn("force_manual", body)
        self.assertEqual(result["handoff_status"], "auto_executed")
        self.assertTrue(result["execution_attempted"])
        _, waiting = await self.send(auto=True)
        self.assertEqual(waiting["handoff_status"], "approval_pending")
        self.assertFalse(waiting["execution_attempted"])

    async def test_manual_mode_never_accepts_an_execution_answer(self):
        _, result = await self.send(answer={"status": "executed", "remediation_id": "fixture-rid"})
        self.assertEqual(result["handoff_status"], "approval_proposal_not_accepted")
