"""RCA planning and actual signed HTTP handoff over MockTransport; no real LLM/API."""
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

import httpx
import main
from identity import ObservationIdentity
from schemas.llm_output import LLMAnalysisResult
from schemas.remediation_plan import build_proposals, PlanError
from security.service_auth import SIGNATURE_HEADER, TIMESTAMP_HEADER, sign

IDENTITY = {"site":"gc", "service":"backend", "source":"pc2", "runtime":"container", "target":"leafy-backend"}


def raw():
    return {"root_cause":"Observed CPU saturation", "action_type":"THROTTLE",
            "action_targets":["leafy-backend"], "action_parameters":{},
            "threat_level":"medium", "confidence":.9, "evidence":["CPU > threshold"]}


def alert():
    return main.Alert(status="firing", startsAt="2026-11-12T00:00:00Z", fingerprint="fixture-incident",
        labels=main.AlertLabel(alertname="HighCPU", **IDENTITY))


class ManualApprovalHandoffTests(unittest.IsolatedAsyncioTestCase):
    async def send(self, analysis=None, answer=None, error=False, identity_status="resolved", notice=True):
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
             patch.object(main.settings, "remediation_api_key", "fixture-api-key"), \
             patch.object(main.httpx, "AsyncClient", side_effect=lambda **kw: original(transport=httpx.MockTransport(handler), **kw)):
            status = await main.forward_to_remediation(alert(), LLMAnalysisResult(**(analysis or raw())),
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
                         {"action_type":"ENABLE_FEATURE"}, {"action_targets":["other-pc"]},
                         {"evidence":[]}, {"action_parameters":{"command":"arbitrary"}}):
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

    async def test_two_steps_are_sent_as_one_manual_plan_without_advancing(self):
        value = raw()
        value["remediation_steps"] = [deepcopy(value), {"action_type":"RECREATE", "action_targets":["leafy-backend"],
                                                       "action_parameters":{}}]
        # Step schema forbids nested plans and inherits the root cause itself.
        value["remediation_steps"][0].pop("root_cause")
        seen, _ = await self.send(value)
        body = json.loads(seen[0].content)
        self.assertEqual(body["operation"], "propose_plan")
        self.assertEqual(len(body["plan_steps"]), 2)
        self.assertTrue(body["force_manual"])
        self.assertEqual(len(seen), 1)

    def test_required_resource_parameters_are_typed_and_unknown_inputs_are_discarded(self):
        value = raw()
        value.update(action_type="LOCK_ACCOUNT", action_parameters={"account_id":"123", "duration_seconds":300})
        model = LLMAnalysisResult(**value)
        self.assertEqual(model.analysis_status, "valid")
        self.assertEqual(build_proposals(alert(), model, ObservationIdentity(**IDENTITY), "resolved")[0]["plan"]["parameters"],
                         {"account_id":"123", "duration_seconds":300})
        for invalid in ({"account_id":"123", "duration_seconds":"300"},
                        {"account_id":"123", "duration_seconds":300, "token":"private-never-store"}, {}):
            value["action_parameters"] = invalid
            model = LLMAnalysisResult(**value)
            self.assertEqual(model.analysis_status, "invalid")
            self.assertNotIn("private-never-store", model.model_dump_json())
            with self.assertRaises(PlanError):
                build_proposals(alert(), model, ObservationIdentity(**IDENTITY), "resolved")
