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
            "action_targets":["leafy-backend"], "threat_level":"medium", "confidence":.9,
            "evidence":["CPU > threshold"]}


def parsed(value):
    return parse_analysis(json.dumps(value), evidence_ids=None)


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

    def test_actions_needing_execution_details_are_not_proposed_from_llm_output(self):
        # 잠금 시간·세션 정리 방식은 LLM 이 아니라 정책이 정한다. 그 전까지 제안하지 않는다.
        for action in ("LOCK_ACCOUNT", "KILL_SESSIONS"):
            value = raw()
            value["action_type"] = action
            model = parsed(value)
            self.assertEqual(model.analysis_status, "valid")
            with self.assertRaises(PlanError):
                build_proposal(alert(), model, ObservationIdentity(**IDENTITY), "resolved")
