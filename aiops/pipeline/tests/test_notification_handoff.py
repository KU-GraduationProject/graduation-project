"""Notion 2.4/2.5 notification handoff: signed source-aware payloads, no action path."""
from contextlib import ExitStack
from datetime import datetime, timezone
import json
import os
import sys
import unittest
from unittest.mock import AsyncMock, patch

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import main
from identity import ObservationIdentity, LogEvidence, MetricEvidence, parse_bindings
from collector.network import NetworkContext
from security.service_auth import SIGNATURE_HEADER, TIMESTAMP_HEADER, sign
from schemas.actions import ACTION_TYPES
from schemas.llm_output import parse_analysis

IDENTITY = {"site": "fixture-gc", "service": "backend", "source": "fixture-docker",
            "runtime": "container", "target": "fixture-backend"}
START = "2026-11-11T01:00:00Z"


def alert(**labels):
    return main.Alert(status="firing", startsAt=START, fingerprint="fixture-fingerprint",
                      labels=main.AlertLabel(alertname="HighCpuUsage", **labels))


def result():
    # 알림 경로는 분석 결과를 그대로 전달만 한다. fixture 대상 이름은 조치 대상 enum 밖이라 검증을 건너뛴다.
    return main.LLMAnalysisResult.model_construct(
        root_cause="fixture cpu saturation", incident_class="failure", action_type="THROTTLE",
        action_targets=["fixture-backend"], threat_level="medium", evidence=["cpu > threshold"],
        confidence=.9, analysis_status="valid", invalid_reasons=[])


class NotificationHandoffTests(unittest.IsolatedAsyncioTestCase):
    async def send(self, response=None, error=None, enabled=True, key="fixture-key",
                   identity_status="resolved", observation=None):
        seen = []
        async def handler(request):
            seen.append(request)
            if error:
                raise error
            return response or httpx.Response(200, json={"dispatch": {"sent": True}})
        factory = httpx.AsyncClient
        with patch.object(main.settings, "remediation_notification_enabled", enabled), \
             patch.object(main.settings, "remediation_api_key", key), \
             patch.object(main.httpx, "AsyncClient", side_effect=lambda **kw: factory(transport=httpx.MockTransport(handler), **kw)):
            status = await main.forward_to_remediation(
                alert(container="fixture-backend"), result(), observation or ObservationIdentity(**IDENTITY), identity_status)
        return seen, status

    async def test_all_identity_and_incident_fields_are_signed_without_action_dispatch(self):
        seen, status = await self.send()
        self.assertEqual(len(seen), 1)
        request = seen[0]
        self.assertEqual(request.url.path, "/notify")
        body = json.loads(request.content)
        self.assertEqual(body["operation"], "notify_only")
        self.assertEqual(body["alert"]["fingerprint"], "fixture-fingerprint")
        self.assertEqual(body["alert"]["startsAt"], START)
        self.assertEqual({k: body["alert"]["labels"][k] for k in IDENTITY}, IDENTITY)
        self.assertEqual({k: body["identity"][k] for k in IDENTITY}, IDENTITY)
        self.assertEqual(body["alert"]["raw_labels"]["container"], "fixture-backend")
        self.assertEqual(request.headers[SIGNATURE_HEADER],
                         sign("fixture-key", request.headers[TIMESTAMP_HEADER], request.content))
        self.assertTrue(status["notification_dispatched"])
        self.assertFalse(status["remediation_dispatched"])

    async def test_disabled_or_missing_auth_never_sends(self):
        for args, expected in (({"enabled": False}, "notification_disabled"),
                               ({"key": ""}, "notification_auth_unconfigured")):
            seen, status = await self.send(**args)
            self.assertEqual(seen, [])
            self.assertEqual(status["handoff_status"], expected)

    async def test_http_success_does_not_imply_slack_delivery(self):
        for payload in ({}, {"dispatch": {"sent": False}}, {"dispatch": {"sent": "true"}}, [], {"dispatch": []}):
            seen, status = await self.send(httpx.Response(200, json=payload))
            self.assertEqual(len(seen), 1)
            self.assertEqual(status["handoff_status"], "notification_not_sent")
            self.assertFalse(status["notification_dispatched"])

    async def test_http_or_invalid_reply_failure_has_no_action_fallback(self):
        for response in (httpx.Response(503), httpx.Response(200, text="bad json")):
            seen, status = await self.send(response)
            self.assertEqual(len(seen), 1)
            self.assertEqual(status["handoff_status"], "notification_failed")
            self.assertEqual(seen[0].url.path, "/notify")
        seen, status = await self.send(error=httpx.ReadTimeout("fixture timeout"))
        self.assertEqual(len(seen), 1)
        self.assertEqual(status["handoff_status"], "notification_failed")

    async def test_unresolved_or_ambiguous_source_remains_manual_information(self):
        for reason in ("source_unknown", "ambiguous_source", "identity_conflict"):
            seen, status = await self.send(identity_status=reason, observation=ObservationIdentity())
            body = json.loads(seen[0].content)
            self.assertEqual(body["alert"]["identity_status"], reason)
            self.assertIsNone(body["alert"]["labels"]["site"])
            self.assertEqual(body["alert"]["identity"]["site"], "UNKNOWN")
            self.assertFalse(status["remediation_dispatched"])

    async def test_periodic_and_health_messages_have_no_approval_buttons(self):
        for source in ("periodic_log_scan", "llm_health_check"):
            captured = []
            def handler(request):
                captured.append(json.loads(request.content))
                return httpx.Response(200, text="ok")
            factory = httpx.AsyncClient
            with patch.object(main.settings, "slack_webhook_url", "http://fixture.invalid/webhook"), \
                 patch.object(main.httpx, "AsyncClient", side_effect=lambda **kw: factory(transport=httpx.MockTransport(handler), **kw)):
                await main.send_periodic_slack("fixture-issue", "fixture-backend", ["fixture symptom"],
                                               {"action_type": "ISOLATE", "confidence": .9}, source)
            self.assertEqual(len(captured), 1)
            self.assertFalse(any(b["type"] == "actions" for b in captured[0]["blocks"]))
            self.assertNotIn("approve_action", json.dumps(captured))
            self.assertIn("ALERT ONLY", json.dumps(captured))

    def test_team_proposal_candidates_remain_recommendations(self):
        def parse(action):
            return parse_analysis(json.dumps({"root_cause": "x", "incident_class": "failure",
                "action_type": action, "action_targets": [], "target_evidence": [], "threat_level": "low",
                "evidence": [], "confidence": .5}), evidence_ids=None)
        for action in ACTION_TYPES:
            self.assertEqual(parse(action).action_type, action)
        invalid = parse("arbitrary_shell")
        self.assertEqual(invalid.analysis_status, "invalid")
        self.assertEqual(invalid.action_type, "NOTIFY")


class PipelineNotificationFlowTests(unittest.IsolatedAsyncioTestCase):
    async def test_enabled_flow_records_notification_and_preserves_incident(self):
        main._recent_alerts.clear()
        main.analysis_history.clear()
        binding = parse_bindings(json.dumps([{"identity": IDENTITY,
            "match": {"site": IDENTITY["site"], "target": IDENTITY["target"]}}]))[0]
        anchor = datetime.now(timezone.utc)
        network = NetworkContext("backend", anchor, anchor, provenance={"status": "empty"})
        seen = []
        async def handler(request):
            seen.append(request)
            return httpx.Response(200, json={"status": "notification_only", "dispatch": {"sent": True}})
        factory = httpx.AsyncClient
        with ExitStack() as stack:
            stack.enter_context(patch.object(main.settings, "remediation_notification_enabled", True))
            stack.enter_context(patch.object(main.settings, "remediation_api_key", "fixture-key"))
            stack.enter_context(patch.object(main, "_observation_bindings", (binding,)))
            stack.enter_context(patch.object(main.metrics_collector, "fetch_around", AsyncMock(return_value=MetricEvidence(status="empty"))))
            stack.enter_context(patch.object(main.logs_collector, "fetch", AsyncMock(return_value=LogEvidence([{"line": "fixture"}], status="ok"))))
            stack.enter_context(patch.object(main.network_collector, "fetch", AsyncMock(return_value=network)))
            stack.enter_context(patch.object(main.prompt_builder, "build", return_value={"system": "fixture", "user": "fixture"}))
            llm = stack.enter_context(patch.object(main, "call_llm", AsyncMock(return_value=result())))
            push = stack.enter_context(patch.object(main, "push_to_loki", AsyncMock(return_value=True)))
            stack.enter_context(patch.object(main.httpx, "AsyncClient", side_effect=lambda **kw: factory(transport=httpx.MockTransport(handler), **kw)))
            await main.analyze_alerts([alert(**IDENTITY), alert(**IDENTITY)])
        llm.assert_awaited_once()
        push.assert_awaited_once()
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].url.path, "/notify")
        entry = main.analysis_history[-1]
        self.assertEqual(entry["alert_fingerprint"], "fixture-fingerprint")
        self.assertEqual(entry["alert_starts_at"], START)
        self.assertEqual(entry["handoff_status"], "notification_sent")
        self.assertTrue(entry["notification_dispatched"])
        self.assertFalse(entry["remediation_dispatched"])
