"""Notification-only messages expose RCA and observation identity without approval paths."""
import json
import unittest
from unittest.mock import AsyncMock

from actions.notify import Notifier


class NotificationMessageTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.notifier = Notifier()
        self.notifier._send_slack = AsyncMock(return_value={"sent": True})
        self.alert = {"labels": {"alertname": "fixture-alert"}, "startsAt": "2026-11-11T01:00:00Z",
                      "identity": {"site": "fixture-gc", "source": "fixture-host", "service": "db",
                                   "runtime": "host", "target": "fixture-pg17"},
                      "identity_status": "resolved"}
        self.analysis = {"root_cause": "fixture connection exhaustion", "action_type": "KILL_SESSIONS",
                         "action_targets": ["fixture-pg17"], "action_description": "manual DBA review",
                         "evidence": ["connection slots occupied"], "threat_level": "high", "confidence": .9}

    async def test_alert_only_shows_identity_cause_evidence_and_recommendation(self):
        await self.notifier.send_alert_only(self.alert, self.analysis)
        payload = self.notifier._send_slack.await_args.args[1]
        body = json.dumps(payload, ensure_ascii=False)
        for value in ("fixture-gc", "fixture-host", "db", "host", "fixture-pg17",
                      "fixture connection exhaustion", "connection slots occupied", "KILL_SESSIONS", "manual DBA review"):
            self.assertIn(value, body)
        self.assertFalse(any(b["type"] == "actions" for b in payload["blocks"]))
        self.assertNotIn("approve_action", body)

    async def test_no_durable_record_id_downgrades_approval_to_alert_only(self):
        await self.notifier.send_approval_request(self.alert, self.analysis)
        body = json.dumps(self.notifier._send_slack.await_args.args[1])
        self.assertIn("ALERT ONLY", body)
        self.assertNotIn('"type": "button"', body)

    async def test_durable_id_is_in_all_approval_buttons(self):
        await self.notifier.send_approval_request(self.alert, self.analysis, "fixture-record-id")
        payload = self.notifier._send_slack.await_args.args[1]
        buttons = [e for b in payload["blocks"] if b["type"] == "actions" for e in b["elements"]]
        self.assertEqual(len(buttons), 2)
        for button in buttons:
            self.assertEqual(json.loads(button["value"])["remediation_id"], "fixture-record-id")

    async def test_unresolved_identity_is_explicit_information(self):
        self.alert["identity"] = {}
        self.alert["identity_status"] = "ambiguous_source"
        self.analysis["confidence"] = None
        await self.notifier.send_alert_only(self.alert, self.analysis)
        body = json.dumps(self.notifier._send_slack.await_args.args[1])
        self.assertIn("UNKNOWN", body)
        self.assertIn("ambiguous_source", body)
        self.assertNotIn('"type": "button"', body)

    async def test_legacy_single_target_input_matches_stored_button_plan(self):
        self.analysis["action_targets"] = " fixture-pg17 "
        await self.notifier.send_approval_request(self.alert, self.analysis, "fixture-record-id")
        payload = self.notifier._send_slack.await_args.args[1]
        buttons = [e for b in payload["blocks"] if b["type"] == "actions" for e in b["elements"]]
        for button in buttons:
            self.assertEqual(json.loads(button["value"])["action_targets"], ["fixture-pg17"])

    async def test_nullable_targets_do_not_drop_notification(self):
        self.analysis["action_targets"] = None
        self.alert["identity"] = "unverified input"
        result = await self.notifier.send_alert_only(self.alert, self.analysis)
        self.assertTrue(result["sent"])
        payload = self.notifier._send_slack.await_args.args[1]
        self.assertFalse(any(b["type"] == "actions" for b in payload["blocks"]))
