"""
REMEDIATION_MODE 테스트.

실행 (remediation 디렉터리에서):
    python -m unittest discover -s tests -v
"""

import importlib
import json
import os
import sys
import unittest
import urllib.parse
from unittest import mock

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

LOW_RISK_RESTART = {
    "alert": {"labels": {"alertname": "HighCpuUsage"}},
    "analysis": {"action_type": "RESTART", "action_targets": ["leafy-backend"],
                 "action_risk": "low", "threat_level": "high", "confidence": 0.9},
}


def load_main(mode):
    """REMEDIATION_MODE는 import 시점에 읽으므로 환경변수를 바꿔 새로 import 한다."""
    env = {"SLACK_WEBHOOK_URL": ""}
    if mode is not None:
        env["REMEDIATION_MODE"] = mode
    for name in ("main", "actions.notify", "actions.container"):
        sys.modules.pop(name, None)
    with mock.patch.dict(os.environ, env, clear=False):
        if mode is None:
            os.environ.pop("REMEDIATION_MODE", None)
        with mock.patch("docker.from_env") as from_env:
            module = importlib.import_module("main")
    return module, from_env


class DisabledModeTest(unittest.TestCase):
    def setUp(self):
        self.main, self.from_env = load_main("disabled")
        self.events = []
        patcher = mock.patch.object(self.main, "_push_soc_event", side_effect=self._record)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = TestClient(self.main.app)

    async def _record(self, job, event):
        self.events.append((job, event))

    def test_docker_client_is_never_created(self):
        self.from_env.assert_not_called()
        self.assertIsNone(self.main.container_actions)

    def test_auto_path_reports_skipped_not_executed(self):
        body = self.client.post("/action", json=LOW_RISK_RESTART).json()
        self.assertEqual(body["status"], "skipped")
        self.assertTrue(body["results"][0].startswith("Skipped:"))
        statuses = {(job, e["event"]): e["status"] for job, e in self.events if "status" in e}
        self.assertEqual(statuses[("aiops-remediation", "auto_remediation")], "SKIPPED")
        self.assertEqual(statuses[("aiops-timeline", "auto_remediation_completed")], "SKIPPED")

    def test_slack_approval_is_logged_as_skipped(self):
        value = json.dumps({"alertname": "HighCpuUsage", "action_type": "RESTART",
                            "action_targets": ["leafy-backend"]})
        payload = json.dumps({"actions": [{"action_id": "approve_action", "value": value}],
                              "user": {"name": "tester"}})
        body = self.client.post("/slack/action", content="payload=" + urllib.parse.quote(payload),
                                headers={"Content-Type": "application/x-www-form-urlencoded"}).json()
        self.assertEqual(body["status"], "approved")
        self.assertTrue(body["results"][0].startswith("Skipped:"))
        executed = [e for job, e in self.events if e.get("event") == "manual_approval_executed"]
        self.assertEqual([e["status"] for e in executed], ["SKIPPED"])

    def test_approval_message_says_it_will_not_run(self):
        from actions import notify
        self.assertTrue(notify.REMEDIATION_DISABLED)


class ModeValidationTest(unittest.TestCase):
    def test_default_mode_keeps_local_docker_actions(self):
        main, from_env = load_main(None)
        self.assertEqual(main.REMEDIATION_MODE, "docker")
        from_env.assert_called_once()
        self.assertIsNotNone(main.container_actions)

    def test_unknown_mode_fails_fast(self):
        with self.assertRaises(ValueError):
            load_main("remote")


if __name__ == "__main__":
    unittest.main()
