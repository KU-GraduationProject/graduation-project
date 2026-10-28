"""
REMEDIATION_MODE 테스트.

Phase 0 이후 두 엔드포인트는 HMAC 서명을 요구한다. 이 파일이 검증하는 것은
모드별 실행 동작이므로, 요청에 유효한 서명을 붙여 전송 단계를 통과시킨다.
서명 자체의 검증은 test_service_auth.py / test_endpoint_auth.py 가 담당한다.

실행 (remediation 디렉터리에서):
    python -m unittest discover -s tests -v
"""

import importlib
import json
import os
import sys
import time
import unittest
import urllib.parse
from unittest import mock

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from security import service_auth, signing, slack_signature  # noqa: E402

SLACK_SECRET = "test-slack-secret"
API_KEY = "test-api-key"

LOW_RISK_RESTART = {
    "alert": {"labels": {"alertname": "HighCpuUsage"}},
    "analysis": {"action_type": "RESTART", "action_targets": ["leafy-backend"],
                 "action_risk": "low", "threat_level": "high", "confidence": 0.9},
}


def signed_action(payload: dict) -> tuple[bytes, dict]:
    """/action 용 (본문, 헤더). 본문 바이트가 서명 대상이므로 그대로 전송해야 한다."""
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    ts = str(int(time.time()))
    return body, {
        service_auth.TIMESTAMP_HEADER: ts,
        service_auth.SIGNATURE_HEADER: signing.sign(API_KEY, ts, body),
        "Content-Type": "application/json",
    }


def signed_slack(form: str) -> tuple[bytes, dict]:
    """/slack/action 용 (본문, 헤더)."""
    body = form.encode("utf-8")
    ts = str(int(time.time()))
    return body, {
        slack_signature.TIMESTAMP_HEADER: ts,
        slack_signature.SIGNATURE_HEADER: signing.sign(SLACK_SECRET, ts, body),
        "Content-Type": "application/x-www-form-urlencoded",
    }


def load_main(mode):
    """REMEDIATION_MODE는 import 시점에 읽으므로 환경변수를 바꿔 새로 import 한다."""
    env = {"SLACK_WEBHOOK_URL": "",
           "SLACK_SIGNING_SECRET": SLACK_SECRET,
           "REMEDIATION_API_KEY": API_KEY}
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
        content, headers = signed_action(LOW_RISK_RESTART)
        body = self.client.post("/action", content=content, headers=headers).json()
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
        content, headers = signed_slack("payload=" + urllib.parse.quote(payload))
        body = self.client.post("/slack/action", content=content, headers=headers).json()
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
