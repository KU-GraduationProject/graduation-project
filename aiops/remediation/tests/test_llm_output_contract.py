"""
Pipeline 새 출력 형식(incident_class·증거 ID·analysis_status) ↔ Remediation 호환 테스트.

확인하는 것:
  - 정책 엔진이 쓰는 필드(action_type / action_targets / threat_level / confidence)는
    이름·의미가 그대로라 기존 판단이 같다.
  - analysis_status=invalid 는 action_type 과 무관하게 NOTIFY 로 판단되고 Docker 를 건드리지 않는다.
  - Slack 메시지가 action_description 없이도 만들어지고, invalid 면 "분석 실패" 로 표시된다.

실행 (remediation 디렉터리에서):
    python -m unittest discover -s tests -v
"""

import asyncio
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from actions.notify import Notifier  # noqa: E402
from policy.engine import PolicyEngine  # noqa: E402
from policy.schema import AUTO_EXECUTE_CANDIDATE, AWAITING_APPROVAL, NOTIFY  # noqa: E402
from tests.test_policy_integration import PolicyEndpointBase  # noqa: E402

POLICY = os.path.join(os.path.dirname(__file__), "..", "..", "policy", "remediation_policy.yml")

# Pipeline schemas/llm_output.LLMAnalysisResult.model_dump() 와 같은 모양
VALID = {
    "root_cause": "backend sends large data to an unauthorized destination.",
    "incident_class": "attack", "action_type": "ISOLATE", "action_targets": ["leafy-backend"],
    "threat_level": "critical", "evidence": ["A1", "N1"], "confidence": 0.9,
    "analysis_status": "valid", "invalid_reasons": [],
}
INVALID = {
    "root_cause": "분석 실패 — 수동 확인 필요 (truncated, parse_error)",
    "incident_class": None, "action_type": "NOTIFY", "action_targets": [],
    "threat_level": "medium", "evidence": [], "confidence": 0.0,
    "analysis_status": "invalid", "invalid_reasons": ["truncated", "parse_error"],
}


def body(analysis):
    return json.dumps({"alert": {"labels": {"alertname": "UnauthorizedDataTransfer"}},
                       "analysis": analysis}, ensure_ascii=False).encode("utf-8")


class EngineContractTest(unittest.TestCase):
    def setUp(self):
        self.engine = PolicyEngine.from_file(POLICY)

    def test_valid_new_format_decides_as_before(self):
        d = self.engine.decide_from_analysis(VALID)
        self.assertEqual(d.outcome, AWAITING_APPROVAL)
        self.assertEqual(d.targets, ("leafy-backend",))
        throttle = dict(VALID, action_type="THROTTLE", threat_level="medium", confidence=0.85)
        self.assertEqual(self.engine.decide_from_analysis(throttle).outcome, AUTO_EXECUTE_CANDIDATE)

    def test_invalid_is_notify_even_if_action_type_is_executable(self):
        for spoofed in ("ISOLATE", "THROTTLE", "RESTART", "NONE"):
            d = self.engine.decide_from_analysis(
                dict(INVALID, action_type=spoofed, action_targets=["leafy-backend"], confidence=1.0))
            self.assertEqual(d.outcome, NOTIFY, spoofed)
            self.assertFalse(d.performs_action)
            self.assertEqual(d.targets, ())
            self.assertIn("analysis_invalid:truncated,parse_error", d.reasons)


class EndpointContractTest(PolicyEndpointBase):
    def test_invalid_analysis_is_notified_without_docker(self):
        resp = self.post_action(body(dict(INVALID, action_type="ISOLATE",
                                          action_targets=["leafy-backend"])))
        self.assertEqual(resp.json()["status"], "notified")
        self.assertEqual(resp.json()["policy"]["outcome"], "NOTIFY")
        self.assertEqual(self.docker_calls(), 0)

    def test_valid_new_format_goes_to_approval(self):
        resp = self.post_action(body(VALID))
        self.assertEqual(resp.json()["status"], "pending_approval")
        self.assertEqual(self.docker_calls(), 0)


class SlackContractTest(unittest.TestCase):
    def _payload(self, method, analysis):
        sent = {}

        async def fake_send(alert_name, payload):
            sent["payload"] = payload
            return {"sent": False}

        n = Notifier()
        with mock.patch.object(n, "_send_slack", side_effect=fake_send):
            asyncio.run(getattr(n, method)({"labels": {"alertname": "X"}}, analysis))
        return json.dumps(sent["payload"], ensure_ascii=False)

    def test_approval_message_without_action_description(self):
        text = self._payload("send_approval_request", VALID)
        self.assertNotIn("N/A", text.split("*Action*")[1][:40])
        self.assertIn("ISOLATE → leafy-backend", text)
        self.assertIn("A1", text)

    def test_invalid_alert_says_analysis_failed(self):
        text = self._payload("send_alert_only", INVALID)
        self.assertIn("분석 실패", text)
        self.assertIn("truncated, parse_error", text)

    def test_valid_alert_only_keeps_header(self):
        self.assertIn("[ALERT ONLY]", self._payload("send_alert_only", dict(VALID, action_type="NOTIFY")))


if __name__ == "__main__":
    unittest.main()
