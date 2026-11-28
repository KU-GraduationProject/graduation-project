"""
Remediation 감사 이벤트의 사건 연결 키 (#81).

데이터 플랫폼은 Loki 이벤트만 읽으므로 이벤트 본문만으로 정책 결정·조치 레코드를
경보 사건(fingerprint·startsAt·identity)과 이을 수 있어야 한다.
  - policy_decision: alert_fingerprint, alert_starts_at, identity, (레코드가 있을 때만) remediation_id
  - 레코드 이벤트(_push_record): incident_key, plan_id, rejected_by — SQLite 레코드 값과 같다
기존 필드·이벤트 이름은 그대로 둔다(추가만).

실행 (remediation 디렉터리에서):
    python -m unittest tests.test_event_keys -v
"""

import asyncio
import json
import os
import time
import unittest
from unittest import mock

from tests import test_integrated_plans as plan_tests
from tests.test_policy_integration import IDENTITY, PolicyEndpointBase, analysis_body, slack_approve_form

NEW_RECORD_KEYS = ("incident_key", "plan_id", "rejected_by")


def alert_of(body: bytes) -> dict:
    return json.loads(body)["alert"]


class EventKeyMixin:
    def remediation_events(self, name):
        return [e for job, e in self.events if job == "aiops-remediation" and e.get("event") == name]

    def assert_incident_fields(self, row, alert):
        self.assertEqual(row["alert_fingerprint"], alert["fingerprint"])
        self.assertEqual(row["alert_starts_at"], alert["startsAt"])
        self.assertEqual(row["identity"], {k: alert["labels"].get(k)
                                           for k in self.main.store_mod.IDENTITY_FIELDS})

    def assert_record_keys(self, row, rid, alert):
        record = self.main.record_store.get(rid)
        self.assertEqual(row["remediation_id"], rid)
        for key in NEW_RECORD_KEYS:
            self.assertIn(key, row)
        self.assertEqual(row["incident_key"], record.incident_key)
        self.assertEqual(row["incident_key"], self.main.store_mod.incident_key(alert)[0])
        self.assertEqual(row["plan_id"], record.plan_id)
        self.assertEqual(row["rejected_by"], record.rejected_by)


class PolicyDecisionKeysTest(EventKeyMixin, PolicyEndpointBase):
    def test_blocked_decision_has_incident_keys_but_no_remediation_id(self):
        body = analysis_body("WIPE_DISK", threat_level="critical", confidence=1.0, llm_risk="low")
        resp = self.post_action(body)
        self.assertEqual(resp.json()["status"], "blocked")
        self.assertEqual(self.main.record_store.all(), [])
        rows = self.decisions()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "BLOCKED")
        self.assertNotIn("remediation_id", rows[0])
        self.assert_incident_fields(rows[0], alert_of(body))
        self.assertEqual(rows[0]["identity"], IDENTITY)

    def test_no_action_decision_has_incident_keys_but_no_remediation_id(self):
        body = analysis_body("NONE", threat_level="low", targets=())
        self.assertEqual(self.post_action(body).json()["status"], "notified")
        row, = self.decisions()
        self.assertNotIn("remediation_id", row)
        self.assert_incident_fields(row, alert_of(body))

    def test_recorded_decision_carries_remediation_id_before_approval_event(self):
        body = analysis_body("RESTART")
        resp = self.post_action(body)
        rid = resp.json()["remediation_id"]
        row, = self.decisions()
        self.assertEqual(row["remediation_id"], rid)
        self.assert_incident_fields(row, alert_of(body))
        names = [e.get("event") for _, e in self.events]
        self.assertLess(names.index("policy_decision"), names.index("approval_requested"))

    def test_duplicate_proposal_decision_points_at_existing_record(self):
        body = analysis_body("RESTART")
        rid = self.post_action(body).json()["remediation_id"]
        # 같은 바이트는 재전송으로 거부되므로 내용은 같고 공백만 다른 본문을 보낸다.
        again = self.post_action(json.dumps(json.loads(body), indent=1).encode("utf-8")).json()
        self.assertEqual(again["status"], "existing")
        self.assertEqual([r["remediation_id"] for r in self.decisions()], [rid, rid])

    def test_decision_failing_before_record_is_still_recorded_without_id(self):
        payload = json.loads(analysis_body("RESTART"))
        del payload["alert"]["labels"]["site"]
        body = json.dumps(payload).encode("utf-8")
        resp = self.post_action(body)
        self.assertEqual(resp.status_code, 422, resp.text)
        row, = self.decisions()
        self.assertNotIn("remediation_id", row)
        self.assertIsNone(row["identity"]["site"])
        self.assert_incident_fields(row, payload["alert"])

    def test_existing_decision_fields_are_preserved(self):
        resp = self.post_action(analysis_body("ISOLATE", threat_level="critical", llm_risk="low"))
        row, = self.decisions()
        for key in ("event", "alert", "source", "status", *resp.json()["policy"]):
            self.assertIn(key, row)
        self.assertEqual(row["alert"], "UnauthorizedDataTransfer")
        self.assertEqual(row["status"], resp.json()["policy"]["outcome"])


class RecordEventKeysTest(EventKeyMixin, PolicyEndpointBase):
    def test_approval_requested_event_has_record_keys(self):
        body = analysis_body("RESTART")
        rid = self.post_action(body).json()["remediation_id"]
        row, = self.remediation_events("approval_requested")
        self.assert_record_keys(row, rid, alert_of(body))
        self.assertIsNone(row["plan_id"])
        self.assertIsNone(row["rejected_by"])

    def test_rejected_event_carries_rejected_by(self):
        body = analysis_body("RESTART")
        rid = self.post_action(body).json()["remediation_id"]
        resp = self.post_slack(slack_approve_form("RESTART", remediation_id=rid, action_id="reject_action"))
        self.assertEqual(resp.json()["status"], "rejected")
        row, = self.remediation_events("manual_approval_rejected")
        self.assert_record_keys(row, rid, alert_of(body))
        self.assertTrue(row["rejected_by"])

    def test_approved_execution_event_has_record_keys(self):
        body = analysis_body("RESTART")
        rid = self.post_action(body).json()["remediation_id"]
        self.assertEqual(self.post_slack(slack_approve_form("RESTART", remediation_id=rid)).json()["status"],
                         "approved")
        row, = self.remediation_events("remediation_executed")
        self.assert_record_keys(row, rid, alert_of(body))
        self.assertIsNone(row["rejected_by"])

    def test_ttl_recovery_event_has_record_keys(self):
        body = analysis_body("THROTTLE", threat_level="medium", confidence=0.85)
        with mock.patch.dict(os.environ, {"REMEDIATION_AUTO_EXECUTE_ENABLED": "true"}):
            rid = self.post_action(body).json()["remediation_id"]
        processed = self.main.recovery_mod.run_due(self.main.record_store, self.main.executor,
                                                   now=time.time() + 10_000)
        self.assertEqual(len(processed), 1)
        for record, results, state in processed:
            asyncio.run(self.main._on_ttl_event(record, results, state))
        row, = self.remediation_events("ttl_recovery_processed")
        self.assert_record_keys(row, rid, alert_of(body))

    def test_existing_record_event_fields_are_preserved(self):
        rid = self.post_action(analysis_body("RESTART")).json()["remediation_id"]
        row, = self.remediation_events("approval_requested")
        record = self.main.record_store.get(rid)
        for key in ("event", "status", "remediation_id", "alert", "action_type", "targets", "state",
                    *record.timings()):
            self.assertIn(key, row)
        self.assertEqual(row["alert"], record.alertname)
        self.assertEqual(row["status"], record.state)


class TimingsEventKeysTest(unittest.TestCase):
    def test_linked_record_values_are_copied(self):
        import recovery
        import store
        record = store.RemediationRecord(remediation_id="r2", alertname="A", action_type="RESTART",
                                         incident_key="dkey", plan_id="r1", rejected_by="U1")
        event = recovery.timings_event(record)
        self.assertEqual((event["incident_key"], event["plan_id"], event["rejected_by"]),
                         ("dkey", "r1", "U1"))


class ReplanEventKeysTest(EventKeyMixin, plan_tests.IntegratedPlanTests):
    """연결 레코드(replan)는 루트 remediation_id 를 plan_id 로 싣는다."""

    def test_replanned_record_event_carries_root_plan_id(self):
        body = plan_tests.proposal("RESTART")
        first = self.post(body).json()["remediation_id"]
        self.main.record_store.update(first, state="EXPIRED")
        body.update(operation="replan_action", replan_of=first, reason="Refreshed target inspection")
        second = self.post(body).json()["remediation_id"]
        rows = {e["remediation_id"]: e for e in self.remediation_events("approval_requested")}
        self.assert_record_keys(rows[second], second, body["alert"])
        self.assertEqual(rows[second]["plan_id"], first)
        self.assertIsNone(rows[first]["plan_id"])
        self.assertEqual(rows[second]["incident_key"], rows[first]["incident_key"])


# IntegratedPlanTests 의 테스트를 이 파일에서 다시 돌리지 않는다.
for _name in [n for n in vars(plan_tests.IntegratedPlanTests) if n.startswith("test_")]:
    setattr(ReplanEventKeysTest, _name, None)


if __name__ == "__main__":
    unittest.main()
