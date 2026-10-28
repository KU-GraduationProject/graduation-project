"""
정책 엔진 ↔ 엔드포인트 통합 테스트 (Phase 1).

확인하는 것:
  - /action 의 outcome 별 응답과 감사 로그
  - 승인 경로가 정책의 실행 게이트를 통과해야만 실행한다 (경로 간 모순 없음)
  - Phase 0 인증이 정책 엔진보다 앞에 있다 (인증 실패 시 판단조차 하지 않는다)
  - disabled 모드에서 조치를 성공으로 표시하지 않는다
  - 정책 로드 실패 시 모든 조치가 차단된다

Docker 는 Mock 이고 Slack 은 webhook 미설정으로 전송되지 않는다.

실행 (remediation 디렉터리에서):
    python -m unittest discover -s tests -v
"""

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
from tests.test_endpoint_auth import API_KEY, SLACK_SECRET, load_main  # noqa: E402


def analysis_body(action_type, threat_level="high", confidence=0.9,
                  targets=("leafy-backend",), llm_risk=None):
    analysis = {"action_type": action_type, "action_targets": list(targets),
                "threat_level": threat_level, "confidence": confidence}
    if llm_risk is not None:
        analysis["action_risk"] = llm_risk
    return json.dumps({"alert": {"labels": {"alertname": "UnauthorizedDataTransfer"}},
                       "analysis": analysis}, ensure_ascii=False).encode("utf-8")


def slack_approve_form(action_type, targets=("leafy-backend",)):
    value = json.dumps({"alertname": "UnauthorizedDataTransfer",
                        "action_type": action_type, "action_targets": list(targets)})
    return "payload=" + urllib.parse.quote(json.dumps({
        "actions": [{"action_id": "approve_action", "value": value}],
        "user": {"name": "tester"}}))


class PolicyEndpointBase(unittest.TestCase):
    mode = "docker"

    def setUp(self):
        self.main, self.from_env = load_main(self.mode, SLACK_SECRET, API_KEY)
        self.events = []
        patcher = mock.patch.object(self.main, "_push_soc_event", side_effect=self._record)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = TestClient(self.main.app)

    async def _record(self, job, event):
        self.events.append((job, event))

    def docker_calls(self) -> int:
        """
        실제로 컨테이너·네트워크를 '바꾼' Docker 호출 횟수.
        [Phase 2 변경] containers.get 은 상태 수집·재조회에도 쓰이므로 세지 않는다.
        """
        client = self.from_env.return_value
        container = client.containers.get.return_value
        network = client.networks.get.return_value
        return (container.restart.call_count + container.pause.call_count
                + container.unpause.call_count + container.update.call_count
                + network.disconnect.call_count + network.connect.call_count)

    def post_action(self, body):
        ts = str(int(time.time()))
        return self.client.post("/action", content=body, headers={
            service_auth.TIMESTAMP_HEADER: ts,
            service_auth.SIGNATURE_HEADER: signing.sign(API_KEY, ts, body),
            "Content-Type": "application/json",
        })

    def post_slack(self, form):
        body = form.encode("utf-8")
        ts = str(int(time.time()))
        return self.client.post("/slack/action", content=body, headers={
            slack_signature.TIMESTAMP_HEADER: ts,
            slack_signature.SIGNATURE_HEADER: signing.sign(SLACK_SECRET, ts, body),
            "Content-Type": "application/x-www-form-urlencoded",
        })

    def decisions(self):
        return [e for job, e in self.events if e.get("event") == "policy_decision"]


class ActionOutcomeTest(PolicyEndpointBase):
    def test_high_risk_goes_to_approval(self):
        for action in ("RESTART", "PAUSE", "ISOLATE"):
            resp = self.post_action(analysis_body(action, llm_risk="low"))
            self.assertEqual(resp.json()["status"], "pending_approval", action)
            self.assertEqual(resp.json()["policy"]["action_risk"], "high", action)
        self.assertEqual(self.docker_calls(), 0)

    def test_critical_threat_still_requires_approval(self):
        resp = self.post_action(analysis_body("ISOLATE", threat_level="critical",
                                              confidence=1.0, llm_risk="low"))
        policy = resp.json()["policy"]
        self.assertEqual(resp.json()["status"], "pending_approval")
        self.assertEqual(policy["urgency"], "immediate")
        self.assertTrue(policy["mention"])
        self.assertTrue(policy["requires_approval"])
        self.assertEqual(self.docker_calls(), 0)

    def test_throttle_candidate_is_executed_with_ttl(self):
        """
        [Phase 2 기대값 변경] Phase 1 에서는 TTL 자동 복구가 없어 후보 상태로만 남고
        'auto_execution_deferred' 였다. Phase 2 는 UNTHROTTLE 복구를 구현했으므로
        정책대로 실행된다 (executable_now=true). 복구 TTL 은 그대로 1800초다.
        """
        resp = self.post_action(analysis_body("THROTTLE", threat_level="medium",
                                              confidence=0.85))
        body = resp.json()
        self.assertEqual(body["policy"]["outcome"], "AUTO_EXECUTE_CANDIDATE")
        self.assertTrue(body["policy"]["executable_now"])
        self.assertEqual(body["policy"]["ttl_seconds"], 1800)
        self.assertEqual(body["policy"]["recovery_mode"], "auto")
        self.assertEqual(self.docker_calls(), 1)

    def test_throttle_below_threshold_goes_to_approval(self):
        resp = self.post_action(analysis_body("THROTTLE", threat_level="medium",
                                              confidence=0.79))
        self.assertEqual(resp.json()["status"], "pending_approval")
        self.assertEqual(self.docker_calls(), 0)

    def test_unsupported_action_is_blocked(self):
        resp = self.post_action(analysis_body("SCALE"))
        body = resp.json()
        self.assertEqual(body["status"], "blocked")
        self.assertEqual(body["reason"], "unsupported_action_type:no_executor_implemented")
        self.assertEqual(self.docker_calls(), 0)

    def test_undefined_action_is_blocked(self):
        resp = self.post_action(analysis_body("WIPE_DISK", threat_level="critical",
                                              confidence=1.0, llm_risk="low"))
        self.assertEqual(resp.json()["status"], "blocked")
        self.assertEqual(resp.json()["reason"], "undefined_action_type")
        self.assertEqual(self.docker_calls(), 0)

    def test_none_is_notified(self):
        resp = self.post_action(analysis_body("NONE", threat_level="low", targets=()))
        self.assertEqual(resp.json()["status"], "notified")
        self.assertEqual(resp.json()["policy"]["outcome"], "NO_ACTION")


class AuditLogTest(PolicyEndpointBase):
    def test_policy_decision_is_recorded_with_reasons(self):
        self.post_action(analysis_body("ISOLATE", threat_level="critical", llm_risk="low"))
        rows = self.decisions()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["action_risk"], "high")
        self.assertEqual(row["threat_level"], "critical")
        self.assertEqual(row["urgency"], "immediate")
        self.assertEqual(row["status"], "AWAITING_APPROVAL")
        self.assertEqual(row["llm_action_risk"], "low")
        self.assertFalse(row["llm_action_risk_used"])
        self.assertIn("llm_action_risk_ignored:low", row["reasons"])
        self.assertEqual(row["source"], "action")

    def test_decision_goes_to_existing_remediation_stream(self):
        """기존 Loki job 라벨을 그대로 쓴다 — Grafana SOC 패널 호환."""
        self.post_action(analysis_body("RESTART"))
        jobs = {job for job, e in self.events if e.get("event") == "policy_decision"}
        self.assertEqual(jobs, {"aiops-remediation"})

    def test_existing_timeline_event_is_preserved(self):
        self.post_action(analysis_body("RESTART"))
        events = {e.get("event") for _, e in self.events}
        self.assertIn("remediation_decision_started", events)


class ApprovalPathConsistencyTest(PolicyEndpointBase):
    """승인 경로와 자동 경로가 같은 정책 게이트를 쓴다 (모순 제거)."""

    def test_approved_restart_executes(self):
        resp = self.post_slack(slack_approve_form("RESTART"))
        self.assertEqual(resp.json()["status"], "approved")
        self.assertEqual(self.docker_calls(), 1)

    def test_approved_isolate_passes_the_policy_gate(self):
        """
        [Phase 2 기대값 변경] Docker 변경 호출 수 단정을 뺐다. ISOLATE 는 Phase 2 부터
        증거 보존(네트워크 IP·alias)을 실행 전제조건으로 요구하는데, 이 테스트의
        Mock 클라이언트에서는 증거를 모을 수 없어 게이트에서 막히는 것이 옳은 동작이다.
        실제 격리·검증·복구는 test_phase2_integration 이 현실적인 Fake Docker 로 검증한다.
        여기서는 정책 게이트가 ISOLATE 를 허용하는지만 본다.
        """
        allowed, reason = self.main.policy_engine.execution_allowed(
            "ISOLATE", ["leafy-backend"])
        self.assertTrue(allowed, reason)
        resp = self.post_slack(slack_approve_form("ISOLATE"))
        self.assertEqual(resp.json()["status"], "approved")
        self.assertNotIn("blocked by policy", resp.json()["results"][0])

    def test_approved_pause_passes_the_policy_gate(self):
        """
        [Phase 2 기대값 변경] Phase 1 에서는 PAUSE 실행기가 승인 경로에 연결되지 않아
        정책이 차단했다. Phase 2 는 PAUSE/UNPAUSE 와 복구(재승인 필요)를 구현해 게이트가
        열렸다. 실제 동결·해제는 test_executor / test_recovery_store 가 검증한다.
        """
        allowed, reason = self.main.policy_engine.execution_allowed(
            "PAUSE", ["leafy-backend"])
        self.assertTrue(allowed, reason)
        self.assertEqual(self.main.policy_engine.config.actions["PAUSE"].recovery_mode,
                         "require_approval")
        resp = self.post_slack(slack_approve_form("PAUSE"))
        self.assertEqual(resp.json()["status"], "approved")
        self.assertNotIn("blocked by policy", resp.json()["results"][0])

    def test_approved_throttle_executes_now_that_recovery_exists(self):
        """[Phase 2 기대값 변경] TTL 복구 구현으로 THROTTLE 실행이 열렸다."""
        resp = self.post_slack(slack_approve_form("THROTTLE"))
        self.assertEqual(resp.json()["status"], "approved")
        self.assertEqual(self.docker_calls(), 1)

    def test_approved_unsupported_action_is_blocked(self):
        resp = self.post_slack(slack_approve_form("SCALE"))
        self.assertIn("unsupported_action_type", resp.json()["results"][0])
        self.assertEqual(self.docker_calls(), 0)

    def test_approval_without_targets_does_not_execute(self):
        resp = self.post_slack(slack_approve_form("RESTART", targets=()))
        self.assertIn("no_action_targets", resp.json()["results"][0])
        self.assertEqual(self.docker_calls(), 0)

    def test_reject_still_records_and_does_not_execute(self):
        value = json.dumps({"alertname": "x", "action_type": "RESTART",
                            "action_targets": ["leafy-backend"]})
        form = "payload=" + urllib.parse.quote(json.dumps({
            "actions": [{"action_id": "reject_action", "value": value}],
            "user": {"name": "tester"}}))
        resp = self.post_slack(form)
        self.assertEqual(resp.json()["status"], "rejected")
        self.assertEqual(self.docker_calls(), 0)


class AuthRunsBeforePolicyTest(PolicyEndpointBase):
    """Phase 0 보존 — 인증을 통과하지 못한 요청은 정책 판단조차 하지 않는다."""

    def test_unauthenticated_action_makes_no_policy_decision(self):
        resp = self.client.post("/action", content=analysis_body("ISOLATE"),
                                headers={"Content-Type": "application/json"})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(self.decisions(), [])
        self.assertEqual(self.docker_calls(), 0)

    def test_unauthenticated_slack_approval_does_not_execute(self):
        resp = self.client.post(
            "/slack/action", content=slack_approve_form("RESTART").encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(self.docker_calls(), 0)


class DisabledModePolicyTest(PolicyEndpointBase):
    mode = "disabled"

    def test_policy_still_evaluated(self):
        resp = self.post_action(analysis_body("ISOLATE", llm_risk="low"))
        self.assertEqual(resp.json()["status"], "pending_approval")
        self.assertEqual(len(self.decisions()), 1)

    def test_approved_action_is_not_reported_as_success(self):
        resp = self.post_slack(slack_approve_form("RESTART"))
        results = resp.json()["results"]
        self.assertTrue(results[0].startswith("Skipped:"))
        self.assertNotIn("Success", results[0])
        executed = [e for _, e in self.events if e.get("event") == "manual_approval_executed"]
        self.assertEqual([e["status"] for e in executed], ["SKIPPED"])
        self.assertIsNone(self.main.container_actions)


class PolicyUnavailableTest(unittest.TestCase):
    """정책을 로드하지 못하면 모든 조치가 차단된다 (fail closed)."""

    def setUp(self):
        env = {"SLACK_WEBHOOK_URL": "", "REMEDIATION_MODE": "docker",
               "SLACK_SIGNING_SECRET": SLACK_SECRET, "REMEDIATION_API_KEY": API_KEY,
               "REMEDIATION_POLICY_PATH": "/definitely/not/here.yml"}
        import importlib
        for name in ("main", "actions.notify", "actions.container",
                     "policy.engine", "policy.schema"):
            sys.modules.pop(name, None)
        with mock.patch.dict(os.environ, env, clear=False):
            with mock.patch("docker.from_env") as from_env:
                self.main = importlib.import_module("main")
        self.from_env = from_env
        patcher = mock.patch.object(self.main, "_push_soc_event", side_effect=self._noop)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = TestClient(self.main.app)
        # 다음 테스트가 정상 정책으로 돌아오도록 모듈 캐시를 비운다
        self.addCleanup(lambda: [sys.modules.pop(n, None) for n in
                                 ("main", "policy.engine", "policy.schema")])

    async def _noop(self, job, event):
        return None

    def test_everything_is_blocked(self):
        ts = str(int(time.time()))
        body = analysis_body("ISOLATE", threat_level="critical", confidence=1.0)
        resp = self.client.post("/action", content=body, headers={
            service_auth.TIMESTAMP_HEADER: ts,
            service_auth.SIGNATURE_HEADER: signing.sign(API_KEY, ts, body),
            "Content-Type": "application/json"})
        self.assertEqual(resp.json()["status"], "blocked")
        self.assertTrue(resp.json()["reason"].startswith("policy_unavailable:"))
        self.assertEqual(self.from_env.return_value.containers.get.call_count, 0)

    def test_approval_is_blocked_too(self):
        form = slack_approve_form("RESTART").encode("utf-8")
        ts = str(int(time.time()))
        resp = self.client.post("/slack/action", content=form, headers={
            slack_signature.TIMESTAMP_HEADER: ts,
            slack_signature.SIGNATURE_HEADER: signing.sign(SLACK_SECRET, ts, form),
            "Content-Type": "application/x-www-form-urlencoded"})
        self.assertIn("policy_unavailable", resp.json()["results"][0])
        self.assertEqual(self.from_env.return_value.containers.get.call_count, 0)


if __name__ == "__main__":
    unittest.main()
