"""
Phase 0 엔드포인트 인증 테스트.

핵심 단정: **인증이 실패하면 Docker 호출이 0회다.** 서명 검증은 조치 코드보다
앞에 있으므로, 거부된 요청은 ContainerActions 에 닿지 않아야 한다.

Docker 데몬은 쓰지 않는다 — docker.from_env 를 Mock 으로 두고 호출 횟수를 센다.
실제 컨테이너 조치·Slack 발송은 일어나지 않는다.

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

SLACK_SECRET = "slack-signing-secret"
API_KEY = "remediation-shared-key"

# action_risk=low + confidence>=0.7 → 기존 자동 실행 경로 (조치가 실제로 호출되는 경로)
AUTO_EXEC_BODY = json.dumps({
    "alert": {"labels": {"alertname": "HighCpuUsage"}},
    "analysis": {"action_type": "RESTART", "action_targets": ["leafy-backend"],
                 "action_risk": "low", "threat_level": "high", "confidence": 0.9},
}, ensure_ascii=False).encode("utf-8")

SLACK_APPROVE_FORM = "payload=" + urllib.parse.quote(json.dumps({
    "actions": [{"action_id": "approve_action", "value": json.dumps({
        "alertname": "HighCpuUsage", "action_type": "RESTART",
        "action_targets": ["leafy-backend"]})}],
    "user": {"name": "tester"},
}))


def load_main(mode="docker", slack_secret=SLACK_SECRET, api_key=API_KEY):
    """환경변수는 import 시점에 읽으므로 모듈을 새로 import 한다."""
    env = {
        "SLACK_WEBHOOK_URL": "",
        "REMEDIATION_MODE": mode,
        "SLACK_SIGNING_SECRET": slack_secret,
        "REMEDIATION_API_KEY": api_key,
    }
    for name in ("main", "actions.notify", "actions.container"):
        sys.modules.pop(name, None)
    with mock.patch.dict(os.environ, env, clear=False):
        with mock.patch("docker.from_env") as from_env:
            module = importlib.import_module("main")
    return module, from_env


class AuthTestBase(unittest.TestCase):
    mode = "docker"
    slack_secret = SLACK_SECRET
    api_key = API_KEY

    def setUp(self):
        self.main, self.from_env = load_main(self.mode, self.slack_secret, self.api_key)
        self.events = []
        patcher = mock.patch.object(self.main, "_push_soc_event", side_effect=self._record)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = TestClient(self.main.app)

    async def _record(self, job, event):
        self.events.append((job, event))

    # ── 헬퍼 ──────────────────────────────────────────────
    def docker_calls(self) -> int:
        """ContainerActions 가 Docker 클라이언트를 건드린 횟수."""
        return self.from_env.return_value.containers.get.call_count

    def post_action(self, body=AUTO_EXEC_BODY, headers=None, key=None, ts=None):
        if headers is None:
            ts = str(int(time.time())) if ts is None else str(ts)
            headers = {
                service_auth.TIMESTAMP_HEADER: ts,
                service_auth.SIGNATURE_HEADER: signing.sign(key or self.api_key, ts, body),
            }
        headers = {**headers, "Content-Type": "application/json"}
        return self.client.post("/action", content=body, headers=headers)

    def post_slack(self, form=SLACK_APPROVE_FORM, headers=None, secret=None, ts=None):
        body = form.encode("utf-8")
        if headers is None:
            ts = str(int(time.time())) if ts is None else str(ts)
            headers = {
                slack_signature.TIMESTAMP_HEADER: ts,
                slack_signature.SIGNATURE_HEADER: signing.sign(
                    secret or self.slack_secret, ts, body),
            }
        headers = {**headers, "Content-Type": "application/x-www-form-urlencoded"}
        return self.client.post("/slack/action", content=body, headers=headers)

    def denied_reasons(self):
        return [e["reason"] for _, e in self.events if e.get("event") == "auth_denied"]


class ActionEndpointAuthTest(AuthTestBase):
    def test_valid_signature_passes_and_executes(self):
        resp = self.post_action()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "executed")
        self.assertEqual(self.docker_calls(), 1)

    def test_no_signature_is_denied_and_docker_untouched(self):
        resp = self.post_action(headers={})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(self.docker_calls(), 0)
        self.assertIn("missing_signature", self.denied_reasons())

    def test_forged_signature(self):
        ts = str(int(time.time()))
        resp = self.post_action(headers={
            service_auth.TIMESTAMP_HEADER: ts,
            service_auth.SIGNATURE_HEADER: "v0=" + "0" * 64,
        })
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(self.docker_calls(), 0)
        self.assertIn("signature_mismatch", self.denied_reasons())

    def test_wrong_api_key(self):
        resp = self.post_action(key="wrong-key")
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(self.docker_calls(), 0)
        self.assertIn("signature_mismatch", self.denied_reasons())

    def test_expired_timestamp(self):
        resp = self.post_action(ts=int(time.time()) - 400)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(self.docker_calls(), 0)
        self.assertIn("timestamp_out_of_window", self.denied_reasons())

    def test_tampered_body_after_signing(self):
        ts = str(int(time.time()))
        headers = {
            service_auth.TIMESTAMP_HEADER: ts,
            service_auth.SIGNATURE_HEADER: signing.sign(self.api_key, ts, AUTO_EXEC_BODY),
        }
        # 대상 컨테이너를 leafy-db 로 바꿔치기한 본문
        tampered = AUTO_EXEC_BODY.replace(b"leafy-backend", b"leafy-db\x20\x20\x20\x20\x20")
        resp = self.post_action(body=tampered, headers=headers)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(self.docker_calls(), 0)

    def test_replayed_request_executes_only_once(self):
        ts = str(int(time.time()))
        headers = {
            service_auth.TIMESTAMP_HEADER: ts,
            service_auth.SIGNATURE_HEADER: signing.sign(self.api_key, ts, AUTO_EXEC_BODY),
        }
        first = self.post_action(headers=headers)
        second = self.post_action(headers=headers)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 401)
        self.assertEqual(self.docker_calls(), 1)
        self.assertIn("replayed_signature", self.denied_reasons())


class SlackEndpointAuthTest(AuthTestBase):
    def test_valid_signature_passes_and_executes(self):
        resp = self.post_slack()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "approved")
        self.assertEqual(self.docker_calls(), 1)

    def test_no_signature_is_denied_and_docker_untouched(self):
        resp = self.post_slack(headers={})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"], "unauthorized")
        self.assertEqual(self.docker_calls(), 0)
        self.assertIn("missing_signature", self.denied_reasons())

    def test_forged_signature(self):
        ts = str(int(time.time()))
        resp = self.post_slack(headers={
            slack_signature.TIMESTAMP_HEADER: ts,
            slack_signature.SIGNATURE_HEADER: "v0=" + "f" * 64,
        })
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(self.docker_calls(), 0)

    def test_wrong_signing_secret(self):
        resp = self.post_slack(secret="not-the-slack-secret")
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(self.docker_calls(), 0)

    def test_expired_timestamp(self):
        resp = self.post_slack(ts=int(time.time()) - 400)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(self.docker_calls(), 0)
        self.assertIn("timestamp_out_of_window", self.denied_reasons())

    def test_replayed_approval_executes_only_once(self):
        ts = str(int(time.time()))
        headers = {
            slack_signature.TIMESTAMP_HEADER: ts,
            slack_signature.SIGNATURE_HEADER: signing.sign(
                self.slack_secret, ts, SLACK_APPROVE_FORM.encode("utf-8")),
        }
        first = self.post_slack(headers=headers)
        second = self.post_slack(headers=headers)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 401)
        self.assertEqual(self.docker_calls(), 1)

    def test_repeat_click_still_executes_known_gap(self):
        """
        같은 사람이 승인 버튼을 두 번 누르면 Slack 은 타임스탬프가 다른 별개 요청을
        보내므로 둘 다 유효한 서명이다 → 두 번 실행된다.

        Phase 0 은 '위조·리플레이'를 막는 범위이고, 이 중복은 조치 레코드
        (remediation_id) 단위 멱등성이 필요해 Phase 2 범위다. 현재 동작을 여기에
        고정해 두고, 멱등성 구현 시 이 테스트를 뒤집는다.
        """
        now = int(time.time())
        self.assertEqual(self.post_slack(ts=now).status_code, 200)
        self.assertEqual(self.post_slack(ts=now - 1).status_code, 200)
        self.assertEqual(self.docker_calls(), 2)


class MissingSecretFailsClosedTest(unittest.TestCase):
    """키가 설정되지 않으면 '인증 없이 통과'가 아니라 '전부 거부'다."""

    def _client(self, slack_secret, api_key):
        main, from_env = load_main("docker", slack_secret, api_key)
        patcher = mock.patch.object(main, "_push_soc_event", side_effect=self._noop)
        patcher.start()
        self.addCleanup(patcher.stop)
        return main, from_env, TestClient(main.app)

    async def _noop(self, job, event):
        return None

    def test_action_denied_without_api_key(self):
        main, from_env, client = self._client(SLACK_SECRET, "")
        ts = str(int(time.time()))
        # 공격자가 빈 키로 "올바르게" 서명해도 통과하지 않는다
        resp = client.post("/action", content=AUTO_EXEC_BODY, headers={
            service_auth.TIMESTAMP_HEADER: ts,
            service_auth.SIGNATURE_HEADER: signing.sign("", ts, AUTO_EXEC_BODY),
            "Content-Type": "application/json",
        })
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(from_env.return_value.containers.get.call_count, 0)

    def test_slack_denied_without_signing_secret(self):
        main, from_env, client = self._client("", API_KEY)
        body = SLACK_APPROVE_FORM.encode("utf-8")
        ts = str(int(time.time()))
        resp = client.post("/slack/action", content=body, headers={
            slack_signature.TIMESTAMP_HEADER: ts,
            slack_signature.SIGNATURE_HEADER: signing.sign("", ts, body),
            "Content-Type": "application/x-www-form-urlencoded",
        })
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(from_env.return_value.containers.get.call_count, 0)

    def test_health_stays_open(self):
        """/health 는 인증 대상이 아니다 — compose healthcheck·운영 점검용."""
        main, _, client = self._client("", "")
        self.assertEqual(client.get("/health").status_code, 200)


class DisabledModeAuthTest(AuthTestBase):
    """REMEDIATION_MODE=disabled 에서도 인증은 똑같이 요구된다."""

    mode = "disabled"

    def test_unauthenticated_is_denied(self):
        self.assertEqual(self.post_action(headers={}).status_code, 401)
        self.assertEqual(self.post_slack(headers={}).status_code, 401)

    def test_authenticated_still_skips_execution(self):
        body = self.post_action().json()
        self.assertEqual(body["status"], "skipped")
        self.assertTrue(body["results"][0].startswith("Skipped:"))
        self.assertIsNone(self.main.container_actions)


class PipelineCompatibilityTest(AuthTestBase):
    """
    Pipeline 이 실제로 만드는 요청이 그대로 통과하는지 — 송신측 구현을 직접 import 해
    헤더를 만든다. 규격 문서가 아니라 코드끼리 맞춰 본다.
    """

    def setUp(self):
        super().setUp()
        from test_service_auth import load_pipeline_sender
        self.sender = load_pipeline_sender()

    def test_pipeline_signed_request_is_accepted(self):
        headers = self.sender.build_headers(API_KEY, AUTO_EXEC_BODY)
        resp = self.client.post("/action", content=AUTO_EXEC_BODY, headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "executed")
        self.assertEqual(self.docker_calls(), 1)

    def test_pipeline_headers_include_content_type(self):
        headers = self.sender.build_headers(API_KEY, AUTO_EXEC_BODY)
        self.assertEqual(headers["Content-Type"], "application/json")


if __name__ == "__main__":
    unittest.main()
