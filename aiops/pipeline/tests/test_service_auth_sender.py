"""
Pipeline → Remediation /action 서명 (송신측) 테스트.

Remediation 이 /action 에 HMAC 서명을 요구하므로, 송신측은 전송할 본문 바이트
그대로를 서명해야 한다. 수신측 검증은 aiops/remediation/tests 가 담당한다.

실행 (pipeline 디렉터리에서):
    python -m unittest discover -s tests -v
"""

import asyncio
import hashlib
import hmac
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import main  # noqa: E402
from security.service_auth import SIGNATURE_HEADER, TIMESTAMP_HEADER, build_headers, sign  # noqa: E402

API_KEY = "shared-key"


def _alert():
    return main.Alert(
        status="firing",
        labels=main.AlertLabel(alertname="UnauthorizedDataTransfer", container="leafy-backend"),
        startsAt="2026-10-28T14:16:29Z",
        annotations={"container": "leafy-backend"},
    )


def _result():
    return main.LLMAnalysisResult(
        root_cause="unauthorized transfer",
        action_type="ISOLATE",
        action_targets=["leafy-backend"],
        threat_level="high",
        confidence=0.9,
    )


class SignTest(unittest.TestCase):
    def test_signature_matches_manual_hmac(self):
        body = b'{"a":1}'
        expected = "v0=" + hmac.new(
            API_KEY.encode(), b"v0:1700000000:" + body, hashlib.sha256).hexdigest()
        self.assertEqual(sign(API_KEY, "1700000000", body), expected)

    def test_build_headers_shape(self):
        h = build_headers(API_KEY, b"{}", now=1700000000)
        self.assertEqual(h[TIMESTAMP_HEADER], "1700000000")
        self.assertTrue(h[SIGNATURE_HEADER].startswith("v0="))
        self.assertEqual(h["Content-Type"], "application/json")

    def test_body_change_changes_signature(self):
        self.assertNotEqual(sign(API_KEY, "1", b'{"t":"leafy-backend"}'),
                            sign(API_KEY, "1", b'{"t":"leafy-db"}'))


class ForwardToRemediationTest(unittest.TestCase):
    """서명한 본문과 전송한 본문이 같은지 — 다르면 수신측에서 전부 거부된다."""

    def _post_calls(self, api_key):
        posted = {}

        class FakeClient:
            async def __aenter__(self_inner):
                return self_inner

            async def __aexit__(self_inner, *exc):
                return False

            async def post(self_inner, url, content=None, headers=None, **kw):
                posted.update(url=url, content=content, headers=headers, kw=kw)

        with mock.patch.object(main.settings, "remediation_api_key", api_key), \
             mock.patch.object(main.httpx, "AsyncClient", return_value=FakeClient()):
            asyncio.run(main.forward_to_remediation(_alert(), _result()))
        return posted

    def test_signed_body_equals_sent_body(self):
        posted = self._post_calls(API_KEY)
        body = posted["content"]
        self.assertIsInstance(body, bytes)
        ts = posted["headers"][TIMESTAMP_HEADER]
        self.assertEqual(posted["headers"][SIGNATURE_HEADER], sign(API_KEY, ts, body))

    def test_sent_body_is_valid_action_payload(self):
        posted = self._post_calls(API_KEY)
        payload = json.loads(posted["content"].decode("utf-8"))
        self.assertEqual(set(payload), {"alert", "analysis"})
        self.assertEqual(payload["analysis"]["action_type"], "ISOLATE")
        self.assertEqual(payload["alert"]["labels"]["alertname"], "UnauthorizedDataTransfer")

    def test_url_unchanged(self):
        posted = self._post_calls(API_KEY)
        self.assertTrue(posted["url"].endswith("/action"))

    def test_missing_key_skips_forwarding(self):
        """
        키가 없으면 전송하지 않는다. 서명 없는 요청은 수신측이 거부하므로 보내 봐야
        의미가 없고, '인증 없이 보내는' 우회 경로를 만들지 않는다.
        """
        posted = self._post_calls("")
        self.assertEqual(posted, {})


if __name__ == "__main__":
    unittest.main()
