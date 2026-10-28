"""
Phase 0 인증 테스트 — 서명 모듈(순수 로직)과 송·수신 구현의 교차 검증.

엔드포인트 단위 검증은 test_endpoint_auth.py 가 담당한다.

실행 (remediation 디렉터리에서):
    python -m unittest discover -s tests -v
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from security import service_auth, signing, slack_signature  # noqa: E402
from security.replay import ReplayGuard  # noqa: E402

SECRET = "test-signing-secret"
BODY = b'{"alert":{"labels":{"alertname":"HighCpuUsage"}},"analysis":{"action_type":"RESTART"}}'


def load_pipeline_sender():
    """
    Pipeline 쪽 송신 구현을 파일 경로로 로드한다. 모듈 이름(security.service_auth)이
    remediation 쪽과 같아 import 경로로는 가려지므로, 별개 이름으로 올린다.
    """
    import importlib.util
    path = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "..", "pipeline", "security", "service_auth.py"))
    spec = importlib.util.spec_from_file_location("pipeline_service_auth", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _slack_headers(secret, body, ts=None, sig=None):
    ts = str(int(time.time())) if ts is None else str(ts)
    return {
        slack_signature.TIMESTAMP_HEADER: ts,
        slack_signature.SIGNATURE_HEADER: sig or signing.sign(secret, ts, body),
    }


class SigningTest(unittest.TestCase):
    def test_canonical_string_covers_whole_body(self):
        self.assertEqual(signing.canonical_string("123", b"abc"), b"v0:123:abc")

    def test_sign_is_deterministic_and_prefixed(self):
        a = signing.sign(SECRET, "123", BODY)
        self.assertEqual(a, signing.sign(SECRET, "123", BODY))
        self.assertTrue(a.startswith("v0="))
        self.assertEqual(len(a), 3 + 64)  # v0= + sha256 hex

    def test_valid_signature_passes(self):
        ts = "1700000000"
        sig = signing.sign(SECRET, ts, BODY)
        ok, reason = signing.verify(SECRET, ts, sig, BODY, now=1700000000)
        self.assertTrue(ok)
        self.assertEqual(reason, "ok")

    def test_body_tampering_is_rejected(self):
        ts = "1700000000"
        sig = signing.sign(SECRET, ts, BODY)
        ok, reason = signing.verify(SECRET, ts, sig, BODY + b" ", now=1700000000)
        self.assertFalse(ok)
        self.assertEqual(reason, "signature_mismatch")

    def test_wrong_key_is_rejected(self):
        ts = "1700000000"
        sig = signing.sign("other-key", ts, BODY)
        ok, reason = signing.verify(SECRET, ts, sig, BODY, now=1700000000)
        self.assertFalse(ok)
        self.assertEqual(reason, "signature_mismatch")

    def test_missing_pieces_are_rejected(self):
        ts = "1700000000"
        sig = signing.sign(SECRET, ts, BODY)
        self.assertEqual(signing.verify(SECRET, ts, None, BODY, now=1700000000)[1],
                         "missing_signature")
        self.assertEqual(signing.verify(SECRET, None, sig, BODY, now=1700000000)[1],
                         "missing_timestamp")
        self.assertEqual(signing.verify(SECRET, "nope", sig, BODY, now=1700000000)[1],
                         "invalid_timestamp")

    def test_expired_and_future_timestamps_are_rejected(self):
        ts = "1700000000"
        sig = signing.sign(SECRET, ts, BODY)
        # 5분 + 1초 지난 요청
        ok, reason = signing.verify(SECRET, ts, sig, BODY, now=1700000000 + 301)
        self.assertFalse(ok)
        self.assertEqual(reason, "timestamp_out_of_window")
        # 미래로 조작된 요청도 같은 창으로 거부
        ok, reason = signing.verify(SECRET, ts, sig, BODY, now=1700000000 - 301)
        self.assertFalse(ok)
        self.assertEqual(reason, "timestamp_out_of_window")
        # 창 안이면 통과
        self.assertTrue(signing.verify(SECRET, ts, sig, BODY, now=1700000000 + 299)[0])

    def test_missing_secret_fails_closed(self):
        ts = "1700000000"
        sig = signing.sign(SECRET, ts, BODY)
        for secret in (None, ""):
            ok, reason = signing.verify(secret, ts, sig, BODY, now=1700000000)
            self.assertFalse(ok)
            self.assertEqual(reason, "secret_not_configured")


class SlackVerifyTest(unittest.TestCase):
    def test_valid_request(self):
        ok, _ = slack_signature.verify_slack_request(BODY, _slack_headers(SECRET, BODY), SECRET)
        self.assertTrue(ok)

    def test_header_lookup_is_case_insensitive(self):
        ts = str(int(time.time()))
        headers = {
            "X-Slack-Request-Timestamp": ts,
            "X-Slack-Signature": signing.sign(SECRET, ts, BODY),
        }
        self.assertTrue(slack_signature.verify_slack_request(BODY, headers, SECRET)[0])

    def test_forged_signature(self):
        headers = _slack_headers(SECRET, BODY, sig="v0=" + "0" * 64)
        ok, reason = slack_signature.verify_slack_request(BODY, headers, SECRET)
        self.assertFalse(ok)
        self.assertEqual(reason, "signature_mismatch")

    def test_no_headers_at_all(self):
        ok, _ = slack_signature.verify_slack_request(BODY, {}, SECRET)
        self.assertFalse(ok)


class CrossImplementationTest(unittest.TestCase):
    """
    Pipeline(송신)과 Remediation(수신)은 이미지가 분리돼 코드를 공유할 수 없다.
    두 구현이 같은 서명을 만드는지 여기서 고정한다 — 규격 드리프트 방지.
    """

    def setUp(self):
        self.sender = load_pipeline_sender()

    def test_header_names_match(self):
        self.assertEqual(self.sender.TIMESTAMP_HEADER, service_auth.TIMESTAMP_HEADER)
        self.assertEqual(self.sender.SIGNATURE_HEADER, service_auth.SIGNATURE_HEADER)

    def test_sender_signature_verifies_on_receiver(self):
        headers = self.sender.build_headers("shared-key", BODY, now=1700000000)
        ok, reason = service_auth.verify_service_request(
            BODY, headers, "shared-key", now=1700000000)
        self.assertTrue(ok, reason)

    def test_sender_and_receiver_produce_same_digest(self):
        self.assertEqual(
            self.sender.sign("shared-key", "1700000000", BODY),
            signing.sign("shared-key", "1700000000", BODY),
        )


class ReplayGuardTest(unittest.TestCase):
    def test_same_signature_twice_is_rejected(self):
        g = ReplayGuard()
        self.assertTrue(g.remember("v0=abc", now=1000))
        self.assertFalse(g.remember("v0=abc", now=1000))

    def test_different_signatures_pass(self):
        g = ReplayGuard()
        self.assertTrue(g.remember("v0=a", now=1000))
        self.assertTrue(g.remember("v0=b", now=1000))

    def test_entry_expires_after_ttl(self):
        g = ReplayGuard(ttl_sec=300)
        self.assertTrue(g.remember("v0=abc", now=1000))
        # TTL 이 지나면 잊는다. 그 시점의 요청은 서명 타임스탬프 창에서 걸린다.
        self.assertTrue(g.remember("v0=abc", now=1000 + 301))

    def test_cache_is_bounded(self):
        g = ReplayGuard(max_entries=16)
        for i in range(64):
            g.remember(f"v0={i}", now=1000)
        self.assertLessEqual(len(g._seen), 16)


if __name__ == "__main__":
    unittest.main()
