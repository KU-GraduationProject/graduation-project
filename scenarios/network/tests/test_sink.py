"""
Sink 수신 서버 테스트 (P2).

실행 (scenarios/network 디렉터리에서):
    python -m unittest discover -s tests -v

실제 TCP로 서버를 띄워 POST 하고, 수신 바이트/해시/집계/초기화를 확인한다.
"""

import hashlib
import json
import os
import sys
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sink"))

import sink_server  # noqa: E402


def _post(base, data, transfer_id=None):
    headers = {"Content-Type": "application/octet-stream"}
    if transfer_id:
        headers["X-Transfer-Id"] = transfer_id
    req = urllib.request.Request(base, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


def _get(base, path):
    with urllib.request.urlopen(base + path, timeout=5) as resp:
        return json.loads(resp.read())


def _delete(base, path):
    req = urllib.request.Request(base + path, method="DELETE")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


class SinkServerTest(unittest.TestCase):
    def setUp(self):
        sink_server.STATE.reset()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), sink_server.Handler)
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        sink_server.STATE.reset()

    def test_records_bytes_and_hash(self):
        payload = b"hello-exfil-" * 1000
        result = _post(self.base + "/", payload, transfer_id="t-1")
        self.assertTrue(result["ok"])
        self.assertEqual(result["bytes_received"], len(payload))
        self.assertEqual(result["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(result["transfer_id"], "t-1")

    def test_large_body_streamed(self):
        # 10MB 본문도 스트리밍으로 정확히 집계하는지 (메모리에 통째로 올리지 않는 경로)
        payload = os.urandom(10 * 1024 * 1024)
        result = _post(self.base + "/", payload)
        self.assertEqual(result["bytes_received"], len(payload))
        self.assertEqual(result["sha256"], hashlib.sha256(payload).hexdigest())

    def test_stats_aggregate_and_reset(self):
        _post(self.base + "/", b"a" * 100)
        _post(self.base + "/", b"b" * 250)
        stats = _get(self.base, "/stats")
        self.assertEqual(stats["transfers"], 2)
        self.assertEqual(stats["total_bytes"], 350)
        self.assertEqual(len(stats["receipts"]), 2)

        _delete(self.base, "/stats")
        stats = _get(self.base, "/stats")
        self.assertEqual(stats["transfers"], 0)
        self.assertEqual(stats["total_bytes"], 0)

    def test_two_sinks_same_payload_same_hash(self):
        # S2/C-a 핵심: 같은 payload면 두 Sink 수신 해시가 같아야 한다(E 교차검증).
        payload = b"identical-transfer-body" * 5000
        r1 = _post(self.base + "/", payload)
        # 같은 서버에 두 번 보내도 해시는 동일 — A/B가 같은 코드이므로 결과가 같음을 대리 검증
        r2 = _post(self.base + "/", payload)
        self.assertEqual(r1["sha256"], r2["sha256"])


if __name__ == "__main__":
    unittest.main()
