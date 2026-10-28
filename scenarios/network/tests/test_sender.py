"""
송신기 HTTP 전송 로직 테스트 (Step 2 / P1).

실제 Sink 서버를 띄워 send_payload 로 보내고, 모드별 동작과 Sink 수신 결과(바이트·해시)를
확인한다. DB/Docker 없이 전송 로직만 검증한다.

실행: cd scenarios/network && python -m unittest discover -s tests -v
"""

import hashlib
import os
import sys
import threading
import time
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "sink"))
sys.path.insert(0, os.path.join(HERE, "..", "sender"))

import sink_server  # noqa: E402
from send import _split_ranges, send_payload  # noqa: E402
from transfer_spec import TransferSpec  # noqa: E402


def _sink_stats(base):
    with urllib.request.urlopen(base + "/stats", timeout=5) as resp:
        import json
        return json.loads(resp.read())


class SenderTest(unittest.TestCase):
    def setUp(self):
        sink_server.STATE.reset()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), sink_server.Handler)
        self.host, self.port = self.server.server_address
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.payload = b"row,data\n" + b"x" * (512 * 1024)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        sink_server.STATE.reset()

    def test_single_transfer(self):
        spec = TransferSpec(target_bytes=len(self.payload), mode="single")
        receipts = send_payload(self.host, self.port, self.payload, spec, "t")
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["status"], 200)
        self.assertEqual(receipts[0]["bytes_sent"], len(self.payload))
        # 송신 sha == Sink 수신 sha (교차검증 기본)
        self.assertEqual(receipts[0]["sha256"], receipts[0]["sink_sha256"])
        self.assertEqual(receipts[0]["sha256"], hashlib.sha256(self.payload).hexdigest())

    def test_split_uses_multiple_connections(self):
        spec = TransferSpec(target_bytes=len(self.payload), mode="split", chunks=8)
        receipts = send_payload(self.host, self.port, self.payload, spec, "t")
        self.assertEqual(len(receipts), 8)
        # 분할 합계 == 전체 바이트 (누적 집계 검증의 전제)
        self.assertEqual(sum(r["bytes_sent"] for r in receipts), len(self.payload))
        stats = _sink_stats(self.base)
        self.assertEqual(stats["transfers"], 8)
        self.assertEqual(stats["total_bytes"], len(self.payload))

    def test_slow_mode_throttles(self):
        # 256KB 를 512KB/s 로 → 약 0.5s 이상 걸려야 한다 (연결이 길게 유지됨)
        payload = b"y" * (256 * 1024)
        spec = TransferSpec(target_bytes=len(payload), mode="slow", rate_bps=512 * 1024)
        start = time.monotonic()
        receipts = send_payload(self.host, self.port, payload, spec, "t")
        elapsed = time.monotonic() - start
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["bytes_sent"], len(payload))
        self.assertGreaterEqual(elapsed, 0.4)

    def test_split_ranges_partition(self):
        ranges = _split_ranges(1000, 7)
        self.assertEqual(ranges[0][0], 0)
        self.assertEqual(ranges[-1][1], 1000)
        self.assertEqual(sum(e - s for s, e in ranges), 1000)
        # 연속·비중첩
        for (s1, e1), (s2, e2) in zip(ranges, ranges[1:]):
            self.assertEqual(e1, s2)


if __name__ == "__main__":
    unittest.main()
