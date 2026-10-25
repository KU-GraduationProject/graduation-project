"""
오케스트레이터 순수 로직 테스트 (Step 2) — env 구성·로그 파싱·교차검증.

실행: cd scenarios/network && python -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from orchestrator import build_sender_env, crosscheck, parse_sender_meta  # noqa: E402
from transfer_spec import Destination, build_pair  # noqa: E402

SINK_A = Destination(name="sink-a", ip="10.210.0.30", port=8080, host="sink-a")
SINK_B = Destination(name="sink-b", ip="10.210.0.31", port=8080, host="sink-b")


class OrchestratorTest(unittest.TestCase):
    def test_env_has_no_ground_truth_and_carries_password(self):
        run = build_pair("V1", SINK_A, SINK_B)["S2"]
        env = build_sender_env(run, db_password="secret-pw", transfer_id="tid-1")
        # GT 라벨은 사이드카 env 에 절대 들어가면 안 된다
        joined = " ".join(f"{k}={v}" for k, v in env.items())
        self.assertNotIn("should_alert", joined)
        self.assertNotIn("True", [str(v) for v in env.values()])  # GT bool 누출 없음
        # 목적지·전송조건은 전달된다
        self.assertEqual(env["SINK_HOST"], "sink-b")
        self.assertEqual(env["MODE"], "split")
        self.assertEqual(env["CHUNKS"], "8")
        self.assertEqual(env["DB_PASSWORD"], "secret-pw")

    def test_env_slow_includes_rate(self):
        run = build_pair("V2", SINK_A, SINK_B)["C-a"]
        env = build_sender_env(run, db_password="x", transfer_id="t")
        self.assertIn("RATE_BPS", env)
        self.assertEqual(env["SINK_HOST"], "sink-a")

    def test_parse_sender_meta(self):
        logs = (
            "some log line\n"
            'SENDER_META {"run_label":"S2-V1","connections":[],"total_bytes_sent":10}\n'
            "trailing\n"
        )
        meta = parse_sender_meta(logs)
        self.assertEqual(meta["run_label"], "S2-V1")
        self.assertEqual(meta["total_bytes_sent"], 10)

    def test_parse_sender_meta_missing(self):
        with self.assertRaises(ValueError):
            parse_sender_meta("no meta here\n")

    def test_crosscheck_match(self):
        sender = {
            "total_bytes_sent": 300,
            "connections": [
                {"transfer_id": "t-0", "bytes_sent": 100, "sha256": "aa"},
                {"transfer_id": "t-1", "bytes_sent": 200, "sha256": "bb"},
            ],
        }
        sink = {
            "total_bytes": 300,
            "receipts": [
                {"transfer_id": "t-0", "bytes_received": 100, "sha256": "aa"},
                {"transfer_id": "t-1", "bytes_received": 200, "sha256": "bb"},
            ],
        }
        result = crosscheck(sender, sink)
        self.assertTrue(result["ok"])
        self.assertEqual(result["total_bytes_sent"], result["total_bytes_received"])

    def test_crosscheck_hash_mismatch(self):
        sender = {"total_bytes_sent": 100,
                  "connections": [{"transfer_id": "t-0", "bytes_sent": 100, "sha256": "aa"}]}
        sink = {"total_bytes": 100,
                "receipts": [{"transfer_id": "t-0", "bytes_received": 100, "sha256": "ZZ"}]}
        result = crosscheck(sender, sink)
        self.assertFalse(result["ok"])
        self.assertFalse(result["connections"][0]["sha_match"])

    def test_crosscheck_missing_receipt(self):
        sender = {"total_bytes_sent": 100,
                  "connections": [{"transfer_id": "t-0", "bytes_sent": 100, "sha256": "aa"}]}
        sink = {"total_bytes": 0, "receipts": []}
        result = crosscheck(sender, sink)
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
