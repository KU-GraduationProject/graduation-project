"""
NetworkCollector dedup — 조기(threshold)/최종(connection) 이벤트 구분 (P6).

같은 connection_id 라도 event_type 이 다르면 둘 다 보존해야 하고, 완전히 같은
이벤트(두 selector 중복)만 제거해야 한다. 바이트 중복 집계 방지는 소비자 몫이다.

실행 (pipeline 디렉터리에서): python -m unittest discover -s tests -v
"""

import os
import sys
import unittest
from datetime import timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json  # noqa: E402

from collector.network import NetworkCollector  # noqa: E402
from correlation import CorrelationContext, to_instant  # noqa: E402

ANCHOR = "2026-10-25T05:00:00Z"


def ctx():
    a = to_instant(ANCHOR)
    return CorrelationContext(service="backend", start=a - timedelta(minutes=5),
                              end=a + timedelta(minutes=5), anchor=a)


def ev(event_type, cid, bytes_sent, ts=ANCHOR):
    return json.dumps({
        "schema_version": "1.0", "timestamp": ts, "event_type": event_type,
        "observer": "network-observer",
        "src_service": "backend", "src_container": "leafy-backend", "src_runtime": "container",
        "src_ip": "10.210.0.5", "src_port": 40000,
        "dst_service": "sink-b", "dst_container": "s2-sink-b", "dst_runtime": "container",
        "dst_ip": "10.210.0.31", "dst_port": 8080,
        "protocol": "tcp", "network": "leafy-net", "interface": "eth0", "app_protocol": None,
        "connection_state": "closed", "duration_ms": 1,
        "bytes_sent": bytes_sent, "bytes_received": 0,
        "connection_id": cid, "request_id": None,
        "observer_instance": None, "observer_meta": {"zeek_uid": cid},
    })


class CollectorDedupTest(unittest.TestCase):
    def setUp(self):
        self.c = NetworkCollector("http://loki.invalid")

    def test_threshold_and_final_both_kept(self):
        lines = [
            ev("connection_threshold", "CxYZ", 1048576),
            ev("connection", "CxYZ", 10485760),
        ]
        events, skipped = self.c._parse(lines, ctx())
        self.assertEqual(len(events), 2)
        self.assertEqual(skipped, 0)
        kinds = {e["event_type"] for e in events}
        self.assertEqual(kinds, {"connection", "connection_threshold"})

    def test_true_duplicate_collapsed(self):
        # 같은 event_type + connection_id 인 완전 중복은 1건으로
        lines = [ev("connection", "CxYZ", 10485760), ev("connection", "CxYZ", 10485760)]
        events, _ = self.c._parse(lines, ctx())
        self.assertEqual(len(events), 1)


if __name__ == "__main__":
    unittest.main()
