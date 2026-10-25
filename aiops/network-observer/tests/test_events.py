"""
Enricher event builder 테스트 (P6) — Docker/YAML 없이 순수 함수만.

실행 (network-observer 디렉터리에서):
    PYTHONPATH=enricher python -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "enricher"))

from events import build_connection_event, build_threshold_event  # noqa: E402
from zeek_map import EVENT_TYPE_CONNECTION, EVENT_TYPE_THRESHOLD  # noqa: E402


class _Endpoint:
    def __init__(self, service, container, runtime, network):
        self.service, self.container, self.runtime, self.network = (
            service, container, runtime, network)


class _Resolver:
    """ip -> Endpoint 고정 매핑 (IdentityResolver 대역)."""
    def __init__(self, mapping):
        self._m = mapping

    def resolve(self, ip, port):
        return self._m.get(ip, _Endpoint("unknown", None, "unknown", None))

    def refresh(self, force=False):
        pass


RESOLVER = _Resolver({
    "10.210.0.5": _Endpoint("backend", "leafy-backend", "container", "leafy-net"),
    "10.210.0.31": _Endpoint("sink-b", "s2-sink-b", "container", "leafy-net"),
})
CAPTURE = {"logical_network": "leafy-net", "interface": "eth0"}
OBSERVER = {"name": "network-observer", "instance": None}

CONN_RECORD = {
    "ts": 1700000000.5, "uid": "CxYZ", "proto": "tcp",
    "id.orig_h": "10.210.0.5", "id.orig_p": 40000,
    "id.resp_h": "10.210.0.31", "id.resp_p": 8080,
    "conn_state": "SF", "duration": 2.0, "orig_bytes": 10485760, "resp_bytes": 200,
}
THRESHOLD_RECORD = {
    "ts": 1700000001.0, "uid": "CxYZ", "proto": "tcp",
    "id.orig_h": "10.210.0.5", "id.orig_p": 40000,
    "id.resp_h": "10.210.0.31", "id.resp_p": 8080,
    "orig_bytes": 1048576, "threshold": 1048576, "event_kind": "connection_threshold",
}


class EventBuilderTest(unittest.TestCase):
    def test_connection_event(self):
        e = build_connection_event(CONN_RECORD, RESOLVER, CAPTURE, OBSERVER)
        self.assertEqual(e["event_type"], EVENT_TYPE_CONNECTION)
        self.assertEqual(e["src_service"], "backend")
        self.assertEqual(e["dst_service"], "sink-b")
        self.assertEqual(e["dst_ip"], "10.210.0.31")
        self.assertEqual(e["dst_port"], 8080)
        self.assertEqual(e["bytes_sent"], 10485760)
        self.assertEqual(e["connection_id"], "CxYZ")
        self.assertEqual(e["connection_state"], "closed")  # SF -> closed

    def test_threshold_event(self):
        e = build_threshold_event(THRESHOLD_RECORD, RESOLVER, CAPTURE, OBSERVER)
        self.assertEqual(e["event_type"], EVENT_TYPE_THRESHOLD)
        self.assertEqual(e["src_service"], "backend")
        self.assertEqual(e["dst_service"], "sink-b")
        self.assertEqual(e["bytes_sent"], 1048576)        # 임계 도달 시점 누적 (최종값 아님)
        self.assertIsNone(e["bytes_received"])
        self.assertIsNone(e["duration_ms"])
        self.assertEqual(e["connection_state"], "established")  # 전송 중
        self.assertEqual(e["connection_id"], "CxYZ")           # 최종과 같은 uid
        self.assertEqual(e["observer_meta"]["bytes_threshold"], 1048576)

    def test_same_connection_id_different_event_type(self):
        # 조기/최종이 같은 connection_id 이지만 event_type 이 달라야 구분·중복집계방지 가능
        conn = build_connection_event(CONN_RECORD, RESOLVER, CAPTURE, OBSERVER)
        thr = build_threshold_event(THRESHOLD_RECORD, RESOLVER, CAPTURE, OBSERVER)
        self.assertEqual(conn["connection_id"], thr["connection_id"])
        self.assertNotEqual(conn["event_type"], thr["event_type"])

    def test_missing_tuple_returns_none(self):
        self.assertIsNone(build_connection_event({"ts": 1.0, "id.orig_h": "x"},
                                                 RESOLVER, CAPTURE, OBSERVER))
        self.assertIsNone(build_threshold_event({"ts": 1.0}, RESOLVER, CAPTURE, OBSERVER))


if __name__ == "__main__":
    unittest.main()
