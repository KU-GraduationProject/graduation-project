"""
Network Context P4 개선 테스트 — 목적지 IP:포트, Allowlist 위반, 조기 신호, 중복집계 방지.

실행 (pipeline 디렉터리에서): python -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from collector.network import NetworkContext  # noqa: E402
from correlation import to_instant  # noqa: E402
from policy.allowlist import PolicyEvaluator  # noqa: E402
from prompt.network_section import build_network_section  # noqa: E402

START = to_instant("2026-10-25T04:55:00Z")
END = to_instant("2026-10-25T05:05:00Z")

POLICY = PolicyEvaluator.from_dict({
    "version": 1, "sources": ["backend"],
    "allow": [
        {"service": "sink-a", "match": "endpoint", "ip": "10.210.0.30", "port": 8080},
        {"service": "db", "match": "service"},
    ],
    "thresholds": {"min_transfer_bytes": 1048576, "window": "5m"},
})


def ev(**o):
    e = {"schema_version": "1.0", "timestamp": "2026-10-25T05:00:00.000Z",
         "event_type": "connection", "src_service": "backend", "dst_service": "sink-b",
         "dst_ip": "10.210.0.31", "dst_port": 8080, "protocol": "tcp", "app_protocol": None,
         "connection_state": "closed", "bytes_sent": 100, "bytes_received": 0,
         "duration_ms": 5, "connection_id": "C0", "observer_meta": None}
    e.update(o)
    return e


def nc(events):
    return NetworkContext(service="backend", start=START, end=END, events=tuple(events))


class P4Test(unittest.TestCase):
    def test_distinct_endpoints_not_merged(self):
        # 같은 src/dst_service/proto 라도 dst_ip 가 다르면 별도 flow
        s = build_network_section(nc([
            ev(dst_ip="10.210.0.31", connection_id="a"),
            ev(dst_ip="10.210.0.32", connection_id="b"),
        ]))
        self.assertIn("2 flows", s)
        self.assertIn("dst=10.210.0.31:8080", s)
        self.assertIn("dst=10.210.0.32:8080", s)

    def test_allowlist_violation_and_ok(self):
        s = build_network_section(nc([
            ev(dst_service="sink-b", dst_ip="10.210.0.31", dst_port=8080, connection_id="x"),
            ev(dst_service="sink-a", dst_ip="10.210.0.30", dst_port=8080, connection_id="y"),
        ]), policy=POLICY)
        self.assertIn("allowlist=VIOLATION", s)   # 비인가 sink-b
        self.assertIn("allowlist=ok", s)           # 인가 sink-a
        # 정상 전송에 공격 단정 라벨을 넣지 않는다
        self.assertNotIn("[ATTACK]", s)

    def test_early_threshold_excluded_from_bytes(self):
        # 최종(10MB) + 조기(1MB) 같은 연결 -> bytes_sent=10485760 (11534336 아님), conns=1, early 표기
        s = build_network_section(nc([
            ev(event_type="connection", bytes_sent=10485760, connection_id="C1"),
            ev(event_type="connection_threshold", bytes_sent=1048576, connection_id="C1",
               timestamp="2026-10-25T05:00:01.000Z",
               observer_meta={"zeek_uid": "C1", "bytes_threshold": 1048576}),
        ]))
        self.assertIn("conns=1", s)
        self.assertIn("bytes_sent=10485760", s)
        self.assertNotIn("bytes_sent=11534336", s)   # 조기 바이트를 더하지 않는다
        self.assertIn("early=1@2026-10-25T05:00:01.000Z", s)
        self.assertIn(">=1048576B", s)

    def test_threshold_only_flow_shows_early(self):
        # 최종 이벤트가 아직 없고 조기 이벤트만 있는 진행중 전송
        s = build_network_section(nc([
            ev(event_type="connection_threshold", bytes_sent=1048576, connection_id="C2",
               observer_meta={"zeek_uid": "C2", "bytes_threshold": 1048576}),
        ]))
        self.assertIn("conns=0", s)
        self.assertIn("early=1", s)

    def test_no_policy_keeps_base_format(self):
        # policy 미제공 시 flow 줄에는 allowlist 표기가 없다 (해석 규칙 텍스트엔 있음)
        s = build_network_section(nc([ev()]))
        # flow 영역(수집 상태 헤더 이전)의 flow 줄만 검사한다
        flows_part = s.split("=== NETWORK COLLECTION STATUS ===")[0]
        flow_lines = [ln for ln in flows_part.splitlines() if ln.startswith("- ")]
        self.assertTrue(flow_lines)
        for ln in flow_lines:
            self.assertNotIn("allowlist=", ln)
        self.assertIn("dst=10.210.0.31:8080", s)


if __name__ == "__main__":
    unittest.main()
