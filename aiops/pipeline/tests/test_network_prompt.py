"""
#11 Network Context -> RCA 프롬프트 테스트.

실행 (pipeline 디렉터리에서):
    python -m unittest discover -s tests -v
"""

import os
import sys
import unittest
from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from collector.network import NetworkContext  # noqa: E402
from correlation import to_instant  # noqa: E402
from prompt import builder as builder_mod  # noqa: E402
from prompt.builder import MAX_PROMPT_CHARS, PromptBuilder  # noqa: E402
from prompt.network_section import NETWORK_MAX_CHARS, _RULES, build_network_section  # noqa: E402

START = to_instant("2026-10-04T04:55:00Z")
END = to_instant("2026-10-04T05:05:00Z")


def ev(src, dst, state="closed", sent=100, recv=200, dur=5, app=None, proto="tcp", i=0):
    return {"schema_version": "1.0", "timestamp": "2026-10-04T05:00:00.000Z", "src_service": src,
            "dst_service": dst, "protocol": proto, "app_protocol": app, "connection_state": state,
            "bytes_sent": sent, "bytes_received": recv, "duration_ms": dur, "connection_id": f"C{src}{dst}{i}"}


def nc(events=(), service="backend", errors=(), skipped=0, truncated=False):
    return NetworkContext(service=service, start=START, end=END, events=tuple(events),
                          errors=tuple(errors), skipped=skipped, truncated=truncated)


ALERT = SimpleNamespace(labels=SimpleNamespace(alertname="HighMemoryUsage", severity="warning"),
                        annotations={"container": "leafy-backend", "summary": "mem"}, startsAt="2026-10-04T05:00:00Z")
METRICS = {"memory_usage": [{"values": [{"v": 1.0}, {"v": 3.0}]}]}
LOGS = [{"ts": 1.0, "labels": {"container": "backend"}, "line": 'message="ERROR db timeout"'},
        {"ts": 2.0, "labels": {"container": "backend"}, "line": 'message="ok"'}]


class FlowSummaryTest(unittest.TestCase):
    def test_backend_both_flows_summarized(self):
        s = build_network_section(nc([
            ev("frontend", "backend", app="http", sent=183, recv=415, dur=1),
            ev("frontend", "backend", app="http", state="reset", sent=10, recv=0, dur=3, i=1),
            ev("backend", "db", sent=6, recv=11, dur=None, state="established"),
        ]))
        self.assertIn("3 connections in 2 flows", s)
        self.assertIn("- frontend -> backend tcp/http: conns=2 states[closed=1 reset=1] "
                      "bytes_sent=193 bytes_recv=415 duration_ms[avg=2 max=3]", s)
        # duration이 전부 없으면 n/a (0으로 만들지 않는다)
        self.assertIn("- backend -> db tcp: conns=1 states[established=1] "
                      "bytes_sent=6 bytes_recv=11 duration_ms[n/a]", s)

    def test_not_limited_to_known_service_pairs(self):
        s = build_network_section(nc([ev("minio", "redis", proto="udp")], service="minio"))
        self.assertIn("- minio -> redis udp: conns=1", s)

    def test_unknown_endpoint_kept(self):
        s = build_network_section(nc([ev("unknown", "frontend", state="timeout", sent=None, recv=None, dur=None)],
                                     service="frontend"))
        self.assertIn("- unknown -> frontend tcp: conns=1 states[timeout=1] bytes_sent=n/a bytes_recv=n/a", s)
        self.assertIn('"unknown" = endpoint identity could not be resolved', s)

    def test_flows_ordered_by_connection_count(self):
        s = build_network_section(nc([ev("a", "backend")] + [ev("backend", "z", i=i) for i in range(3)]))
        self.assertLess(s.index("backend -> z"), s.index("a -> backend"))


class ReliabilityTest(unittest.TestCase):
    def test_zero_events_is_not_no_traffic(self):
        s = build_network_section(nc([]))
        self.assertIn("0 network events recorded for backend", s)
        self.assertIn("This does NOT mean that traffic was absent or that the network was normal.", s)
        self.assertIn("query_complete=true", s)
        lowered = s.lower()
        for claim in ("no traffic", "network is healthy", "network healthy", "network is normal"):
            self.assertNotIn(claim, lowered)
        for rule in _RULES:  # 0건이어도 해석 규칙은 들어간다
            self.assertIn(rule, s)

    def test_incomplete_with_errors(self):
        err = '{log_type="network", dst_service="backend"}: ConnectError("x' + "y" * 300 + '")'
        s = build_network_section(nc([ev("backend", "db")], errors=[err, "second"]))
        self.assertIn("query_complete=false", s)
        self.assertIn("errors=2", s)
        self.assertIn("WARNING: network context is INCOMPLETE; some events may be missing.", s)
        self.assertIn("Collection error: " + err[:120] + " (+1 more)", s)
        self.assertNotIn("y" * 200, s)  # 긴 오류 문자열은 잘라서 넣는다

    def test_truncated(self):
        s = build_network_section(nc([ev("frontend", "backend")], truncated=True))
        self.assertIn("truncated=true", s)
        self.assertIn("Event limit reached: some events in this window are not included.", s)
        self.assertIn("INCOMPLETE", s)

    def test_skipped_reported(self):
        s = build_network_section(nc([ev("frontend", "backend")], skipped=4))
        self.assertIn("skipped=4", s)
        self.assertIn("4 malformed network events were ignored.", s)

    def test_supplementary_rule_present(self):
        s = build_network_section(nc([ev("frontend", "backend")]))
        self.assertIn("do not determine the root cause from network data alone", s)


class SizeLimitTest(unittest.TestCase):
    def test_many_events_bounded_and_rules_never_cut(self):
        events = [ev(f"svc{f:02d}", "backend", i=i) for f in range(40) for i in range(125)]  # 5000건, 40 flow
        s = build_network_section(nc(events, errors=["e" * 200], truncated=True, skipped=3))
        self.assertLessEqual(len(s), NETWORK_MAX_CHARS)
        for rule in _RULES:
            self.assertIn(rule, s)
        self.assertIn("INCOMPLETE", s)
        # 보여준 flow + 숨긴 flow의 connection 합이 전체와 맞는다
        shown = sum(int(line.split("conns=")[1].split()[0]) for line in s.splitlines() if line.startswith("- svc"))
        hidden_line = next(line for line in s.splitlines() if line.startswith("(+"))
        hidden = int(hidden_line.split(", ")[1].split()[0])
        self.assertEqual(shown + hidden, 5000)

    def test_max_flows(self):
        events = [ev(f"svc{f}", "backend", i=f) for f in range(20)]
        s = build_network_section(nc(events))
        self.assertLessEqual(sum(1 for line in s.splitlines() if line.startswith("- svc")), 8)
        self.assertIn("more flows", s)


class BuilderIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.b = PromptBuilder()
        self.old = self.b.build(ALERT, METRICS, LOGS, "leafy-backend")["user"]

    def test_existing_content_unchanged(self):
        network = nc([ev("frontend", "backend"), ev("backend", "db")])
        new = self.b.build(ALERT, METRICS, LOGS, "leafy-backend", network=network)["user"]
        section = build_network_section(network)
        self.assertEqual(new.replace("\n" + section, "", 1), self.old)
        # METRICS 다음, LOGS 앞
        self.assertLess(new.index("=== METRICS"), new.index("=== NETWORK CONTEXT"))
        self.assertLess(new.index("=== NETWORK COLLECTION STATUS"), new.index("=== LOGS"))

    def test_system_prompt_unchanged(self):
        p = self.b.build(ALERT, METRICS, LOGS, "leafy-backend", network=nc([ev("frontend", "backend")]))
        self.assertIs(p["system"], builder_mod.SYSTEM_PROMPT)

    def test_section_survives_existing_truncation(self):
        # builder는 줄당 200자, error 30 + 기타 20줄만 쓰므로 둘 다 채워야 기존 cap(6000)을 넘는다
        big_logs = [{"ts": float(i), "labels": {"container": "backend"},
                     "line": ("message=ERROR " if i % 2 else "message=") + "x" * 300} for i in range(60)]
        old = self.b.build(ALERT, METRICS, big_logs, "leafy-backend")["user"]
        self.assertTrue(old.endswith("...(truncated)"))
        network = nc([ev("frontend", "backend")])
        new = self.b.build(ALERT, METRICS, big_logs, "leafy-backend", network=network)["user"]
        section = build_network_section(network)
        self.assertIn(section, new)  # 해석 규칙까지 통째로 남는다
        self.assertEqual(new.replace("\n" + section, "", 1), old)
        self.assertLessEqual(len(new), MAX_PROMPT_CHARS + len("\n...(truncated)") + 1 + NETWORK_MAX_CHARS)

    def test_no_network_is_identical_to_before(self):
        self.assertEqual(self.b.build(ALERT, METRICS, LOGS, "leafy-backend", network=None)["user"], self.old)
        unresolved = nc([], service=None)
        self.assertEqual(self.b.build(ALERT, METRICS, LOGS, "leafy-backend", network=unresolved)["user"], self.old)

    def test_summary_failure_falls_back_to_existing_prompt(self):
        with mock.patch.object(builder_mod, "build_network_section", side_effect=RuntimeError("boom")):
            p = self.b.build(ALERT, METRICS, LOGS, "leafy-backend", network=nc([ev("frontend", "backend")]))
        self.assertEqual(p["user"], self.old)

    def test_retrieval_failure_context_still_builds(self):
        # #10이 실패를 errors로 돌려준 경우: 섹션은 불완전 표시, 기존 로그/메트릭은 그대로
        failed = nc([], errors=["src: ConnectError", "dst: ConnectError"])
        new = self.b.build(ALERT, METRICS, LOGS, "leafy-backend", network=failed)["user"]
        self.assertIn("INCOMPLETE", new)
        self.assertIn('message="ERROR db timeout"', new)
        self.assertIn("memory_usage: latest=3.0000, peak=3.0000", new)


if __name__ == "__main__":
    unittest.main()
