"""pipeline 컨텍스트 저장 → 실행 기록과 짝짓기 → 픽스처 → 하네스 build_inputs 왕복.

실행 (aiops 디렉터리에서):
    python -m unittest discover -s eval/tests -t . -v
"""
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from eval import harness  # pipeline·scenarios 경로를 sys.path 에 넣는다
from capture import build_context, save_context
from collector.network import NetworkContext
from collector.rules import RuleContext
from identity import LogEvidence, MetricEvidence
from prompt.builder import make_builder
from v2 import fixtures

T0 = datetime(2026, 11, 1, 5, 10, 0, tzinfo=timezone.utc)
RECEIVED = T0 + timedelta(seconds=20)


def _alert():
    labels = SimpleNamespace(alertname="AuthFailureBurst", severity="warning",
                             model_dump=lambda exclude_none=True: {"alertname": "AuthFailureBurst", "severity": "warning"})
    return SimpleNamespace(status="firing", labels=labels, annotations={"container": "leafy-backend"},
                           startsAt="2026-11-01T05:10:00Z", endsAt=None, fingerprint="abc")


def _context():
    rule = RuleContext(name="AuthFailureBurst", source="loki",
                       expr='sum(count_over_time({service="backend"} |= "Login failed" [2m])) > 5',
                       for_seconds=0, range_seconds=120, ranges=("2m",), conditions=((">", 5.0),), value=12)
    logs = LogEvidence([{"ts": T0.timestamp() - i, "labels": {"service": "backend"},
                         "line": f"WARN Login failed for user test password=secret{i}"} for i in range(5)], status="ok")
    metrics = MetricEvidence({"cpu_usage": [{"labels": {}, "values": [{"t": T0.timestamp(), "v": 0.2}]}]}, status="ok")
    net = NetworkContext(service="backend", start=T0 - timedelta(minutes=3), end=RECEIVED)
    meta = {"start": T0 - timedelta(minutes=3), "end": RECEIVED, "limit": 200}
    return build_context(_alert(), RECEIVED, "leafy-backend", rule, metrics, logs, meta, net, "v2", "resolved")


class TestCaptureRoundTrip(unittest.TestCase):
    def test_context_to_fixture_to_harness(self):
        with tempfile.TemporaryDirectory() as d:
            ctx_dir, out_dir = os.path.join(d, "context"), os.path.join(d, "fixtures")
            save_context(ctx_dir, _context())
            runs = os.path.join(d, "runs.jsonl")
            fixtures.append_run_record("s1_c_login_bruteforce", None, None, T0 - timedelta(minutes=2),
                                       T0 + timedelta(seconds=5), "ok", runs)
            report = fixtures.build_fixtures_from_contexts(ctx_dir, runs, out_dir, grace_seconds=60)
            self.assertEqual(len(report), 1)
            self.assertIsNotNone(report[0]["fixture"], report)
            [fx] = harness.load_fixtures(out_dir)
        self.assertEqual(fx["scenario_id"], "s1_c_login_bruteforce")
        self.assertEqual(fixtures.find_answer_label_keys(fx), [])
        inputs = harness.build_inputs(fx)
        self.assertEqual(inputs["rule"].value, 12)
        self.assertEqual(len(inputs["logs"]), 5)
        for builder in harness.BUILDERS:
            prompt = make_builder(builder).build(**inputs)
            self.assertEqual(harness.prompt_leaks(prompt, fx), [])
            self.assertNotIn("secret0", prompt["user"])
        v2 = make_builder("v2").build(**inputs)
        self.assertIn("value_at_start=12", v2["user"])
        self.assertIn("[rule-match]", v2["user"])


if __name__ == "__main__":
    unittest.main()
