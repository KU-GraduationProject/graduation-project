"""
프롬프트 조립 v2 (prompt/builder_v2.py, collector/rules.py) 와 main 의 v2 조회 구간.

11-01 측정 결함이 다시 생기지 않는지 확인한다:
  경보 구간 로그 0줄 / 6,000자 절단 / 줄마다 UA / ALERT 에 값·임계값 없음.

실행 (pipeline 디렉터리에서):
    python -m unittest discover -s tests -v
"""

import asyncio
import json
import os
import re
import sys
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from collector.logs import LogsCollector  # noqa: E402
from collector.network import NetworkContext  # noqa: E402
from collector.rules import (RuleContext, RulesCollector, max_range_seconds,  # noqa: E402
                             parse_duration, split_threshold)
from correlation import CorrelationContext  # noqa: E402
from prompt.builder import PromptBuilder, make_builder  # noqa: E402
from prompt.builder_v2 import SECTION_BUDGETS, est_tokens, rule_log_matcher  # noqa: E402

T0 = datetime(2026, 11, 1, 5, 3, 10, tzinfo=timezone.utc)
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"
RULE_4XX = RuleContext(
    name="Http4xxBurst", source="loki",
    expr='sum(count_over_time({service="frontend", log_format="json"} | json | status >= 400 [2m])) > 20',
    for_seconds=30, range_seconds=120, op=">", threshold=20, value=24)


def alert(name="Http4xxBurst"):
    return SimpleNamespace(labels=SimpleNamespace(alertname=name, severity="warning", container="leafy-frontend"),
                           annotations={"summary": "4xx burst"}, startsAt="2026-11-01T14:03:10+09:00")


def access(ts, status, uri, method="GET", rid="r1"):
    rec = {"timestamp": "2026-11-01T14:00:00+09:00", "request_method": method, "request_uri": uri,
           "status": str(status), "request_time": "0.010", "http_user_agent": UA,
           "remote_addr": "10.0.0.5", "request_id": rid}
    return {"ts": ts, "labels": {"service": "frontend", "log_format": "json"}, "line": json.dumps(rec)}


def build(logs=(), metrics=None, rule=RULE_4XX, network=None):
    return make_builder("v2").build(alert(), metrics or {}, list(logs), "leafy-frontend", network,
                                    rule=rule, received_at=T0 + timedelta(seconds=30),
                                    log_meta={"start": T0 - timedelta(minutes=4), "end": T0, "limit": 200},
                                    policy=None)


class RuleParsingTest(unittest.TestCase):
    def test_split_threshold_top_level_only(self):
        expr = ('sum by (name) (irate(x{id=~"/docker/.+",cpu="total"}[30s]) * on(id) group_left(name) y)'
                ' > 0.5 and on(name) y{name=~"a|b"}')
        lhs, op, th = split_threshold(expr)
        self.assertTrue(lhs.endswith("group_left(name) y)"))
        self.assertEqual((op, th), (">", 0.5))
        lhs, op, th = split_threshold(RULE_4XX.expr)
        self.assertEqual((op, th), (">", 20.0))
        self.assertIn("status >= 400", lhs)
        self.assertIsNone(split_threshold("up"))

    def test_durations(self):
        self.assertEqual(parse_duration("1m30s"), 90)
        self.assertIsNone(parse_duration("abc"))
        self.assertEqual(max_range_seconds('rate(a[1m]) + rate(b[5m])'), 300)

    def test_window_is_range_plus_for(self):
        self.assertEqual(RULE_4XX.window_seconds, 150)
        self.assertIsNone(RuleContext(name="x").window_seconds)


class RulesCollectorTest(unittest.TestCase):
    def run_fetch(self, handler, name="Http4xxBurst"):
        rc = RulesCollector("http://prom", "http://loki", transport=httpx.MockTransport(handler))
        return asyncio.run(rc.fetch(name, {"alertname": name, "name": "leafy-frontend"}, T0))

    def test_loki_rule_value_at_starts_at(self):
        seen = {}

        def handler(req):
            if req.url.path == "/api/v1/rules":
                return httpx.Response(200, json={"data": {"groups": []}})
            if req.url.path == "/prometheus/api/v1/rules":
                return httpx.Response(200, json={"data": {"groups": [{"rules": [
                    {"name": "Http4xxBurst", "type": "alerting", "query": RULE_4XX.expr, "duration": 30}]}]}})
            seen["time"] = req.url.params["time"]
            return httpx.Response(200, json={"data": {"result": [{"metric": {}, "value": [0, "24"]}]}})

        r = self.run_fetch(handler)
        self.assertEqual((r.source, r.value, r.threshold, r.window_seconds), ("loki", 24.0, 20.0, 150))
        self.assertEqual(seen["time"], str(int(T0.timestamp() * 1e9)))

    def test_prometheus_series_matching_alert_labels(self):
        def handler(req):
            if req.url.path == "/api/v1/rules":
                return httpx.Response(200, json={"data": {"groups": [{"rules": [
                    {"name": "Cpu", "type": "alerting", "query": "max by (name) (x[1m]) > 0.5", "duration": 30}]}]}})
            if req.url.path == "/api/v1/query":
                return httpx.Response(200, json={"data": {"result": [
                    {"metric": {"name": "leafy-db"}, "value": [0, "0.9"]},
                    {"metric": {"name": "leafy-frontend"}, "value": [0, "0.7"]}]}})
            return httpx.Response(404)

        r = self.run_fetch(handler, "Cpu")
        self.assertEqual((r.source, r.value), ("prometheus", 0.7))

    def test_failures_are_reported_not_raised(self):
        r = self.run_fetch(lambda req: httpx.Response(200, json={"data": {"groups": []}}))
        self.assertIsNone(r.value)
        self.assertIn("rule not found", r.error)

        def boom(req):
            raise httpx.ConnectError("down")
        self.assertIn("rule", self.run_fetch(boom).error)


class LogsDirectionTest(unittest.TestCase):
    def test_backward_param_and_ascending_result(self):
        seen = {}

        def handler(req):
            seen.update(req.url.params)
            return httpx.Response(200, json={"data": {"result": [{"stream": {}, "values": [
                ["2000000000", "b"], ["1000000000", "a"]]}]}})

        lc = LogsCollector("http://loki", transport=httpx.MockTransport(handler))
        ctx = CorrelationContext(service="frontend", start=T0 - timedelta(minutes=3), end=T0)
        logs = asyncio.run(lc.fetch(ctx, direction="backward"))
        self.assertEqual(seen["direction"], "backward")
        self.assertEqual([l["line"] for l in logs], ["a", "b"])


class BuilderV2Test(unittest.TestCase):
    def test_alert_section_has_rule_value_threshold_window(self):
        user = build()["user"]
        for text in ("rule=Http4xxBurst", "severity=warning", "starts_at=2026-11-01T05:03:10Z",
                     "received_at=2026-11-01T05:03:40Z", "value_at_start=24", "threshold: > 20",
                     "window=2m30s", "container=leafy-frontend"):
            self.assertIn(text, user)

    def test_value_lookup_failure_is_explicit(self):
        user = build(rule=RuleContext(name="Http4xxBurst", error="rule not found"))["user"]
        self.assertIn("value lookup failed (rule not found)", user)
        self.assertIn("value lookup failed", build(rule=None)["user"])

    def test_rule_matching_lines_first_and_grouped(self):
        t = T0.timestamp()
        logs = [access(t - 200 + i, 200, f"/api/plants/{i}") for i in range(150)]
        logs += [access(t - 30 + i, 401, "/api/auth/login", "POST", rid=f"x{i}") for i in range(20)]
        user = build(logs)["user"]
        first = re.search(r"^\[L1\].*$", user, re.M).group(0)
        self.assertIn("status=401", first)
        self.assertIn("x20", first)
        self.assertIn("[rule-match]", first)
        self.assertIn("x150", user)

    def test_rule_matcher_filters(self):
        m = rule_log_matcher(r'sum(count_over_time({service="frontend"} |~ "(?i)(union.{0,3}select|sleep\\()" [2m])) > 5')
        self.assertTrue(m({"line": "GET /?q=UNION SELECT 1"}))
        self.assertTrue(m({"line": "sleep(5)"}))
        self.assertFalse(m({"line": "GET /plants"}))
        net = rule_log_matcher('sum(sum_over_time({log_type="network"} | json | __error__="" | bytes_sent!="" | unwrap bytes_sent [5m])) > 1')
        self.assertIsNone(net)
        self.assertIsNone(rule_log_matcher("rate(x[1m]) > 1"))

    def test_lines_are_compact_masked_and_utc(self):
        rec = {"timestamp": "2026-11-01T14:03:00+09:00", "request_method": "POST",
               "request_uri": "/api/auth/login?password=hunter2", "status": "401",
               "http_user_agent": UA, "request_id": "abc"}
        user = build([{"ts": T0.timestamp() - 10, "labels": {"service": "frontend", "log_format": "json"},
                       "line": json.dumps(rec)}])["user"]
        self.assertNotIn("Mozilla", user)
        self.assertNotIn("hunter2", user)
        self.assertNotIn("+09:00", user)
        self.assertIn("05:03:00Z", user)
        self.assertIn("rid=abc", user)

    def test_section_budgets_and_truncation_flag(self):
        t = T0.timestamp()
        logs = [{"ts": t - i, "labels": {"service": "backend"},
                 "line": f"ERROR unique failure {chr(65 + i % 26)}{chr(65 + i // 26 % 26)} in module m{i}"}
                for i in range(600)]
        p = build(logs, rule=None)
        self.assertTrue(p["truncated"])
        self.assertTrue(p["sections"]["logs"]["truncated"])
        self.assertRegex(p["user"], r"\(\d+ lines omitted in \d+ patterns: budget\)")
        for name, sec in p["sections"].items():
            self.assertLessEqual(sec["tokens_est"], SECTION_BUDGETS[name], name)
        self.assertLess(est_tokens(p["system"] + p["user"]), 4096 - 400)

    def test_evidence_ids_match_prompt(self):
        t = T0.timestamp()
        metrics = {"cpu_usage": [{"labels": {}, "values": [{"t": t, "v": 0.9}]}]}
        nc = NetworkContext(service="backend", start=T0 - timedelta(minutes=3), end=T0, events=(
            {"src_service": "backend", "dst_service": "unknown", "dst_ip": "203.0.113.9", "dst_port": 443,
             "protocol": "tcp", "event_type": "connection", "bytes_sent": 5_000_000,
             "timestamp": "2026-11-01T14:02:00+09:00"},
            {"src_service": "backend", "dst_service": "unknown", "dst_ip": "203.0.113.9", "dst_port": 443,
             "protocol": "tcp", "event_type": "connection_threshold", "bytes_sent": 1_048_576,
             "timestamp": "2026-11-01T14:01:00+09:00"}))
        p = build([access(t - 5, 500, "/x")], metrics=metrics, network=nc)
        in_text = re.findall(r"^\s*\[([AMLN]\d+)\]", p["user"], re.M)
        self.assertEqual(in_text, p["evidence_ids"])
        self.assertEqual(p["evidence_ids"], ["A1", "M1", "L1", "N1"])
        self.assertIn("early=1@2026-11-01T05:01:00Z", p["user"])

    def test_legacy_mode_unchanged(self):
        a = alert()
        legacy = make_builder("legacy").build(a, {}, [], "leafy-frontend", None, rule=RULE_4XX)
        self.assertEqual(legacy, PromptBuilder().build(a, {}, [], "leafy-frontend", None))
        with self.assertRaises(ValueError):
            make_builder("v3")


class MainV2WindowTest(unittest.TestCase):
    def setUp(self):
        try:
            import main
        except ImportError:
            self.skipTest("fastapi not installed")
        self.main = main

    def test_log_window_from_rule_and_received_at_and_invalid_forwarded(self):
        main = self.main
        a = main.Alert(status="firing", labels=main.AlertLabel(alertname="Http4xxBurst", container="leafy-frontend",
                                                               category="security"),
                       startsAt="2026-11-01T05:03:10Z", annotations={"container": "leafy-frontend"})
        received = T0 + timedelta(seconds=30)
        logs_fetch = mock.AsyncMock(return_value=[])
        rules_fetch = mock.AsyncMock(return_value=RULE_4XX)
        invalid = main.LLMAnalysisResult.invalid(["parse_error"])
        forward = mock.AsyncMock()
        main._recent_alerts.clear()
        with mock.patch.object(main.settings, "prompt_builder", "v2"), \
             mock.patch.object(main, "prompt_builder", make_builder("v2")), \
             mock.patch.object(main.rules_collector, "fetch", rules_fetch), \
             mock.patch.object(main.logs_collector, "fetch", logs_fetch), \
             mock.patch.object(main.metrics_collector, "fetch_around", mock.AsyncMock(return_value={})), \
             mock.patch.object(main.network_collector, "fetch", mock.AsyncMock(
                 return_value=NetworkContext(service="frontend", start=T0, end=T0))), \
             mock.patch.object(main, "resolve_service", mock.AsyncMock(return_value=("frontend", "container"))), \
             mock.patch.object(main, "call_llm", mock.AsyncMock(return_value=invalid)), \
             mock.patch.object(main, "push_to_loki", mock.AsyncMock()), \
             mock.patch.object(main, "forward_to_remediation", forward):
            asyncio.run(main.analyze_alerts([a], received))

        self.assertEqual(rules_fetch.call_args.args[1]["category"], "security")  # 추가 라벨 유지
        ctx = logs_fetch.call_args.args[0]
        self.assertEqual(logs_fetch.call_args.kwargs["direction"], "backward")
        self.assertEqual(ctx.start, T0 - timedelta(seconds=150) - main.LOG_WINDOW_MARGIN)
        self.assertEqual(ctx.end, received)
        sent = forward.call_args.args[1]
        self.assertEqual((sent.analysis_status, sent.action_type), ("invalid", "NOTIFY"))

    def test_call_llm_does_not_retry_truncated(self):
        main = self.main
        calls = []

        async def chat(client, system, user, fmt="json"):
            calls.append(fmt)
            return {"message": {"content": '{"root_cause":'}, "done_reason": "length", "prompt_eval_count": 10}

        with mock.patch.object(main, "_ollama_chat", chat), \
             mock.patch.object(main.asyncio, "sleep", mock.AsyncMock()), \
             mock.patch.object(main.httpx, "AsyncClient"):
            r = asyncio.run(main.call_llm({"system": "s", "user": "u", "evidence_ids": ["A1"]}))
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["properties"]["evidence"]["items"]["enum"], ["A1"])
        self.assertEqual(r.invalid_reasons, ["truncated", "parse_error"])


if __name__ == "__main__":
    unittest.main()
