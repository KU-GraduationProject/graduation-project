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
from collector.rules import (RuleContext, RulesCollector, conditions, max_range_seconds,  # noqa: E402
                             parse_duration, range_selectors, split_threshold)
from correlation import CorrelationContext  # noqa: E402
from prompt.builder import PromptBuilder, make_builder  # noqa: E402
from prompt.builder_v2 import SECTION_BUDGETS, est_tokens, rule_log_matcher  # noqa: E402

T0 = datetime(2026, 11, 1, 5, 3, 10, tzinfo=timezone.utc)
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"
RULE_4XX = RuleContext(
    name="Http4xxBurst", source="loki",
    expr='sum(count_over_time({service="frontend", log_format="json"} | json | status >= 400 [2m])) > 20',
    for_seconds=30, range_seconds=120, ranges=("2m",), conditions=((">", 20.0),), value=24)


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

    def test_rulepack_shapes(self):
        # or 갈래 + 서브쿼리 + offset (ContainerRestarted)
        restarted = ('max by (name) (sum_over_time((last_over_time(x[10m]) - last_over_time(x[10m] offset 5s))[10m:5s]))'
                     ' >= 2 or max by (name) (changes(y[10m])) >= 2')
        self.assertEqual(conditions(restarted), ((">=", 2.0),))
        self.assertEqual(range_selectors(restarted), ["10m", "10m:5s"])
        self.assertEqual(max_range_seconds(restarted), 600)
        # 최상위 비교 없이 괄호 안에만 있는 or 식 (HighNetworkReceive)
        net = '(sum by (name) (rate(a[1m])) > 1e7) or ((sum without (interface) (rate(b[1m])) > 1e7) unless on () (count(c) > 0))'
        self.assertIsNone(split_threshold(net))
        self.assertEqual(conditions(net), ((">", 1e7),))
        # 서로 다른 임계의 갈래
        self.assertEqual(conditions("a > 1 or b < 0.5"), ((">", 1.0), ("<", 0.5)))
        # __error__ 안의 'or' 로 나누지 않는다
        self.assertEqual(conditions('sum(count_over_time({a="b"} | json | __error__="" [1m])) > 10'), ((">", 10.0),))

    def test_durations(self):
        self.assertEqual(parse_duration("1m30s"), 90)
        self.assertIsNone(parse_duration("abc"))
        self.assertEqual(max_range_seconds('rate(a[1m]) + rate(b[5m])'), 300)

    def test_window_is_range_plus_for(self):
        self.assertEqual(RULE_4XX.window_seconds, 150)
        self.assertIsNone(RuleContext(name="x").window_seconds)
        self.assertEqual((RULE_4XX.op, RULE_4XX.threshold), (">", 20.0))

    def test_from_dict_roundtrip_and_old_format(self):
        self.assertEqual(RuleContext.from_dict(RULE_4XX.as_dict()), RULE_4XX)
        old = RuleContext.from_dict({"name": "x", "op": ">", "threshold": 3, "value": 4})
        self.assertEqual(old.conditions, ((">", 3.0),))


class RulepackShapesTest(unittest.TestCase):
    """룰팩 M5 후보 룰(docs/rulepack/m5/generated) 전부에서 임계·시간 창을 읽을 수 있는지."""

    def test_every_m5_rule_has_conditions_and_window(self):
        import yaml
        root = os.path.join(os.path.dirname(__file__), "..", "..", "..", "docs", "rulepack", "m5", "generated")
        rules = []
        for name in ("prometheus.rules.yml", "loki.rules.yml"):
            with open(os.path.join(root, name), encoding="utf-8") as fh:
                rules += [(name, r) for g in yaml.safe_load(fh)["groups"] for r in g["rules"]]
        self.assertEqual(len(rules), 21)
        for name, r in rules:
            ctx = RuleContext(name=r["alert"], expr=r["expr"], for_seconds=parse_duration(r.get("for", "0s")),
                              range_seconds=max_range_seconds(r["expr"]), conditions=conditions(r["expr"]))
            self.assertTrue(ctx.conditions, r["alert"])
            self.assertIsNotNone(ctx.window_seconds, r["alert"])
        # 줄 그대로 판정할 수 없는 Loki 룰(필드 추출·or 결합)은 관련 줄 판정을 하지 않는다
        loki = {r["alert"]: r["expr"] for n, r in rules if n.startswith("loki")}
        for alert in ("SQLInjection", "DBConnectionLimit", "UnauthorizedDataTransfer"):
            self.assertIsNone(rule_log_matcher(loki[alert]), alert)
        m = rule_log_matcher(loki["VulnerabilityScanningDetected"])
        self.assertTrue(m({"line": '{"status": "404"}'}))
        self.assertFalse(m({"line": '{"status": "503"}'}))


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
                return httpx.Response(200, json={"data": {"groups": [{"interval": 5, "rules": [
                    {"name": "Http4xxBurst", "type": "alerting", "query": RULE_4XX.expr, "duration": 30}]}]}})
            seen["time"] = req.url.params["time"]
            seen["query"] = req.url.params["query"]
            return httpx.Response(200, json={"data": {"result": [{"metric": {}, "value": [0, "24"]}]}})

        r = self.run_fetch(handler)
        self.assertEqual((r.source, r.value, r.threshold, r.window_seconds), ("loki", 24.0, 20.0, 150))
        self.assertEqual(seen["time"], str(int(T0.timestamp() * 1e9)))
        self.assertEqual(seen["query"], RULE_4XX.expr)        # 룰 식 전체를 평가한다
        self.assertEqual(r.eval_interval_seconds, 5)

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

    def _cpu_rules(self, req, targets=("leafy-frontend", "leafy-backend")):
        if req.url.path == "/api/v1/rules":
            return httpx.Response(200, json={"data": {"groups": [{"rules": [
                {"name": "Cpu", "type": "alerting", "duration": 30, "keepFiringFor": "2m",
                 "labels": {"severity": "warning", "rulepack_target": t},
                 "query": f'sum by (name) (irate(x[30s])) > 0.5 and on(name) info{{name="{t}"}}'}
                for t in targets]}]}})
        if req.url.path == "/api/v1/query":
            return httpx.Response(200, json={"data": {"result": [
                {"metric": {"name": "leafy-backend"}, "value": [0, "0.8"]}]}})
        return httpx.Response(404)

    def test_same_alertname_rules_selected_by_rule_labels(self):
        rc = RulesCollector("http://prom", "http://loki", transport=httpx.MockTransport(self._cpu_rules))
        r = asyncio.run(rc.fetch("Cpu", {"alertname": "Cpu", "rulepack_target": "leafy-backend",
                                         "severity": "warning", "name": "leafy-backend"}, T0))
        self.assertIn('name="leafy-backend"', r.expr)
        self.assertEqual((r.value, r.conditions, r.keep_firing_seconds), (0.8, ((">", 0.5),), 120))
        # 라벨로 고를 수 없으면 엉뚱한 룰 값을 쓰지 않고 실패로 남긴다
        for labels in ({"alertname": "Cpu", "severity": "warning"},
                       {"alertname": "Cpu", "rulepack_target": "leafy-db"}):
            r = asyncio.run(rc.fetch("Cpu", labels, T0))
            self.assertIsNone(r.value)
            self.assertIn("2 rules named Cpu, none match alert labels", r.error)

    def test_ambiguous_rules_are_not_guessed(self):
        def handler(req):
            if req.url.path == "/api/v1/rules":
                return httpx.Response(200, json={"data": {"groups": [{"rules": [
                    {"name": "Cpu", "type": "alerting", "query": f"x{{i=\"{i}\"}} > 0.5", "labels": {}}
                    for i in range(2)]}]}})
            return httpx.Response(404)
        rc = RulesCollector("http://prom", "http://loki", transport=httpx.MockTransport(handler))
        r = asyncio.run(rc.fetch("Cpu", {"alertname": "Cpu"}, T0))
        self.assertIn("ambiguous", r.error)

    def test_failures_are_reported_not_raised(self):
        def empty_value(req):
            if req.url.path == "/api/v1/rules":
                return httpx.Response(200, json={"data": {"groups": [{"rules": [
                    {"name": "Http4xxBurst", "type": "alerting", "query": "x > 1", "duration": 0}]}]}})
            return httpx.Response(200, json={"data": {"result": []}})
        r = self.run_fetch(empty_value)
        self.assertIn("no series at startsAt", r.error)
        r = self.run_fetch(lambda req: httpx.Response(200, json={"data": {"groups": []}}))
        self.assertIsNone(r.value)
        self.assertIn("rule not found", r.error)

        def boom(req):
            raise httpx.ConnectError("down")
        self.assertIn("rule", self.run_fetch(boom).error)


class LogsDirectionTest(unittest.TestCase):
    def test_backward_param_and_ascending_result(self):
        try:
            from tests.test_source_identity import binding, context
        except ImportError:
            self.skipTest("fastapi not installed")
        b = binding()
        ctx = context(b)
        seen = {}

        def handler(req):
            if req.url.path.endswith("/series"):
                return httpx.Response(200, json={"status": "success", "data": [b.logs]})
            seen.update(req.url.params)
            return httpx.Response(200, json={"status": "success", "data": {"resultType": "streams", "result": [
                {"stream": b.logs, "values": [[str(ctx.start_ns + 2_000_000_000), "b"], [str(ctx.start_ns + 1_000_000_000), "a"]]}]}})

        lc = LogsCollector("http://loki", transport=httpx.MockTransport(handler))
        logs = asyncio.run(lc.fetch(ctx, direction="backward"))
        self.assertEqual(seen["direction"], "backward")
        self.assertEqual([l["line"] for l in logs], ["a", "b"])


class BuilderV2Test(unittest.TestCase):
    def test_alert_section_has_rule_value_threshold_window(self):
        user = build()["user"]
        for text in ("rule=Http4xxBurst", "severity=warning", "starts_at=2026-11-01T05:03:10Z",
                     "received_at=2026-11-01T05:03:40Z", "value_at_start=24", "threshold: > 20",
                     "window=2m30s", "ranges=2m", "container=leafy-frontend"):
            self.assertIn(text, user)

    def test_multiple_conditions_keep_firing_and_interval(self):
        rule = RuleContext(name="Http4xxBurst", source="prometheus", expr="a > 1 or b < 0.5",
                           for_seconds=0, range_seconds=600, ranges=("10m", "10m:5s"),
                           conditions=((">", 1.0), ("<", 0.5)), keep_firing_seconds=120,
                           eval_interval_seconds=5, value=3)
        user = build(rule=rule)["user"]
        self.assertIn("conditions (any): > 1 | < 0.5", user)
        self.assertIn("ranges=10m,10m:5s", user)
        self.assertIn("keep_firing_for=2m00s", user)
        self.assertIn("eval_every=5s", user)

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

    def test_rule_matcher_loki_api_normalized_form(self):
        # Loki ruler API 는 'and' 를 ',' 로, 필터를 괄호로 묶고 범위를 공백 없이 붙여 돌려준다 (11-01 측정)
        m = rule_log_matcher('(sum(count_over_time({service="frontend", log_format="json"} | json'
                             ' | ( status>=400 , status<500 )[1m])) > 50)')
        self.assertIsNotNone(m)
        self.assertTrue(m({"line": '{"status": "404"}'}))
        self.assertFalse(m({"line": '{"status": "503"}'}))
        self.assertFalse(m({"line": '{"status": "200"}'}))
        # or 결합 괄호는 여전히 판정하지 않는다
        self.assertIsNone(rule_log_matcher('sum(count_over_time({a="b"} | json | ( status>=500 or status=429 )[1m])) > 1'))

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
            from tests.test_source_identity import binding
        except ImportError:
            self.skipTest("fastapi not installed")
        self.main, self.binding = main, binding(runtime="container", target="leafy-frontend")

    def _run(self, bindings, llm_result=None):
        from identity import LogEvidence, MetricEvidence
        main, b = self.main, self.binding
        a = main.Alert(status="firing", startsAt="2026-11-01T05:03:10Z",
                       annotations={"container": b.identity.target},
                       labels=main.AlertLabel(alertname="Http4xxBurst", category="security", **b.match))
        mocks = {
            "rules": mock.AsyncMock(return_value=RULE_4XX),
            "logs": mock.AsyncMock(return_value=LogEvidence([], status="empty")),
            "llm": mock.AsyncMock(return_value=llm_result or main.LLMAnalysisResult.invalid(["parse_error"])),
            "forward": mock.AsyncMock(),
        }
        main._recent_alerts.clear()
        main.analysis_history.clear()
        metrics = MetricEvidence({"cpu_usage": [{"labels": {}, "values": [{"t": T0.timestamp(), "v": 0.2}]}]},
                                 status="ok")
        with mock.patch.object(main.settings, "prompt_builder", "v2"), \
             mock.patch.object(main, "prompt_builder", make_builder("v2")), \
             mock.patch.object(main, "_observation_bindings", bindings), \
             mock.patch.object(main.rules_collector, "fetch", mocks["rules"]), \
             mock.patch.object(main.logs_collector, "fetch", mocks["logs"]), \
             mock.patch.object(main.metrics_collector, "fetch_around", mock.AsyncMock(return_value=metrics)), \
             mock.patch.object(main.network_collector, "fetch", mock.AsyncMock(
                 return_value=NetworkContext(service="frontend", start=T0, end=T0))), \
             mock.patch.object(main, "call_llm", mocks["llm"]), \
             mock.patch.object(main, "push_to_loki", mock.AsyncMock(return_value=True)), \
             mock.patch.object(main, "forward_to_remediation", mocks["forward"]):
            asyncio.run(main.analyze_alerts([a], T0 + timedelta(seconds=30)))
        return mocks

    def test_log_window_from_rule_and_received_at(self):
        m = self._run((self.binding,))
        self.assertEqual(m["rules"].call_args.args[1]["category"], "security")  # 추가 라벨 유지
        ctx = m["logs"].call_args.args[0]
        self.assertEqual(m["logs"].call_args.kwargs["direction"], "backward")
        self.assertEqual(ctx.start, T0 - timedelta(seconds=150) - self.main.LOG_WINDOW_MARGIN)
        self.assertEqual(ctx.end, T0 + timedelta(seconds=30))
        self.assertEqual(ctx.binding, self.binding)                              # 수집 범위는 그대로
        prompt = m["llm"].call_args.args[0]
        self.assertIn("value_at_start=24", prompt["user"])
        self.assertIn("observation identity:", prompt["user"])
        entry = self.main.analysis_history[-1]
        self.assertEqual(entry["result"]["analysis_status"], "invalid")
        self.assertEqual(entry["result"]["action_type"], "NOTIFY")
        m["forward"].assert_not_awaited()                                        # 전달 보류(main 계약) 유지

    def test_unresolved_source_is_invalid_not_none(self):
        m = self._run(())
        m["llm"].assert_not_awaited()
        result = self.main.analysis_history[-1]["result"]
        self.assertEqual((result["analysis_status"], result["action_type"]), ("invalid", "NOTIFY"))
        self.assertEqual(result["invalid_reasons"], ["observation_unresolved"])

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
