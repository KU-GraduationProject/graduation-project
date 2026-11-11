"""Synthetic-only checks: native LogQL pipelines plus Prometheus alert boundaries.

M3_LOGCLI: upstream logcli; M3_PROMTOOL: upstream promtool. No service requests.
LogCLI stdin cannot evaluate metric queries or real stream selection. The tests
therefore separate native parsing/filtering, fixture scope/time selection, and
native Prometheus evaluation of test-only matching-count gauges. This is not a
full Loki ruler evaluation or evidence of application traffic.
"""

from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

import yaml

spec = importlib.util.spec_from_file_location("m3_generator", Path(__file__).resolve().parents[1] / "generate_m3.py")
m3 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m3)
LOGCLI = os.environ.get("M3_LOGCLI")
PROMTOOL = os.environ.get("M3_PROMTOOL")


def defaults():
    return yaml.safe_load(m3.DEFAULT_CONFIG.read_text(encoding="utf-8"))


def generated(config=None):
    return yaml.safe_load(m3.render(config or defaults()))["groups"][0]["rules"]


def fixture(name, fields, expected, kind="SQLInjection", **kwargs):
    labels = {"service": "frontend", "runtime": "container", "log_format": "json"} if kind == "SQLInjection" else {
        "service": "db", "runtime": "host", "log_format": "json"}
    return {"id": name, "line": {"fixture_id": name, **fields}, "expected": expected,
            "labels": labels, "time": 120, **kwargs}


def sql_fixtures():
    return [
        fixture("union", {"request_uri": "/search?q=UNION SELECT"}, True),
        fixture("encoded-keyword", {"request_uri": "/search?q=%55%4e%49%4f%4e%20SELECT"}, True),
        fixture("plus", {"request_uri": "/search?q=union+all+select"}, True),
        fixture("comments", {"request_uri": "/search?q=UnIoN/**/ALL/**/SeLeCt"}, True),
        fixture("newline", {"request_uri": "/search?q=UNION%0ASELECT"}, True),
        fixture("boolean", {"request_uri": "/search?q=x%27+OR+1%3D1--"}, True),
        fixture("quoted-boolean", {"request_uri": "/search?q=OR+'1'%3D'1'"}, True),
        fixture("sleep", {"request_uri": "/search?q=pg_sleep(2)"}, True),
        fixture("schema", {"request_uri": "/search?q=information_schema.tables"}, True),
        fixture("stacked", {"request_uri": "/search?q=x%3B+DROP+TABLE+t"}, True),
        fixture("ordinary", {"request_uri": "/products?q=green+leaf"}, False),
        fixture("word-boundary", {"request_uri": "/communion?mode=selection"}, False),
        fixture("non-tautology", {"request_uri": "/search?q=OR+1%3D10"}, False),
        fixture("user-agent-only", {"request_uri": "/products", "http_user_agent": "union select"}, False),
        fixture("message-only", {"message": "union select"}, False),
        fixture("missing-uri", {"uri": "/search", "args": "union select"}, False),
        fixture("null-uri", {"request_uri": None}, False),
        fixture("empty-uri", {"request_uri": ""}, False),
        fixture("numeric-uri", {"request_uri": 17}, False),
        fixture("object-uri", {"request_uri": {"q": "union select"}}, False),
        fixture("array-uri", {"request_uri": ["union select"]}, False),
        fixture("malformed-escape", {"request_uri": "/search?q=UNION+SELECT%ZZ"}, False),
        fixture("double-encoded", {"request_uri": "/search?q=%2555NION%2520SELECT"}, False),
        fixture("json-escape", {"request_uri": "/search?q=UNION%20SELECT", "http_user_agent": '"\\'}, True),
        fixture("alias-in-body", {"request_uri": "/products", "m3_decoded": "union select"}, False),
        {"id": "broken-json", "line": '{"request_uri": "union select"', "expected": False},
        {"id": "trailing-json", "line": '{"request_uri": "union select"} trailing', "expected": False},
        {"id": "non-object", "line": '["union select"]', "expected": False},
        {"id": "array-object", "line": '[{"request_uri":"union select"}]', "expected": False},
    ]


def db_fixtures():
    fields = {"error_severity": "FATAL", "state_code": "53300", "message": "sorry, too many clients already"}
    def row(name, expected, **changes):
        return fixture(name, {**fields, **changes}, expected, "DBConnectionLimit")
    return [
        row("server-full", True),
        row("reserved-superuser", True, message="remaining connection slots are reserved for non-replication superuser connections"),
        row("reserved-role", True, message='remaining connection slots are reserved for roles with privileges of the "pg_use_reserved_connections" role'),
        row("authentication", False, state_code="28P01", message='password authentication failed for user "fixture"'),
        row("wrong-code", False, state_code="08006"),
        row("wrong-severity", False, error_severity="LOG"),
        row("role-cap", False, message='too many connections for role "fixture"'),
        row("database-cap", False, message='too many connections for database "fixture"'),
        row("hikari-timeout", False, message="HikariPool-1 - Connection is not available, request timed out"),
        row("quoted-statement", False, message="statement: SELECT 'sorry, too many clients already'"),
        row("localized", False, message="합성 로컬 언어 오류"),
        row("missing-code", False, state_code=None),
        row("numeric-code", False, state_code=53300),
        row("missing-message", False, message=None),
        fixture("message-only", {"message": "sorry, too many clients already"}, False, "DBConnectionLimit"),
        row("ordinary-connection", False, state_code="00000", error_severity="LOG", message="connection authorized"),
        {"id": "truncated-db-json", "line": '{"error_severity":"FATAL","state_code":"53300","message":"sorry, too many clients already"', "expected": False},
    ]


def native_matches(query, rows):
    payload = "\n".join(json.dumps(row["line"], ensure_ascii=False) if isinstance(row["line"], dict) else row["line"] for row in rows)
    if not payload:
        return set()
    env = {key: value for key, value in os.environ.items() if not key.startswith("LOKI_")}
    result = subprocess.run([LOGCLI, "--stdin", "--quiet", "--addr=http://127.0.0.1:1", "--output=raw", "query", query],
                            input=payload + "\n", text=True, capture_output=True, timeout=20, env=env)
    if result.returncode:
        raise AssertionError(result.stderr)
    return {json.loads(line)["fixture_id"] for line in result.stdout.splitlines()}


class M3ContractTest(unittest.TestCase):
    def test_default_rules_use_only_documented_inputs_and_no_deferred_rules(self):
        rules = generated()
        self.assertEqual([rule["alert"] for rule in rules], ["SQLInjection", "DBConnectionLimit"])
        self.assertTrue(all(rule["for"] == "0m" for rule in rules))
        self.assertTrue(all(rule["expr"].endswith("[2m]\n)) > 0") for rule in rules))
        self.assertIn('m3_uri="request_uri"', rules[0]["expr"])
        self.assertIn('m3_code="state_code"', rules[1]["expr"])
        self.assertNotIn("hikaricp_", m3.render(defaults()))
        self.assertNotIn("pg_settings_", m3.render(defaults()))
        with self.assertRaises(ValueError):
            m3.pipeline("LoginBruteForce", defaults()["web_targets"][0])

    def test_renamed_and_disjoint_targets_and_literal_escaping(self):
        config = defaults()
        config["web_targets"] = [{"id": "shop-" + name, "alert_target": "nginx-" + name,
                                  "log_selector": {"service": "shop", "runtime": "container", "container_name": name + '"\\'}} for name in ("a", "b")]
        rendered = generated(config)
        self.assertEqual(len(rendered), 3)
        for rule, target in zip(rendered, config["web_targets"] + config["postgres_targets"]):
            self.assertEqual(rule["annotations"]["container"], target["alert_target"])
            self.assertEqual(rule["labels"]["rulepack_target"], target["id"])
        self.assertIn(r'container_name="a\"\\"', rendered[0]["expr"])

    def test_invalid_config_and_unsupported_fields_are_rejected(self):
        mutations = [lambda c: c.update(version=True), lambda c: c.update(auth_targets=[]),
                     lambda c: c["web_targets"][0]["log_selector"].update(role="web"),
                     lambda c: c["web_targets"][0]["log_selector"].update(runtime="host"),
                     lambda c: c["web_targets"][0]["log_selector"].update(service="unknown"),
                     lambda c: c["web_targets"][0]["log_selector"].update(source="other"),
                     lambda c: c["postgres_targets"][0]["log_selector"].update(runtime="container"),
                     lambda c: c["postgres_targets"][0]["log_selector"].update(container_name="db"),
                     lambda c: c["postgres_targets"][0]["log_selector"].update(source="stderr"),
                     lambda c: c["web_targets"][0]["log_selector"].update(container_name="bad\nvalue"),
                     lambda c: c["web_targets"][0]["log_selector"].pop("runtime"),
                     lambda c: c.update(web_targets=[], postgres_targets=[])]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                config = defaults()
                mutate(config)
                with self.assertRaises(ValueError):
                    m3.render(config)

    def test_duplicate_and_overlapping_targets_are_rejected(self):
        for field in ("id", "alert_target", "selector"):
            config = defaults()
            other = deepcopy(config["web_targets"][0])
            other.update(id="other-web", alert_target="other-nginx")
            other["log_selector"]["container_name"] = "other"
            if field == "selector":
                pass  # A broad service selector already overlaps the narrower one.
            else:
                config["web_targets"][0]["log_selector"]["container_name"] = "first"
                other[field] = config["web_targets"][0][field]
            config["web_targets"].append(other)
            with self.subTest(field=field), self.assertRaises(ValueError):
                m3.render(config)

    def test_one_kind_can_be_deferred_without_disabling_the_other(self):
        for key in ("web_targets", "postgres_targets"):
            config = defaults()
            config[key] = []
            self.assertEqual(len(generated(config)), 1)

    def test_render_preserves_input_and_generated_file_matches(self):
        config = defaults()
        before = deepcopy(config)
        text = m3.render(config)
        self.assertEqual(config, before)
        self.assertEqual(text, m3.OUTPUT.read_text(encoding="utf-8"))
        self.assertNotIn(m3.OUTPUT, list((m3.ROOT / "monitoring").rglob("*.yml")))

    def test_cli_check_has_no_file_changes(self):
        before = m3.OUTPUT.read_bytes()
        result = subprocess.run([os.sys.executable, str(m3.ROOT / "tools/rulepack/generate_m3.py"), "--check"], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(m3.OUTPUT.read_bytes(), before)

    @unittest.skipUnless(LOGCLI, "M3_LOGCLI not set; native LogQL checks skipped")
    def test_native_full_expressions_parse_including_renamed_targets(self):
        config = defaults()
        config["web_targets"][0]["log_selector"]["container_name"] = 'web"\\name'
        for rule in generated() + generated(config):
            result = subprocess.run([LOGCLI, "fmt"], input=rule["expr"], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(LOGCLI, "M3_LOGCLI not set; native pipeline checks skipped")
    def test_native_sql_pipeline_on_synthetic_json_and_invalid_rows(self):
        rows = sql_fixtures()
        actual = native_matches(m3.pipeline("SQLInjection", defaults()["web_targets"][0]), rows)
        self.assertEqual(actual, {row["id"] for row in rows if row["expected"]})

    @unittest.skipUnless(LOGCLI, "M3_LOGCLI not set; native pipeline checks skipped")
    def test_native_db_pipeline_excludes_auth_pool_role_and_database_limits(self):
        rows = db_fixtures()
        actual = native_matches(m3.pipeline("DBConnectionLimit", defaults()["postgres_targets"][0]), rows)
        self.assertEqual(actual, {row["id"] for row in rows if row["expected"]})

    @unittest.skipUnless(LOGCLI, "M3_LOGCLI not set; native comparison skipped")
    def test_existing_sql_rule_overlap_and_intended_differences(self):
        source = yaml.safe_load((m3.ROOT / "monitoring/loki/rules/fake/security-rules.yml").read_text())
        baseline = next(rule for group in source["groups"] for rule in group["rules"] if rule.get("alert") == "SQLInjectionAttempt")
        query = re.fullmatch(r"\s*sum\(count_over_time\(\s*(.*?)\s*\[2m\]\s*\)\)\s*>\s*5\s*", baseline["expr"], re.S)[1]
        rows = [row for row in sql_fixtures() if row["id"] in {"union", "encoded-keyword", "comments", "user-agent-only"}]
        self.assertEqual(native_matches(query, rows), {"union", "user-agent-only"})
        self.assertEqual(native_matches(m3.pipeline("SQLInjection", defaults()["web_targets"][0]), rows), {"union", "encoded-keyword", "comments"})

    @unittest.skipUnless(LOGCLI, "M3_LOGCLI not set; native pipeline/window fixture checks skipped")
    def test_scope_and_time_window_fixtures_with_native_filtering(self):
        target = defaults()["web_targets"][0]
        base = {"request_uri": "/search?q=union+select"}
        rows = [fixture("at-left-boundary", base, True, time=0), fixture("in-window", base, True, time=1),
                fixture("at-now", base, True), fixture("future", base, True, time=121),
                fixture("other-service", base, True, labels={"service": "other", "runtime": "container", "log_format": "json"}),
                fixture("other-runtime", base, True, labels={"service": "frontend", "runtime": "host", "log_format": "json"})]
        labels = {**target["log_selector"], "log_format": "json"}
        # Fixture routing/time slicing is deliberately separate from LogCLI stdin:
        # stdin has neither real stream labels nor metric-window evaluation.
        selected = [row for row in rows if 0 < row["time"] <= 120 and all(row["labels"].get(k) == v for k, v in labels.items())]
        self.assertEqual(native_matches(m3.pipeline("SQLInjection", target), selected), {"in-window", "at-now"})
        self.assertEqual(native_matches(m3.pipeline("SQLInjection", target), []), set())

    @unittest.skipUnless(LOGCLI and PROMTOOL, "M3_LOGCLI/M3_PROMTOOL not set; native count/alert boundary checks skipped")
    def test_native_promql_count_boundary_alert_labels_and_resolution(self):
        rules = generated()
        series, alert_tests = [], []
        for rule, rows, key in zip(rules, (sql_fixtures(), db_fixtures()), ("web_targets", "postgres_targets")):
            count = len(native_matches(m3.pipeline(rule["alert"], defaults()[key][0]), rows))
            self.assertGreater(count, 0)
            # Replace ONLY the Loki range aggregation with an explicitly test-only
            # gauge. Native Prometheus now checks sum/comparison, timing and alert
            # metadata; it does not validate Loki range semantics or Ruler loading.
            metric = 'm3_fixture_matches{rule="' + rule["alert"] + '"}'
            rule["expr"] = re.sub(r"count_over_time\(.*\[2m\]\s*\)", metric, rule["expr"], flags=re.S)
            self.assertEqual(rule["expr"], "sum(" + metric + ") > 0")
            series.append({"series": metric, "values": f"0 1 {count} 0 stale"})
            for time, firing in (("0s", False), ("5s", True), ("10s", True), ("15s", False), ("20s", False)):
                alert_tests.append({"eval_time": time, "alertname": rule["alert"], "exp_alerts": [
                    {"exp_labels": rule["labels"], "exp_annotations": rule["annotations"]}] if firing else []})
        with tempfile.TemporaryDirectory(prefix="leafy-m3-") as directory:
            directory = Path(directory)
            rule_path = directory / "fixture.rules.yml"
            rule_path.write_text(yaml.safe_dump({"groups": [{"name": "m3-fixture-counts-only", "rules": rules}]}, allow_unicode=True))
            test_path = directory / "fixture.test.yml"
            test_path.write_text(yaml.safe_dump({"rule_files": [str(rule_path)], "evaluation_interval": "5s", "tests": [
                {"interval": "5s", "input_series": series, "alert_rule_test": alert_tests},
                {"interval": "5s", "input_series": [], "alert_rule_test": [
                    {"eval_time": "5s", "alertname": rule["alert"], "exp_alerts": []} for rule in rules]},
            ]}, allow_unicode=True))
            for args in (("check", "rules", str(rule_path)), ("test", "rules", str(test_path))):
                result = subprocess.run([PROMTOOL, *args], capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
