"""Offline rulepack checks using synthetic labels/counters, without application traffic.

Optional M2_PROMTOOL / M2_LOGCLI paths enable the upstream native validators.
"""

from copy import deepcopy
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

import yaml

MODULE = Path(__file__).resolve().parents[1] / "generate_m2.py"
spec = importlib.util.spec_from_file_location("m2_generator", MODULE)
m2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m2)


def defaults():
    return yaml.safe_load(m2.DEFAULT_CONFIG.read_text(encoding="utf-8"))


def rules(text):
    return yaml.safe_load(text)["groups"][0]["rules"]


def two_web_targets():
    config = defaults()
    config["web_targets"] = [
        {"id": f"web-{name}", "alert_target": f"nginx-{name}",
         "log_selector": {"service": "store-web", "runtime": "container", "container_name": f"nginx-{name}"},
         "metric_selector": {"job": "store-nginx", "instance": f"web-{name}:9113"}}
        for name in ("a", "b")
    ]
    return config


class GeneralizationTest(unittest.TestCase):
    def test_preserves_predicates_thresholds_windows_and_alert_timing(self):
        rendered = m2.render(defaults())
        expected = set(m2.WEB_LOG_RULES) | {m2.DB_LOG_RULE, m2.WEB_METRIC_RULE}
        found = set()
        for engine, source_path in m2.SOURCE_FILES.items():
            source = m2._source_rules(source_path, tuple(expected - {m2.WEB_METRIC_RULE}) if engine == "loki"
                                     else (m2.WEB_METRIC_RULE,))
            for rule in rules(rendered[f"{engine}.rules.yml"]):
                found.add(rule["alert"])
                baseline = source[rule["alert"]]
                normalize = lambda text: re.sub(r"\s+", "", re.sub(r"\{[^{}]*\}", "{}", text)
                                               .replace('| __error__=""', ''))
                # Strip only the newly scoped metric selector for the comparison.
                original = baseline["expr"]
                if engine == "prometheus":
                    original = original.replace("nginx_http_requests_total[", "nginx_http_requests_total{}[")
                self.assertEqual(normalize(rule["expr"]), normalize(original))
                self.assertEqual(rule.get("for"), baseline.get("for"))
                self.assertEqual(rule.get("keep_firing_for"), baseline.get("keep_firing_for"))
                self.assertEqual(rule["annotations"]["summary"], baseline["annotations"]["summary"])
                self.assertEqual({k: v for k, v in rule["labels"].items() if k != "rulepack_target"}, baseline["labels"])
        self.assertEqual(found, expected)

    def test_renamed_targets_need_no_leafy_names_or_service_role_labels(self):
        config = two_web_targets()
        config["postgres_targets"] = [{"id": "orders-db", "alert_target": "orders-host-db",
                                        "log_selector": {"service": "orders-postgres", "runtime": "host"}}]
        rendered = m2.render(config)
        self.assertNotIn("leafy", "".join(rendered.values()))
        for rule in rules(rendered["loki.rules.yml"]):
            self.assertNotIn("role=", rule["expr"])
            self.assertTrue(rule["annotations"]["container"])
        self.assertEqual(len(rules(rendered["loki.rules.yml"])), 5)
        self.assertEqual(len(rules(rendered["prometheus.rules.yml"])), 2)

    def test_same_service_host_and_container_db_are_explicitly_separate(self):
        config = defaults()
        config["postgres_targets"] = [
            {"id": "db-" + runtime, "alert_target": "postgres-" + runtime,
             "log_selector": {"service": "postgres", "runtime": runtime}}
            for runtime in ("host", "container")
        ]
        db_rules = [r for r in rules(m2.render(config)["loki.rules.yml"]) if r["alert"] == m2.DB_LOG_RULE]
        self.assertEqual(len(db_rules), 2)
        self.assertIn('runtime="host"', db_rules[0]["expr"])
        self.assertIn('runtime="container"', db_rules[1]["expr"])
        self.assertNotEqual(db_rules[0]["annotations"], db_rules[1]["annotations"])

    def test_ambiguous_source_selectors_are_rejected(self):
        for field in ("log_selector", "metric_selector"):
            config = two_web_targets()
            other = config["web_targets"][1]
            other[field] = {k: v for k, v in config["web_targets"][0][field].items()
                            if k in {"service", "job"}}
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "Overlapping"):
                m2.render(config)

    def test_duplicate_ids_or_pipeline_destinations_are_rejected(self):
        for key in ("id", "alert_target"):
            config = two_web_targets()
            config["web_targets"][1][key] = config["web_targets"][0][key]
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "unique"):
                m2.render(config)

    def test_unknown_collector_labels_and_unscoped_jobs_are_rejected(self):
        mutations = [
            lambda t: t["log_selector"].update(role="web"),
            lambda t: t["log_selector"].update(runtime="unknown"),
            lambda t: t["log_selector"].update(service="unknown"),
            lambda t: t["log_selector"].update(runtime="host", container_name="nginx"),
            lambda t: t["metric_selector"].pop("job"),
            lambda t: t["metric_selector"].update(instance="bad\nlabel"),
        ]
        for mutation in mutations:
            config = defaults()
            mutation(config["web_targets"][0])
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                m2.render(config)

    def test_selector_values_cannot_escape_their_quoted_literals(self):
        value = 'node\\path"} or vector(999) #'
        expression = m2.selector({"job": "nginx", "instance": value})
        self.assertIn('instance="node\\\\path\\\"} or vector(999) #"', expression)

    def test_generation_is_deterministic_and_leaves_inputs_unchanged(self):
        config = defaults()
        snapshot = deepcopy(config)
        sources = {p: p.read_bytes() for p in m2.SOURCE_FILES.values()}
        self.assertEqual(m2.render(config), m2.render(config))
        self.assertEqual(config, snapshot)
        self.assertEqual(sources, {p: p.read_bytes() for p in sources})

    def test_committed_drafts_match_generator(self):
        for name, text in m2.render(defaults()).items():
            self.assertEqual((m2.DEFAULT_OUTPUT / name).read_text(encoding="utf-8"), text)


@unittest.skipUnless(os.getenv("M2_PROMTOOL"), "M2_PROMTOOL not configured")
class NativePrometheusTest(unittest.TestCase):
    def test_per_target_isolation_threshold_boundary_pending_and_no_data(self):
        config = two_web_targets()
        with tempfile.TemporaryDirectory(prefix="leafy-m2-promtool-") as directory:
            root = Path(directory)
            (root / "rules.yml").write_text(m2.render(config)["prometheus.rules.yml"])
            def series(instance, step, job="store-nginx"):
                return {"series": f'nginx_http_requests_total{{job="{job}",instance="{instance}"}}',
                        "values": f"0+{step}x24"}
            expected_a = {"exp_labels": {"job": "store-nginx", "instance": "web-a:9113",
                                          "severity": "warning", "category": "security", "rulepack_target": "web-a"},
                          "exp_annotations": {"summary": "Nginx 요청량 급증 (잠재적 SQLi/DDoS/스캔)", "container": "nginx-a"}}
            expected_b = deepcopy(expected_a)
            expected_b["exp_labels"].update(instance="web-b:9113", rulepack_target="web-b")
            expected_b["exp_annotations"]["container"] = "nginx-b"
            tests = {"rule_files": ["rules.yml"], "evaluation_interval": "5s", "tests": [
                {"interval": "5s", "input_series": [series("web-a:9113", 155), series("web-b:9113", 100),
                                                       series("unmapped:9113", 500), series("web-b:9113", 500, "other-job")],
                 # The counter starts at zero; its full 1m rate reaches 31/s at 1m.
                 "alert_rule_test": [{"eval_time": "1m25s", "alertname": m2.WEB_METRIC_RULE, "exp_alerts": []},
                                     {"eval_time": "1m30s", "alertname": m2.WEB_METRIC_RULE, "exp_alerts": [expected_a]}]},
                {"interval": "5s", "input_series": [series("web-a:9113", 100), series("web-b:9113", 155)],
                 "alert_rule_test": [{"eval_time": "1m30s", "alertname": m2.WEB_METRIC_RULE, "exp_alerts": [expected_b]}]},
                {"interval": "5s", "input_series": [series("web-a:9113", 150)],
                 "alert_rule_test": [{"eval_time": "2m", "alertname": m2.WEB_METRIC_RULE, "exp_alerts": []}]},
                {"interval": "5s", "input_series": [],
                 "alert_rule_test": [{"eval_time": "1m", "alertname": m2.WEB_METRIC_RULE, "exp_alerts": []}]},
            ]}
            (root / "test.yml").write_text(yaml.safe_dump(tests, allow_unicode=True))
            result = subprocess.run([os.environ["M2_PROMTOOL"], "test", "rules", "test.yml"],
                                    cwd=root, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


@unittest.skipUnless(os.getenv("M2_LOGCLI"), "M2_LOGCLI not configured")
class NativeLogQLTest(unittest.TestCase):
    def test_all_default_and_renamed_target_expressions_parse(self):
        configs = [defaults(), two_web_targets()]
        # Quotes and backslashes in an instance name must remain string literals.
        configs[1]["web_targets"][0]["log_selector"]["container_name"] = 'nginx\\a"test'
        for config in configs:
            for rule in rules(m2.render(config)["loki.rules.yml"]):
                with self.subTest(alert=rule["alert"], target=rule["labels"]["rulepack_target"]):
                    result = subprocess.run([os.environ["M2_LOGCLI"], "fmt"], input=rule["expr"],
                                            capture_output=True, text=True, timeout=15)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(result.stdout.strip())


if __name__ == "__main__":
    unittest.main()
