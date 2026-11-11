"""Integration fixtures only: no real addresses, services, Docker, DB or LLM."""
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

import yaml

sys.path.insert(0, str(Path(__file__).parents[1]))
import prepare_release as release
import acceptance_m5b as acceptance

PROMTOOL = os.getenv("M5_PROMTOOL")
LOGCLI = os.getenv("M5_LOGCLI")


def profile(site="fixture-gc"):
    return {"version": 1, "inventory_verified": True,
            "gc": {"site": site, "source": site + "-docker", "project": "fixture-project",
                   "targets": {"backend": {"name": "fixture-backend", "id": "a" * 64},
                               "frontend": {"name": "fixture-frontend", "id": "b" * 64},
                               "minio": {"name": "fixture-minio", "id": "c" * 64}}},
            "telemetry": {"job": "fixture-telemetry", "instance": site + ".invalid:9108"},
            "host_postgres": {"site": site, "source": site + "-pg", "target": "fixture-pg17",
                              "dedicated_receiver_verified": True}}


def rules(bundle, name="prometheus.rules.yml"):
    return [r for g in yaml.safe_load(bundle[name])["groups"] for r in g["rules"]]


def save(directory, bundle):
    for name, text in bundle.items():
        path = Path(directory) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


class ReleaseIdentityTests(unittest.TestCase):
    def test_placeholder_or_unattested_profile_refused(self):
        template = json.loads((release.ROOT / "docs/rulepack/integration/profile.template.json").read_text())
        with self.assertRaises(ValueError): release.render(template)
        p = profile(); p["inventory_verified"] = False
        with self.assertRaises(ValueError): release.render(p)

    def test_duplicate_ids_names_and_host_alias_conflicts_refused(self):
        for field in ("name", "id"):
            p = profile(); p["gc"]["targets"]["frontend"][field] = p["gc"]["targets"]["backend"][field]
            with self.assertRaises(ValueError): release.render(p)
        for field, text in (("source", "fixture-gc-docker"), ("target", "fixture-backend")):
            p = profile(); p["host_postgres"][field] = text
            with self.assertRaises(ValueError): release.render(p)

    def test_bad_endpoints_and_host_receiver_refused(self):
        for endpoint in ("http://user:secret@host", "host:99999", "REPLACE_HOST:9108", "host:0"):
            p = profile(); p["telemetry"]["instance"] = endpoint
            with self.assertRaises(ValueError): release.render(p)
        p = profile(); p["host_postgres"]["dedicated_receiver_verified"] = False
        with self.assertRaises(ValueError): release.render(p)

    def test_generator_does_not_mutate_profile_and_is_deterministic(self):
        p = profile(); original = deepcopy(p)
        self.assertEqual(release.render(p), release.render(p))
        self.assertEqual(p, original)

    def test_all_alerts_keep_identity_and_scoped_inputs(self):
        b = release.render(profile())
        for r in rules(b) + rules(b, "loki/fake/release.rules.yml"):
            self.assertTrue(set(release.FIELDS) <= r["labels"].keys())
            selectors = acceptance.SELECTOR.findall(r["expr"])
            self.assertTrue(selectors)
            for selector in selectors:
                self.assertIn('site="fixture-gc"', selector)
                self.assertRegex(selector, r'source="fixture-gc-(?:docker|pg)"')
        for r in rules(b):
            self.assertNotIn("by (name)", r["expr"])

    def test_gc_contract_and_host_metrics_are_separate(self):
        b = release.render(profile())
        bindings = release.parse_bindings(b["bindings.json"])
        self.assertEqual(len(bindings), 5)
        for binding in bindings[:3]:
            self.assertEqual(binding.metrics_profile, "gc-telemetry-v1")
            self.assertEqual(binding.identity.to_dict()["source"], "fixture-gc-docker")
            self.assertTrue(set(release.FIELDS) <= binding.metrics.keys())
        self.assertEqual(bindings[-1].identity.runtime, "host")
        self.assertEqual(bindings[-1].metrics, {})
        self.assertEqual(bindings[-1].identity.target, "fixture-pg17")

    def test_am_and_compose_do_not_merge_old_rules_or_enable_actions(self):
        b = release.render(profile())
        am = yaml.safe_load(b["alertmanager.yml"])
        self.assertEqual(set(am["route"]["group_by"]), {"alertname", *release.FIELDS})
        self.assertEqual(am["receivers"][0]["webhook_configs"][0]["url"], "http://pipeline:8000/webhook/alert")
        override = yaml.safe_load(b["jh.compose.override.yml"])["services"]
        self.assertEqual(override["remediation"]["environment"]["REMEDIATION_MODE"], "disabled")
        self.assertEqual(override["pipeline"]["environment"]["SLACK_WEBHOOK_URL"], "")
        self.assertIn("empty-prometheus-rules", str(override["prometheus"]["volumes"]))
        self.assertNotIn("pipeline-metadata", b["prometheus.yml"])
        self.assertEqual(yaml.safe_load(b["prometheus.yml"])["global"]["evaluation_interval"], "5s")

    def test_thresholds_windows_and_hold_times_preserved(self):
        p = profile(); b = release.render(p)
        originals = {r["alert"]: r for r in release.infra.source_rules().values()}
        originals.update({r["alert"]: r for r in release.resources.source_rules().values()})
        for r in rules(b):
            original = originals[r["alert"]]
            for key in ("for", "keep_firing_for"):
                self.assertEqual(r.get(key), original.get(key))
            # Compare numbers outside selectors/label names; identity rewrites
            # cannot silently change thresholds, ranges, offsets or reset math.
            strip = lambda text: re.sub(r"\{[^{}]*\}", "{}", text)
            self.assertEqual(re.findall(r"\b\d+(?:\.\d+)?(?:e\d+)?\b", strip(r["expr"])),
                             re.findall(r"\b\d+(?:\.\d+)?(?:e\d+)?\b", strip(original["expr"])))

    def test_log_channel_is_separate_and_driver_labels_are_required(self):
        b = release.render(profile())
        self.assertIn("source         $._lbl_observation_source", b["fluent.conf"])
        self.assertIn("log_stream     $._lbl_source", b["fluent.conf"])
        self.assertIn('target "fixture-pg17"', b["fluent.conf"])
        logging = yaml.safe_load(b["gc.logging.override.yml"])
        for service in logging["services"].values():
            self.assertEqual(service["labels"]["aiops.source"], "fixture-gc-docker")
            self.assertIn("aiops.site,aiops.source", service["logging"]["options"]["labels"])

    def test_missing_pg_is_excluded_without_inventing_a_target(self):
        p = profile(); p["host_postgres"] = None
        b = release.render(p)
        self.assertNotIn("DBConnectionLimit", b["loki/fake/release.rules.yml"])
        self.assertNotIn("fixture-pg17", b["bindings.json"])
        m = json.loads(b["manifest.json"])
        self.assertFalse(m["deployment_allowed"])
        self.assertFalse(m["runtime_accepted"])
        self.assertTrue(any("PostgreSQL inventory" in x for x in m["excluded"]))

    def test_acceptance_plan_uses_exact_bundle_and_detects_drift(self):
        b = release.render(profile())
        with tempfile.TemporaryDirectory() as directory:
            save(directory, b)
            p = acceptance.plan(directory)
            self.assertEqual(len(p["rules"]), len(rules(b)) + len(rules(b, "loki/fake/release.rules.yml")))
            self.assertIsNone(p["legacy_sql_expr"])
            (Path(directory) / "prometheus.rules.yml").write_text("groups: []")
            with self.assertRaises(ValueError): acceptance.plan(directory)

    def test_duplicate_loaded_definition_cannot_pass_acceptance(self):
        state = acceptance.stages({"inputs": [], "evaluation": "unused", "exact_definition_loaded": False,
                                   "matching_definition_count": 2}, {})
        self.assertEqual(state["RULE_LOADED"], "FAIL")

    @unittest.skipUnless(PROMTOOL and LOGCLI, "native validators missing")
    def test_native_prometheus_config_and_all_logql_expressions(self):
        b = release.render(profile())
        with tempfile.TemporaryDirectory() as directory:
            save(directory, b)
            p = Path(directory)
            config = yaml.safe_load(b["prometheus.yml"])
            config["rule_files"] = [str(p / "prometheus.rules.yml")]
            config["scrape_configs"][0]["file_sd_configs"][0]["files"] = [str(p / "targets.json")]
            (p / "validation.yml").write_text(yaml.safe_dump(config))
            result = subprocess.run([PROMTOOL, "check", "config", str(p / "validation.yml")], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for rule in rules(b, "loki/fake/release.rules.yml"):
                result = subprocess.run([LOGCLI, "fmt"], input=rule["expr"], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def native(self, input_series, queries):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tests.yml"
            path.write_text(yaml.safe_dump({"evaluation_interval": "5s", "tests": [{
                "interval": "5s", "input_series": input_series, "promql_expr_test": queries}]}))
            result = subprocess.run([PROMTOOL, "test", "rules", str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(PROMTOOL, "native promtool missing")
    def test_native_same_name_id_two_sites_cpu_memory_and_network_do_not_mix(self):
        series, queries = [], []
        for site in ("fixture-gc", "fixture-jh"):
            p = profile(site); gc = p["gc"]
            ident = release.identity(gc, "backend", "fixture-backend")
            labels = {**ident, **p["telemetry"], "id": "/docker/" + "a" * 64, "name": "fixture-backend"}
            def s(metric, values, extra=None):
                label = ",".join(k + "=" + json.dumps(v) for k, v in {**labels, **(extra or {})}.items())
                series.append({"series": metric + "{" + label + "}", "values": values})
            s("container_cpu_usage_seconds_total", "0+4x24", {"cpu": "total"})
            s("container_name_info", "1+0x24")
            s("container_memory_working_set_bytes", "900+0x24")
            s("container_spec_memory_limit_bytes", "1000+0x24")
            s("container_network_receive_bytes_total", "0+100000000x24", {"interface": "eth0"})
            expected = {**ident, "name": "fixture-backend"}
            for rule in rules(release.render(p)):
                if rule["alert"] not in ("HighCpuUsage", "HighMemoryUsage", "HighNetworkReceive"):
                    continue
                if rule["labels"].get("rulepack_target", "backend") != "backend": continue
                queries.append({"expr": rule["expr"], "eval_time": "2m", "exp_samples": [{
                    "labels": "{" + ",".join(k + "=" + json.dumps(v) for k, v in expected.items()) + "}",
                    "value": {"HighCpuUsage": .8, "HighMemoryUsage": .9, "HighNetworkReceive": 2e7}[rule["alert"]]}]})
        self.native(series, queries)

    @unittest.skipUnless(PROMTOOL, "native promtool missing")
    def test_native_root_fallback_is_vm_host_and_lo_suppresses_it(self):
        p = profile(); expr = next(r["expr"] for r in rules(release.render(p)) if r["alert"] == "HighNetworkReceive")
        labels = {"site": "fixture-gc", "source": "fixture-gc-docker", "runtime": "host",
                  "service": "docker-vm", "target": "docker-vm", "id": "/", **p["telemetry"]}
        def label(values): return "{" + ",".join(k + "=" + json.dumps(v) for k, v in values.items()) + "}"
        series = [{"series": "container_network_receive_bytes_total" + label({**labels, "interface": "eth0"}),
                   "values": "0+100000000x24"}]
        self.native(series, [{"expr": expr, "eval_time": "2m", "exp_samples": [{"labels": label(labels), "value": 2e7}]}])
        series.append({"series": "container_network_receive_bytes_total" + label({**labels, "id": "/docker/" + "a" * 64,
                       "runtime": "container", "interface": "lo"}), "values": "0+0x24"})
        self.native(series, [{"expr": expr, "eval_time": "2m", "exp_samples": []}])

    @unittest.skipUnless(PROMTOOL, "native promtool missing")
    def test_native_memory_alert_identity_templates_and_five_minute_hold(self):
        p = profile(); bundle = release.render(p)
        rule = next(r for r in rules(bundle) if r["alert"] == "HighMemoryUsage")
        ident = release.identity(p["gc"], "backend", "fixture-backend")
        labels = {**ident, **p["telemetry"], "id": "/docker/" + "a" * 64, "name": "fixture-backend"}
        text = "{" + ",".join(k + "=" + json.dumps(v) for k, v in labels.items()) + "}"
        expected = {**ident, "name": "fixture-backend", "severity": "warning", "category": "infra", "rulepack_source": "gc"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "rules.yml").write_text(yaml.safe_dump({"groups": [{"name": "memory-fixture", "interval": "5s", "rules": [rule]}]}))
            annotations = {**rule["annotations"], "container": "fixture-backend"}
            data = {"rule_files": [str(path / "rules.yml")], "evaluation_interval": "5s", "tests": [{
                "interval": "5s", "input_series": [{"series": metric + text, "values": value + "+0x72"} for metric, value in (
                    ("container_memory_working_set_bytes", "900"), ("container_spec_memory_limit_bytes", "1000"), ("container_name_info", "1"))],
                "alert_rule_test": [{"eval_time": "4m55s", "alertname": "HighMemoryUsage", "exp_alerts": []},
                                    {"eval_time": "5m", "alertname": "HighMemoryUsage", "exp_alerts": [
                                        {"exp_labels": expected, "exp_annotations": annotations}]}]}]}
            (path / "tests.yml").write_text(yaml.safe_dump(data))
            result = subprocess.run([PROMTOOL, "test", "rules", str(path / "tests.yml")], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__": unittest.main()
