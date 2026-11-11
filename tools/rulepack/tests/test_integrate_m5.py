"""M5-A offline assembly regression; no services, scenarios or application traffic.

M5_PROMTOOL/M5_LOGCLI enable native tests. Integrated files themselves are tested;
component fixtures are synthetic helpers, never baseline measurements.
"""

from contextlib import redirect_stderr
from copy import deepcopy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


DIRECTORY = Path(__file__).resolve().parent
m5 = load("m5_integration", DIRECTORY.parent / "integrate_m5.py")
infra_tests = load("m5_infra_fixtures", DIRECTORY / "test_generate_m2_2.py")
resource_tests = load("m5_resource_fixtures", DIRECTORY / "test_generate_m2_3.py")
log_tests = load("m5_log_fixtures", DIRECTORY / "test_generate_m3.py")
PROMTOOL, LOGCLI = os.getenv("M5_PROMTOOL"), os.getenv("M5_LOGCLI")


def defaults():
    return yaml.safe_load(m5.CONFIG.read_text(encoding="utf-8"))


def document(engine):
    return yaml.safe_load((m5.OUTPUT / f"generated/{engine}.rules.yml").read_text(encoding="utf-8"))


def active(engine):
    return m5.flattened(document(engine))


def rule(name, target=None):
    return next(r for r in active("prometheus") if r["alert"] == name and (target is None or r["labels"].get("rulepack_target") == target))


def expected(name, labels, target=None):
    source = rule(name, target)
    annotations = deepcopy(source["annotations"])
    if name in {"HighMemoryUsage", "HighNetworkReceive"}:
        annotations["container"] = labels.get("name", "unknown (host-level)")
    return {"exp_labels": {**labels, **source["labels"]}, "exp_annotations": annotations}


def series(metric, labels, values):
    return {"series": metric + resource_tests.m2.selector(labels), "values": values}


def check(name, when, alerts):
    return {"alertname": name, "eval_time": when, "exp_alerts": alerts}


def full_input(high=True):
    inputs = []
    for name in ("leafy-frontend", "leafy-backend", "leafy-db", "leafy-minio"):
        peak = high and name in {"leafy-frontend", "leafy-backend"}
        inputs += infra_tests.cpu_input(name, usage=.8 if peak else .2)
        inputs += resource_tests.memory_input(name, working=90 if peak else 20, metadata=False)
        inputs += resource_tests.network_input(name, bps=20e6 if high and name == "leafy-frontend" else 1e6)
    inputs += infra_tests.restart_input(counters=infra_tests.steps({0: 0, 12: 1, 24: 2}) if high else None)
    inputs += resource_tests.network_input(None, bps=30e6)
    inputs.append(series("nginx_http_requests_total", {"job": "nginx-exporter", "instance": "nginx-exporter:9113"}, "0+" + ("200" if high else "50") + "x180"))
    inputs.append(series("pg_stat_activity_count", {"job": "postgres-exporter", "instance": "postgres-exporter:9187", "datname": "fixture", "state": "idle"}, ("45" if high else "15") + "+0x180"))
    return inputs


class M5AssemblyTest(unittest.TestCase):
    def test_inventory_disposition_and_reference_separation(self):
        result = m5.render(defaults())
        manifest = json.loads(result["manifest.json"])
        self.assertEqual(manifest["counts"], {"original_names": 17, "m2_replaced_names": 8, "legacy_sql_reference_names": 1,
            "retained_original_definitions": 8, "active_definitions": 21, "unique_active_names": 18, "definitions_by_engine": {"loki": 12, "prometheus": 9}})
        self.assertEqual(len(manifest["original_disposition"]), 17)
        self.assertFalse(manifest["deployment_allowed"])
        self.assertTrue(all(name.startswith("generated/") for name in manifest["active_files"]))
        self.assertNotIn("SQLInjectionAttempt", {r["alert"] for r in active("loki")})
        reference = m5.flattened(yaml.safe_load(result["reference/loki.legacy-sqli.rules.yml"]))
        self.assertEqual([r["alert"] for r in reference], ["SQLInjectionAttempt"])
        self.assertEqual(sum(r["alert"] == "HighCpuUsage" for r in active("prometheus")), 4)

    def test_every_active_rule_is_an_exact_input_object(self):
        manifest = json.loads(m5.render(defaults())["manifest.json"])
        found = []
        for engine in ("loki", "prometheus"):
            for output in active(engine):
                entry = next(e for e in manifest["entries"] if e["engine"] == engine and e["alert"] == output["alert"] and e["labels"] == output["labels"])
                source = m5.read_document(m5.ROOT / entry["origin"])
                origin = next(g for g in source["groups"] if g["name"] == entry["origin_group"])["rules"][entry["origin_index"]]
                self.assertEqual(output, origin)
                self.assertEqual(entry["rule_sha256"], hashlib.sha256(json.dumps(output, sort_keys=True, ensure_ascii=False).encode()).hexdigest())
                found.append(entry)
        self.assertEqual(len(found), 21)

    def test_group_intervals_and_rule_timing_are_preserved(self):
        for engine in ("loki", "prometheus"):
            for group in document(engine)["groups"]:
                component = next(key for key in {**m5.ORIGINALS, **m5.DRAFTS} if group["name"].startswith("m5-" + key + "-"))
                source_path = {**m5.ORIGINALS, **m5.DRAFTS}[component][1]
                source_group = next(g for g in m5.read_document(m5.ROOT / source_path)["groups"] if group["name"] == "m5-" + component + "-" + g["name"])
                self.assertEqual({k: v for k, v in group.items() if k not in {"name", "rules"}}, {k: v for k, v in source_group.items() if k not in {"name", "rules"}})
        self.assertEqual(rule("ContainerRestarted")["keep_firing_for"], "2m")

    def test_duplicate_static_identity_and_exact_predicate_are_rejected(self):
        for change_identity in (False, True):
            docs = {engine: deepcopy(document(engine)) for engine in ("loki", "prometheus")}
            duplicate = deepcopy(docs["prometheus"]["groups"][0]["rules"][0])
            if change_identity:
                duplicate["alert"] = "DifferentAlertSameCondition"
            docs["prometheus"]["groups"][0]["rules"].append(duplicate)
            with self.subTest(change_identity=change_identity), self.assertRaises(ValueError):
                m5.validate_bundle(docs)
        docs = {engine: deepcopy(document(engine)) for engine in ("loki", "prometheus")}
        docs["loki"]["groups"].append(deepcopy(docs["loki"]["groups"][0]))
        with self.assertRaises(ValueError):
            m5.validate_bundle(docs)

    def test_upstream_drift_is_refused_without_writing_any_draft(self):
        target = m5.ROOT / m5.DRAFTS["m2_logs"][1]
        before = target.read_bytes()
        original = Path.read_text
        def changed(path, *args, **kwargs):
            text = original(path, *args, **kwargs)
            return text + "\n# fixture drift" if path == target else text
        with patch.object(Path, "read_text", changed), self.assertRaisesRegex(ValueError, "Upstream draft drift"):
            m5.render(defaults())
        self.assertEqual(target.read_bytes(), before)

    def test_deterministic_manifest_hashes_input_immutability_and_check(self):
        config = defaults()
        before = deepcopy(config)
        first = m5.render(config)
        self.assertEqual(first, m5.render(config))
        self.assertEqual(config, before)
        for name, text in first.items():
            self.assertEqual((m5.OUTPUT / name).read_text(encoding="utf-8"), text)
        manifest = json.loads(first["manifest.json"])
        for name, value in manifest["outputs_sha256"].items():
            self.assertEqual(hashlib.sha256(first[name].encode()).hexdigest(), value)
        for name, value in manifest["inputs_sha256"].items():
            self.assertEqual(hashlib.sha256((m5.ROOT / name).read_bytes()).hexdigest(), value)

    def test_invalid_policy_and_stale_output_check_are_non_mutating(self):
        for policy in (None, {"version": True, "sql_injection_policy": "m3_primary_legacy_reference"},
                       {"version": 1, "sql_injection_policy": "load_both"}, {**defaults(), "runtime_reload": True}):
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                m5.render(policy)
        with tempfile.TemporaryDirectory(prefix="leafy-m5-drift-") as directory:
            path = Path(directory) / "generated/loki.rules.yml"
            path.parent.mkdir()
            path.write_text("fixture sentinel\n", encoding="utf-8")
            with patch.object(m5, "OUTPUT", Path(directory)), patch("sys.argv", ["integrate_m5.py", "--check"]), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
                m5.main()
            self.assertEqual(result.exception.code, 2)
            self.assertEqual(path.read_text(encoding="utf-8"), "fixture sentinel\n")

    def test_runtime_warnings_and_deferred_inputs_survive_integration(self):
        manifest = json.loads(m5.render(defaults())["manifest.json"])
        warnings = {w["id"]: w for w in manifest["warnings"]}
        self.assertIn("leafy-db", warnings["HOST_CONTAINER_ALIAS_CONFLICT"]["aliases"])
        self.assertIn("PIPELINE_SOURCE_AND_HOST_ROUTING", warnings)
        self.assertIn("BASELINE_NOT_USED", warnings)
        self.assertIn("LoginBruteForce", manifest["deferred"])
        self.assertFalse(any("LoginBruteForce" == r["alert"] for r in active("loki")))

    def test_conflicting_shared_sources_and_log_role_aliases_are_rejected(self):
        configs = [yaml.safe_load((m5.ROOT / name).read_text(encoding="utf-8")) for name in (
            "docs/rulepack/m2/targets.yml", "docs/rulepack/m2/infra_targets.yml",
            "docs/rulepack/m2/resource_targets.yml", "docs/rulepack/m3/targets.yml")]
        checks = m5.validate_cross_component_mappings(*configs)
        self.assertEqual(checks["shared_source_ids_checked"], ["integrated"])
        changed = deepcopy(configs)
        changed[2]["sources"]["integrated"]["cadvisor"]["instance"] = "different-scope:8080"
        with self.assertRaises(ValueError):
            m5.validate_cross_component_mappings(*changed)
        changed = deepcopy(configs)
        changed[3]["web_targets"][0]["log_selector"]["service"] = "other-web"
        with self.assertRaises(ValueError):
            m5.validate_cross_component_mappings(*changed)

    @unittest.skipUnless(PROMTOOL, "M5_PROMTOOL not set; native Prometheus checks skipped")
    def test_native_prometheus_bundle_syntax(self):
        result = subprocess.run([PROMTOOL, "check", "rules", str(m5.OUTPUT / "generated/prometheus.rules.yml")], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(LOGCLI, "M5_LOGCLI not set; native LogQL parser skipped")
    def test_native_all_candidate_and_reference_logql_expressions(self):
        reference = m5.flattened(m5.read_document(m5.OUTPUT / "reference/loki.legacy-sqli.rules.yml"))
        for source in active("loki") + reference:
            result = subprocess.run([LOGCLI, "fmt"], input=source["expr"], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, source["alert"] + result.stderr)

    @unittest.skipUnless(LOGCLI, "M5_LOGCLI not set; native synthetic log regression skipped")
    def test_native_integrated_sql_db_and_http_pipelines(self):
        def pipeline(source):
            match = re.fullmatch(r"\s*sum\(count_over_time\(\s*(.*?)\s*\[(?:1|2)m\]\s*\)\)\s*>\s*\d+\s*", source["expr"], re.S)
            self.assertIsNotNone(match, source["alert"])
            return match[1]
        with patch.object(log_tests, "LOGCLI", LOGCLI):
            for name, fixtures in (("SQLInjection", log_tests.sql_fixtures()), ("DBConnectionLimit", log_tests.db_fixtures())):
                source = next(r for r in active("loki") if r["alert"] == name)
                self.assertEqual(log_tests.native_matches(pipeline(source), fixtures), {row["id"] for row in fixtures if row["expected"]})
            fixtures = [log_tests.fixture("server", {"status": "500"}, True), log_tests.fixture("client", {"status": "404"}, True),
                        log_tests.fixture("ok", {"status": "200"}, False), log_tests.fixture("numeric-error", {"status": "invalid"}, False)]
            for name, matched in (("HighNginxErrorRate", {"server"}), ("VulnerabilityScanningDetected", {"client"})):
                source = next(r for r in active("loki") if r["alert"] == name)
                self.assertEqual(log_tests.native_matches(pipeline(source), fixtures), matched)

    def native_cases(self, tests, expect_error=False):
        with tempfile.TemporaryDirectory(prefix="leafy-m5-prom-") as directory:
            path = Path(directory) / "matrix.yml"
            path.write_text(yaml.safe_dump({"rule_files": [str(m5.OUTPUT / "generated/prometheus.rules.yml")], "evaluation_interval": "5s", "tests": tests}, allow_unicode=True), encoding="utf-8")
            result = subprocess.run([PROMTOOL, "test", "rules", str(path)], capture_output=True, text=True, timeout=30)
            if expect_error:
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("many-to-many", result.stdout + result.stderr)
            else:
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(PROMTOOL, "M5_PROMTOOL not set; integrated synthetic concurrency skipped")
    def test_native_concurrent_targets_and_all_metric_rule_families(self):
        cpu = [expected("HighCpuUsage", {"name": name}, name) for name in ("leafy-frontend", "leafy-backend")]
        memory = [expected("HighMemoryUsage", {"name": name}) for name in ("leafy-frontend", "leafy-backend")]
        checks = [check("HighCpuUsage", "30s", []), check("HighCpuUsage", "35s", cpu), check("HighCpuUsage", "6m", cpu),
                  check("HighMemoryUsage", "4m55s", []), check("HighMemoryUsage", "5m", memory), check("HighMemoryUsage", "6m", memory),
                  check("ContainerRestarted", "6m", [expected("ContainerRestarted", {"name": "leafy-backend"})]),
                  check("HighNetworkReceive", "6m", [expected("HighNetworkReceive", {"name": "leafy-frontend"})]),
                  check("HighNginxRequestRate", "6m", [expected("HighNginxRequestRate", {"job": "nginx-exporter", "instance": "nginx-exporter:9113"})]),
                  check("HighPostgresConnections", "6m", [expected("HighPostgresConnections", {"job": "postgres-exporter", "instance": "postgres-exporter:9187", "datname": "fixture", "state": "idle"})])]
        self.native_cases([{"name": "synthetic-concurrent-only", "interval": "5s", "input_series": full_input(), "alert_rule_test": checks}])

    @unittest.skipUnless(PROMTOOL, "M5_PROMTOOL not set; normal/missing/source regression skipped")
    def test_native_normal_missing_and_other_job_inputs(self):
        all_names = sorted({r["alert"] for r in active("prometheus")})
        other = deepcopy(infra_tests.defaults()["sources"]["integrated"])
        other["cadvisor"]["job"] = "unmapped-cadvisor"
        missing_metadata = infra_tests.cpu_input(metadata=False) + resource_tests.memory_input(metadata=False)
        tests = [{"name": name, "interval": "5s", "input_series": data, "alert_rule_test": [check(alert, "6m", []) for alert in all_names]}
                 for name, data in (("synthetic-low-values", full_input(False)), ("no-input", []), ("missing-metadata", missing_metadata),
                                    ("other-job", infra_tests.cpu_input(source=other)))]
        self.native_cases(tests)

    @unittest.skipUnless(PROMTOOL, "M5_PROMTOOL not set; host/DB dimension regression skipped")
    def test_native_host_fallback_and_individual_database_series_semantics(self):
        root = resource_tests.network_input(None, bps=30e6)
        pg = [series("pg_stat_activity_count", {"job": "postgres-exporter", "instance": "postgres-exporter:9187", "datname": "fixture", "state": state}, str(value) + "+0x100") for state, value in (("active", 30), ("idle", 16))]
        self.native_cases([
            {"name": "root-only", "interval": "5s", "input_series": root, "alert_rule_test": [check("HighNetworkReceive", "6m", [expected("HighNetworkReceive", {"id": "/", "job": "cadvisor", "instance": "cadvisor:8080"})])]},
            {"name": "unnamed-loopback-blocks-root", "interval": "5s", "input_series": root + resource_tests.network_input("", interface="lo", cid="/docker/unselected"), "alert_rule_test": [check("HighNetworkReceive", "6m", [])]},
            {"name": "pg-states-total-46-individually-under-40", "interval": "5s", "input_series": pg, "alert_rule_test": [check("HighPostgresConnections", "6m", [])]},
        ])

    @unittest.skipUnless(PROMTOOL, "M5_PROMTOOL not set; expected metadata join error skipped")
    def test_native_duplicate_metadata_remains_an_error_in_combined_bundle(self):
        data = infra_tests.cpu_input()
        data.append(series("container_name_info", {"job": "pipeline-metadata", "instance": "pipeline:8000", "id": "/docker/leafy-backend", "name": "leafy-frontend"}, "1+0x180"))
        self.native_cases([{"interval": "5s", "input_series": data, "alert_rule_test": [check("HighCpuUsage", "1m", [])]}], expect_error=True)


if __name__ == "__main__":
    unittest.main()
