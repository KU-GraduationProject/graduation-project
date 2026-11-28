"""Offline signal contracts and native synthetic regressions, never deployment."""
from copy import deepcopy
import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

sys.path.insert(0, str(Path(__file__).parents[1]))
import prepare_release as release
import scenario_v2 as v2
from test_release_identity import profile, rules

LOGCLI = os.getenv("M5_LOGCLI")
PROMTOOL = os.getenv("M5_PROMTOOL")


def config():
    return {"version": 1, "thresholds": dict(v2.DEFAULTS),
            "network": {"observer": "fixture-observer", "observer_instance": "fixture-capture", "mapping_verified": True},
            "postgres_exporter": {"job": "fixture-postgres", "instance": "fixture-pg.invalid:9187",
                                  "database": "fixture", "metrics_verified": True}}


def policy():
    return yaml.safe_load((release.ROOT / "aiops/policy/allowlist.yml").read_text())


def event(**changes):
    return {"fixture_id": "base", "observer": "fixture-observer", "observer_instance": "fixture-capture",
            "src_container": "fixture-backend", "src_service": "backend", "event_type": "connection",
            "dst_service": "unknown", "dst_ip": "192.0.2.9", "dst_port": 8080,
            "connection_id": "fixture-connection", "bytes_sent": 240, **changes}


def native_matches(pipeline, rows):
    payload = "\n".join(json.dumps(r, ensure_ascii=False) if isinstance(r, dict) else r for r in rows)
    env = {k: v for k, v in os.environ.items() if not k.startswith("LOKI_")}
    r = subprocess.run([LOGCLI, "--stdin", "--quiet", "--addr=http://127.0.0.1:1", "--output=raw", "query", pipeline],
                       input=payload + "\n", text=True, capture_output=True, timeout=30, env=env)
    if r.returncode:
        raise AssertionError(r.stderr)
    return {json.loads(line)["fixture_id"] for line in r.stdout.splitlines()}


class ScenarioV2Tests(unittest.TestCase):
    def test_bundle_integration_identity_bindings_and_no_double_4xx_rule(self):
        p, c = profile(), config()
        before = deepcopy((p, c))
        b = release.render(p, c)
        self.assertEqual((p, c), before)
        self.assertEqual(b, release.render(p, c))
        logs = rules(b, "loki/fake/release.rules.yml")
        expected = {"V2ReconScan", "V2LoginBruteForce", "V2DependencyErrors", "V2RepeatedExternalConnections", "V2InternalPortScan"}
        self.assertTrue(expected <= {r["alert"] for r in logs})
        self.assertNotIn("VulnerabilityScanningDetected", {r["alert"] for r in logs})
        self.assertTrue(all(set(v2.FIELDS) <= r["labels"].keys() for r in logs + rules(b)))
        bindings = json.loads(b["bindings.json"])
        backend = next(x for x in bindings if x["identity"]["service"] == "backend")
        self.assertEqual(backend["network"], {"observer": "fixture-observer", "observer_instance": "fixture-capture"})
        self.assertFalse(json.loads(b["manifest.json"])["deployment_allowed"])
        self.assertFalse(json.loads(b["manifest.json"])["runtime_accepted"])
        self.assertNotIn("expected_action", "".join(b.values()))
        self.assertNotIn("incident_class", "".join(b.values()))

    def test_optional_unverified_producers_are_excluded(self):
        c = config(); c.update(network=None, postgres_exporter=None)
        b = release.render(profile(), c)
        alerts = {r["alert"] for r in rules(b) + rules(b, "loki/fake/release.rules.yml")}
        self.assertNotIn("V2InternalPortScan", alerts)
        self.assertNotIn("V2DBReadSurge", alerts)
        self.assertIn("V2LoginBruteForce", alerts)
        self.assertTrue(any("observer mapping" in x for x in json.loads(b["manifest.json"])["excluded"]))

    def test_reject_placeholder_unattested_injection_and_missing_pg(self):
        changes = [lambda c: c.update(version=True), lambda c: c["network"].update(mapping_verified=False),
                   lambda c: c["network"].update(observer_instance='x" | count_over_time'),
                   lambda c: c["network"].update(observer="REPLACE_NAME"),
                   lambda c: c["thresholds"].update(internal_endpoints=0),
                   lambda c: c["thresholds"].update(external_connections=True),
                   lambda c: c["postgres_exporter"].update(instance="pg:99999"),
                   lambda c: c["postgres_exporter"].update(instance="http://user:password@pg:9187"),
                   lambda c: c["postgres_exporter"].update(metrics_verified=False),
                   lambda c: c["postgres_exporter"].update(job="fixture-telemetry")]
        for change in changes:
            c = config(); change(c)
            with self.subTest(config=c), self.assertRaises(ValueError):
                release.render(profile(), c)
        p = profile(); p["host_postgres"] = None
        with self.assertRaises(ValueError): release.render(p, config())

    def test_db_target_scoping_and_no_container_or_account_repair(self):
        b = release.render(profile(), config())
        db = next(r for r in rules(b) if r["alert"] == "V2DBReadSurge")
        self.assertIn('datname="fixture"', db["expr"])
        self.assertIn('source="fixture-gc-pg"', db["expr"])
        self.assertIn('runtime="host"', db["expr"])
        self.assertEqual(db["labels"]["target"], "fixture-pg17")
        self.assertNotIn("fixture-backend", db["expr"])
        scrape = yaml.safe_load(b["prometheus.yml"])["scrape_configs"][-1]
        self.assertFalse(scrape["honor_labels"])
        self.assertEqual(scrape["static_configs"][0]["labels"]["source"], "fixture-gc-pg")

    def test_generated_signal_names_match_remediation_profiles_in_separate_image(self):
        tree = ast.parse((release.ROOT / "aiops/remediation/response_profiles.py").read_text())
        assignment = next(n for n in tree.body if isinstance(n, ast.Assign)
                          and any(isinstance(t, ast.Name) and t.id == "PROFILES" for t in n.targets))
        names = {ast.literal_eval(k) for k in assignment.value.keys}
        b = release.render(profile(), config())
        generated = {r["alert"] for r in rules(b) + rules(b, "loki/fake/release.rules.yml") if r["alert"].startswith("V2")}
        self.assertEqual(generated, names)

    @unittest.skipUnless(LOGCLI, "M5_LOGCLI not set")
    def test_native_transfer_bytes_and_early_threshold_do_not_count_wrong_events(self):
        b = release.render(profile(), config())
        log_rules = rules(b, "loki/fake/release.rules.yml")
        transfer = next(r for r in log_rules if r["alert"] == "V2UnauthorizedDataTransfer")
        p = transfer["expr"].split("max_over_time(", 1)[1].split(" | unwrap", 1)[0]
        rows = [event(fixture_id="data", bytes_sent=2000000), event(fixture_id="bad", bytes_sent="invalid"),
                event(fixture_id="missing", bytes_sent=None), event(fixture_id="negative", bytes_sent=-1),
                event(fixture_id="allowed", bytes_sent=2000000, dst_service="db")]
        self.assertEqual(native_matches(p, rows), {"data"})
        early = next(r for r in log_rules if r["alert"] == "V2UnauthorizedTransferEarly")
        p = early["expr"].split("count_over_time(", 1)[1].rsplit(" [5m]", 1)[0]
        rows = [event(fixture_id="threshold", event_type="connection_threshold", observer_meta={"bytes_threshold": 1048576}),
                event(fixture_id="too-small", event_type="connection_threshold", observer_meta={"bytes_threshold": 100}),
                event(fixture_id="no-threshold", event_type="connection_threshold"),
                event(fixture_id="final", observer_meta={"bytes_threshold": 1048576})]
        self.assertEqual(native_matches(p, rows), {"threshold"})

    @unittest.skipUnless(LOGCLI, "M5_LOGCLI not set")
    def test_native_all_logql_metric_expressions_parse(self):
        b = release.render(profile(), config())
        for r in rules(b, "loki/fake/release.rules.yml"):
            if not r["alert"].startswith("V2"): continue
            result = subprocess.run([LOGCLI, "fmt"], input=r["expr"], text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, r["alert"] + ": " + result.stderr)

    @unittest.skipUnless(LOGCLI, "M5_LOGCLI not set")
    def test_native_network_allowlist_scope_malformed_and_threshold_event(self):
        pipeline = v2.unauthorized(v2.network_pipeline(profile(), config()), policy())
        rows = [event(fixture_id="external"), event(fixture_id="internal", dst_service="db"),
                event(fixture_id="allowed", dst_ip="10.210.0.30", dst_port=8080),
                event(fixture_id="wrong-port", dst_ip="10.210.0.30", dst_port=8081),
                event(fixture_id="other-observer", observer_instance="other"),
                event(fixture_id="other-container", src_container="other"),
                event(fixture_id="early", event_type="connection_threshold"),
                event(fixture_id="missing-port", dst_port=None),
                event(fixture_id="invalid-port", dst_port="8080"),
                event(fixture_id="missing-id", connection_id=None),
                event(fixture_id="object-ip", dst_ip={"value": "192.0.2.9"}),
                '{"fixture_id":"truncated"', '[{"fixture_id":"array"}]']
        self.assertEqual(native_matches(pipeline, rows), {"external", "wrong-port"})

    @unittest.skipUnless(LOGCLI, "M5_LOGCLI not set")
    def test_native_internal_scan_includes_failed_connections_and_allowed_peers(self):
        p = v2.network_pipeline(profile(), config())
        p += ' | v2_dst_ip=~"^(10\\\\..*|192\\\\.168\\\\..*|172\\\\.(1[6-9]|2[0-9]|3[01])\\\\..*)$"'
        rows = [event(fixture_id="db", dst_service="db", dst_ip="10.0.0.2", bytes_sent=None),
                event(fixture_id="minio", dst_service="minio", dst_ip="172.16.1.2", dst_port=9000),
                event(fixture_id="local", dst_ip="192.168.3.2"),
                event(fixture_id="external", dst_ip="192.0.2.9"),
                event(fixture_id="not-private", dst_ip="172.160.0.1")]
        self.assertEqual(native_matches(p, rows), {"db", "minio", "local"})

    @unittest.skipUnless(LOGCLI, "M5_LOGCLI not set")
    def test_native_login_and_dependency_patterns(self):
        b = release.render(profile(), config())
        for name, lines, expected in [
            ("V2LoginBruteForce", ['[AUTH] 로그인 실패 reason=wrong_password', '[AUTH] 로그인 성공', 'normal'], {'0'}),
            ("V2DependencyErrors", ['io.minio.errors.ErrorResponseException connection failed', 'normal 200', 'database Connection refused'], {'0'})]:
            r = next(r for r in rules(b, "loki/fake/release.rules.yml") if r["alert"] == name)
            # Raw text fixtures are wrapped in JSON only to carry a stable ID;
            # production substring/regex filters see both raw and JSON lines.
            p = r["expr"].split('count_over_time(', 1)[1].rsplit(' [2m]', 1)[0]
            self.assertEqual(native_matches(p, [{"fixture_id": str(n), "message": s} for n, s in enumerate(lines)]), expected)

    @unittest.skipUnless(PROMTOOL, "M5_PROMTOOL not set")
    def test_native_db_rate_reset_boundary_backup_signal_and_other_database(self):
        b = release.render(profile(), config())
        r = next(r for r in rules(b) if r["alert"] == "V2DBReadSurge")
        # Metric is explicitly rows visited; normal backup MAY match this same
        # alert and therefore must stay notification-only in Remediation tests.
        labels = {**{k: r["labels"][k] for k in v2.FIELDS}, "job": "fixture-postgres",
                  "instance": "fixture-pg.invalid:9187", "datname": "fixture"}
        def metric(extra=None):
            return "pg_stat_database_tup_returned" + v2.selector({**labels, **(extra or {})})
        series = [{"series": metric(), "values": "0+100000x72"},
                  {"series": metric({"datname": "other"}), "values": "0+10000000x72"}]
        expected = {**labels}; expected.pop("datname"); expected.pop("job"); expected.pop("instance")
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            (p / "rules.yml").write_text(yaml.safe_dump({"groups": [{"name": "fixture", "rules": [r]}]}))
            tests = {"rule_files": [str(p / "rules.yml")], "evaluation_interval": "5s", "tests": [
                {"interval": "5s", "input_series": series,
                 "promql_expr_test": [{"expr": r["expr"], "eval_time": "2m", "exp_samples": [{"labels": "{}", "value": 20000}]}],
                 "alert_rule_test": [{"eval_time": "2m", "alertname": r["alert"], "exp_alerts": [
                     {"exp_labels": r["labels"], "exp_annotations": r["annotations"]}]}]},
                {"interval": "5s", "input_series": [{"series": metric(), "values": "0+50000x72"}],
                 "promql_expr_test": [{"expr": r["expr"], "eval_time": "2m", "exp_samples": []}]},
                {"interval": "5s", "input_series": [{"series": metric(), "values": "500000 0+100x71"}],
                 "promql_expr_test": [{"expr": r["expr"], "eval_time": "2m", "exp_samples": []}]},
                {"interval": "5s", "input_series": [series[1]],
                 "promql_expr_test": [{"expr": r["expr"], "eval_time": "2m", "exp_samples": []}]}]}
            (p / "tests.yml").write_text(yaml.safe_dump(tests))
            result = subprocess.run([PROMTOOL, "test", "rules", str(p / "tests.yml")], text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__": unittest.main()
