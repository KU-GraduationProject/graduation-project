"""Synthetic M4 statistics/quality tests; no traffic, scenarios or live services.

Optional M4_PROMTOOL / M4_LOGCLI enable native expression parsers. In-memory
observed envelopes below test gating only; they are never measurement evidence.
"""

from copy import deepcopy
import importlib.util
import json
import math
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

spec = importlib.util.spec_from_file_location("baseline_m4", Path(__file__).resolve().parents[1] / "baseline_m4.py")
m4 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m4)


def config():
    return yaml.safe_load(m4.CONFIG.read_text())


def measured_config():
    value = config()
    value["window"] = {"start": "2026-01-01T00:00:00Z", "end": "2026-01-01T01:01:00Z"}
    value["normal"].update(confirmed=True, incident_and_injection_free=True, confirmed_by="synthetic-fixture-operator", evidence="unit-test-only attestation")
    value["sources"]["integrated"]["scope_confirmed"] = True
    return value


def envelope(value, kind="synthetic"):
    definition = m4.plan(value)["queries"][0]
    start = m4.timestamp(value["window"]["start"])
    end = m4.timestamp(value["window"]["end"])
    points = [[time, .8] for time in range(int(start + 30), int(end) + 1, 5)]
    _, check = m4.quality([[time, 1] for time in range(int(start), int(end) + 1, 5)], start, end, 5, raw=True)
    entry = {"series_id": "fixture", "id_token": "fixture-id", "labelset_token": "fixture-labelset", "all_one": True,
             "quality": check, "invalid_limits": 0, "label_keys": ["id", "name"]}
    return {"version": 1, "data_kind": kind, "config_sha256": m4.digest(value), "plan_sha256": m4.digest(m4.plan(value)),
            "window": value["window"], "series": [{"query_id": definition["id"], "series_id": "fixture", "entity": "leafy-frontend", "points": points}],
            "checks": {definition["id"]: "OK"}, "raw_quality": {"integrated/" + family: {"status": "OK", "series": [deepcopy(entry)]} for family in ("cpu_counter", "metadata")},
            "log_summaries": {}, "event_totals": {}}


def network_line(time, uid, destination="192.0.2.30", port=8080, value=100, event="connection", observer="fixture-observer", **extra):
    return json.dumps({"schema_version": "1.0", "event_type": event, "timestamp": m4.utc(time), "observer_instance": observer,
                       "connection_id": uid, "src_ip": "192.0.2.10", "src_port": 40000, "dst_ip": destination, "dst_port": port,
                       "dst_service": "external", "bytes_sent": value, **extra})


class M4AnalysisTest(unittest.TestCase):
    def test_percentiles_mean_dispersion_and_trend(self):
        result = m4.summarize([(time * 5, float(time)) for time in range(1, 101)])
        self.assertEqual(result["mean"], 50.5)
        self.assertEqual(result["median"], 50.5)
        self.assertAlmostEqual(result["p90"], 90.1)
        self.assertAlmostEqual(result["p95"], 95.05)
        self.assertAlmostEqual(result["p99"], 99.01)
        self.assertEqual(result["max"], 100)
        self.assertAlmostEqual(result["stddev"], math.sqrt(833.25))
        self.assertAlmostEqual(result["linear_trend_per_hour"], 720)
        self.assertIsNone(m4.summarize([]))
        self.assertIsNone(m4.summarize([(0, 0)])["coefficient_of_variation"])

    def test_hourly_statistics_keep_utc_hours_separate(self):
        result = m4.summarize([(3595, 2), (3600, 10)])
        self.assertEqual(len(result["hourly_utc"]), 2)
        self.assertEqual([r["mean"] for r in result["hourly_utc"].values()], [2, 10])

    def test_missing_nonfinite_and_out_of_range_are_not_zero(self):
        points, result = m4.quality([[0, 0], [5, "NaN"], [15, "Inf"], [20, 2], [100, 3]], 0, 20, 5)
        self.assertEqual(points, [(0, 0), (20, 2)])
        self.assertEqual(result["observed_samples"], 2)
        self.assertEqual(result["expected_samples"], 5)
        self.assertEqual(result["rejected_samples"], 3)
        self.assertEqual(result["max_gap_seconds"], 20)
        self.assertEqual(result["coverage"], .4)
        self.assertEqual(m4.quality([], 0, 20, 5)[1]["coverage"], 0)

    def test_duplicate_samples_rejected_and_raw_scrape_jitter_allowed(self):
        with self.assertRaises(ValueError):
            m4.quality([[0, 1], [0, 2]], 0, 5, 5)
        self.assertEqual(len(m4.quality([[.2, 1], [5.1, 2]], 0, 10, 5, raw=True)[0]), 2)
        self.assertEqual(len(m4.quality([[.2, 1], [5.1, 2]], 0, 10, 5)[0]), 0)

    def test_exceedance_boundary_for_duration_and_gaps(self):
        points = [(time, .8) for time in range(0, 31, 5)]
        self.assertEqual(m4.excursions(points, .5, 30, 5)["for_satisfied_episodes"], 1)
        self.assertEqual(m4.excursions(points[:-1], .5, 30, 5)["for_satisfied_episodes"], 0)
        self.assertEqual(m4.excursions([(0, .5)], .5, 0, 5)["exceeding_samples"], 0)
        self.assertEqual(m4.excursions([(0, .8), (5, .8), (20, .8), (25, .8)], .5, 30, 5)["for_satisfied_episodes"], 0)
        self.assertEqual(m4.excursions([(0, 1)], 0, 0, 5)["for_satisfied_episodes"], 1)
        self.assertEqual(m4.excursions([(time, .9) for time in range(0, 301, 5)], .85, 300, 5)["for_satisfied_episodes"], 1)

    def test_no_window_or_data_produces_no_baseline_or_threshold(self):
        result = m4.analyze(config())
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["normal_status"], "NORMAL_UNCONFIRMED")
        self.assertEqual(result["series"], [])
        self.assertEqual(result["baseline_eligible_series"], 0)
        self.assertIn("산출하지 않은", m4.markdown(result))
        with self.assertRaises(ValueError):
            m4.collect(config(), "http://localhost", "http://localhost")

    def test_unconfirmed_or_synthetic_never_becomes_normal_baseline(self):
        value = measured_config()
        data = envelope(value)
        result = m4.analyze(value, data)
        self.assertEqual(result["baseline_eligible_series"], 0)
        self.assertIsNone(result["series"][0]["normal_baseline_statistics"])
        self.assertIn("SYNTHETIC_TEST_ONLY", result["series"][0]["excluded_reasons"])
        value["normal"]["confirmed"] = False
        data = envelope(value, "observed")
        result = m4.analyze(value, data)
        self.assertIn("NORMAL_UNCONFIRMED", result["series"][0]["excluded_reasons"])

    def test_unconfirmed_percentiles_withheld_from_all_export_sections(self):
        value = measured_config()
        value["normal"]["confirmed"] = False
        data = envelope(value, "observed")
        data["raw_quality"]["integrated/cpu_counter"]["series"][0]["diagnostic_statistics"] = {"p95": 95123, "p99": 99123, "mean": 3}
        data["log_summaries"] = {"network": {"bytes_per_connection": {"median": 7, "p90": 90, "p95": 95, "p99": 99}}}
        result = m4.analyze(value, data)
        self.assertEqual(result["percentiles_status"], "NORMAL_UNCONFIRMED")
        def check(node):
            if isinstance(node, dict):
                for key, item in node.items():
                    if key in {"median", "p50", "p90", "p95", "p99"}: self.assertIsNone(item)
                    else: check(item)
            elif isinstance(node, list):
                for item in node: check(item)
        check(result)
        self.assertIsNone(result["series"][0]["normal_baseline_statistics"])
        self.assertIsNone(result["series"][0]["candidate_condition"])
        self.assertNotIn("95123", m4.markdown(result))
        self.assertIn("정상 P95", m4.markdown(result))
        self.assertEqual(result["raw_input_diagnostics"]["integrated/cpu_counter"]["series"][0]["diagnostic_statistics"]["mean"], 3)
        self.assertIsNone(m4.publish_statistics({"p95": 95}, True, "synthetic")["p95"])

    def test_cli_window_options_validate_pairs_timezone_and_preserve_config(self):
        command = [os.sys.executable, str(m4.ROOT / "tools/rulepack/baseline_m4.py")]
        before = m4.CONFIG.read_bytes()
        bounds = ["--start", "2026-01-01T09:00:00+09:00", "--end", "2026-01-01T10:00:00+09:00"]
        with tempfile.TemporaryDirectory(prefix="leafy-m4-cli-") as directory:
            output = Path(directory) / "plan.json"
            result = subprocess.run(command + ["plan", *bounds, "--output", str(output)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(output.read_text())
            self.assertEqual(data["window"], {"start": "2026-01-01T00:00:00+00:00", "end": "2026-01-01T01:00:00+00:00"})
            self.assertFalse(data["normal"]["confirmed"])
            result = subprocess.run(command + ["analyze", *bounds, "--output", directory], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads((Path(directory) / "analysis.json").read_text())["normal_status"], "NORMAL_UNCONFIRMED")
            for invalid in (["--start", "2026-01-01T00:00:00Z"], ["--start", "2026-01-01T00:00:00", "--end", "2026-01-01T01:00:00Z"]):
                result = subprocess.run(command + ["plan", *invalid, "--output", str(output)], capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
        self.assertEqual(m4.CONFIG.read_bytes(), before)

    def test_cli_window_cannot_reassign_existing_normal_attestation(self):
        value = measured_config()
        before = deepcopy(value)
        with self.assertRaises(ValueError):
            m4.window_override(value, "2026-01-02T00:00:00Z", "2026-01-02T01:01:00Z")
        same = m4.window_override(value, "2026-01-01T09:00:00+09:00", "2026-01-01T10:01:00+09:00")
        self.assertTrue(same["normal"]["confirmed"])
        self.assertEqual(value, before)

    def test_raw_samples_detect_lookback_masked_gaps_and_metadata_duplicates(self):
        value = measured_config()
        data = envelope(value, "observed")
        self.assertEqual(m4.analyze(value, data)["baseline_eligible_series"], 1)
        # Evaluated values remain complete while the source scrape has a hole.
        data["raw_quality"]["integrated/cpu_counter"]["series"][0]["quality"]["max_gap_seconds"] = 60
        result = m4.analyze(value, data)
        self.assertIn("RAW_INPUT_GAPS:cpu_counter", result["series"][0]["excluded_reasons"])
        data = envelope(value, "observed")
        data["raw_quality"]["integrated/metadata"]["series"] *= 2
        self.assertIn("DUPLICATE_METADATA_ID", m4.analyze(value, data)["series"][0]["excluded_reasons"])

    def test_candidate_needs_evidence_units_and_normal_quality(self):
        value = measured_config()
        query_id = m4.plan(value)["queries"][0]["id"]
        value["candidates"][query_id] = {"threshold": 1, "unit": "CPU_core_equivalent", "rationale": "unit-test-only review"}
        result = m4.analyze(value, envelope(value, "observed"))
        self.assertEqual(result["series"][0]["current_condition"]["for_satisfied_episodes"], 1)
        self.assertEqual(result["series"][0]["candidate_condition"]["exceeding_samples"], 0)
        self.assertIsNone(m4.analyze(value, envelope(value))["series"][0]["candidate_condition"])
        value["candidates"][query_id]["unit"] = "% of host CPU"
        with self.assertRaises(ValueError):
            m4.plan(value)

    def test_fitting_and_m6_intervals_and_timezones_validated(self):
        value = measured_config()
        value["reserved_evaluation_windows"] = [{"start": "2026-01-01T00:30:00Z", "end": "2026-01-01T02:00:00Z"}]
        with self.assertRaises(ValueError):
            m4.plan(value)
        value["reserved_evaluation_windows"] = [{"start": value["window"]["end"], "end": "2026-01-01T02:00:00Z"}]
        with self.assertRaises(ValueError):
            m4.plan(value)
        value["reserved_evaluation_windows"][0]["start"] = "2026-01-01T01:01:05Z"
        m4.plan(value)
        with self.assertRaises(ValueError):
            m4.timestamp("2026-01-01T00:00:00")
        value["normal"]["incident_and_injection_free"] = False
        with self.assertRaises(ValueError):
            m4.plan(value)

    def test_provenance_mismatches_and_unknown_queries_rejected(self):
        value = measured_config()
        for field in ("config_sha256", "plan_sha256", "window"):
            data = envelope(value)
            data[field] = None
            with self.subTest(field=field), self.assertRaises(ValueError):
                m4.analyze(value, data)
        data = envelope(value)
        data["series"][0]["query_id"] = "other-source"
        with self.assertRaises(ValueError):
            m4.analyze(value, data)

    def test_scopes_and_immutable_units_and_expressions(self):
        value = config()
        before = deepcopy(value)
        queries = m4.plan(value)["queries"]
        self.assertEqual(value, before)
        cpu = next(q for q in queries if q["family"] == "cpu")
        self.assertIn("irate(", cpu["expression"])
        self.assertIn("[30s]", cpu["expression"])
        self.assertNotIn("> 0.5", cpu["expression"])
        self.assertIn("on(id) group_left(name)", cpu["expression"])
        memory = next(q for q in queries if q["family"] == "memory")
        self.assertIn(" > 0)", memory["expression"])
        self.assertNotIn(" > 0.85", memory["expression"])
        host = next(q for q in queries if q["family"] == "network_host_fallback")
        self.assertIn("unless on ()", host["expression"])
        self.assertIn('id=~"/docker/.+"', host["expression"])
        self.assertIn(") > 0", host["expression"])
        self.assertEqual(host["unit"], "bytes/second")
        value["sources"]["same-collector"] = deepcopy(value["sources"]["integrated"])
        with self.assertRaises(ValueError):
            m4.plan(value)

    def test_http_sanitization_counts_and_sample_cap(self):
        secret = "/users/fixture-person/search?token=fixture-secret"
        rows = [(10, json.dumps({"request_uri": secret, "status": "200", "principal": "fixture-person"})),
                (20, json.dumps({"request_uri": "/missing", "status": "404"})), (30, "broken")]
        result = m4.http_summary(rows, m4.tagger(), 0, 60, True)
        self.assertEqual(result["status_class_counts_in_sample"], {"2xx": 1, "4xx": 1})
        self.assertEqual(result["invalid_rows"], 1)
        self.assertTrue(result["truncated"])
        self.assertNotIn("fixture-person", json.dumps(result))
        self.assertNotIn("fixture-secret", json.dumps(result))

    def test_network_thresholds_duplicate_cumulative_bytes_and_scopes(self):
        policy = {"allow": [{"match": "endpoint", "ip": "192.0.2.30", "port": 8080}]}
        final = network_line(100, "same", value=120)
        rows = [(100, final), (100, final), (100, network_line(100, "same", value=90, event="connection_threshold")),
                (200, network_line(200, "new", destination="192.0.2.31", value=500)),
                (200, network_line(200, "new", observer="other-observer", value=700)),
                (250, network_line(250, "missing-bytes", value=None))]
        result = m4.network_summary(rows, m4.tagger(), 0, 3600, False, policy)
        self.assertEqual(result["duplicate_final_events_excluded"], 1)
        self.assertEqual(result["threshold_events_excluded"], 1)
        self.assertEqual(result["invalid_rows"], 1)
        window = result["windows"][1]
        self.assertEqual(window["event_samples"], 3)
        self.assertEqual(sum(r["payload_bytes"] for r in window["destinations"]), 1320)
        self.assertEqual(len({r["observer_token"] for r in window["destinations"]}), 2)
        self.assertNotIn("192.0.2.", json.dumps(result))
        self.assertNotIn("same", json.dumps(result))

    def test_network_requested_windows_and_first_observed_are_not_global_novelty(self):
        rows = [(100, network_line(100, "a")), (900, network_line(900, "b"))]
        result = m4.network_summary(rows, m4.tagger(), 0, 1000, True, {"allow": []})
        self.assertEqual([w["available_window_seconds"] for w in result["windows"]], [300, 1000, 1000])
        self.assertFalse(result["windows"][2]["complete_requested_duration"])
        self.assertFalse(result["windows"][0]["destinations"][0]["first_observed_in_available_reference"])

    def test_conflicting_final_connection_bytes_are_excluded_not_summed_or_maxed(self):
        rows = [(100, network_line(100, "conflict", value=100)), (100, network_line(100, "conflict", value=200))]
        result = m4.network_summary(rows, m4.tagger(), 0, 1000, False, {"allow": []})
        self.assertEqual(result["conflicting_final_event_identities_excluded"], 1)
        self.assertEqual(result["windows"][1]["event_samples"], 0)

    def test_readonly_api_validation_errors_never_echo_credentials(self):
        for url in ("file:///tmp/source", "http://fixture-user:fixture-password@localhost", "http://localhost?token=fixture-secret"):
            with self.assertRaises(ValueError):
                m4.get(url, "/api/v1/query", {})
        class Reply:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size): return b'{"status":"success","warnings":["partial"],"data":{}}'
        class Opener:
            def open(self, request, timeout):
                self.request = request
                return Reply()
        opener = Opener()
        with patch.object(m4, "build_opener", return_value=opener):
            self.assertEqual(m4.get("http://127.0.0.1:1", "/api/v1/query", {"query": "up"}), {"error": "API_PARTIAL_OR_ANNOTATED_RESULT"})
        self.assertEqual(opener.request.get_method(), "GET")
        self.assertIsNone(opener.request.data)

    def test_raw_limit_matching_and_no_source_mixing(self):
        value = measured_config()
        data = envelope(value, "observed")
        memory = next(q for q in m4.plan(value)["queries"] if q["family"] == "memory")
        row = data["series"][0]
        row["query_id"] = memory["id"]
        data["checks"][memory["id"]] = "OK"
        data["raw_quality"]["integrated/working_set"] = deepcopy(data["raw_quality"]["integrated/metadata"])
        data["raw_quality"]["integrated/memory_limit"] = deepcopy(data["raw_quality"]["integrated/metadata"])
        data["raw_quality"]["integrated/memory_limit"]["series"][0].update(invalid_limits=1, labelset_token="different-labelset")
        result = m4.analyze(value, data)["series"][0]
        self.assertIn("INVALID_OR_UNLIMITED_MEMORY_LIMIT", result["excluded_reasons"])
        self.assertIn("MEMORY_FULL_LABEL_MISMATCH", result["excluded_reasons"])
        self.assertIsNone(result["normal_baseline_statistics"])
        row["query_id"] = next(q for q in m4.plan(value)["queries"] if q["family"] == "network_host_fallback")["id"]
        self.assertEqual(m4.analyze(value, data)["series"][0]["entity"], "host_scope")

    def test_collection_uses_warmup_raw_samples_and_sanitized_outputs(self):
        value = measured_config()
        value["normal"]["confirmed"] = False
        start = m4.timestamp(value["window"]["start"])
        end = m4.timestamp(value["window"]["end"])
        calls = []
        def fake_get(base, path, params):
            calls.append((path, params))
            if "label/" in path:
                return {"status": "success", "data": []}
            if "loki" in path and params.get("direction"):
                line = json.dumps({"request_uri": "/private/fixture-user?token=fixture-secret", "status": "200"})
                return {"status": "success", "data": {"resultType": "streams", "result": [{"values": [[str(int((start + 180) * 1e9)), line]]}]}}
            if path.endswith("/query") and "loki" in path:
                return {"status": "success", "data": {"resultType": "vector", "result": [{"metric": {}, "value": [end, "1"]}]}}
            left = params.get("start", start + 5)
            return {"status": "success", "data": {"resultType": "matrix", "result": [{"metric": {"name": "leafy-frontend", "id": "/docker/fixture", "state": "idle"},
                "values": [[left, "1"], [end, "1"]]}]}}
        with patch.object(m4, "get", side_effect=fake_get):
            result = m4.collect(value, "http://127.0.0.1:1", "http://127.0.0.1:2")
        cpu = next(params for path, params in calls if "irate(" in params["query"])
        self.assertEqual(cpu["start"], start + 30)
        self.assertTrue(any(path == "/api/v1/query" and params["query"].endswith("[3660s]") for path, params in calls))
        self.assertTrue(result["raw_quality"])
        self.assertTrue(result["event_totals"])
        self.assertEqual(result["series"][0]["dimensions"], {"state": "idle"})
        self.assertNotIn("fixture-user", json.dumps(result))
        self.assertNotIn("fixture-secret", json.dumps(result))
        self.assertEqual(result["percentiles_status"], "NORMAL_UNCONFIRMED")
        self.assertTrue(all(row["diagnostic_statistics"]["p95"] is None for raw in result["raw_quality"].values() for row in raw["series"]))
        for _, params in calls:
            if params.get("direction"):
                self.assertEqual(int(params["start"]), int(start * 1e9))
            else:
                self.assertGreaterEqual(params.get("start", start), start)

    def test_partial_api_no_series_and_zero_are_distinct(self):
        self.assertEqual(m4.matrix_rows({"error": "HTTP_403"}, "q", str), ([], "HTTP_403"))
        self.assertEqual(m4.matrix_rows({"data": {"resultType": "matrix", "result": []}}, "q", str), ([], "NO_SERIES"))
        rows, status = m4.matrix_rows({"data": {"resultType": "matrix", "result": [{"metric": {}, "values": [[0, "0"]]}]}}, "q", lambda _: "fixture")
        self.assertEqual(status, "OK")
        self.assertEqual(rows[0]["points"], [[0, "0"]])

    def test_fallback_mask_active_and_missing_are_different_states(self):
        value = measured_config()
        start = m4.timestamp(value["window"]["start"])
        data = {"series": [], "checks": {}}
        for kind, points in (("root_rate", [[start + 60, 100], [start + 65, 200]]),
                             ("presence_guard", [[start + 60, 2]]), ("host_fallback", [[start + 65, 200]])):
            query_id = "integrated/receive/" + kind
            data["series"].append({"query_id": query_id, "points": points})
            data["checks"][query_id] = "OK"
        result = m4.fallback_activity(data, value, (start, start + 70))[0]
        self.assertEqual(result["states_by_evaluation_samples"], {"MASKED_BY_ANY_DOCKER_SERIES": 1, "HOST_FALLBACK_ACTIVE": 1, "ROOT_RATE_MISSING": 1})

    def test_cli_protects_operating_paths_and_writes_only_local_analysis(self):
        command = [os.sys.executable, str(m4.ROOT / "tools/rulepack/baseline_m4.py")]
        before = (m4.ROOT / "monitoring/prometheus/rules/alert.rules.yml").read_bytes()
        blocked = subprocess.run(command + ["plan", "--output", str(m4.ROOT / "monitoring/prometheus/rules/alert.rules.yml")], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(blocked.returncode, 0)
        self.assertEqual((m4.ROOT / "monitoring/prometheus/rules/alert.rules.yml").read_bytes(), before)
        with tempfile.TemporaryDirectory(prefix="leafy-m4-empty-") as directory:
            result = subprocess.run(command + ["analyze", "--output", directory], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads((Path(directory) / "analysis.json").read_text())
            self.assertEqual(data["data_kind"], "none")
            self.assertEqual(data["baseline_eligible_series"], 0)

    @unittest.skipUnless(os.environ.get("M4_PROMTOOL"), "M4_PROMTOOL not set; native PromQL parser skipped")
    def test_native_promql_query_plan(self):
        rules = [{"record": "m4_fixture_query_" + str(index), "expr": query["expression"]} for index, query in enumerate(m4.plan(config())["queries"]) if query["engine"] == "prometheus"]
        with tempfile.TemporaryDirectory(prefix="leafy-m4-promql-") as directory:
            path = Path(directory) / "fixture.yml"
            path.write_text(yaml.safe_dump({"groups": [{"name": "syntax-only-not-deployed", "rules": rules}]}))
            result = subprocess.run([os.environ["M4_PROMTOOL"], "check", "rules", str(path)], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(os.environ.get("M4_PROMTOOL"), "M4_PROMTOOL not set; native units/branch evaluation skipped")
    def test_native_cpu_memory_rate_and_host_fallback_values(self):
        queries = m4.plan(config())["queries"]
        def expression(family): return next(q["expression"] for q in queries if q["family"] == family)
        labels = '{id="/docker/fixture",job="cadvisor",instance="cadvisor:8080"}'
        root = '{id="/",name="vm-root",interface="eth0",job="cadvisor",instance="cadvisor:8080"}'
        inputs = [
            {"series": 'container_cpu_usage_seconds_total' + labels[:-1] + ',cpu="total"}', "values": "0+4x240"},
            {"series": 'container_name_info{id="/docker/fixture",name="leafy-frontend",job="pipeline-metadata",instance="pipeline:8000"}', "values": "1+0x240"},
            {"series": "container_memory_working_set_bytes" + labels, "values": "80+0x240"},
            {"series": "container_spec_memory_limit_bytes" + labels, "values": "100+0x240"},
            {"series": "container_network_receive_bytes_total" + labels[:-1] + ',name="leafy-frontend",interface="eth0"}', "values": "0+5000000x240"},
            {"series": "container_network_receive_bytes_total" + root, "values": "0+10000000x240"},
            {"series": 'nginx_http_requests_total{job="nginx-exporter",instance="nginx-exporter:9113"}', "values": "0+100x240"},
        ]
        tests = [{"interval": "5s", "input_series": inputs, "promql_expr_test": [
            {"expr": expression("cpu"), "eval_time": "2m", "exp_samples": [{"labels": '{name="leafy-frontend"}', "value": .8}]},
            {"expr": expression("memory"), "eval_time": "2m", "exp_samples": [{"labels": '{name="leafy-frontend"}', "value": .8}]},
            {"expr": expression("network_container"), "eval_time": "2m", "exp_samples": [{"labels": '{name="leafy-frontend"}', "value": 1e6}]},
            {"expr": expression("network_host_fallback"), "eval_time": "2m", "exp_samples": []},
            {"expr": expression("http_rate"), "eval_time": "2m", "exp_samples": [{"labels": '{job="nginx-exporter",instance="nginx-exporter:9113"}', "value": 20}]},
        ]}, {"interval": "5s", "input_series": [inputs[5]], "promql_expr_test": [
            {"expr": expression("network_host_fallback"), "eval_time": "2m", "exp_samples": [{"labels": root.replace(',interface="eth0"', ''), "value": 2e6}]},
        ]}]
        with tempfile.TemporaryDirectory(prefix="leafy-m4-native-") as directory:
            path = Path(directory) / "test.yml"
            path.write_text(yaml.safe_dump({"rule_files": [], "evaluation_interval": "5s", "tests": tests}))
            result = subprocess.run([os.environ["M4_PROMTOOL"], "test", "rules", str(path)], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(os.environ.get("M4_LOGCLI"), "M4_LOGCLI not set; native LogQL parser skipped")
    def test_native_logql_query_plan(self):
        for query in m4.plan(config())["queries"]:
            if query["engine"] == "loki":
                result = subprocess.run([os.environ["M4_LOGCLI"], "fmt"], input=query["expression"], capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, query["id"] + result.stderr)


if __name__ == "__main__":
    unittest.main()
