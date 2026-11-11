"""Read-only transport and acceptance boundaries; no real service required."""
import importlib.util
from io import BytesIO
import json
from pathlib import Path
import unittest
from unittest.mock import Mock
from urllib.error import HTTPError, URLError

SPEC = importlib.util.spec_from_file_location("acceptance_m5b", Path(__file__).parents[1] / "acceptance_m5b.py")
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def vector(value=None):
    return {"status": "success", "data": {"resultType": "vector", "result": [] if value is None else [
        {"metric": {"secret_label": "NEVER_EXPORT_THIS"}, "value": [123, value]}]}}


class AcceptanceTests(unittest.TestCase):
    def test_plan_has_all_21_exact_definitions_and_valid_inputs(self):
        p = m.plan()
        self.assertEqual(len(p["rules"]), 21)
        self.assertEqual(sum(r["engine"] == "loki" for r in p["rules"]), 12)
        self.assertEqual(len({r["id"] for r in p["rules"]}), 21)
        self.assertEqual(sum(r["alert"] == "HighCpuUsage" for r in p["rules"]), 4)
        for rule in p["rules"]:
            self.assertTrue(rule["inputs"])
            self.assertFalse(any("{{" in s or "m3_" in s for s in rule["inputs"]))
        self.assertNotIn("SQLInjectionAttempt", {r["alert"] for r in p["rules"]})

    def test_credential_urls_redirects_and_unsafe_output_are_refused(self):
        for url in ("http://user:password@host", "http://host/?token=x", "http://host/#x", "file:///etc/passwd", "http://host/config"):
            with self.assertRaises(ValueError):
                m.Client(url)
        self.assertIsNone(m.NoRedirect().redirect_request(None, None, 302, "", {}, "http://elsewhere"))
        with self.assertRaises(ValueError):
            m.output_path(str(m.ROOT / "monitoring/prometheus/rules/result.json"))
        c = m.Client("http://localhost")
        with self.assertRaises(ValueError):
            c.get("//elsewhere")

    def test_http_uses_get_and_does_not_export_errors_or_warning_text(self):
        c = m.Client("http://localhost")
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = json.dumps({"warnings": ["NEVER_EXPORT_THIS"], **vector("0")}).encode()
        c.opener = Mock()
        c.opener.open.return_value = response
        meta, _ = c.get("/api/v1/query", {"query": "up"})
        self.assertEqual(meta["status"], "PARTIAL")
        self.assertNotIn("NEVER_EXPORT_THIS", json.dumps(meta))
        self.assertEqual(c.opener.open.call_args.args[0].get_method(), "GET")
        c.opener.open.side_effect = HTTPError("http://localhost", 422, "NEVER_EXPORT_THIS", {}, BytesIO(b"NEVER_EXPORT_THIS"))
        meta, data = c.get("/api/v1/query")
        self.assertEqual(meta["http_status"], 422)
        self.assertIsNone(data)
        self.assertNotIn("NEVER_EXPORT_THIS", json.dumps(meta))
        c.opener.open.side_effect = URLError(PermissionError(1, "denied"))
        self.assertEqual(c.get("/api/v1/query")[0]["status"], "ACCESS_DENIED")

    def test_empty_zero_nonfinite_and_label_values_are_distinct(self):
        empty, zero = m.vector_summary(vector()), m.vector_summary(vector("0"))
        self.assertEqual(empty["result"], "EMPTY")
        self.assertEqual(zero["result"], "PRESENT")
        self.assertEqual(zero["positive_values"], 0)
        self.assertEqual(m.vector_summary(vector("NaN"))["finite_values"], 0)
        self.assertNotIn("NEVER_EXPORT_THIS", json.dumps(zero))

    def test_raw_logs_only_export_whitelisted_key_types(self):
        d = {"data": {"resultType": "streams", "result": [{"stream": {"secret": "NEVER_EXPORT_THIS"}, "values": [
            ["100", '{"request_uri":"NEVER_EXPORT_THIS","principal":"NEVER_EXPORT_THIS","status":500}'],
            ["200", "NEVER_EXPORT_THIS"], ["300", "[]"]]}]}}
        s = m.log_summary(d)
        self.assertEqual(s["schema_key_type_counts"], {"request_uri:str": 1, "status:int": 1})
        self.assertEqual(s["invalid_or_nonobject_json"], 2)
        self.assertNotIn("NEVER_EXPORT_THIS", json.dumps(s))
        self.assertNotIn("principal", json.dumps(s))

    def test_am_original_config_and_webhook_credentials_never_export(self):
        s = m.am_summary({"config": {"original": 'receivers:\n- name: x\n  webhook_configs:\n  - url: https://user:NEVER_EXPORT_THIS@host/path\n'}})
        self.assertFalse(s["configured_pipeline_webhook_present"])
        self.assertNotIn("NEVER_EXPORT_THIS", json.dumps(s))

    def test_unreachable_apis_do_not_claim_inputs_missing_or_e2e_pass(self):
        class Unreachable:
            base = "http://localhost"
            def get(self, path, params=None):
                return {"status": "CONNECTION_REFUSED", "path": path}, None
        d = m.collect({k: Unreachable() for k in ("prometheus", "loki", "alertmanager", "pipeline", "ollama")}, 123)
        self.assertEqual(len(d["rules"]), 21)
        self.assertTrue(all(r["inputs"] == "UNVERIFIED_API_UNAVAILABLE" for r in d["rules"]))
        self.assertFalse(d["actual_alert_e2e_verified"])
        self.assertFalse(d["deployment_performed"])

    def test_successful_predicates_still_do_not_certify_delivery_or_scope(self):
        class Present:
            base = "http://localhost"
            def get(self, path, params=None):
                if path == "/api/v1/targets":
                    d = {"data": {"activeTargets": []}}
                elif path == "/loki/api/v1/labels":
                    d = {"data": ["service"]}
                elif "query_range" in path:
                    d = {"data": {"resultType": "streams", "result": []}}
                elif "query" in path:
                    d = vector("1")
                elif path.endswith("/rules"):
                    return {"status": "HTTP_ERROR", "http_status": 404}, None
                else:
                    return {"status": "CONNECTION_REFUSED"}, None
                return {"status": "SUCCESS"}, d
        d = m.collect({k: Present() for k in ("prometheus", "loki", "alertmanager", "pipeline", "ollama")}, 123)
        self.assertTrue(all(r["scope_acceptance"] == "UNVERIFIED" for r in d["rules"]))
        self.assertTrue(all(r["exact_expression_loaded"] is None for r in d["rules"]))
        self.assertFalse(d["actual_alert_e2e_verified"])
        self.assertEqual(d["evidence"][d["rules"][0]["evaluation"]]["summary"]["positive_values"], 1)

    def test_loaded_candidate_firing_does_not_certify_correlated_e2e(self):
        candidate = m.plan()["rules"][0]
        class Loaded:
            base = "http://192.0.2.80:9090"
            legacy_group = False
            def get(self, path, params=None):
                if path.endswith("/rules"):
                    d = {"data": {"groups": [{"name": "legacy" if self.legacy_group else candidate["id"].split(":")[1], "interval": 5, "rules": [{
                        "type": "alerting", "name": candidate["alert"], "query": candidate["expr"],
                        "labels": candidate["static_labels"], "annotations": {"container": "redacted"},
                        "duration": candidate["duration"], "keepFiringFor": candidate["keep_firing_for"],
                        "state": "firing", "health": "ok"}]}]}}
                    # Supply the exact approved annotation object without importing Pipeline.
                    import yaml
                    source = yaml.safe_load((m.ROOT / "docs/rulepack/m5/generated/loki.rules.yml").read_text())
                    d["data"]["groups"][0]["rules"][0]["annotations"] = source["groups"][0]["rules"][0]["annotations"]
                elif path == "/api/v1/targets":
                    d = {"data": {"activeTargets": [{"labels": {"job": "secret-job", "instance": "192.0.2.81:123"},
                         "health": "up", "lastScrape": "2026-11-11T00:00:00Z"}]}}
                elif path == "/loki/api/v1/labels":
                    d = {"data": ["service"]}
                elif "query_range" in path:
                    d = {"data": {"resultType": "streams", "result": []}}
                elif "query" in path:
                    d = vector("1")
                else:
                    return {"status": "CONNECTION_REFUSED"}, None
                return {"status": "SUCCESS"}, d
        d = m.collect({k: Loaded() for k in ("prometheus", "loki", "alertmanager", "pipeline", "ollama")}, 123)
        rule = d["rules"][0]
        self.assertTrue(rule["exact_definition_loaded"])
        self.assertEqual(rule["loaded_state_observations"], ["firing"])
        self.assertEqual(rule["stages"]["RULE_LOADED"], "VERIFIED")
        self.assertEqual(rule["stages"]["QUERY_SUCCESS"], "VERIFIED")
        for stage in ("INPUT_VERIFIED", "FIRING_VERIFIED", "ALERT_DELIVERED", "PIPELINE_RECEIVED", "RCA_VERIFIED"):
            self.assertEqual(rule["stages"][stage], "UNVERIFIED")
        self.assertEqual(set(rule["stages"]), set(m.STAGES))
        for secret in ("192.0.2.80", "192.0.2.81", "secret-job", "NEVER_EXPORT_THIS"):
            self.assertNotIn(secret, json.dumps(d))
        Loaded.legacy_group = True
        legacy = m.collect({k: Loaded() for k in ("prometheus", "loki", "alertmanager", "pipeline", "ollama")}, 123)
        self.assertTrue(legacy["rules"][0]["exact_expression_loaded"])
        self.assertFalse(legacy["rules"][0]["exact_definition_loaded"])
        self.assertEqual(legacy["rules"][0]["stages"]["RULE_LOADED"], "UNVERIFIED")

    def test_metadata_endpoint_denial_does_not_skip_queries_or_other_apis(self):
        class DeniedMetadata:
            base = "http://localhost"
            def get(self, path, params=None):
                if path in {"/api/v1/targets", "/loki/api/v1/labels"}:
                    return {"status": "HTTP_ERROR", "http_status": 403}, None
                if "query_range" in path:
                    return {"status": "SUCCESS"}, {"data": {"resultType": "streams", "result": []}}
                if "query" in path:
                    return {"status": "SUCCESS"}, vector()
                return {"status": "CONNECTION_REFUSED"}, None
        d = m.collect({k: DeniedMetadata() for k in ("prometheus", "loki", "alertmanager", "pipeline", "ollama")}, 123)
        self.assertTrue(all(r["stages"]["QUERY_SUCCESS"] == "VERIFIED" for r in d["rules"]))
        self.assertTrue(all(r["stages"]["SELECTOR_VERIFIED"] == "UNVERIFIED" for r in d["rules"]))
        self.assertTrue(all(r["stages"]["RULE_LOADED"] == "UNVERIFIED" for r in d["rules"]))

    def test_exact_expression_alone_cannot_certify_loaded_definition(self):
        item = {"inputs": [], "evaluation": "eval", "exact_expression_loaded": True,
                "exact_definition_loaded": False}
        s = m.stages(item, {"eval": {"status": "HTTP_ERROR", "http_status": 422}})
        self.assertEqual(s["RULE_LOADED"], "UNVERIFIED")
        self.assertEqual(s["QUERY_SUCCESS"], "FAIL")
        item["inputs"] = "UNVERIFIED_API_UNAVAILABLE"
        s = m.stages(item, {"eval": {"status": "HTTP_ERROR", "http_status": 403}})
        self.assertEqual(s["QUERY_SUCCESS"], "BLOCKED")
        self.assertEqual(s["SELECTOR_VERIFIED"], "BLOCKED")

    def test_server_join_errors_are_classified_without_raw_message(self):
        c = m.Client("http://localhost")
        c.opener = Mock()
        c.opener.open.side_effect = HTTPError("http://localhost", 422, "hidden", {},
            BytesIO(b'{"error":"many-to-many matching: NEVER_EXPORT_THIS"}'))
        meta, data = c.get("/api/v1/query")
        self.assertIsNone(data)
        self.assertEqual(meta["error_class"], "JOIN_ERROR")
        self.assertNotIn("NEVER_EXPORT_THIS", json.dumps(meta))

    def test_historical_rca_metadata_is_not_inference_or_candidate_proof(self):
        s = m.rca_summary({"data": {"resultType": "streams", "result": [{"values": [["123", json.dumps({
            "timestamp": "2026-01-01T00:00:00Z", "container": "192.0.2.1", "alert_name": "NEVER_EXPORT_THIS",
            "result": {"confidence": 0, "root_cause": "NEVER_EXPORT_THIS", "evidence": ["secret URI"]}})]]}]}})
        self.assertTrue(s["historical_metadata_only"])
        self.assertTrue(s["entries"][0]["zero_confidence"])
        self.assertEqual(s["entries"][0]["identity_keys"], [])
        self.assertFalse(s["entries"][0]["candidate_rca_verified"])
        self.assertNotIn("NEVER_EXPORT_THIS", json.dumps(s))
        self.assertNotIn("192.0.2.1", json.dumps(s))


if __name__ == "__main__":
    unittest.main()
