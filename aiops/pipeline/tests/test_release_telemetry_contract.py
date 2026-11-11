"""Actual GC producer output through generated bindings and Pipeline HTTP mocks."""
from datetime import datetime, timezone, timedelta
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock, patch

import httpx

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "aiops/pipeline"))
sys.path.insert(0, str(ROOT / "tools/rulepack"))
import main
from collector.metrics import MetricsCollector
from collector.logs import LogsCollector
from collector.network import NetworkCollector
from correlation import CorrelationContext
from identity import parse_bindings
import prepare_release

spec = importlib.util.spec_from_file_location("release_gc_producer", ROOT / "deploy/leafy-pc/telemetry/exporter.py")
producer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = producer
spec.loader.exec_module(producer)

CID = "a" * 64
IDENTITY = {"site": "fixture-gc", "source": "fixture-docker", "runtime": "container",
            "service": "backend", "target": "fixture-backend"}
PROFILE = {"version": 1, "inventory_verified": True,
           "gc": {"site": IDENTITY["site"], "source": IDENTITY["source"], "project": "fixture-project",
                  "targets": {"backend": {"name": IDENTITY["target"], "id": CID}}},
           "telemetry": {"job": "fixture-telemetry", "instance": "fixture.invalid:9108"}, "host_postgres": None}


def exported_samples():
    driver_labels = {"com.docker.compose.project": "fixture-project", "com.docker.compose.service": "backend"}
    class DockerFixture:
        def inventory(self):
            return [{"Id": CID, "Names": ["/fixture-backend"], "State": "running", "Labels": driver_labels}]
        def inspect(self, cid):
            return {"Id": cid, "Name": "/fixture-backend", "Config": {"Labels": driver_labels},
                    "RestartCount": 2, "HostConfig": {"Memory": 1000},
                    "State": {"Running": True, "StartedAt": "2026-11-10T00:00:00Z"}}
    labels = {"id": "/docker/" + CID, "name": "fixture-backend"}
    raw = "\n".join(producer.line(metric, {**labels, **extra}, val) for metric, val, extra in (
        (producer.CPU, 80, {"cpu": "total"}), (producer.MEM, 900, {}), (producer.LIMIT, 1000, {}),
        (producer.NET, 2000, {"interface": "eth0"}), (producer.LAST_SEEN, 100, {})))
    collector = producer.Collector(producer.Config("fixture-gc", "fixture-docker", "fixture-project",
                                   {"backend": "fixture-backend"}), DockerFixture(), lambda: raw, clock=lambda: 100)
    return producer.parse_metrics(collector.collect(), upstream=False)


class ReleaseTelemetryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.bundle = prepare_release.render(PROFILE)
        self.binding = parse_bindings(self.bundle["bindings.json"])[0]
        self.samples = exported_samples()
        main._recent_alerts.clear(); main.analysis_history.clear()

    async def test_producer_metrics_profile_queries_only_supported_families(self):
        seen = []
        def handler(request):
            query = request.url.params["query"]; seen.append(query)
            family = next((n for n in [*producer.RESOURCE_TYPES, "aiops_docker_container_restarts_total",
                                      "aiops_docker_container_started_at_seconds"] if n in query), None)
            self.assertIsNotNone(family, query)
            sample = next(s for s in self.samples if s.metric == family)
            return httpx.Response(200, json={"status": "success", "data": {"resultType": "matrix", "result": [
                {"metric": {**sample.labels, **PROFILE["telemetry"]}, "values": [[100, str(sample.value)]]}]}})
        ctx = CorrelationContext.around("backend", datetime.now(timezone.utc), timedelta(minutes=5),
                                        identity=self.binding.identity, binding=self.binding, runtime="container")
        evidence = await MetricsCollector("http://fixture.invalid", httpx.MockTransport(handler)).fetch_around(None, ctx.anchor, ctx=ctx)
        self.assertEqual(evidence.report["status"], "ok")
        self.assertEqual(len(seen), 6)
        self.assertTrue(evidence["memory_working_set"])
        self.assertEqual(evidence["restart_count"][0]["values"][0]["v"], 2)
        self.assertNotIn("id=", next(q for q in seen if "aiops_docker_container_restarts_total" in q))
        self.assertEqual(evidence.report["unsupported_metrics"], ["memory_usage", "net_tx_bytes"])
        self.assertTrue(all('source="fixture-docker"' in q and 'target="fixture-backend"' in q for q in seen))

    async def test_generated_rule_alert_reaches_loki_with_all_identity_and_no_action(self):
        rule = yaml_rules(self.bundle)[0]
        posted = []
        def handler(request):
            if request.method == "POST":
                posted.append(json.loads(request.content)); return httpx.Response(204)
            if request.url.path.endswith("/series"):
                return httpx.Response(200, json={"status": "success", "data": [self.binding.logs]})
            if request.url.path.startswith("/loki/"):
                return httpx.Response(200, json={"status": "success", "data": {"resultType": "streams", "result": [{
                    "stream": self.binding.logs, "values": [[str(int(datetime.now(timezone.utc).timestamp() * 1e9)), "fixture event"]]}]}})
            query = request.url.params["query"]
            family = next(n for n in [*producer.RESOURCE_TYPES, "aiops_docker_container_restarts_total",
                                     "aiops_docker_container_started_at_seconds"] if n in query)
            sample = next(s for s in self.samples if s.metric == family)
            return httpx.Response(200, json={"status": "success", "data": {"resultType": "matrix", "result": [{
                "metric": {**sample.labels, **PROFILE["telemetry"]}, "values": [[100, "0.8"]]}]}})
        transport = httpx.MockTransport(handler)
        factory = httpx.AsyncClient
        def client(**kw):
            kw.setdefault("transport", transport)
            return factory(**kw)
        result = main.LLMAnalysisResult(root_cause="fixture RCA", incident_class="failure", action_type="NOTIFY",
                                        action_targets=[], threat_level="medium", evidence=[], confidence=.8)
        starts_at = datetime.now(timezone.utc).isoformat()
        with patch.object(main, "_observation_bindings", (self.binding,)), \
             patch.object(main, "metrics_collector", MetricsCollector("http://fixture.invalid", transport)), \
             patch.object(main, "logs_collector", LogsCollector("http://fixture.invalid", transport)), \
             patch.object(main, "network_collector", NetworkCollector("http://fixture.invalid", transport)), \
             patch.object(main.httpx, "AsyncClient", side_effect=client), \
             patch.object(main, "call_llm", new_callable=AsyncMock, return_value=result) as llm, \
             patch.object(main, "forward_to_remediation", new_callable=AsyncMock) as forward:
            await main.analyze_alerts([main.Alert(status="firing", labels=main.AlertLabel(alertname=rule["alert"], **rule["labels"]),
                startsAt=starts_at, fingerprint="fixture-fingerprint", annotations=rule["annotations"])])
        llm.assert_awaited_once(); forward.assert_not_awaited()
        self.assertEqual(main.analysis_history[-1]["storage_status"], "stored")
        stream = next(s for p in posted for s in p["streams"] if s["stream"]["job"] == "aiops-llm")
        body = json.loads(stream["values"][0][1])
        for k, v in IDENTITY.items():
            self.assertEqual(stream["stream"][k], v)
            self.assertEqual(body["identity"][k], v)
        self.assertEqual(body["schema_version"], "2.0")
        self.assertEqual(body["alert_starts_at"], starts_at)
        self.assertEqual(body["alert_fingerprint"], "fixture-fingerprint")
        self.assertFalse(body["remediation_dispatched"])
        self.assertFalse(body["notification_dispatched"])

    async def test_unknown_source_never_queries_evidence_or_calls_llm(self):
        rule = yaml_rules(self.bundle)[0]
        def forbidden(request): raise AssertionError("unknown source evidence query")
        transport = httpx.MockTransport(forbidden)
        with patch.object(main, "_observation_bindings", (self.binding,)), \
             patch.object(main, "metrics_collector", MetricsCollector("http://fixture.invalid", transport)), \
             patch.object(main, "logs_collector", LogsCollector("http://fixture.invalid", transport)), \
             patch.object(main, "network_collector", NetworkCollector("http://fixture.invalid", transport)), \
             patch.object(main, "call_llm", new_callable=AsyncMock) as llm, \
             patch.object(main, "push_to_loki", new_callable=AsyncMock, return_value=True):
            labels = {**rule["labels"], "source": "fixture-unknown"}
            await main.analyze_alerts([main.Alert(status="firing", labels=main.AlertLabel(alertname=rule["alert"], **labels),
                startsAt=datetime.now(timezone.utc).isoformat(), annotations=rule["annotations"])])
        llm.assert_not_awaited()
        self.assertEqual(main.analysis_history[-1]["result"]["confidence"], 0)

    def test_gc_profile_refuses_incomplete_or_conflicting_identity(self):
        original = json.loads(self.bundle["bindings.json"])[0]
        for key in IDENTITY:
            row = json.loads(json.dumps(original)); row["metrics"].pop(key)
            with self.assertRaises(ValueError): parse_bindings(json.dumps([row]))
        row = json.loads(json.dumps(original)); row["metrics_profile"] = "guess"
        with self.assertRaises(ValueError): parse_bindings(json.dumps([row]))


def yaml_rules(bundle):
    import yaml
    return [r for g in yaml.safe_load(bundle["prometheus.rules.yml"])["groups"] for r in g["rules"]]


if __name__ == "__main__": unittest.main()
