"""OI-09 contracts. Synthetic identities/HTTP only; no Docker, DB, LLM or external API."""
import json
import os
import sys
import unittest
from datetime import timedelta
from unittest.mock import AsyncMock, patch
import httpx
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import main
from identity import parse_bindings, resolve_identity, dedup_key, selector
from correlation import CorrelationContext
from collector.logs import LogsCollector
from collector.metrics import MetricsCollector
from collector.network import NetworkCollector

ANCHOR = "2026-11-10T12:00:00Z"


def binding_row(site="gc", runtime="container", target="leafy-db"):
    return {
        "identity": {"site": site, "service": "db", "runtime": runtime, "target": target,
                     "source": f"{site}-{runtime}-producer"},
        "match": {"job": f"{site}-{runtime}", "instance": f"{site}-agent:9100"},
        "logs": {"site": site, "service": "db", "runtime": runtime,
                 "container_name" if runtime == "container" else "target": target},
        "metrics": {"job": f"{site}-cadvisor" if runtime == "container" else f"{site}-node",
                    "instance": f"{site}-agent:8080" if runtime == "container" else f"{site}-agent:9100",
                    **({"id": "/docker/" + "a" * 64} if runtime == "container" else {})},
        "network": {"observer": f"{site}-observer", "observer_instance": f"{site}-agent-1"},
    }


def binding(**kw):
    return parse_bindings(json.dumps([binding_row(**kw)]))[0]


def context(b=None):
    b = b or binding()
    return CorrelationContext.around(b.identity.service, ANCHOR, timedelta(minutes=5),
                                    identity=b.identity, binding=b, runtime=b.identity.runtime)


def alert(b=None, **labels):
    b = b or binding()
    return main.Alert(status="firing", startsAt=ANCHOR, annotations={"container": b.identity.target},
                      labels=main.AlertLabel(alertname="DBAlert", **{**b.match, **labels}))


def loki_result(ctx, scope=None, lines=None):
    return {"status": "success", "data": {"resultType": "streams", "result": [{
        "stream": ctx.binding.logs if scope is None else scope,
        "values": [[str(ctx.start_ns + 1), "postgres log"]] if lines is None else lines}]}}


class IdentityTests(unittest.TestCase):
    def test_legacy_webhook_and_extra_labels_roundtrip(self):
        a = main.AlertManagerWebhook(version="4", groupKey="x", status="firing", alerts=[{
            "status": "firing", "startsAt": ANCHOR, "labels": {
                "alertname": "Old", "container": "leafy-db", "rulepack_source": "m5", "custom_source": "kept"}}])
        self.assertEqual(a.alerts[0].labels.model_dump()["custom_source"], "kept")
        i, b, status = resolve_identity(a.alerts[0].labels.model_dump(), {}, (), {"leafy-db": ("db", "host")})
        self.assertIsNone(b)
        self.assertIsNone(i.runtime)  # legacy alias does not prove host vs container
        self.assertEqual(status, "source_unknown")

    def test_job_instance_explicitly_maps_to_site(self):
        b = binding()
        i, found, status = resolve_identity(b.match, {"container": "leafy-db"}, [b])
        self.assertEqual((i.site, i.runtime, found, status), ("gc", "container", b, "resolved"))

    def test_host_pg17_and_container_pg16_are_distinct(self):
        for runtime, target in (("host", "pg17-host"), ("container", "leafy-db")):
            b = binding(runtime=runtime, target=target)
            i, _, status = resolve_identity(b.match, {"container": target}, [b])
            self.assertEqual((i.runtime, i.target, status), (runtime, target, "resolved"))

    def test_wrong_instance_cannot_use_other_pc(self):
        b = binding()
        i, found, status = resolve_identity({**b.match, "instance": "jh-agent:9100"}, {}, [b])
        self.assertIsNone(found)
        self.assertIsNone(i.site)
        self.assertEqual(status, "source_unmapped")

    def test_host_placeholder_never_resolves_as_container(self):
        b = binding()
        i, found, status = resolve_identity(b.match, {"container": "unknown (host-level)"}, [b])
        self.assertEqual(i.runtime, "host")
        self.assertIsNone(i.target)
        self.assertIsNone(found)
        self.assertEqual(status, "identity_conflict")

    def test_root_id_does_not_use_cgroup_name(self):
        i, _, _ = resolve_identity({"id": "/", "name": "leafy-backend"}, {})
        self.assertEqual(i.runtime, "host")
        self.assertIsNone(i.target)

    def test_explicit_identity_conflict_and_ambiguity(self):
        b = binding()
        self.assertEqual(resolve_identity({**b.match, "runtime": "host"}, {}, [b])[2], "identity_conflict")
        self.assertEqual(resolve_identity(b.match, {}, [b, b])[2], "ambiguous_source")
        self.assertEqual(resolve_identity({"site": "gc"}, {"site": "jh"}, [b])[2], "identity_conflict")

    def test_dedup_separates_sites_and_sources_but_retains_repeats(self):
        def key(b, **extra):
            a = alert(b, **extra)
            i, _, _ = resolve_identity(a.labels.model_dump(), a.annotations, [b])
            return dedup_key(a.labels.alertname, i, a.labels.model_dump(), a.annotations)
        gc, jh = binding(), binding(site="jh")
        self.assertNotEqual(key(gc), key(jh))
        self.assertEqual(key(gc), key(gc))
        self.assertNotEqual(key(gc, observer_instance="one"), key(gc, observer_instance="two"))

    def test_stdout_label_is_preserved_but_not_a_producer(self):
        i, found, _ = resolve_identity({"source": "stdout", "container": "leafy-db"}, {})
        self.assertIsNone(i.source)
        self.assertIsNone(found)
        row = binding_row()
        row["match"] = {"site": "gc", "target": "leafy-db"}
        b = parse_bindings(json.dumps([row]))[0]
        i, found, status = resolve_identity({"site": "gc", "target": "leafy-db", "source": "stdout"}, {}, [b])
        self.assertEqual(i.source, "gc-container-producer")
        self.assertEqual(status, "resolved")

    def test_same_site_target_but_different_producers_do_not_dedup(self):
        a = binding()
        row = binding_row()
        row["identity"]["source"] = "gc-second-producer"
        row["match"]["instance"] = "gc-other-agent:9100"
        b = parse_bindings(json.dumps([row]))[0]
        self.assertNotEqual(dedup_key("DBAlert", a.identity, a.match, {}),
                            dedup_key("DBAlert", b.identity, b.match, {}))

    def test_dedup_keeps_unrecognized_source_labels(self):
        b = binding()
        self.assertNotEqual(dedup_key("Old", b.identity, {"source_pc": "gc"}, {}),
                            dedup_key("Old", b.identity, {"source_pc": "jh"}, {}))

    def test_cadvisor_id_and_name_must_match_verified_target(self):
        b = binding()
        for extra in ({"id": "/docker/" + "b" * 64}, {"name": "leafy-frontend"}):
            self.assertEqual(resolve_identity({**b.match, **extra}, {"container": "leafy-db"}, [b])[2], "identity_conflict")

    def test_root_source_cannot_turn_into_postgres_service(self):
        b = binding(runtime="host", target="pg17-host")
        i, found, status = resolve_identity({**b.match, "id": "/"}, {"container": "unknown (host-level)"}, [b])
        self.assertIsNone(found)
        self.assertIsNone(i.service)
        self.assertEqual(status, "identity_conflict")
        row = binding_row(runtime="host", target="gc-host")
        row["identity"]["service"] = "host"
        row["logs"] = {}
        b = parse_bindings(json.dumps([row]))[0]
        i, found, status = resolve_identity({**b.match, "id": "/"}, {"container": "unknown (host-level)"}, [b])
        self.assertEqual((i.target, i.service, status), ("gc-host", "host", "resolved"))

    def test_invalid_binding_rejected(self):
        for mutate in (
            lambda r: r["metrics"].pop("instance"),
            lambda r: r["metrics"].update(id="/"),
            lambda r: r["logs"].pop("site"),
            lambda r: r["logs"].update(runtime="host"),
            lambda r: r.update(match={"target": "leafy-db"}),
            lambda r: r["identity"].update(source="UNKNOWN"),
            lambda r: r["match"].update(site="wrong"),
            lambda r: r.update(match={"source": "stdout"}),
            lambda r: r.update(match={"observer": "network-observer"}),
        ):
            row = binding_row(); mutate(row)
            with self.assertRaises(ValueError):
                parse_bindings(json.dumps([row]))


class LogsTests(unittest.IsolatedAsyncioTestCase):
    async def test_queries_isolate_same_service_and_runtime(self):
        for b in (binding(), binding(site="jh"), binding(runtime="host", target="pg17-host")):
            ctx, seen = context(b), []
            def handler(req):
                seen.append(req)
                if req.url.path.endswith("/series"):
                    return httpx.Response(200, json={"status": "success", "data": [b.logs]})
                return httpx.Response(200, json=loki_result(ctx))
            logs = await LogsCollector("http://loki", httpx.MockTransport(handler)).fetch(ctx)
            self.assertEqual(logs.report["status"], "ok")
            self.assertEqual(len(logs), 1)
            self.assertEqual(seen[-1].url.params["query"], selector(b.logs))
            self.assertIn(f'runtime="{b.identity.runtime}"', seen[-1].url.params["query"])

    async def test_scoped_logs_keep_original_timestamp_sorting(self):
        ctx = context()
        lines = [[str(ctx.start_ns + 2_000_000_000), "later"], [str(ctx.start_ns + 1_000_000_000), "earlier"]]
        def handler(req):
            if req.url.path.endswith("/series"):
                return httpx.Response(200, json={"status": "success", "data": [ctx.binding.logs]})
            return httpx.Response(200, json=loki_result(ctx, lines=lines))
        logs = await LogsCollector("http://loki", httpx.MockTransport(handler)).fetch(ctx)
        self.assertEqual([row["line"] for row in logs], ["earlier", "later"])
        self.assertEqual(logs.report["stream_labels"], [ctx.binding.logs])

    async def test_missing_loki_labels_never_widens_query(self):
        seen = []
        def handler(req):
            seen.append(req)
            return httpx.Response(200, json={"status": "success", "data": []})
        logs = await LogsCollector("http://loki", httpx.MockTransport(handler)).fetch(context())
        self.assertEqual(logs.report["status"], "scope_unavailable")
        self.assertEqual(len(seen), 1)
        self.assertTrue(seen[0].url.path.endswith("/series"))

    async def test_error_empty_and_source_mismatch_are_distinct(self):
        ctx = context()
        for mode, expected in (("empty", "empty"), ("error", "api_error"), ("rogue", "source_mismatch"), ("invalid", "invalid_response")):
            def handler(req):
                if mode == "error": return httpx.Response(503)
                if mode == "invalid": return httpx.Response(200, text="not json")
                if req.url.path.endswith("/series"):
                    return httpx.Response(200, json={"status": "success", "data": [ctx.binding.logs]})
                return httpx.Response(200, json=loki_result(ctx, scope={"site": "jh"} if mode == "rogue" else None, lines=[]))
            logs = await LogsCollector("http://loki", httpx.MockTransport(handler)).fetch(ctx)
            self.assertEqual(logs, [])
            self.assertEqual(logs.report["status"], expected)

    async def test_missing_source_runtime_never_calls_loki(self):
        def handler(req): raise AssertionError("no scoped source")
        logs = await LogsCollector("http://loki", httpx.MockTransport(handler)).fetch(
            CorrelationContext.around("db", ANCHOR, timedelta(minutes=5)))
        self.assertEqual(logs.report["status"], "scope_unavailable")


class MetricsTests(unittest.IsolatedAsyncioTestCase):
    async def test_host_and_container_never_fallback(self):
        for b in (binding(), binding(runtime="host", target="pg17-host")):
            ctx, seen = context(b), []
            def handler(req):
                seen.append(req.url.params["query"])
                return httpx.Response(200, json={"status": "success", "data": {"resultType": "matrix", "result": []}})
            m = await MetricsCollector("http://prom", httpx.MockTransport(handler)).fetch_around(None, ctx.anchor, ctx=ctx)
            self.assertEqual(m.report["status"], "empty")
            self.assertTrue(all('job="'+b.metrics['job']+'"' in q and 'instance="'+b.metrics['instance']+'"' in q for q in seen))
            self.assertTrue(all(("container_" in q) == (b.identity.runtime == "container") for q in seen))
            self.assertTrue(all(("node_" in q) == (b.identity.runtime == "host") for q in seen))

    async def test_api_errors_not_empty_and_rogue_series_excluded(self):
        ctx = context()
        for mode, expected in (("http", "api_error"), ("status", "api_error"), ("rogue", "source_mismatch"), ("bad", "invalid_response")):
            def handler(req):
                if mode == "http": return httpx.Response(500)
                if mode == "status": return httpx.Response(200, json={"status": "error"})
                if mode == "bad": return httpx.Response(200, text="bad")
                return httpx.Response(200, json={"status": "success", "data": {"resultType": "matrix", "result": [{"metric": {**ctx.binding.metrics, "instance": "jh:8080"}, "values": [[1, "7"]]}]}})
            m = await MetricsCollector("http://prom", httpx.MockTransport(handler)).fetch_around(None, ctx.anchor, ctx=ctx)
            self.assertEqual(m.report["status"], expected)
            self.assertFalse(any(m.values()))

    async def test_partial_failure_keeps_only_verified_evidence(self):
        ctx = context()
        def handler(req):
            if "memory_usage" in req.url.params["query"]: return httpx.Response(503)
            return httpx.Response(200, json={"status": "success", "data": {"resultType": "matrix", "result": [{
                "metric": ctx.binding.metrics, "values": [[ctx.anchor.timestamp(), "0.5"]]}]}})
        m = await MetricsCollector("http://prom", httpx.MockTransport(handler)).fetch_around(None, ctx.anchor, ctx=ctx)
        self.assertEqual(m.report["status"], "partial")
        self.assertEqual(m.report["query_status"]["memory_usage"], "api_error")
        self.assertNotIn("memory_usage", m)
        self.assertEqual(m["cpu_usage"][0]["values"][0]["v"], .5)
        self.assertEqual(m.report["series_labels"]["cpu_usage"], [ctx.binding.metrics])

    async def test_local_docker_never_used_for_legacy_name_or_id(self):
        def handler(req): raise AssertionError("must not call Docker or Prometheus")
        m = await MetricsCollector("http://prom", httpx.MockTransport(handler)).fetch_around("leafy-db", context().anchor, container_id="a"*64)
        self.assertEqual(m.report["status"], "scope_unavailable")


class NetworkIdentityTests(unittest.IsolatedAsyncioTestCase):
    async def test_other_observer_runtime_or_target_never_reaches_rca(self):
        ctx = context()
        good = {"schema_version": "1.0", "timestamp": ANCHOR, "event_type": "connection",
                "connection_id": "same-id", "observer": "gc-observer", "observer_instance": "gc-agent-1",
                "src_service": "db", "src_runtime": "container", "src_container": "leafy-db", "dst_service": "backend"}
        rows = [good, dict(good, observer_instance="jh-agent-1"), dict(good, src_runtime="host"), dict(good, src_container="other-db")]
        def handler(req):
            return httpx.Response(200, json={"status": "success", "data": {"resultType": "streams", "result": [{
                "stream": {}, "values": [[str(ctx.start_ns + 1), json.dumps(e)] for e in rows]}]}})
        n = await NetworkCollector("http://loki", httpx.MockTransport(handler)).fetch(ctx)
        self.assertEqual(n.events, (good,))
        self.assertEqual(n.provenance["observer"], ctx.binding.network)
        self.assertEqual(n.provenance["status"], "partial")

    async def test_host_network_requires_explicit_host_target(self):
        ctx = context(binding(runtime="host", target="pg17-host"))
        base = {"schema_version": "1.0", "timestamp": ANCHOR, "observer": "gc-observer", "observer_instance": "gc-agent-1",
                "src_service": "backend", "dst_service": "db", "dst_runtime": "host", "dst_container": None}
        collector = NetworkCollector("http://loki")
        events, _ = collector._parse([json.dumps(base)], ctx)
        self.assertEqual(events, [])
        events, _ = collector._parse([json.dumps(dict(base, dst_target="pg17-host"))], ctx)
        self.assertEqual(len(events), 1)


class PipelineTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        main._recent_alerts.clear()
        main.analysis_history.clear()

    async def test_legacy_webhook_is_queued_without_external_calls(self):
        payload = main.AlertManagerWebhook(version="4", groupKey="x", status="firing", alerts=[{
            "status": "firing", "startsAt": ANCHOR, "labels": {"alertname": "Old"}}])
        from fastapi import BackgroundTasks
        tasks = BackgroundTasks()
        result = await main.receive_alert(payload, tasks)
        self.assertIn("queued", result["message"])
        self.assertEqual(len(tasks.tasks), 1)

    async def test_identity_persists_through_collectors_prompt_history_and_loki(self):
        b = binding(runtime="host", target="pg17-host")
        ctx = context(b)
        def handler(req):
            if req.url.path.endswith("/series"):
                return httpx.Response(200, json={"status": "success", "data": [b.logs]})
            if "loki" in req.url.host: return httpx.Response(200, json=loki_result(ctx))
            return httpx.Response(200, json={"status": "success", "data": {"resultType": "matrix", "result": []}})
        transport = httpx.MockTransport(handler)
        captured = []
        async def llm(prompt):
            captured.append(prompt)
            return main.LLMAnalysisResult(root_cause="pg17 host evidence", incident_class="failure", action_type="NOTIFY",
                                         action_targets=[], threat_level="medium", evidence=[], confidence=.7)
        with patch.object(main, "_observation_bindings", (b,)), \
             patch.object(main, "metrics_collector", MetricsCollector("http://prom", transport)), \
             patch.object(main, "logs_collector", LogsCollector("http://loki", transport)), \
             patch.object(main, "network_collector", NetworkCollector("http://loki", transport)), \
             patch.object(main, "call_llm", side_effect=llm), \
             patch.object(main, "push_to_loki", new_callable=AsyncMock, return_value=True) as push, \
             patch.object(main, "forward_to_remediation", new_callable=AsyncMock) as forward:
            await main.analyze_alerts([alert(b), alert(b)])
        self.assertEqual(len(main.analysis_history), 1)
        entry = main.analysis_history[-1]
        self.assertEqual(entry["identity"]["site"], "gc")
        self.assertEqual(entry["identity"]["runtime"], "host")
        self.assertEqual(entry["container"], "unknown")
        self.assertEqual(entry["evidence_sources"]["logs"]["selector"], b.logs)
        self.assertEqual(entry["evidence_sources"]["metrics"]["selector"], b.metrics)
        self.assertIn('"target": "pg17-host"', captured[0]["user"])
        self.assertEqual(push.await_args.args[0]["identity"], resolve_identity(b.match, {"container": b.identity.target}, [b])[0].to_dict())
        forward.assert_not_awaited()
        # Legacy LLM result consumers still validate the unchanged nested result schema.
        self.assertEqual(main.LLMAnalysisResult.model_validate(entry["result"]).confidence, .7)

    async def test_two_sites_same_alert_target_are_not_suppressed(self):
        with patch.object(main, "_observation_bindings", ()), patch.object(main, "push_to_loki", new_callable=AsyncMock), patch.object(main, "call_llm", new_callable=AsyncMock) as llm:
            await main.analyze_alerts([alert(binding(), site="gc"), alert(binding(site="jh"), site="jh")])
        self.assertEqual(len(main.analysis_history), 2)
        llm.assert_not_awaited()

    async def test_host_placeholder_and_missing_source_record_unknown_without_query(self):
        with patch.object(main, "_observation_bindings", ()), patch.object(main, "push_to_loki", new_callable=AsyncMock), patch.object(main, "call_llm", new_callable=AsyncMock) as llm:
            await main.analyze_alerts([main.Alert(status="firing", startsAt=ANCHOR, labels=main.AlertLabel(alertname="HighCpuUsage"), annotations={"container": "unknown (host-level)"})])
        e = main.analysis_history[-1]
        self.assertEqual(e["identity"]["runtime"], "host")
        self.assertEqual(e["identity"]["target"], "UNKNOWN")
        self.assertEqual(e["result"]["confidence"], 0)
        llm.assert_not_awaited()

    async def test_dedup_keeps_original_300_second_window(self):
        a = alert()
        with patch.object(main, "_observation_bindings", ()), patch.object(main, "push_to_loki", new_callable=AsyncMock), patch.object(main.time, "time", return_value=1000) as clock:
            await main.analyze_alerts([a])
            clock.return_value = 1299
            await main.analyze_alerts([a])
            self.assertEqual(len(main.analysis_history), 1)
            clock.return_value = 1300
            await main.analyze_alerts([a])
            self.assertEqual(len(main.analysis_history), 2)

    async def test_loki_push_preserves_identity_and_rejects_http_failure(self):
        b = binding()
        entry = {"alert_name": "DBAlert", "container": "leafy-db", "identity": b.identity.to_dict(), "result": {}}
        posted = []
        def handler(req):
            posted.append(json.loads(req.content))
            return httpx.Response(204)
        factory = httpx.AsyncClient
        with patch.object(main.httpx, "AsyncClient", side_effect=lambda **kw: factory(transport=httpx.MockTransport(handler), **kw)), patch.object(main, "push_timeline_event", new_callable=AsyncMock):
            self.assertTrue(await main.push_to_loki(entry))
        stream = posted[0]["streams"][0]
        self.assertEqual(stream["stream"]["site"], "gc")
        self.assertEqual(json.loads(stream["values"][0][1])["identity"], b.identity.to_dict())
        with patch.object(main.httpx, "AsyncClient", side_effect=lambda **kw: factory(transport=httpx.MockTransport(lambda r: httpx.Response(500)), **kw)), patch.object(main, "push_timeline_event", new_callable=AsyncMock) as timeline:
            self.assertFalse(await main.push_to_loki(entry))
            timeline.assert_not_awaited()


if __name__ == "__main__": unittest.main()
