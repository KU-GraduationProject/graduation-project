"""Track A — Bronze acquisition tests (docs/data-platform/05 §5 ①~⑧). HTTP is httpx.MockTransport only."""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

import httpx

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

import fixture_data as fx  # noqa: E402
from bronze.acquire import acquire  # noqa: E402
from bronze.plan import ForbiddenSelector, plan_incident  # noqa: E402
from contracts import canonical, pipeline_compat  # noqa: E402
from mock_sources.fixture_backend import FixtureSources, dumps, mock_transport  # noqa: E402
from storage.manifest import output_rows  # noqa: E402
from storage.store import LocalFsStore  # noqa: E402

TIMES = ("requested_at", "completed_at")


def fixture_acquisitions(run_id):
    return {a["acquisition_key"]: a for a in fx.jsonl("10_bronze_acquisition.jsonl") if a["run_id"] == run_id}


class BronzeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = LocalFsStore(self.tmp.name)
        self.sources = FixtureSources()
        self.hex = fx.Hex()

    def tearDown(self):
        self.tmp.cleanup()

    def run_item(self, item, fixture_row=None, transport=None, clock="2026-11-10T03:20:00.000000Z", run=None):
        hex8 = fx.Hex([fixture_row["acquisition_id"][-8:]]) if fixture_row else self.hex
        start = fixture_row["requested_at"] if fixture_row else clock
        # Loki holds only what was pushed before the request (remediation events, #77)
        self.sources.now_ns = canonical.ns_of(canonical.parse_ts(fixture_row["requested_at"])) if fixture_row else None
        context = fx.run_context(fx.runs()[run or fx.FIRST_RUN], clock=fx.Clock(start), hex8=hex8)
        result = acquire(item, self.store, context, transport=transport or mock_transport(self.sources),
                         page_delay_s=0, run_log_path=str(fx.FIXTURE_DIR / "02_scenario_runs.jsonl"))
        manifest = self.store.read_manifest("bronze", result["build_id"])
        return result, manifest, output_rows(self.store, manifest, "bronze.acquisition")[0]

    def rows(self, manifest):
        return (output_rows(self.store, manifest, "bronze.loki_entry")
                + output_rows(self.store, manifest, "bronze.prometheus_sample")
                + output_rows(self.store, manifest, "bronze.scenario_run_entry"))

    # ① fixture request -> the same rows as 10/11/12 (ids and times aside: ids are injected here)
    def test_fixture_request_reproduces_bronze(self):
        items = plan_incident(fx.request(), fx.bindings_raw())
        want = fixture_acquisitions(fx.FIRST_RUN)
        by_key = {i["acquisition_key"]: i for i in items}
        self.assertLessEqual(set(want), set(by_key))
        manifests = {m["build_id"]: m for m in fx.manifests()}
        for key, expected in want.items():
            result, manifest, acq = self.run_item(by_key[key], expected)
            self.assertEqual({k: v for k, v in acq.items() if k not in TIMES + ("run_id",)},
                             {k: v for k, v in expected.items() if k not in TIMES + ("run_id",)}, expected["query_name"])
            self.assertEqual(self.rows(manifest), [r for r in fx.jsonl("11_bronze_loki_entry.jsonl")
                                                   + fx.jsonl("12_bronze_prometheus_sample.jsonl")
                                                   + fx.jsonl("14_bronze_scenario_run_entry.jsonl")
                                                   if r["acquisition_id"] == expected["acquisition_id"]])
            fixture_manifest = manifests[expected["acquisition_id"]]
            data_outputs = [o for o in manifest["outputs"] if o["dataset"] != "bronze.acquisition"]
            self.assertEqual(data_outputs, [o for o in fixture_manifest["outputs"] if o["dataset"] != "bronze.acquisition"])
            self.assertEqual((manifest["build_status"], manifest["quality"], manifest["inputs"]),
                             (fixture_manifest["build_status"], fixture_manifest["quality"], []))
            for uri, digest in zip(acq["raw_pages"], acq["raw_sha256"]):
                self.assertEqual(canonical.sha256_bytes(self.store.get_raw(uri)), digest)

    def test_plan_covers_the_full_collector_query_set(self):
        items = plan_incident(fx.request(), fx.bindings_raw())
        names = [(i["scope_role"], i["query_name"]) for i in items]
        self.assertIn(("related", "memory_working_set"), names)
        self.assertEqual(len({i["plan_binding_sha256"] for i in items}), 1)
        only_db = plan_incident({**fx.request(), "stream_classes": ["db_log"]}, fx.bindings_raw())
        self.assertEqual([i["query_name"] for i in only_db], ["logs"])
        # A stream filter never changes the binding set, so the coverage stays the same (fixture reprocess run).
        self.assertEqual(only_db[0]["plan_binding_sha256"], items[0]["plan_binding_sha256"])

    # ② limit 3: page-boundary duplicates removed by record_key
    def test_pagination_boundary_dedup(self):
        item = next(i for i in plan_incident({**fx.request(), "page_limit": 3}, fx.bindings_raw())
                    if i["stream_class"] == "db_log")
        result, manifest, acq = self.run_item(item)
        rows = self.rows(manifest)
        self.assertEqual((acq["status"], acq["limit_hit"], acq["page_count"], len(rows)), ("ok", True, 3, 6))
        self.assertEqual(len({r["record_key"] for r in rows}), 6)
        self.assertEqual([r["record_key"] for r in rows],
                         [r["record_key"] for r in fx.build_rows("bronze.loki_entry", "acq_20261110T032000Z_f6122f9f")])
        starts = [c[1]["start"] for c in self.sources.calls if c[0] == "/loki/api/v1/query_range"]
        self.assertEqual(starts[1], str(rows[2]["entry_ts_ns"]))  # cursor = last ns, inclusive

    # ③ page 2 timeout -> partial, received rows kept (fixture reprocess acquisition)
    def test_second_page_timeout_is_partial(self):
        expected = next(a for a in fx.jsonl("10_bronze_acquisition.jsonl") if a["run_id"] == fx.REPROCESS_RUN)
        request = {**fx.request(), "force_reacquire": True, "page_limit": 3, "stream_classes": ["db_log"]}
        item = plan_incident(request, fx.bindings_raw())[0]
        calls = {"n": 0}

        def fault(request, _):
            if request.url.path == "/loki/api/v1/query_range":
                calls["n"] += 1
                if calls["n"] == 2:
                    raise httpx.ReadTimeout("fixture timeout", request=request)
            return None

        result, manifest, acq = self.run_item(item, expected, mock_transport(self.sources, fault),
                                              run=fx.REPROCESS_RUN)
        self.assertEqual({k: v for k, v in acq.items() if k not in TIMES + ("run_id",)},
                         {k: v for k, v in expected.items() if k not in TIMES + ("run_id",)})
        self.assertEqual(self.rows(manifest), fx.build_rows("bronze.loki_entry", expected["acquisition_id"]))

    # ④ series absent -> empty_unverified
    def test_absent_series_is_empty_unverified(self):
        item = next(i for i in plan_incident(fx.request(), fx.bindings_raw())
                    if i["scope_role"] == "primary" and i["query_name"] == "network_src")
        _, manifest, acq = self.run_item(item)
        self.assertEqual((acq["status"], acq["series_preflight"], acq["row_count"]),
                         ("empty_unverified", "absent", 0))
        series = [c for c in self.sources.calls if c[0] == "/loki/api/v1/series"]
        self.assertEqual(len(series), 2)  # window, then 24h lookback

    # ⑤ no binding -> 0 queries + scope_unavailable
    def test_missing_binding_queries_nothing(self):
        rows = json.loads(fx.bindings_raw())
        items = plan_incident(fx.request(), json.dumps([rows[1]]))  # primary (db) binding removed
        primary = [i for i in items if i["scope_role"] == "primary"]
        self.assertEqual({i["unavailable_reason"] for i in primary}, {"source_unknown"})
        for item in primary:
            _, _, acq = self.run_item(item)
            self.assertEqual((acq["status"], acq["status_reason"], acq["page_count"], acq["api"]),
                             ("scope_unavailable", "source_unknown", 0, None))
        self.assertEqual(self.sources.calls, [])

    # ⑥ network-experiment is refused before any request
    def test_forbidden_stream_is_refused(self):
        item = plan_incident(fx.request(), fx.bindings_raw())[0]
        bad = {**item, "query_text": '{job="network-experiment"}'}
        with self.assertRaises(ValueError):
            self.run_item(bad)
        self.assertEqual(self.sources.calls, [])
        with self.assertRaises(ForbiddenSelector):
            request = fx.request()
            request["alert"]["labels"] = {**request["alert"]["labels"], "alertname": "heldout"}
            request.pop("expected_incident_id")
            plan_incident(request, fx.bindings_raw())

    def test_returned_forbidden_stream_blocks_commit(self):
        item = next(i for i in plan_incident(fx.request(), fx.bindings_raw()) if i["stream_class"] == "db_log")

        def fault(request, _):
            if request.url.path == "/loki/api/v1/query_range":
                body = {"status": "success", "data": {"resultType": "streams", "result": [
                    {"stream": {"job": "network-experiment"}, "values": [["1794279600000000000", "x"]]}]}}
                return httpx.Response(200, content=dumps(body))
            return None

        with self.assertRaises(ValueError):
            self.run_item(item, transport=mock_transport(self.sources, fault))
        self.assertEqual(self.store.manifests("bronze"), [])

    # ⑦ metric query strings == MetricsCollector strings
    def test_metric_queries_equal_collector(self):
        import asyncio
        collector = pipeline_compat.metrics_collector()
        corr = pipeline_compat.correlation()
        ident = pipeline_compat.identity()
        binding = ident.parse_bindings(fx.bindings_raw())[1]
        seen = []

        def handler(request):
            seen.append(request.url.params["query"])
            return httpx.Response(200, json={"status": "success", "data": {"resultType": "matrix", "result": []}})

        ctx = corr.CorrelationContext.around(binding.identity.service, corr.to_instant(fx.request()["alert"]["starts_at"]),
                                             __import__("datetime").timedelta(minutes=5), identity=binding.identity,
                                             binding=binding, runtime=binding.identity.runtime)
        asyncio.run(collector.MetricsCollector("http://capture", transport=httpx.MockTransport(handler))
                    .fetch_around(None, ctx.anchor, ctx=ctx))
        planned = [i["query_text"] for i in plan_incident(fx.request(), fx.bindings_raw())
                   if i["scope_role"] == "related" and i["stream_class"] == "metric"]
        self.assertEqual(planned, seen)

    # ⑧ L+1 entries with the same ns + a later entry -> truncated/same_ts_overflow, L rows, no loop
    def test_same_ns_overflow_stops(self):
        item = next(i for i in plan_incident({**fx.request(), "page_limit": 3}, fx.bindings_raw())
                    if i["stream_class"] == "db_log")
        ts = str(item["start_ns"] + 1)
        calls = {"n": 0}

        def fault(request, _):
            if request.url.path != "/loki/api/v1/query_range":
                return None
            calls["n"] += 1
            if calls["n"] > 3:
                raise AssertionError("cursor did not stop")
            limit = int(request.url.params["limit"])
            values = [[ts, f'{{"n":{i}}}'] for i in range(4)] + [[str(int(ts) + 5), '{"n":9}']]
            body = {"status": "success", "data": {"resultType": "streams", "result": [
                {"stream": {**item["expected_labels"], "log_format": "json"}, "values": values[:limit]}]}}
            return httpx.Response(200, content=dumps(body))

        _, manifest, acq = self.run_item(item, transport=mock_transport(self.sources, fault))
        self.assertEqual((acq["status"], acq["status_reason"], acq["row_count"], calls["n"]),
                         ("truncated", "same_ts_overflow", 3, 1))

    def test_first_page_failure_is_failed_and_recorded(self):
        item = next(i for i in plan_incident(fx.request(), fx.bindings_raw()) if i["stream_class"] == "db_log")

        def fault(request, _):
            return httpx.Response(503, content=b"down") if request.url.path.endswith("query_range") else None

        _, manifest, acq = self.run_item(item, transport=mock_transport(self.sources, fault))
        self.assertEqual((acq["status"], acq["status_reason"], acq["http_status_last"], manifest["status"]),
                         ("failed", "api_error", 503, "committed"))  # DQ-B01: failures leave a row

    def test_returned_label_mismatch_is_source_mismatch(self):
        item = next(i for i in plan_incident(fx.request(), fx.bindings_raw()) if i["stream_class"] == "db_log")

        def fault(request, _):
            if request.url.path == "/loki/api/v1/query_range":
                body = {"status": "success", "data": {"resultType": "streams", "result": [
                    {"stream": {"service": "other"}, "values": [["1794279600000000000", "x"]]}]}}
                return httpx.Response(200, content=dumps(body))
            return None

        _, manifest, acq = self.run_item(item, transport=mock_transport(self.sources, fault))
        self.assertEqual((acq["status"], acq["row_count"]), ("source_mismatch", 1))  # raw kept, flagged

    def test_ok_closed_acquisition_is_reused_unless_forced(self):
        item = next(i for i in plan_incident(fx.request(), fx.bindings_raw()) if i["stream_class"] == "db_log")
        first, _, _ = self.run_item(item)
        again, _, _ = self.run_item(item)
        self.assertEqual((again["status"], again["build_id"]), ("reused", first["build_id"]))
        forced, _, _ = self.run_item({**item, "force_reacquire": True})
        self.assertNotEqual(forced["build_id"], first["build_id"])
        self.assertEqual(len(self.store.manifests("bronze")), 2)  # previous acquisition preserved

    def test_open_window_is_marked(self):
        item = next(i for i in plan_incident(fx.request(), fx.bindings_raw()) if i["stream_class"] == "db_log")
        _, _, acq = self.run_item(item, clock="2026-11-10T03:10:00.000000Z")  # before window_end + 600s
        self.assertFalse(acq["window_closed"])

    # scenario run log (#71): the file is kept uninterpreted, one Bronze row per non-empty line
    def run_file(self, path):
        item = next(i for i in plan_incident(fx.request(), fx.bindings_raw()) if i["stream_class"] == "scenario_run")
        context = fx.run_context(fx.runs()[fx.FIRST_RUN], clock=fx.Clock("2026-11-10T03:20:09.000000Z"), hex8=self.hex)
        result = acquire(item, self.store, context, run_log_path=path, page_delay_s=0)
        manifest = self.store.read_manifest("bronze", result["build_id"])
        return (output_rows(self.store, manifest, "bronze.acquisition")[0],
                output_rows(self.store, manifest, "bronze.scenario_run_entry"))

    def test_scenario_run_log_is_kept_line_by_line(self):
        path = os.path.join(self.tmp.name, "runs.jsonl")
        body = b'{"scenario_id":"a"}\r\n\r\n{"scenario_id":"b"}\r\n'  # run.py on Windows writes CRLF
        with open(path, "wb") as fh:
            fh.write(body)
        acq, rows = self.run_file(path)
        self.assertEqual((acq["status"], acq["source_system"], acq["api"], acq["scope_role"], acq["query_text"],
                          acq["row_count"], acq["page_count"], acq["response_bytes"], acq["window_closed"]),
                         ("ok", "scenario_run_log", "file.read", "global", None, 2, 1, len(body), True))
        self.assertEqual(acq["raw_sha256"], [canonical.sha256_bytes(body)])
        self.assertEqual(self.store.get_raw(acq["raw_pages"][0]), body)
        self.assertEqual([(r["bronze_id"], r["line_no"], r["line"]) for r in rows],
                         [(canonical.bronze_id(acq["acquisition_id"], 0, 0), 1, '{"scenario_id":"a"}'),
                          (canonical.bronze_id(acq["acquisition_id"], 0, 1), 3, '{"scenario_id":"b"}')])
        self.assertEqual(rows[0]["record_key"], canonical.scenario_run_record_key('{"scenario_id":"a"}'))

    def test_scenario_run_log_states(self):
        empty = os.path.join(self.tmp.name, "empty.jsonl")
        open(empty, "wb").close()
        self.assertEqual(self.run_file(empty)[0]["status"], "empty_verified")
        missing = self.run_file(os.path.join(self.tmp.name, "absent.jsonl"))[0]
        self.assertEqual((missing["status"], missing["status_reason"], missing["raw_pages"], missing["page_count"]),
                         ("failed", "file_not_found", [], 0))
        with mock.patch.dict(os.environ):
            os.environ.pop("DP_SCENARIO_RUN_LOG", None)
            unset = self.run_file(None)[0]
        self.assertEqual((unset["status"], unset["status_reason"]), ("not_attempted", "run_log_unconfigured"))


if __name__ == "__main__":
    unittest.main()
