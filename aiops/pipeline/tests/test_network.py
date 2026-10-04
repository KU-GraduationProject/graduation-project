"""
#10 Network Context retrieval 테스트.

실행 (pipeline 디렉터리에서):
    python -m unittest discover -s tests -v
"""

import json
import os
import re
import sys
import unittest
from datetime import timedelta

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from collector.network import NetworkCollector  # noqa: E402
from correlation import CorrelationContext, network_event_selectors, to_instant  # noqa: E402

ANCHOR = "2026-10-04T05:00:00Z"
WINDOW = timedelta(minutes=5)


def event(src, dst, ts, cid, dst_port=8080, **overrides):
    """NETWORK_EVENT_SCHEMA.md v1.0 canonical event"""
    e = {
        "schema_version": "1.0", "timestamp": ts, "event_type": "connection", "observer": "network-observer",
        "src_service": src, "src_container": f"leafy-{src}", "src_runtime": "container",
        "src_ip": "10.0.0.1", "src_port": 40000,
        "dst_service": dst, "dst_container": f"leafy-{dst}", "dst_runtime": "container",
        "dst_ip": "10.0.0.2", "dst_port": dst_port,
        "protocol": "tcp", "network": "leafy-net", "interface": "eth0", "app_protocol": None,
        "connection_state": "closed", "duration_ms": 1, "bytes_sent": 183, "bytes_received": 415,
        "direction": None, "connection_id": cid, "request_id": None,
        "observer_instance": None, "observer_meta": {"zeek_uid": cid},
    }
    e.update(overrides)
    return e


class FakeLoki:
    """label selector와 start/end를 Loki처럼 적용하는 최소 emulator"""

    def __init__(self, entries, status=200, fail_on=None):
        # entries: [(labels, line_str, ts_ns)]
        self.entries, self.status, self.fail_on, self.queries = entries, status, fail_on, []

    @classmethod
    def of(cls, *events, **kw):
        rows = []
        for e in events:
            labels = {"log_type": "network", "event_type": e["event_type"], "src_service": e["src_service"],
                      "dst_service": e["dst_service"], "protocol": e["protocol"], "network": e["network"]}
            rows.append((labels, json.dumps(e), int(to_instant(e["timestamp"]).timestamp() * 1e9)))
        return cls(rows, **kw)

    def handler(self, request):
        q = request.url.params["query"]
        self.queries.append(q)
        if self.fail_on and self.fail_on in q:
            return httpx.Response(500, text="loki error")
        if self.status != 200:
            return httpx.Response(self.status, text="loki error")
        matchers = dict(re.findall(r'(\w+)="([^"]*)"', q))
        start, end = int(request.url.params["start"]), int(request.url.params["end"])
        streams = {}
        for labels, line, ts in self.entries:
            if all(labels.get(k) == v for k, v in matchers.items()) and start <= ts <= end:
                streams.setdefault(json.dumps(labels, sort_keys=True), []).append([str(ts), line])
        return httpx.Response(200, json={"data": {"result": [
            {"stream": json.loads(k), "values": v} for k, v in streams.items()]}})

    def collector(self):
        return NetworkCollector("http://loki:3100", transport=httpx.MockTransport(self.handler))


def ctx_for(service):
    return CorrelationContext.around(service, ANCHOR, WINDOW)


FRONT_TO_BACK = event("frontend", "backend", "2026-10-04T04:58:00.000Z", "C1")
BACK_TO_DB = event("backend", "db", "2026-10-04T05:01:00.000Z", "C2", dst_port=5432)
UNRELATED = event("unknown", "frontend", "2026-10-04T04:59:00.000Z", "C3", dst_port=443)
OUTSIDE = event("frontend", "backend", "2026-10-04T05:30:00.000Z", "C4")


class SelectorTest(unittest.TestCase):
    def test_two_selectors_src_and_dst(self):
        self.assertEqual(network_event_selectors("backend"), (
            '{log_type="network", src_service="backend"}',
            '{log_type="network", dst_service="backend"}',
        ))

    def test_invalid_service(self):
        with self.assertRaises(ValueError):
            network_event_selectors('a"b')


class ServiceScopeTest(unittest.IsolatedAsyncioTestCase):
    async def test_backend_gets_both_directions(self):
        loki = FakeLoki.of(FRONT_TO_BACK, BACK_TO_DB, UNRELATED, OUTSIDE)
        nc = await loki.collector().fetch(ctx_for("backend"))
        self.assertEqual([e["connection_id"] for e in nc.events], ["C1", "C2"])  # 시간 오름차순
        self.assertEqual(sorted(loki.queries), sorted(network_event_selectors("backend")))
        self.assertTrue(nc.query_complete)
        # canonical event를 재정의하지 않고 그대로 둔다
        self.assertEqual(nc.events[0], FRONT_TO_BACK)

    async def test_frontend_only_its_own_events(self):
        nc = await FakeLoki.of(FRONT_TO_BACK, BACK_TO_DB, UNRELATED).collector().fetch(ctx_for("frontend"))
        self.assertEqual([e["connection_id"] for e in nc.events], ["C1", "C3"])
        for e in nc.events:
            self.assertIn("frontend", (e["src_service"], e["dst_service"]))

    async def test_db_gets_backend_to_db(self):
        nc = await FakeLoki.of(FRONT_TO_BACK, BACK_TO_DB, UNRELATED).collector().fetch(ctx_for("db"))
        self.assertEqual([(e["src_service"], e["dst_service"]) for e in nc.events], [("backend", "db")])

    async def test_unrelated_excluded_even_if_loki_returns_it(self):
        # Loki가 엉뚱한 stream을 돌려줘도 service가 관여하지 않으면 버린다
        rogue = FakeLoki.of(UNRELATED)
        rogue.handler = lambda req: httpx.Response(200, json={"data": {"result": [
            {"stream": {}, "values": [["1", json.dumps(UNRELATED)]]}]}})
        nc = await NetworkCollector("http://loki:3100", transport=httpx.MockTransport(rogue.handler)).fetch(ctx_for("backend"))
        self.assertEqual(nc.events, ())


class WindowTest(unittest.IsolatedAsyncioTestCase):
    async def test_outside_window_excluded(self):
        nc = await FakeLoki.of(FRONT_TO_BACK, OUTSIDE).collector().fetch(ctx_for("backend"))
        self.assertEqual([e["connection_id"] for e in nc.events], ["C1"])

    async def test_window_checked_on_instant_even_if_loki_returns_it(self):
        # Loki가 창 밖 event를 돌려줘도 canonical timestamp(instant)로 다시 거른다
        rogue = lambda req: httpx.Response(200, json={"data": {"result": [
            {"stream": {}, "values": [["1", json.dumps(OUTSIDE)]]}]}})
        nc = await NetworkCollector("http://loki:3100", transport=httpx.MockTransport(rogue)).fetch(ctx_for("backend"))
        self.assertEqual(nc.events, ())

    async def test_kst_offset_timestamp_is_compared_as_instant(self):
        # 같은 순간을 +09:00으로 쓴 event도 창 안으로 판정되어야 한다
        kst = event("frontend", "backend", "2026-10-04T13:58:00.000+09:00", "C9")
        nc = await FakeLoki.of(kst).collector().fetch(ctx_for("backend"))
        self.assertEqual([e["connection_id"] for e in nc.events], ["C9"])


class DedupTest(unittest.IsolatedAsyncioTestCase):
    async def test_same_connection_in_src_and_dst_query_once(self):
        # src==dst==backend이면 두 query 모두에 나온다
        loop = event("backend", "backend", "2026-10-04T05:00:00.000Z", "C5")
        loki = FakeLoki.of(loop)
        nc = await loki.collector().fetch(ctx_for("backend"))
        self.assertEqual(len(loki.queries), 2)
        self.assertEqual([e["connection_id"] for e in nc.events], ["C5"])

    async def test_fallback_key_without_connection_id(self):
        loop = event("backend", "backend", "2026-10-04T05:00:00.000Z", None)
        other = event("backend", "backend", "2026-10-04T05:00:00.000Z", None, src_port=40001)
        nc = await FakeLoki.of(loop, other).collector().fetch(ctx_for("backend"))
        # 같은 5-tuple+시각은 1건, src_port가 다르면 다른 연결
        self.assertEqual(sorted(e["src_port"] for e in nc.events), [40000, 40001])


class DegradationTest(unittest.IsolatedAsyncioTestCase):
    async def test_zero_events_is_normal(self):
        nc = await FakeLoki.of().collector().fetch(ctx_for("backend"))
        self.assertEqual(nc.events, ())
        self.assertEqual(nc.errors, ())
        self.assertTrue(nc.query_complete)

    async def test_loki_500_does_not_raise(self):
        nc = await FakeLoki.of(FRONT_TO_BACK, status=500).collector().fetch(ctx_for("backend"))
        self.assertEqual(nc.events, ())
        self.assertEqual(len(nc.errors), 2)
        self.assertFalse(nc.query_complete)

    async def test_loki_unreachable_does_not_raise(self):
        def down(request):
            raise httpx.ConnectError("loki down")
        nc = await NetworkCollector("http://loki:3100", transport=httpx.MockTransport(down)).fetch(ctx_for("backend"))
        self.assertEqual(nc.events, ())
        self.assertFalse(nc.query_complete)

    async def test_partial_failure_keeps_other_direction(self):
        # dst query만 실패 -> src(backend -> db) 결과는 유지하고 불완전함을 표시
        loki = FakeLoki.of(FRONT_TO_BACK, BACK_TO_DB, fail_on="dst_service")
        nc = await loki.collector().fetch(ctx_for("backend"))
        self.assertEqual([e["connection_id"] for e in nc.events], ["C2"])
        self.assertEqual(len(nc.errors), 1)
        self.assertFalse(nc.query_complete)

    async def test_unresolved_service_no_query(self):
        def must_not_call(request):
            raise AssertionError("service가 없으면 조회하지 않는다")
        nc = await NetworkCollector("http://loki:3100", transport=httpx.MockTransport(must_not_call)).fetch(
            CorrelationContext.around(None, ANCHOR, WINDOW))
        self.assertEqual(nc.events, ())

    async def test_truncated_flag(self):
        events = [event("frontend", "backend", f"2026-10-04T04:58:0{i}.000Z", f"T{i}") for i in range(3)]
        nc = await FakeLoki.of(*events).collector().fetch(ctx_for("backend"), limit=3)
        self.assertTrue(nc.truncated)
        self.assertFalse(nc.query_complete)


class MalformedTest(unittest.IsolatedAsyncioTestCase):
    async def test_bad_events_skipped_good_ones_kept(self):
        bad_lines = [
            "not json",
            json.dumps(["array", "not object"]),
            json.dumps({k: v for k, v in FRONT_TO_BACK.items() if k != "timestamp"}),        # timestamp 없음
            json.dumps(dict(FRONT_TO_BACK, timestamp="2026-10-04T04:58:00")),                 # offset 없음
            json.dumps(dict(FRONT_TO_BACK, schema_version="2.0", connection_id="V2")),        # 미지원 MAJOR
            json.dumps({k: v for k, v in FRONT_TO_BACK.items() if k != "src_service"}),       # 필수 identity 없음
        ]
        ts = str(int(to_instant(FRONT_TO_BACK["timestamp"]).timestamp() * 1e9))
        values = [[ts, l] for l in bad_lines] + [[ts, json.dumps(BACK_TO_DB)]]
        handler = lambda req: httpx.Response(200, json={"data": {"result": [{"stream": {}, "values": values}]}})
        nc = await NetworkCollector("http://loki:3100", transport=httpx.MockTransport(handler)).fetch(ctx_for("backend"))
        self.assertEqual([e["connection_id"] for e in nc.events], ["C2"])
        self.assertEqual(nc.skipped, 2 * len(bad_lines))  # 두 query가 같은 응답을 받으므로 2배
        self.assertEqual(nc.errors, ())

    async def test_minor_schema_version_accepted(self):
        newer = dict(FRONT_TO_BACK, schema_version="1.1", new_optional_field="x")
        nc = await FakeLoki.of(newer).collector().fetch(ctx_for("backend"))
        self.assertEqual(len(nc.events), 1)
        self.assertEqual(nc.events[0]["new_optional_field"], "x")  # 모르는 필드는 무시하고 보존

    async def test_garbage_loki_response_does_not_raise(self):
        handler = lambda req: httpx.Response(200, text="<html>proxy error</html>")
        nc = await NetworkCollector("http://loki:3100", transport=httpx.MockTransport(handler)).fetch(ctx_for("backend"))
        self.assertEqual(nc.events, ())
        self.assertFalse(nc.query_complete)


if __name__ == "__main__":
    unittest.main()
