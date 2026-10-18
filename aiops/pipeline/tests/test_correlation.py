"""
#9 correlation identity 테스트.

실행 (pipeline 디렉터리에서):
    python -m unittest discover -s tests -v
"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from collector.logs import LogsCollector  # noqa: E402
from correlation import (  # noqa: E402
    CorrelationContext,
    resolve_service,
    service_log_selector,
    to_instant,
)


class ToInstantTest(unittest.TestCase):
    def test_kst_and_utc_are_the_same_instant(self):
        # Application Log(+09:00)와 Network Event(Z)가 같은 순간을 가리키면 같아야 한다
        kst = to_instant("2026-10-04T14:51:08.812+09:00")
        utc = to_instant("2026-10-04T05:51:08.812Z")
        self.assertEqual(kst, utc)
        self.assertEqual(utc.tzinfo, timezone.utc)

    def test_loki_epoch_ns(self):
        expected = datetime(2026, 10, 4, 5, 51, 8, tzinfo=timezone.utc)
        ns = int(expected.timestamp() * 1e9)
        self.assertEqual(to_instant(ns), expected)
        self.assertEqual(to_instant(str(ns)), expected)

    def test_naive_timestamp_is_rejected(self):
        with self.assertRaises(ValueError):
            to_instant("2026-10-04T05:51:08")
        with self.assertRaises(ValueError):
            to_instant(datetime(2026, 10, 4, 5, 51, 8))


class CorrelationContextTest(unittest.TestCase):
    def test_around_window_is_instant_based(self):
        ctx = CorrelationContext.around(
            "backend", "2026-10-04T05:00:00Z", timedelta(minutes=5),
            container_name="leafy-backend", runtime="container",
        )
        self.assertEqual(ctx.start, to_instant("2026-10-04T04:55:00Z"))
        self.assertEqual(ctx.end, to_instant("2026-10-04T05:05:00Z"))
        # 같은 구간을 KST로 표현한 시각도 포함되어야 한다
        self.assertTrue(ctx.contains("2026-10-04T14:03:00+09:00"))
        self.assertFalse(ctx.contains("2026-10-04T14:06:00+09:00"))
        self.assertEqual(ctx.end_ns - ctx.start_ns, 600 * 10**9)
        self.assertIsNone(ctx.request_id)

    def test_trailing_window(self):
        ctx = CorrelationContext.trailing("db", timedelta(seconds=600), now="2026-10-04T05:00:00Z")
        self.assertEqual(ctx.start, to_instant("2026-10-04T04:50:00Z"))
        self.assertEqual(ctx.end, to_instant("2026-10-04T05:00:00Z"))


class ServiceLogSelectorTest(unittest.TestCase):
    def test_selector_uses_service_label(self):
        self.assertEqual(service_log_selector("backend"), '{service="backend"}')

    def test_invalid_service_rejected(self):
        for bad in (None, "", 'a"b', "leafy db", "x}"):
            with self.assertRaises(ValueError):
                service_log_selector(bad)


def _docker(handler):
    return httpx.MockTransport(handler)


class ResolveServiceTest(unittest.IsolatedAsyncioTestCase):
    async def test_container_resolves_to_compose_service(self):
        def handler(request):
            self.assertEqual(request.url.path, "/containers/leafy-backend/json")
            return httpx.Response(200, json={
                "Config": {"Labels": {"com.docker.compose.service": "backend"}},
            })
        self.assertEqual(
            await resolve_service("leafy-backend", transport=_docker(handler)),
            ("backend", "container"),
        )

    async def test_db_resolves_without_name_mangling(self):
        # 문자열 가공이 아니라 라벨 값을 그대로 쓴다
        handler = lambda r: httpx.Response(200, json={
            "Config": {"Labels": {"com.docker.compose.service": "db"}},
        })
        self.assertEqual(await resolve_service("leafy-db", transport=_docker(handler)), ("db", "container"))

    async def test_unknown_container(self):
        handler = lambda r: httpx.Response(404, json={"message": "No such container"})
        self.assertEqual(await resolve_service("nope", transport=_docker(handler)), (None, None))

    async def test_container_without_compose_label(self):
        handler = lambda r: httpx.Response(200, json={"Config": {"Labels": {}}})
        self.assertEqual(await resolve_service("x", transport=_docker(handler)), (None, None))

    async def test_docker_unreachable(self):
        def handler(request):
            raise httpx.ConnectError("docker down")
        self.assertEqual(await resolve_service("leafy-backend", transport=_docker(handler)), (None, None))

    async def test_alert_placeholder_names(self):
        calls = []
        def handler(request):
            calls.append(request)
            return httpx.Response(404)
        # 빈 이름은 Docker를 조회하지 않는다
        self.assertEqual(await resolve_service("", transport=_docker(handler)), (None, None))
        self.assertEqual(calls, [])
        # alert rule의 "unknown (host-level)"은 컨테이너가 아니므로 해석 실패
        self.assertEqual(await resolve_service("unknown (host-level)", transport=_docker(handler)), (None, None))


class LogsCollectorTest(unittest.IsolatedAsyncioTestCase):
    async def test_queries_by_service_never_by_container(self):
        seen = {}

        def handler(request):
            seen.update(request.url.params)
            return httpx.Response(200, json={"data": {"result": [{
                "stream": {"service": "backend", "container": "backend",
                           "container_name": "leafy-backend"},
                "values": [["2000000000000000000", "message=b"], ["1000000000000000000", "message=a"]],
            }]}})

        ctx = CorrelationContext.around(
            "backend", "2026-10-04T05:00:00Z", timedelta(minutes=5),
            container_name="leafy-backend", runtime="container",
        )
        logs = await LogsCollector("http://loki:3100", transport=_docker(handler)).fetch(ctx)

        # 기존 버그: {container="leafy-backend"} -> aiops-llm 자체 출력이 반환되었다
        self.assertEqual(seen["query"], '{service="backend"}')
        self.assertNotIn("container", seen["query"])
        self.assertEqual(int(seen["start"]), ctx.start_ns)
        self.assertEqual(int(seen["end"]), ctx.end_ns)
        self.assertEqual([l["line"] for l in logs], ["message=a", "message=b"])  # ts 순 정렬

    async def test_unresolved_service_skips_query(self):
        def handler(request):
            raise AssertionError("service가 없으면 Loki를 조회하면 안 된다")

        ctx = CorrelationContext.around(None, "2026-10-04T05:00:00Z", timedelta(minutes=5))
        self.assertEqual(await LogsCollector("http://loki:3100", transport=_docker(handler)).fetch(ctx), [])


if __name__ == "__main__":
    unittest.main()
