"""
Gemini RCA 호출 테스트.

A. Mock 단위 테스트 — 실제 API 키·네트워크 없이 SDK 클라이언트를 가짜로 바꿔 검증한다.
B. 실제 API Smoke Test — GEMINI_SMOKE=1 과 GEMINI_API_KEY 가 모두 있을 때만 실행 (그 외 SKIP).

실행 (pipeline 디렉터리에서):
    python -m unittest tests.test_gemini_rca -v
    GEMINI_SMOKE=1 GEMINI_API_KEY=... python -m unittest tests.test_gemini_rca.GeminiSmokeTest -v
"""

import json
import os
import sys
import time
import unittest
from contextlib import ExitStack
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from google.genai import errors as genai_errors

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import main  # noqa: E402
from collector.network import NetworkContext  # noqa: E402
from identity import LogEvidence, MetricEvidence, parse_bindings  # noqa: E402
from schemas.llm_output import output_schema  # noqa: E402

VALID_RCA = {
    "root_cause": "leafy-backend CPU is saturated and requests time out.",
    "incident_class": "failure",
    "action_type": "THROTTLE",
    "action_targets": ["leafy-backend"],
    "target_evidence": [],
    "threat_level": "medium",
    "evidence": ["cpu_usage: latest=2.1, peak=2.4", "HTTP 200 still returned"],
    "confidence": 0.9,
}
PROMPT = {"system": "fixture-system", "user": "fixture-user"}
REAL_ASYNC_CLIENT = httpx.AsyncClient  # setUp 이 main.httpx.AsyncClient 를 바꾸기 전의 원본


def response(text, finish="STOP"):
    usage = SimpleNamespace(prompt_token_count=1200, candidates_token_count=150, total_token_count=1350)
    return SimpleNamespace(text=text, usage_metadata=usage, candidates=[SimpleNamespace(finish_reason=finish)])


def api_error(code, status):
    cls = genai_errors.ServerError if code >= 500 else genai_errors.ClientError
    return cls(code, {"error": {"code": code, "message": "fixture", "status": status}})


class GeminiMockCase(unittest.IsolatedAsyncioTestCase):
    """SDK Client·asyncio.sleep·Loki 오류 푸시를 가짜로 바꾼다. 실제 대기·외부 호출 없음."""

    def setUp(self):
        self.generate = AsyncMock()
        self.fake_client = MagicMock()
        self.fake_client.aio.models.generate_content = self.generate
        self.fake_client.aio.aclose = AsyncMock()
        self.loki_posts = []

        async def loki(request):
            self.loki_posts.append(request)
            return httpx.Response(204)

        factory = REAL_ASYNC_CLIENT
        self.stack = ExitStack()
        self.client_cls = self.stack.enter_context(patch.object(main.genai, "Client", return_value=self.fake_client))
        self.sleep = self.stack.enter_context(patch.object(main.asyncio, "sleep", AsyncMock()))
        self.stack.enter_context(patch.object(main.httpx, "AsyncClient",
                                              side_effect=lambda **kw: factory(transport=httpx.MockTransport(loki), **kw)))
        for name, value in {"llm_provider": "gemini", "gemini_api_key": "fixture-gemini-key",
                            "gemini_model": "fixture-model", "gemini_max_retries": 2,
                            "gemini_retry_base_delay": 2.0, "gemini_timeout": 30.0}.items():
            self.stack.enter_context(patch.object(main.settings, name, value))

    def tearDown(self):
        self.stack.close()

    def backoff_delays(self):
        return [c.args[0] for c in self.sleep.await_args_list if c.args and c.args[0] in (2.0, 4.0)]

    def assert_failed_rca(self, result):
        # #30 엄격 검증: 실패는 NONE 으로 메우지 않고 NOTIFY(사람 확인)로 남긴다.
        self.assertTrue(result.root_cause.startswith("분석 실패"))
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.action_type, "NOTIFY")
        self.assertEqual(result.analysis_status, "invalid")


class GeminiRcaUnitTests(GeminiMockCase):
    async def test_valid_json_returns_valid_rca_with_structured_output(self):
        self.generate.return_value = response(json.dumps(VALID_RCA))
        with self.assertLogs(main.logger, "INFO") as logs:
            result = await main.call_llm(PROMPT)
        self.assertEqual(result.analysis_status, "valid")
        self.assertEqual(result.action_type, "THROTTLE")
        self.assertEqual(result.action_targets, ["leafy-backend"])
        self.generate.assert_awaited_once()
        kwargs = self.generate.await_args.kwargs
        self.assertEqual(kwargs["model"], "fixture-model")
        self.assertEqual(kwargs["contents"], "fixture-user")
        config = kwargs["config"]
        self.assertEqual(config.system_instruction, "fixture-system")
        self.assertEqual(config.response_mime_type, "application/json")
        self.assertEqual(config.response_json_schema, main._gemini_schema(output_schema(None)))
        self.assertEqual(config.temperature, main.settings.llm_temperature)
        # 키는 SDK 생성자에만 전달되고 로그에는 남지 않는다. 토큰·응답 시간은 기록된다.
        self.assertEqual(self.client_cls.call_args.kwargs["api_key"], "fixture-gemini-key")
        self.assertEqual(self.client_cls.call_args.kwargs["http_options"].timeout, 30000)
        text = "\n".join(logs.output)
        self.assertNotIn("fixture-gemini-key", text)
        self.assertIn("prompt_tokens=1200", text)
        self.assertIn("output_tokens=150", text)
        self.assertIn("latency=", text)
        self.fake_client.aio.aclose.assert_awaited()
        self.assertEqual(self.loki_posts, [])

    async def test_json_parse_failure_twice_is_not_success(self):
        self.generate.return_value = response("not json {")
        result = await main.call_llm(PROMPT)
        self.assert_failed_rca(result)
        self.assertEqual(self.generate.await_count, 2)  # 기존 계약: JSON 재요청 1회
        self.assertIn("valid JSON only", self.generate.await_args_list[1].kwargs["contents"])
        self.assertEqual(len(self.loki_posts), 1)  # aiops-llm-error 기록

    async def test_missing_required_field_marks_analysis_invalid(self):
        partial = {k: v for k, v in VALID_RCA.items() if k != "confidence"}
        self.generate.return_value = response(json.dumps(partial))
        result = await main.call_llm(PROMPT)
        self.assertEqual(result.analysis_status, "invalid")
        self.assertIn("missing_field:confidence", result.invalid_reasons)

    async def test_timeout_fails_without_retry(self):
        self.generate.side_effect = httpx.ReadTimeout("fixture timeout")
        result = await main.call_llm(PROMPT)
        self.assert_failed_rca(result)
        self.assertEqual(self.generate.await_count, 1)

    async def test_rate_limit_is_retried_with_backoff_then_succeeds(self):
        self.generate.side_effect = [api_error(429, "RESOURCE_EXHAUSTED"), response(json.dumps(VALID_RCA))]
        result = await main.call_llm(PROMPT)
        self.assertEqual(result.analysis_status, "valid")
        self.assertEqual(self.generate.await_count, 2)
        self.assertEqual(self.backoff_delays(), [2.0])

    async def test_server_error_retries_are_bounded(self):
        self.generate.side_effect = api_error(503, "UNAVAILABLE")
        result = await main.call_llm(PROMPT)
        self.assert_failed_rca(result)
        # 1회 + 재시도 2회에서 멈춘다. call_llm 의 JSON 재요청 루프가 이를 다시 곱하지 않는다.
        self.assertEqual(self.generate.await_count, 3)
        self.assertEqual(self.backoff_delays(), [2.0, 4.0])

    async def test_rate_limit_exhausted_stops(self):
        self.generate.side_effect = api_error(429, "RESOURCE_EXHAUSTED")
        result = await main.call_llm(PROMPT)
        self.assert_failed_rca(result)
        self.assertEqual(self.generate.await_count, 3)

    async def test_non_retryable_client_error_fails_immediately(self):
        self.generate.side_effect = api_error(400, "INVALID_ARGUMENT")
        result = await main.call_llm(PROMPT)
        self.assert_failed_rca(result)
        self.assertEqual(self.generate.await_count, 1)
        self.assertEqual(self.backoff_delays(), [])

    async def test_missing_api_key_is_config_error_without_request(self):
        with patch.object(main.settings, "gemini_api_key", ""), self.assertLogs(main.logger, "ERROR") as logs:
            result = await main.call_llm(PROMPT)
        self.assert_failed_rca(result)
        self.client_cls.assert_not_called()
        self.generate.assert_not_awaited()
        self.assertIn("GEMINI_API_KEY", "\n".join(logs.output))

    async def test_empty_response_body_is_not_success(self):
        self.generate.return_value = response(None, finish="SAFETY")
        result = await main.call_llm(PROMPT)
        self.assert_failed_rca(result)
        self.assertEqual(self.generate.await_count, 1)

    async def test_unknown_provider_is_config_error(self):
        with patch.object(main.settings, "llm_provider", "fixture-unknown"):
            result = await main.call_llm(PROMPT)
        self.assert_failed_rca(result)
        self.client_cls.assert_not_called()

    async def test_periodic_raw_call_uses_gemini_without_rca_schema(self):
        self.generate.return_value = response(json.dumps({"is_healthy": True}))
        self.assertEqual(await main._call_llm_raw(PROMPT), {"is_healthy": True})
        self.assertIsNone(self.generate.await_args.kwargs["config"].response_json_schema)


IDENTITY = {"site": "gc", "service": "backend", "source": "pc2", "runtime": "container", "target": "leafy-backend"}


class GeminiRcaFlowTests(GeminiMockCase):
    """Alert → 증거 수집(가짜 collector) → 실제 PromptBuilder → Gemini(가짜) → Remediation 승인 요청.

    Remediation 은 MockTransport 로 받기만 하며 조치는 실행되지 않는다.
    """

    async def run_flow(self):
        main._recent_alerts.clear()
        main.analysis_history.clear()
        binding = parse_bindings(json.dumps([{"identity": IDENTITY,
                                              "match": {"site": IDENTITY["site"], "target": IDENTITY["target"]}}]))[0]
        anchor = datetime.now(timezone.utc)
        logs = LogEvidence([{"ts": time.time(), "labels": {"container": "backend"},
                             "line": "ERROR request timeout password=fixture-db-secret"}], status="ok")
        seen = []

        async def remediation(request):
            seen.append(request)
            return httpx.Response(200, json={"status": "pending_approval", "remediation_id": "fixture-rid",
                                             "dispatch": {"sent": True}})
        factory = REAL_ASYNC_CLIENT
        alert = main.Alert(status="firing", startsAt="2026-11-24T00:00:00Z", fingerprint="fixture-incident",
                           labels=main.AlertLabel(alertname="HighCpuUsage", **IDENTITY))
        with ExitStack() as stack:
            for name, value in {"remediation_approval_enabled": True, "remediation_notification_enabled": False,
                                "remediation_api_key": "fixture-api-key"}.items():
                stack.enter_context(patch.object(main.settings, name, value))
            stack.enter_context(patch.object(main, "_observation_bindings", (binding,)))
            stack.enter_context(patch.object(main.metrics_collector, "fetch_around", AsyncMock(
                return_value=MetricEvidence({"cpu_usage": [{"values": [{"t": time.time() - 60, "v": 2.1},
                                                                       {"t": time.time(), "v": 2.4}]}]},
                                            status="ok"))))
            stack.enter_context(patch.object(main.logs_collector, "fetch", AsyncMock(return_value=logs)))
            stack.enter_context(patch.object(main.network_collector, "fetch", AsyncMock(
                return_value=NetworkContext("backend", anchor, anchor, provenance={"status": "empty"}))))
            stack.enter_context(patch.object(main, "push_to_loki", AsyncMock(return_value=True)))
            stack.enter_context(patch.object(main.httpx, "AsyncClient", side_effect=lambda **kw: factory(
                transport=httpx.MockTransport(remediation), **kw)))
            await main.analyze_alerts([alert])
        return seen, main.analysis_history[-1]

    async def test_gemini_rca_reaches_manual_approval_request(self):
        # v2 프롬프트는 증거 ID 를 쓴다. 실제 프롬프트에 있는 경보 항목 [A1] 을 인용한다.
        # 대상(leafy-backend)은 ALERT [A1] 에 나온다 — 대상 근거로 인용해야 조치가 유지된다
        self.generate.return_value = response(json.dumps(dict(VALID_RCA, evidence=["A1"], target_evidence=["A1"])))
        seen, entry = await self.run_flow()
        sent_prompt = self.generate.await_args.kwargs["contents"]
        self.assertIn("leafy-backend", sent_prompt)
        self.assertNotIn("fixture-db-secret", sent_prompt)  # 기존 마스킹을 거친 로그만 전송
        self.assertEqual(entry["result"]["analysis_status"], "valid")
        self.assertEqual([r.url.path for r in seen], ["/action"])
        body = json.loads(seen[0].content)
        self.assertEqual(body["operation"], "propose_manual_action")
        self.assertIs(body["force_manual"], True)
        self.assertEqual(entry["handoff_status"], "approval_pending")
        self.assertFalse(entry["execution_attempted"])

    async def test_gemini_failure_never_opens_approval_path(self):
        self.generate.side_effect = api_error(429, "RESOURCE_EXHAUSTED")
        seen, entry = await self.run_flow()
        self.assertEqual(entry["result"]["analysis_status"], "invalid")
        self.assertNotIn("/action", [r.url.path for r in seen])
        self.assertFalse(entry["remediation_dispatched"])


@unittest.skipUnless(os.getenv("GEMINI_SMOKE") == "1" and os.getenv("GEMINI_API_KEY"),
                     "실제 Gemini 호출은 GEMINI_SMOKE=1 과 GEMINI_API_KEY 가 있을 때만 실행 (비용·무료 한도 보호)")
class GeminiSmokeTest(unittest.IsolatedAsyncioTestCase):
    """기존 CPU 장애 시나리오 형태의 증거로 실제 Gemini 1회 호출 → 기존 RCA 스키마 통과 확인."""

    async def test_real_gemini_rca_passes_existing_schema(self):
        alert = SimpleNamespace(labels=SimpleNamespace(alertname="HighCpuUsage", severity="warning"),
                                annotations={"container": "leafy-backend", "summary": "CPU usage above 80% for 2m"},
                                startsAt="2026-11-24T00:00:00Z")
        metrics = {"cpu_usage": [{"values": [{"v": 0.4}, {"v": 4.93}, {"v": 4.97}]}]}
        logs = [{"ts": time.time(), "labels": {"container": "backend"}, "line": "ERROR HTTP 503 upstream timeout"},
                {"ts": time.time(), "labels": {"container": "backend"}, "line": "WARN request queue saturated"}]
        prompt = main.prompt_builder.build(alert=alert, metrics=metrics, logs=logs, container_name="leafy-backend")
        with patch.object(main.settings, "llm_provider", "gemini"), \
             self.assertLogs(main.logger, "INFO") as logs_out:
            started = time.monotonic()
            result = await main.call_llm(prompt)
            elapsed = time.monotonic() - started
        usage = [line for line in logs_out.output if "provider=gemini" in line]
        print(f"\n[smoke] model={main.settings.gemini_model} elapsed={elapsed:.2f}s")
        print("\n".join(f"[smoke] {line}" for line in usage))
        print(f"[smoke] result={json.dumps(result.model_dump(), ensure_ascii=False)}")
        self.assertNotEqual(result.root_cause, FALLBACK_ROOT_CAUSE)
        self.assertEqual(result.analysis_status, "valid", result.invalid_reasons)


if __name__ == "__main__":
    unittest.main()
