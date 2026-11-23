"""경보 시점 입력 컨텍스트 저장 (CONTEXT_CAPTURE_DIR, 기본 꺼짐)."""
import asyncio
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import main  # noqa: E402
from collector.network import NetworkContext  # noqa: E402
from collector.rules import RuleContext  # noqa: E402
from identity import LogEvidence, MetricEvidence  # noqa: E402

T0 = datetime(2026, 11, 1, 7, 37, 9, tzinfo=timezone.utc)
RECEIVED = T0 + timedelta(seconds=19)
# eval/harness.py 가 읽는 observations 키
HARNESS_KEYS = {"received_at", "container", "rule", "metrics", "logs", "log_query", "network"}
JSON_LINE = json.dumps({"status": "401", "request_uri": "/api/v1/auth/login", "password": "hunter2",
                        "query": "token=abc123secret"})
TEXT_LINE = "FATAL: password authentication failed; Authorization: Bearer eyJabc.def.ghi"


def alert():
    return main.Alert(status="firing", startsAt=T0.isoformat().replace("+00:00", "Z"), fingerprint="fp1",
                      labels=main.AlertLabel(alertname="VulnerabilityScanningDetected", severity="warning"),
                      annotations={"container": "leafy-frontend"})


async def run(capture_dir):
    main._recent_alerts.clear()
    rule = RuleContext(name="VulnerabilityScanningDetected", source="loki", expr="x > 50", for_seconds=0,
                       range_seconds=60, ranges=("1m",), conditions=((">", 50.0),), value=59)
    metrics = MetricEvidence({"cpu_usage": [{"labels": {}, "values": [{"t": T0.timestamp(), "v": 0.1}]}]}, status="ok")
    logs = LogEvidence([{"ts": T0.timestamp() - 5, "labels": {"service": "frontend", "log_format": "json"}, "line": JSON_LINE},
                        {"ts": T0.timestamp() - 3, "labels": {"service": "frontend"}, "line": TEXT_LINE}], status="ok")
    net = NetworkContext(service="frontend", start=T0 - timedelta(minutes=2), end=RECEIVED,
                         events=({"src_service": "frontend", "request_uri": "/x?api_key=zzz999"},))
    with patch.object(main.settings, "context_capture_dir", capture_dir), \
         patch.object(main.settings, "prompt_builder", "v2"), \
         patch.object(main, "_observation_bindings", ()), \
         patch.object(main.rules_collector, "fetch", new_callable=AsyncMock, return_value=rule), \
         patch.object(main.metrics_collector, "fetch_around", new_callable=AsyncMock, return_value=metrics), \
         patch.object(main.logs_collector, "fetch", new_callable=AsyncMock, return_value=logs), \
         patch.object(main.network_collector, "fetch", new_callable=AsyncMock, return_value=net), \
         patch.object(main, "push_to_loki", new_callable=AsyncMock, return_value=True), \
         patch.object(main, "call_llm", new_callable=AsyncMock) as llm:
        await main.analyze_alerts([alert()], RECEIVED)
    return llm


class TestContextCapture(unittest.TestCase):
    def test_disabled_writes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            cwd = os.getcwd()
            os.chdir(d)
            try:
                asyncio.run(run(""))
            finally:
                os.chdir(cwd)
            self.assertEqual(os.listdir(d), [])

    def test_enabled_writes_harness_keys_masked(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "context")
            llm = asyncio.run(run(out))
            llm.assert_not_called()   # binding 없음 → LLM 미호출(main 계약). 저장은 그래도 한다
            files = os.listdir(out)
            self.assertEqual(len(files), 1)
            with open(os.path.join(out, files[0]), encoding="utf-8") as fh:
                raw = fh.read()
            ctx = json.loads(raw)
        self.assertTrue(HARNESS_KEYS <= set(ctx))
        self.assertEqual(ctx["alert"]["labels"]["alertname"], "VulnerabilityScanningDetected")
        self.assertEqual(ctx["rule"]["value"], 59)
        self.assertEqual(ctx["log_query"]["limit"], 200)
        self.assertEqual(ctx["received_at"], RECEIVED.isoformat())
        self.assertEqual(ctx["identity_status"], "source_unknown")
        # 마스킹: 원문 비밀값이 파일 어디에도 없다. JSON 줄은 JSON 그대로 남는다
        for secret in ("hunter2", "abc123secret", "eyJabc.def.ghi", "zzz999"):
            self.assertNotIn(secret, raw)
        rec = json.loads(ctx["logs"][0]["line"])
        self.assertEqual((rec["password"], rec["status"]), ("***", "401"))
        # pipeline 은 시나리오를 모른다: 시나리오 메타·정답 키 없음
        for key in ("scenario_id", "variant_id", "seed", "expected_action", "incident_class", "threat_level"):
            self.assertNotIn(f'"{key}"', raw)

    def test_save_failure_does_not_block_analysis(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:   # 파일 경로를 폴더로 주면 저장 실패
            path = f.name
        try:
            with self.assertLogs("main", level="WARNING") as logs:
                asyncio.run(run(os.path.join(path, "sub")))
            self.assertTrue(any("context 저장 실패" in m for m in logs.output))
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
