"""Detection payload -> RCA fixture -> real Pipeline/Controller/Agent -> health -> service recovery time.

LLM/collectors/Slack/health metrics and Docker are fixtures. All application paths,
HMAC checks, HTTP parsing and durable state transitions run in process.
"""
import asyncio
from contextlib import contextmanager, ExitStack
from datetime import datetime, timezone
import json
from pathlib import Path
import runpy
import sys
import time
import unittest
from unittest.mock import AsyncMock, patch

import httpx
import service_verification
from tests import test_remote_deployment_flow as remote_fixture
from tests import test_service_verification as health_fixture


@contextmanager
def pipeline_image():
    # The real services intentionally have separate import roots/images. Isolate
    # those roots temporarily without subprocesses or changing application code.
    roots = {"main", "config", "schemas", "policy", "security", "collector", "prompt", "identity", "correlation"}
    affected = lambda name: name.split(".")[0] in roots
    snapshot = {name:module for name,module in sys.modules.items() if affected(name)}
    path = Path(__file__).resolve().parents[2] / "pipeline"
    for name in snapshot:
        sys.modules.pop(name, None)
    sys.path.insert(0, str(path))
    try:
        yield runpy.run_path(str(path / "main.py"), run_name="pipeline_image_fixture")
    finally:
        sys.path.remove(str(path))
        for name in list(sys.modules):
            if affected(name):
                sys.modules.pop(name, None)
        sys.modules.update(snapshot)


class PipelineAgentEndToEndTests(unittest.TestCase):
    def setUp(self):
        remote_fixture.RemoteDeploymentFlowTests.setUp(self)

    post_action = remote_fixture.RemoteDeploymentFlowTests.post_action
    post_slack = remote_fixture.RemoteDeploymentFlowTests.post_slack
    approve = remote_fixture.RemoteDeploymentFlowTests.approve

    def test_detection_to_rca_manual_approval_remote_recreate_health_and_durable_service_recovery(self):
        identity = self.fixture.identity
        profile = health_fixture.profile()
        profile["profiles"][0]["identity"] = identity
        profile_path = Path(self.fixture.tmp.name) / "health.json"
        profile_path.write_text(json.dumps(profile))
        sent = []
        original_client = httpx.AsyncClient
        async def controller_http(request):
            sent.append(request)
            async with original_client(transport=httpx.ASGITransport(app=self.main.app), base_url="http://controller") as client:
                return await client.post(request.url.path, content=request.content, headers=dict(request.headers))
        with patch.dict("os.environ", {service_verification.CONFIG_ENV:str(profile_path)}), pipeline_image() as pipeline:
            from identity import parse_bindings, LogEvidence, MetricEvidence
            from collector.network import NetworkContext
            binding = parse_bindings(json.dumps([{"identity":identity, "match":{"site":identity["site"], "target":identity["target"]}}]))[0]
            anchor = datetime.now(timezone.utc)
            network = NetworkContext("backend", anchor, anchor, provenance={"status":"empty"})
            result = pipeline["LLMAnalysisResult"](root_cause="Synthetic deployment configuration failure",
                incident_class="failure", action_type="RECREATE", action_targets=[identity["target"]],
                evidence=["fixture app errors"], confidence=.95, threat_level="high")
            self.assertEqual(result.analysis_status, "valid")
            alert = pipeline["Alert"](status="firing", startsAt=datetime.fromtimestamp(time.time()-120, timezone.utc).isoformat(),
                fingerprint="pipeline-agent-fixture", labels=pipeline["AlertLabel"](alertname="UnauthorizedDataTransfer", **identity))
            settings = pipeline["settings"]
            with ExitStack() as stack:
                stack.enter_context(patch.object(settings,"remediation_approval_enabled",True))
                stack.enter_context(patch.object(settings,"remediation_notification_enabled",False))
                stack.enter_context(patch.object(settings,"remediation_api_key",self.main.REMEDIATION_API_KEY))
                # run_path returns a copy; functions retain their original globals.
                globals_ = pipeline["analyze_alerts"].__globals__
                stack.enter_context(patch.dict(globals_, {"_observation_bindings":(binding,),
                    "call_llm":AsyncMock(return_value=result), "push_to_loki":AsyncMock(return_value=True)}))
                stack.enter_context(patch.object(pipeline["metrics_collector"],"fetch_around",AsyncMock(return_value=MetricEvidence(status="empty"))))
                stack.enter_context(patch.object(pipeline["logs_collector"],"fetch",AsyncMock(return_value=LogEvidence([{"line":"fixture"}],status="ok"))))
                stack.enter_context(patch.object(pipeline["network_collector"],"fetch",AsyncMock(return_value=network)))
                stack.enter_context(patch.object(pipeline["prompt_builder"],"build",return_value={"system":"fixture","user":"fixture"}))
                stack.enter_context(patch.object(httpx,"AsyncClient",side_effect=lambda **kw:original_client(transport=httpx.MockTransport(controller_http),**kw)))
                asyncio.run(pipeline["analyze_alerts"]([alert]))
            self.assertEqual(len(sent),1)
            self.assertEqual(json.loads(sent[0].content)["operation"],"propose_manual_action")
            records = self.main.record_store.all()
            self.assertEqual(len(records),1)
            record = records[0]
            self.assertEqual(record.state,"AWAITING_APPROVAL")
            self.assertEqual(self.fixture.fake.calls,[])
            self.assertEqual(record.service_verification["state"],"PENDING")
            response = self.approve("RECREATE",record.remediation_id)
            self.assertEqual(response.json()["record_state"],"VERIFIED",response.text)
            self.assertIsNone(record.time_to_service_recovery())
            verified_at = datetime.fromisoformat(record.action_verified_at).timestamp()
            now = verified_at + 10
            def health_http(request):
                if request.url.host == "health.fixture.invalid":
                    return httpx.Response(200,json={"status":"UP"})
                value = str(now) if request.url.params["query"].startswith("timestamp(") else "1"
                return httpx.Response(200,json={"status":"success","data":{"resultType":"vector",
                    "result":[{"metric":{},"value":[now,value]}]}})
            with httpx.Client(transport=httpx.MockTransport(health_http)) as checks:
                for offset in (10,20,30):
                    now = verified_at + offset
                    service_verification.verify_record(self.main.record_store,record,now=now,client=checks)
            self.assertEqual(record.service_verification["state"],"RECOVERED")
            self.assertGreaterEqual(record.time_to_service_recovery(),120)
            restored = self.main.store_mod.RecordStore(self.main.record_store.path)
            restored.load()
            self.assertEqual(restored.get(record.remediation_id).time_to_service_recovery(),record.time_to_service_recovery())
