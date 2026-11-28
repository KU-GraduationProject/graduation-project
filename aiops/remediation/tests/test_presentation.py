import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
import httpx

from tests.test_endpoint_auth import load_main, API_KEY
from security.signing import sign
from tests.safety_fixtures import IDENTITY


class PresentationApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.module, _ = load_main(mode="disabled", state_dir=self.tmp.name)
        self.client = TestClient(self.module.app)
        audit = patch.object(self.module, "_push_soc_event", AsyncMock())
        audit.start(); self.addCleanup(audit.stop)
        self.body = {"operation": "presentation_status", "nonce": "fixture-nonce", "identity": IDENTITY,
                     "since": "2026-01-01T00:00:00Z"}

    def request(self, body=None, signed=True):
        raw = json.dumps(body or self.body).encode()
        stamp = str(time.time())
        headers = {"content-type": "application/json"}
        if signed:
            headers.update({"x-aiops-timestamp": stamp, "x-aiops-signature": sign(API_KEY, stamp, raw)})
        return self.client.post("/presentation/status", content=raw, headers=headers)

    def test_auth_scope_and_operation_are_required_without_executor_calls(self):
        self.assertEqual(self.request(signed=False).status_code, 401)
        self.assertEqual(self.request({**self.body, "operation": "propose_action"}).status_code, 422)
        self.assertEqual(self.request({**self.body, "identity": {"service": "backend"}}).status_code, 422)
        self.assertEqual(self.request({**self.body, "since": "2026-01-01T00:00:00"}).status_code, 422)
        self.assertEqual(self.request().json()["mode"], "disabled")

    def test_context_filters_exact_identity_and_record_omits_sensitive_evidence(self):
        ctx = {"received_at": "2026-01-02T00:00:00Z", "alert": {"labels": IDENTITY}, "metrics": {}, "logs": []}
        Path(self.tmp.name, "context.json").write_text(json.dumps(ctx))
        Path(self.tmp.name, "other.json").write_text(json.dumps({**ctx, "alert": {"labels": {**IDENTITY, "site": "other"}}}))
        with patch.dict(os.environ, {"PRESENTATION_CONTEXT_DIR": self.tmp.name}):
            response = self.request()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["contexts"], [ctx])
        record = self.module.store_mod.RemediationRecord("read-rid", "fixture", "RESTART", identity=IDENTITY,
            evidence={"secret": "fixture-private"}, action_parameters={"token": "fixture-private"},
            results=[{"status": "FAILED", "detail": "executor_not_ready", "private": "fixture-private"}])
        self.module.record_store.create(record)
        body = self.request({**self.body, "remediation_id": "read-rid"}).json()["record"]
        self.assertNotIn("fixture-private", json.dumps(body))
        self.assertEqual(body["results"][0]["detail"], "executor_not_ready")


class SlackLinkTests(unittest.IsolatedAsyncioTestCase):
    async def test_same_buttons_use_bot_transport_and_get_real_permalink(self):
        from actions.notify import Notifier
        calls = []
        def handle(request):
            calls.append(request)
            if request.url.path.endswith("chat.postMessage"):
                self.assertEqual(json.loads(request.content)["blocks"], [{"type": "divider"}])
                return httpx.Response(200, json={"ok": True, "channel": "CTEST", "ts": "1.2"})
            return httpx.Response(200, json={"ok": True, "permalink": "https://fixture.slack.com/archives/CTEST/p12"})
        client = httpx.AsyncClient(transport=httpx.MockTransport(handle))
        with patch.dict(os.environ, {"SLACK_BOT_TOKEN": "fixture-only", "SLACK_CHANNEL_ID": "CTEST"}), \
             patch("actions.notify.httpx.AsyncClient", return_value=client):
            result = await Notifier()._send_slack("fixture", {"blocks": [{"type": "divider"}]})
        self.assertEqual(result["status"], "SUCCESS")
        self.assertEqual(result["message_url"], "https://fixture.slack.com/archives/CTEST/p12")
        self.assertEqual(len(calls), 2)
