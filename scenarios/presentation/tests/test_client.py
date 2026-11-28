import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import httpx

from scenarios.presentation.client import Airflow, Backend, Injector, clean, worker_command
from types import SimpleNamespace
from scenarios.presentation.config import Config
from scenarios.presentation.state import Run
from .test_state import IDENTITY


class AdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_signed_read_and_verify_operations_are_not_action_requests(self):
        calls = []
        def handle(request):
            body = json.loads(request.content)
            self.assertIn('x-aiops-signature', request.headers)
            calls.append((request.url.path, body))
            return httpx.Response(200, json={"contexts": [], "record": None})
        backend = Backend(Config(), httpx.MockTransport(handle))
        self.addAsyncCleanup(backend.close)
        with patch.dict(os.environ, {"REMEDIATION_API_KEY": "fixture-only-key"}):
            run = Run("f", IDENTITY)
            await backend.status(run); await backend.status(run); await backend.verify("rid")
        self.assertNotEqual(calls[0][1]["nonce"], calls[1][1]["nonce"])
        self.assertEqual(calls[2], ("/service/verify", {"operation": "verify_service", "remediation_id": "rid"}))
        self.assertFalse(any(path == "/action" for path, _ in calls))

    async def test_airflow_trigger_and_poll_contract_and_auth_refresh(self):
        calls = []
        def handle(request):
            calls.append((request.method, request.url.path))
            if request.url.path == "/auth/token":
                return httpx.Response(200, json={"access_token": "fixture-only"})
            if request.headers.get("Authorization") != "Bearer fixture-only":
                return httpx.Response(401)
            if request.method == "POST":
                body = json.loads(request.content)
                self.assertIn("logical_date", body)
                self.assertTrue(body["dag_run_id"].startswith("leafy_tui__"))
                return httpx.Response(200, json={**body, "state": "queued"})
            if request.url.path.endswith("/dags"):
                return httpx.Response(200, json={"dags": [{"dag_id": "dp_bronze_acquire"}, {"dag_id": "other"}]})
            return httpx.Response(200, json={"state": "success"})
        client = Airflow(Config(), httpx.MockTransport(handle)); self.addAsyncCleanup(client.close)
        with patch.dict(os.environ, {"AIRFLOW_USERNAME": "fixture", "AIRFLOW_PASSWORD": "fixture"}):
            self.assertEqual([d['dag_id'] for d in await client.dags()], ["dp_bronze_acquire"])
            rid, path, body = await client.trigger("dp_bronze_acquire", {})
            await client.request("POST", path, json=body)
            self.assertEqual((await client.run("dp_bronze_acquire", rid))["state"], "success")
        self.assertEqual(sum(method == "POST" and p.endswith("/dagRuns") for method, p in calls), 1)

    async def test_uncertain_airflow_post_is_never_retried(self):
        calls = []
        def handle(request):
            calls.append(request)
            raise httpx.ReadTimeout("fixture", request=request)
        client = Airflow(Config(), httpx.MockTransport(handle)); self.addAsyncCleanup(client.close)
        with self.assertRaises(httpx.ReadTimeout):
            await client.request("POST", "/dags/dp_bronze_acquire/dagRuns", json={})
        self.assertEqual(len(calls), 1)

    async def test_metric_multiple_series_never_becomes_zero(self):
        def handle(request):
            return httpx.Response(200, json={"status": "success", "data": {"resultType": "vector", "result": [
                {"metric": {"job": "x"}, "value": [time.time(), "1"]},
                {"metric": {"job": "x"}, "value": [time.time(), "2"]}]}})
        backend = Backend(Config(metric_selector={"job": "x"}), httpx.MockTransport(handle))
        self.addAsyncCleanup(backend.close)
        self.assertTrue(all(v is None for v in (await backend.metrics()).values()))

    async def test_evidence_formatter_reuses_model_input_ids(self):
        backend = Backend(Config()); self.addAsyncCleanup(backend.close)
        run = Run("f", IDENTITY)
        run.context = {"builder": "v2", "alert": {"startsAt": "2026-01-01T00:00:00Z"}, "metrics": {
            "cpu_usage": [{"values": [{"t": 1767225600, "v": 1.2}]}]}, "logs": [
                {"ts": 1767225600, "line": "ERROR database unavailable", "labels": {}}]}
        text = await backend.evidence(run)
        self.assertIn("[M1] cpu_usage", text)
        self.assertIn("[L1]", text)

    async def test_execution_logs_are_bound_to_remediation_id(self):
        def handle(request):
            values = [[str(time.time_ns()), json.dumps({"remediation_id": rid, "event": "execution_completed", "status": "VERIFIED"})]
                      for rid in ("current", "other")]
            return httpx.Response(200, json={"status": "success", "data": {"resultType": "streams",
                "result": [{"stream": {"job": "aiops-remediation"}, "values": values}]}})
        backend = Backend(Config(), httpx.MockTransport(handle)); self.addAsyncCleanup(backend.close)
        run = Run("f", IDENTITY, remediation_id="current")
        rows = await backend.execution_logs(run)
        self.assertEqual(rows, ["execution_completed · VERIFIED"])

    async def test_remote_exit_without_cleanup_ack_is_not_confirmed_cleanup(self):
        injector = Injector(Config(), Run("f", IDENTITY), lambda event: None)
        injector.process = SimpleNamespace(returncode=255)
        injector.injected = True
        with self.assertRaisesRegex(RuntimeError, "정리 응답 미확인"):
            await injector.close()


class ProcessCommandTests(unittest.TestCase):
    def test_local_and_remote_hosts_are_independent_of_aiops_host(self):
        cfg = Config(runner={"mode": "local", "python": "python3"})
        cmd, _ = worker_command(cfg, "f1_b_memory_leak")
        self.assertEqual(cmd[:3], ["python3", "-u", "-m"])
        cfg.runner = {"mode": "ssh", "host": "scenario-pc", "repo": "/a path/repo", "python": "/a path/python"}
        cmd, _ = worker_command(cfg, "f1_b_memory_leak")
        self.assertEqual(cmd[:5], ["ssh", "-T", "-o", "BatchMode=yes", "scenario-pc"])
        self.assertIn("cd '/a path/repo'", cmd[-1])
        cfg.runner["shell"] = "powershell"
        self.assertIn("-EncodedCommand", worker_command(cfg, "f1_b_memory_leak")[0][-1])

    def test_untrusted_terminal_data_has_no_control_sequence(self):
        self.assertNotIn("\x1b", clean("\x1b[2Jpassword=fixture"))
        self.assertNotIn("fixture", clean("password=fixture"))
