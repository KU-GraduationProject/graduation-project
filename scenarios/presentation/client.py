"""HTTP and process adapters. Never approve Slack actions or synthesize RCA."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import shlex
import sys
import time
from urllib.parse import quote
import uuid

import httpx

from .config import selector
from .state import instant, now

ROOT = Path(__file__).resolve().parents[2]


def clean(value):
    """Untrusted logs must not inject terminal escapes, OSC links or Rich markup."""
    value = re.sub(r"\x1b\][^\x07]*(?:\x07|\x1b\\)", "", str(value))
    value = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value)
    value = "".join(c for c in value if c in "\n\t" or ord(c) >= 32 and ord(c) != 127)
    # Captured model inputs are already masked by pipeline.capture. Also mask
    # common credential assignments in live service/worker output.
    value = re.sub(r'''(?i)((?:password|token|secret|api[_-]?key|authorization)["']?\s*[=:]\s*["']?)[^"'\s,;}]+''', r'\1[REDACTED]', value)
    return value


def signed(body):
    secret = os.environ.get("REMEDIATION_API_KEY", "")
    if not secret:
        raise ValueError("REMEDIATION_API_KEY가 필요합니다")
    stamp = str(time.time())
    digest = hmac.new(secret.encode(), b"v0:" + stamp.encode() + b":" + body, hashlib.sha256).hexdigest()
    return {"Content-Type": "application/json", "x-aiops-timestamp": stamp, "x-aiops-signature": "v0=" + digest}


class Backend:
    def __init__(self, config, transport=None):
        self.config = config
        self.http = httpx.AsyncClient(timeout=8, transport=transport, trust_env=False, follow_redirects=False)

    async def close(self):
        await self.http.aclose()

    async def get(self, base, path, **kwargs):
        response = await self.http.get(base.rstrip("/") + path, **kwargs)
        response.raise_for_status()
        return response.json()

    async def status(self, run):
        body = json.dumps({"operation": "presentation_status", "nonce": uuid.uuid4().hex,
                           "identity": run.identity, "since": run.started_at,
                           "remediation_id": run.remediation_id}, separators=(",", ":")).encode()
        response = await self.http.post(self.config.remediation_url.rstrip("/") + "/presentation/status",
                                        content=body, headers=signed(body))
        response.raise_for_status()
        return response.json()

    async def verify(self, rid):
        body = json.dumps({"operation": "verify_service", "remediation_id": rid}, separators=(",", ":")).encode()
        response = await self.http.post(self.config.remediation_url.rstrip("/") + "/service/verify",
                                        content=body, headers=signed(body))
        response.raise_for_status()
        return response.json()

    async def logs(self, labels, since, limit=40):
        body = await self.get(self.config.loki_url, "/loki/api/v1/query_range", params={
            "query": selector(labels), "start": str(int(since * 1e9)),
            "end": str(time.time_ns()), "limit": limit, "direction": "backward"})
        if body.get("status") != "success" or body.get("data", {}).get("resultType") != "streams":
            raise ValueError("Loki response invalid")
        rows = []
        for stream in body["data"]["result"]:
            if any(stream["stream"].get(k) != v for k, v in labels.items()):
                raise ValueError("Loki source mismatch")
            rows.extend((int(ts), line) for ts, line in stream["values"])
        return [line for _, line in sorted(rows)]

    async def rca(self, since):
        lines = await self.logs({"job": "aiops-llm"}, since, limit=200)
        entries = []
        for line in lines:
            try:
                body = json.loads(line)
                if isinstance(body, dict):
                    entries.append(body)
            except ValueError:
                continue
        return entries

    async def evidence(self, run):
        proc = await asyncio.create_subprocess_exec(sys.executable, "-m", "scenarios.presentation.evidence",
            cwd=str(ROOT), stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        body = json.dumps({"context": run.context, "sources": run.rca.get("evidence_sources", {})}).encode()
        try:
            output, _ = await asyncio.wait_for(proc.communicate(body), 10)
            result = json.loads(output)
            return result.get("text")
        except (asyncio.TimeoutError, ValueError):
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
            return None

    async def execution_logs(self, run):
        if not run.remediation_id:
            return []
        lines = await self.logs({"job": "aiops-remediation"}, instant(run.started_at), limit=200)
        output = []
        for line in lines:
            try:
                row = json.loads(line)
                if row.get("remediation_id") == run.remediation_id:
                    output.append(" · ".join(str(row[k]) for k in
                        ("timestamp", "event", "state", "status", "reason", "message", "result") if row.get(k)))
            except (ValueError, AttributeError):
                continue
        return output[-15:]

    async def metrics(self):
        scope = selector(self.config.metric_selector)
        async def one(name, template):
            query = template.replace("{selector}", scope)
            body = await self.get(self.config.prometheus_url, "/api/v1/query", params={"query": query})
            rows = body.get("data", {}).get("result", [])
            if body.get("status") != "success" or body.get("data", {}).get("resultType") != "vector" or len(rows) != 1:
                return name, None
            row = rows[0]
            if any(row.get("metric", {}).get(k) != v for k, v in self.config.metric_selector.items()):
                raise ValueError("Prometheus source mismatch")
            ts, raw = row["value"]
            value = float(raw)
            # A sample's evaluation time alone cannot prove scrape freshness.
            # For display only, show timestamp; service_verification proves recovery.
            return name, (value, ts) if math.isfinite(value) and 0 <= time.time() - float(ts) <= 60 else None
        return dict(await asyncio.gather(*(one(k, v) for k, v in self.config.metric_names.items())))


class Airflow:
    def __init__(self, config, transport=None):
        self.base = config.airflow_url.rstrip("/")
        self.http = httpx.AsyncClient(timeout=10, transport=transport, trust_env=False, follow_redirects=False)
        self.token = os.getenv("AIRFLOW_API_TOKEN", "")

    async def close(self):
        await self.http.aclose()

    async def authenticate(self):
        user, password = os.getenv("AIRFLOW_USERNAME"), os.getenv("AIRFLOW_PASSWORD")
        if user and password:
            response = await self.http.post(self.base + "/auth/token", json={"username": user, "password": password})
            response.raise_for_status()
            self.token = response.json()["access_token"]

    async def request(self, method, path, **kwargs):
        headers = {"Authorization": "Bearer " + self.token} if self.token else {}
        response = await self.http.request(method, self.base + "/api/v2" + path, headers=headers, **kwargs)
        if response.status_code == 401 and os.getenv("AIRFLOW_USERNAME"):
            await self.authenticate()
            response = await self.http.request(method, self.base + "/api/v2" + path,
                headers={"Authorization": "Bearer " + self.token}, **kwargs)
        response.raise_for_status()
        return response.json()

    async def dags(self):
        # Only existing project DAGs can appear in the Trigger selector.
        body = await self.request("GET", "/dags", params={"limit": 100})
        return [r for r in body["dags"] if r["dag_id"].startswith("dp_")]

    async def trigger(self, dag_id, conf):
        stamp = now()
        rid = "leafy_tui__" + uuid.uuid4().hex
        path = "/dags/" + quote(dag_id, safe="") + "/dagRuns"
        # POST is deliberately not retried after network errors. rid is shown
        # before sending, so an uncertain submission can be queried by ID.
        return rid, path, {"dag_run_id": rid, "logical_date": stamp, "conf": conf}

    async def run(self, dag_id, rid):
        return await self.request("GET", "/dags/" + quote(dag_id, safe="") + "/dagRuns/" + quote(rid, safe=""))

    async def tasks(self, dag_id, rid):
        return await self.request("GET", "/dags/" + quote(dag_id, safe="") + "/dagRuns/" + quote(rid, safe="") + "/taskInstances")


def worker_command(config, scenario):
    args = ["-u", "-m", "scenarios.presentation.worker", scenario, "--hold", str(config.timeout)]
    runner = config.runner
    if runner.get("mode", "local") == "local":
        return [runner.get("python", sys.executable), *args], str(ROOT)
    host, repo = runner["host"], runner["repo"]
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@-]*", host):
        raise ValueError("runner.host must be an SSH alias")
    python = runner.get("python", "python3")
    if runner.get("shell", "posix") == "powershell":
        q = lambda s: "'" + s.replace("'", "''") + "'"
        script = "Set-Location -LiteralPath " + q(repo) + "; & " + " ".join(q(x) for x in [python, *args]) + "; exit $LASTEXITCODE"
        remote = "powershell -NoProfile -NonInteractive -EncodedCommand " + base64.b64encode(script.encode("utf-16-le")).decode()
    else:
        remote = "cd " + shlex.quote(repo) + " && exec " + shlex.join([python, *args])
    return ["ssh", "-T", "-o", "BatchMode=yes", host, remote], str(ROOT)


class Injector:
    def __init__(self, config, run, on_event):
        self.config, self.run, self.on_event = config, run, on_event
        self.process = None
        self.output = []
        self.readers = []
        self.injected = False
        self.cleanup_confirmed = False

    async def start(self):
        cmd, cwd = worker_command(self.config, self.run.scenario_id)
        self.process = await asyncio.create_subprocess_exec(*cmd, cwd=cwd, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        self.readers = [asyncio.create_task(self.read(self.process.stdout, True)),
                        asyncio.create_task(self.read(self.process.stderr, False))]

    async def read(self, stream, events):
        while line := await stream.readline():
            value = line.decode("utf-8", errors="replace").strip()
            if events:
                try:
                    event = json.loads(value)
                    if event.get("event") == "injected":
                        self.injected = True
                    elif event.get("event") == "cleanup":
                        self.cleanup_confirmed = event.get("ok") is True
                    self.on_event(event)
                    continue
                except (ValueError, TypeError):
                    pass
            self.output.append(clean(value))
            self.output = self.output[-50:]

    async def close(self):
        if not self.process:
            return
        if self.process.returncode is None:
            try:
                self.process.stdin.write(b"cleanup\n")
                await self.process.stdin.drain()
                self.process.stdin.close()
                await asyncio.wait_for(self.process.wait(), 20)
            except (BrokenPipeError, ConnectionResetError, asyncio.TimeoutError):
                # Do not kill a remote cleanup or watchdog. EOF plus its own
                # upper bound is the fallback; surface uncertainty to the UI.
                raise RuntimeError("주입기 정리 미확인 · 원격 watchdog/로그 확인 필요") from None
        await asyncio.gather(*self.readers)
        if self.injected and not self.cleanup_confirmed:
            raise RuntimeError("주입기 정리 응답 미확인 · 대상 호스트/안전 watchdog 로그를 확인하세요")
