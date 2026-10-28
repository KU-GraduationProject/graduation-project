"""Run with uvicorn agent.api:create_app --factory --workers 1 --port 8002."""
import asyncio
from contextlib import asynccontextmanager
import logging
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool
import yaml

from agent.contract import AgentConfig, Command
from agent.ledger import Conflict, Ledger
from agent.service import AgentService, Denied
from security.agent_auth import authenticate

log = logging.getLogger(__name__)


class InstanceLock:
    """Fail startup if another process uses this ledger (single-worker contract)."""
    def __init__(self, path):
        self.file = open(path, "a+b")
        try:
            if os.name == "nt":
                import msvcrt
                self.file.seek(0)
                if not self.file.read(1):
                    self.file.write(b"0")
                    self.file.flush()
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            self.file.close()
            raise

    def close(self):
        self.file.close()


def read_secret():
    path = os.getenv("AGENT_HMAC_KEY_FILE")
    secret = Path(path).read_text(encoding="utf-8").strip() if path else os.getenv("AGENT_HMAC_KEY", "")
    if secret and secret in (os.getenv("REMEDIATION_API_KEY"), os.getenv("SLACK_SIGNING_SECRET")):
        raise ValueError("Agent must use a separate HMAC key")
    return secret


def create_app(service=None, secret=None):
    if service is None:
        path = os.getenv("AGENT_ALLOWLIST_PATH")
        config = AgentConfig.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8"))) \
            if path else AgentConfig(controller_id="pc1")
        service = AgentService(config, Ledger(os.getenv("AGENT_STATE_PATH", "/app/state/agent.sqlite3")),
                               mode=os.getenv("AGENT_MODE", "disabled"))
    secret = read_secret() if secret is None else secret

    @asynccontextmanager
    async def lifespan(app):
        lock = InstanceLock(service.ledger.path + ".lock")
        service.reconcile_interrupted()
        async def scan():
            while True:
                try:
                    await run_in_threadpool(service.tick)
                except Exception:
                    log.exception("Agent TTL scan failed; evidence retained")
                await asyncio.sleep(5)
        task = asyncio.create_task(scan())
        try:
            yield
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            lock.close()

    app = FastAPI(title="Leafy Remediation Agent", version="1.0", lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.service = service

    async def authenticated_body(request):
        if request.url.query:
            raise HTTPException(400, "query_parameters_not_supported")
        body = b""
        async for chunk in request.stream():
            body += chunk
            if len(body) > 65536:
                raise HTTPException(413, "request_too_large")
        try:
            ok = authenticate(secret, request.method, request.url.path, body, request.headers,
                              service.config.controller_id, service.ledger)
        except Exception:
            # No persistence means no replay protection, hence no execution.
            raise HTTPException(503, "authentication_store_unavailable") from None
        if not ok:
            raise HTTPException(401, "unauthorized")
        return body

    @app.get("/healthz")
    async def health():
        # Liveness only. Never inspect Docker, expose targets or claim operational readiness.
        return {"status": "ok", "mode": service.mode, "auth_configured": bool(secret and len(secret) >= 32),
                "remote_auto_execute": False}

    async def dispatch(request, recovery=False):
        body = await authenticated_body(request)
        try:
            command = Command.model_validate_json(body)
        except ValidationError:
            raise HTTPException(422, "invalid_command") from None
        try:
            fn = service.recover if recovery else service.execute
            return await run_in_threadpool(fn, command)
        except Denied as exc:
            raise HTTPException(403, str(exc)) from None
        except Conflict as exc:
            raise HTTPException(409, str(exc)) from None

    @app.post("/v1/executions")
    async def execute(request: Request):
        return await dispatch(request)

    @app.post("/v1/recoveries")
    async def recover(request: Request):
        return await dispatch(request, recovery=True)

    @app.get("/v1/executions/{rid}/{target}")
    async def status(rid: str, target: str, request: Request):
        await authenticated_body(request)
        record = await run_in_threadpool(service.ledger.get, rid, target)
        if record is None:
            raise HTTPException(404, "unknown_remediation_id")
        return record

    return app
