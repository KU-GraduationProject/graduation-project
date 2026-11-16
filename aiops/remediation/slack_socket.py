"""Outbound-only Slack Socket Mode transport. Never dispatch HTTP bodies here."""
import asyncio
from collections import OrderedDict
from dataclasses import dataclass, field
import logging
import os
import re

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SlackSettings:
    transport: str = "socket_mode"
    app_token: str = field(default="", repr=False)
    team_id: str = ""
    allowed_users: frozenset = frozenset()
    approval_ttl: int = 900

    @classmethod
    def from_env(cls):
        mode = os.getenv("SLACK_TRANSPORT", "socket_mode")
        if mode not in {"socket_mode", "http", "disabled"}:
            raise ValueError("SLACK_TRANSPORT must be socket_mode, http or disabled")
        ttl = int(os.getenv("SLACK_APPROVAL_TTL_SEC", "900"))
        if not 1 <= ttl <= 86400:
            raise ValueError("SLACK_APPROVAL_TTL_SEC must be 1..86400")
        config = cls(mode, os.getenv("SLACK_APP_TOKEN", "").strip(),
                     os.getenv("SLACK_TEAM_ID", "").strip(),
                     frozenset(x.strip() for x in os.getenv("SLACK_ALLOWED_USER_IDS", "").split(",") if x.strip()),
                     ttl)
        if mode == "socket_mode" and config.app_token:
            if not config.app_token.startswith("xapp-"):
                raise ValueError("SLACK_APP_TOKEN must be an app-level xapp token")
            if not re.fullmatch(r"T[A-Z0-9]+", config.team_id):
                raise ValueError("SLACK_TEAM_ID is required for Socket Mode")
            if not config.allowed_users or any(not re.fullmatch(r"[UW][A-Z0-9]+", u) for u in config.allowed_users):
                raise ValueError("SLACK_ALLOWED_USER_IDS must contain Slack member IDs")
        return config


def create_client(config):
    # The app token opens the socket. Messages still use the existing Incoming
    # Webhook and response_url, so no bot Web API token is needed by this adapter.
    from slack_sdk.socket_mode.aiohttp import SocketModeClient
    from slack_sdk.web.async_client import AsyncWebClient
    sdk_logger = logging.getLogger("remediation.slack_sdk")
    sdk_logger.setLevel(logging.CRITICAL)  # SDK debug output can include payloads/URLs.
    return SocketModeClient(app_token=config.app_token, logger=sdk_logger,
                            web_client=AsyncWebClient(logger=sdk_logger),
                            auto_reconnect_enabled=True, trace_enabled=False)


class SocketModeRuntime:
    """ACK promptly; keep slow Docker/HTTP work off the SDK message listener.

    Pending tasks are bounded and drained at graceful shutdown. The ACK is
    transport receipt, not durable acceptance or execution success. If the
    process is killed after ACK, the operator can click again; the durable
    remediation record is the execution idempotency boundary.
    """
    def __init__(self, config, dispatch, client_factory=create_client, response_factory=None):
        self.config, self.dispatch = config, dispatch
        self.client_factory, self.response_factory = client_factory, response_factory
        self.client = None
        self.supervisor = None
        self.pending = set()
        self.seen = OrderedDict()
        self.closing = False
        self.status = "not_configured" if not config.app_token else "starting"

    async def start(self):
        if not self.config.app_token:
            logger.warning("[Slack Socket] not configured; SLACK_APP_TOKEN is missing")
            return
        self.supervisor = asyncio.create_task(self._connect(), name="slack-socket-connect")

    async def _connect(self):
        delay = 1
        while not self.closing:
            try:
                self.client = self.client_factory(self.config)
                self.client.socket_mode_request_listeners.append(self.receive)
                await self.client.connect()
                self.status = "connected"
                logger.info("[Slack Socket] connected")
                return  # SDK owns ongoing ping/pong and reconnection.
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.status = "retrying"
                logger.warning("[Slack Socket] connection failed (%s); retrying", type(exc).__name__)
                if self.client:
                    try:
                        await self.client.close()
                    except Exception as close_error:
                        logger.warning("[Slack Socket] client cleanup failed (%s)", type(close_error).__name__)
                    self.client = None
                await asyncio.sleep(delay)
                delay = min(delay * 2, 30)

    async def receive(self, client, request):
        if self.closing:
            return
        # Do not ACK work beyond the capacity limit; Slack may redeliver it.
        if request.envelope_id not in self.seen and len(self.pending) >= 32:
            logger.warning("[Slack Socket] handler capacity reached; envelope not acknowledged")
            return
        if self.response_factory:
            response = self.response_factory(request.envelope_id)
        else:
            from slack_sdk.socket_mode.response import SocketModeResponse
            response = SocketModeResponse(envelope_id=request.envelope_id)
        await client.send_socket_mode_response(response)
        if self.closing:
            return
        if request.envelope_id in self.seen:
            return
        self.seen[request.envelope_id] = None
        if len(self.seen) > 4096:
            self.seen.popitem(last=False)
        if request.type != "interactive":
            return
        task = asyncio.create_task(self._dispatch(request.payload), name="slack-action")
        self.pending.add(task)
        task.add_done_callback(self.pending.discard)

    async def _dispatch(self, payload):
        try:
            await self.dispatch(payload)
        except Exception as exc:
            # Payloads contain response URLs; never dump them or exception text.
            logger.error("[Slack Socket] action handler failed (%s)", type(exc).__name__)

    async def health(self):
        connected = bool(self.client and await self.client.is_connected())
        state = self.status
        if state == "connected" and not connected:
            state = "reconnecting"
        return {"transport": "socket_mode", "status": state, "connected": connected,
                "pending_actions": len(self.pending)}

    async def close(self):
        self.closing = True
        if self.supervisor:
            self.supervisor.cancel()
            await asyncio.gather(self.supervisor, return_exceptions=True)
        if self.client:
            await self.client.close()
        if self.pending:
            # A forced container kill can still interrupt a mutation; existing
            # record reconciliation marks that uncertainty on the next startup.
            await asyncio.gather(*tuple(self.pending), return_exceptions=True)
        self.status = "stopped"
