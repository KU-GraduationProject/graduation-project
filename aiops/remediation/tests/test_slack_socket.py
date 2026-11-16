"""Socket Mode contracts with fake Slack and FakeDocker; no external IO."""
import asyncio
import json
import os
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from slack_socket import SlackSettings, SocketModeRuntime, create_client
from tests import test_phase2_integration as phase2


class SettingsTests(unittest.TestCase):
    def config(self, **env):
        with patch.dict(os.environ, env, clear=True):
            return SlackSettings.from_env()

    def test_default_is_socket_without_http_fallback(self):
        self.assertEqual(self.config().transport, "socket_mode")
        self.assertEqual(self.config().app_token, "")

    def test_token_needs_workspace_and_approvers(self):
        for env in ({"SLACK_APP_TOKEN": "xapp-fixture"},
                    {"SLACK_APP_TOKEN": "xapp-fixture", "SLACK_TEAM_ID": "TTEST"},
                    {"SLACK_APP_TOKEN": "xoxb-fixture"},
                    {"SLACK_TRANSPORT": "typo"}, {"SLACK_APPROVAL_TTL_SEC": "0"}):
            with self.subTest(env_keys=list(env)), self.assertRaises(ValueError):
                self.config(**env)

    def test_valid_config_uses_ids_and_hides_token_in_repr(self):
        cfg = self.config(SLACK_APP_TOKEN="xapp-fixture", SLACK_TEAM_ID="TTEST",
                          SLACK_ALLOWED_USER_IDS="UTEST, WOTHER")
        self.assertEqual(cfg.allowed_users, {"UTEST", "WOTHER"})
        self.assertNotIn("xapp-fixture", repr(cfg))


class FakeClient:
    def __init__(self):
        self.socket_mode_request_listeners = []
        self.connected = False
        self.acks = []
        self.closed = False

    async def connect(self):
        self.connected = True

    async def is_connected(self):
        return self.connected

    async def close(self):
        self.closed = True
        self.connected = False

    async def send_socket_mode_response(self, response):
        self.acks.append(response)


class RuntimeTests(unittest.IsolatedAsyncioTestCase):
    def make_runtime(self, dispatch=None, client=None):
        client = client or FakeClient()
        cfg = SlackSettings(app_token="xapp-fixture")
        runtime = SocketModeRuntime(cfg, dispatch or AsyncMock(),
                                    client_factory=lambda _: client,
                                    response_factory=lambda eid: eid)
        self.addAsyncCleanup(runtime.close)
        return runtime, client

    def request(self, eid="envelope-1", type="interactive"):
        return SimpleNamespace(envelope_id=eid, type=type, payload={"type": "block_actions"})

    async def test_acks_before_dispatch_and_deduplicates_envelope(self):
        client = FakeClient()
        observed = []
        async def dispatch(payload):
            observed.append(len(client.acks))
        runtime, _ = self.make_runtime(dispatch, client)
        await runtime.receive(client, self.request())
        await runtime.receive(client, self.request())
        await asyncio.gather(*tuple(runtime.pending))
        self.assertEqual(client.acks, ["envelope-1", "envelope-1"])
        self.assertEqual(observed, [2])

    async def test_slow_action_does_not_block_next_envelope_ack(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def slow(payload):
            entered.set()
            await release.wait()
        runtime, client = self.make_runtime(slow)
        await runtime.receive(client, self.request())
        await entered.wait()
        await runtime.receive(client, self.request("envelope-2"))
        self.assertEqual(len(client.acks), 2)
        release.set()
        await runtime.close()
        self.assertFalse(runtime.pending)

    async def test_connect_health_and_shutdown(self):
        runtime, client = self.make_runtime()
        await runtime.start()
        await runtime.supervisor
        self.assertEqual(client.socket_mode_request_listeners, [runtime.receive])
        self.assertTrue((await runtime.health())["connected"])
        client.connected = False
        self.assertEqual((await runtime.health())["status"], "reconnecting")
        await runtime.close()
        self.assertTrue(client.closed)

    async def test_unconfigured_never_creates_network_client(self):
        factory = AsyncMock()
        runtime = SocketModeRuntime(SlackSettings(), AsyncMock(), client_factory=factory)
        await runtime.start()
        self.assertEqual((await runtime.health())["status"], "not_configured")
        factory.assert_not_called()
        await runtime.close()

    async def test_initial_connect_failure_retries_with_fresh_client(self):
        broken, healthy = FakeClient(), FakeClient()
        broken.connect = AsyncMock(side_effect=OSError("do not log bearer material"))
        runtime, _ = self.make_runtime()
        clients = iter([broken, healthy])
        runtime.client_factory = lambda _: next(clients)
        with patch("slack_socket.asyncio.sleep", new=AsyncMock()) as sleep:
            await runtime.start()
            await runtime.supervisor
        self.assertTrue(broken.closed)
        self.assertTrue(healthy.connected)
        sleep.assert_awaited_once_with(1)

    async def test_noninteractive_event_acked_without_dispatch(self):
        dispatch = AsyncMock()
        runtime, client = self.make_runtime(dispatch)
        await runtime.receive(client, self.request(type="events_api"))
        self.assertEqual(len(client.acks), 1)
        dispatch.assert_not_awaited()

    async def test_over_capacity_does_not_ack_new_work(self):
        runtime, client = self.make_runtime()
        runtime.pending = set(range(32))
        await runtime.receive(client, self.request())
        self.assertFalse(client.acks)
        runtime.pending.clear()

    async def test_handler_error_does_not_dump_payload_or_exception(self):
        runtime, client = self.make_runtime(AsyncMock(side_effect=ValueError("secret-response-url")))
        with self.assertLogs("slack_socket", level="ERROR") as logs:
            await runtime.receive(client, self.request())
            await asyncio.gather(*tuple(runtime.pending))
        self.assertIn("ValueError", " ".join(logs.output))
        self.assertNotIn("secret-response-url", " ".join(logs.output))

    async def test_real_sdk_can_initialize_and_close_without_connecting(self):
        client = create_client(SlackSettings(app_token="xapp-fixture"))
        try:
            self.assertFalse(await client.is_connected())
            self.assertTrue(client.auto_reconnect_enabled)
        finally:
            await client.close()

    async def test_real_sdk_envelope_response_contract(self):
        from slack_sdk.socket_mode.request import SocketModeRequest
        from slack_sdk.socket_mode.response import SocketModeResponse
        runtime, client = self.make_runtime()
        runtime.response_factory = None
        request = SocketModeRequest(type="events_api", envelope_id="sdk-envelope", payload={})
        await runtime.receive(client, request)
        self.assertIsInstance(client.acks[0], SocketModeResponse)
        self.assertEqual(client.acks[0].envelope_id, "sdk-envelope")

    async def test_close_cancels_connection_in_progress(self):
        client = FakeClient()
        entered = asyncio.Event()
        async def wait_forever():
            entered.set()
            await asyncio.Event().wait()
        client.connect = wait_forever
        runtime, _ = self.make_runtime(client=client)
        await runtime.start()
        await entered.wait()
        await runtime.close()
        self.assertTrue(client.closed)
        self.assertTrue(runtime.supervisor.cancelled())

    async def test_shutdown_during_ack_never_dispatches_after_close(self):
        dispatch = AsyncMock()
        runtime, client = self.make_runtime(dispatch)
        entered, release = asyncio.Event(), asyncio.Event()
        async def delayed_ack(response):
            entered.set()
            await release.wait()
        client.send_socket_mode_response = delayed_ack
        receiving = asyncio.create_task(runtime.receive(client, self.request()))
        await entered.wait()
        await runtime.close()
        release.set()
        await receiving
        dispatch.assert_not_awaited()

    async def test_ack_failure_does_not_claim_or_execute_envelope(self):
        dispatch = AsyncMock()
        runtime, client = self.make_runtime(dispatch)
        client.send_socket_mode_response = AsyncMock(side_effect=OSError("disconnected"))
        with self.assertRaises(OSError):
            await runtime.receive(client, self.request())
        self.assertFalse(runtime.seen)
        self.assertFalse(runtime.pending)
        dispatch.assert_not_awaited()


class SocketActionTests(phase2.Phase2Base):
    def setUp(self):
        super().setUp()
        self.main.slack_settings = SlackSettings(team_id="TTEST", allowed_users=frozenset({"UTEST"}))
        update = patch.object(self.main, "_update_slack_message", new=AsyncMock())
        update.start()
        self.addCleanup(update.stop)

    def propose(self):
        response = self.post_action(phase2.analysis_body("RESTART"))
        self.assertEqual(response.status_code, 200)
        return response.json()["remediation_id"]

    def payload(self, rid, action_id="approve_action"):
        return {"type": "block_actions", "team": {"id": "TTEST"}, "user": {"id": "UTEST"},
                "actions": [{"action_id": action_id, "value": json.dumps({
                    "alertname": "UnauthorizedDataTransfer", "action_type": "RESTART",
                    "action_targets": ["leafy-backend"], "remediation_id": rid})}]}

    def dispatch(self, payload):
        return asyncio.run(self.main.handle_socket_action(payload))

    def test_http_callback_closed_in_socket_mode(self):
        self.assertEqual(self.post_slack(phase2.approve_form("RESTART")).status_code, 410)
        self.assertEqual(self.docker_actions(), [])

    def test_workspace_and_user_allowlist_deny_before_execution(self):
        rid = self.propose()
        for field, value in (("team", {"id": "TOTHER"}), ("user", {"id": "UOTHER"}),
                             ("user", {"name": "UTEST"}), ("type", "shortcut")):
            payload = self.payload(rid)
            payload[field] = value
            self.assertEqual(self.dispatch(payload).status_code, 403)
        self.assertEqual(self.docker_actions(), [])

    def test_old_button_cannot_create_execution_record(self):
        self.assertEqual(self.dispatch(self.payload(None)).status_code, 404)
        self.assertEqual(self.main.record_store.all(), [])
        self.assertEqual(self.docker_actions(), [])

    def test_changed_plan_cannot_execute_stored_record(self):
        rid = self.propose()
        payload = self.payload(rid)
        value = json.loads(payload["actions"][0]["value"])
        value["action_targets"] = ["another-container"]
        payload["actions"][0]["value"] = json.dumps(value)
        self.assertEqual(self.dispatch(payload).status_code, 409)
        self.assertEqual(self.docker_actions(), [])

    def test_expired_or_future_approval_cannot_execute(self):
        rid = self.propose()
        for stamp in ("2000-01-01T00:00:00Z", "2999-01-01T00:00:00Z", None):
            self.main.record_store.update(rid, approval_requested_at=stamp)
            self.assertEqual(self.dispatch(self.payload(rid)).status_code, 409)
        self.assertEqual(self.docker_actions(), [])

    def test_approval_uses_user_id_and_executes_at_most_once(self):
        rid = self.propose()
        self.assertEqual(self.dispatch(self.payload(rid)).status_code, 200)
        self.assertEqual(self.record(rid).approved_by, "UTEST")
        self.assertEqual(self.docker_actions().count("restart"), 1)
        self.assertEqual(self.dispatch(self.payload(rid)).status_code, 409)
        self.assertEqual(self.docker_actions().count("restart"), 1)

    def test_reject_is_durable_and_blocks_later_approval(self):
        rid = self.propose()
        self.assertEqual(self.dispatch(self.payload(rid, "reject_action")).status_code, 200)
        self.assertEqual(self.record(rid).state, self.main.store_mod.REJECTED)
        restored = self.main.store_mod.RecordStore(self.main.record_store.path)
        restored.load()
        self.assertEqual(restored.get(rid).rejected_by, "UTEST")
        self.assertEqual(self.dispatch(self.payload(rid)).status_code, 409)
        self.assertEqual(self.docker_actions(), [])

    def test_late_reject_cannot_undo_approval(self):
        rid = self.propose()
        self.main.record_store.mark_approved(rid, "UTEST")
        self.assertEqual(self.dispatch(self.payload(rid, "reject_action")).status_code, 409)
        self.assertEqual(self.record(rid).state, self.main.store_mod.APPROVED)

    def test_arbitrary_callback_url_cannot_trigger_outbound_update(self):
        rid = self.propose()
        payload = self.payload(rid)
        payload["response_url"] = "http://127.0.0.1:2375/actions/fixture"
        self.assertEqual(self.dispatch(payload).status_code, 400)
        self.assertEqual(self.docker_actions(), [])
        self.main._update_slack_message.assert_not_awaited()

    def test_invalid_response_url_is_rejected_without_execution(self):
        rid = self.propose()
        for url in (None, "https://hooks.slack.com:wrong/actions/example",
                    "https://hooks.slack.com@evil.invalid/actions/example"):
            payload = self.payload(rid)
            payload["response_url"] = url
            self.assertEqual(self.dispatch(payload).status_code, 400)
        self.assertEqual(self.docker_actions(), [])

    def test_disabled_mode_still_does_not_execute(self):
        rid = self.propose()
        self.main.executor = self.main.DisabledExecutor()
        self.assertEqual(self.dispatch(self.payload(rid)).status_code, 200)
        self.assertEqual(self.record(rid).state, self.main.store_mod.SKIPPED)
        self.assertEqual(self.docker_actions(), [])

    def test_recovery_approval_uses_separate_request_time(self):
        rid = self.propose()
        self.main.record_store.update(rid, state=self.main.store_mod.RECOVERY_APPROVAL_REQUIRED,
                                      approval_requested_at="2000-01-01T00:00:00Z",
                                      recovery_approval_requested_at=self.main.store_mod.utcnow())
        with patch.object(self.main.recovery_mod, "recover", return_value=([], "RECOVERED")) as recover:
            self.assertEqual(self.dispatch(self.payload(rid, "approve_recovery")).status_code, 200)
        recover.assert_called_once()

    def test_malformed_button_value_cannot_execute(self):
        rid = self.propose()
        for value in ("[]", "null", "not-json", None, '{"action_type": null}'):
            payload = self.payload(rid)
            payload["actions"][0]["value"] = value
            self.assertEqual(self.dispatch(payload).status_code, 400)
        self.assertEqual(self.docker_actions(), [])

    def test_fastapi_lifespan_starts_and_closes_socket(self):
        from fastapi.testclient import TestClient
        client = FakeClient()
        self.main.slack_settings = SlackSettings(app_token="xapp-fixture")
        factory = lambda cfg, dispatch: SocketModeRuntime(cfg, dispatch, client_factory=lambda _: client)
        with patch.object(self.main, "SocketModeRuntime", side_effect=factory):
            with TestClient(self.main.app) as api:
                health = api.get("/health").json()
                self.assertTrue(health["slack"]["connected"])
                self.assertEqual(health["slack"]["status"], "connected")
        self.assertTrue(client.closed)
        self.assertIsNone(self.main.slack_socket)
