import asyncio
from datetime import datetime, timezone
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from textual.widgets import Select

from scenarios.presentation.app import AirflowScreen, ChooseScenario, Home, LeafyApp, ScenarioScreen
from scenarios.presentation.catalog import CATALOG
from scenarios.presentation.config import Config
from scenarios.presentation.state import now
from .test_state import IDENTITY


class UiTests(unittest.IsolatedAsyncioTestCase):
    async def test_keyboard_navigation_groups_and_responsive_scenario_screen(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = LeafyApp(Config(identity=IDENTITY, history=str(Path(tmp) / "history.db")))
            with patch.object(ScenarioScreen, "execute", lambda self: None):
                async with app.run_test(size=(120, 45)) as pilot:
                    self.assertIsInstance(app.screen, Home)
                    await pilot.click("#scenario")
                    self.assertIsInstance(app.screen, ChooseScenario)
                    for category, scenario in (("S", "s2_a_resource_theft"), ("F", "f1_b_memory_leak"), ("C", "c_b_short_load_spike")):
                        app.screen.query_one("#group", Select).value = category
                        await pilot.pause()
                        app.screen.query_one("#scenario-choice", Select).value = scenario
                        await pilot.pause()
                        self.assertFalse(app.screen.query_one("#launch").disabled)
                    await pilot.click("#launch")
                    self.assertIsInstance(app.screen, ScenarioScreen)
                    await pilot.resize_terminal(80, 40)
                    await pilot.pause()
                    self.assertTrue(app.screen.has_class("narrow"))
                    await pilot.press("escape")
                    self.assertIsInstance(app.screen, ChooseScenario)

    async def test_live_controller_reaches_completed_only_after_service_confirmation(self):
        started = datetime.now(timezone.utc).timestamp()
        def iso(n):
            return datetime.fromtimestamp(started + n, timezone.utc).isoformat()
        alert = {"labels": IDENTITY, "fingerprint": "ui-fixture", "startsAt": iso(1)}
        class TestBackend:
            count = 0
            async def status(self, run):
                self.count += 1
                record = None
                if run.remediation_id:
                    state = "AWAITING_APPROVAL" if self.count < 4 else "EXECUTING" if self.count < 5 else "VERIFIED"
                    record = {"remediation_id": "fixture-rid", "identity": IDENTITY, "alert_context": alert,
                        "state": state, "slack_dispatch_status": "SUCCESS", "slack_message_url": "https://fixture.slack.com/archives/C/p1",
                        "approval_requested_at": iso(3), "approval_expires_at": iso(600),
                        "approved_at": iso(4) if self.count >= 4 else None,
                        "action_started_at": iso(5) if self.count >= 4 else None,
                        "action_verified_at": iso(6) if self.count >= 5 else None,
                        "service_recovered_at": iso(10) if self.count >= 6 else None,
                        "results": [{"status": "SUCCESS", "verified": True}] if self.count >= 5 else [],
                        "service_verification": {"state": "RECOVERED" if self.count >= 6 else "CHECKING"}}
                return {"capture_status": "ok", "mode": "remote", "slack_link_configured": True,
                        "contexts": [{"alert": alert, "received_at": iso(2)}] if self.count > 1 else [], "record": record}
            async def get(self, *a): return {}
            async def metrics(self): return {"CPU cores": (1.2, started)}
            async def logs(self, *a): return ["fixture service event"]
            async def rca(self, *a):
                return [{"identity": IDENTITY, "alert_fingerprint": "ui-fixture", "alert_starts_at": iso(1),
                         "timestamp": iso(3), "remediation_id": "fixture-rid", "result": {
                             "root_cause": "fixture", "action_type": "RESTART", "action_targets": ["leafy-backend"]}}]
            async def evidence(self, run): return "[M1] fixture metric"
            async def execution_logs(self, run): return ["fixture · execution_completed"]
            async def verify(self, rid): return {}
            async def close(self): pass
        class TestInjector:
            output = []
            process = SimpleNamespace(returncode=None)
            def __init__(self, cfg, run, callback): self.callback = callback
            async def start(self): self.callback({"event": "injected", "at": iso(0.5)})
            async def close(self): pass
        backend = TestBackend()
        with tempfile.TemporaryDirectory() as tmp, \
             patch("scenarios.presentation.app.Backend", return_value=backend), \
             patch("scenarios.presentation.app.Injector", TestInjector):
            app = LeafyApp(Config(identity=IDENTITY, history=str(Path(tmp) / "history.db")))
            async with app.run_test(size=(140, 50)) as pilot:
                app.push_screen(ScenarioScreen(next(r for r in CATALOG if r["id"] == "f1_b_memory_leak")))
                for _ in range(80):
                    await pilot.pause(0.1)
                    screen = app.screen
                    if screen.run and screen.run.status == "COMPLETED": break
                    if screen.config: screen.config.poll_seconds = 0.02
                self.assertEqual(screen.run.status, "COMPLETED")
                self.assertEqual(screen.run.timings()["ttr"], 9.5)
                self.assertEqual(app.history.summary(screen.run)["mttr"], (9.5, 1))
                await screen.action_leave()
