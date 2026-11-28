from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from scenarios.presentation.state import Run, History, delta

IDENTITY = {"site": "fixture", "service": "backend", "source": "fixture-backend",
            "runtime": "container", "target": "leafy-backend"}


def at(seconds):
    return datetime.fromtimestamp(1800000000 + seconds, timezone.utc).isoformat()


def context(offset=10, fingerprint="incident-1"):
    return {"received_at": at(offset), "alert": {"labels": IDENTITY,
        "fingerprint": fingerprint, "startsAt": at(5)}, "metrics": {}, "logs": []}


def rca():
    return {"timestamp": at(20), "identity": IDENTITY, "alert_fingerprint": "incident-1",
            "alert_starts_at": at(5), "remediation_id": "rem-1", "result": {
                "root_cause": "memory growth", "action_type": "RESTART", "analysis_status": "valid"}}


def record(state="AWAITING_APPROVAL"):
    return {"remediation_id": "rem-1", "identity": IDENTITY, "alert_context": context()["alert"],
            "state": state, "approval_requested_at": at(20), "approval_expires_at": at(600),
            "slack_dispatch_status": "SUCCESS", "slack_message_url": "https://fixture.slack.com/archives/C1/p1"}


class StateTests(unittest.TestCase):
    def ready(self):
        run = Run("f1_b_memory_leak", dict(IDENTITY), started_at=at(-1), fault_at=at(0))
        run.attach_contexts([context()])
        run.attach_rca([rca()])
        return run

    def test_event_times_not_poll_times_and_no_false_recovery(self):
        run = self.ready()
        self.assertEqual(run.timings()["ttd"], 10)
        self.assertIsNone(run.timings()["ttr"])
        rec = record("VERIFIED")
        rec.update(approved_at=at(50), action_started_at=at(51), action_verified_at=at(60),
                   results=[{"status": "SUCCESS", "verified": True}], service_verification={"state": "CHECKING"})
        run.attach_record(rec)
        self.assertEqual(run.stage, "복구 검증")
        self.assertNotEqual(run.status, "COMPLETED")
        rec.update(service_verification={"state": "RECOVERED"}, service_recovered_at=at(95))
        run.attach_record(rec)
        self.assertEqual(run.status, "COMPLETED")
        self.assertEqual(run.timings(), {"ttd": 10, "ttr": 95, "approval": 30, "action": 9})

    def test_other_site_old_alert_and_ambiguous_incidents_never_attach(self):
        run = Run("test", IDENTITY, fault_at=at(0))
        other = deepcopy(context())
        other["alert"]["labels"]["site"] = "other"
        old = deepcopy(context())
        old["alert"]["startsAt"] = at(-1)
        run.attach_contexts([other, old])
        self.assertFalse(run.incident)
        run.attach_contexts([context(), context(fingerprint="second")])
        self.assertEqual(run.status, "FAILED")
        self.assertIn("여러", run.reason)

    def test_rca_must_match_fingerprint_start_and_identity(self):
        run = self.ready()
        run.rca = {}
        for key, value in (("alert_fingerprint", "old"), ("alert_starts_at", at(-10)), ("identity", {**IDENTITY, "source": "other"})):
            wrong = rca(); wrong[key] = value
            run.attach_rca([wrong])
            self.assertFalse(run.rca)

    def test_rejected_expired_disabled_failed_and_verification_failure_distinct(self):
        for state in ("REJECTED", "EXPIRED", "FAILED", "SKIPPED", "BLOCKED"):
            with self.subTest(state=state):
                run = self.ready(); rec = record(state)
                rec["rejected_at"] = at(40)
                run.attach_record(rec)
                self.assertEqual(run.status, state if state in {"REJECTED", "EXPIRED"} else "FAILED")
                self.assertIsNone(run.recovered_at)
        for state in ("UNCONFIGURED", "BLOCKED", "TIMEOUT"):
            run = self.ready(); rec = record("VERIFIED")
            rec["service_verification"] = {"state": state, "reason": "health_missing"}
            run.attach_record(rec)
            self.assertEqual((run.status, run.stage, run.reason), ("FAILED", "복구 검증", "health_missing"))

    def test_statistics_use_separate_eligible_cohorts_and_one_row_per_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = History(Path(tmp) / "runs.sqlite")
            self.addCleanup(store.db.close)
            run = self.ready()
            store.save(run); store.save(run)
            second = Run(run.scenario_id, IDENTITY, fault_at=at(100), detected_at=at(130), recovered_at=at(200))
            store.save(second)
            store.save(Run(run.scenario_id, IDENTITY))
            store.save(Run("other-scenario", IDENTITY, fault_at=at(0), detected_at=at(500)))
            self.assertEqual(store.summary(run), {"mttd": (20, 2), "mttr": (100, 1)})

    def test_naive_negative_and_missing_times_are_unknown(self):
        self.assertIsNone(delta(None, at(0)))
        self.assertIsNone(delta(at(10), at(0)))
        self.assertIsNone(delta("2026-01-01T00:00:00", at(0)))

    def test_uninstrumented_runner_can_display_rca_without_fabricating_timing(self):
        run = Run("c_b_short_load_spike", IDENTITY, started_at=at(0))
        run.attach_contexts([context()])
        self.assertTrue(run.incident)
        self.assertIsNone(run.timings()["ttd"])
