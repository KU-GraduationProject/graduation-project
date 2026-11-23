"""Real HTTP parser + durable service checks over MockTransport, no live services."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import httpx

import service_verification as verification
import store as states


IDENTITY = {"site": "fixture", "service": "backend", "source": "pc2-docker",
            "runtime": "container", "target": "leafy-backend"}
BASE = 1800000000.0


def iso(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def profile():
    return {"version": 1, "profiles": [{"identity": IDENTITY,
        "health": {"url": "https://health.fixture.invalid/actuator/health",
                   "json_equals": {"status": "UP"}},
        "prometheus_url": "https://metrics.fixture.invalid",
        "metrics": [{"name": "availability", "query": 'up{instance="fixture"}',
                     "freshness_query": 'timestamp(up{instance="fixture"})',
                     "minimum": 1.0, "maximum": 1.0, "max_age_seconds": 60}],
        "consecutive_samples": 3, "min_interval_seconds": 10, "timeout_seconds": 300}]}


class ServiceVerificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config_path = str(Path(self.tmp.name) / "health.json")
        self.config = profile()
        self.save()
        self.store_path = str(Path(self.tmp.name) / "records.json")
        self.store = states.RecordStore(self.store_path)
        self.store.load()
        self.record = states.RemediationRecord("service-record", "fixture-alert", "RESTART",
            targets=["leafy-backend"], identity=deepcopy(IDENTITY), state=states.VERIFIED,
            alert_active_at=iso(BASE - 100), action_started_at=iso(BASE - 2),
            action_verified_at=iso(BASE), recovery_verified_at=iso(BASE + 1),
            results=[{"status": "SUCCESS", "verified": True}])
        self.record.service_verification = verification.plan_record(self.record, self.config_path)
        self.store.create(self.record)
        self.now = BASE + 10
        self.calls = []
        self.health_status = 200
        self.health_body = {"status": "UP", "private_detail": "never retained"}
        self.metric_value = "1"
        self.metric_time = None
        self.ambiguous = False
        self.client = httpx.Client(transport=httpx.MockTransport(self.handle))
        self.addCleanup(self.client.close)

    def save(self):
        Path(self.config_path).write_text(json.dumps(self.config), encoding="utf-8")

    def handle(self, request):
        self.calls.append(request)
        self.assertEqual(request.method, "GET")
        if request.url.host == "health.fixture.invalid":
            return httpx.Response(self.health_status, json=self.health_body,
                                  headers={"Location": "https://evil.fixture.invalid"})
        self.assertEqual(request.url.host, "metrics.fixture.invalid")
        ts = self.now if self.metric_time is None else self.metric_time
        value = str(ts) if request.url.params["query"].startswith("timestamp(") else self.metric_value
        result = {"metric": {}, "value": [self.now, value]}
        return httpx.Response(200, json={"status": "success", "data": {"resultType": "vector",
            "result": [result, result] if self.ambiguous else [result]}})

    def check(self, now=None):
        self.now = self.now if now is None else now
        return verification.verify_record(self.store, self.record, now=self.now,
            config_path=self.config_path, client=self.client)

    def test_effect_and_restore_success_alone_have_no_mttr(self):
        self.assertIsNone(self.record.mttr())
        self.assertIsNotNone(self.record.time_to_contain())
        self.assertIsNone(self.record.service_recovered_at)

    def test_three_fresh_health_and_metric_samples_confirm_service_and_mttr(self):
        self.check(BASE + 10)
        self.assertEqual(self.record.service_verification["consecutive"], 1)
        self.assertIsNone(self.record.mttr())
        self.check(BASE + 20)
        self.check(BASE + 30)
        self.assertEqual(self.record.service_verification["state"], "RECOVERED")
        self.assertEqual(self.record.state, states.VERIFIED)
        self.assertEqual(self.record.mttr(), 130.0)
        self.assertEqual(self.record.timings()["restore_duration_sec"], 32.0)
        self.assertEqual(len(self.calls), 9)
        self.assertNotIn("private_detail", json.dumps(self.record.as_dict()))
        restarted = states.RecordStore(self.store_path)
        restarted.load()
        self.assertEqual(restarted.get("service-record").mttr(), 130.0)
        self.check(BASE + 50)
        self.assertEqual(len(self.calls), 9)

    def test_duplicate_poll_and_concurrent_poll_do_not_count_as_new_samples(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda _: self.check(BASE + 10), range(4)))
        self.assertEqual(self.record.service_verification["consecutive"], 1)
        self.assertEqual(len(self.calls), 3)
        self.assertIsNone(self.record.mttr())

    def test_health_failure_resets_consecutive_window(self):
        self.check(BASE + 10)
        self.health_body = {"status": "DOWN"}
        self.check(BASE + 20)
        self.assertEqual(self.record.service_verification["consecutive"], 0)
        self.assertIsNone(self.record.mttr())
        self.health_body = {"status": "UP"}
        self.check(BASE + 30)
        self.assertEqual(self.record.service_verification["consecutive"], 1)

    def test_stale_underlying_scrape_cannot_pass_fresh_promql_evaluation(self):
        self.metric_time = BASE - 100
        self.check(BASE + 10)
        self.assertEqual(self.record.service_verification["reason"], "service_metric_not_fresh")
        self.assertIsNone(self.record.mttr())

    def test_same_scrape_repeated_later_does_not_advance_stable_window(self):
        self.metric_time = BASE + 10
        self.check(BASE + 10)
        self.check(BASE + 20)
        self.assertEqual(self.record.service_verification["consecutive"], 0)
        self.assertEqual(self.record.service_verification["reason"], "service_metric_not_fresh")

    def test_future_scrape_or_pre_action_scrape_is_rejected(self):
        for timestamp in (BASE - 1, BASE + 60):
            self.metric_time = timestamp
            self.check(self.now + 10)
            self.assertIsNone(self.record.mttr())
            self.assertEqual(self.record.service_verification["consecutive"], 0)

    def test_missing_ambiguous_nan_and_threshold_metrics_do_not_confirm_recovery(self):
        self.ambiguous = True
        self.check(BASE + 10)
        self.assertEqual(self.record.service_verification["reason"], "service_metric_missing_or_ambiguous")
        self.ambiguous = False
        for value in ("NaN", "Inf", "0", "2"):
            self.metric_value = value
            self.check(self.now + 10)
            self.assertIsNone(self.record.mttr())
            self.assertEqual(self.record.service_verification["consecutive"], 0)

    def test_timeout_is_service_timeout_and_never_changes_successful_action(self):
        self.check(BASE + 301)
        self.assertEqual(self.record.service_verification["state"], "TIMEOUT")
        self.assertEqual(self.record.state, states.VERIFIED)
        self.assertIsNone(self.record.mttr())
        self.assertEqual(self.calls, [])

    def test_unknown_failed_or_unverified_action_never_makes_health_requests(self):
        for state in (states.UNKNOWN, states.FAILED, states.EXECUTING, states.BLOCKED, states.RECOVERY_UNKNOWN):
            self.record.state = state
            self.check()
        self.record.state = states.VERIFIED
        self.record.results[0]["verified"] = False
        self.check()
        self.assertEqual(self.calls, [])
        self.assertIsNone(self.record.mttr())

    def test_profile_change_after_approval_requires_reapproval(self):
        self.config["profiles"][0]["health"]["url"] = "https://other.fixture.invalid"
        self.save()
        self.check()
        self.assertEqual(self.record.service_verification["reason"], "service_profile_changed_reapproval_required")
        self.assertEqual(self.calls, [])

    def test_unconfigured_and_legacy_records_do_not_gain_an_unapproved_profile(self):
        with patch.dict(os.environ, {verification.CONFIG_ENV: ""}):
            self.record.service_verification = verification.plan_record(self.record)
        self.check()
        self.assertEqual(self.calls, [])
        self.record.service_verification = {}
        self.check(BASE + 20)
        self.assertEqual(self.calls, [])
        self.assertIsNone(self.record.mttr())

    def test_network_failure_is_sanitized_without_changing_action_state(self):
        with patch.object(self.client, "stream", side_effect=httpx.ConnectError("secret raw body")):
            self.check()
        self.assertEqual(self.record.service_verification["reason"], "service_check_unavailable")
        self.assertNotIn("secret raw body", json.dumps(self.record.as_dict()))
        self.assertEqual(self.record.state, states.VERIFIED)

    def test_redirect_never_forwards_check_credential(self):
        self.config["profiles"][0]["health"]["token_env"] = "FIXTURE_HEALTH_TOKEN"
        self.save()
        self.record.service_verification = verification.plan_record(self.record, self.config_path)
        self.health_status = 302
        with patch.dict(os.environ, {"FIXTURE_HEALTH_TOKEN": "private-fixture-token"}):
            self.check()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0].headers["Authorization"], "Bearer private-fixture-token")
        self.assertNotIn("private-fixture-token", json.dumps(self.record.as_dict()))

    def test_exact_identity_duplicates_invalid_url_and_unbounded_metrics_are_rejected(self):
        original = deepcopy(self.config)
        mutations = [lambda p: p.update(identity={"target": "leafy-backend"}),
            lambda p: p["health"].update(url="https://user:password@private.invalid"),
            lambda p: p["health"].update(url="http://health.fixture.invalid"),
            lambda p: p["metrics"][0].update(minimum=None, maximum=None),
            lambda p: p["metrics"][0].pop("freshness_query")]
        for mutation in mutations:
            self.config = deepcopy(original)
            mutation(self.config["profiles"][0])
            self.save()
            self.assertEqual(verification.plan_record(self.record, self.config_path)["state"], "BLOCKED")
        self.config = original
        self.config["profiles"].append(deepcopy(original["profiles"][0]))
        self.save()
        self.assertEqual(verification.plan_record(self.record, self.config_path)["state"], "BLOCKED")

    def test_store_failure_never_returns_confirmed_mttr(self):
        self.check(BASE + 10)
        self.check(BASE + 20)
        with patch("store.os.replace", side_effect=OSError("fixture full disk")):
            returned = self.check(BASE + 30)
        self.assertFalse(self.store.writable)
        self.assertIsNone(returned.mttr())
        self.assertIsNone(self.store.get("service-record").mttr())

    def test_intermediate_stage_health_does_not_finalize_incident_mttr(self):
        self.record.plan_steps = [{"fixture":1}, {"fixture":2}]
        for now in (BASE+10,BASE+20,BASE+30):
            self.check(now)
        self.assertEqual(self.record.service_verification["state"], "HEALTHY_INTERMEDIATE")
        self.assertIsNone(self.record.mttr())

    def test_metrics_bind_verified_replacement_id_instead_of_the_retained_old_container(self):
        self.config["profiles"][0]["metrics"][0].update(
            query='up{id="/docker/__CONTAINER_ID__"}', freshness_query='timestamp(up{id="/docker/__CONTAINER_ID__"})')
        self.save()
        self.record.action_type = "RECREATE"
        self.record.results[0]["after"] = {"container_id":"c"*64, "old_container_id":"a"*64}
        self.record.service_verification = verification.plan_record(self.record,self.config_path)
        self.check(BASE+10)
        queries = [request.url.params["query"] for request in self.calls if request.url.host == "metrics.fixture.invalid"]
        self.assertTrue(all("c"*64 in query for query in queries))
        self.assertTrue(all("a"*64 not in query for query in queries))
