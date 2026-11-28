"""Fake-only observation and memory throttle boundary tests."""
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

from executor.observability import ObservabilityExecutor, validate_parameters
from executor.memory_limit import apply_memory_limit, restore_memory_limit
import store

IDENTITY = {"site": "fixture-site", "source": "fixture-docker", "service": "backend",
            "runtime": "container", "target": "fixture-backend"}
LABELS = {"com.docker.compose.project": "fixture", "com.docker.compose.service": "backend", "io.leafy.remediation": "workload"}
CID, IMAGE, HELPER = "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64


class Response:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code, self.body, self.headers = status, body or {}, headers or {}
    def json(self): return self.body


class LoggerHttp:
    def __init__(self):
        self.level, self.version, self.posts = "INFO", 1, []
        self.fail_after_write = False
    def get(self, url, headers=None):
        return Response(body={"configuredLevel": self.level}, headers={"etag": '"' + str(self.version) + '"'})
    def post(self, url, headers=None, json=None):
        self.posts.append((url, deepcopy(headers), deepcopy(json)))
        if headers["If-Match"] != '"' + str(self.version) + '"': return Response(412)
        self.level = json["configuredLevel"]; self.version += 1
        if self.fail_after_write: raise TimeoutError()
        return Response(204)


def record(executor, action, parameters, rid="fixture-observation", **changes):
    plans = executor.plan_record(IDENTITY, [IDENTITY["target"]], action, parameters)
    now = time.time()
    data = dict(remediation_id=rid, state="EXECUTING", executor_name="observability", action_type=action,
                action_parameters=parameters, identity=deepcopy(IDENTITY), targets=[IDENTITY["target"]],
                requires_approval=True, approved_by="fixture-approver", ttl_seconds=None, recovery_mode="none",
                incident_key="d" * 64, approved_at=datetime.fromtimestamp(now - .5, timezone.utc).isoformat(),
                action_started_at=datetime.fromtimestamp(now - .1, timezone.utc).isoformat(),
                approval_requested_at=datetime.fromtimestamp(now - 1, timezone.utc).isoformat(),
                approval_expires_at=datetime.fromtimestamp(now + 300, timezone.utc).isoformat(),
                target_bindings=plans, evidence={"targets": plans},
                action_hash=store.action_hash(action, [IDENTITY["target"]], None, "none", parameters))
    return SimpleNamespace(**{**data, **changes})


class ObservabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = {"version": 1, "enabled": True, "state_dir": str(self.root / "state"), "targets": {
            IDENTITY["target"]: {"identity": IDENTITY, "labels": LABELS,
                "actions": ["SET_LOG_LEVEL", "RESTORE_LOG_LEVEL", "PACKET_CAPTURE", "SILENCE_ALERT", "EXPIRE_SILENCE"],
                "token_env": "FIXTURE_OBSERVATION_TOKEN", "container_id": CID, "image_id": IMAGE,
                "logger_api": {"origin": "https://logger.fixture.invalid", "conditional_updates_verified": True, "allowed_loggers": ["com.leafy"]},
                "packet_capture": {"helper_image_id": HELPER, "max_bytes": 4 * 1024 * 1024, "max_total_bytes": 8 * 1024 * 1024},
                "alertmanager": {"origin": "https://am.fixture.invalid"}}}}
        self.path = self.root / "config.yml"; self.write_config()
        self.http = LoggerHttp(); self.clock = time.time()
        self.executor = ObservabilityExecutor(str(self.path), client=self.http, clock=lambda: self.clock)
        patcher = patch.dict(os.environ, {"FIXTURE_OBSERVATION_TOKEN": "fixture-token"})
        patcher.start(); self.addCleanup(patcher.stop)

    def write_config(self): self.path.write_text(yaml.safe_dump(self.config))
    def params(self): return {"logger": "com.leafy", "level": "DEBUG", "duration_seconds": 60}

    def test_log_level_apply_duplicate_and_durable_ttl_restore(self):
        rec = record(self.executor, "SET_LOG_LEVEL", self.params())
        result = self.executor.execute_record(rec, IDENTITY["target"])
        self.assertTrue(result.ok, result)
        self.assertEqual(self.http.level, "DEBUG")
        self.assertTrue(self.executor.execute_record(rec, IDENTITY["target"]).ok)
        self.assertEqual(len(self.http.posts), 1)
        self.clock += 61
        restarted = ObservabilityExecutor(str(self.path), client=self.http, clock=lambda: self.clock)
        events = restarted.run_due()
        self.assertEqual(events[0]["state"], "RESTORED")
        self.assertEqual(self.http.level, "INFO")
        self.assertEqual(restarted.run_due(), [])

    def test_operator_intervening_same_level_new_version_is_not_overwritten(self):
        rec = record(self.executor, "SET_LOG_LEVEL", self.params())
        self.assertTrue(self.executor.execute_record(rec, IDENTITY["target"]).ok)
        self.http.version += 1
        self.clock += 61
        self.assertEqual(self.executor.run_due()[0]["state"], "NEEDS_REVIEW")
        self.assertEqual(len(self.http.posts), 1)
        self.assertEqual(self.http.level, "DEBUG")

    def test_api_lost_response_retains_unknown_and_never_retries(self):
        rec = record(self.executor, "SET_LOG_LEVEL", self.params())
        self.http.fail_after_write = True
        result = self.executor.execute_record(rec, IDENTITY["target"])
        self.assertEqual(result.status, "UNKNOWN")
        self.assertEqual(self.executor.execute_record(rec, IDENTITY["target"]).status, "UNKNOWN")
        self.clock += 61; self.assertEqual(self.executor.run_due(), [])
        self.assertEqual(len(self.http.posts), 1)

    def test_expired_or_tampered_plan_never_posts(self):
        rec = record(self.executor, "SET_LOG_LEVEL", self.params())
        rec.approval_expires_at = "2020-01-01T00:00:00Z"
        self.assertEqual(self.executor.execute_record(rec, IDENTITY["target"]).status, "BLOCKED")
        rec = record(self.executor, "SET_LOG_LEVEL", self.params())
        rec.target_bindings[IDENTITY["target"]]["parameters"]["level"] = "TRACE"
        self.assertEqual(self.executor.execute_record(rec, IDENTITY["target"]).status, "BLOCKED")
        self.assertEqual(self.http.posts, [])

    def test_missing_etag_and_unverified_conditional_contract_reject_plan(self):
        self.http.get = lambda *a, **kw: Response(body={"configuredLevel": "INFO"})
        with self.assertRaises(ValueError): record(self.executor, "SET_LOG_LEVEL", self.params())
        self.config["targets"][IDENTITY["target"]]["logger_api"]["conditional_updates_verified"] = False
        self.write_config()
        with self.assertRaises(ValueError): record(self.executor, "SET_LOG_LEVEL", self.params())

    def test_original_operator_config_change_prevents_ttl_restore(self):
        rec = record(self.executor, "SET_LOG_LEVEL", self.params())
        self.assertTrue(self.executor.execute_record(rec, IDENTITY["target"]).ok)
        self.config["targets"][IDENTITY["target"]]["logger_api"]["origin"] = "https://other.fixture.invalid"
        self.write_config(); self.clock += 61
        self.assertEqual(self.executor.run_due()[0]["state"], "NEEDS_REVIEW")
        self.assertEqual(len(self.http.posts), 1)

    def test_explicit_logger_restore_uses_verified_parent_original(self):
        rec = record(self.executor, "SET_LOG_LEVEL", self.params())
        self.assertTrue(self.executor.execute_record(rec, IDENTITY["target"]).ok)
        restore = record(self.executor, "RESTORE_LOG_LEVEL", {"source_record_id": rec.remediation_id}, rid="restore-fixture")
        self.assertTrue(self.executor.execute_record(restore, IDENTITY["target"]).ok)
        self.assertEqual(self.http.level, "INFO")

    def test_disabled_and_unknown_parameters_fail_without_io(self):
        self.config["enabled"] = False; self.write_config()
        with self.assertRaises(ValueError): record(self.executor, "SET_LOG_LEVEL", self.params())
        for action, parameters in (("PACKET_CAPTURE", {"duration_seconds": 61, "packet_limit": 10, "snaplen": 128}),
                                   ("SET_LOG_LEVEL", {**self.params(), "url": "https://injected.invalid"}),
                                   ("SET_LOG_LEVEL", {**self.params(), "duration_seconds": True}),
                                   ("SET_LOG_LEVEL", {**self.params(), "level": {"shell": "bad"}})):
            with self.subTest(action=action), self.assertRaises(ValueError): validate_parameters(action, parameters)
        self.assertEqual(self.http.posts, [])

    def test_silence_identity_scope_and_owned_expiration(self):
        silence = {}
        sid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        def get(url, headers=None):
            if url.endswith("/status"): return Response(body={"status": "ready"})
            return Response(body=deepcopy(silence))
        def post(url, headers=None, json=None):
            silence.update(deepcopy(json)); silence["status"] = {"state": "active"}
            return Response(body={"silenceID": sid})
        def delete(url, headers=None):
            silence["status"] = {"state": "expired"}; return Response()
        self.executor._http = SimpleNamespace(get=get, post=post, delete=delete)
        rec = record(self.executor, "SILENCE_ALERT", {"alertname": "HighCpuUsage", "duration_seconds": 60})
        self.assertTrue(self.executor.execute_record(rec, IDENTITY["target"]).ok)
        self.assertEqual({m["name"] for m in silence["matchers"]}, {*IDENTITY, "alertname"})
        self.assertTrue(all(m["isRegex"] is False and m["isEqual"] is True for m in silence["matchers"]))
        restore = record(self.executor, "EXPIRE_SILENCE", {"source_record_id": rec.remediation_id}, rid="expire-silence")
        self.assertTrue(self.executor.execute_record(restore, IDENTITY["target"]).ok)
        self.assertEqual(silence["status"]["state"], "expired")

    def test_silence_operator_extension_prevents_expiration(self):
        silence = {}
        sid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        def get(url, headers=None):
            return Response(body={"status": "ready"} if url.endswith("/status") else deepcopy(silence))
        def post(url, headers=None, json=None):
            silence.update(deepcopy(json)); silence["status"] = {"state": "active"}
            return Response(body={"silenceID": sid})
        self.executor._http = SimpleNamespace(get=get, post=post)
        rec = record(self.executor, "SILENCE_ALERT", {"alertname": "HighCpuUsage", "duration_seconds": 60})
        self.assertTrue(self.executor.execute_record(rec, IDENTITY["target"]).ok)
        silence["endsAt"] = "2099-01-01T00:00:00Z"
        with self.assertRaises(ValueError):
            record(self.executor, "EXPIRE_SILENCE", {"source_record_id": rec.remediation_id}, rid="expire-silence")

    def test_packet_capture_pinned_namespace_argv_and_private_artifact(self):
        self._capture_fixture()

    def test_packet_capture_named_volume_shares_only_capture_artifacts(self):
        self._capture_fixture(volume="fixture-private-captures")

    def test_expiring_capture_approval_after_helper_create_never_starts(self):
        self._capture_fixture(expire=True)

    def _capture_fixture(self, volume=None, expire=False):
        if volume:
            self.config["targets"][IDENTITY["target"]]["packet_capture"]["artifact_volume"] = volume
            self.write_config()
        doc = {"Id": CID, "Image": IMAGE, "Name": "/" + IDENTITY["target"], "Config": {"Labels": LABELS},
               "HostConfig": {}, "State": {"Running": True, "StartedAt": "fixture-start"}}
        target = SimpleNamespace(attrs=doc, reload=lambda: None)
        made, started = [], []
        def create(image, **options):
            made.append((image, options))
            if expire:
                rec.approval_expires_at = "2020-01-01T00:00:00Z"
            directory = (self.root / "state" / "captures" / Path(options["command"][-1]).parent.name
                         if volume else Path(next(iter(options["volumes"]))))
            def start():
                started.append(True)
                (directory / "traffic.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + bytes(20))
            return SimpleNamespace(start=start, wait=lambda timeout: {"StatusCode": 124}, stop=lambda timeout: None, remove=lambda force: None)
        docker = SimpleNamespace(containers=SimpleNamespace(get=lambda cid: target, create=create),
                                 images=SimpleNamespace(get=lambda image: SimpleNamespace(attrs={"Id": HELPER})))
        self.executor._docker = docker
        params = {"duration_seconds": 10, "packet_limit": 20, "snaplen": 128}
        rec = record(self.executor, "PACKET_CAPTURE", params)
        result = self.executor.execute_record(rec, IDENTITY["target"])
        if expire:
            self.assertFalse(result.ok, result)
            self.assertEqual(started, [])
            return
        self.assertTrue(result.ok, result)
        options = made[0][1]
        if volume:
            self.assertEqual(options["volumes"], {volume: {"bind": "/capture", "mode": "rw"}})
            self.assertEqual(options["command"][-1], "/capture/" + result.after["artifact_id"] + "/traffic.pcap")
        self.assertEqual(options["network_mode"], "container:" + CID)
        self.assertEqual(options["cap_add"], ["NET_RAW"])
        self.assertTrue(options["read_only"])
        self.assertNotIn("privileged", options)
        artifact = self.root / "state" / "captures" / result.after["artifact_id"] / "traffic.pcap"
        self.assertEqual(artifact.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("traffic.pcap", json.dumps(result.as_dict()))
        self.assertEqual(len(made), 1)
        self.assertTrue(self.executor.execute_record(rec, IDENTITY["target"]).ok)
        self.assertEqual(len(made), 1)

    def test_changed_capture_container_before_execution_is_blocked(self):
        doc = {"Id": CID, "Image": IMAGE, "Name": "/" + IDENTITY["target"], "Config": {"Labels": LABELS},
               "HostConfig": {}, "State": {"Running": True, "StartedAt": "fixture-start"}}
        target = SimpleNamespace(attrs=doc, reload=lambda: None)
        docker = SimpleNamespace(containers=SimpleNamespace(get=lambda cid: target),
                                 images=SimpleNamespace(get=lambda image: SimpleNamespace(attrs={"Id": HELPER})))
        self.executor._docker = docker
        rec = record(self.executor, "PACKET_CAPTURE", {"duration_seconds": 10, "packet_limit": 20, "snaplen": 128})
        doc["State"]["StartedAt"] = "restarted"
        self.assertEqual(self.executor.execute_record(rec, IDENTITY["target"]).status, "BLOCKED")


class MemoryPrimitiveTests(unittest.TestCase):
    def setup_executor(self, usage=128 * 1024**2):
        doc = {"HostConfig": {"Memory": 1024 * 1024**2, "MemorySwap": 1024 * 1024**2,
                              "CpuQuota": 50000, "CpuPeriod": 100000, "NanoCpus": 0}}
        updates = []
        def update(**kw):
            updates.append(kw); doc["HostConfig"].update(Memory=kw["mem_limit"], MemorySwap=kw["memswap_limit"])
        container = SimpleNamespace(stats=lambda stream: {"memory_stats": {"usage": usage}}, update=update)
        ex = SimpleNamespace(_reload_inspect=lambda target: deepcopy(doc), _mutation_container=lambda target: container)
        return ex, doc, updates

    def test_memory_apply_and_restore_preserve_cpu_independently(self):
        ex, doc, updates = self.setup_executor()
        evidence = {"resources": {"memory": doc["HostConfig"]["Memory"], "memory_swap": doc["HostConfig"]["MemorySwap"]}}
        result = apply_memory_limit(ex, "fixture", evidence, 512 * 1024**2)
        self.assertTrue(result.ok, result)
        evidence["memory_throttle"] = result.after
        self.assertTrue(restore_memory_limit(ex, "fixture", evidence).ok)
        self.assertEqual(doc["HostConfig"]["Memory"], 1024 * 1024**2)
        self.assertEqual(doc["HostConfig"]["CpuQuota"], 50000)
        self.assertEqual(len(updates), 2)
        self.assertTrue(all(set(u) == {"mem_limit", "memswap_limit"} for u in updates))

    def test_memory_below_live_usage_headroom_is_blocked(self):
        ex, doc, updates = self.setup_executor(usage=500 * 1024**2)
        evidence = {"resources": {"memory": doc["HostConfig"]["Memory"], "memory_swap": doc["HostConfig"]["MemorySwap"]}}
        self.assertEqual(apply_memory_limit(ex, "fixture", evidence, 512 * 1024**2).status, "BLOCKED")
        self.assertEqual(updates, [])

    def test_memory_restore_does_not_clobber_operator_changes(self):
        ex, doc, updates = self.setup_executor()
        evidence = {"resources": {"memory": doc["HostConfig"]["Memory"], "memory_swap": doc["HostConfig"]["MemorySwap"]}}
        result = apply_memory_limit(ex, "fixture", evidence, 512 * 1024**2)
        evidence["memory_throttle"] = result.after
        doc["HostConfig"]["Memory"] = 600 * 1024**2
        self.assertEqual(restore_memory_limit(ex, "fixture", evidence).status, "BLOCKED")
        self.assertEqual(len(updates), 1)

    def test_slow_stats_expiring_approval_never_reaches_update(self):
        ex, doc, updates = self.setup_executor()
        container = ex._mutation_container("fixture")
        calls = []
        def mutation(target):
            calls.append(target)
            if len(calls) == 2: raise ValueError("approval_expired")
            return container
        ex._mutation_container = mutation
        evidence = {"resources": {"memory": doc["HostConfig"]["Memory"], "memory_swap": doc["HostConfig"]["MemorySwap"]}}
        self.assertEqual(apply_memory_limit(ex, "fixture", evidence, 512 * 1024**2).status, "BLOCKED")
        self.assertEqual(updates, [])


if __name__ == "__main__": unittest.main()
