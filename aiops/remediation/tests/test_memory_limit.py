"""Memory resource dispatch stays isolated from CPU and immutable target binding."""
from copy import deepcopy
from datetime import datetime, timezone
import os
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from executor.local_docker import LocalDockerExecutor, BoundDockerExecutor, parse_resources

MIB = 1024 * 1024
CID, IMAGE = "a" * 64, "sha256:" + "b" * 64
IDENTITY = {"site": "fixture", "source": "fixture-docker", "runtime": "container", "service": "backend", "target": "fixture-backend"}
LABELS = {"io.leafy.remediation": "workload", "com.docker.compose.project": "fixture", "com.docker.compose.service": "backend"}


class MemoryDocker:
    def __init__(self):
        self.doc = {"Id": CID, "Image": IMAGE, "Name": "/fixture-backend", "Config": {"Labels": LABELS},
                    "State": {"Running": True}, "HostConfig": {"Memory": 1024 * MIB, "MemorySwap": 1024 * MIB,
                       "CpuQuota": 80000, "CpuPeriod": 100000, "NanoCpus": 0, "CpuShares": 0}}
        self.updates, self.lookups, self.usage = [], [], 128 * MIB
        self.on_stats = None
        self.apply = True
        self.fail_after_write = False
        fake = self
        class Container:
            @property
            def attrs(self): return fake.doc
            def reload(self): pass
            def stats(self, stream):
                if fake.on_stats: fake.on_stats()
                return {"memory_stats": {"usage": fake.usage}}
            def update(self, **kw):
                fake.updates.append(kw)
                if fake.apply:
                    for key, value in kw.items():
                        fake.doc["HostConfig"][["Memory", "MemorySwap", "CpuQuota", "CpuPeriod"][["mem_limit", "memswap_limit", "cpu_quota", "cpu_period"].index(key)]] = value
                if fake.fail_after_write: raise TimeoutError()
        self.container = Container()
        def get(target): self.lookups.append(target); return self.container
        self.containers = SimpleNamespace(get=get)


class MemoryDispatchTests(unittest.TestCase):
    def setUp(self):
        self.docker = MemoryDocker()
        self.executor = LocalDockerExecutor(client=self.docker, memory_limit_bytes=512 * MIB)
        self.evidence = {"resources": parse_resources(self.docker.doc), "action_parameters": {"resource": "memory"}}
        self.binding = {"identity": IDENTITY, "executor": "local_docker", "agent_id": "fixture-agent",
                        "container": {"container_id": CID, "image_id": IMAGE, "labels": LABELS,
                                      "actions": ["THROTTLE", "UNTHROTTLE"]}}

    def test_snapshot_records_memory_swap_without_altering_cpu_shape(self):
        resources = self.executor.snapshot("fixture-backend")["resources"]
        self.assertEqual(resources["memory_swap"], 1024 * MIB)
        self.assertEqual(resources["cpu_quota"], 80000)

    def test_memory_resource_apply_and_ttl_restore_dispatch(self):
        result = self.executor.execute("THROTTLE", "fixture-backend", self.evidence)
        self.assertTrue(result.ok, result)
        self.assertEqual(self.docker.doc["HostConfig"]["Memory"], 512 * MIB)
        self.assertEqual(self.docker.doc["HostConfig"]["CpuQuota"], 80000)
        restore = deepcopy(self.evidence); restore["memory_throttle"] = result.after
        result = self.executor.execute("UNTHROTTLE", "fixture-backend", restore)
        self.assertTrue(result.ok, result)
        self.assertEqual(self.docker.doc["HostConfig"]["Memory"], 1024 * MIB)
        self.assertEqual(self.docker.doc["HostConfig"]["MemorySwap"], 1024 * MIB)

    def test_legacy_default_throttle_remains_cpu_only(self):
        result = self.executor.execute("THROTTLE", "fixture-backend", {"resources": self.evidence["resources"]})
        self.assertTrue(result.ok, result)
        self.assertEqual(self.docker.updates, [{"cpu_quota": 50000, "cpu_period": 100000}])
        self.assertEqual(self.docker.doc["HostConfig"]["Memory"], 1024 * MIB)

    def test_unconfigured_memory_and_unspecified_original_swap_are_blocked(self):
        self.executor.memory_limit_bytes = None
        self.assertEqual(self.executor.execute("THROTTLE", "fixture-backend", self.evidence).status, "BLOCKED")
        self.executor.memory_limit_bytes = 512 * MIB
        self.docker.doc["HostConfig"]["MemorySwap"] = 0
        self.evidence["resources"] = parse_resources(self.docker.doc)
        self.assertEqual(self.executor.execute("THROTTLE", "fixture-backend", self.evidence).status, "BLOCKED")
        self.assertEqual(self.docker.updates, [])

    def test_usage_near_limit_rejects_oom_injection(self):
        self.docker.usage = 500 * MIB
        self.assertEqual(self.executor.execute("THROTTLE", "fixture-backend", self.evidence).status, "BLOCKED")
        self.assertEqual(self.docker.updates, [])

    def test_memory_restore_requires_owned_current_limit_and_original_evidence(self):
        self.assertEqual(self.executor.execute("UNTHROTTLE", "fixture-backend", self.evidence).status, "BLOCKED")
        applied = self.executor.execute("THROTTLE", "fixture-backend", self.evidence)
        self.evidence["memory_throttle"] = applied.after
        self.docker.doc["HostConfig"]["MemorySwap"] = -1
        self.assertEqual(self.executor.execute("UNTHROTTLE", "fixture-backend", self.evidence).status, "BLOCKED")
        self.assertEqual(len(self.docker.updates), 1)

    def test_pinned_adapter_keeps_agent_operator_limit(self):
        self.executor.memory_limit_bytes = 384 * MIB
        self.binding["container"]["memory_limit_bytes"] = 384 * MIB
        with patch.dict(os.environ, {"REMEDIATION_MEMORY_LIMIT_BYTES": str(768 * MIB)}):
            pinned = BoundDockerExecutor(self.executor, self.binding)
        self.assertEqual(pinned.memory_limit_bytes, 384 * MIB)
        result = self.executor.execute("THROTTLE", "fixture-backend", {**self.evidence, "target_binding": self.binding})
        self.assertTrue(result.ok, result)
        self.assertEqual(self.docker.doc["HostConfig"]["Memory"], 384 * MIB)
        self.assertTrue(all(target == CID for target in self.docker.lookups))

    def test_missing_binding_memory_opt_in_cannot_use_live_env_limit(self):
        result = self.executor.execute("THROTTLE", "fixture-backend", {**self.evidence, "target_binding": self.binding})
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(self.docker.updates, [])

    def test_replaced_target_or_expiry_after_stats_never_updates(self):
        self.docker.doc["Image"] = "sha256:" + "c" * 64
        evidence = {**self.evidence, "target_binding": self.binding}
        self.assertEqual(self.executor.execute("THROTTLE", "fixture-backend", evidence).status, "BLOCKED")
        self.docker.doc["Image"] = IMAGE
        self.binding["container"]["memory_limit_bytes"] = 512 * MIB
        pinned = BoundDockerExecutor(self.executor, self.binding)
        self.docker.on_stats = lambda: setattr(pinned, "approval_deadline", time.time() - 1)
        self.assertEqual(pinned.execute("THROTTLE", CID, self.evidence).status, "BLOCKED")
        self.assertEqual(self.docker.updates, [])

    def test_partial_write_or_unconfirmed_effect_is_unknown(self):
        self.docker.fail_after_write = True
        result = self.executor.execute("THROTTLE", "fixture-backend", self.evidence)
        self.assertEqual(result.status, "UNKNOWN")
        self.assertFalse(result.verified)

    def test_operator_env_limit_is_captured_at_construction(self):
        with patch.dict(os.environ, {"REMEDIATION_MEMORY_LIMIT_BYTES": str(384 * MIB)}):
            executor = LocalDockerExecutor(client=self.docker)
        self.assertEqual(executor.memory_limit_bytes, 384 * MIB)
        with patch.dict(os.environ, {"REMEDIATION_MEMORY_LIMIT_BYTES": "invalid"}):
            executor = LocalDockerExecutor(client=self.docker)
        self.assertIsNone(executor.memory_limit_bytes)


if __name__ == "__main__": unittest.main()
