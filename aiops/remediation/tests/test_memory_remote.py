"""In-process Agent memory capability, durable evidence and automatic TTL restore."""
from unittest.mock import patch
import unittest
import time

from tests.test_remote_agent import setup_case, send, command, TARGET
from tests.test_executor import FakeContainer

MIB = 1024 * 1024


class RemoteMemoryTests(unittest.TestCase):
    def setUp(self):
        setup_case(self)
        self.service.config.targets[TARGET].memory_limit_bytes = 512 * MIB
        self.doc["HostConfig"].update(Memory=1024 * MIB, MemorySwap=1024 * MIB)
        self.original_update = FakeContainer.update
        def update(container, **values):
            self.original_update(container, **values)
            if "mem_limit" in values: container.fake.doc["HostConfig"]["Memory"] = values["mem_limit"]
            if "memswap_limit" in values: container.fake.doc["HostConfig"]["MemorySwap"] = values["memswap_limit"]
        p = patch.object(FakeContainer, "update", update); p.start(); self.addCleanup(p.stop)
        p = patch.object(FakeContainer, "stats", return_value={"memory_stats": {"usage": 128 * MIB}}, create=True)
        p.start(); self.addCleanup(p.stop)

    def request(self, expected=512 * MIB):
        return command("THROTTLE", rid="memory-fixture", resource="memory", expected_memory_limit_bytes=expected)

    def test_memory_limit_and_durable_ttl_restore_do_not_change_cpu(self):
        result = send(self, self.request())
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(result.json()["state"], "SUCCESS", result.text)
        self.assertEqual(self.doc["HostConfig"]["Memory"], 512 * MIB)
        self.assertEqual(self.doc["HostConfig"]["CpuQuota"], 0)
        persisted = self.ledger.get("memory-fixture", TARGET)
        self.assertEqual(persisted["evidence"]["memory_throttle"]["applied_memory"], 512 * MIB)
        self.assertEqual(persisted["request"]["expected_memory_limit_bytes"], 512 * MIB)
        persisted["deadline"] = time.time() - 1
        self.ledger.save(persisted)
        self.service.tick()
        persisted = self.ledger.get("memory-fixture", TARGET)
        self.assertEqual(persisted["recovery_state"], "SUCCESS", persisted)
        self.assertEqual(self.doc["HostConfig"]["Memory"], 1024 * MIB)
        self.assertEqual(self.doc["HostConfig"]["MemorySwap"], 1024 * MIB)
        self.assertEqual(self.doc["HostConfig"]["CpuQuota"], 0)

    def test_agent_capability_change_requires_new_approval(self):
        request = self.request()
        self.service.config.targets[TARGET].memory_limit_bytes = 384 * MIB
        result = send(self, request)
        self.assertEqual(result.status_code, 403, result.text)
        self.assertEqual(self.fake.calls, [])

    def test_request_cannot_supply_unapproved_kernel_limit(self):
        result = send(self, self.request(384 * MIB))
        self.assertEqual(result.status_code, 403, result.text)
        self.assertEqual(self.fake.calls, [])
