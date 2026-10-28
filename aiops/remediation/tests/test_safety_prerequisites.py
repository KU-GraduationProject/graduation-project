import os
import tempfile
import unittest
from unittest.mock import patch

import recovery
import store
from executor.base import DisabledExecutor
from security import signing
from tests import test_recovery_store as fixtures


class RecoverySafetyTest(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.TtlRecoveryTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture._executed("THROTTLE", recovery.AUTO)
        self.store, self.ex, self.fake = self.fixture.store, self.fixture.ex, self.fixture.fake

    def test_duplicate_recovery_never_changes_docker_twice(self):
        record = self.store.get("rid-1")
        recovery.recover(self.store, self.ex, record)
        count = len(self.fake.calls)
        recovery.recover(self.store, self.ex, record, force=True)
        self.assertEqual(len(self.fake.calls), count)

    def test_disabled_preserves_pending_recovery(self):
        record = self.store.get("rid-1")
        recovery.recover(self.store, DisabledExecutor(), record)
        self.assertEqual(record.state, store.RECOVERY_PENDING)

    def test_interrupted_recovery_requires_review_after_restart(self):
        self.store.claim_recovery("rid-1")
        restored = store.RecordStore(self.store.path)
        restored.load()
        self.assertEqual(restored.reconcile_interrupted(), ["rid-1"])
        self.assertEqual(restored.get("rid-1").state, store.NEEDS_REVIEW)
        self.assertFalse(restored.claim_recovery("rid-1", approved=True))


class StoreSafetyTest(unittest.TestCase):
    def test_corrupt_state_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "records.json")
            with open(path, "w") as f:
                f.write("corrupt")
            s = store.RecordStore(path)
            s.load()
            self.assertFalse(s.check_writable())
            with open(path) as f:
                self.assertEqual(f.read(), "corrupt")

    def test_failed_claim_persistence_denies_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = store.RecordStore(os.path.join(tmp, "records.json"))
            s.create(store.RemediationRecord("r", "a", "RESTART"))
            with patch("os.replace", side_effect=OSError("disk full")):
                self.assertFalse(s.claim_execution("r")[0])

    def test_nonfinite_timestamp_rejected(self):
        for ts in ("nan", "inf", "-inf"):
            signature = signing.sign("key", ts, b"body")
            self.assertFalse(signing.verify("key", ts, signature, b"body")[0])
