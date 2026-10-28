"""
조치 레코드 저장소·증거 게이트·TTL 복구·MTTR 테스트 (Phase 2).

Docker 데몬·Slack·Loki 를 쓰지 않는다. 저장소는 임시 디렉터리에 쓰고, 실행기는
test_executor 의 FakeDocker 를 재사용한다.

실행 (remediation 디렉터리에서):
    python -m unittest discover -s tests -v
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import evidence as evidence_mod  # noqa: E402
import recovery as recovery_mod  # noqa: E402
import store as store_mod  # noqa: E402
from executor.base import DisabledExecutor  # noqa: E402
from tests.test_executor import (  # noqa: E402
    BUSINESS,
    MGMT,
    inspect_doc,
    make_executor,
)

TARGET = "leafy-backend"


def full_doc():
    return inspect_doc({BUSINESS: {"ip": "10.210.0.7", "aliases": ["backend"]},
                        MGMT: {"ip": "10.211.0.7"}}, resources={"CpuQuota": 0})


def new_store(tmpdir) -> store_mod.RecordStore:
    s = store_mod.RecordStore(os.path.join(tmpdir, "records.json"))
    s.load()
    return s


def record_for(action_type, rid="rid-1", ttl=1800, mode="auto", targets=(TARGET,)):
    return store_mod.RemediationRecord(
        remediation_id=rid, alertname="HighCpuUsage", action_type=action_type,
        targets=list(targets), ttl_seconds=ttl, recovery_mode=mode,
        alert_active_at="2026-10-29T00:00:00+00:00",
    )


class StorePersistenceTest(unittest.TestCase):
    def test_record_survives_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "records.json")
            s1 = store_mod.RecordStore(path)
            s1.load()
            s1.create(record_for("ISOLATE", rid="keep-me"))
            s1.update("keep-me", state=store_mod.VERIFIED)

            # 새 프로세스를 흉내낸다
            s2 = store_mod.RecordStore(path)
            s2.load()
            restored = s2.get("keep-me")
            self.assertIsNotNone(restored)
            self.assertEqual(restored.state, store_mod.VERIFIED)
            self.assertEqual(restored.action_type, "ISOLATE")

    def test_write_is_atomic_and_valid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = new_store(tmp)
            s.create(record_for("THROTTLE"))
            with open(s.path, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data["version"], 1)
            self.assertIn("rid-1", data["records"])
            # 임시 파일이 남지 않는다
            leftovers = [f for f in os.listdir(tmp) if f.startswith(".remediation_")]
            self.assertEqual(leftovers, [])

    def test_corrupt_state_file_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "records.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{broken")
            s = store_mod.RecordStore(path)
            s.load()
            self.assertEqual(s.all(), [])

    def test_unwritable_store_is_reported(self):
        # 디렉터리 자리에 파일을 두면 makedirs 가 실패한다 (OS 중립적인 쓰기 불가 상황)
        with tempfile.TemporaryDirectory() as tmp:
            blocker = os.path.join(tmp, "blocked")
            with open(blocker, "w", encoding="utf-8") as fh:
                fh.write("not a directory")
            s = store_mod.RecordStore(os.path.join(blocker, "rec.json"))
            s.load()
            self.assertFalse(s.check_writable())
            self.assertFalse(s.writable)


class IdempotencyTest(unittest.TestCase):
    def test_second_claim_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = new_store(tmp)
            s.create(record_for("RESTART"))
            first, _ = s.claim_execution("rid-1")
            second, why = s.claim_execution("rid-1")
            self.assertTrue(first)
            self.assertFalse(second)
            self.assertEqual(why, "already_executing")

    def test_claim_after_verified_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = new_store(tmp)
            s.create(record_for("RESTART"))
            s.claim_execution("rid-1")
            s.update("rid-1", state=store_mod.VERIFIED)
            ok, why = s.claim_execution("rid-1")
            self.assertFalse(ok)
            self.assertEqual(why, "already_verified")

    def test_claim_survives_restart(self):
        """재시작 후에도 이미 실행한 조치를 다시 실행하지 않는다."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "records.json")
            s1 = store_mod.RecordStore(path)
            s1.load()
            s1.create(record_for("ISOLATE"))
            self.assertTrue(s1.claim_execution("rid-1")[0])

            s2 = store_mod.RecordStore(path)
            s2.load()
            ok, why = s2.claim_execution("rid-1")
            self.assertFalse(ok)
            self.assertEqual(why, "already_executing")

    def test_unknown_id_cannot_be_claimed(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = new_store(tmp)
            ok, why = s.claim_execution("nope")
            self.assertFalse(ok)
            self.assertEqual(why, "unknown_remediation_id")

    def test_derive_id_is_stable_and_distinguishing(self):
        a = store_mod.derive_id("HighCpuUsage", "RESTART", ["leafy-backend"])
        b = store_mod.derive_id("HighCpuUsage", "restart", ["leafy-backend"])
        c = store_mod.derive_id("HighCpuUsage", "RESTART", ["leafy-db"])
        self.assertEqual(a, b)         # 대소문자 무관
        self.assertNotEqual(a, c)      # 대상이 다르면 다른 조치


class EvidenceGateTest(unittest.TestCase):
    def test_collect_captures_required_fields(self):
        ex, _ = make_executor(full_doc())
        ev = evidence_mod.collect(ex, "rid-1", "ISOLATE", [TARGET])
        snap = ev["targets"][TARGET]
        self.assertEqual(snap["container_id"], "abc123")
        self.assertIn(BUSINESS, snap["networks"])
        self.assertEqual(snap["networks"][BUSINESS]["ip_address"], "10.210.0.7")
        self.assertIn("cpu_quota", snap["resources"])
        self.assertTrue(ev["collected_at"])

    def test_isolate_blocked_when_snapshot_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = new_store(tmp)
            ex, _ = make_executor(full_doc(), missing_container=True)
            ev, reason = evidence_mod.gate(ex, s, "rid-1", "ISOLATE", [TARGET])
            self.assertIsNotNone(reason)
            self.assertIn("snapshot_failed", reason)

    def test_isolate_blocked_without_ip(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = new_store(tmp)
            ex, _ = make_executor(inspect_doc({BUSINESS: {}}))
            ev, reason = evidence_mod.gate(ex, s, "rid-1", "ISOLATE", [TARGET])
            self.assertIsNotNone(reason)
            self.assertIn("evidence_missing_ip", reason)

    def test_blocked_when_store_not_writable(self):
        """재시작하면 복구 근거가 사라지므로 가역 조치를 막는다."""
        with tempfile.TemporaryDirectory() as tmp:
            blocker = os.path.join(tmp, "blocked")
            with open(blocker, "w", encoding="utf-8") as fh:
                fh.write("not a directory")
            s = store_mod.RecordStore(os.path.join(blocker, "rec.json"))
            s.load()
            s.check_writable()
            ex, _ = make_executor(full_doc())
            ev, reason = evidence_mod.gate(ex, s, "rid-1", "ISOLATE", [TARGET])
        self.assertEqual(reason, "evidence_store_not_writable")

    def test_restart_needs_no_evidence_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = new_store(tmp)
            ex, _ = make_executor(full_doc())
            ev, reason = evidence_mod.gate(ex, s, "rid-1", "RESTART", [TARGET])
            self.assertIsNone(reason)

    def test_disabled_executor_evidence_is_unusable(self):
        ev = evidence_mod.collect(DisabledExecutor(), "rid-1", "ISOLATE", [TARGET])
        ok, why = evidence_mod.verify_usable(ev, "ISOLATE")
        self.assertFalse(ok)
        self.assertIn("evidence_unavailable", why)


class TtlRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = new_store(self.tmp.name)
        self.ex, self.fake = make_executor(full_doc())

    def _executed(self, action_type, mode, rid="rid-1"):
        """조치를 실제로 실행하고 TTL 일정까지 건 레코드를 만든다."""
        record = record_for(action_type, rid=rid, mode=mode)
        self.store.create(record)
        self.store.claim_execution(rid)
        ev = evidence_mod.collect(self.ex, rid, action_type, [TARGET])
        self.store.update(rid, evidence=ev)
        result = self.ex.execute(action_type, TARGET, evidence_mod.for_target(ev, TARGET))
        self.assertTrue(result.ok, result.detail)
        self.store.update(rid, state=store_mod.VERIFIED,
                          action_verified_at="2026-10-29T00:01:00+00:00")
        recovery_mod.schedule(self.store, self.store.get(rid), 1800, mode, now=0.0)
        return self.store.get(rid)

    def test_throttle_auto_recovers_on_ttl(self):
        record = self._executed("THROTTLE", recovery_mod.AUTO)
        self.assertEqual(record.state, store_mod.RECOVERY_PENDING)
        self.assertEqual(self.ex.snapshot(TARGET)["resources"]["cpu_quota"], 50000)

        # TTL 전에는 아무 일도 없다
        self.assertEqual(recovery_mod.run_due(self.store, self.ex, now=1000.0), [])
        # TTL 후 자동 복구
        processed = recovery_mod.run_due(self.store, self.ex, now=2000.0)
        self.assertEqual(len(processed), 1)
        _, results, state = processed[0]
        self.assertEqual(state, store_mod.RECOVERED)
        self.assertTrue(all(r.ok for r in results))
        self.assertEqual(self.ex.snapshot(TARGET)["resources"]["cpu_quota"], 0)

    def test_isolate_does_not_auto_reconnect_on_ttl(self):
        record = self._executed("ISOLATE", recovery_mod.REQUIRE_APPROVAL)
        self.assertNotIn(BUSINESS, self.ex.snapshot(TARGET)["networks"])

        processed = recovery_mod.run_due(self.store, self.ex, now=2000.0)
        self.assertEqual(len(processed), 1)
        _, results, state = processed[0]
        self.assertEqual(state, store_mod.RECOVERY_APPROVAL_REQUIRED)
        self.assertEqual(results, [])
        # 자동으로 다시 붙지 않았다
        self.assertNotIn(BUSINESS, self.ex.snapshot(TARGET)["networks"])
        self.assertIsNone(self.store.get("rid-1").recovery_verified_at)

    def test_isolate_recovers_only_with_approval(self):
        self._executed("ISOLATE", recovery_mod.REQUIRE_APPROVAL)
        recovery_mod.run_due(self.store, self.ex, now=2000.0)
        record = self.store.get("rid-1")

        results, state = recovery_mod.recover(self.store, self.ex, record,
                                              approved_by="tester", force=True)
        self.assertEqual(state, store_mod.RECOVERED)
        nets = self.ex.snapshot(TARGET)["networks"]
        self.assertIn(BUSINESS, nets)
        self.assertEqual(nets[BUSINESS]["ip_address"], "10.210.0.7")
        self.assertEqual(nets[BUSINESS]["aliases"], ["backend"])
        self.assertEqual(self.store.get("rid-1").approved_by, "tester")

    def test_pause_requires_approval_to_unpause(self):
        self._executed("PAUSE", recovery_mod.REQUIRE_APPROVAL)
        self.assertTrue(self.ex.snapshot(TARGET)["state"]["paused"])
        recovery_mod.run_due(self.store, self.ex, now=2000.0)
        self.assertTrue(self.ex.snapshot(TARGET)["state"]["paused"])

        record = self.store.get("rid-1")
        _, state = recovery_mod.recover(self.store, self.ex, record, force=True)
        self.assertEqual(state, store_mod.RECOVERED)
        self.assertFalse(self.ex.snapshot(TARGET)["state"]["paused"])

    def test_restart_has_no_recovery(self):
        record = record_for("RESTART", mode=recovery_mod.NONE, ttl=None)
        self.store.create(record)
        results, state = recovery_mod.recover(self.store, self.ex, record)
        self.assertEqual(results, [])
        self.assertEqual(state, store_mod.RECOVERED)

    def test_failed_recovery_is_not_recorded_as_success(self):
        self._executed("THROTTLE", recovery_mod.AUTO)
        # 같은 컨테이너(쿼터 50000 적용된 상태)에 대해 update 가 먹지 않는 실행기
        from executor.local_docker import LocalDockerExecutor
        from tests.test_executor import ISOLATE_PATTERNS, PRESERVE_PATTERNS, FakeDocker
        broken = LocalDockerExecutor(
            client=FakeDocker(self.fake.doc, update_applies=False),
            isolate_networks=ISOLATE_PATTERNS, preserve_networks=PRESERVE_PATTERNS)
        record = self.store.get("rid-1")
        results, state = recovery_mod.recover(self.store, broken, record)
        self.assertEqual(state, store_mod.RECOVERY_FAILED)
        self.assertFalse(any(r.ok for r in results))
        # MTTR 을 만들지 않는다
        self.assertIsNone(self.store.get("rid-1").recovery_verified_at)
        self.assertIsNone(self.store.get("rid-1").mttr())

    def test_due_recoveries_only_includes_pending(self):
        self._executed("THROTTLE", recovery_mod.AUTO, rid="a")
        self.store.create(record_for("THROTTLE", rid="b"))
        self.store.update("b", state=store_mod.VERIFIED)
        due = self.store.due_recoveries(now=2000.0)
        self.assertEqual([r.remediation_id for r in due], ["a"])


class MttrTest(unittest.TestCase):
    def test_mttr_uses_verified_recovery_time(self):
        record = store_mod.RemediationRecord(
            remediation_id="r", alertname="a", action_type="ISOLATE",
            alert_active_at="2026-10-29T00:00:00+00:00",
            approval_requested_at="2026-10-29T00:00:10+00:00",
            approved_at="2026-10-29T00:01:00+00:00",
            action_started_at="2026-10-29T00:01:05+00:00",
            action_verified_at="2026-10-29T00:01:20+00:00",
            recovery_started_at="2026-10-29T00:30:00+00:00",
            recovery_verified_at="2026-10-29T00:31:00+00:00",
        )
        t = record.timings()
        self.assertEqual(t["mttr_sec"], 1860.0)             # 복구 확인 - 경보 발생
        self.assertEqual(t["time_to_contain_sec"], 80.0)    # 조치 확인 - 경보 발생
        self.assertEqual(t["approval_latency_sec"], 50.0)
        self.assertEqual(t["action_duration_sec"], 15.0)
        self.assertEqual(t["recovery_duration_sec"], 60.0)

    def test_mttr_and_contain_are_distinct(self):
        record = store_mod.RemediationRecord(
            remediation_id="r", alertname="a", action_type="THROTTLE",
            alert_active_at="2026-10-29T00:00:00+00:00",
            action_verified_at="2026-10-29T00:00:30+00:00")
        self.assertEqual(record.time_to_contain(), 30.0)
        self.assertIsNone(record.mttr())   # 복구 확인 전에는 MTTR 이 없다

    def test_missing_timestamps_give_none_not_zero(self):
        record = store_mod.RemediationRecord(remediation_id="r", alertname="a",
                                             action_type="ISOLATE")
        self.assertIsNone(record.mttr())
        self.assertIsNone(record.time_to_contain())

    def test_recovery_due_at_respects_ttl(self):
        due = recovery_mod.recovery_due_at(1800, now=0.0)
        self.assertEqual(due, "1970-01-01T00:30:00+00:00")
        self.assertIsNone(recovery_mod.recovery_due_at(None))


if __name__ == "__main__":
    unittest.main()
