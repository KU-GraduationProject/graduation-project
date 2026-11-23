"""Notion P0 contracts: durable incidents, one winning decision, zero unsafe mutations."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import os
import tempfile
import threading
import time
import unittest
from unittest.mock import AsyncMock, patch

import store
from security import service_auth, signing
from tests.test_endpoint_auth import API_KEY
from tests.test_phase2_integration import Phase2Base, analysis_body, approve_form


class IncidentStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "records.json")
        self.store = store.RecordStore(self.path)
        self.store.load()

    def proposal(self, action="RESTART", rid="first"):
        alert = json.loads(analysis_body(action))["alert"]
        key, identity = store.incident_key(alert)
        return store.RemediationRecord(rid, "UnauthorizedDataTransfer", action,
            incident_key=key, action_hash=store.action_hash(action, ["leafy-backend"]),
            identity=identity, targets=["leafy-backend"], requires_approval=True,
            state=store.AWAITING_APPROVAL, approval_requested_at=store.utcnow(),
            approval_expires_at=time_iso(time.time() + 900))

    def test_same_incident_action_reuses_record_across_restart(self):
        first, created = self.store.get_or_create_incident(self.proposal())
        self.assertTrue(created)
        self.store.mark_rejected(first.remediation_id, "UONE")
        restarted = store.RecordStore(self.path)
        restarted.load()
        again, created = restarted.get_or_create_incident(self.proposal(rid="second"))
        self.assertFalse(created)
        self.assertEqual(again.remediation_id, "first")
        self.assertEqual(again.state, store.REJECTED)
        self.assertEqual(len(restarted.all()), 1)

    def test_different_action_conflicts_without_overwriting(self):
        self.store.get_or_create_incident(self.proposal())
        with self.assertRaises(store.IncidentConflict):
            self.store.get_or_create_incident(self.proposal("ISOLATE", "second"))
        self.assertEqual(self.store.get("first").action_type, "RESTART")
        self.assertEqual(len(self.store.all()), 1)

    def test_concurrent_retransmissions_create_one_record(self):
        barrier = threading.Barrier(8)
        def submit(i):
            proposal = self.proposal(rid=f"record-{i}")
            barrier.wait()
            return self.store.get_or_create_incident(proposal)
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(submit, range(8)))
        self.assertEqual(sum(created for _, created in results), 1)
        self.assertEqual(len({record.remediation_id for record, _ in results}), 1)
        self.assertEqual(len(self.store.all()), 1)

    def test_approve_and_reject_have_exactly_one_winning_transition(self):
        self.store.create(self.proposal())
        barrier = threading.Barrier(2)
        def approve():
            barrier.wait()
            return self.store.mark_approved("first", "UONE") is not None
        def reject():
            barrier.wait()
            return self.store.mark_rejected("first", "UTWO")
        with ThreadPoolExecutor(max_workers=2) as pool:
            a, b = pool.submit(approve), pool.submit(reject)
            self.assertEqual(int(a.result()) + int(b.result()), 1)
        restored = store.RecordStore(self.path)
        restored.load()
        final = restored.get("first")
        self.assertIn(final.state, (store.APPROVED, store.REJECTED))
        self.assertFalse(restored.mark_rejected("first", "UTHREE"))
        self.assertIsNone(restored.mark_approved("first", "UTHREE"))

    def test_failed_save_does_not_acknowledge_or_keep_approval_in_memory(self):
        self.store.create(self.proposal())
        with patch.object(store.os, "replace", side_effect=OSError("disk unavailable")):
            self.assertIsNone(self.store.mark_approved("first", "UONE"))
        self.assertFalse(self.store.writable)
        self.assertEqual(self.store.get("first").state, store.AWAITING_APPROVAL)
        restarted = store.RecordStore(self.path)
        restarted.load()
        self.assertEqual(restarted.get("first").state, store.AWAITING_APPROVAL)
        self.assertFalse(self.store.claim_execution("first")[0])

    def test_manual_claim_requires_durable_approval_and_current_expiry(self):
        self.store.create(self.proposal())
        self.assertFalse(self.store.claim_execution("first")[0])
        self.assertIsNotNone(self.store.mark_approved("first", "UONE"))
        self.store.update("first", approval_expires_at=time_iso(time.time() - 1))
        self.assertEqual(self.store.claim_execution("first"), (False, "approval_expired"))
        restarted = store.RecordStore(self.path)
        restarted.load()
        self.assertEqual(restarted.get("first").state, store.EXPIRED)

    def test_incident_and_hash_canonicalize_time_targets_and_parameter_order(self):
        alert = json.loads(analysis_body("RESTART"))["alert"]
        key, _ = store.incident_key(alert)
        alert["startsAt"] = "2026-10-29T09:00:00+09:00"
        self.assertEqual(store.incident_key(alert)[0], key)
        self.assertEqual(store.action_hash("restart", ["b", "a"], 10, "auto", {"b": 2, "a": 1}),
                         store.action_hash("RESTART", ["a", "b"], 10, "auto", {"a": 1, "b": 2}))
        self.assertNotEqual(store.action_hash("RESTART", ["a"], 10, "auto"),
                            store.action_hash("RESTART", ["a"], 20, "auto"))
        alert["startsAt"] = "2026-10-29T01:00:00Z"
        self.assertNotEqual(store.incident_key(alert)[0], key)


def time_iso(timestamp):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


class IncidentControllerTests(Phase2Base):
    def setUp(self):
        super().setUp()
        self.nonce = 0

    def post(self, payload, endpoint="/action"):
        self.nonce += 1
        raw = json.dumps(payload).encode()
        ts = str(self.signed_timestamp - self.nonce)
        return self.client.post(endpoint, content=raw, headers={
            service_auth.TIMESTAMP_HEADER: ts,
            service_auth.SIGNATURE_HEADER: signing.sign(API_KEY, ts, raw),
            "Content-Type": "application/json"})

    def proposal(self, action="RESTART"):
        return self.post(json.loads(analysis_body(action)))

    def test_retransmission_after_execution_and_restart_never_reexecutes(self):
        self.fake.restart_effect = lambda: self.fake.doc["State"].update(StartedAt="2026-11-11T10:00:00Z")
        first = self.proposal()
        rid = first.json()["remediation_id"]
        again = self.proposal()
        self.assertEqual(again.json()["remediation_id"], rid)
        self.assertEqual(again.json()["record_state"], self.main.store_mod.AWAITING_APPROVAL)
        self.assertEqual(self.post_slack(approve_form("RESTART", rid)).status_code, 200)
        restored = self.main.store_mod.RecordStore(self.main.record_store.path)
        restored.load()
        restored.reconcile_interrupted()
        self.main.record_store = restored
        final = self.proposal()
        self.assertEqual(final.json()["remediation_id"], rid)
        self.assertEqual(final.json()["record_state"], self.main.store_mod.VERIFIED)
        self.assertEqual(self.docker_actions(), ["restart"])
        self.assertEqual(len(restored.all()), 1)

    def test_same_incident_different_action_returns_409(self):
        first = self.proposal()
        conflict = self.proposal("ISOLATE")
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(self.record(first.json()["remediation_id"]).action_type, "RESTART")
        self.assertEqual(self.docker_actions(), [])

    def test_changed_parameters_conflict_without_replacing_approved_plan(self):
        payload = json.loads(analysis_body("RESTART"))
        payload["analysis"]["action_parameters"] = {"reason": "first"}
        first = self.post(payload)
        payload["analysis"]["action_parameters"] = {"reason": "second"}
        self.assertEqual(self.post(payload).status_code, 409)
        self.assertEqual(self.record(first.json()["remediation_id"]).action_parameters, {"reason": "first"})
        self.assertEqual(self.docker_actions(), [])

    def test_incomplete_incident_never_gets_an_executable_record(self):
        for field in (*self.main.store_mod.IDENTITY_FIELDS, "fingerprint", "startsAt"):
            payload = json.loads(analysis_body("RESTART"))
            container = payload["alert"]["labels"] if field in self.main.store_mod.IDENTITY_FIELDS else payload["alert"]
            container.pop(field)
            with self.subTest(field=field):
                self.assertEqual(self.post(payload).status_code, 422)
        self.assertEqual(self.main.record_store.all(), [])
        self.assertEqual(self.docker_actions(), [])

    def test_other_channel_denied_but_any_designated_channel_member_can_approve(self):
        rid = self.proposal().json()["remediation_id"]
        import urllib.parse
        payload = json.loads(urllib.parse.unquote(approve_form("RESTART", rid)[8:]))
        payload["channel"]["id"] = "COTHER"
        self.assertEqual(asyncio.run(self.main.handle_socket_action(payload)).status_code, 403)
        payload["channel"]["id"] = "CTEST"
        payload["user"]["id"] = "UANYMEMBER"
        self.assertEqual(asyncio.run(self.main.handle_socket_action(payload)).status_code, 200)
        self.assertEqual(self.record(rid).approved_by, "UANYMEMBER")
        self.assertEqual(self.docker_actions(), ["restart"])

    def test_expired_click_persists_expired_and_never_executes(self):
        rid = self.proposal().json()["remediation_id"]
        self.main.record_store.update(rid, approval_expires_at=time_iso(time.time() - 1))
        self.assertEqual(self.post_slack(approve_form("RESTART", rid)).status_code, 409)
        self.assertEqual(self.record(rid).state, self.main.store_mod.EXPIRED)
        self.assertEqual(self.docker_actions(), [])

    def test_expiry_during_preflight_blocks_the_actual_docker_call(self):
        rid = self.proposal().json()["remediation_id"]
        original = self.main.evidence_mod.gate
        def gate(*args):
            result = original(*args)
            self.main.record_store.update(rid, approval_expires_at=time_iso(time.time() - 1))
            return result
        with patch.object(self.main.evidence_mod, "gate", side_effect=gate):
            self.assertEqual(self.post_slack(approve_form("RESTART", rid)).status_code, 200)
        self.assertEqual(self.record(rid).state, self.main.store_mod.EXPIRED)
        self.assertEqual(self.docker_actions(), [])

    def test_approval_persistence_failure_returns_error_without_docker(self):
        rid = self.proposal().json()["remediation_id"]
        with patch.object(self.main.store_mod.os, "replace", side_effect=OSError("disk full")):
            response = self.post_slack(approve_form("RESTART", rid))
        self.assertEqual(response.status_code, 503)
        self.assertEqual(self.docker_actions(), [])
        self.assertEqual(self.record(rid).state, self.main.store_mod.AWAITING_APPROVAL)

    def test_notification_path_has_no_record_no_approval_buttons_no_docker(self):
        payload = json.loads(analysis_body("RESTART"))
        payload["operation"] = "notify_only"
        sent = {"sent": True, "status": "SUCCESS"}
        with patch.object(self.main.notifier, "send_alert_only", new=AsyncMock(return_value=sent)) as notice, \
             patch.object(self.main.notifier, "send_approval_request", new=AsyncMock()) as approval:
            response = self.post(payload, "/notify")
        self.assertEqual(response.json(), {"status": "notification_only", "dispatch": sent})
        notice.assert_awaited_once_with(payload["alert"], payload["analysis"])
        approval.assert_not_awaited()
        self.assertEqual(self.main.record_store.all(), [])
        self.assertEqual(self.docker_actions(), [])
        self.assertEqual(self.fake.reloads, 0)

    def test_notification_path_requires_auth_even_without_execution(self):
        response = self.client.post("/notify", json=json.loads(analysis_body("RESTART")))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.main.record_store.all(), [])
        self.assertEqual(self.docker_actions(), [])

    def test_signed_notification_body_cannot_be_rerouted_to_action(self):
        payload = json.loads(analysis_body("THROTTLE", threat_level="medium"))
        payload["operation"] = "notify_only"
        # FIRST use on /action: a replay rejection would conceal the routing bug.
        response = self.post(payload, "/action")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "action_operation_mismatch")
        self.assertEqual(self.main.record_store.all(), [])
        self.assertEqual(self.docker_actions(), [])
        self.assertEqual(self.fake.reloads, 0)

    def test_notify_requires_signed_operation_marker(self):
        response = self.post(json.loads(analysis_body("RESTART")), "/notify")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.main.record_store.all(), [])
        self.assertEqual(self.docker_actions(), [])

    @unittest.skipIf(os.name == "nt", "Windows has no portable directory fsync")
    def test_directory_durability_failure_blocks_proposal_before_dispatch(self):
        import stat
        original = os.fsync
        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("directory sync unavailable")
            return original(fd)
        with patch.object(self.main.store_mod.os, "fsync", side_effect=fail_directory):
            response = self.proposal()
        self.assertEqual(response.status_code, 503)
        self.assertFalse(self.main.record_store.writable)
        self.assertEqual(self.docker_actions(), [])

    def test_final_ledger_save_failure_is_uncertain_and_cannot_be_reexecuted(self):
        self.fake.restart_effect = lambda: self.fake.doc["State"].update(StartedAt="2026-11-11T10:00:00Z")
        rid = self.proposal().json()["remediation_id"]
        original = self.main.record_store.update
        def update(remediation_id, **fields):
            if fields.get("state") == self.main.store_mod.VERIFIED:
                with patch.object(self.main.store_mod.os, "replace", side_effect=OSError("ledger full")):
                    return original(remediation_id, **fields)
            return original(remediation_id, **fields)
        with patch.object(self.main.record_store, "update", side_effect=update):
            response = self.post_slack(approve_form("RESTART", rid))
        self.assertEqual(response.json()["record_state"], self.main.store_mod.UNKNOWN)
        self.assertFalse(self.main.record_store.writable)
        self.assertEqual(self.docker_actions(), ["restart"])
        self.assertEqual(self.post_slack(approve_form("RESTART", rid), nonce=2).status_code, 503)
        self.assertEqual(self.docker_actions(), ["restart"])

    def test_restored_recovery_request_gets_one_fresh_approval_window(self):
        rid = self.proposal("ISOLATE").json()["remediation_id"]
        self.assertEqual(self.post_slack(approve_form("ISOLATE", rid)).status_code, 200)
        self.main.record_store.update(rid, state=self.main.store_mod.VERIFIED)
        restored = self.main.store_mod.RecordStore(self.main.record_store.path)
        restored.load()
        restored.reconcile_interrupted()
        self.main.record_store = restored
        self.assertEqual(restored.get(rid).state, self.main.store_mod.RECOVERY_APPROVAL_REQUIRED)
        pending = self.main.recovery_mod.run_due(restored, self.main.executor)
        self.assertEqual(len(pending), 1)
        record, results, state = pending[0]
        with patch.object(self.main.notifier, "send_recovery_request", new=AsyncMock()) as notify:
            asyncio.run(self.main._on_ttl_event(record, results, state))
        notify.assert_awaited_once()
        self.assertTrue(self.main.store_mod.approval_valid(restored.get(rid), recovery=True))
        self.assertEqual(self.main.recovery_mod.run_due(restored, self.main.executor), [])
        self.assertEqual(self.docker_actions(), ["disconnect"])
