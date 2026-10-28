"""
Phase 2 엔드포인트 통합 테스트.

확인하는 것:
  - 승인 요청이 여러 번 도착해도 Docker 조치는 한 번만 일어난다 (remediation_id 멱등성)
  - 증거 보존 실패 시 격리·동결이 차단된다
  - 조치 실패가 성공으로 기록되지 않는다
  - TTL 만료 후 복구 승인 경로(approve_recovery)로만 ISOLATE 가 복구된다
  - 인증 실패 시 실행 0회 (Phase 0 보존)
  - 정책 승인 절차를 우회할 수 없다 (Phase 1 보존)
  - disabled 모드에서 조치를 성공으로 표시하지 않는다

Docker 데몬은 쓰지 않는다 — FakeDocker 를 실행기에 주입한다. Slack 은 webhook
미설정으로 전송되지 않는다.

실행 (remediation 디렉터리에서):
    python -m unittest discover -s tests -v
"""

import importlib
import json
import os
import sys
import tempfile
import time
import unittest
import urllib.parse
from unittest import mock

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import recovery as recovery_mod  # noqa: E402
import store as store_mod  # noqa: E402
from executor.local_docker import LocalDockerExecutor  # noqa: E402
from security import service_auth, signing, slack_signature  # noqa: E402
from tests.test_endpoint_auth import API_KEY, SLACK_SECRET  # noqa: E402
from tests.test_executor import (  # noqa: E402
    BUSINESS,
    MGMT,
    ISOLATE_PATTERNS,
    PRESERVE_PATTERNS,
    FakeDocker,
    inspect_doc,
)

TARGET = "leafy-backend"


def full_doc():
    return inspect_doc({BUSINESS: {"ip": "10.210.0.7", "aliases": ["backend"]},
                        MGMT: {"ip": "10.211.0.7"}}, resources={"CpuQuota": 0})


def load_main(mode="docker", state_dir=None, ttl_scan="0"):
    """TTL 스캐너는 테스트에서 끄고(run_due 를 직접 호출) 상태는 임시 디렉터리에 둔다."""
    env = {"SLACK_WEBHOOK_URL": "", "REMEDIATION_MODE": mode,
           "SLACK_SIGNING_SECRET": SLACK_SECRET, "REMEDIATION_API_KEY": API_KEY,
           "REMEDIATION_TTL_SCAN_SEC": ttl_scan}
    if state_dir:
        env["REMEDIATION_STATE_DIR"] = state_dir
    for name in ("main", "actions.notify", "actions.container", "store",
                 "recovery", "evidence", "policy.engine", "policy.schema"):
        sys.modules.pop(name, None)
    with mock.patch.dict(os.environ, env, clear=False):
        with mock.patch("docker.from_env"):
            module = importlib.import_module("main")
    return module


def analysis_body(action_type, threat_level="high", confidence=0.9,
                  targets=(TARGET,), llm_risk=None, starts_at="2026-10-29T00:00:00Z"):
    analysis = {"action_type": action_type, "action_targets": list(targets),
                "threat_level": threat_level, "confidence": confidence}
    if llm_risk is not None:
        analysis["action_risk"] = llm_risk
    return json.dumps({
        "alert": {"labels": {"alertname": "UnauthorizedDataTransfer"},
                  "startsAt": starts_at},
        "analysis": analysis}, ensure_ascii=False).encode("utf-8")


def approve_form(action_type, remediation_id=None, targets=(TARGET,),
                 action_id="approve_action"):
    value = {"alertname": "UnauthorizedDataTransfer", "action_type": action_type,
             "action_targets": list(targets)}
    if remediation_id:
        value["remediation_id"] = remediation_id
    return "payload=" + urllib.parse.quote(json.dumps({
        "actions": [{"action_id": action_id, "value": json.dumps(value)}],
        "user": {"name": "tester"}}))


class Phase2Base(unittest.TestCase):
    mode = "docker"
    docker_flags = {}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.main = load_main(self.mode, state_dir=self.tmp.name)

        self.doc = full_doc()
        self.fake = FakeDocker(self.doc, **self.docker_flags)
        if self.mode == "docker":
            self.main.executor = LocalDockerExecutor(
                client=self.fake, isolate_networks=ISOLATE_PATTERNS,
                preserve_networks=PRESERVE_PATTERNS)
            self.main.container_actions = self.main.executor

        self.events = []
        patcher = mock.patch.object(self.main, "_push_soc_event", side_effect=self._record)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = TestClient(self.main.app)

    async def _record(self, job, event):
        self.events.append((job, event))

    # ── 요청 ──────────────────────────────────────────────
    def post_action(self, body):
        ts = str(int(time.time()))
        return self.client.post("/action", content=body, headers={
            service_auth.TIMESTAMP_HEADER: ts,
            service_auth.SIGNATURE_HEADER: signing.sign(API_KEY, ts, body),
            "Content-Type": "application/json"})

    def post_slack(self, form, nonce=0):
        # 같은 바이트의 요청은 리플레이로 막히므로, 중복 승인은 다른 timestamp 로 보낸다
        body = form.encode("utf-8")
        ts = str(int(time.time()) - nonce)
        return self.client.post("/slack/action", content=body, headers={
            slack_signature.TIMESTAMP_HEADER: ts,
            slack_signature.SIGNATURE_HEADER: signing.sign(SLACK_SECRET, ts, body),
            "Content-Type": "application/x-www-form-urlencoded"})

    # ── 관찰 ──────────────────────────────────────────────
    def docker_actions(self) -> list:
        """실제로 Docker 를 바꾼 호출만 센다 (inspect/reload 는 제외)."""
        out = []
        for call in self.fake.calls:
            if call == "restart":
                out.append("restart")
            elif call in ("pause", "unpause"):
                out.append(call)
            elif isinstance(call, tuple):
                out.append(call[0])
        return out

    def events_named(self, name) -> list:
        return [e for _, e in self.events if e.get("event") == name]

    def record(self, rid):
        return self.main.record_store.get(rid)


class IdempotentApprovalTest(Phase2Base):
    def test_duplicate_approval_executes_once(self):
        resp = self.post_action(analysis_body("RESTART", llm_risk="low"))
        rid = resp.json()["remediation_id"]
        self.assertEqual(resp.json()["status"], "pending_approval")

        # 같은 remediation_id 로 승인 3회 (서로 다른 요청이지만 같은 조치)
        first = self.post_slack(approve_form("RESTART", rid), nonce=0)
        second = self.post_slack(approve_form("RESTART", rid), nonce=1)
        third = self.post_slack(approve_form("RESTART", rid), nonce=2)
        for r in (first, second, third):
            self.assertEqual(r.status_code, 200)

        self.assertEqual(self.docker_actions().count("restart"), 1)
        self.assertGreaterEqual(len(self.events_named("duplicate_execution_suppressed")), 2)
        self.assertIn("Not executed", second.json()["results"][0])

    def test_duplicate_approval_without_id_still_collapses(self):
        """과거 메시지·주기 스캔 버튼에는 remediation_id 가 없다 — 유도 ID 로 합친다."""
        first = self.post_slack(approve_form("RESTART"), nonce=0)
        second = self.post_slack(approve_form("RESTART"), nonce=1)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(self.docker_actions().count("restart"), 1)

    def test_idempotency_survives_restart(self):
        resp = self.post_action(analysis_body("RESTART"))
        rid = resp.json()["remediation_id"]
        self.post_slack(approve_form("RESTART", rid), nonce=0)
        self.assertEqual(self.docker_actions().count("restart"), 1)

        # 프로세스 재시작을 흉내낸다 (같은 상태 디렉터리)
        restarted = load_main("docker", state_dir=self.tmp.name)
        restarted.executor = LocalDockerExecutor(
            client=self.fake, isolate_networks=ISOLATE_PATTERNS,
            preserve_networks=PRESERVE_PATTERNS)
        patcher = mock.patch.object(restarted, "_push_soc_event",
                                    side_effect=self._record)
        patcher.start()
        self.addCleanup(patcher.stop)
        client = TestClient(restarted.app)
        body = approve_form("RESTART", rid).encode("utf-8")
        ts = str(int(time.time()) - 5)
        client.post("/slack/action", content=body, headers={
            slack_signature.TIMESTAMP_HEADER: ts,
            slack_signature.SIGNATURE_HEADER: signing.sign(SLACK_SECRET, ts, body),
            "Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(self.docker_actions().count("restart"), 1)

    def test_different_targets_are_different_remediations(self):
        self.post_slack(approve_form("RESTART", targets=("leafy-backend",)), nonce=0)
        self.post_slack(approve_form("RESTART", targets=("leafy-db",)), nonce=1)
        self.assertEqual(self.docker_actions().count("restart"), 2)


class IsolateFlowTest(Phase2Base):
    def test_isolate_preserves_management_network_and_verifies(self):
        resp = self.post_action(analysis_body("ISOLATE", llm_risk="low"))
        rid = resp.json()["remediation_id"]
        approve = self.post_slack(approve_form("ISOLATE", rid))
        self.assertEqual(approve.status_code, 200)

        self.assertEqual(self.docker_actions().count("disconnect"), 1)
        nets = self.main.executor.snapshot(TARGET)["networks"]
        self.assertNotIn(BUSINESS, nets)      # 업무 네트워크는 끊겼다
        self.assertIn(MGMT, nets)             # 관리 경로는 살아 있다

        record = self.record(rid)
        self.assertEqual(record.state, store_mod.RECOVERY_PENDING)
        self.assertTrue(record.action_verified_at)
        self.assertIsNotNone(record.recovery_due_at)
        # 증거가 복구용으로 저장됐다
        snap = record.evidence["targets"][TARGET]
        self.assertEqual(snap["networks"][BUSINESS]["ip_address"], "10.210.0.7")

    def test_ttl_expiry_does_not_auto_reconnect(self):
        resp = self.post_action(analysis_body("ISOLATE"))
        rid = resp.json()["remediation_id"]
        self.post_slack(approve_form("ISOLATE", rid))

        processed = recovery_mod.run_due(self.main.record_store, self.main.executor,
                                         now=time.time() + 10_000)
        self.assertEqual(len(processed), 1)
        self.assertEqual(processed[0][2], store_mod.RECOVERY_APPROVAL_REQUIRED)
        self.assertEqual(self.docker_actions().count("connect"), 0)
        self.assertNotIn(BUSINESS, self.main.executor.snapshot(TARGET)["networks"])

    def test_recovery_approval_restores_ip_and_aliases(self):
        resp = self.post_action(analysis_body("ISOLATE"))
        rid = resp.json()["remediation_id"]
        self.post_slack(approve_form("ISOLATE", rid))
        recovery_mod.run_due(self.main.record_store, self.main.executor,
                             now=time.time() + 10_000)

        recovered = self.post_slack(
            approve_form("ISOLATE", rid, action_id="approve_recovery"), nonce=3)
        self.assertEqual(recovered.status_code, 200)
        self.assertEqual(recovered.json()["status"], "recovery_recovered")

        nets = self.main.executor.snapshot(TARGET)["networks"]
        self.assertIn(BUSINESS, nets)
        self.assertEqual(nets[BUSINESS]["ip_address"], "10.210.0.7")
        self.assertEqual(nets[BUSINESS]["aliases"], ["backend"])

        record = self.record(rid)
        self.assertEqual(record.state, store_mod.RECOVERED)
        self.assertIsNotNone(record.timings()["mttr_sec"])
        self.assertIsNotNone(record.timings()["time_to_contain_sec"])

    def test_recovery_for_unknown_id_is_rejected(self):
        resp = self.post_slack(approve_form("ISOLATE", "no-such-id",
                                            action_id="approve_recovery"))
        self.assertEqual(resp.status_code, 404)


class EvidenceGateEndpointTest(Phase2Base):
    docker_flags = {"missing_container": True}

    def test_isolate_blocked_when_evidence_cannot_be_collected(self):
        resp = self.post_action(analysis_body("ISOLATE"))
        rid = resp.json()["remediation_id"]
        approve = self.post_slack(approve_form("ISOLATE", rid))
        self.assertEqual(approve.status_code, 200)
        self.assertIn("Not executed", approve.json()["results"][0])
        self.assertEqual(self.docker_actions().count("disconnect"), 0)
        blocked = self.events_named("evidence_gate_blocked")
        self.assertEqual(len(blocked), 1)
        self.assertIn("snapshot_failed", blocked[0]["reason"])
        self.assertEqual(self.record(rid).state, store_mod.BLOCKED)


class FailureIsNotSuccessTest(Phase2Base):
    docker_flags = {"disconnect_applies": False}

    def test_unapplied_isolation_is_recorded_as_failure(self):
        resp = self.post_action(analysis_body("ISOLATE"))
        rid = resp.json()["remediation_id"]
        approve = self.post_slack(approve_form("ISOLATE", rid))
        results = approve.json()["results"]
        self.assertTrue(results[0].startswith("Fail:"), results)
        self.assertIn("still_attached", results[0])

        record = self.record(rid)
        self.assertEqual(record.state, store_mod.FAILED)
        self.assertIsNone(record.action_verified_at)
        # 실패한 조치에는 복구 일정을 걸지 않는다 (되돌릴 것이 없다)
        self.assertIsNone(record.recovery_due_at)
        executed = self.events_named("manual_approval_executed")
        self.assertEqual(executed[0]["status"], "FAILED")
        self.assertFalse(executed[0]["verified"])


class ThrottleAutoExecuteTest(Phase2Base):
    def test_throttle_auto_executes_verifies_and_schedules_recovery(self):
        resp = self.post_action(analysis_body("THROTTLE", threat_level="medium",
                                              confidence=0.85))
        body = resp.json()
        self.assertEqual(body["status"], "executed")
        rid = body["remediation_id"]
        self.assertEqual(self.main.executor.snapshot(TARGET)["resources"]["cpu_quota"],
                         50000)

        record = self.record(rid)
        self.assertEqual(record.state, store_mod.RECOVERY_PENDING)
        self.assertEqual(record.recovery_mode, "auto")
        self.assertEqual(record.ttl_seconds, 1800)

    def test_ttl_expiry_restores_original_quota(self):
        resp = self.post_action(analysis_body("THROTTLE", threat_level="medium",
                                              confidence=0.85))
        rid = resp.json()["remediation_id"]
        processed = recovery_mod.run_due(self.main.record_store, self.main.executor,
                                         now=time.time() + 10_000)
        self.assertEqual(processed[0][2], store_mod.RECOVERED)
        self.assertEqual(self.main.executor.snapshot(TARGET)["resources"]["cpu_quota"], 0)
        self.assertIsNotNone(self.record(rid).timings()["mttr_sec"])

    def test_throttle_below_threshold_is_not_executed(self):
        resp = self.post_action(analysis_body("THROTTLE", threat_level="medium",
                                              confidence=0.79))
        self.assertEqual(resp.json()["status"], "pending_approval")
        self.assertEqual(self.docker_actions(), [])


class PolicyBypassTest(Phase2Base):
    def test_unsupported_action_cannot_be_approved(self):
        resp = self.post_slack(approve_form("SCALE"))
        self.assertIn("blocked by policy", resp.json()["results"][0])
        self.assertEqual(self.docker_actions(), [])

    def test_undefined_action_cannot_be_approved(self):
        resp = self.post_slack(approve_form("WIPE_DISK"))
        self.assertIn("blocked by policy", resp.json()["results"][0])
        self.assertEqual(self.docker_actions(), [])

    def test_high_risk_action_is_never_auto_executed(self):
        for action in ("RESTART", "PAUSE", "ISOLATE"):
            resp = self.post_action(analysis_body(action, threat_level="critical",
                                                  confidence=1.0, llm_risk="low"))
            self.assertEqual(resp.json()["status"], "pending_approval", action)
        self.assertEqual(self.docker_actions(), [])

    def test_unauthenticated_requests_execute_nothing(self):
        self.client.post("/action", content=analysis_body("ISOLATE"),
                         headers={"Content-Type": "application/json"})
        self.client.post("/slack/action",
                         content=approve_form("RESTART").encode("utf-8"),
                         headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(self.docker_actions(), [])
        self.assertEqual(self.events_named("policy_decision"), [])


class DisabledModeTest(Phase2Base):
    mode = "disabled"

    def test_nothing_is_executed_and_not_reported_as_success(self):
        resp = self.post_action(analysis_body("RESTART"))
        rid = resp.json()["remediation_id"]
        approve = self.post_slack(approve_form("RESTART", rid))
        results = approve.json()["results"]
        self.assertTrue(results[0].startswith("Skipped:"), results)
        self.assertNotIn("Success", results[0])
        record = self.record(rid)
        self.assertEqual(record.state, store_mod.SKIPPED)
        self.assertIsNone(record.action_verified_at)
        self.assertIsNone(record.mttr())

    def test_throttle_candidate_is_skipped_not_executed(self):
        resp = self.post_action(analysis_body("THROTTLE", threat_level="medium",
                                              confidence=0.9))
        self.assertEqual(resp.json()["status"], "skipped")
        self.assertEqual(self.record(resp.json()["remediation_id"]).state,
                         store_mod.SKIPPED)

    def test_disabled_executor_is_used(self):
        self.assertEqual(self.main.executor.name, "disabled")
        self.assertIsNone(self.main.container_actions)


class AuditTimingTest(Phase2Base):
    def test_timestamps_are_recorded_in_order(self):
        resp = self.post_action(analysis_body("ISOLATE"))
        rid = resp.json()["remediation_id"]
        self.post_slack(approve_form("ISOLATE", rid))
        recovery_mod.run_due(self.main.record_store, self.main.executor,
                             now=time.time() + 10_000)
        self.post_slack(approve_form("ISOLATE", rid, action_id="approve_recovery"),
                        nonce=4)

        t = self.record(rid).timings()
        for key in ("alert_active_at", "approval_requested_at", "approved_at",
                    "action_started_at", "action_verified_at",
                    "recovery_started_at", "recovery_verified_at"):
            self.assertIsNotNone(t[key], key)
        self.assertGreaterEqual(t["mttr_sec"], t["time_to_contain_sec"])

    def test_audit_events_use_existing_job_label(self):
        resp = self.post_action(analysis_body("ISOLATE"))
        rid = resp.json()["remediation_id"]
        self.post_slack(approve_form("ISOLATE", rid))
        jobs = {job for job, e in self.events}
        self.assertTrue(jobs <= {"aiops-remediation", "aiops-slack", "aiops-timeline"},
                        jobs)
        self.assertTrue(self.events_named("remediation_executed"))


if __name__ == "__main__":
    unittest.main()
