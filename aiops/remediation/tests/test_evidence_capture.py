"""
증거 보존(CAPTURE) 선행 단계 (#51, 노션: 파괴적 조치 앞 증거 보존).

확인하는 것:
  - 비밀값 마스킹, 로그·프로세스 크기 제한, 0600 저장과 manifest
  - 네트워크 이벤트 조회 실패는 차단하지 않음, 보관 기한이 지난 수집물 정리
  - 정책: PAUSE·ISOLATE·RECREATE·ROLLBACK 만 capture, 알 수 없는 단계는 거부
  - Controller: 승인 후 실행 직전 수집, 수집 실패 시 Docker 변경 0회
  - Agent: 허용 목록·live 모드·HMAC 인증이 있어야만 읽기 전용 수집
"""

import json
import os
import stat
import tempfile
import time
import unittest

import yaml

import evidence_capture as capture
from policy.engine import REPO_POLICY_PATH, PolicyEngine
from policy.schema import PolicyError, parse_policy
from security.agent_auth import headers
from tests.test_phase2_integration import Phase2Base, analysis_body, approve_form
from tests import test_remote_agent as agent_fixture


class FakeLogsContainer:
    def __init__(self, logs=b"", processes=None):
        self._logs, self._processes = logs, processes or []

    def logs(self, **kw):
        self.kw = kw
        return self._logs

    def top(self):
        return {"Titles": ["PID", "CMD"], "Processes": self._processes}


class CaptureModuleTest(unittest.TestCase):
    def test_mask_hides_tokens_passwords_and_jwts(self):
        text = ('Authorization: Bearer abc.def password=hunter2 api_key="k-123" '
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJlLXZhbHVl ok")
        masked = capture.mask(text)
        for secret in ("abc.def", "hunter2", "k-123", "c2lnbmF0dXJlLXZhbHVl"):
            self.assertNotIn(secret, masked)
        self.assertIn("ok", masked)

    def test_container_capture_is_bounded_and_masked(self):
        lines = b"".join(b"line %d token=secret%d\n" % (i, i) for i in range(20000))
        rows = [[str(i), "java"] for i in range(capture.MAX_PROCESSES + 50)]
        container = FakeLogsContainer(lines, rows)
        doc = capture.container_capture(container)
        self.assertEqual(container.kw["tail"], capture.MAX_LOG_LINES)
        self.assertLessEqual(len(doc["log_lines"]), capture.MAX_LOG_LINES)
        self.assertLessEqual(sum(len(l) for l in doc["log_lines"]), capture.MAX_LOG_BYTES)
        self.assertTrue(doc["log_truncated"])
        self.assertEqual(len(doc["processes"]), capture.MAX_PROCESSES)
        self.assertTrue(doc["processes_truncated"])
        self.assertFalse(any("secret" in line for line in doc["log_lines"]))

    def test_preserve_writes_private_file_and_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifests = capture.preserve(lambda t: {"log_lines": ["a"], "processes": []}, "rid-1",
                                         ["leafy-backend"], tmp)
            self.assertEqual(len(manifests), 1)
            path = manifests[0]["path"]
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            with open(path, encoding="utf-8") as fh:
                saved = json.load(fh)
            self.assertEqual(saved["target"], "leafy-backend")
            self.assertEqual(saved["network_events"]["status"], "not_configured")

    def test_capture_failure_and_bad_ids_raise(self):
        def boom(target):
            raise RuntimeError("docker down")
        with tempfile.TemporaryDirectory() as tmp:
            for args in ((boom, "rid", ["leafy-backend"]), (lambda t: {}, "rid", ["leafy-backend"]),
                         (lambda t: {"log_lines": []}, "../x", ["leafy-backend"]),
                         (lambda t: {"log_lines": []}, "rid", ["../etc"]), (lambda t: {"log_lines": []}, "rid", [])):
                with self.subTest(args=args[1:]), self.assertRaises(capture.CaptureError):
                    capture.preserve(*args, tmp)

    def test_network_events_failure_never_blocks(self):
        def broken(*a, **kw):
            raise OSError("loki down")
        with tempfile.TemporaryDirectory() as tmp:
            manifests = capture.preserve(lambda t: {"log_lines": []}, "rid", ["leafy-backend"], tmp,
                                         loki_url="http://loki:3100", service="backend", http_get=broken)
        self.assertTrue(manifests[0]["network_events"].startswith("unavailable"))

    def test_expired_captures_are_pruned(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = os.path.join(tmp, "captures", "old-rid")
            os.makedirs(old)
            past = time.time() - 30 * 86400
            os.utime(old, (past, past))
            capture.preserve(lambda t: {"log_lines": []}, "new-rid", ["leafy-backend"], tmp, retention_days=14)
            self.assertFalse(os.path.exists(old))
            self.assertTrue(os.path.exists(os.path.join(tmp, "captures", "new-rid")))


class CapturePolicyTest(unittest.TestCase):
    def test_destructive_actions_require_capture(self):
        engine = PolicyEngine.from_file(REPO_POLICY_PATH)
        for action in ("PAUSE", "ISOLATE", "RECREATE", "ROLLBACK"):
            self.assertEqual(engine.prerequisite_steps(action), ("capture",), action)
        for action in ("RESTART", "THROTTLE", "KILL_SESSIONS", "LOCK_ACCOUNT", "NOTIFY"):
            self.assertEqual(engine.prerequisite_steps(action), (), action)

    def test_unknown_or_duplicate_steps_are_rejected(self):
        with open(REPO_POLICY_PATH, encoding="utf-8") as fh:
            original = yaml.safe_load(fh)
        for value in (["backup_db"], ["capture", "capture"], ["rm -rf"]):
            raw = yaml.safe_load(yaml.safe_dump(original))
            raw["actions"]["PAUSE"]["prerequisite_steps"] = value
            with self.subTest(value=value), self.assertRaises(PolicyError):
                parse_policy(raw)


class ControllerCaptureTest(Phase2Base):
    def approve_pause(self):
        rid = self.post_action(analysis_body("PAUSE")).json()["remediation_id"]
        return rid, self.post_slack(approve_form("PAUSE", rid))

    def test_capture_is_saved_before_pause_runs(self):
        rid, response = self.approve_pause()
        self.assertEqual(response.status_code, 200, response.text)
        record = self.record(rid)
        self.assertIsNotNone(record.action_verified_at)  # PAUSE 는 이후 복구 대기(RECOVERY_PENDING)
        manifest = record.evidence["captures"][0]
        self.assertEqual(manifest["target"], "leafy-backend")
        self.assertTrue(os.path.exists(manifest["path"]))
        self.assertEqual(self.docker_actions(), ["pause"])

    def test_capture_failure_blocks_without_docker_mutation(self):
        def broken_logs(self_container, **kw):
            raise RuntimeError("logs unavailable")
        from tests.test_executor import FakeContainer
        original = FakeContainer.logs
        FakeContainer.logs = broken_logs
        self.addCleanup(setattr, FakeContainer, "logs", original)
        rid, _ = self.approve_pause()
        record = self.record(rid)
        self.assertEqual(record.state, "BLOCKED")
        self.assertTrue(record.results[0]["blocked_reason"].startswith("capture_failed"))
        self.assertEqual(self.docker_actions(), [])


class AgentCaptureTest(unittest.TestCase):
    def setUp(self):
        agent_fixture.setup_case(self)

    def get(self, target, signed=True):
        path = f"/v1/targets/{target}/capture"
        auth = headers(agent_fixture.KEY, "GET", path, b"") if signed else {}
        return self.client.get(path, headers=auth)

    def test_allowlisted_live_target_returns_masked_capture(self):
        response = self.get(agent_fixture.TARGET)
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["target"], agent_fixture.TARGET)
        self.assertIsInstance(body["log_lines"], list)
        self.assertEqual(self.fake.calls, [])  # 읽기 전용: 변경 호출 없음

    def test_unsigned_unknown_or_disabled_requests_are_refused(self):
        self.assertEqual(self.get(agent_fixture.TARGET, signed=False).status_code, 401)
        self.assertEqual(self.get("aiops-remediation").status_code, 403)
        self.service.mode = "disabled"
        self.assertEqual(self.get(agent_fixture.TARGET).status_code, 403)


if __name__ == "__main__":
    unittest.main()
