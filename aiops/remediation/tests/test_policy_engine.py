"""
정책 엔진 단위 테스트 (Phase 1).

핵심 불변식을 고정한다.
  1. action_risk 는 action_type 에서만 나온다 — LLM 입력으로 바뀌지 않는다.
  2. high-risk 조치는 confidence·threat_level(critical 포함)과 무관하게 자동 실행 불가.
  3. 정책에 없는 action_type 은 차단한다 (fail closed).
  4. 자동 경로와 승인 경로가 같은 execution_allowed() 게이트를 통과해야 실행된다.

Docker·Slack·Loki 는 쓰지 않는다. 실제 정책 파일(aiops/policy/remediation_policy.yml)
을 로드해 검증하므로, 정책을 고치면 여기서 먼저 드러난다.

실행 (remediation 디렉터리에서):
    python -m unittest discover -s tests -v
"""

import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from policy.engine import (  # noqa: E402
    REPO_POLICY_PATH,
    BlockAllPolicyEngine,
    PolicyEngine,
    load_engine,
    resolve_policy_path,
)
from policy.schema import (  # noqa: E402
    AUTO_EXECUTE_CANDIDATE,
    AWAITING_APPROVAL,
    BLOCKED,
    NO_ACTION,
    NOTIFY,
    THREAT_LEVELS,
    PolicyError,
    parse_policy,
)

TARGETS = ["leafy-backend"]


def engine() -> PolicyEngine:
    return PolicyEngine.from_file(REPO_POLICY_PATH)


class PolicyFileTest(unittest.TestCase):
    def test_repo_policy_loads(self):
        e = engine()
        self.assertEqual(e.config.version, 1)
        for action in ("NONE", "NOTIFY", "THROTTLE", "RESTART", "PAUSE", "ISOLATE"):
            self.assertIn(action, e.config.actions)

    def test_four_threat_levels(self):
        e = engine()
        self.assertEqual(sorted(e.config.threat_levels), sorted(THREAT_LEVELS))
        self.assertEqual(e.config.threat_levels["critical"].urgency, "immediate")
        self.assertTrue(e.config.threat_levels["critical"].mention)

    def test_risk_table_matches_confirmed_design(self):
        e = engine()
        expected = {"NONE": "low", "NOTIFY": "low", "THROTTLE": "medium",
                    "RESTART": "high", "PAUSE": "high", "ISOLATE": "high"}
        self.assertEqual({k: v.action_risk for k, v in e.config.actions.items()}, expected)

    def test_throttle_confirmed_parameters(self):
        throttle = engine().config.actions["THROTTLE"]
        self.assertEqual(throttle.min_confidence, 0.8)
        self.assertEqual(throttle.ttl_seconds, 1800)
        self.assertTrue(throttle.recovery_required)

    def test_high_risk_actions_require_approval(self):
        e = engine()
        for action in ("RESTART", "PAUSE", "ISOLATE"):
            self.assertTrue(e.config.actions[action].requires_approval, action)
            self.assertFalse(e.config.actions[action].auto_execute, action)

    def test_policy_path_resolution_prefers_explicit(self):
        self.assertEqual(resolve_policy_path("/tmp/x.yml"), "/tmp/x.yml")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("REMEDIATION_POLICY_PATH", None)
            self.assertTrue(os.path.isfile(resolve_policy_path()))

    def test_env_path_is_not_silently_replaced(self):
        """
        운영자가 지정한 정책 파일이 없으면 다른 정책으로 대체하지 않고 실패한다 —
        의도한 것과 다른 게이트로 조치가 흐르면 안 된다.
        """
        with mock.patch.dict(os.environ,
                             {"REMEDIATION_POLICY_PATH": "/definitely/not/here.yml"}):
            self.assertEqual(resolve_policy_path(), "/definitely/not/here.yml")
            with self.assertRaises(PolicyError):
                PolicyEngine.from_file()
            self.assertIsInstance(load_engine(), BlockAllPolicyEngine)


class RiskIsPolicyOwnedTest(unittest.TestCase):
    """불변식 1 — LLM 이 보낸 action_risk 로 위험도가 바뀌지 않는다."""

    def setUp(self):
        self.e = engine()

    def test_llm_low_risk_isolate_is_still_high(self):
        d = self.e.decide("ISOLATE", "high", 0.99, TARGETS, llm_action_risk="low")
        self.assertEqual(d.action_risk, "high")
        self.assertEqual(d.outcome, AWAITING_APPROVAL)
        self.assertTrue(d.requires_approval)
        self.assertFalse(d.executable_now)

    def test_llm_risk_is_recorded_but_unused(self):
        d = self.e.decide("ISOLATE", "high", 0.9, TARGETS, llm_action_risk="low")
        self.assertEqual(d.llm_action_risk, "low")
        self.assertFalse(d.as_dict()["llm_action_risk_used"])
        self.assertIn("llm_action_risk_ignored:low", d.reasons)

    def test_risk_identical_regardless_of_llm_value(self):
        risks = {self.e.decide("RESTART", "high", 0.9, TARGETS, llm_action_risk=v).action_risk
                 for v in (None, "low", "medium", "high", "garbage")}
        self.assertEqual(risks, {"high"})

    def test_legacy_analysis_dict_cannot_escalate_privileges(self):
        """이전 스키마(action_risk 포함) 입력으로도 자동 실행이 열리지 않는다."""
        legacy = {"action_type": "ISOLATE", "action_targets": TARGETS,
                  "action_risk": "low", "threat_level": "high", "confidence": 1.0}
        d = self.e.decide_from_analysis(legacy)
        self.assertEqual(d.action_risk, "high")
        self.assertEqual(d.outcome, AWAITING_APPROVAL)
        self.assertFalse(d.executable_now)


class ApprovalGateTest(unittest.TestCase):
    """불변식 2 — high-risk 는 어떤 조건에서도 자동 실행되지 않는다."""

    def setUp(self):
        self.e = engine()

    def test_isolate_high_threat_requires_approval(self):
        d = self.e.decide("ISOLATE", "high", 0.95, TARGETS)
        self.assertEqual(d.outcome, AWAITING_APPROVAL)
        self.assertEqual(d.urgency, "urgent")

    def test_isolate_critical_is_urgent_but_still_requires_approval(self):
        d = self.e.decide("ISOLATE", "critical", 1.0, TARGETS)
        self.assertEqual(d.urgency, "immediate")
        self.assertTrue(d.mention)
        self.assertTrue(d.requires_approval)
        self.assertEqual(d.outcome, AWAITING_APPROVAL)
        self.assertFalse(d.executable_now)
        self.assertIn("critical_raises_urgency_not_bypasses_approval", d.reasons)

    def test_restart_and_pause_never_auto_execute(self):
        for action in ("RESTART", "PAUSE"):
            for threat in THREAT_LEVELS:
                for conf in (0.0, 0.8, 1.0):
                    d = self.e.decide(action, threat, conf, TARGETS)
                    self.assertEqual(d.outcome, AWAITING_APPROVAL, (action, threat, conf))
                    self.assertFalse(d.executable_now, (action, threat, conf))

    def test_missing_targets_blocks_execution(self):
        d = self.e.decide("ISOLATE", "high", 0.9, [])
        self.assertEqual(d.outcome, AWAITING_APPROVAL)
        self.assertIn("no_action_targets", d.reasons)
        allowed, reason = self.e.execution_allowed("ISOLATE", [])
        self.assertFalse(allowed)
        self.assertEqual(reason, "no_action_targets")

    def test_pause_is_executable_after_phase2(self):
        """
        [Phase 2 기대값 변경] Phase 1 에서는 PAUSE 실행기가 승인 경로에 연결되지 않아
        차단됐다. Phase 2 가 PAUSE/UNPAUSE 와 복구(재승인 필요)를 구현해 열렸다.
        승인 필수라는 성질은 그대로다.
        """
        allowed, reason = self.e.execution_allowed("PAUSE", TARGETS)
        self.assertTrue(allowed, reason)
        self.assertTrue(self.e.config.actions["PAUSE"].requires_approval)
        self.assertEqual(self.e.config.actions["PAUSE"].recovery_mode,
                         "require_approval")

    def test_restart_isolate_remain_executable_on_approval(self):
        """RESTART·ISOLATE 는 Phase 0 부터 승인 후 실행되던 조치다."""
        for action in ("RESTART", "ISOLATE"):
            allowed, reason = self.e.execution_allowed(action, TARGETS)
            self.assertTrue(allowed, (action, reason))


class ThrottleAutoExecuteTest(unittest.TestCase):
    def setUp(self):
        self.e = engine()

    def test_confidence_below_threshold_is_not_auto(self):
        d = self.e.decide("THROTTLE", "medium", 0.79, TARGETS)
        self.assertEqual(d.outcome, AWAITING_APPROVAL)
        self.assertTrue(any(r.startswith("confidence_below_threshold") for r in d.reasons))
        self.assertFalse(d.executable_now)

    def test_confidence_at_threshold_is_executable_with_ttl(self):
        """
        [Phase 2 기대값 변경] Phase 1 에서는 TTL 자동 복구가 없어 executable_now=false
        였다. Phase 2 가 UNTHROTTLE 복구를 구현해 실행 가능해졌다. 자동 실행 조건
        (confidence>=0.8, threat medium/high)과 TTL 1800초는 그대로다.
        """
        d = self.e.decide("THROTTLE", "medium", 0.80, TARGETS)
        self.assertEqual(d.outcome, AUTO_EXECUTE_CANDIDATE)
        self.assertFalse(d.requires_approval)
        self.assertTrue(d.executable_now)
        self.assertEqual(d.ttl_seconds, 1800)
        self.assertTrue(d.recovery_required)
        self.assertEqual(d.recovery_mode, "auto")

    def test_threat_level_not_eligible(self):
        for threat in ("low", "critical"):
            d = self.e.decide("THROTTLE", threat, 0.95, TARGETS)
            self.assertEqual(d.outcome, AWAITING_APPROVAL, threat)
            self.assertIn(f"threat_level_not_eligible:{threat}", d.reasons)

    def test_no_targets_is_not_auto(self):
        d = self.e.decide("THROTTLE", "medium", 0.95, [])
        self.assertEqual(d.outcome, AWAITING_APPROVAL)

    def test_throttle_is_executable_after_phase2(self):
        """[Phase 2 기대값 변경] TTL 자동 복구 구현으로 실행이 열렸다."""
        allowed, reason = self.e.execution_allowed("THROTTLE", TARGETS)
        self.assertTrue(allowed, reason)


class NoActionAndNotifyTest(unittest.TestCase):
    def setUp(self):
        self.e = engine()

    def test_none_performs_no_action(self):
        d = self.e.decide("NONE", "low", 0.9, [])
        self.assertEqual(d.outcome, NO_ACTION)
        self.assertFalse(d.performs_action)
        self.assertFalse(d.requires_approval)
        self.assertFalse(d.executable_now)

    def test_notify_is_alert_only(self):
        d = self.e.decide("NOTIFY", "medium", 0.5, TARGETS)
        self.assertEqual(d.outcome, NOTIFY)
        self.assertEqual(d.notify, "alert_only")

    def test_execution_gate_rejects_non_action(self):
        for action in ("NONE", "NOTIFY"):
            allowed, reason = self.e.execution_allowed(action, TARGETS)
            self.assertFalse(allowed)
            self.assertEqual(reason, "action_performs_nothing")


class FailClosedTest(unittest.TestCase):
    """불변식 3 — 모르는/지원하지 않는 조치는 차단한다."""

    def setUp(self):
        self.e = engine()

    def test_unsupported_action_is_blocked_with_reason(self):
        d = self.e.decide("SCALE", "high", 0.99, TARGETS)
        self.assertEqual(d.outcome, BLOCKED)
        self.assertEqual(d.blocked_reason,
                         "unsupported_action_type:no_executor_implemented")
        self.assertFalse(d.executable_now)

    def test_undefined_action_is_blocked(self):
        for action in ("WIPE_DISK", "", None, "drop table", "restart "):
            d = self.e.decide(action, "critical", 1.0, TARGETS)
            if d.outcome != BLOCKED:
                # "restart " 는 정규화 후 RESTART 로 인식되는 것이 맞다
                self.assertEqual(d.action_type, "RESTART")
                continue
            self.assertFalse(d.executable_now)
            self.assertIn(d.blocked_reason, ("undefined_action_type",))

    def test_blocked_actions_are_never_executable(self):
        for action in ("SCALE", "WIPE_DISK", "NOPE"):
            allowed, _ = self.e.execution_allowed(action, TARGETS)
            self.assertFalse(allowed, action)

    def test_unknown_threat_level_falls_back_to_medium(self):
        d = self.e.decide("ISOLATE", "apocalyptic", 0.9, TARGETS)
        self.assertEqual(d.threat_level, "medium")
        self.assertEqual(d.outcome, AWAITING_APPROVAL)

    def test_bad_confidence_is_coerced_not_trusted(self):
        for bad in (None, "", "high", float("nan")):
            d = self.e.decide("THROTTLE", "medium", bad, TARGETS)
            # 숫자로 읽히지 않으면 0.0 -> 임계값 미달 -> 자동 실행 불가
            self.assertEqual(d.outcome, AWAITING_APPROVAL, bad)

    def test_confidence_above_one_is_clamped(self):
        d = self.e.decide("THROTTLE", "medium", 99.0, TARGETS)
        self.assertEqual(d.confidence, 1.0)


class MalformedPolicyTest(unittest.TestCase):
    """잘못된 정책 파일은 안전하게 실패한다."""

    def _load(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "policy.yml")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            return PolicyEngine.from_file(path)

    def test_missing_file(self):
        with self.assertRaises(PolicyError):
            PolicyEngine.from_file("/definitely/not/here.yml")

    def test_invalid_yaml(self):
        with self.assertRaises(PolicyError):
            self._load("actions: [unclosed\n")

    def test_wrong_version(self):
        with self.assertRaises(PolicyError):
            self._load("version: 99\nactions: {}\n")

    def test_missing_required_action(self):
        text = (
            "version: 1\n"
            "threat_levels:\n"
            + "".join(f"  {t}:\n    urgency: x\n" for t in THREAT_LEVELS) +
            "actions:\n"
            "  NONE:\n"
            "    action_risk: low\n"
            "    performs_action: false\n"
            "    requires_approval: false\n"
            "    auto_execute: false\n"
            "    executor_ready: false\n"
            "    notify: alert_only\n"
        )
        with self.assertRaises(PolicyError) as ctx:
            self._load(text)
        self.assertIn("필수 조치 정책 누락", str(ctx.exception))

    def test_missing_threat_level(self):
        text = (
            "version: 1\n"
            "threat_levels:\n  low:\n    urgency: routine\n"
            "actions:\n  NONE:\n    action_risk: low\n    performs_action: false\n"
            "    requires_approval: false\n    auto_execute: false\n"
            "    executor_ready: false\n    notify: alert_only\n"
        )
        with self.assertRaises(PolicyError):
            self._load(text)

    def test_bad_risk_value(self):
        with self.assertRaises(PolicyError):
            parse_policy({"version": 1,
                          "threat_levels": {t: {"urgency": "x"} for t in THREAT_LEVELS},
                          "actions": {"NONE": {"action_risk": "catastrophic",
                                               "performs_action": False,
                                               "requires_approval": False,
                                               "auto_execute": False,
                                               "executor_ready": False,
                                               "notify": "alert_only"}}})

    def test_contradictory_action_definition(self):
        """auto_execute 와 requires_approval 을 동시에 참으로 둘 수 없다."""
        with self.assertRaises(PolicyError) as ctx:
            parse_policy({"version": 1,
                          "threat_levels": {t: {"urgency": "x"} for t in THREAT_LEVELS},
                          "actions": {"RESTART": {"action_risk": "high",
                                                  "performs_action": True,
                                                  "requires_approval": True,
                                                  "auto_execute": True,
                                                  "executor_ready": True,
                                                  "notify": "approval_request"}}})
        self.assertIn("동시에 참으로", str(ctx.exception))

    def test_recovery_without_ttl_is_rejected(self):
        with self.assertRaises(PolicyError):
            parse_policy({"version": 1,
                          "threat_levels": {t: {"urgency": "x"} for t in THREAT_LEVELS},
                          "actions": {"THROTTLE": {"action_risk": "medium",
                                                   "performs_action": True,
                                                   "requires_approval": False,
                                                   "auto_execute": True,
                                                   "executor_ready": False,
                                                   "notify": "post_action",
                                                   "recovery_required": True}}})

    def test_load_engine_degrades_to_block_all(self):
        """로드 실패 시 예외로 죽지 않고 '전부 차단' 엔진으로 내려간다."""
        e = load_engine("/definitely/not/here.yml")
        self.assertIsInstance(e, BlockAllPolicyEngine)
        d = e.decide("ISOLATE", "critical", 1.0, TARGETS, llm_action_risk="low")
        self.assertEqual(d.outcome, BLOCKED)
        self.assertEqual(d.action_risk, "high")
        self.assertFalse(d.executable_now)
        allowed, reason = e.execution_allowed("RESTART", TARGETS)
        self.assertFalse(allowed)
        self.assertTrue(reason.startswith("policy_unavailable:"))


class DecisionRecordTest(unittest.TestCase):
    def test_as_dict_carries_audit_fields(self):
        d = engine().decide("ISOLATE", "critical", 0.9, TARGETS, llm_action_risk="low")
        row = d.as_dict()
        for key in ("action_type", "action_risk", "threat_level", "urgency", "outcome",
                    "requires_approval", "executable_now", "reasons", "prerequisites",
                    "ttl_seconds", "llm_action_risk", "llm_action_risk_used"):
            self.assertIn(key, row)
        self.assertEqual(row["prerequisites"], ["network_connections"])

    def test_decision_is_immutable(self):
        d = engine().decide("ISOLATE", "high", 0.9, TARGETS)
        with self.assertRaises(Exception):
            d.action_risk = "low"


if __name__ == "__main__":
    unittest.main()
