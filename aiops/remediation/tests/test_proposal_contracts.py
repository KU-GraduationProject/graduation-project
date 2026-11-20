"""Verify proposed actions remain recommendations until executors are implemented."""
from dataclasses import replace
from pathlib import Path
import runpy
import unittest
from unittest.mock import Mock

import yaml
from executor.router import route_action
from policy.catalog import ACTION_FAMILIES, DOCKER_ACTIONS, SCENARIO_RECOMMENDATIONS
from policy.engine import PolicyEngine, REPO_POLICY_PATH
from policy.schema import BLOCKED, AWAITING_APPROVAL, PolicyError, parse_policy


class ProposalContractTests(unittest.TestCase):
    def setUp(self):
        self.engine = PolicyEngine.from_file(REPO_POLICY_PATH)

    def test_recommendation_vocabularies_match_across_separate_images(self):
        actions = Path(__file__).resolve().parents[2] / "pipeline/schemas/actions.py"
        pipeline_names = runpy.run_path(str(actions))["RECOMMENDED_ACTIONS"]
        self.assertEqual(set(pipeline_names), set(ACTION_FAMILIES))

    def test_all_proposals_have_policy_risk_and_cannot_execute_at_any_severity(self):
        self.assertEqual(len(self.engine.config.proposed_actions), 16)
        for name, proposal in self.engine.config.proposed_actions.items():
            for severity in ("low", "medium", "high", "critical"):
                with self.subTest(action=name, severity=severity):
                    decision = self.engine.decide(name, severity, 1.0, ["leafy-backend"], "low")
                    self.assertEqual(decision.outcome, BLOCKED)
                    self.assertEqual(decision.action_risk, proposal["action_risk"])
                    self.assertFalse(decision.executable_now)
                    self.assertFalse(self.engine.execution_allowed(name, ["leafy-backend"])[0])

    def test_proposal_readiness_cannot_be_enabled_by_configuration(self):
        with open(REPO_POLICY_PATH, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        raw["proposed_actions"]["BACKUP_DB"]["executor_ready"] = True
        with self.assertRaises(PolicyError):
            parse_policy(raw)

    def test_high_risk_policy_cannot_remove_approval(self):
        with open(REPO_POLICY_PATH, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
        raw["actions"]["RESTART"]["requires_approval"] = False
        raw["actions"]["RESTART"]["auto_execute"] = True
        with self.assertRaises(PolicyError):
            parse_policy(raw)

    def test_underresponse_mutation_blocked_but_notify_remains_valid(self):
        actions = dict(self.engine.config.actions)
        actions["THROTTLE"] = replace(actions["THROTTLE"], action_risk="low")
        engine = PolicyEngine(replace(self.engine.config, actions=actions))
        for severity in ("high", "critical"):
            decision = engine.decide("THROTTLE", severity, 1.0, ["leafy-backend"])
            self.assertEqual(decision.blocked_reason, "risk_threat_underresponse_review")
            self.assertFalse(decision.executable_now)
            self.assertEqual(engine.decide("NOTIFY", severity, 1.0).outcome, "NOTIFY")

    def test_overresponse_still_requires_review_and_approval(self):
        decision = self.engine.decide("RESTART", "low", 1.0, ["leafy-backend"])
        self.assertEqual(decision.outcome, AWAITING_APPROVAL)
        self.assertIn("risk_threat_overresponse_review_requires_approval", decision.reasons)

    def test_router_cannot_route_other_families_to_docker_or_host(self):
        executor = Mock(name="executor")
        executor.name = "local_docker"
        for action in set(ACTION_FAMILIES) - DOCKER_ACTIONS:
            for runtime in ("container", "host"):
                self.assertFalse(route_action(action, runtime, executor)[0], (action, runtime))
        for runtime in (None, "", "host", "docker"):
            self.assertFalse(route_action("RESTART", runtime, executor)[0])
        executor.execute.assert_not_called()

    def test_supported_docker_route_and_disabled_semantics(self):
        for name in ("local_docker", "remote", "disabled"):
            executor = Mock()
            executor.name = name
            executor.changes_system = name != "disabled"
            self.assertTrue(route_action("RESTART", "container", executor)[0])
        self.assertFalse(route_action("RESTART", "container", Mock(name="db"))[0])

    def test_scenarios_are_candidates_and_db_operations_stay_distinct(self):
        self.assertEqual(SCENARIO_RECOMMENDATIONS["F2-c"], ("KILL_SESSIONS",))
        for candidates in SCENARIO_RECOMMENDATIONS.values():
            self.assertTrue(set(candidates) <= set(ACTION_FAMILIES))
        db = self.engine.config.actions["KILL_SESSIONS"]
        self.assertEqual(db.operations, ("terminate_idle_sessions", "cancel_long_queries"))
        self.assertTrue(db.requires_approval)
        self.assertFalse(db.auto_execute)
