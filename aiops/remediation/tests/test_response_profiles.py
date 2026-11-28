"""Aggregate signals cannot invent remediation targets or bypass approval."""
from copy import deepcopy
import json
import os
import unittest
from unittest.mock import patch

import response_profiles as responses
from tests.test_policy_integration import PolicyEndpointBase, IDENTITY


def alert(name="V2RepeatedExternalConnections", identity=None):
    return {"labels": {"alertname": name, **(identity or IDENTITY)},
            "fingerprint": "fixture-v2", "startsAt": "2026-11-28T00:00:00Z"}


def analysis(action="ISOLATE", target="leafy-backend"):
    return {"action_type": action, "action_targets": [target], "action_parameters": {},
            "root_cause": "Verified unexplained repeated connections", "evidence": ["network evidence 1"],
            "confidence": .95, "threat_level": "high", "analysis_status": "valid"}


def proposal(name="V2RepeatedExternalConnections", action="ISOLATE", identity=None):
    a = alert(name, identity)
    result = analysis(action, a["labels"]["target"])
    ident = {k: a["labels"][k] for k in ("site", "source", "service", "runtime", "target")}
    return {"operation": "propose_rca_action", "alert": a, "analysis": result,
            "plan": {"version": 1, "action_type": action, "targets": result["action_targets"],
                     "parameters": {}, "identity": ident,
                     "incident": {"fingerprint": a["fingerprint"], "starts_at": a["startsAt"]}}}


class ResponseProfileTests(unittest.TestCase):
    def test_unknown_alert_keeps_existing_behavior(self):
        responses.validate_response(alert("HighCpuUsage"), analysis("THROTTLE"))
        self.assertIsNone(responses.profile_for(alert("HighCpuUsage")))

    def test_supported_response_does_not_mutate_or_synthesize_evidence(self):
        a, result = alert(), analysis()
        before = deepcopy((a, result))
        responses.validate_response(a, result)
        self.assertEqual((a, result), before)

    def test_db_reads_and_aggregate_accounts_stay_notification_only(self):
        db = {**IDENTITY, "service": "db", "runtime": "host", "target": "fixture-pg"}
        for name, identity, action in (("V2DBReadSurge", db, "KILL_SESSIONS"),
                                       ("V2DBReadSurge", db, "ISOLATE"),
                                       ("V2LoginBruteForce", IDENTITY, "LOCK_ACCOUNT")):
            with self.subTest(name=name, action=action), self.assertRaises(ValueError):
                responses.validate_response(alert(name, identity), analysis(action, identity["target"]))
            for safe in ("NONE", "NOTIFY"):
                responses.validate_response(alert(name, identity), analysis(safe, identity["target"]))

    def test_cross_service_runtime_target_and_missing_fingerprint_refused(self):
        for changes in ({"service": "db"}, {"runtime": "host"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                responses.validate_response(alert(identity={**IDENTITY, **changes}), analysis())
        with self.assertRaises(ValueError): responses.validate_response(alert(), analysis(target="other"))
        a = alert(); a.pop("fingerprint")
        with self.assertRaises(ValueError): responses.validate_response(a, analysis())

    def test_catalog_uses_only_existing_forward_actions_and_no_ground_truth(self):
        import plans
        for p in responses.PROFILES.values():
            self.assertLessEqual(set(p.actions), plans.FORWARD_ACTIONS)
        serialized = json.dumps(responses.capabilities())
        for field in ("scenario_id", "incident_class"):
            self.assertNotIn(field, serialized)


class ResponseEndpointTests(PolicyEndpointBase):
    def test_unsigned_new_signal_cannot_reach_planning(self):
        r = self.client.post("/action", json=proposal())
        self.assertEqual(r.status_code, 401)
        self.assertEqual(self.docker_calls(), 0)

    def test_legacy_new_signal_mutation_requires_strict_plan(self):
        body = {"alert": alert(), "analysis": analysis()}
        r = self.post_action(json.dumps(body).encode())
        self.assertEqual(r.status_code, 422)
        self.assertIn("incident_bound_plan", r.text)
        self.assertEqual(self.docker_calls(), 0)

    def test_valid_new_signal_proposal_waits_for_approval_even_auto_enabled(self):
        with patch.dict(os.environ, {"REMEDIATION_AUTO_EXECUTE_ENABLED": "true"}):
            r = self.post_action(json.dumps(proposal()).encode())
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["status"], "pending_approval")
        self.assertEqual(self.docker_calls(), 0)
        record = self.main.record_store.get(r.json()["remediation_id"])
        self.assertTrue(record.requires_approval)
        self.assertEqual(record.identity, IDENTITY)

    def test_db_read_surge_cannot_isolate_backend_or_terminate_sessions(self):
        db = {**IDENTITY, "service": "db", "runtime": "host", "target": "fixture-pg"}
        for action in ("ISOLATE", "KILL_SESSIONS", "RESTART"):
            r = self.post_action(json.dumps(proposal("V2DBReadSurge", action, db)).encode())
            self.assertEqual(r.status_code, 422, r.text)
            self.assertIn("requires_notification", r.text)
        self.assertEqual(self.docker_calls(), 0)

    def test_normal_backup_can_be_notified_without_record(self):
        db = {**IDENTITY, "service": "db", "runtime": "host", "target": "fixture-pg"}
        for action in ("NONE", "NOTIFY"):
            body = {"alert": alert("V2DBReadSurge", db), "analysis": analysis(action, db["target"])}
            r = self.post_action(json.dumps(body).encode())
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(r.json()["status"], "notified")
            self.assertNotIn("remediation_id", r.json())
        self.assertEqual(self.docker_calls(), 0)

    def test_multistep_plan_cannot_smuggle_unrelated_action(self):
        p = proposal()
        first = {"analysis": p["analysis"], "plan": p["plan"]}
        second = deepcopy(first)
        second["analysis"]["action_type"] = "RESTART"
        second["plan"]["action_type"] = "RESTART"
        body = {"operation": "propose_plan", "force_manual": True, "alert": p["alert"], "plan_steps": [first, second]}
        r = self.post_action(json.dumps(body).encode())
        self.assertEqual(r.status_code, 422, r.text)
        self.assertIn("requires_notification", r.text)
        self.assertEqual(self.docker_calls(), 0)


if __name__ == "__main__": unittest.main()
