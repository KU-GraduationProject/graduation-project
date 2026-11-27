"""
조치 대상 검증 (schemas/targets.py, prompt/builder_v2.py 대상 후보).

대상은 입력 증거에 실제로 나온 값만 허용한다. 근거가 없으면 NOTIFY 로 낮추고 사유를 남긴다.
로그에서 온 계정 값은 신뢰하지 않는다 — 형식에 맞지 않으면 후보로 쓰지 않고, LLM 이 내면 분석 무효다.

실행 (pipeline 디렉터리에서):
    python -m unittest discover -s tests -v
"""

import json
import os
import re
import sys
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from prompt.builder import make_builder  # noqa: E402
from schemas.llm_output import LLM_FIELDS, output_schema, parse_analysis  # noqa: E402

T0 = datetime(2026, 11, 20, 3, 0, 0, tzinfo=timezone.utc)
TARGETS = {"A1": ["leafy-backend"], "L1": ["account:s1c_test"]}
IDS = ["A1", "M1", "L1", "L2"]


def answer(**kw):
    base = {"root_cause": "x", "incident_class": "failure", "action_type": "RESTART",
            "action_targets": ["leafy-backend"], "target_evidence": ["A1"], "threat_level": "high",
            "evidence": ["A1", "M1"], "confidence": 0.9}
    base.update(kw)
    return base


def parse(obj, target_values=TARGETS):
    return parse_analysis(json.dumps(obj), evidence_ids=IDS, target_values=target_values)


class TargetValidationTest(unittest.TestCase):
    def test_observed_target_with_evidence_is_validated(self):
        r = parse(answer())
        self.assertEqual((r.action_type, r.action_targets, r.target_validation), ("RESTART", ["leafy-backend"], "validated"))
        self.assertIsNone(r.proposed_action)

    def test_account_seen_in_logs_is_validated(self):
        r = parse(answer(action_type="LOCK_ACCOUNT", action_targets=["account:s1c_test"], target_evidence=["L1"]))
        self.assertEqual((r.action_type, r.target_validation), ("LOCK_ACCOUNT", "validated"))

    def test_downgrades(self):
        cases = {
            "target_not_in_evidence": answer(action_targets=["leafy-minio"]),            # 허용 밖(관측 아님)
            "target_evidence_missing": answer(target_evidence=[]),
            "target_count": answer(action_targets=[]),
            "account_target_required": answer(action_type="LOCK_ACCOUNT"),
            "account_target_not_allowed": answer(action_targets=["account:s1c_test"], target_evidence=["L1"]),
        }
        for reason, obj in cases.items():
            r = parse(obj)
            self.assertEqual(r.analysis_status, "valid", reason)
            self.assertEqual(r.action_type, "NOTIFY", reason)
            self.assertEqual(r.action_targets, [], reason)
            self.assertEqual((r.target_validation, r.target_reason), ("downgraded", reason))
            self.assertEqual(r.proposed_action, obj["action_type"], reason)

    def test_hallucinated_account_is_downgraded(self):
        r = parse(answer(action_type="LOCK_ACCOUNT", action_targets=["account:admin"], target_evidence=["L1"]))
        self.assertEqual((r.action_type, r.target_reason), ("NOTIFY", "target_not_in_evidence"))
        # 대상이 나온 항목이 아닌 다른 증거만 인용해도 근거로 인정하지 않는다
        r = parse(answer(target_evidence=["M1"]))
        self.assertEqual(r.target_reason, "target_not_in_evidence")

    def test_injection_shaped_targets_are_invalid(self):
        for bad in ("account:../../etc", "account:a b", "account:x;DROP TABLE", "leafy-backend\nrm -rf",
                    "account:" + "a" * 200, "user:fixture", "account:"):
            r = parse(answer(action_type="LOCK_ACCOUNT", action_targets=[bad], target_evidence=["L1"]))
            self.assertEqual((r.analysis_status, r.action_type), ("invalid", "NOTIFY"), bad)
            self.assertIn("invalid_enum:action_targets", r.invalid_reasons, bad)

    def test_unknown_target_evidence_id_is_invalid(self):
        r = parse(answer(target_evidence=["L9"]))
        self.assertEqual(r.invalid_reasons, ["unknown_evidence:L9"])

    def test_no_target_actions_clear_targets(self):
        r = parse(answer(action_type="NOTIFY"))
        self.assertEqual((r.action_targets, r.target_evidence, r.target_validation), ([], [], "not_applicable"))

    def test_parse_failure_stays_analysis_failed_notify(self):
        r = parse_analysis("{broken", evidence_ids=IDS, target_values=TARGETS)
        self.assertEqual((r.analysis_status, r.action_type, r.target_validation), ("invalid", "NOTIFY", "not_applicable"))
        self.assertIn("분석 실패", r.root_cause)

    def test_target_evidence_is_required(self):
        self.assertIn("target_evidence", LLM_FIELDS)
        obj = answer()
        obj.pop("target_evidence")
        self.assertIn("missing_field:target_evidence", parse(obj).invalid_reasons)

    def test_schema_restricts_targets_to_candidates(self):
        s = output_schema(IDS, TARGETS)
        self.assertEqual(s["properties"]["action_targets"]["items"]["enum"], ["leafy-backend", "account:s1c_test"])
        self.assertEqual(s["properties"]["action_targets"]["maxItems"], 1)
        self.assertEqual(s["properties"]["target_evidence"]["items"]["enum"], IDS)
        self.assertEqual(output_schema(IDS, {})["properties"]["action_targets"]["maxItems"], 0)
        self.assertNotIn("action_risk", s["properties"])


def _log(ts, rec):
    return {"ts": ts, "labels": {"service": "backend", "log_format": "json"}, "line": json.dumps(rec)}


class TargetCandidatesTest(unittest.TestCase):
    def build(self, logs, container="leafy-backend"):
        alert = SimpleNamespace(labels=SimpleNamespace(alertname="LoginFailures", severity="warning"),
                                annotations={}, startsAt="2026-11-20T03:00:00Z")
        return make_builder("v2").build(alert, {}, logs, container, None, policy=None)

    def test_candidates_come_from_alert_target_and_visible_log_accounts(self):
        t = T0.timestamp()
        logs = [_log(t - i, {"level": "WARN", "message": "[AUTH] 로그인 실패 loginId=s1c_test reason=wrong_password"})
                for i in range(5)]
        logs.append(_log(t - 30, {"request_method": "POST", "request_uri": "/api/auth/login", "status": "401",
                                  "login_id": "other_user"}))
        p = self.build(logs)
        values = [v for vs in p["target_values"].values() for v in vs]
        self.assertEqual(p["target_values"]["A1"], ["leafy-backend"])
        self.assertIn("account:s1c_test", values)
        self.assertIn("account:other_user", values)
        self.assertIn("=== ACTION TARGETS", p["user"])
        for eid, vs in p["target_values"].items():
            line = next(l for l in p["user"].splitlines() if l.startswith(f"[{eid}]"))
            self.assertTrue(all(v.split(":", 1)[-1] in line for v in vs), eid)   # 값이 그 증거 줄에 보인다

    def test_untrusted_account_values_are_not_candidates(self):
        t = T0.timestamp()
        logs = [_log(t - 1, {"message": "로그인 실패 loginId=../../etc/passwd"}),
                _log(t - 2, {"message": "x", "user": "a b;rm"})]
        values = [v for vs in self.build(logs)["target_values"].values() for v in vs]
        self.assertEqual(values, ["leafy-backend"])

    def test_no_container_means_no_target_candidates(self):
        p = self.build([], container=None)
        self.assertEqual(p["target_values"], {})
        self.assertIn("none: action_targets must be []", p["user"])

    def test_host_note_uses_alert_target_not_fixed_name(self):
        from prompt.builder_v2 import HOST_NOTE
        self.assertNotIn("leafy-db", HOST_NOTE)
        self.assertIn("alert target", HOST_NOTE)

    def test_system_prompt_states_target_rule(self):
        p = self.build([])
        self.assertIn("Use only listed values; if no listed value fits, choose NOTIFY", p["system"])
        self.assertIn("target_evidence", p["system"])
        self.assertFalse(re.search(r"leafy-(minio|db)", p["system"]))


if __name__ == "__main__":
    unittest.main()
