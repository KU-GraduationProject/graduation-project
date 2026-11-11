"""
LLM 출력 엄격 검증 (schemas/llm_output.py).

잘리거나 깨진 응답이 기본값으로 메워져 정상 판단처럼 처리되지 않는지 확인한다.

실행 (pipeline 디렉터리에서):
    python -m unittest discover -s tests -v
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from schemas.llm_output import LLM_FIELDS, output_schema, parse_analysis  # noqa: E402

GOOD = {"root_cause": "4xx burst from one source.", "incident_class": "attack",
        "action_type": "NOTIFY", "action_targets": [], "threat_level": "medium",
        "evidence": ["A1", "L1"], "confidence": 0.7}
IDS = ["A1", "M1", "L1", "L2"]


def parse(obj, **kw):
    kw.setdefault("evidence_ids", IDS)
    return parse_analysis(json.dumps(obj) if not isinstance(obj, str) else obj, **kw)


class StrictParseTest(unittest.TestCase):
    def test_valid(self):
        r = parse(GOOD)
        self.assertEqual(r.analysis_status, "valid")
        self.assertEqual(r.invalid_reasons, [])
        self.assertEqual(r.evidence, ["A1", "L1"])

    def test_every_field_is_required(self):
        for field in LLM_FIELDS:
            obj = {k: v for k, v in GOOD.items() if k != field}
            r = parse(obj)
            self.assertEqual(r.analysis_status, "invalid", field)
            self.assertIn(f"missing_field:{field}", r.invalid_reasons)

    def test_invalid_result_goes_to_notify_not_none(self):
        r = parse("{not json")
        self.assertEqual(r.analysis_status, "invalid")
        self.assertEqual(r.invalid_reasons, ["parse_error"])
        self.assertEqual(r.action_type, "NOTIFY")
        self.assertEqual(r.action_targets, [])
        self.assertIn("분석 실패", r.root_cause)
        self.assertIsNone(r.incident_class)

    def test_invalid_enums(self):
        for field, bad in (("action_type", "SCALE"), ("threat_level", "severe"),
                           ("incident_class", "unknown")):
            r = parse(dict(GOOD, **{field: bad}))
            self.assertIn(f"invalid_enum:{field}", r.invalid_reasons, field)
        r = parse(dict(GOOD, action_type="RESTART", action_targets=["aiops-pipeline"]))
        self.assertIn("invalid_enum:action_targets", r.invalid_reasons)

    def test_unknown_evidence_id(self):
        r = parse(dict(GOOD, evidence=["L1", "L9"]))
        self.assertEqual(r.invalid_reasons, ["unknown_evidence:L9"])

    def test_legacy_prompt_skips_evidence_id_check(self):
        r = parse(dict(GOOD, evidence=["cpu_usage: latest=0.9"]), evidence_ids=None)
        self.assertEqual(r.analysis_status, "valid")

    def test_truncated_by_done_reason_or_context(self):
        self.assertIn("truncated", parse(GOOD, done_reason="length").invalid_reasons)
        r = parse(GOOD, prompt_eval_count=3800, num_ctx=4096, num_predict=400)
        self.assertEqual(r.invalid_reasons, ["truncated"])
        self.assertEqual(parse(GOOD, prompt_eval_count=3500).analysis_status, "valid")

    def test_confidence_not_coerced(self):
        for bad in ("high", None, True):
            r = parse(dict(GOOD, confidence=bad))
            self.assertEqual(r.analysis_status, "invalid", bad)
        self.assertIn("invalid_type:confidence", parse(dict(GOOD, confidence="0.9")).invalid_reasons)

    def test_root_cause_length_limit(self):
        self.assertEqual(parse(dict(GOOD, root_cause="x" * 401)).analysis_status, "invalid")

    def test_targets_cleared_for_no_target_actions(self):
        r = parse(dict(GOOD, action_type="NONE", action_targets=["leafy-backend"]))
        self.assertEqual(r.analysis_status, "valid")
        self.assertEqual(r.action_targets, [])

    def test_llm_cannot_set_status(self):
        r = parse(dict(GOOD, evidence=["L9"], analysis_status="valid", invalid_reasons=[]))
        self.assertEqual(r.analysis_status, "invalid")

    def test_removed_field_is_not_in_output(self):
        r = parse(dict(GOOD, action_description="restart it"))
        self.assertNotIn("action_description", r.model_dump())

    def test_schema_restricts_evidence_to_prompt_ids(self):
        s = output_schema(IDS)
        self.assertEqual(s["properties"]["evidence"]["items"]["enum"], IDS)
        self.assertEqual(sorted(s["required"]), sorted(LLM_FIELDS))
        self.assertFalse(s["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
