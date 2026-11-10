"""
평가 하네스 흐름 검증 (aiops/eval/harness.py). Ollama 는 모의 함수로 대체한다.

tests/fixtures 의 픽스처는 가짜다 — 이 테스트의 수치는 흐름 확인용이며 지표 보고용이 아니다.

실행 (aiops 디렉터리에서):
    python -m unittest discover -s eval/tests -t . -v
"""

import json
import os
import tempfile
import unittest
from unittest import mock

from eval import harness
from v2 import registry

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def answer(**kw):
    base = {"root_cause": "x", "incident_class": "attack", "action_type": "NOTIFY", "action_targets": [],
            "threat_level": "medium", "evidence": ["A1", "L1"], "confidence": 0.8}
    base.update(kw)
    return json.dumps(base)


def fake_chat(body):
    """프롬프트에 찍힌 경보 시각(startsAt, legacy·v2 모두 표기)으로 픽스처를 구분해 정해진 답을 낸다."""
    user, seed = body["messages"][1]["content"], body["options"]["seed"]
    meta = {"prompt_eval_count": len(user) // 3, "eval_count": 60, "total_duration": 2_000_000_000,
            "done_reason": "stop"}
    if "T05:10:00Z" in user:        # 인증 공격형 → 정답
        content = answer()
    elif "T06:00:00Z" in user:      # 대조 → 과잉대응(RESTART), class 오답
        content = answer(incident_class="failure", action_type="RESTART",
                         action_targets=["leafy-frontend"], evidence=["A1"], confidence=0.6)
    elif "T08:00:00Z" in user:      # 평가 분할 → 없는 증거 ID
        content = answer(evidence=["L99"])
    elif seed % 2:                  # 장애형, 홀수 seed → 출력 잘림
        return dict(meta, message={"content": '{"root_cause": "S3 fail'}, done_reason="length")
    else:                           # 장애형, 짝수 seed → 정답
        content = answer(incident_class="failure", action_type="RESTART", action_targets=["leafy-minio"],
                         evidence=["A1"], confidence=0.9)
    return dict(meta, message={"content": content})


class SplitTest(unittest.TestCase):
    def test_eval_split_excluded_by_default(self):
        fixtures = harness.load_fixtures(FIXTURES)
        self.assertEqual(len(fixtures), 4)
        self.assertEqual({f["_split"] for f in fixtures}, {"tuning", "eval"})
        self.assertEqual(len(harness.select(fixtures)), 3)
        self.assertEqual(len(harness.select(fixtures, include_eval=True)), 4)
        self.assertEqual(harness.split_of("s1_c_login_bruteforce", "single-account"), "tuning")
        self.assertEqual(harness.split_of("s1_c_login_bruteforce", None), "tuning")
        self.assertEqual(harness.split_of("s1_c_login_bruteforce", "not-public"), "eval")


class NoLeakTest(unittest.TestCase):
    """프롬프트에 시나리오 이름·레이블·변형 id·정답이 들어가지 않는다 (legacy·v2 모두)."""

    def test_prompts_carry_no_scenario_metadata_or_answers(self):
        ideal = {r["expected_action_ideal"] for r in registry.SCENARIO_REGISTRY_V2} - set(registry.POLICY_ACTIONS)
        for fx in harness.load_fixtures(FIXTURES):
            row = harness._row(fx["scenario_id"])
            for builder in harness.BUILDERS:
                p = harness.make_builder(builder).build(**harness.build_inputs(fx))
                text = p["system"] + "\n" + p["user"]
                for needle in [fx["scenario_id"], row["label"], fx["variant_id"], "expected_action",
                               "ground_truth", "heldout", *ideal]:
                    self.assertNotIn(needle, text, (fx["_file"], builder, needle))
                self.assertEqual(harness.prompt_leaks(p, fx), [])

    def test_build_inputs_has_no_fixture_metadata(self):
        fx = harness.load_fixtures(FIXTURES)[0]
        dumped = json.dumps(harness.build_inputs(fx), default=lambda o: getattr(o, "__dict__", str(o)))
        for key in ("scenario_id", "variant_id", fx["scenario_id"], fx["variant_id"], "_note"):
            self.assertNotIn(key, dumped)

    def test_leak_detector_catches_leak(self):
        fx = harness.load_fixtures(FIXTURES)[0]
        p = {"system": "s", "user": f"scenario {fx['scenario_id']}"}
        self.assertEqual(harness.prompt_leaks(p, fx), [fx["scenario_id"]])


class RunTest(unittest.TestCase):
    def setUp(self):
        self.fixtures = harness.select(harness.load_fixtures(FIXTURES))
        self.records, self.summary = harness.run(self.fixtures, builders=("legacy", "v2"), reps=3,
                                                 seed_base=1000, chat=fake_chat)

    def test_runs_and_seeds(self):
        self.assertEqual(len(self.records), 3 * 2 * 3)
        for r in self.records:
            self.assertEqual(r["seed"], 1000 + r["rep"])
            self.assertEqual(r["options"]["seed"], r["seed"])
            self.assertEqual(r["options"]["num_ctx"], 4096)
            self.assertEqual(r["options"]["num_predict"], 400)
            self.assertEqual(r["options"]["temperature"], 0.3)
            self.assertEqual("prompt" in r, r["rep"] == 0)

    def test_v2_metrics(self):
        s = self.summary["v2"]
        self.assertEqual(s["runs"], 9)
        self.assertEqual(s["action_accuracy"], round(5 / 9, 4))        # login 3 + minio 2
        self.assertEqual(s["threat_accuracy"], round(5 / 9, 4))         # login medium 3, minio medium 2
        self.assertEqual(s["incident_class_accuracy"], round(5 / 9, 4))
        self.assertEqual(s["evidence_cited_rate"], round(8 / 9, 4))
        self.assertEqual(s["control_over_response_rate"], 1.0)
        self.assertEqual(s["incident_under_response_rate"], 0.0)
        self.assertEqual(s["invalid_rate"], round(1 / 9, 4))
        self.assertEqual(s["invalid_by_reason"], {"parse_error": round(1 / 9, 4), "truncated": round(1 / 9, 4)})
        self.assertEqual(s["prompt_leak_runs"], 0)
        self.assertEqual(s["confidence_when_action_correct"]["n"], 5)
        self.assertEqual(s["confidence_when_action_wrong"]["mean"], 0.6)
        self.assertIsNotNone(s["prompt_tokens"])
        self.assertIsNotNone(s["latency_s"])

    def test_legacy_has_no_evidence_ids(self):
        self.assertIsNone(self.summary["legacy"]["evidence_cited_rate"])
        legacy = [r for r in self.records if r["builder"] == "legacy" and r["valid"]]
        self.assertTrue(legacy)

    def test_outputs_written(self):
        with tempfile.TemporaryDirectory() as d:
            harness.write_outputs(self.records, self.summary, d)
            with open(os.path.join(d, "runs.jsonl"), encoding="utf-8") as fh:
                rows = [json.loads(line) for line in fh]
            self.assertEqual(len(rows), 18)
            with open(os.path.join(d, "summary.md"), encoding="utf-8") as fh:
                table = fh.read()
            self.assertIn("| 지표 | legacy | v2 |", table)
            self.assertIn("evidence 인용 비율", table)
            self.assertIn("invalid: truncated", table)

    def test_unknown_evidence_counted_when_eval_included(self):
        fixtures = harness.select(harness.load_fixtures(FIXTURES), include_eval=True)
        _, summary = harness.run(fixtures, builders=("v2",), reps=1, chat=fake_chat)
        self.assertIn("unknown_evidence", summary["v2"]["invalid_by_reason"])
        self.assertEqual(summary["v2"]["splits"], {"tuning": 3, "eval": 1})

    def test_call_failure_is_recorded_invalid(self):
        def down(body):
            raise ConnectionError("ollama down")
        recs, s = harness.run(self.fixtures[:1], reps=1, chat=down)
        self.assertEqual(recs[0]["result"]["invalid_reasons"], ["llm_call_failed"])
        self.assertIn("ConnectionError", recs[0]["call_error"])

    def test_cli(self):
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(harness, "ollama_chat", return_value=fake_chat), \
             mock.patch("builtins.print"):
            code = harness.main(["--fixtures", FIXTURES, "--reps", "1", "--builder", "both", "--out", d])
            self.assertEqual(code, 0)
            self.assertTrue(os.path.exists(os.path.join(d, "summary.json")))


class LegacyEvalRegressionTest(unittest.TestCase):
    """1학기 eval(8케이스)은 회귀용으로 그대로 import·구성된다."""

    def test_legacy_eval_still_loads(self):
        from eval import run_eval, test_cases
        self.assertEqual(len(test_cases.TEST_CASES), 8)
        self.assertTrue(run_eval.SYSTEM_PROMPT_FEWSHOT)


if __name__ == "__main__":
    unittest.main()
