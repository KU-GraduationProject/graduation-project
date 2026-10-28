"""
실험 러너 테스트 (Step 5/6) — 계획 수립, 판정 매핑, 결과 저장, V2 held-out 보호.

Docker 가 필요한 실제 실행(run_experiment 의 전송·검증 루프)은 테스트하지 않는다.
동결 보호 분기는 Docker 호출 이전에 raise 하므로 Docker 없이 검증 가능하다.

실행: cd scenarios/network && python -m unittest discover -s tests -v
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import experiment  # noqa: E402
from evaluation import ConfusionMatrix  # noqa: E402
from experiment import build_plan, evaluate_run, run_experiment, write_results  # noqa: E402
from freeze import FrozenConfig  # noqa: E402


class PlanTest(unittest.TestCase):
    def test_interleaved_counts(self):
        plan = build_plan("V2", s2_reps=2, ca_reps=3)
        self.assertEqual(len(plan), 5)
        self.assertEqual(sum(1 for r in plan if r.scenario == "S2"), 2)
        self.assertEqual(sum(1 for r in plan if r.scenario == "C-a"), 3)
        # 앞쪽은 번갈아 배치 (시간 편향 감소)
        self.assertEqual([r.scenario for r in plan[:2]], ["S2", "C-a"])

    def test_s2_ca_share_transfer(self):
        # E2: 같은 variant 의 S2/C-a 는 동일 TransferSpec 을 쓰고 목적지만 다르다
        plan = build_plan("V1", s2_reps=1, ca_reps=1)
        s2 = next(r for r in plan if r.scenario == "S2")
        ca = next(r for r in plan if r.scenario == "C-a")
        self.assertEqual(s2.transfer, ca.transfer)
        self.assertNotEqual(s2.destination, ca.destination)
        self.assertTrue(s2.should_alert)
        self.assertFalse(ca.should_alert)

    def test_default_v2_reps(self):
        self.assertEqual(experiment.DEFAULT_V2_REPS["S2"], 30)
        self.assertTrue(50 <= experiment.DEFAULT_V2_REPS["C-a"] <= 100)


class EvaluateRunTest(unittest.TestCase):
    def test_mapping(self):
        plan = build_plan("V1", 1, 1)
        s2 = next(r for r in plan if r.scenario == "S2")
        ca = next(r for r in plan if r.scenario == "C-a")
        self.assertEqual(evaluate_run(s2, True, True, 4.0).outcome, "TP")
        self.assertEqual(evaluate_run(s2, True, False, None).outcome, "FN")
        self.assertEqual(evaluate_run(ca, True, True, 1.0).outcome, "FP")
        self.assertEqual(evaluate_run(ca, True, False, None).outcome, "TN")
        # 전송 교차검증 실패 -> 무효(판정 제외)
        self.assertIsNone(evaluate_run(s2, False, True, 1.0).outcome)


class WriteResultsTest(unittest.TestCase):
    def test_files_written(self):
        plan = build_plan("V1", 1, 1)
        outs = [evaluate_run(plan[0], True, True, 5.0),
                evaluate_run(plan[1], True, False, None)]
        m = ConfusionMatrix.from_outcomes(outs)
        with tempfile.TemporaryDirectory() as d:
            paths = write_results(outs, m, d, "S2CA-V1")
            for key in ("runs_jsonl", "runs_csv", "summary_json"):
                self.assertTrue(os.path.exists(paths[key]))
            with open(paths["summary_json"], encoding="utf-8") as fh:
                summary = json.load(fh)
            self.assertIn("confusion_matrix", summary)
            self.assertEqual(summary["confusion_matrix"]["total_valid"], 2)


class V2HeldOutGuardTest(unittest.TestCase):
    def test_v2_requires_frozen(self):
        plan = build_plan("V2", 1, 1)
        cfg = experiment.ExperimentConfig(db_password="x", verifier=object())
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(RuntimeError):
                run_experiment(plan, cfg, d, "S2CA-V2", frozen=None, require_frozen=True)

    def test_v2_refuses_on_drift(self):
        # 동결 해시가 현재 repo 파일과 다르면(존재하지 않는 가짜 해시) drift -> 거부
        frozen = FrozenConfig(created_at="t", git_sha=None, params={},
                              file_hashes={"aiops/policy/allowlist.yml": "deadbeef"})
        plan = build_plan("V2", 1, 1)
        cfg = experiment.ExperimentConfig(db_password="x", verifier=object())
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(RuntimeError):
                run_experiment(plan, cfg, d, "S2CA-V2", frozen=frozen, require_frozen=True)


if __name__ == "__main__":
    unittest.main()
