"""
판정·집계 테스트 (E3) — TP/FP/TN/FN 분류, Confusion Matrix, 지표, 유효성.

실행: cd scenarios/network && python -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from evaluation import ConfusionMatrix, RunOutcome, classify  # noqa: E402


def outcome(scenario, should_alert, detected, valid=True, mttd=None):
    return RunOutcome(label=f"{scenario}-V", scenario=scenario, variant="V",
                      should_alert=should_alert, detected=detected, valid=valid,
                      mttd_seconds=mttd)


class ClassifyTest(unittest.TestCase):
    def test_four_cells(self):
        self.assertEqual(classify(True, True), "TP")
        self.assertEqual(classify(True, False), "FN")
        self.assertEqual(classify(False, True), "FP")
        self.assertEqual(classify(False, False), "TN")

    def test_invalid_outcome_none(self):
        self.assertIsNone(outcome("S2", True, True, valid=False).outcome)
        self.assertEqual(outcome("S2", True, True, valid=True).outcome, "TP")


class ConfusionMatrixTest(unittest.TestCase):
    def test_success_condition_perfect(self):
        # S2 전부 탐지(TP), C-a 전부 무오탐(TN) => recall=1, specificity=1, FPR=0
        outs = ([outcome("S2", True, True, mttd=5.0) for _ in range(3)] +
                [outcome("C-a", False, False) for _ in range(5)])
        m = ConfusionMatrix.from_outcomes(outs)
        self.assertEqual((m.tp, m.fp, m.tn, m.fn), (3, 0, 5, 0))
        self.assertEqual(m.recall, 1.0)
        self.assertEqual(m.specificity, 1.0)
        self.assertEqual(m.false_positive_rate, 0.0)
        self.assertEqual(m.precision, 1.0)
        self.assertEqual(m.f1, 1.0)

    def test_mixed_metrics(self):
        outs = [
            outcome("S2", True, True, mttd=4.0),   # TP
            outcome("S2", True, False),            # FN (미탐)
            outcome("C-a", False, True),           # FP (오탐)
            outcome("C-a", False, False),          # TN
        ]
        m = ConfusionMatrix.from_outcomes(outs)
        self.assertEqual((m.tp, m.fp, m.tn, m.fn), (1, 1, 1, 1))
        self.assertEqual(m.precision, 0.5)
        self.assertEqual(m.recall, 0.5)
        self.assertEqual(m.specificity, 0.5)
        self.assertEqual(m.accuracy, 0.5)

    def test_invalid_excluded(self):
        outs = [outcome("S2", True, True, valid=False), outcome("C-a", False, False)]
        m = ConfusionMatrix.from_outcomes(outs)
        self.assertEqual(m.invalid, 1)
        self.assertEqual(m.total_valid, 1)
        self.assertEqual(m.tn, 1)

    def test_mttd_stats_only_tp(self):
        outs = [outcome("S2", True, True, mttd=4.0), outcome("S2", True, True, mttd=8.0),
                outcome("C-a", False, True, mttd=1.0)]  # FP MTTD는 포함 안 함
        m = ConfusionMatrix.from_outcomes(outs)
        stats = m.mttd_stats()
        self.assertEqual(stats["count"], 2)
        self.assertEqual(stats["min"], 4.0)
        self.assertEqual(stats["max"], 8.0)
        self.assertEqual(stats["mean"], 6.0)

    def test_zero_division_guarded(self):
        m = ConfusionMatrix()
        self.assertIsNone(m.precision)
        self.assertIsNone(m.recall)
        self.assertIsNone(m.accuracy)


if __name__ == "__main__":
    unittest.main()
