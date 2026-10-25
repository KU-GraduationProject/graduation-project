"""
TransferSpec / RunSpec 테스트 (E2 불변식).

실행: cd scenarios/network && python -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from transfer_spec import (  # noqa: E402
    DEV_VARIANTS,
    Destination,
    MODE_SLOW,
    MODE_SPLIT,
    TransferSpec,
    build_pair,
    transfer_fields_equal,
)

SINK_A = Destination(name="sink-a", ip="10.210.0.30", port=8080)
SINK_B = Destination(name="sink-b", ip="10.210.0.31", port=8080)


class TransferSpecTest(unittest.TestCase):
    def test_s2_ca_differ_only_in_destination(self):
        for variant in ("V1", "V2", "dev-slow"):
            pair = build_pair(variant, SINK_A, SINK_B)
            s2, ca = pair["S2"], pair["C-a"]
            # 전송 조건은 완전히 같다 (E2)
            self.assertTrue(transfer_fields_equal(s2, ca))
            self.assertIs(s2.transfer, ca.transfer)
            # 목적지만 다르다
            self.assertEqual(s2.destination, SINK_B)
            self.assertEqual(ca.destination, SINK_A)
            self.assertNotEqual(s2.destination, ca.destination)

    def test_ground_truth_labels(self):
        pair = build_pair("V1", SINK_A, SINK_B)
        self.assertTrue(pair["S2"].should_alert)      # 비인가 → 경보 기대 (TP)
        self.assertFalse(pair["C-a"].should_alert)     # 인가 → 무경보 기대 (TN)

    def test_dev_variants_shape(self):
        self.assertEqual(DEV_VARIANTS["V1"].mode, MODE_SPLIT)
        self.assertGreaterEqual(DEV_VARIANTS["V1"].chunks, 2)
        self.assertEqual(DEV_VARIANTS["V2"].mode, MODE_SLOW)
        self.assertTrue(DEV_VARIANTS["V2"].rate_bps)

    def test_spec_validation(self):
        with self.assertRaises(ValueError):
            TransferSpec(mode="split", chunks=1)      # split 은 chunks>=2
        with self.assertRaises(ValueError):
            TransferSpec(mode="slow", rate_bps=None)  # slow 는 rate 필요
        with self.assertRaises(ValueError):
            TransferSpec(mode="bogus")
        with self.assertRaises(ValueError):
            TransferSpec(target_bytes=0)


if __name__ == "__main__":
    unittest.main()
