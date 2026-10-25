"""
전송 파일 생성기 테스트 (P1 순수 로직).

실행 (scenarios/network 디렉터리에서):
    python -m unittest discover -s tests -v

검증 항목 (사용자 계획 §9의 4,5):
  - 목표 크기 정확히 일치
  - SHA-256 재현성 (같은 입력 -> 같은 해시 => S2/C-a 동일 payload 보장)
  - 원본/합성 바이트 분리 집계 + 합성 마커 존재
"""

import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from payload import (  # noqa: E402
    SYNTHETIC_MARKER,
    TransferPayload,
    build_transfer_payload,
)

HEADER = b"id,email,password_hash\n"
ROWS = b"".join(f"{i},user{i}@example.test,hash{i}\n".encode() for i in range(500))
CSV = HEADER + ROWS


class PayloadTest(unittest.TestCase):
    def test_exact_target_size(self):
        for target in (1024, 1024 * 1024, 5 * 1024 * 1024, 10 * 1024 * 1024):
            p = build_transfer_payload(CSV, target_bytes=target)
            self.assertEqual(len(p.data), target)
            self.assertEqual(p.total_bytes, target)

    def test_deterministic_hash(self):
        # 같은 입력이면 항상 같은 해시 — S2와 C-a에 동일 payload를 보낼 수 있어야 한다.
        p1 = build_transfer_payload(CSV, target_bytes=5 * 1024 * 1024)
        p2 = build_transfer_payload(CSV, target_bytes=5 * 1024 * 1024)
        self.assertEqual(p1.sha256, p2.sha256)
        self.assertEqual(p1.sha256, hashlib.sha256(p1.data).hexdigest())

    def test_original_and_synthetic_split(self):
        target = 2 * 1024 * 1024
        p = build_transfer_payload(CSV, target_bytes=target)
        self.assertEqual(p.original_bytes, len(CSV))
        self.assertEqual(p.synthetic_bytes, target - len(CSV))
        self.assertEqual(p.original_bytes + p.synthetic_bytes, target)
        # 원본 전체가 payload 앞부분에 그대로 들어간다
        self.assertTrue(p.data.startswith(CSV))
        # 합성 구간은 본문 안에서도 마커로 구분된다 ("전체가 원본"이라는 주장 방지)
        self.assertIn(SYNTHETIC_MARKER, p.data)
        self.assertGreater(p.summary["synthetic_ratio"], 0)

    def test_target_smaller_than_original(self):
        target = len(CSV) // 2
        p = build_transfer_payload(CSV, target_bytes=target)
        self.assertEqual(len(p.data), target)
        self.assertEqual(p.synthetic_bytes, 0)
        self.assertEqual(p.data, CSV[:target])

    def test_rejects_bad_input(self):
        with self.assertRaises(ValueError):
            build_transfer_payload(b"", target_bytes=1024)
        with self.assertRaises(ValueError):
            build_transfer_payload(CSV, target_bytes=0)

    def test_summary_shape(self):
        p = build_transfer_payload(CSV, target_bytes=1024 * 1024)
        self.assertIsInstance(p, TransferPayload)
        self.assertEqual(
            set(p.summary),
            {"total_bytes", "original_bytes", "synthetic_bytes", "synthetic_ratio", "sha256"},
        )


if __name__ == "__main__":
    unittest.main()
