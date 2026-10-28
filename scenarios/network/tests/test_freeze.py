"""
설정 동결 테스트 (E4) — 해시 결정성, drift 감지, 저장/로드.

실행: cd scenarios/network && python -m unittest discover -s tests -v
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from freeze import FrozenConfig, freeze_config, sha256_file, verify_unchanged  # noqa: E402

FILES = ["a.yml", "b.txt"]


class FreezeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._write("a.yml", "allow: [sink-a]\n")
        self._write("b.txt", "threshold=1048576\n")

    def _write(self, rel, content):
        with open(os.path.join(self.tmp, rel), "w", encoding="utf-8") as fh:
            fh.write(content)

    def test_sha_deterministic(self):
        p = os.path.join(self.tmp, "a.yml")
        self.assertEqual(sha256_file(p), sha256_file(p))

    def test_freeze_structure(self):
        f = freeze_config(self.tmp, {"T": 30, "N": 1048576}, files=FILES)
        self.assertEqual(f.params["T"], 30)
        self.assertEqual(set(f.file_hashes), set(FILES))
        self.assertIsNotNone(f.file_hashes["a.yml"])

    def test_no_drift_when_unchanged(self):
        f = freeze_config(self.tmp, {}, files=FILES)
        self.assertEqual(verify_unchanged(f, self.tmp, files=FILES), [])

    def test_drift_detected_on_change(self):
        f = freeze_config(self.tmp, {}, files=FILES)
        self._write("a.yml", "allow: [sink-a, sink-b]\n")   # 정책 변경
        drift = verify_unchanged(f, self.tmp, files=FILES)
        self.assertEqual(drift, ["a.yml"])

    def test_missing_file_is_drift(self):
        f = freeze_config(self.tmp, {}, files=FILES)
        os.remove(os.path.join(self.tmp, "b.txt"))
        self.assertIn("b.txt", verify_unchanged(f, self.tmp, files=FILES))

    def test_save_load_roundtrip(self):
        f = freeze_config(self.tmp, {"T": 30}, files=FILES)
        path = os.path.join(self.tmp, "frozen.json")
        f.save(path)
        g = FrozenConfig.load(path)
        self.assertEqual(g.file_hashes, f.file_hashes)
        self.assertEqual(g.params, f.params)


if __name__ == "__main__":
    unittest.main()
