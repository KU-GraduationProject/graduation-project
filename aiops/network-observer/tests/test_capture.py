"""
CaptureInterface 테스트 — 실제 캡처 인터페이스 전달 경로.

실행: cd aiops/network-observer && PYTHONPATH=enricher python -m unittest discover -s tests -v
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "enricher"))

from capture import CaptureInterface  # noqa: E402


class TestCaptureInterface(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "capture-interface")

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, text, mtime=None):
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(text)
        if mtime is not None:
            os.utime(self.path, (mtime, mtime))

    def test_파일이_없으면_fallback(self):
        """Zeek 가 아직 안 올라왔거나 파일을 못 쓴 경우."""
        self.assertIsNone(CaptureInterface(self.path).get())
        self.assertEqual(CaptureInterface(self.path, fallback="eth0").get(), "eth0")

    def test_파일의_이름을_읽는다(self):
        self._write("eth1\n")
        self.assertEqual(CaptureInterface(self.path, fallback="eth0").get(), "eth1")

    def test_공백과_개행을_제거한다(self):
        self._write("  eth2 \n")
        self.assertEqual(CaptureInterface(self.path).get(), "eth2")

    def test_빈_파일이면_fallback_유지(self):
        """쓰는 중에 읽었을 수 있다 — 빈 문자열을 interface 로 적지 않는다."""
        self._write("")
        self.assertEqual(CaptureInterface(self.path, fallback="eth0").get(), "eth0")

    def test_mtime_이_같으면_다시_읽지_않는다(self):
        """매 이벤트마다 호출되므로 변화가 없으면 stat 한 번으로 끝낸다."""
        self._write("eth1\n", mtime=1_000_000)
        iface = CaptureInterface(self.path)
        self.assertEqual(iface.get(), "eth1")

        # mtime 을 유지한 채 내용만 바꾸면 캐시된 값이 유지된다.
        self._write("eth9\n", mtime=1_000_000)
        self.assertEqual(iface.get(), "eth1")

    def test_mtime_이_바뀌면_다시_읽는다(self):
        """Zeek 가 재생성되며 다른 인터페이스를 잡는 경우 — 이 파일이 생긴 이유다."""
        self._write("eth1\n", mtime=1_000_000)
        iface = CaptureInterface(self.path)
        self.assertEqual(iface.get(), "eth1")

        self._write("eth0\n", mtime=2_000_000)
        self.assertEqual(iface.get(), "eth0")

    def test_파일이_사라지면_fallback_으로_돌아간다(self):
        self._write("eth1\n")
        iface = CaptureInterface(self.path, fallback=None)
        self.assertEqual(iface.get(), "eth1")

        os.remove(self.path)
        self.assertIsNone(iface.get())


if __name__ == "__main__":
    unittest.main()
