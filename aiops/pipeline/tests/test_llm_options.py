"""
Pipeline → Ollama 호출 options 테스트.

모든 LLM 호출 지점(call_llm, _call_llm_raw)이 config 의 같은 모델·options 를 보내는지 확인한다.
options 가 빠지면 temperature·num_ctx 가 Ollama 서버 기본값을 따라가 측정을 재현할 수 없다.

실행 (pipeline 디렉터리에서):
    python -m unittest discover -s tests -v
"""

import asyncio
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import main  # noqa: E402

_CONTENT = {
    "root_cause": "cpu saturated",
    "action_type": "RESTART",
    "action_targets": ["leafy-backend"],
    "action_description": "restart",
    "threat_level": "high",
    "evidence": ["cpu_usage: latest=4.9"],
    "confidence": 0.9,
}


class _FakeResponse:
    def raise_for_status(self):
        pass

    def json(self):
        return {"message": {"content": json.dumps(_CONTENT)}, "prompt_eval_count": 1000,
                "eval_count": 150, "total_duration": 4_000_000_000, "done_reason": "stop"}


class LlmOptionsTest(unittest.TestCase):
    def _sent_bodies(self, seed=None):
        bodies = []

        class FakeClient:
            async def __aenter__(self_inner):
                return self_inner

            async def __aexit__(self_inner, *exc):
                return False

            async def post(self_inner, url, **kw):
                bodies.append(kw["json"])
                return _FakeResponse()

        prompt = {"system": "sys", "user": "usr"}
        with mock.patch.object(main.settings, "llm_seed", seed), \
             mock.patch.object(main.httpx, "AsyncClient", return_value=FakeClient()):
            asyncio.run(main.call_llm(prompt))
            asyncio.run(main._call_llm_raw(prompt))
        return bodies

    def test_all_call_sites_send_config_options(self):
        bodies = self._sent_bodies()
        self.assertEqual(len(bodies), 2)  # call_llm 1회(첫 시도 성공) + _call_llm_raw 1회
        expected = {
            "temperature": main.settings.llm_temperature,
            "num_ctx": main.settings.llm_num_ctx,
            "num_predict": main.settings.llm_num_predict,
        }
        for body in bodies:
            self.assertEqual(body["options"], expected)  # seed 미설정이면 키 자체가 없다
            self.assertEqual(body["model"], main.settings.llm_model)
            self.assertEqual(body["format"], "json")

    def test_seed_sent_only_when_configured(self):
        for body in self._sent_bodies(seed=42):
            self.assertEqual(body["options"]["seed"], 42)


if __name__ == "__main__":
    unittest.main()
