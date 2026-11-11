"""
action_type 허용 목록 단일 정의(schemas/actions.py)가 스키마·프롬프트·정책 파일과 일치하는지.

실행 (pipeline 디렉터리에서):
    python -m unittest discover -s tests -v
"""

import os
import re
import sys
import unittest

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from prompt.builder import SYSTEM_PROMPT as LEGACY_SYSTEM_PROMPT  # noqa: E402
from prompt.builder_v2 import SYSTEM_PROMPT_V2  # noqa: E402
from schemas.actions import ACTION_TYPES  # noqa: E402
from schemas.llm_output import output_schema, parse_analysis  # noqa: E402

POLICY = os.path.join(os.path.dirname(__file__), "..", "..", "policy", "remediation_policy.yml")


class ActionTypesTest(unittest.TestCase):
    def test_policy_file_defines_exactly_these_actions(self):
        with open(POLICY, encoding="utf-8") as fh:
            policy = yaml.safe_load(fh)
        self.assertEqual(set(policy["actions"]), set(ACTION_TYPES))
        self.assertIn("SCALE", policy["unsupported"])
        self.assertNotIn("SCALE", ACTION_TYPES)

    def test_output_schema_uses_the_list(self):
        self.assertEqual(output_schema()["properties"]["action_type"]["enum"], list(ACTION_TYPES))

    def test_prompts_list_the_same_actions(self):
        listed = re.search(r"action_type: one of ([A-Z |]+)\.", SYSTEM_PROMPT_V2).group(1)
        self.assertEqual([a.strip() for a in listed.split("|")], list(ACTION_TYPES))
        legacy = re.search(r'"action_type": "<([A-Z|]+)>"', LEGACY_SYSTEM_PROMPT).group(1)
        self.assertEqual(set(legacy.split("|")), set(ACTION_TYPES))
        self.assertNotIn("SCALE", SYSTEM_PROMPT_V2)

    def test_periodic_scan_prompt_excludes_scale(self):
        try:
            import main
        except ImportError:  # fastapi 없는 환경
            self.skipTest("fastapi not installed")
        self.assertNotIn("SCALE", main.PERIODIC_SCAN_SYSTEM_PROMPT)
        for a in ACTION_TYPES:
            self.assertIn(a, main.PERIODIC_SCAN_SYSTEM_PROMPT)

    def test_scale_is_rejected_by_parser(self):
        r = parse_analysis('{"root_cause":"x","incident_class":"failure","action_type":"SCALE",'
                           '"action_targets":[],"threat_level":"low","evidence":[],"confidence":0.5}',
                           evidence_ids=[])
        self.assertEqual(r.analysis_status, "invalid")
        self.assertIn("invalid_enum:action_type", r.invalid_reasons)


if __name__ == "__main__":
    unittest.main()
