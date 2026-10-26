"""
Allowlist 정책 평가기 + LogQL 규칙 생성기 테스트 (P3).

검증 항목 (사용자 계획 §9의 1,2,3):
  - Allowlist IP 판정 (endpoint/service, 인가/비인가)
  - YAML -> Loki Ruler 규칙 생성
  - LogQL 문법 요소 및 정책 필터 반영
  - "dst_service=unknown 단독으로 공격 아님" 원칙

실행 (pipeline 디렉터리에서): python -m unittest discover -s tests -v
"""

import os
import sys
import unittest

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from policy.allowlist import PolicyEvaluator  # noqa: E402
from policy.rulegen import (  # noqa: E402
    ALERT_NAME,
    ALERT_NAME_EARLY,
    build_early_logql,
    build_logql,
    render_yaml,
    validate,
)

POLICY = {
    "version": 1,
    "sources": ["backend"],
    "alert_container": "leafy-backend",
    "allow": [
        {"service": "sink-a", "match": "endpoint", "ip": "10.210.0.30", "port": 8080},
        {"service": "db", "match": "service"},
        {"service": "minio", "match": "service"},
        {"service": "frontend", "match": "service"},
    ],
    "thresholds": {"min_transfer_bytes": 1048576, "window": "5m"},
}


def ev():
    return PolicyEvaluator.from_dict(POLICY)


def event(dst_service=None, dst_ip=None, dst_port=None, src="backend"):
    return {"src_service": src, "dst_service": dst_service,
            "dst_ip": dst_ip, "dst_port": dst_port}


class AllowlistDecisionTest(unittest.TestCase):
    def test_authorized_sink_endpoint_exact(self):
        d = ev().evaluate(event("sink-a", "10.210.0.30", 8080))
        self.assertTrue(d.authorized)
        self.assertTrue(d.applicable)
        self.assertIn("endpoint", d.matched)

    def test_unauthorized_sink_endpoint(self):
        d = ev().evaluate(event("sink-b", "10.210.0.31", 8080))
        self.assertFalse(d.authorized)
        self.assertTrue(d.applicable)
        self.assertIsNone(d.matched)

    def test_endpoint_port_mismatch_is_unauthorized(self):
        # 같은 IP라도 포트가 다르면 인가 아님 (정확한 ip:port 비교)
        d = ev().evaluate(event("sink-a", "10.210.0.30", 9999))
        self.assertFalse(d.authorized)

    def test_internal_service_allowed(self):
        for svc in ("db", "minio", "frontend"):
            d = ev().evaluate(event(svc, "10.210.0.99", 5432))
            self.assertTrue(d.authorized, svc)
            self.assertIn("service", d.matched)

    def test_unknown_service_not_attack_by_itself(self):
        # dst_service=unknown 이어도 evaluate 는 "목적지 비인가"만 말한다.
        # 공격 단정(경보)은 전송량 임계와 함께 봐야 하며, 그 판단은 규칙/집계 몫이다.
        d = ev().evaluate(event("unknown", "10.210.0.77", 8080))
        self.assertFalse(d.authorized)   # 허용 목록엔 없음
        self.assertTrue(d.applicable)
        # evaluate 는 "unknown 이라서 공격"이라고 말하지 않는다 — reason 은 목적지 미등재 근거
        self.assertIn("Allowlist", d.reason)

    def test_non_source_not_applicable(self):
        d = ev().evaluate(event("sink-b", "10.210.0.31", 8080, src="frontend"))
        self.assertTrue(d.authorized)      # 정책 대상 아님 → 판정 안 함
        self.assertFalse(d.applicable)

    def test_violation_reason(self):
        self.assertIsNone(ev().violation_reason(event("sink-a", "10.210.0.30", 8080)))
        self.assertIsNotNone(ev().violation_reason(event("sink-b", "10.210.0.31", 8080)))

    def test_validation_rejects_bad_policy(self):
        with self.assertRaises(ValueError):
            PolicyEvaluator.from_dict({"sources": [], "allow": []})
        with self.assertRaises(ValueError):
            PolicyEvaluator.from_dict({"sources": ["backend"],
                                       "allow": [{"match": "endpoint", "ip": "1.1.1.1"}]})


class RuleGenTest(unittest.TestCase):
    def test_logql_contains_policy_filters(self):
        expr = build_logql(ev())
        self.assertIn('src_service="backend"', expr)
        # 누적 규칙은 최종 연결 이벤트만 (조기 이벤트와 중복 집계 방지)
        self.assertIn('event_type="connection"', expr)
        # service 허용은 스트림 라벨에서 제외
        self.assertIn('dst_service!~"db|minio|frontend"', expr)
        # endpoint 허용은 라인 필터로 제외
        self.assertIn('(dst_ip!="10.210.0.30" or dst_port!=8080)', expr)
        # 누적 집계 + 임계
        self.assertIn("sum_over_time", expr)
        self.assertIn("sum by (dst_ip, dst_port)", expr)
        self.assertIn("unwrap bytes_sent", expr)
        self.assertIn("[5m]", expr)
        self.assertIn("> 1048576", expr)
        # JSON/unwrap 오류 처리
        self.assertIn('| __error__=""', expr)
        self.assertIn('| bytes_sent!=""', expr)

    def test_early_logql_is_threshold_scoped(self):
        # P6 조기 규칙: threshold 이벤트만, count>0, 누적과 분리
        expr = build_early_logql(ev())
        self.assertIn('event_type="connection_threshold"', expr)
        self.assertIn("count_over_time", expr)
        self.assertIn("> 0", expr)
        self.assertNotIn("unwrap bytes_sent", expr)  # 바이트 합산하지 않는다

    def test_rendered_yaml_valid_and_parses(self):
        rendered = render_yaml(ev())
        self.assertEqual(validate(rendered), [])
        doc = yaml.safe_load(rendered)
        rules = {r["alert"]: r for r in doc["groups"][0]["rules"]}
        self.assertIn(ALERT_NAME, rules)
        self.assertIn(ALERT_NAME_EARLY, rules)        # 누적 + 조기 두 규칙
        self.assertEqual(rules[ALERT_NAME]["labels"]["severity"], "critical")
        # pipeline 은 annotations.container 가 없으면 RCA 를 건너뛴다 (두 규칙 모두 필요)
        for rule in rules.values():
            self.assertEqual(rule["annotations"]["container"], "leafy-backend")
        # annotation 에 GT/정답 힌트가 없어야 한다 (두 규칙 모두)
        for rule in rules.values():
            joined = (rule["annotations"]["summary"] + rule["annotations"]["description"]).lower()
            for banned in ("[attack]", "ground", "정답", "s2", "c-a"):
                self.assertNotIn(banned, joined)

    def test_validate_flags_missing_container(self):
        policy = {k: v for k, v in POLICY.items() if k != "alert_container"}
        problems = validate(render_yaml(PolicyEvaluator.from_dict(policy)))
        self.assertEqual(sum("annotations.container" in p for p in problems), 2)

    def test_validate_detects_broken(self):
        self.assertTrue(validate("groups: [bad"))
        self.assertTrue(validate("groups:\n- name: x\n  rules: []\n"))


class CommittedRuleConsistencyTest(unittest.TestCase):
    """커밋된 규칙 파일이 현재 allowlist 로 재생성한 결과와 일치하는지(정책 드리프트 방지)."""

    def test_committed_rule_matches_policy(self):
        here = os.path.dirname(__file__)
        allowlist = os.path.join(here, "..", "..", "policy", "allowlist.yml")
        rule_path = os.path.join(here, "..", "..", "..",
                                 "monitoring", "loki", "rules", "fake", "network-allowlist.yml")
        if not (os.path.exists(allowlist) and os.path.exists(rule_path)):
            self.skipTest("allowlist/규칙 파일 경로 없음")
        evaluator = PolicyEvaluator.from_file(allowlist)
        expected = render_yaml(evaluator)
        with open(rule_path, encoding="utf-8") as fh:
            committed = fh.read()
        self.assertEqual(
            yaml.safe_load(committed), yaml.safe_load(expected),
            "커밋된 규칙이 allowlist 와 불일치 — rulegen 재실행 필요",
        )


if __name__ == "__main__":
    unittest.main()
