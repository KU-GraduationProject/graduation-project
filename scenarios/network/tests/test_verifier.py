"""
네트워크 경보 검증기 테스트 (P5).

검증 항목 (사용자 계획 §9의 9):
  - 이전 실행 경보와 occurrence 혼입 방지 (t0 이후 activeAt/startsAt 만 선택)
  - 세 단계(Loki Ruler firing / Alertmanager 수신 / 전달) 독립 판정
  - MTTD = 전이시각(t2) - t0, polling 관측시각과 구분

실행: cd scenarios/network && python -m unittest discover -s tests -v
"""

import os
import sys
import unittest
from datetime import timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from verifier import (  # noqa: E402
    DEFAULT_ALERTS,
    compute_mttd,
    evaluate_stages,
    is_any_firing,
    parse_am_alerts,
    parse_ruler_alerts,
    parse_ts,
    select_firing_occurrence,
)

T0 = parse_ts("2026-10-25T05:00:00Z")


def ruler_obj(*alerts):
    return {"data": {"alerts": list(alerts)}}


def ralert(name, state, active_at):
    return {"labels": {"alertname": name}, "state": state, "activeAt": active_at}


def amalert(name, starts_at, state="active"):
    return {"labels": {"alertname": name}, "startsAt": starts_at, "status": {"state": state}}


class ParseTest(unittest.TestCase):
    def test_parse_ts_variants(self):
        self.assertIsNotNone(parse_ts("2026-10-25T05:00:00Z"))
        self.assertIsNotNone(parse_ts("2026-10-25T05:00:00.123+00:00"))
        self.assertIsNone(parse_ts(""))
        self.assertIsNone(parse_ts("0001-01-01T00:00:00Z"))   # Prometheus "없음" 표기

    def test_parse_ruler_and_am(self):
        r = parse_ruler_alerts(ruler_obj(ralert("UnauthorizedDataTransfer", "firing",
                                                 "2026-10-25T05:00:05Z")))
        self.assertEqual(r[0].alertname, "UnauthorizedDataTransfer")
        self.assertEqual(r[0].state, "firing")
        a = parse_am_alerts([amalert("UnauthorizedDataTransfer", "2026-10-25T05:00:06Z")])
        self.assertEqual(a[0].state, "active")


class OccurrenceIsolationTest(unittest.TestCase):
    def test_ignores_prior_run_firing(self):
        alerts = parse_ruler_alerts(ruler_obj(
            ralert("UnauthorizedDataTransfer", "firing", "2026-10-25T04:50:00Z"),  # 이전 실행
            ralert("UnauthorizedDataTransfer", "firing", "2026-10-25T05:00:05Z"),  # 이번 실행
        ))
        chosen = select_firing_occurrence(alerts, DEFAULT_ALERTS, T0)
        self.assertIsNotNone(chosen)
        self.assertEqual(chosen.active_at, parse_ts("2026-10-25T05:00:05Z"))

    def test_only_prior_run_returns_none(self):
        alerts = parse_ruler_alerts(ruler_obj(
            ralert("UnauthorizedDataTransfer", "firing", "2026-10-25T04:50:00Z"),
        ))
        self.assertIsNone(select_firing_occurrence(alerts, DEFAULT_ALERTS, T0))

    def test_pending_not_selected(self):
        alerts = parse_ruler_alerts(ruler_obj(
            ralert("UnauthorizedDataTransfer", "pending", "2026-10-25T05:00:05Z"),
        ))
        self.assertIsNone(select_firing_occurrence(alerts, DEFAULT_ALERTS, T0))


class MttdTest(unittest.TestCase):
    def test_mttd_is_transition_minus_t0(self):
        t2 = parse_ts("2026-10-25T05:00:08Z")
        self.assertEqual(compute_mttd(T0, t2), 8.0)

    def test_mttd_none_without_firing(self):
        self.assertIsNone(compute_mttd(T0, None))

    def test_mttd_non_negative(self):
        self.assertEqual(compute_mttd(T0, T0 - timedelta(seconds=3)), 0.0)


class StageEvaluationTest(unittest.TestCase):
    def test_all_stages_pass(self):
        ruler = parse_ruler_alerts(ruler_obj(
            ralert("UnauthorizedTransferEarly", "firing", "2026-10-25T05:00:04Z")))
        am = parse_am_alerts([amalert("UnauthorizedTransferEarly", "2026-10-25T05:00:05Z")])
        res = evaluate_stages(T0, ruler, am, delivery_ok=True,
                              delivery_detail="lines=2", now_iso="2026-10-25T05:00:10Z")
        self.assertTrue(res.all_ok)
        self.assertEqual(res.mttd_seconds, 4.0)
        # 전이 시각(t2) 과 polling 관측 시각을 구분해 기록한다
        self.assertEqual(res.firing_active_at, "2026-10-25T05:00:04+00:00")
        self.assertEqual(res.first_observed_at, "2026-10-25T05:00:10Z")

    def test_independent_stage_failures(self):
        # firing 은 있으나(A ok) Alertmanager 미수신(B fail), 전달 실패(C fail)
        ruler = parse_ruler_alerts(ruler_obj(
            ralert("UnauthorizedDataTransfer", "firing", "2026-10-25T05:00:04Z")))
        res = evaluate_stages(T0, ruler, am_alerts=[], delivery_ok=False,
                              delivery_detail="none")
        self.assertTrue(res.stages["loki_ruler_firing"].ok)
        self.assertFalse(res.stages["alertmanager_received"].ok)
        self.assertFalse(res.stages["delivery"].ok)
        self.assertFalse(res.all_ok)
        self.assertEqual(res.mttd_seconds, 4.0)   # A 가 떴으므로 MTTD 는 계산됨

    def test_no_firing_no_mttd(self):
        res = evaluate_stages(T0, [], [], delivery_ok=False, delivery_detail="none")
        self.assertFalse(res.stages["loki_ruler_firing"].ok)
        self.assertIsNone(res.mttd_seconds)


class CooldownTest(unittest.TestCase):
    def test_is_any_firing(self):
        firing = parse_ruler_alerts(ruler_obj(
            ralert("UnauthorizedDataTransfer", "firing", "2026-10-25T05:00:04Z")))
        inactive = parse_ruler_alerts(ruler_obj(
            ralert("UnauthorizedDataTransfer", "inactive", None)))
        self.assertTrue(is_any_firing(firing, DEFAULT_ALERTS))
        self.assertFalse(is_any_firing(inactive, DEFAULT_ALERTS))


if __name__ == "__main__":
    unittest.main()
