"""
실험 판정·집계 (Step 5/6 / E3) — 순수 로직.

한 실행(run)의 Ground Truth(should_alert)와 탐지 결과(detected)를 TP/FP/TN/FN 으로
분류하고, 여러 실행을 Confusion Matrix 로 집계한다.

  S2  (should_alert=True)  : detected → TP,  미탐 → FN
  C-a (should_alert=False) : detected → FP,  미탐 → TN   (오탐 여부가 핵심)

성공 조건(사용자 계획): S2 는 탐지(recall↑), C-a 는 오탐 없음(specificity↑ / FPR↓).

유효성(valid): 전송이 실제로 완료·교차검증(crosscheck)되어 "판정 가능한" 실행만
Confusion Matrix 에 넣는다. 무효 실행은 따로 기록한다. GT 는 평가 측에만 둔다.
"""

from __future__ import annotations

from dataclasses import dataclass, field

TP, FP, TN, FN = "TP", "FP", "TN", "FN"


def classify(should_alert: bool, detected: bool) -> str:
    if should_alert:
        return TP if detected else FN
    return FP if detected else TN


@dataclass
class RunOutcome:
    label: str          # "S2-V1" 등
    scenario: str       # "S2" | "C-a"
    variant: str
    should_alert: bool  # GT (평가 전용)
    detected: bool      # verifier Stage A(FIRING) 여부
    valid: bool         # 전송 교차검증 성공 등 — 판정 가능 여부
    mttd_seconds: float | None = None
    detail: str = ""

    @property
    def outcome(self) -> str | None:
        """유효할 때만 TP/FP/TN/FN. 무효면 None (집계 제외)."""
        return classify(self.should_alert, self.detected) if self.valid else None

    def as_dict(self) -> dict:
        return {
            "label": self.label, "scenario": self.scenario, "variant": self.variant,
            "should_alert": self.should_alert, "detected": self.detected,
            "valid": self.valid, "outcome": self.outcome,
            "mttd_seconds": self.mttd_seconds, "detail": self.detail,
        }


@dataclass
class ConfusionMatrix:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    invalid: int = 0
    mttds: list = field(default_factory=list)   # 탐지된(TP) 실행들의 MTTD

    def add(self, outcome: RunOutcome) -> None:
        oc = outcome.outcome
        if oc is None:
            self.invalid += 1
            return
        setattr(self, oc.lower(), getattr(self, oc.lower()) + 1)
        if oc == TP and outcome.mttd_seconds is not None:
            self.mttds.append(outcome.mttd_seconds)

    @classmethod
    def from_outcomes(cls, outcomes) -> "ConfusionMatrix":
        m = cls()
        for o in outcomes:
            m.add(o)
        return m

    # --- 지표 (분모 0 이면 None) ---
    @staticmethod
    def _ratio(num, den):
        return (num / den) if den else None

    @property
    def total_valid(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self):
        return self._ratio(self.tp, self.tp + self.fp)

    @property
    def recall(self):        # 민감도 / TPR — S2 탐지율
        return self._ratio(self.tp, self.tp + self.fn)

    @property
    def specificity(self):   # TNR — C-a 무오탐율
        return self._ratio(self.tn, self.tn + self.fp)

    @property
    def false_positive_rate(self):
        return self._ratio(self.fp, self.fp + self.tn)

    @property
    def accuracy(self):
        return self._ratio(self.tp + self.tn, self.total_valid)

    @property
    def f1(self):
        p, r = self.precision, self.recall
        if not p or not r:
            return None
        return 2 * p * r / (p + r)

    def mttd_stats(self) -> dict:
        if not self.mttds:
            return {"count": 0, "min": None, "max": None, "mean": None}
        s = sorted(self.mttds)
        return {"count": len(s), "min": s[0], "max": s[-1],
                "mean": round(sum(s) / len(s), 3)}

    def as_dict(self) -> dict:
        return {
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "invalid": self.invalid, "total_valid": self.total_valid,
            "precision": self.precision, "recall": self.recall,
            "specificity": self.specificity, "false_positive_rate": self.false_positive_rate,
            "accuracy": self.accuracy, "f1": self.f1,
            "mttd": self.mttd_stats(),
        }
