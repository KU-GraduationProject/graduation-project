"""
정책 엔진 (Phase 1) — LLM 추천을 집행 결정으로 바꾼다.

LLM 은 무엇이 일어났고 무엇을 하면 좋겠는지만 말한다. 위험도·승인 여부·자동 실행
가능 여부·선행 조건·TTL 은 모두 이 엔진이 정책 파일을 근거로 결정한다.
LLM 이 보낸 action_risk 는 기록만 하고 판단에 쓰지 않는다.

불변식 (테스트로 고정):
  1. action_risk 는 action_type 에서만 나온다. LLM 입력으로 바뀌지 않는다.
  2. requires_approval 인 조치는 confidence·threat_level 과 무관하게 자동 실행되지 않는다.
     threat_level=critical 은 긴급도만 올리고 승인을 생략하지 않는다.
  3. 정책에 없는 action_type 은 차단한다 (fail closed).
  4. 자동 경로와 승인 경로가 모두 execution_allowed() 를 통과해야 실행된다 —
     한쪽만 실행 가능한 상태가 생기지 않는다.
"""

from __future__ import annotations

import logging
import math
import os

from policy.schema import (
    AUTO_EXECUTE_CANDIDATE,
    AWAITING_APPROVAL,
    BLOCKED,
    NO_ACTION,
    NOTIFY,
    THREAT_LEVELS,
    PolicyConfig,
    PolicyDecision,
    PolicyError,
    parse_policy,
)

logger = logging.getLogger(__name__)

POLICY_PATH_ENV = "REMEDIATION_POLICY_PATH"
# 컨테이너에서는 compose 가 읽기 전용으로 마운트한다 (allowlist.yml 과 같은 방식).
CONTAINER_POLICY_PATH = "/app/config/remediation_policy.yml"
# 레포에서 바로 실행·테스트할 때의 경로 (aiops/remediation/policy -> aiops/policy)
REPO_POLICY_PATH = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "policy",
    "remediation_policy.yml"))

DEFAULT_THREAT_LEVEL = "medium"


def resolve_policy_path(path: str | None = None) -> str:
    """
    정책 파일 경로를 정한다.

      1. 인자로 준 경로
      2. REMEDIATION_POLICY_PATH 환경변수 — 설정돼 있으면 그대로 쓴다.
         파일이 없어도 다른 파일로 대체하지 않는다. 운영자가 지정한 정책 대신
         다른 정책으로 조용히 돌아가면, 의도한 것과 다른 게이트로 조치가 흐른다.
      3. 컨테이너 마운트 경로 (있으면)
      4. 레포 경로 (로컬 실행·테스트)

    찾지 못하면 컨테이너 경로를 돌려주고, 로드 단계에서 PolicyError 로 실패한다.
    """
    if path:
        return path
    env_path = os.getenv(POLICY_PATH_ENV)
    if env_path:
        return env_path
    if os.path.isfile(CONTAINER_POLICY_PATH):
        return CONTAINER_POLICY_PATH
    if os.path.isfile(REPO_POLICY_PATH):
        return REPO_POLICY_PATH
    return CONTAINER_POLICY_PATH


class PolicyEngine:
    def __init__(self, config: PolicyConfig, source: str = "<memory>"):
        self.config = config
        self.source = source

    # ── 로드 ──────────────────────────────────────────────────────────────────
    @classmethod
    def from_file(cls, path: str | None = None) -> "PolicyEngine":
        """정책 파일을 검증해 로드한다. 없거나 형식이 틀리면 PolicyError."""
        resolved = resolve_policy_path(path)
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover - 런타임 의존성 누락
            raise PolicyError(f"PyYAML 이 필요하다: {exc}") from exc
        if not os.path.isfile(resolved):
            raise PolicyError(f"정책 파일이 없다: {resolved}")
        try:
            with open(resolved, "r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            raise PolicyError(f"정책 파일 YAML 파싱 실패 ({resolved}): {exc}") from exc
        engine = cls(parse_policy(raw), source=resolved)
        logger.info("[Policy] 로드 완료: %s (조치 %d종, 미지원 %d종)",
                    resolved, len(engine.config.actions), len(engine.config.unsupported))
        return engine

    # ── 보조 ──────────────────────────────────────────────────────────────────
    def _threat(self, threat_level: str):
        level = str(threat_level or "").lower()
        if level not in THREAT_LEVELS:
            level = DEFAULT_THREAT_LEVEL
        return level, self.config.threat_levels[level]

    @staticmethod
    def _normalize_targets(targets) -> tuple:
        if targets is None:
            return ()
        if isinstance(targets, str):
            targets = [targets]
        return tuple(str(t).strip() for t in targets if str(t).strip())

    @staticmethod
    def _normalize_confidence(confidence) -> float:
        """
        읽을 수 없는 값은 0.0 으로 본다 — 모르는 값을 높은 신뢰도로 올려서는 안 된다.
        NaN 주의: min/max 는 NaN 을 걸러내지 못해 clamp 만 하면 1.0 이 되어 버린다.
        """
        try:
            value = float(confidence)
        except (TypeError, ValueError):
            return 0.0
        if not math.isfinite(value):
            return 0.0
        return max(0.0, min(1.0, value))

    # ── 단일 실행 게이트 ──────────────────────────────────────────────────────
    def execution_allowed(self, action_type: str, targets) -> tuple[bool, str]:
        """
        실제 조치를 실행해도 되는지. 자동 경로와 승인 경로가 **둘 다** 이 함수를
        통과해야 실행한다 — 경로별로 실행 가능한 조치가 달라지는 일을 막는다.
        """
        key = str(action_type or "").upper().strip()
        policy = self.config.actions.get(key)
        if policy is None:
            if key in self.config.unsupported:
                return False, f"unsupported_action_type:{self.config.unsupported[key]}"
            return False, "undefined_action_type"
        if not policy.performs_action:
            return False, "action_performs_nothing"
        if not policy.executor_ready:
            return False, policy.executor_blocked_reason or "executor_not_ready"
        if policy.requires_targets and not self._normalize_targets(targets):
            return False, "no_action_targets"
        return True, "ok"

    # ── 판단 ──────────────────────────────────────────────────────────────────
    def decide(self, action_type, threat_level=None, confidence=None,
               action_targets=None, llm_action_risk=None) -> PolicyDecision:
        key = str(action_type or "").upper().strip()
        level, threat = self._threat(threat_level)
        targets = self._normalize_targets(action_targets)
        conf = self._normalize_confidence(confidence)
        llm_risk = str(llm_action_risk).lower() if llm_action_risk else None

        def blocked(risk: str, reason: str, *reasons: str) -> PolicyDecision:
            return PolicyDecision(
                action_type=key or "UNKNOWN", action_risk=risk, threat_level=level,
                urgency=threat.urgency, outcome=BLOCKED, requires_approval=False,
                executable_now=False, performs_action=False, confidence=conf,
                targets=targets, reasons=reasons or (reason,), blocked_reason=reason,
                notify="alert_only", mention=threat.mention, llm_action_risk=llm_risk,
            )

        policy = self.config.actions.get(key)
        if policy is None:
            # fail closed: 모르는/지원하지 않는 조치는 차단하고 사유를 남긴다.
            if key in self.config.unsupported:
                return blocked("high", f"unsupported_action_type:"
                                       f"{self.config.unsupported[key]}")
            return blocked("high", "undefined_action_type")

        reasons = [f"action_risk_from_policy:{policy.action_risk}",
                   f"urgency_from_threat_level:{level}->{threat.urgency}"]
        if llm_risk:
            # LLM 이 위험도를 보냈다 — 기록만 한다. 판단에는 쓰지 않는다.
            reasons.append(f"llm_action_risk_ignored:{llm_risk}")

        common = dict(
            action_type=key, action_risk=policy.action_risk, threat_level=level,
            urgency=threat.urgency, performs_action=policy.performs_action,
            confidence=conf, targets=targets, prerequisites=policy.evidence_required,
            ttl_seconds=policy.ttl_seconds, recovery_required=policy.recovery_required,
            recovery_mode=policy.recovery_mode,
            mention=threat.mention, llm_action_risk=llm_risk,
        )

        # 1) 실행할 조치가 없는 경우
        if not policy.performs_action:
            return PolicyDecision(
                outcome=NO_ACTION if key == "NONE" else NOTIFY,
                requires_approval=False, executable_now=False,
                reasons=tuple(reasons + ["policy_performs_no_action"]),
                notify=policy.notify, **common)

        # 2) 대상 검증 — 대상이 없으면 어떤 조치도 실행할 수 없다
        if policy.requires_targets and not targets:
            return PolicyDecision(
                outcome=AWAITING_APPROVAL, requires_approval=True, executable_now=False,
                reasons=tuple(reasons + ["no_action_targets"]),
                notify="approval_request", **common)

        # 3) 승인 필수 조치 (high risk) — confidence·critical 과 무관하게 자동 불가
        if policy.requires_approval:
            reasons.append("approval_required_by_policy")
            if level == "critical":
                reasons.append("critical_raises_urgency_not_bypasses_approval")
            allowed, exec_reason = self.execution_allowed(key, targets)
            if not allowed:
                reasons.append(f"execution_blocked_on_approval:{exec_reason}")
            return PolicyDecision(
                outcome=AWAITING_APPROVAL, requires_approval=True,
                executable_now=False,   # 승인 전에는 실행 불가
                reasons=tuple(reasons), notify=policy.notify, **common)

        # 4) 자동 실행 후보 (medium risk) — 조건을 모두 만족해야 한다
        if policy.auto_execute:
            unmet = []
            if policy.auto_threat_levels and level not in policy.auto_threat_levels:
                unmet.append(f"threat_level_not_eligible:{level}")
            if policy.min_confidence is not None and conf < policy.min_confidence:
                unmet.append(f"confidence_below_threshold:{conf}<{policy.min_confidence}")
            if unmet:
                # 자동 조건 미충족 -> 자동 실행하지 않고 승인으로 돌린다
                return PolicyDecision(
                    outcome=AWAITING_APPROVAL, requires_approval=True,
                    executable_now=False, reasons=tuple(reasons + unmet),
                    notify="approval_request", **common)

            reasons.append(f"auto_conditions_met:confidence>={policy.min_confidence}")
            allowed, exec_reason = self.execution_allowed(key, targets)
            if not allowed:
                # 정책상 후보이지만 지금 실행할 수는 없다 — 두 상태를 구분해 기록한다.
                reasons.append(f"execution_deferred:{exec_reason}")
            return PolicyDecision(
                outcome=AUTO_EXECUTE_CANDIDATE, requires_approval=False,
                executable_now=allowed, reasons=tuple(reasons),
                notify=policy.notify, **common)

        # 5) 승인도 자동도 아닌 조치 정의 -> 차단 (정책 작성 실수)
        return blocked(policy.action_risk, "policy_defines_no_execution_path",
                       *reasons, "policy_defines_no_execution_path")

    def decide_from_analysis(self, analysis: dict) -> PolicyDecision:
        """Remediation /action 의 analysis dict 에서 바로 판단한다."""
        return self.decide(
            action_type=analysis.get("action_type"),
            threat_level=analysis.get("threat_level"),
            confidence=analysis.get("confidence"),
            action_targets=analysis.get("action_targets"),
            # 과거 스키마 호환: 값이 와도 기록만 한다
            llm_action_risk=analysis.get("action_risk"),
        )


class BlockAllPolicyEngine:
    """
    정책을 로드하지 못했을 때 쓰는 대체 엔진. 모든 조치를 차단하고 사유를 남긴다.
    서비스는 떠 있어야 감사 로그와 /health 가 동작하지만, 조치는 절대 실행되지
    않아야 한다 (fail closed).
    """

    def __init__(self, reason: str):
        self.reason = reason
        self.source = "<unavailable>"

    def execution_allowed(self, action_type: str, targets) -> tuple[bool, str]:
        return False, f"policy_unavailable:{self.reason}"

    def decide(self, action_type, threat_level=None, confidence=None,
               action_targets=None, llm_action_risk=None) -> PolicyDecision:
        level = str(threat_level or "").lower()
        if level not in THREAT_LEVELS:
            level = DEFAULT_THREAT_LEVEL
        return PolicyDecision(
            action_type=str(action_type or "UNKNOWN").upper(), action_risk="high",
            threat_level=level, urgency="unknown", outcome=BLOCKED,
            requires_approval=False, executable_now=False, performs_action=False,
            confidence=PolicyEngine._normalize_confidence(confidence),
            targets=PolicyEngine._normalize_targets(action_targets),
            reasons=(f"policy_unavailable:{self.reason}",),
            blocked_reason=f"policy_unavailable:{self.reason}",
            notify="alert_only", recovery_mode="none",
            llm_action_risk=str(llm_action_risk).lower() if llm_action_risk else None,
        )

    def decide_from_analysis(self, analysis: dict) -> PolicyDecision:
        return self.decide(
            action_type=analysis.get("action_type"),
            threat_level=analysis.get("threat_level"),
            confidence=analysis.get("confidence"),
            action_targets=analysis.get("action_targets"),
            llm_action_risk=analysis.get("action_risk"),
        )


def load_engine(path: str | None = None):
    """
    정책 엔진을 로드한다. 실패하면 예외를 던지지 않고 BlockAllPolicyEngine 을
    돌려준다 — 조치는 전부 차단되고, 운영자는 ERROR 로그로 원인을 본다.
    """
    try:
        return PolicyEngine.from_file(path)
    except PolicyError as exc:
        logger.error("[Policy] 정책 로드 실패 — 모든 조치를 차단한다: %s", exc)
        return BlockAllPolicyEngine(str(exc))
