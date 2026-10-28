"""
정책 파일 스키마와 판단 결과 모델 (Phase 1).

YAML 을 그대로 dict 로 쓰지 않고 검증된 dataclass 로 바꾼다. 필수 항목이 없거나
형식이 틀리면 로드 단계에서 PolicyError 로 실패한다 — 조치 경로에서 KeyError 로
터지거나, 빠진 값을 기본값으로 메워 위험한 조치를 열어 주면 안 된다.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ── 판단 결과 outcome ─────────────────────────────────────────────────────────
NO_ACTION = "NO_ACTION"                            # 실행할 조치가 없음 (NONE)
NOTIFY = "NOTIFY"                                  # 알림만
AWAITING_APPROVAL = "AWAITING_APPROVAL"            # Slack 승인 필요
AUTO_EXECUTE_CANDIDATE = "AUTO_EXECUTE_CANDIDATE"  # 정책상 자동 실행 후보
BLOCKED = "BLOCKED"                                # 정책이 차단

OUTCOMES = (NO_ACTION, NOTIFY, AWAITING_APPROVAL, AUTO_EXECUTE_CANDIDATE, BLOCKED)

RISKS = ("low", "medium", "high")
THREAT_LEVELS = ("low", "medium", "high", "critical")

# 복구 방식 (Phase 2)
RECOVERY_AUTO = "auto"                        # TTL 만료 시 자동 복구
RECOVERY_REQUIRE_APPROVAL = "require_approval"  # TTL 만료 시 재승인 요청
RECOVERY_NONE = "none"                        # 되돌릴 수 없음 / 대상 아님
RECOVERY_MODES = (RECOVERY_AUTO, RECOVERY_REQUIRE_APPROVAL, RECOVERY_NONE)


class PolicyError(ValueError):
    """정책 파일이 없거나 형식이 잘못됐다. 조치를 열어 주지 않고 실패한다."""


@dataclass(frozen=True)
class ThreatPolicy:
    urgency: str
    mention: bool = False


@dataclass(frozen=True)
class NetworkPolicy:
    """ISOLATE 대상 분류. 이름은 Docker inspect 로 읽고 접미사로 맞춘다."""
    isolate: tuple = ()
    preserve: tuple = ()


@dataclass(frozen=True)
class ActionPolicy:
    action_type: str
    action_risk: str
    performs_action: bool
    requires_approval: bool
    auto_execute: bool
    executor_ready: bool
    notify: str
    description: str = ""
    min_confidence: float | None = None
    auto_threat_levels: tuple = ()
    requires_targets: bool = False
    ttl_seconds: int | None = None
    recovery_required: bool = False
    evidence_required: tuple = ()
    executor_blocked_reason: str | None = None
    recovery_mode: str = RECOVERY_NONE


@dataclass(frozen=True)
class PolicyDecision:
    """
    한 건의 분석 결과에 대한 정책 판단. 감사 로그에 그대로 싣는다.

    executable_now 는 "지금 실제로 실행해도 되는가"다. outcome 이 자동 실행 후보여도
    실행기가 준비되지 않았으면 False 이고, 이 둘을 구분해 기록한다.
    """
    action_type: str
    action_risk: str
    threat_level: str
    urgency: str
    outcome: str
    requires_approval: bool
    executable_now: bool
    performs_action: bool
    confidence: float
    targets: tuple = ()
    reasons: tuple = ()
    blocked_reason: str | None = None
    prerequisites: tuple = ()
    ttl_seconds: int | None = None
    recovery_required: bool = False
    recovery_mode: str = RECOVERY_NONE
    notify: str = "none"
    mention: bool = False
    # ↑ PolicyDecision 필드. recovery_mode 는 Phase 2 복구기가 소비한다.
    llm_action_risk: str | None = None   # LLM 이 보낸 값 — 기록만 하고 판단에 쓰지 않는다

    def as_dict(self) -> dict:
        return {
            "action_type": self.action_type,
            "action_risk": self.action_risk,
            "threat_level": self.threat_level,
            "urgency": self.urgency,
            "outcome": self.outcome,
            "requires_approval": self.requires_approval,
            "executable_now": self.executable_now,
            "performs_action": self.performs_action,
            "confidence": self.confidence,
            "targets": list(self.targets),
            "reasons": list(self.reasons),
            "blocked_reason": self.blocked_reason,
            "prerequisites": list(self.prerequisites),
            "ttl_seconds": self.ttl_seconds,
            "recovery_required": self.recovery_required,
            "recovery_mode": self.recovery_mode,
            "notify": self.notify,
            "mention": self.mention,
            "llm_action_risk": self.llm_action_risk,
            "llm_action_risk_used": False,   # 불변식: LLM 값은 판단에 쓰이지 않는다
        }


@dataclass(frozen=True)
class PolicyConfig:
    version: int
    actions: dict = field(default_factory=dict)        # action_type -> ActionPolicy
    unsupported: dict = field(default_factory=dict)    # action_type -> 사유
    threat_levels: dict = field(default_factory=dict)  # level -> ThreatPolicy
    networks: NetworkPolicy = field(default_factory=NetworkPolicy)


# ── 검증 로더 ─────────────────────────────────────────────────────────────────
_REQUIRED_ACTION_FIELDS = (
    "action_risk", "performs_action", "requires_approval", "auto_execute",
    "executor_ready", "notify",
)
# 이 조치들의 정책이 없으면 로드를 거부한다 — 일부만 정의된 정책 파일로 돌면
# 정의되지 않은 쪽이 조용히 차단되거나 열릴 수 있다.
_REQUIRED_ACTIONS = ("NONE", "NOTIFY", "THROTTLE", "RESTART", "PAUSE", "ISOLATE")


def _as_bool(value, where: str) -> bool:
    if not isinstance(value, bool):
        raise PolicyError(f"{where}: 참/거짓이어야 한다 (받은 값: {value!r})")
    return value


def _as_tuple(value, where: str) -> tuple:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise PolicyError(f"{where}: 목록이어야 한다 (받은 값: {value!r})")
    return tuple(str(v) for v in value)


def parse_action_policy(action_type: str, raw) -> ActionPolicy:
    if not isinstance(raw, dict):
        raise PolicyError(f"actions.{action_type}: 매핑이어야 한다")
    missing = [k for k in _REQUIRED_ACTION_FIELDS if k not in raw]
    if missing:
        raise PolicyError(f"actions.{action_type}: 필수 항목 누락 {missing}")

    risk = str(raw["action_risk"]).lower()
    if risk not in RISKS:
        raise PolicyError(f"actions.{action_type}.action_risk: {RISKS} 중 하나여야 한다 "
                          f"(받은 값: {raw['action_risk']!r})")

    min_conf = raw.get("min_confidence")
    if min_conf is not None:
        try:
            min_conf = float(min_conf)
        except (TypeError, ValueError):
            raise PolicyError(f"actions.{action_type}.min_confidence: 숫자여야 한다")
        if not 0.0 <= min_conf <= 1.0:
            raise PolicyError(f"actions.{action_type}.min_confidence: 0.0~1.0 이어야 한다")

    ttl = raw.get("ttl_seconds")
    if ttl is not None:
        if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0:
            raise PolicyError(f"actions.{action_type}.ttl_seconds: 양의 정수여야 한다")

    auto_execute = _as_bool(raw["auto_execute"], f"actions.{action_type}.auto_execute")
    requires_approval = _as_bool(raw["requires_approval"],
                                 f"actions.{action_type}.requires_approval")
    if auto_execute and requires_approval:
        # 자동 실행과 승인 필수가 동시에 참이면 두 경로가 모순된다.
        raise PolicyError(f"actions.{action_type}: auto_execute 와 requires_approval 을 "
                          f"동시에 참으로 둘 수 없다")

    threat_levels = _as_tuple(raw.get("auto_threat_levels"),
                              f"actions.{action_type}.auto_threat_levels")
    unknown = [t for t in threat_levels if t not in THREAT_LEVELS]
    if unknown:
        raise PolicyError(f"actions.{action_type}.auto_threat_levels: 알 수 없는 단계 {unknown}")

    recovery_required = _as_bool(raw.get("recovery_required", False),
                                 f"actions.{action_type}.recovery_required")
    if recovery_required and ttl is None:
        raise PolicyError(f"actions.{action_type}: recovery_required 면 ttl_seconds 가 필요하다")

    recovery_mode = str(raw.get("recovery_mode", RECOVERY_NONE)).lower()
    if recovery_mode not in RECOVERY_MODES:
        raise PolicyError(f"actions.{action_type}.recovery_mode: {RECOVERY_MODES} 중 "
                          f"하나여야 한다 (받은 값: {raw.get('recovery_mode')!r})")
    if recovery_required and recovery_mode == RECOVERY_NONE:
        raise PolicyError(f"actions.{action_type}: recovery_required 인데 recovery_mode 가 "
                          f"none 이다 — 복구 경로 없이 되돌려야 하는 조치를 둘 수 없다")
    if recovery_mode != RECOVERY_NONE and ttl is None:
        raise PolicyError(f"actions.{action_type}: recovery_mode 가 {recovery_mode} 면 "
                          f"ttl_seconds 가 필요하다")

    return ActionPolicy(
        action_type=action_type,
        action_risk=risk,
        performs_action=_as_bool(raw["performs_action"],
                                 f"actions.{action_type}.performs_action"),
        requires_approval=requires_approval,
        auto_execute=auto_execute,
        executor_ready=_as_bool(raw["executor_ready"],
                                f"actions.{action_type}.executor_ready"),
        notify=str(raw["notify"]),
        description=str(raw.get("description", "")),
        min_confidence=min_conf,
        auto_threat_levels=threat_levels,
        requires_targets=_as_bool(raw.get("requires_targets", False),
                                  f"actions.{action_type}.requires_targets"),
        ttl_seconds=ttl,
        recovery_required=recovery_required,
        evidence_required=_as_tuple(raw.get("evidence_required"),
                                    f"actions.{action_type}.evidence_required"),
        executor_blocked_reason=(str(raw["executor_blocked_reason"])
                                 if raw.get("executor_blocked_reason") else None),
        recovery_mode=recovery_mode,
    )


def parse_policy(raw) -> PolicyConfig:
    """검증한 PolicyConfig 를 돌려준다. 문제가 있으면 PolicyError."""
    if not isinstance(raw, dict):
        raise PolicyError("정책 파일 최상위는 매핑이어야 한다")

    version = raw.get("version")
    if version != 1:
        raise PolicyError(f"지원하지 않는 정책 version: {version!r} (지원: 1)")

    raw_actions = raw.get("actions")
    if not isinstance(raw_actions, dict) or not raw_actions:
        raise PolicyError("actions 가 비어 있다")

    actions = {}
    for name, body in raw_actions.items():
        key = str(name).upper()
        actions[key] = parse_action_policy(key, body)

    missing = [a for a in _REQUIRED_ACTIONS if a not in actions]
    if missing:
        raise PolicyError(f"필수 조치 정책 누락: {missing}")

    raw_threats = raw.get("threat_levels")
    if not isinstance(raw_threats, dict):
        raise PolicyError("threat_levels 가 비어 있다")
    threat_levels = {}
    for name, body in raw_threats.items():
        level = str(name).lower()
        if level not in THREAT_LEVELS:
            raise PolicyError(f"threat_levels.{name}: 알 수 없는 단계")
        if not isinstance(body, dict) or "urgency" not in body:
            raise PolicyError(f"threat_levels.{level}: urgency 가 필요하다")
        threat_levels[level] = ThreatPolicy(
            urgency=str(body["urgency"]),
            mention=_as_bool(body.get("mention", False),
                             f"threat_levels.{level}.mention"),
        )
    missing_levels = [t for t in THREAT_LEVELS if t not in threat_levels]
    if missing_levels:
        raise PolicyError(f"threat_levels 누락: {missing_levels} (4단계 모두 필요)")

    raw_unsupported = raw.get("unsupported") or {}
    if not isinstance(raw_unsupported, dict):
        raise PolicyError("unsupported 는 매핑이어야 한다")
    unsupported = {str(k).upper(): str(v) for k, v in raw_unsupported.items()}

    overlap = sorted(set(actions) & set(unsupported))
    if overlap:
        raise PolicyError(f"actions 와 unsupported 에 같은 조치가 있다: {overlap}")

    raw_networks = raw.get("networks") or {}
    if not isinstance(raw_networks, dict):
        raise PolicyError("networks 는 매핑이어야 한다")
    isolate = _as_tuple(raw_networks.get("isolate"), "networks.isolate")
    preserve = _as_tuple(raw_networks.get("preserve"), "networks.preserve")
    both = sorted(set(isolate) & set(preserve))
    if both:
        raise PolicyError(f"networks: 같은 이름이 isolate 와 preserve 에 있다: {both}")
    # ISOLATE 를 실행 가능으로 둔 채 격리 대상 네트워크를 지정하지 않으면, 실행
    # 시점에 "끊을 대상이 없다" 로 전부 막힌다. 정책 작성 실수를 로드에서 잡는다.
    isolate_policy = actions.get("ISOLATE")
    if isolate_policy is not None and isolate_policy.executor_ready and not isolate:
        raise PolicyError("networks.isolate 가 비어 있는데 ISOLATE 가 executor_ready 다")

    return PolicyConfig(version=version, actions=actions,
                        unsupported=unsupported, threat_levels=threat_levels,
                        networks=NetworkPolicy(isolate=isolate, preserve=preserve))
