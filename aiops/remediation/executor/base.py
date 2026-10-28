"""
실행기 인터페이스 (Phase 2).

조치를 "호출했다"와 "실제로 적용됐다"를 구분한다. 이전 구현은 Docker SDK 호출이
예외를 던지지 않은 것만으로 성공을 기록했고, 네트워크를 찾지 못해 아무것도 끊지
않았는데도 "Success: isolated" 를 남겼다. 그래서 모든 조치는 실행 뒤 상태를 다시
조회해 확인하고, 확인되지 않으면 실패로 기록한다.

가역 조치는 짝을 이룬다.
    RESTART   -> (비가역, 사후 상태 확인만)
    PAUSE     <-> UNPAUSE
    ISOLATE   <-> RECONNECT
    THROTTLE  <-> UNTHROTTLE
"""

from __future__ import annotations

from dataclasses import dataclass, field

# 조치
RESTART = "RESTART"
PAUSE = "PAUSE"
UNPAUSE = "UNPAUSE"
ISOLATE = "ISOLATE"
RECONNECT = "RECONNECT"
THROTTLE = "THROTTLE"
UNTHROTTLE = "UNTHROTTLE"

# 복구 조치 매핑 (가역 조치만)
RECOVERY_ACTION = {
    PAUSE: UNPAUSE,
    ISOLATE: RECONNECT,
    THROTTLE: UNTHROTTLE,
}

# 결과 상태
SUCCESS = "SUCCESS"
FAILED = "FAILED"
SKIPPED = "SKIPPED"       # 실행 모드가 disabled — 실행하지 않았다
BLOCKED = "BLOCKED"       # 선행 조건 미충족 (증거 보존 실패, 네트워크 불명확 등)


class ExecutorError(RuntimeError):
    """실행기가 조치를 수행할 수 없다."""


def jsonable(value):
    """JSON 으로 쓸 수 있는 형태로 바꾼다. 모르는 타입은 문자열로 남긴다."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [jsonable(v) for v in value]
    return str(value)


@dataclass(frozen=True)
class ExecutionResult:
    """
    한 대상에 대한 조치 결과.

    verified 는 "조치 뒤 상태를 다시 조회해 의도한 상태임을 확인했다" 는 뜻이다.
    status=SUCCESS 는 verified=True 일 때만 쓴다.
    """
    action: str
    target: str
    status: str
    verified: bool = False
    detail: str = ""
    before: dict = field(default_factory=dict)
    after: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == SUCCESS and self.verified

    def as_dict(self) -> dict:
        # 감사 레코드는 JSON 으로 영속화된다. Docker SDK 가 예상 밖의 타입을 주더라도
        # 기록이 깨지면 안 되므로 직렬화 가능한 형태로 정규화한다.
        return {
            "action": self.action, "target": self.target, "status": self.status,
            "verified": self.verified, "detail": self.detail,
            "before": jsonable(self.before), "after": jsonable(self.after),
        }

    def summary(self) -> str:
        """Slack·로그용 한 줄 요약. 성공을 단정하지 않는다."""
        mark = {SUCCESS: "Success", FAILED: "Fail", SKIPPED: "Skipped",
                BLOCKED: "Blocked"}.get(self.status, self.status)
        return f"{mark}: {self.action} {self.target} — {self.detail}"


def failed(action: str, target: str, detail: str, **kw) -> ExecutionResult:
    return ExecutionResult(action=action, target=target, status=FAILED,
                           verified=False, detail=detail, **kw)


def blocked(action: str, target: str, detail: str, **kw) -> ExecutionResult:
    return ExecutionResult(action=action, target=target, status=BLOCKED,
                           verified=False, detail=detail, **kw)


def skipped(action: str, target: str, detail: str, **kw) -> ExecutionResult:
    return ExecutionResult(action=action, target=target, status=SKIPPED,
                           verified=False, detail=detail, **kw)


def succeeded(action: str, target: str, detail: str, **kw) -> ExecutionResult:
    return ExecutionResult(action=action, target=target, status=SUCCESS,
                           verified=True, detail=detail, **kw)


class Executor:
    """실행기 인터페이스. Phase 3 의 원격 Agent 실행기도 이 형태를 따른다."""

    name = "base"
    # 이 실행기가 실제로 시스템을 바꾸는가. False 면 증거 보존 게이트를 건너뛴다 —
    # 아무것도 바뀌지 않으므로 되돌릴 상태도 없다.
    changes_system = True

    def snapshot(self, target: str) -> dict:
        """조치 전 상태(컨테이너·네트워크·리소스 제한). 실패 시 ExecutorError."""
        raise NotImplementedError

    def execute(self, action: str, target: str, evidence: dict) -> ExecutionResult:
        """조치를 수행하고 상태를 재조회해 확인한다."""
        raise NotImplementedError


class DisabledExecutor(Executor):
    """
    REMEDIATION_MODE=disabled 용. 상태 조회도 하지 않고 아무것도 실행하지 않는다.
    판단·승인·감사 기록은 그대로 남고 결과는 SKIPPED 로 기록된다.
    """

    name = "disabled"
    changes_system = False

    def snapshot(self, target: str) -> dict:
        return {"target": target, "mode": "disabled", "available": False}

    def execute(self, action: str, target: str, evidence: dict) -> ExecutionResult:
        return skipped(action, target,
                       "REMEDIATION_MODE=disabled — 조치를 실행하지 않았다")
