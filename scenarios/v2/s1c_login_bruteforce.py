"""
S1-c — 인증 공격 (로그인 대입) (scenarios-v2).

주입: backend 로그인에 대상 계정으로 오답 비밀번호를 반복 POST 한다. 앱은 401
  invalid_credentials 를 돌려주고 "[AUTH] 로그인 실패 loginId=.. reason=wrong_password" 를
  정상적으로 로그에 남긴다(자기신고 아님 — 앱의 실제 인증 실패 로그).
탐지: 룰 작성은 팀원 몫(THREAT_SPEC.md). 증거는 앱의 실제 인증 실패 로그다.
정리: 앱에 계정 잠금·시도 제한 로직이 없어 상태 변화가 없다 → 원복 불필요. DB 실데이터 불변.

강도(strength): 주입 횟수는 **룰 임계가 아니라 현실적인 공격 볼륨**으로 정한다.
  - weak   : 저속·조심스러운 수동/저빈도 추측(볼륨 탐지 회피 시도).
  - medium : 기본적인 스크립트 대입 버스트.
  - strong : 공격적인 크리덴셜 스터핑.

안전: 실제 사용자 비밀번호를 쓰지 않는다. 대상은 전용 테스트 계정(seed)으로 두고 env 로 바꾼다.
미확정(측정 PC): 로그인 경로(S1C_LOGIN_PATH)와 요청 본문 형식을 확정한다.

순수 로직(요청 계획)은 단위 테스트, HTTP 실행은 UNVERIFIED.
"""

from __future__ import annotations

import json
import os
import urllib.request

BASE_URL = os.getenv("S1C_BASE_URL", "http://127.0.0.1:80")
LOGIN_PATH = os.getenv("S1C_LOGIN_PATH", "/api/auth/login")   # 측정 PC에서 확정
TARGET_LOGIN_ID = os.getenv("S1C_LOGIN_ID", "s1c_test")       # 전용 테스트 계정(실사용자 금지)

# 오답 비밀번호 목록(실제 자격증명 아님).
WRONG_PASSWORDS = ["wrong1", "wrong2", "guess3", "guess4", "nope5", "nope6"]

# 강도별 로그인 시도 횟수. 근거는 룰 임계가 아니라 현실적인 자동 로그인 대입 볼륨이다:
#   weak=저속 추측, medium=기본 스크립트 버스트, strong=공격적 크리덴셜 스터핑.
STRENGTH_ATTEMPTS = {"weak": 6, "medium": 20, "strong": 60}
DEFAULT_STRENGTH = "medium"

# 정상 인증 실패로 볼 상태코드(앱이 "[AUTH] 로그인 실패" 를 남기는 경우).
FAIL_STATUSES = {401, 400, 403}


# --------------------------------------------------------------------------- #
# 순수 로직 (단위 테스트 대상)
# --------------------------------------------------------------------------- #

def attempts_for(strength: str = DEFAULT_STRENGTH) -> int:
    """강도 → 시도 횟수. 알 수 없는 강도는 오류."""
    if strength not in STRENGTH_ATTEMPTS:
        raise ValueError(f"unknown strength: {strength}")
    return STRENGTH_ATTEMPTS[strength]


def build_attempts(strength: str = DEFAULT_STRENGTH, attempts: int | None = None,
                   login_id: str = TARGET_LOGIN_ID, passwords=WRONG_PASSWORDS) -> list[dict]:
    """
    로그인 시도 본문 목록. 같은 계정에 오답 비밀번호를 순환 적용한다.
    attempts 를 직접 주면 그 값을, 아니면 강도(strength)로 횟수를 정한다.
    """
    n = attempts if attempts is not None else attempts_for(strength)
    if n < 1:
        raise ValueError("attempts 는 1 이상")
    return [{"loginId": login_id, "password": passwords[i % len(passwords)]}
            for i in range(n)]


def is_auth_failure(status: int) -> bool:
    return status in FAIL_STATUSES


# --------------------------------------------------------------------------- #
# HTTP 런타임 (UNVERIFIED — 실행은 측정 PC)
# --------------------------------------------------------------------------- #

def _post(url: str, body: dict, timeout: float = 5.0) -> int:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def inject(strength: str = DEFAULT_STRENGTH, attempts: int | None = None):
    url = f"{BASE_URL}{LOGIN_PATH}"
    bodies = build_attempts(strength=strength, attempts=attempts)
    statuses = [_post(url, b) for b in bodies]
    failures = sum(1 for s in statuses if is_auth_failure(s))
    # loginId 값을 출력에도 남기지 않는다(평문 ID 보호) — 건수만 센다.
    print(f"[S1-c] strength={strength} attempts={len(bodies)} auth_failures={failures}", flush=True)
    return {"strength": strength, "attempts": len(bodies), "auth_failures": failures}


def dry_run() -> dict:
    """HTTP 없이 시도 계획만. loginId 값은 노출하지 않는다(건수·경로만). run --dry-run 용."""
    return {"strength": DEFAULT_STRENGTH, "attempts": len(build_attempts()),
            "login_path": LOGIN_PATH,
            "note": "실제 자격증명 미사용, 전용 테스트 계정, 계정상태 불변"}


def main():
    inject()


if __name__ == "__main__":
    main()
