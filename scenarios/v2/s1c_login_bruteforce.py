"""
S1-c — 인증 공격 (로그인 대입) (scenarios-v2).

주입: backend 로그인에 대상 계정으로 오답 비밀번호를 반복 POST 한다. 앱은 401
  invalid_credentials 를 돌려주고 "[AUTH] 로그인 실패 loginId=.. reason=wrong_password" 를
  정상적으로 로그에 남긴다(자기신고 아님 — 앱의 실제 인증 실패 로그).
탐지: 신설 LoginBruteForce 룰(2분 내 실패 >5). loginId 는 경보 라벨로 올리지 않는다(평문 ID 보호).
정리: 앱에 계정 잠금·시도 제한 로직이 없어 상태 변화가 없다 → 원복 불필요. DB 실데이터 불변.

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

# 오답 비밀번호 목록(실제 자격증명 아님). LoginBruteForce 임계(>5/2m)를 넘기려 반복한다.
WRONG_PASSWORDS = ["wrong1", "wrong2", "guess3", "guess4", "nope5", "nope6"]
DEFAULT_ATTEMPTS = 20   # LoginBruteForce 임계(2분>5)의 4배 — 사용자 조건 '최소 3배 이상'.
                        # 시도는 연속 전송이라 2분 창 안에 모두 들어간다.

# 정상 인증 실패로 볼 상태코드(앱이 "[AUTH] 로그인 실패" 를 남기는 경우).
FAIL_STATUSES = {401, 400, 403}


# --------------------------------------------------------------------------- #
# 순수 로직 (단위 테스트 대상)
# --------------------------------------------------------------------------- #

def build_attempts(attempts: int = DEFAULT_ATTEMPTS, login_id: str = TARGET_LOGIN_ID,
                   passwords=WRONG_PASSWORDS) -> list[dict]:
    """attempts 개의 로그인 시도 본문. 같은 계정에 오답 비밀번호를 순환 적용한다."""
    if attempts < 1:
        raise ValueError("attempts 는 1 이상")
    return [{"loginId": login_id, "password": passwords[i % len(passwords)]}
            for i in range(attempts)]


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


def inject(attempts: int = DEFAULT_ATTEMPTS):
    url = f"{BASE_URL}{LOGIN_PATH}"
    bodies = build_attempts(attempts)
    statuses = [_post(url, b) for b in bodies]
    failures = sum(1 for s in statuses if is_auth_failure(s))
    # loginId 값을 출력에도 남기지 않는다(평문 ID 보호) — 건수만 센다.
    print(f"[S1-c] attempts={len(bodies)} auth_failures={failures}", flush=True)
    return {"attempts": len(bodies), "auth_failures": failures}


def dry_run() -> dict:
    """HTTP 없이 시도 계획만. loginId 값은 노출하지 않는다(건수·경로만). run --dry-run 용."""
    return {"attempts": len(build_attempts()), "login_path": LOGIN_PATH,
            "note": "실제 자격증명 미사용, 전용 테스트 계정, 계정상태 불변"}


def main():
    inject()


if __name__ == "__main__":
    main()
