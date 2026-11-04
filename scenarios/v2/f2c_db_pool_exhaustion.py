"""
F2-c — DB 커넥션 풀 고갈 (scenarios-v2).

위협 정의: DB 연결이 과도하게 점유돼 풀이 고갈된다(데이터 조작 없이 연결만 보유). 정상 요청이
  연결을 얻지 못해 지연·실패하기 시작한다. 증거는 동시 연결 수 상승 + 커넥션 타임아웃 로그다.

주입: DB 에 강도만큼 연결을 열고, 각 연결을 **읽기 전용·유휴**로 붙잡아 둔다(지속 시간 동안).
정리: 보유한 연결을 모두 닫는다 → 풀 회복.

강도(strength): 붙잡는 연결 수. 근거는 룰 임계가 아니라 현실적인 커넥션 누수 규모다:
  weak=소규모 누수, medium=중간, strong=풀을 압박하는 대규모.

데이터 안전: 어떤 쓰기도 하지 않는다. 보유 쿼리는 읽기 전용(SELECT 1)만 쓴다.
자기신고 없음: Loki/pipeline 에 아무것도 쓰지 않는다. 증거는 "실제 연결 점유"뿐이다.

순수 로직(연결 수 산정·쿼리 안전성)은 단위 테스트, 실제 연결은 DB 필요 — UNVERIFIED (측정 PC).
"""

from __future__ import annotations

import os

STRENGTH_CONNECTIONS = {"weak": 15, "medium": 30, "strong": 60}
DEFAULT_STRENGTH = "medium"
DEFAULT_HOLD_SECONDS = 120
HOLD_QUERY = "SELECT 1"                # 읽기 전용 유휴 보유. 데이터 불변.

# 쓰기·DDL 로 간주해 거부할 토큰(안전 가드: 보유 쿼리가 읽기 전용인지 검사).
_WRITE_TOKENS = ("insert", "update", "delete", "drop", "truncate",
                 "alter", "create", "grant", "revoke", "merge")


# --------------------------------------------------------------------------- #
# 순수 로직 (단위 테스트 대상)
# --------------------------------------------------------------------------- #

def plan_connections(strength: str = DEFAULT_STRENGTH,
                     hold_seconds: int = DEFAULT_HOLD_SECONDS) -> dict:
    """강도 → 붙잡을 연결 수와 보유 시간. 알 수 없는 강도는 오류."""
    if strength not in STRENGTH_CONNECTIONS:
        raise ValueError(f"unknown strength: {strength}")
    if hold_seconds < 1:
        raise ValueError("hold_seconds 는 1 이상")
    return {"strength": strength, "connections": STRENGTH_CONNECTIONS[strength],
            "hold_seconds": hold_seconds}


def is_readonly_statement(sql: str) -> bool:
    """보유 쿼리가 읽기 전용인가(안전 가드). 쓰기·DDL 토큰이 있으면 False."""
    low = sql.lower()
    return not any(tok in low for tok in _WRITE_TOKENS)


# --------------------------------------------------------------------------- #
# DB 런타임 (psycopg 필요 — UNVERIFIED)
# --------------------------------------------------------------------------- #

def _dsn() -> str:
    return os.getenv("F2C_DB_DSN", "")   # 측정 PC에서 DSN 지정(실데이터 쓰기 금지)


def inject(strength: str = DEFAULT_STRENGTH, hold_seconds: int = DEFAULT_HOLD_SECONDS):
    """연결을 강도만큼 열어 읽기 전용으로 붙잡는다. 반환 시 cleanup 이 닫는다."""
    import time
    import psycopg
    plan = plan_connections(strength, hold_seconds)
    if not is_readonly_statement(HOLD_QUERY):
        raise SystemExit("[F2-c] 보유 쿼리가 읽기 전용이 아님 — 중단")
    conns = []
    try:
        for _ in range(plan["connections"]):
            c = psycopg.connect(_dsn())
            c.execute(HOLD_QUERY)      # 유휴 보유(데이터 불변)
            conns.append(c)
        print(f"[F2-c] strength={strength} held_connections={len(conns)}", flush=True)
        time.sleep(hold_seconds)
    finally:
        _close_all(conns)
    return plan


def _close_all(conns) -> int:
    closed = 0
    for c in conns:
        try:
            c.close(); closed += 1
        except Exception:
            pass
    return closed


def cleanup(conns=None) -> None:
    """보유 연결을 닫는다(inject 가 finally 로도 닫지만 보강용)."""
    if conns:
        print(f"[F2-c] cleanup: closed={_close_all(conns)}", flush=True)


def dry_run() -> dict:
    return {"plan": plan_connections(), "hold_query": HOLD_QUERY,
            "readonly": is_readonly_statement(HOLD_QUERY)}


def main():
    inject()


if __name__ == "__main__":
    main()
