"""
S2-e — DB 대량 조회 (scenarios-v2, 2차).

위협 정의: 탈취한 DB 자격증명(또는 침해된 서비스)으로 **테이블 전체를 반복해서 읽어 간다**(수집 단계).
  쓰기·스키마 변경은 없고, 평소보다 훨씬 많은 행 반환·순차 스캔이 짧은 시간에 몰린다.
대조: C-h(정상 관리 작업 — 백업 1회).

주입: F2-c 와 **같은 접속 방식**(v2.f2c_runtime Target/Psql — 명시적 대상·클러스터 확인 토큰 필수,
  비밀번호는 PGPASSFILE 경로로만, argv·로그에 값 없음)으로 일반 세션 사용자로 접속해
  `BEGIN TRANSACTION READ ONLY` 안에서 public 테이블 전체 SELECT(결과는 해시 한 줄로 축약)를 반복한다.
  SQL 은 assert_read_only 로 쓰기·DDL 키워드를 거부한 뒤에만 보낸다. DB 실데이터 불변.
정리: 반복을 멈추면 끝(세션은 쿼리마다 열고 닫음). 워치독이 최대 시간 뒤 주입 프로세스를 끊는다.

강도(현실적인 수집 속도): strong=쉬지 않는 연속 스캔, medium=수 초 간격, weak=느린 은닉 수집.
"""

from __future__ import annotations

import os
import re

from v2 import supervisor

STRENGTH_INTERVAL = {"weak": 15.0, "medium": 2.0, "strong": 0.0}
DEFAULT_STRENGTH = "medium"
DEFAULT_DURATION_SECONDS = 300
DEFAULT_MAX_SECONDS = 600
BACKGROUND_DEFAULT = True
APP_NAME = "psql"            # 중립 application_name

_WRITE = re.compile(r"(?i)\b(insert|update|delete|merge|drop|alter|truncate|create|grant|revoke|"
                    r"copy|vacuum|reindex|cluster|lock|call|do|comment|security|set\s+role)\b")

LIST_TABLES_SQL = ("SELECT json_build_object('t', coalesce(json_agg(table_name ORDER BY table_name), "
                   "'[]'::json)) FROM information_schema.tables "
                   "WHERE table_schema = 'public' AND table_type = 'BASE TABLE'")


def assert_read_only(sql: str) -> str:
    """쓰기·DDL·권한 변경 키워드가 있으면 거부. 통과한 SQL 만 반환."""
    if _WRITE.search(sql):
        raise ValueError("읽기 전용이 아닌 SQL 거부")
    return sql


def scan_sql(table: str) -> str:
    """READ ONLY 트랜잭션 안에서 테이블 전체를 읽고 해시 한 줄만 돌려받는다."""
    from v2.f2c_runtime import identifier
    t = identifier(table)
    return assert_read_only(
        "BEGIN TRANSACTION READ ONLY; "
        f"SELECT md5(coalesce(string_agg(x::text, ''), '')) FROM public.\"{t}\" x; COMMIT;")


def plan_reads(strength: str = DEFAULT_STRENGTH, duration_seconds: int = DEFAULT_DURATION_SECONDS,
               interval_seconds: float | None = None) -> dict:
    if strength not in STRENGTH_INTERVAL:
        raise ValueError(f"unknown strength: {strength}")
    if duration_seconds < 1:
        raise ValueError("duration_seconds 는 1 이상")
    iv = STRENGTH_INTERVAL[strength] if interval_seconds is None else interval_seconds
    return {"strength": strength, "interval_seconds": iv, "duration_seconds": duration_seconds}


def inject(strength: str = DEFAULT_STRENGTH, duration_seconds: int = DEFAULT_DURATION_SECONDS,
           interval_seconds: float | None = None, max_seconds: int = DEFAULT_MAX_SECONDS,
           work_dir: str | None = None, background: bool | None = None,
           traffic_gen_path: str | None = None, traffic_target: str | None = None):
    import time

    from v2.f2c_runtime import Psql, Target
    plan = plan_reads(strength, duration_seconds, interval_seconds)
    target = Target.from_env()               # 확인 토큰 불일치면 여기서 중단
    psql = Psql(target)
    tables = psql.query(assert_read_only(LIST_TABLES_SQL), user=target.user, app=APP_NAME)["t"]
    if not tables:
        raise RuntimeError("읽을 테이블 없음 — 중단")
    wd = supervisor.spawn_watchdog(f"kill {os.getpid()} 2>/dev/null; true",
                                   max(max_seconds, duration_seconds + 60), tag="s2e",
                                   work_dir=work_dir)
    bg = None
    if supervisor.background_enabled(BACKGROUND_DEFAULT, background) and traffic_target:
        bg = supervisor.spawn_background_traffic(traffic_gen_path, traffic_target)
    scans = fails = 0
    try:
        end = time.time() + plan["duration_seconds"]
        while time.time() < end:
            for t in tables:
                r = psql.execute(scan_sql(t), user=target.user, app=APP_NAME)
                scans += 1
                fails += 1 if r.returncode else 0
            time.sleep(plan["interval_seconds"])
        # 테이블 이름·결과는 출력하지 않는다 — 건수만.
        print(f"[S2-e] strength={strength} tables={len(tables)} scans={scans} failed={fails}", flush=True)
        return {"plan": plan, "tables": len(tables), "scans": scans, "failed": fails}
    finally:
        supervisor.cancel_watchdog(wd)
        supervisor.stop_background_traffic(bg)


def dry_run() -> dict:
    return {"plan": plan_reads(), "sql_preview": scan_sql("example_table"),
            "transport": "v2.f2c_runtime (F2-c 와 같은 접속·확인 토큰)",
            "env": ["F2C_DB_MODE", "F2C_DB_NAME", "F2C_ADMIN_USER", "F2C_DB_USER",
                    "F2C_EXPECTED_SYSTEM_ID", "F2C_DB_HOST", "F2C_DB_PORT", "F2C_DB_CONTAINER",
                    "F2C_PGPASSFILE", "F2C_CONFIRM_TARGET", "V2_WORK_DIR", "V2_TRAFFIC_GEN"],
            "pair_control": "c_h_admin_backup",
            "note": "READ ONLY 트랜잭션·쓰기/DDL 키워드 거부, 결과는 해시 한 줄"}


def main(**kw):
    return inject(**kw)


if __name__ == "__main__":
    main()
