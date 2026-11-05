"""
F2-c — DB 커넥션 풀 고갈 (scenarios-v2).

위협 정의: DB 연결이 과도하게 점유돼 풀이 고갈된다(데이터 조작 없이 연결만 보유). 정상 요청이
  연결을 얻지 못해 지연·실패하기 시작한다. 증거는 동시 연결 수 상승 + 커넥션 타임아웃 로그다.

주입(측정 PC 결과 반영): **호스트에서 비밀번호로 접속하던 방식 대신**, DB 컨테이너 안에서
  **로컬 소켓**으로 세션을 점유한다 — `docker exec leafy-db psql ...` 로 `SELECT pg_sleep(...)`
  세션을 강도만큼 띄워 유휴 보유한다. 로컬 소켓은 peer/trust 라 **자격 증명을 쓰지 않는다**.
  점유 세션은 중립 application_name(HOLD_APPNAME)으로 표시해 정리 때 정확히 그것만 종료한다.
정리: 표시된 세션을 모두 종료(pg_terminate_backend)하고 **numbackends 가 기준치로 복귀**했는지 확인한다.

강도(strength): 붙잡는 연결 수. 근거는 룰 임계가 아니라 현실적인 커넥션 누수 규모다.
자동 복구: 세션이 멈춰도 max_seconds 뒤 watchdog 이 표시된 세션을 종료한다(supervisor).

데이터 안전: 쓰기 없음 — 보유 쿼리는 읽기 전용(pg_sleep)만. DB 실데이터·스키마 불변.
자기신고 없음: Loki/pipeline 에 아무것도 쓰지 않는다. application_name 은 로그 접두사에 없고
  탐지 입력도 아니다. 증거는 "실제 연결 점유"뿐이다.

순수 로직(연결 수·쿼리 안전성·명령·복구 판정)은 단위 테스트, 실제 연결은 Docker/DB 필요 — UNVERIFIED.
"""

from __future__ import annotations

import os

from v2 import supervisor

DB_CONTAINER = os.getenv("F2C_DB_CONTAINER", "leafy-db")
DB_NAME = os.getenv("F2C_DB_NAME", "leafy")
HOLD_APPNAME = "holdsess"              # 중립 표시(로그 접두사에 없음, 탐지 입력 아님)

STRENGTH_CONNECTIONS = {"weak": 15, "medium": 30, "strong": 60}
DEFAULT_STRENGTH = "medium"
DEFAULT_HOLD_SECONDS = 120
DEFAULT_MAX_SECONDS = 300              # watchdog 자동 복구 상한(세션이 멈춰도 복구)
BACKGROUND_DEFAULT = True              # F2-c 는 배경 트래픽 기본 ON

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


def hold_sql(hold_seconds: int = DEFAULT_HOLD_SECONDS) -> str:
    """유휴 보유 쿼리(읽기 전용). pg_sleep 으로 세션만 붙잡는다 — 데이터 불변."""
    if hold_seconds < 1:
        raise ValueError("hold_seconds 는 1 이상")
    return f"SELECT pg_sleep({int(hold_seconds)})"


def is_readonly_statement(sql: str) -> bool:
    """보유 쿼리가 읽기 전용인가(안전 가드). 쓰기·DDL 토큰이 있으면 False."""
    low = sql.lower()
    return not any(tok in low for tok in _WRITE_TOKENS)


def hold_inner_sh(hold_seconds: int = DEFAULT_HOLD_SECONDS,
                  appname: str = HOLD_APPNAME, db_name: str = DB_NAME) -> str:
    """컨테이너 안에서 실행할 세션 점유 명령. 로컬 소켓·자격증명 미사용.
    DB 사용자/이름은 컨테이너 env(POSTGRES_USER)·인자로만 참조한다(비밀번호 없음)."""
    return (f'PGAPPNAME={appname} psql -v ON_ERROR_STOP=1 '
            f'-U "$POSTGRES_USER" -d {db_name} -c "{hold_sql(hold_seconds)}"')


def hold_session_argv(db_container: str = DB_CONTAINER,
                      hold_seconds: int = DEFAULT_HOLD_SECONDS,
                      appname: str = HOLD_APPNAME, db_name: str = DB_NAME) -> list[str]:
    """세션 하나를 분리(-d)로 점유하는 docker exec argv."""
    return ["docker", "exec", "-d", db_container, "sh", "-c",
            hold_inner_sh(hold_seconds, appname, db_name)]


def terminate_sql(appname: str = HOLD_APPNAME) -> str:
    """표시된 점유 세션만 종료(자기 자신 제외)."""
    return ("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            f"WHERE application_name = '{appname}' AND pid <> pg_backend_pid()")


def numbackends_sql(db_name: str = DB_NAME) -> str:
    return f"SELECT numbackends FROM pg_stat_database WHERE datname = '{db_name}'"


def _psql_argv(sql: str, db_container: str = DB_CONTAINER, db_name: str = DB_NAME) -> list[str]:
    inner = f'psql -tA -U "$POSTGRES_USER" -d {db_name} -c "{sql}"'
    return ["docker", "exec", db_container, "sh", "-c", inner]


def terminate_argv(db_container: str = DB_CONTAINER, appname: str = HOLD_APPNAME,
                   db_name: str = DB_NAME) -> list[str]:
    return _psql_argv(terminate_sql(appname), db_container, db_name)


def numbackends_argv(db_container: str = DB_CONTAINER, db_name: str = DB_NAME) -> list[str]:
    return _psql_argv(numbackends_sql(db_name), db_container, db_name)


def numbackends_recovered(after: int, baseline: int, slack: int = 2) -> bool:
    """정리 후 연결 수가 기준치(+여유) 이하로 돌아왔는가."""
    return after <= baseline + slack


def watchdog_restore_sh(db_container: str = DB_CONTAINER, appname: str = HOLD_APPNAME,
                        db_name: str = DB_NAME) -> str:
    """watchdog 복구 명령(호스트 sh): 컨테이너 안에서 표시된 세션을 종료한다."""
    inner = f'psql -U "$POSTGRES_USER" -d {db_name} -c "{terminate_sql(appname)}"'
    return f"docker exec {db_container} sh -c {_shq(inner)}"


def _shq(s: str) -> str:
    import shlex
    return shlex.quote(s)


# --------------------------------------------------------------------------- #
# Docker/DB 런타임 (UNVERIFIED — 측정 PC)
# --------------------------------------------------------------------------- #

def _exec(container, argv_tail: list[str]):
    """container.exec_run 로 sh -c 실행(argv_tail = ['docker','exec',cname,'sh','-c',inner])."""
    return container.exec_run(cmd=argv_tail[3:])  # ['sh','-c',inner]


def _read_numbackends(container, db_name: str = DB_NAME) -> int | None:
    try:
        res = _exec(container, numbackends_argv(db_name=db_name))
        out = (res.output or b"").decode("utf-8", "replace").strip()
        return int(out) if out.isdigit() else None
    except Exception:
        return None


def inject(strength: str = DEFAULT_STRENGTH, hold_seconds: int = DEFAULT_HOLD_SECONDS,
           max_seconds: int = DEFAULT_MAX_SECONDS, db_container: str = DB_CONTAINER,
           db_name: str = DB_NAME, work_dir: str | None = None,
           background: bool | None = None, traffic_gen_path: str | None = None,
           traffic_target: str | None = None):
    """로컬 소켓 세션을 강도만큼 점유. watchdog·배경 트래픽을 함께 띄운다. cleanup 이 정리한다."""
    import docker
    plan = plan_connections(strength, hold_seconds)
    if not is_readonly_statement(hold_sql(hold_seconds)):
        raise SystemExit("[F2-c] 보유 쿼리가 읽기 전용이 아님 — 중단")
    client = docker.from_env()
    container = client.containers.get(db_container)
    baseline = _read_numbackends(container, db_name)

    wd = supervisor.spawn_watchdog(watchdog_restore_sh(db_container, db_name=db_name),
                                   max_seconds, tag="f2c", work_dir=work_dir)
    bg = None
    if supervisor.background_enabled(BACKGROUND_DEFAULT, background) and traffic_target:
        bg = supervisor.spawn_background_traffic(traffic_gen_path, traffic_target)

    opened = 0
    inner = hold_inner_sh(hold_seconds, HOLD_APPNAME, db_name)
    for _ in range(plan["connections"]):
        container.exec_run(cmd=["sh", "-c", inner], detach=True)
        opened += 1
    print(f"[F2-c] strength={strength} held_sessions={opened} baseline_numbackends={baseline}",
          flush=True)
    return {"plan": plan, "db_container": db_container, "db_name": db_name,
            "appname": HOLD_APPNAME, "baseline": baseline, "watchdog": wd, "background": bg}


def cleanup(meta: dict | None = None, db_container: str = DB_CONTAINER,
            db_name: str = DB_NAME) -> bool:
    """표시된 세션 종료 → numbackends 복귀 확인. watchdog·배경 트래픽도 정리."""
    meta = meta or {}
    db_container = meta.get("db_container", db_container)
    db_name = meta.get("db_name", db_name)
    baseline = meta.get("baseline")
    recovered = False
    try:
        import docker
        container = docker.from_env().containers.get(db_container)
        _exec(container, terminate_argv(db_container, meta.get("appname", HOLD_APPNAME), db_name))
        after = _read_numbackends(container, db_name)
        if baseline is not None and after is not None:
            recovered = numbackends_recovered(after, baseline)
        print(f"[F2-c] cleanup: 세션 종료, numbackends after={after} baseline={baseline} "
              f"recovered={recovered}", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(f"[F2-c] cleanup 실패(watchdog 이 복구함): {exc}", flush=True)
    finally:
        supervisor.cancel_watchdog(meta.get("watchdog"))
        supervisor.stop_background_traffic(meta.get("background"))
    return recovered


def dry_run() -> dict:
    return {"plan": plan_connections(), "method": "docker exec leafy-db psql (local socket, no cred)",
            "hold_sql": hold_sql(), "readonly": is_readonly_statement(hold_sql()),
            "appname": HOLD_APPNAME, "db_container": DB_CONTAINER, "db_name": DB_NAME,
            "watchdog_max_seconds": DEFAULT_MAX_SECONDS, "background_default": BACKGROUND_DEFAULT,
            "env": ["F2C_DB_CONTAINER", "F2C_DB_NAME", "V2_WORK_DIR", "V2_TRAFFIC_GEN"]}


def main():
    meta = None
    try:
        meta = inject()
    finally:
        cleanup(meta)


if __name__ == "__main__":
    main()
