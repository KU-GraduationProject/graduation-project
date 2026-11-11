"""
F2-c — DB 연결 한도 고갈 (scenarios-v2).

위협 정의: 외부 세션이 PostgreSQL **연결 한도(max_connections)**를 소진한다. 앱 커넥션 풀이
  아니라 **DB 서버의 연결 슬롯**이 바닥나 새 연결이 거부된다(too many clients). 미리 연결을
  열어 둔 backend 는 한동안 정상일 수 있다.
  → 조치는 backend 재시작이 아니라 **점유 세션 종료**(이상 조치 KILL_SESSIONS)다.
     (backend 를 재시작하면 점유 세션은 그대로이고, backend 가 DB 에 다시 붙지 못해 악화된다.)

주입: DB 컨테이너 안에서 **로컬 소켓**으로 psql 세션을 열어 `pg_sleep` 으로 유휴 보유한다.
  점유 수는 **런타임에 DB 에서 계산**한다(하드코딩 없음):
    usable = max_connections − superuser_reserved_connections − 현재 연결 수   (비예약 자유 슬롯)
  강도는 위협 기준으로 정의한다(룰 임계가 아님):
    - weak   : usable 의 약 90% 까지 압박(비예약 슬롯 여유 남김 → 아직 거부 없음).
    - medium : usable **전부** 점유 → 비예약 슬롯 소진 → 새 (비superuser)연결 거부.
    - strong : medium 과 같은 수를 **더 빠르게 채우고 더 오래 유지**한다.

안전(중요):
  - 관리용 예약 연결(superuser_reserved_connections)은 **절대 채우지 않는다**. 점유 수를 usable
    이하로 엄격히 제한한다(current + 점유 ≤ max − reserved). usable≤0 이면 주입 중단. 점유 사용자가
    superuser 여도 이 상한이 예약 슬롯을 지킨다. 주입 후 **예약 연결이 비어 있는지** 확인한다.
  - 정리·watchdog 은 **DB 에 새로 접속하지 않는 방식**이 기본이다: 컨테이너 안에서 점유용 psql
    클라이언트를 **라운드별 표식**(argv `mark=connhold-<runid>`)으로 찾아 kill. 같은 표식의 이 라운드
    프로세스만 종료하므로 병렬 실행끼리 섞이지 않는다. pg_terminate_backend 는 보조.
  - backend 를 재시작하지 않는다. 데이터·스키마·DB 설정(pg_hba, postgresql.conf)은 바꾸지 않는다.

자기신고 없음: Loki/pipeline 에 아무것도 쓰지 않는다. 표식 `mark=` 는 psql 클라이언트 argv 에만
  있고 DB 로그(log_line_prefix)에는 없다. 보유 쿼리(pg_sleep)만 로그에 남는다.

순수 로직(슬롯 계산·강도·안전 판정·표식·명령 생성)은 단위 테스트, 실제 연결은 Docker/DB 필요 — UNVERIFIED.
"""

from __future__ import annotations

import os
import secrets
import shlex
import time

from v2 import supervisor

DB_CONTAINER = os.getenv("F2C_DB_CONTAINER", "leafy-db")
DB_NAME = os.getenv("F2C_DB_NAME", "leafy")
MARK_PREFIX = "connhold"               # 라운드별 표식 접두사(mark=connhold-<runid>)

DEFAULT_STRENGTH = "medium"
RECOVER_SLACK = 2                      # 정리 후 연결 수 복귀 판정 여유
DEFAULT_MAX_SECONDS = 420              # watchdog 자동 복구 상한(세션이 멈춰도 복구)
BACKGROUND_DEFAULT = True              # F2-c 는 배경 트래픽 기본 ON(정상 트래픽의 API 실패가 기록됨)

# 강도 = 위협의 모양(룰 임계 아님). fill_fraction=비예약 슬롯 점유 비율, open_interval_s=채우는 속도,
# hold_seconds=유지 시간. medium/strong 은 비예약 슬롯을 전부(1.0) 소진해 새 연결 거부를 노린다.
STRENGTH_PROFILE = {
    "weak":   {"fill_fraction": 0.9, "open_interval_s": 1.0, "hold_seconds": 180},
    "medium": {"fill_fraction": 1.0, "open_interval_s": 0.5, "hold_seconds": 240},
    "strong": {"fill_fraction": 1.0, "open_interval_s": 0.1, "hold_seconds": 360},
}


# --------------------------------------------------------------------------- #
# 순수 로직 (단위 테스트 대상)
# --------------------------------------------------------------------------- #

def usable_slots(max_conn: int, reserved: int, current: int) -> int:
    """비예약 자유 슬롯 = max − 예약 − 현재. 이 값을 넘겨 점유하면 예약을 침범하므로 상한이다."""
    return max_conn - reserved - current


def target_for_strength(usable: int, strength: str = DEFAULT_STRENGTH) -> int:
    """강도 → 점유 목표 수. 항상 usable 이하(예약 슬롯은 건드리지 않는다).
    medium/strong 은 usable 전부를 점유해 비예약 슬롯을 소진(새 연결 거부)한다."""
    if strength not in STRENGTH_PROFILE:
        raise ValueError(f"unknown strength: {strength}")
    if usable <= 0:
        return 0
    return int(usable * STRENGTH_PROFILE[strength]["fill_fraction"])


def rejection_expected(strength: str = DEFAULT_STRENGTH) -> bool:
    """이 강도가 '새 연결 거부'를 노리는가(성공기준). weak 은 압박만, medium/strong 은 거부."""
    if strength not in STRENGTH_PROFILE:
        raise ValueError(f"unknown strength: {strength}")
    return STRENGTH_PROFILE[strength]["fill_fraction"] >= 1.0


def should_abort(usable: int, min_slots: int = 1) -> bool:
    """점유 가능한 비예약 슬롯이 최소치 미만이면 주입하지 않는다."""
    return usable < min_slots


def reserved_untouched(total_now: int, max_conn: int, reserved: int) -> bool:
    """전체 연결이 (max − 예약) 이하면 예약 슬롯은 비어 있다."""
    return total_now <= max_conn - reserved


def connections_recovered(after: int, baseline: int, slack: int = RECOVER_SLACK) -> bool:
    """정리 후 연결 수가 주입 전 수준(+여유) 이하로 돌아왔는가."""
    return after <= baseline + slack


def hold_seconds_for(strength: str = DEFAULT_STRENGTH) -> int:
    """강도별 유지 시간(점유를 이 시간 동안 유지해야 장애가 재현된다)."""
    if strength not in STRENGTH_PROFILE:
        raise ValueError(f"unknown strength: {strength}")
    return STRENGTH_PROFILE[strength]["hold_seconds"]


def new_run_id() -> str:
    """라운드마다 다른 표식용 id(병렬 실행 구분)."""
    return secrets.token_hex(4)


def run_mark(run_id: str) -> str:
    """이번 라운드의 점유 표식. pkill·application_name 에 이 값만 쓴다."""
    return f"{MARK_PREFIX}-{run_id}"


def held_query(hold_seconds: int) -> str:
    """유휴 보유 쿼리(읽기 전용). pg_sleep 으로 세션만 붙잡는다 — 데이터 불변."""
    if hold_seconds < 1:
        raise ValueError("hold_seconds 는 1 이상")
    return f"SELECT pg_sleep({int(hold_seconds)})"


def hold_inner_sh(hold_seconds: int, mark: str, db_name: str = DB_NAME) -> str:
    """컨테이너 안에서 실행할 세션 점유 명령. 로컬 소켓·자격증명 미사용.
    `-v mark=<mark>` 는 psql argv 에 남아 pkill 로 이 라운드만 찾을 수 있다(DB 로그에는 안 남음).
    application_name 도 같은 표식으로 둬 보조 종료(pg_terminate_backend)가 이 라운드만 겨냥한다."""
    return (f'PGAPPNAME={mark} psql -v mark={mark} '
            f'-U "$POSTGRES_USER" -d {db_name} -c "{held_query(hold_seconds)}"')


def hold_session_argv(mark: str, db_container: str = DB_CONTAINER,
                      hold_seconds: int = 180, db_name: str = DB_NAME) -> list[str]:
    """세션 하나를 분리(-d)로 점유하는 docker exec argv."""
    return ["docker", "exec", "-d", db_container, "sh", "-c",
            hold_inner_sh(hold_seconds, mark, db_name)]


def show_argv(setting: str, db_container: str = DB_CONTAINER, db_name: str = DB_NAME) -> list[str]:
    inner = f'psql -tA -U "$POSTGRES_USER" -d {db_name} -c "SHOW {setting}"'
    return ["docker", "exec", db_container, "sh", "-c", inner]


def count_connections_argv(db_container: str = DB_CONTAINER, db_name: str = DB_NAME) -> list[str]:
    inner = ('psql -tA -U "$POSTGRES_USER" -d ' + db_name +
             ' -c "SELECT count(*) FROM pg_stat_activity WHERE backend_type = \'client backend\'"')
    return ["docker", "exec", db_container, "sh", "-c", inner]


def pkill_cleanup_sh(mark: str) -> str:
    """이 라운드 점유용 psql 클라이언트만 표식으로 kill(컨테이너 안, DB 접속 없이)."""
    return f"pkill -f 'mark={mark}' || true"


def pkill_cleanup_argv(mark: str, db_container: str = DB_CONTAINER) -> list[str]:
    return ["docker", "exec", db_container, "sh", "-c", pkill_cleanup_sh(mark)]


def terminate_sql(mark: str) -> str:
    """(보조) 이 라운드 표식의 점유 세션만 종료 — pkill 다음에 보조로만 쓴다."""
    return ("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            f"WHERE application_name = '{mark}' AND pid <> pg_backend_pid()")


def watchdog_restore_sh(mark: str, db_container: str = DB_CONTAINER) -> str:
    """watchdog 복구(호스트 sh): DB 접속 없이 이 라운드 점유 psql 클라이언트만 kill. backend 재시작 안 함."""
    return f"docker exec {db_container} sh -c {shlex.quote(pkill_cleanup_sh(mark))}"


# --------------------------------------------------------------------------- #
# Docker/DB 런타임 (UNVERIFIED — 측정 PC)
# --------------------------------------------------------------------------- #

def _exec_out(container, argv: list[str]) -> str | None:
    try:
        res = container.exec_run(cmd=argv[3:])   # ['sh','-c',inner]
        return (res.output or b"").decode("utf-8", "replace").strip()
    except Exception:
        return None


def _show_int(container, setting: str, db_name: str) -> int | None:
    out = _exec_out(container, show_argv(setting, db_name=db_name))
    return int(out) if out and out.lstrip("-").isdigit() else None


def _count(container, db_name: str) -> int | None:
    out = _exec_out(container, count_connections_argv(db_name=db_name))
    return int(out) if out and out.isdigit() else None


def inject(strength: str = DEFAULT_STRENGTH, db_container: str = DB_CONTAINER,
           db_name: str = DB_NAME, max_seconds: int = DEFAULT_MAX_SECONDS,
           work_dir: str | None = None, background: bool | None = None,
           traffic_gen_path: str | None = None, traffic_target: str | None = None,
           traffic_run_dir: str | None = None):
    """비예약 슬롯까지 세션을 점유. 점유 수는 런타임 계산하고 예약 연결은 건드리지 않는다.
    라운드별 표식으로 띄워 cleanup/watchdog 이 이 라운드만 정리한다."""
    import docker
    if strength not in STRENGTH_PROFILE:
        raise ValueError(f"unknown strength: {strength}")
    container = docker.from_env().containers.get(db_container)

    max_conn = _show_int(container, "max_connections", db_name)
    reserved = _show_int(container, "superuser_reserved_connections", db_name)
    current = _count(container, db_name)
    if None in (max_conn, reserved, current):
        raise SystemExit(f"[F2-c] DB 연결 설정/현황 조회 실패 — 주입 중단 "
                         f"(max={max_conn} reserved={reserved} current={current})")

    usable = usable_slots(max_conn, reserved, current)
    if should_abort(usable):
        raise SystemExit(f"[F2-c] 점유 가능한 비예약 슬롯 없음(usable={usable}) — 주입 중단")
    target = target_for_strength(usable, strength)
    if target > usable:  # 이중 안전: 예약 침범 금지
        raise SystemExit(f"[F2-c] target({target}) > usable({usable}) — 주입 중단")

    prof = STRENGTH_PROFILE[strength]
    hold_seconds = prof["hold_seconds"]
    run_id = new_run_id()
    mark = run_mark(run_id)

    wd = supervisor.spawn_watchdog(watchdog_restore_sh(mark, db_container), max_seconds,
                                   tag=f"f2c-{run_id}", work_dir=work_dir)
    bg = None
    if supervisor.background_enabled(BACKGROUND_DEFAULT, background) and traffic_target:
        bg = supervisor.spawn_background_traffic(traffic_gen_path, traffic_target,
                                                 run_dir=traffic_run_dir,
                                                 duration=hold_seconds + 60)

    inner = hold_inner_sh(hold_seconds, mark, db_name)
    opened = 0
    for _ in range(target):
        container.exec_run(cmd=["sh", "-c", inner], detach=True)
        opened += 1
        if prof["open_interval_s"]:
            time.sleep(prof["open_interval_s"])

    total_after = _count(container, db_name)
    safe = reserved_untouched(total_after, max_conn, reserved) if total_after is not None else None
    print(f"[F2-c] strength={strength} max={max_conn} reserved={reserved} current={current} "
          f"usable={usable} held={opened} total_after={total_after} reserved_untouched={safe} "
          f"rejection_expected={rejection_expected(strength)} mark={mark} hold={hold_seconds}s",
          flush=True)
    meta = {"db_container": db_container, "db_name": db_name, "mark": mark, "run_id": run_id,
            "baseline": current, "max_conn": max_conn, "reserved": reserved, "held": opened,
            "hold_seconds": hold_seconds, "watchdog": wd, "background": bg}
    if safe is False:
        print("[F2-c] 경고: 예약 연결이 점유됨 — 즉시 정리", flush=True)
        cleanup(meta)
        raise SystemExit("[F2-c] 예약 연결 침범 — 중단")
    return meta


def cleanup(meta: dict | None = None, db_container: str = DB_CONTAINER,
            db_name: str = DB_NAME) -> bool:
    """정리: (1) DB 접속 없이 이 라운드 점유 psql 클라이언트 kill → (2) 보조 pg_terminate_backend →
    (3) 연결 수 복귀 확인. watchdog·배경 트래픽도 정리. backend 재시작 안 함."""
    meta = meta or {}
    db_container = meta.get("db_container", db_container)
    db_name = meta.get("db_name", db_name)
    baseline = meta.get("baseline")
    mark = meta.get("mark")
    recovered = False
    try:
        import docker
        container = docker.from_env().containers.get(db_container)
        if mark:
            # (1) 1차: DB 접속 없이 이 라운드 클라이언트 프로세스 종료.
            container.exec_run(cmd=pkill_cleanup_argv(mark, db_container)[3:])
            # (2) 보조: 남은 세션이 있으면 pg_terminate_backend(접속 가능해진 뒤).
            try:
                inner = f'psql -U "$POSTGRES_USER" -d {db_name} -c "{terminate_sql(mark)}"'
                container.exec_run(cmd=["sh", "-c", inner])
            except Exception:
                pass
        after = _count(container, db_name)
        if baseline is not None and after is not None:
            recovered = connections_recovered(after, baseline)
        print(f"[F2-c] cleanup: pkill(mark={mark}) → 연결수 after={after} baseline={baseline} "
              f"recovered={recovered}", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(f"[F2-c] cleanup 실패(watchdog 이 복구함): {exc}", flush=True)
    finally:
        supervisor.cancel_watchdog(meta.get("watchdog"))
        supervisor.stop_background_traffic(meta.get("background"))
    return recovered


def dry_run() -> dict:
    return {"method": "docker exec leafy-db psql (local socket, no cred); 점유 수는 런타임 계산",
            "usable_formula": "max_connections - superuser_reserved_connections - current",
            "strength_profile": STRENGTH_PROFILE,
            "rejection_expected": {s: rejection_expected(s) for s in STRENGTH_PROFILE},
            "cleanup": "pkill -f mark=connhold-<runid> (DB 접속 없음) + 보조 pg_terminate_backend",
            "mark": "connhold-<runid> (라운드별)", "db_container": DB_CONTAINER, "db_name": DB_NAME,
            "watchdog_max_seconds": DEFAULT_MAX_SECONDS, "background_default": BACKGROUND_DEFAULT,
            "restart_backend": False,
            "env": ["F2C_DB_CONTAINER", "F2C_DB_NAME", "V2_WORK_DIR", "V2_TRAFFIC_GEN"]}


def main():
    meta = None
    try:
        meta = inject()
        # 점유를 유지 시간 동안 유지해야 장애가 재현된다(inject 직후 바로 정리하지 않는다).
        time.sleep(hold_seconds_for(DEFAULT_STRENGTH))
    finally:
        cleanup(meta)


if __name__ == "__main__":
    main()
