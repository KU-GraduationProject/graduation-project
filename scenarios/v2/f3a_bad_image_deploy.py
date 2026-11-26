"""
F3-a — 잘못된 이미지 배포 (scenarios-v2).

위협 정의: 서비스가 깨진 이미지/설정으로 배포돼 기동에 실패한다(crashloop 또는 헬스 실패).
  증거는 반복 재시작 또는 기동/헬스 실패 로그다.

주입 방식(스키마 안전):
  - **원본 이미지 고정**: 재생성은 capture_original 로 기록한 **원본 이미지(태그·digest)** 그대로
    쓰고, 명령/엔트리포인트만 실패하게 덮어쓴다. 다른 앱 버전 이미지·태그로 띄우지 않는다.
    (backend 는 ddl-auto=update — 다른 버전이 뜨면 Hibernate 가 스키마를 바꿀 수 있다.)
    재생성 이미지가 원본과 다르면 assert_recreate_image 가 **주입을 중단**한다.
  - crashloop        : 즉시 비정상 종료 → 재시작 반복(앱 미기동).
  - healthcheck-fail : 떠 있지만 서비스를 열지 않아 헬스가 계속 실패(앱 미기동 → ddl-auto 안 돎).
  두 양상 모두 Spring 앱이 기동하지 않으므로 Hibernate ddl-auto 가 실행되지 않는다.

실행 전 DB 백업(필수):
  - 주입 전에 pg_dump 커스텀 포맷(-Fc)으로 **저장소 밖**(backup_dir) 에 백업하고,
    pg_restore --list 로 유효성을 확인한다. 실패하면 **주입하지 않고 중단**한다.
  - 자격증명은 **컨테이너 env 로만** 참조한다(.env 직접 읽지 않음). 값은 로그·출력·파일에 남기지 않는다.
  - 기록은 파일명·크기·소요 시간만. 복원은 자동으로 하지 않고 명령만 안내로 출력한다.

정리: 원본 이미지/명령으로 재배포(완전 가역) 후 **원본 복귀·healthy 를 확인**한다.
  상태 저장 서비스(DB·MinIO)는 대상에서 제외한다 — 데이터 볼륨 무변경.

자기신고 없음: Loki/pipeline 에 아무것도 쓰지 않는다. 증거는 "실제 기동 실패"뿐이다.

순수 로직(실패 명령, 원본 기록, 이미지 가드, 백업 명령·검증)은 단위 테스트,
재생성·백업 실행은 Docker/DB 필요 — UNVERIFIED.
"""

from __future__ import annotations

import os
import re
import shlex

from v2 import supervisor

DEFAULT_TARGET = os.getenv("F3A_TARGET", "leafy-backend")
# 상태 저장 서비스는 대상에서 제외(데이터 안전).
FORBIDDEN_TARGETS = ("leafy-db", "leafy-minio")

MODES = ("crashloop", "healthcheck-fail")
DEFAULT_MODE = "crashloop"
DEFAULT_DURATION_SECONDS = 180

# DB 백업 대상(컨테이너·DB명). 자격증명은 컨테이너 env(POSTGRES_USER/PASSWORD/DB)로만 참조.
DB_CONTAINER = os.getenv("F3A_DB_CONTAINER", "leafy-db")

# DB 접속 모드. 측정 PC 앱 DB 는 Windows 호스트 PostgreSQL 이므로 기본 host.
# container 는 기존 docker exec 경로를 옵션으로 남긴다(SCEN_DB_MODE=container|host).
DB_MODE = os.getenv("SCEN_DB_MODE", os.getenv("F2C_DB_MODE", "host"))
_HOST_RE = re.compile(r"[A-Za-z0-9_.:-]+")
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

DEFAULT_MAX_SECONDS = 300    # watchdog 자동 복구 상한(세션이 멈춰도 복구)
BACKGROUND_DEFAULT = True    # F3-a 는 배경 트래픽 기본 ON
COMPOSE_DIR = os.getenv("V2_COMPOSE_DIR", ".")   # watchdog 복구(compose up --force-recreate) 실행 위치


# --------------------------------------------------------------------------- #
# 순수 로직 (단위 테스트 대상)
# --------------------------------------------------------------------------- #

def failing_command(mode: str = DEFAULT_MODE) -> list[str]:
    """실패 양상 → 컨테이너 엔트리 명령(원본 이미지 위에 덮어씀)."""
    if mode == "crashloop":
        return ["sh", "-c", "exit 1"]                 # 즉시 비정상 종료 → 재시작 반복
    if mode == "healthcheck-fail":
        return ["sh", "-c", "sleep infinity"]         # 떠 있지만 서비스 미개방 → 헬스 실패
    raise ValueError(f"unknown mode: {mode}")


def assert_target_allowed(target: str) -> None:
    """상태 저장 서비스는 대상 금지(데이터 안전 가드)."""
    if target in FORBIDDEN_TARGETS:
        raise ValueError(f"대상 금지(상태 저장 서비스): {target}")


def capture_original(container_attrs: dict) -> dict:
    """정리 때 복원할 원본 배포 정보. 이미지(태그)·이미지 id(digest)·엔트리·명령 보관."""
    cfg = container_attrs.get("Config", {})
    return {"image": cfg.get("Image"),
            "image_id": container_attrs.get("Image"),   # sha256 digest id
            "entrypoint": cfg.get("Entrypoint"),
            "cmd": cfg.get("Cmd")}


def assert_recreate_image(original: dict, recreate_image: str,
                          recreate_image_id: str | None = None) -> None:
    """재생성 이미지가 원본(태그·digest)과 같은지 단언. 다르면 중단(태그 변경 금지)."""
    if recreate_image != original.get("image"):
        raise ValueError(
            f"재생성 이미지가 원본과 다름 — 주입 중단: {recreate_image} != {original.get('image')}")
    if (recreate_image_id is not None and original.get("image_id") is not None
            and recreate_image_id != original.get("image_id")):
        raise ValueError("재생성 이미지 digest 가 원본과 다름 — 주입 중단")


def pg_dump_argv(db_container: str = DB_CONTAINER) -> list[str]:
    """컨테이너 안에서 custom 포맷(-Fc)으로 덤프를 stdout 으로 낸다.
    자격증명은 컨테이너 env(POSTGRES_*)로만 참조 — 값은 argv/로그에 들어가지 않는다."""
    inner = ('PGPASSWORD="$POSTGRES_PASSWORD" '
             'pg_dump -Fc -U "$POSTGRES_USER" -d "$POSTGRES_DB"')
    return ["docker", "exec", db_container, "sh", "-c", inner]


def pg_restore_list_argv(db_container: str = DB_CONTAINER) -> list[str]:
    """덤프 유효성 확인: pg_restore --list (덤프는 stdin 으로 입력)."""
    return ["docker", "exec", "-i", db_container, "pg_restore", "--list"]


def verify_backup(dump_returncode: int, list_returncode: int, list_output: str) -> None:
    """백업·검증 실패면 예외 → 주입 중단."""
    if dump_returncode != 0:
        raise RuntimeError("pg_dump 실패 — 주입 중단")
    if list_returncode != 0 or not (list_output or "").strip():
        raise RuntimeError("백업 검증(pg_restore --list) 실패 — 주입 중단")


def restore_hint(backup_path: str, db_container: str = DB_CONTAINER) -> str:
    """복원은 자동으로 하지 않는다 — 수동 명령만 안내. 자격증명은 컨테이너 env 참조."""
    return (f"복원(수동): docker exec -i {db_container} "
            f"sh -c 'PGPASSWORD=\"$POSTGRES_PASSWORD\" pg_restore -U \"$POSTGRES_USER\" "
            f"-d \"$POSTGRES_DB\" --clean --if-exists' < {backup_path}")


def restored_healthy(container_attrs: dict) -> bool:
    """복원된 컨테이너가 Running 이고, healthcheck 가 있으면 healthy 인지."""
    state = container_attrs.get("State", {})
    if not state.get("Running"):
        return False
    health = state.get("Health")
    if health:
        return health.get("Status") == "healthy"
    return True


# --------------------------------------------------------------------------- #
# 실행 전 DB 백업 프리플라이트 (UNVERIFIED — Docker/DB 필요)
# --------------------------------------------------------------------------- #

def host_db_conn() -> dict:
    """호스트 모드 백업 접속값(SCEN_ 우선, F2C_ 대체). 비밀번호는 PGPASSFILE 로만.

    SCEN_PGDATABASE 와 백업 역할(SCEN_PGADMIN, 없으면 SCEN_PGUSER)이 없으면 거부한다.
    """
    host = os.getenv("SCEN_PGHOST") or os.getenv("F2C_DB_HOST") or "host.docker.internal"
    port = os.getenv("SCEN_PGPORT") or os.getenv("F2C_DB_PORT") or "5432"
    database = os.getenv("SCEN_PGDATABASE") or os.getenv("F2C_DB_NAME")
    # 백업(pg_dump)은 전체 객체(시퀀스 포함)를 읽어야 하므로 운영자(관리자) 역할로 접속한다.
    # 일반 앱 사용자는 시퀀스 권한이 없어 pg_dump 가 실패한다(C-h 는 정상 관리 작업).
    user = (os.getenv("SCEN_PGADMIN") or os.getenv("F2C_ADMIN_USER")
            or os.getenv("SCEN_PGUSER") or os.getenv("F2C_DB_USER"))
    passfile = (os.getenv("SCEN_PGPASSFILE") or os.getenv("F2C_PGPASSFILE")
                or os.getenv("PGPASSFILE"))
    if not database or not user:
        raise RuntimeError("host 모드 백업: SCEN_PGDATABASE 와 백업 역할(SCEN_PGADMIN/SCEN_PGUSER) 필요")
    if not (_HOST_RE.fullmatch(host) and not host.startswith("-") and str(port).isdigit()
            and _IDENT_RE.fullmatch(user) and _IDENT_RE.fullmatch(database)):
        raise RuntimeError("host 모드 백업: 접속값 형식 오류")
    return {"host": host, "port": str(int(port)), "database": database, "user": user,
            "passfile": passfile, "pg_dump": os.getenv("SCEN_PG_DUMP", "pg_dump"),
            "pg_restore": os.getenv("SCEN_PG_RESTORE", "pg_restore")}


def pg_dump_host_argv(conn: dict) -> list[str]:
    """호스트 TCP 로 custom(-Fc) 덤프. -w 로 프롬프트 금지 — 비밀번호는 argv 에 없다."""
    return [conn["pg_dump"], "-Fc", "-w", "-h", conn["host"], "-p", conn["port"],
            "-U", conn["user"], "-d", conn["database"]]


def pg_restore_list_host_argv(conn: dict) -> list[str]:
    """덤프 유효성 확인(pg_restore --list). 덤프는 stdin 으로 입력."""
    return [conn["pg_restore"], "--list"]


def host_env(conn: dict) -> dict:
    """PGPASSFILE 만 비밀번호 경로로 전달. PGPASSWORD 는 제거(값 노출 방지)."""
    env = {k: v for k, v in os.environ.items() if k != "PGPASSWORD"}
    env["PGCONNECT_TIMEOUT"] = "5"
    if conn.get("passfile"):
        env["PGPASSFILE"] = conn["passfile"]
    return env


def host_restore_hint(backup_path: str, conn: dict) -> str:
    """복원은 자동으로 하지 않는다 — 수동 명령만 안내. 비밀번호는 PGPASSFILE 로."""
    return (f"복원(수동, host): {conn['pg_restore']} -w -h {conn['host']} -p {conn['port']} "
            f"-U {conn['user']} -d {conn['database']} --clean --if-exists {backup_path}")


def preflight_backup(backup_dir: str, db_container: str = DB_CONTAINER,
                     mode: str | None = None) -> dict:
    """주입 전 DB 백업. 저장소 밖(backup_dir)에 -Fc 덤프 → pg_restore --list 검증.

    mode=host(기본): 호스트 TCP pg_dump(비밀번호는 PGPASSFILE 로만, argv 에 값 없음).
    mode=container: 기존 docker exec 경로(컨테이너 env 로만). 실패하면 예외(주입 중단).
    자격증명 값은 로그·출력·파일명에 남기지 않는다.
    """
    import subprocess
    import time

    mode = mode or DB_MODE
    conn = host_db_conn() if mode == "host" else None
    os.makedirs(backup_dir, exist_ok=True)
    fname = f"leafy-{time.strftime('%Y%m%d-%H%M%S')}.dump"
    path = os.path.join(backup_dir, fname)

    if mode == "host":
        dump_argv, list_argv, run_env = pg_dump_host_argv(conn), pg_restore_list_host_argv(conn), host_env(conn)
    else:
        dump_argv, list_argv, run_env = pg_dump_argv(db_container), pg_restore_list_argv(db_container), None

    t0 = time.time()
    with open(path, "wb") as fh:
        dump = subprocess.run(dump_argv, stdout=fh, stderr=subprocess.DEVNULL, env=run_env)
    elapsed = round(time.time() - t0, 1)

    with open(path, "rb") as fh:
        chk = subprocess.run(list_argv, stdin=fh, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True, env=run_env)
    try:
        verify_backup(dump.returncode, chk.returncode, chk.stdout)
    except Exception:
        # 불완전한 덤프는 남기지 않는다(유효 백업 오인 방지).
        if os.path.exists(path):
            os.remove(path)
        raise

    size = os.path.getsize(path)
    hint = host_restore_hint(path, conn) if mode == "host" else restore_hint(path, db_container)
    # 자격증명 값은 출력하지 않는다 — 파일명·크기·소요 시간만.
    print(f"[F3-a] DB 백업 OK: mode={mode} file={fname} size={size}B elapsed={elapsed}s", flush=True)
    print(f"[F3-a] {hint}", flush=True)
    return {"path": path, "file": fname, "size": size, "elapsed_s": elapsed, "mode": mode}


# --------------------------------------------------------------------------- #
# docker 런타임 (UNVERIFIED)
# --------------------------------------------------------------------------- #

def watchdog_restore_sh(target: str = DEFAULT_TARGET, compose_dir: str = COMPOSE_DIR) -> str:
    """watchdog 복구 명령(호스트 sh): 원본 이미지로 compose 재생성(F3-a 복구 = 원본 재배포)."""
    return (f"cd {shlex.quote(compose_dir)} && "
            f"docker compose up -d --force-recreate {shlex.quote(target)}")


def inject(mode: str = DEFAULT_MODE, target: str = DEFAULT_TARGET,
           duration_seconds: int = DEFAULT_DURATION_SECONDS,
           backup_dir: str | None = None, max_seconds: int = DEFAULT_MAX_SECONDS,
           compose_dir: str = COMPOSE_DIR, work_dir: str | None = None,
           background: bool | None = None, traffic_gen_path: str | None = None,
           traffic_target: str | None = None):
    """
    (1) 실행 전 DB 백업(필수) → (2) 원본 기록 → (3) 원본 이미지 고정 단언 → (4) watchdog·배경 →
    (5) 실패 명령 덮어쓰기. 재생성은 측정 PC에서 compose 기반으로 하는 것을 권장.
    """
    import docker

    assert_target_allowed(target)
    backup_dir = backup_dir or os.environ.get("F3A_BACKUP_DIR")
    if not backup_dir:
        raise ValueError("backup_dir(저장소 밖 백업 경로) 필요 — DB 백업 없이 주입 금지")

    client = docker.from_env()
    container = client.containers.get(target)
    original = capture_original(container.attrs)

    # 실행 전 DB 백업(실패 시 여기서 중단 — 주입 안 함).
    backup = preflight_backup(backup_dir)

    # 재생성은 '원본 이미지 + 명령/엔트리포인트 덮어쓰기'로만. 이미지 교체 금지.
    recreate_image = original["image"]
    assert_recreate_image(original, recreate_image, original.get("image_id"))

    # 자동 복구 watchdog + 배경 트래픽.
    wd = supervisor.spawn_watchdog(watchdog_restore_sh(target, compose_dir), max_seconds,
                                   tag="f3a", work_dir=work_dir)
    bg = None
    if supervisor.background_enabled(BACKGROUND_DEFAULT, background) and traffic_target:
        bg = supervisor.spawn_background_traffic(traffic_gen_path, traffic_target)

    print(f"[F3-a] mode={mode} target={target} image={recreate_image}(원본 고정)", flush=True)
    return {"mode": mode, "target": target, "original": original,
            "recreate_image": recreate_image,
            "failing_command": failing_command(mode),
            "duration_seconds": duration_seconds, "backup": backup,
            "watchdog": wd, "background": bg}


def cleanup(meta: dict) -> None:
    """원본 이미지/명령으로 재배포(완전 가역) 후 원본 복귀·healthy 를 확인. 데이터 볼륨 불변."""
    if not meta:
        return
    target = meta.get("target")
    original = meta.get("original", {})
    print(f"[F3-a] cleanup: {target} 를 원본 이미지({original.get('image')})·명령으로 복원 "
          f"(측정 PC: compose up -d --force-recreate)", flush=True)
    try:
        import docker
        client = docker.from_env()
        attrs = client.containers.get(target).attrs
        now = capture_original(attrs)
        img_ok = now.get("image") == original.get("image")
        cmd_ok = (now.get("cmd") == original.get("cmd")
                  and now.get("entrypoint") == original.get("entrypoint"))
        healthy = restored_healthy(attrs)
        print(f"[F3-a] 복원 확인: image_ok={img_ok} cmd_ok={cmd_ok} healthy={healthy}", flush=True)
        if not (img_ok and cmd_ok and healthy):
            print("[F3-a] 경고: 복원이 완전하지 않음 — 수동 확인 필요", flush=True)
    except Exception as e:  # 도커 접근 불가 등
        print(f"[F3-a] 복원 확인 생략(watchdog 이 복구함): {e}", flush=True)
    finally:
        supervisor.cancel_watchdog(meta.get("watchdog"))
        supervisor.stop_background_traffic(meta.get("background"))


def dry_run() -> dict:
    return {"mode": DEFAULT_MODE, "target": DEFAULT_TARGET,
            "failing_command": failing_command(DEFAULT_MODE),
            "forbidden_targets": list(FORBIDDEN_TARGETS),
            "watchdog_max_seconds": DEFAULT_MAX_SECONDS, "background_default": BACKGROUND_DEFAULT,
            "db_mode": DB_MODE,
            "env": ["F3A_TARGET", "F3A_BACKUP_DIR", "V2_COMPOSE_DIR", "V2_WORK_DIR",
                    "V2_TRAFFIC_GEN", "SCEN_DB_MODE", "SCEN_PGHOST", "SCEN_PGPORT",
                    "SCEN_PGDATABASE", "SCEN_PGUSER", "SCEN_PGPASSFILE",
                    "F3A_DB_CONTAINER (container 모드)"],
            "note": "원본 이미지 고정(태그 변경 금지) + 실행 전 DB 백업 필수(backup_dir); "
                    "백업 기본 host 모드(Windows 호스트 PG), container 옵션"}


def main():
    meta = None
    try:
        meta = inject()
    finally:
        cleanup(meta)


if __name__ == "__main__":
    main()
