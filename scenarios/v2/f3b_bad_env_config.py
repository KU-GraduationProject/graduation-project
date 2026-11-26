"""
F3-b — 잘못된 설정(환경변수) 배포 (scenarios-v2, 2차).

장애 정의: 이미지는 그대로인데 **설정값 하나가 잘못된 채 재배포**돼(예: 의존 서비스 주소 오타) 서비스가
  기동에 실패하거나, 떠 있어도 의존 서비스 호출이 계속 실패한다. F3-a(깨진 이미지/명령)와 달리
  이미지·명령은 정상이고 **설정만** 다르다.
대조: C-d(정상 재시작 — 설정 그대로).

주입(F3-a 방식 재사용):
  (1) 실행 전 DB 백업·검증(f3a.preflight_backup, 실패 시 중단)
  (2) 원본 기록(이미지 태그·digest·명령) → (3) 워치독(원본 compose 재생성)
  (4) 저장소 밖 work_dir 에 **override compose 파일 1개**를 만들어 환경변수 1개만 잘못된 값으로 바꾸고
      `docker compose up -d --no-deps --no-build --pull never --force-recreate <service>` 로 재생성
  (5) 재생성 후 이미지 digest 가 원본과 다르면 **즉시 원본으로 되돌리고 중단**(태그 교체 금지 가드)
  바꿀 수 있는 키는 비밀이 아닌 주소 키(BAD_ENV_KEYS)만. 값은 존재하지 않는 내부 호스트명.
  .env 는 읽지 않는다 — compose 가 기존대로 보간한다.
정리: override 없이 원본 compose 로 재생성(완전 가역) → 이미지·명령 원본 복귀와 healthy 확인.
"""

from __future__ import annotations

import os
import shlex

from v2 import f3a_bad_image_deploy as f3a
from v2 import supervisor

SERVICE = os.getenv("F3B_SERVICE", "backend")             # compose 서비스 이름
CONTAINER = os.getenv("F3B_CONTAINER", "leafy-backend")   # 그 서비스의 컨테이너 이름
COMPOSE_DIR = os.getenv("V2_COMPOSE_DIR", ".")
COMPOSE_FILES = [f for f in os.getenv("V2_COMPOSE_FILES", "docker-compose.yml").split(",") if f]

# 비밀이 아닌 '의존 서비스 주소' 키만 허용. 값은 존재하지 않는 내부 호스트명.
BAD_ENV_KEYS = {
    "STORAGE_ENDPOINT": "http://minio-unavailable:9000",
    "SPRING_DATASOURCE_URL": "jdbc:postgresql://db-unavailable:5432/leafy",
}
DEFAULT_KEY = "STORAGE_ENDPOINT"
DEFAULT_DURATION_SECONDS = 180
DEFAULT_MAX_SECONDS = 360
BACKGROUND_DEFAULT = True


def bad_override_yaml(service: str = SERVICE, key: str = DEFAULT_KEY) -> str:
    """환경변수 1개만 덮어쓰는 compose override. image/command 는 쓰지 않는다(원본 유지)."""
    if key not in BAD_ENV_KEYS:
        raise ValueError(f"허용되지 않은 키: {key} (허용: {sorted(BAD_ENV_KEYS)})")
    return (f"services:\n  {service}:\n    environment:\n"
            f"      {key}: \"{BAD_ENV_KEYS[key]}\"\n")


def compose_argv(files, extra=None, service: str = SERVICE) -> list[str]:
    argv = ["docker", "compose"]
    for f in [*files, *(extra or [])]:
        argv += ["-f", f]
    return argv + ["up", "-d", "--no-deps", "--no-build", "--pull", "never",
                   "--force-recreate", service]


def restore_sh(compose_dir: str = COMPOSE_DIR, files=None, service: str = SERVICE) -> str:
    """워치독 복구(호스트 sh): override 없이 원본 compose 로 재생성."""
    argv = compose_argv(files or COMPOSE_FILES, service=service)
    return f"cd {shlex.quote(compose_dir)} && " + " ".join(shlex.quote(a) for a in argv)


def inject(key: str = DEFAULT_KEY, duration_seconds: int = DEFAULT_DURATION_SECONDS,
           backup_dir: str | None = None, max_seconds: int = DEFAULT_MAX_SECONDS,
           compose_dir: str = COMPOSE_DIR, work_dir: str | None = None,
           background: bool | None = None, traffic_gen_path: str | None = None,
           traffic_target: str | None = None):
    import subprocess

    import docker
    f3a.assert_target_allowed(CONTAINER)
    override_text = bad_override_yaml(SERVICE, key)
    backup_dir = backup_dir or os.environ.get("F3A_BACKUP_DIR")
    if not backup_dir:
        raise ValueError("backup_dir(저장소 밖 백업 경로) 필요 — DB 백업 없이 주입 금지")

    client = docker.from_env()
    original = f3a.capture_original(client.containers.get(CONTAINER).attrs)
    backup = f3a.preflight_backup(backup_dir)

    wd_dir = supervisor.resolve_work_dir(work_dir)
    os.makedirs(wd_dir, exist_ok=True)
    override = os.path.join(wd_dir, "f3b_override.yml")
    with open(override, "w", encoding="utf-8") as fh:
        fh.write(override_text)

    wd = supervisor.spawn_watchdog(restore_sh(compose_dir), max(max_seconds, duration_seconds + 60),
                                   tag="f3b", work_dir=work_dir)
    bg = None
    if supervisor.background_enabled(BACKGROUND_DEFAULT, background) and traffic_target:
        bg = supervisor.spawn_background_traffic(traffic_gen_path, traffic_target)

    meta = {"key": key, "original": original, "backup": backup, "watchdog": wd, "background": bg,
            "compose_dir": compose_dir, "override": override, "duration_seconds": duration_seconds}
    subprocess.run(compose_argv(COMPOSE_FILES, [override]), cwd=compose_dir, check=True,
                   stdout=subprocess.DEVNULL)
    now = f3a.capture_original(client.containers.get(CONTAINER).attrs)
    try:
        f3a.assert_recreate_image(original, now["image"], now["image_id"])
    except ValueError:
        cleanup(meta)
        raise
    # 키 이름만 출력(값·다른 env 는 출력하지 않는다).
    print(f"[F3-b] {SERVICE} 재생성: {key} 만 잘못된 값, 이미지 원본 고정 확인", flush=True)
    return meta


def cleanup(meta: dict | None) -> None:
    meta = meta or {}
    if not meta:
        return
    try:
        import subprocess
        subprocess.run(["sh", "-c", restore_sh(meta.get("compose_dir", COMPOSE_DIR))], check=True,
                       stdout=subprocess.DEVNULL)
        import docker
        attrs = docker.from_env().containers.get(CONTAINER).attrs
        now = f3a.capture_original(attrs)
        o = meta.get("original", {})
        print(f"[F3-b] 복원 확인: image_ok={now['image_id'] == o.get('image_id')} "
              f"cmd_ok={now['cmd'] == o.get('cmd')} healthy={f3a.restored_healthy(attrs)}", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(f"[F3-b] cleanup 실패(워치독이 복구함): {exc}", flush=True)
    finally:
        try:
            if meta.get("override"):
                os.remove(meta["override"])
        except OSError:
            pass
        supervisor.cancel_watchdog(meta.get("watchdog"))
        supervisor.stop_background_traffic(meta.get("background"))


def dry_run() -> dict:
    return {"service": SERVICE, "container": CONTAINER, "key": DEFAULT_KEY,
            "allowed_keys": sorted(BAD_ENV_KEYS), "override_preview": bad_override_yaml(),
            "recreate_argv": compose_argv(COMPOSE_FILES, ["<work_dir>/f3b_override.yml"]),
            "restore": restore_sh(), "watchdog_max_seconds": DEFAULT_MAX_SECONDS,
            "env": ["F3B_SERVICE", "F3B_CONTAINER", "F3A_BACKUP_DIR", "F3A_DB_CONTAINER",
                    "V2_COMPOSE_DIR", "V2_COMPOSE_FILES", "V2_WORK_DIR", "V2_TRAFFIC_GEN"],
            "note": "원본 이미지 고정, 비밀 아닌 주소 키 1개만, 실행 전 DB 백업 필수"}


def main(**kw):
    import time
    meta = None
    try:
        meta = inject(**kw)
        time.sleep(meta["duration_seconds"])
    finally:
        cleanup(meta)


if __name__ == "__main__":
    main()
