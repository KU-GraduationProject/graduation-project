"""
DB 백업(BACKUP_DB) — 파괴적 조치 직전 pg_dump + 검증 (노션 선행 단계).

  - 대상 DB 연결은 Postgres 실행기 설정(remediation_postgres.yml)의 host/port/db/sslmode 를 재사용한다.
  - 계정은 전용 읽기 전용 역할(예: leafy_backup + pg_read_all_data)을 별도 환경변수로 받는다.
    KILL_SESSIONS 실행 계정과 섞지 않는다.
  - 검증: 크기 상한, PGDMP 헤더, pg_restore --list 통과, sha256.
  - manifest 는 기존 ROLLBACK 백업 검사(executor/deployment.py _backup)와 같은 필드를 쓴다.
  - 덤프에는 개인정보가 있다. 0600 으로 저장하고, 레코드·Slack·Loki 에는 manifest 정보만 남긴다.

비밀번호는 명령행이 아니라 PGPASSWORD 환경변수로만 넘긴다. pg_dump 의 오류 출력은 저장하지 않는다.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DIR = "/app/backups"
DEFAULT_RETENTION_DAYS = 7
DEFAULT_KEEP = 5
DEFAULT_MAX_BYTES = 2 * 1024 ** 3
DEFAULT_TIMEOUT = 300
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")


class BackupError(RuntimeError):
    """DB 백업을 만들거나 검증하지 못했다."""


@dataclass(frozen=True)
class BackupSettings:
    target: str
    directory: str = DEFAULT_DIR
    user_env: str = "REMEDIATION_BACKUP_PGUSER"
    password_env: str = "REMEDIATION_BACKUP_PGPASSWORD"
    retention_days: int = DEFAULT_RETENTION_DAYS
    keep: int = DEFAULT_KEEP
    max_bytes: int = DEFAULT_MAX_BYTES
    timeout: int = DEFAULT_TIMEOUT

    @classmethod
    def from_env(cls) -> "BackupSettings | None":
        target = os.getenv("REMEDIATION_BACKUP_TARGET", "").strip()
        if not target:
            return None
        return cls(target=target, directory=os.getenv("REMEDIATION_BACKUP_DIR", DEFAULT_DIR))


def _now_iso(now: float) -> str:
    return datetime.fromtimestamp(now, timezone.utc).isoformat()


def _prune(directory: Path, keep_names: set, retention_days: int, keep: int, now: float) -> None:
    dumps = sorted(directory.glob("*.dump"), key=lambda p: p.stat().st_mtime, reverse=True)
    for index, dump in enumerate(dumps):
        if dump.name in keep_names:
            continue
        if index >= keep or now - dump.stat().st_mtime > retention_days * 86400:
            for path in (dump, dump.with_suffix(".json")):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
    for partial in directory.glob("*.partial"):
        if now - partial.stat().st_mtime > 3600:
            partial.unlink(missing_ok=True)


def _fsync_dir(directory: Path) -> None:
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def create_backup(settings: BackupSettings, postgres_config: dict, remediation_id: str, *,
                  run=subprocess.run, now=time.time, environ=os.environ) -> dict:
    """pg_dump 로 백업을 만들고 검증한 뒤 manifest 를 돌려준다. 실패하면 BackupError."""
    if not _ID.fullmatch(str(remediation_id)):
        raise BackupError("invalid_remediation_id")
    conn = postgres_config["connection"]
    user, password = environ.get(settings.user_env, ""), environ.get(settings.password_env, "")
    host, port, dbname = (environ.get(conn["host_env"], ""), environ.get(conn["port_env"], ""),
                          environ.get(conn["dbname_env"], ""))
    if not (user and password and host and port and dbname):
        raise BackupError("backup_connection_not_configured")
    if dbname != postgres_config["database"]:
        raise BackupError("backup_database_mismatch")

    directory = Path(settings.directory)
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if shutil.disk_usage(directory).free < settings.max_bytes:
            raise BackupError("backup_disk_space_insufficient")
    except OSError as exc:
        raise BackupError("backup_directory_unavailable") from exc

    started = now()
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(started))
    name = f"{postgres_config['database']}-{stamp}-{remediation_id}"
    partial, dump, manifest_path = (directory / f"{name}.dump.partial", directory / f"{name}.dump",
                                    directory / f"{name}.json")
    env = {"PATH": environ.get("PATH", "/usr/bin:/bin"), "PGHOST": host, "PGPORT": port,
           "PGUSER": user, "PGPASSWORD": password, "PGDATABASE": dbname,
           "PGSSLMODE": conn["sslmode"], "PGCONNECT_TIMEOUT": "10",
           "PGAPPNAME": "leafy-remediation-backup"}
    try:
        try:
            dumped = run(["pg_dump", "--format=custom", "--no-password", "--file", str(partial)],
                         env=env, capture_output=True, timeout=settings.timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BackupError("pg_dump_unavailable_or_timeout") from exc
        if dumped.returncode != 0 or not partial.exists():
            raise BackupError("pg_dump_failed")
        os.chmod(partial, 0o600)
        size = partial.stat().st_size
        if not 0 < size <= settings.max_bytes:
            raise BackupError("backup_size_out_of_bounds")
        with partial.open("rb") as fh:
            if fh.read(5) != b"PGDMP":
                raise BackupError("backup_format_invalid")
            fh.seek(0)
            digest = hashlib.file_digest(fh, "sha256").hexdigest()
        try:
            listed = run(["pg_restore", "--list", str(partial)], env={"PATH": env["PATH"]},
                         capture_output=True, timeout=settings.timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BackupError("pg_restore_list_unavailable_or_timeout") from exc
        if listed.returncode != 0:
            raise BackupError("pg_restore_list_failed")
        os.replace(partial, dump)
        manifest = {
            "artifact_path": str(dump), "sha256": digest, "bytes": size, "format": "postgres-custom",
            "database_id": f"{postgres_config['system_identifier']}:{postgres_config['database']}",
            "verified": True, "restore_list_verified": True, "verified_at": _now_iso(now()),
            "started_at": _now_iso(started), "remediation_id": remediation_id,
        }
        fd = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        _fsync_dir(directory)
    except BackupError:
        partial.unlink(missing_ok=True)
        raise
    except OSError as exc:
        partial.unlink(missing_ok=True)
        raise BackupError("backup_store_failed") from exc
    _prune(directory, {dump.name}, settings.retention_days, settings.keep, now())
    return {**manifest, "manifest_path": str(manifest_path)}
