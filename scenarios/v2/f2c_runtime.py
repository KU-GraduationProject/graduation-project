"""F2-c psql transports and independent recovery worker. No shell or stored passwords."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

if __package__:
    from . import supervisor
else:  # Independent worker launched by absolute path, from any working directory.
    import supervisor


class RuntimeFailure(RuntimeError):
    """Safe to print: never include subprocess output or connection credentials."""


def identifier(value: str) -> str:
    """Accept only the identifier characters used in SQL filters and run markers."""
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", value):
        raise RuntimeFailure("invalid F2-c identifier")
    return value


@dataclass(frozen=True)
class Target:
    """Immutable, explicitly selected test endpoint and its expected cluster ID."""

    mode: str
    database: str
    admin: str
    user: str
    system_id: str
    host: str
    port: int = 5432
    container: str = ""
    psql: str = "psql"
    passfile: str = ""

    def __post_init__(self):
        """Reject ambiguous endpoints, unsafe names, and identical admin/holder roles."""
        if self.mode not in ("docker", "host"):
            raise RuntimeFailure("F2C_DB_MODE must explicitly be docker or host")
        for value in (self.database, self.admin, self.user):
            identifier(value)
        if not self.system_id.isdigit() or not 1 <= self.port <= 65535:
            raise RuntimeFailure("invalid expected cluster ID or port")
        if self.admin == self.user:
            raise RuntimeFailure("admin and ordinary session user must differ")
        if self.mode == "docker":
            identifier(self.container)
            if not self.host.startswith("/") or any(c.isspace() for c in self.host):
                raise RuntimeFailure("docker mode requires an explicit local socket directory")
        elif not re.fullmatch(r"[A-Za-z0-9_.:-]+", self.host) or self.host.startswith("-"):
            raise RuntimeFailure("host mode requires one explicit TCP host")

    @property
    def confirmation(self) -> str:
        """Return the mode/endpoint/database/cluster token required for injection."""
        endpoint = self.container if self.mode == "docker" else f"{self.host}:{self.port}"
        return f"{self.mode}:{endpoint}:{self.database}:{self.system_id}"

    @classmethod
    def from_env(cls, *, allow_injection: bool = True):
        """Load an explicit target and, by default, require its confirmation token.

        Missing or invalid configuration raises a safe RuntimeFailure. Disabling
        confirmation here is for inspection; inject still enforces confirmation.
        """
        env = os.environ
        required = ("F2C_DB_MODE", "F2C_DB_NAME", "F2C_ADMIN_USER", "F2C_DB_USER",
                    "F2C_EXPECTED_SYSTEM_ID", "F2C_DB_HOST", "F2C_DB_PORT")
        if any(not env.get(k) for k in required):
            raise RuntimeFailure("explicit F2-c target configuration is required; see F2C_RUNTIME.md")
        try:
            target = cls(env[required[0]], env[required[1]], env[required[2]],
                         env[required[3]], env[required[4]], env[required[5]],
                         int(env[required[6]]), env.get("F2C_DB_CONTAINER", ""),
                         env.get("F2C_PSQL", "psql"), env.get("F2C_PGPASSFILE", ""))
        except ValueError:
            raise RuntimeFailure("invalid F2-c port") from None
        if allow_injection and env.get("F2C_CONFIRM_TARGET") != target.confirmation:
            raise RuntimeFailure("F2C_CONFIRM_TARGET must match the selected test cluster")
        return target


# Remove ambient libpq routing/auth options; a service or PGHOSTADDR can override -h.
_PG_ROUTING = ("PGHOST", "PGHOSTADDR", "PGPORT", "PGDATABASE", "PGUSER", "PGSERVICE",
               "PGSERVICEFILE", "PGOPTIONS", "PGPASSWORD", "PGPASSFILE", "PGAPPNAME")


class Psql:
    """Bounded psql operations for a Host TCP or Docker socket test endpoint."""

    def __init__(self, target: Target):
        """Bind operations to the validated target without opening a connection."""
        self.target = target

    def command(self, sql: str, user: str, app: str) -> list[str]:
        """Build shell-free argv with explicit routing, user, and run application name.

        Docker runs env/psql inside the named container. Neither transport enables
        startup files or password prompts, and password values never enter argv.
        """
        t = self.target
        args = [t.psql, "-X", "-w", "-A", "-t", "-v", "ON_ERROR_STOP=1",
                "-v", "VERBOSITY=verbose", "-h", t.host, "-p", str(t.port),
                "-U", user, "-d", t.database, "-c", sql]
        if t.mode == "docker":
            # env is inside the Linux PostgreSQL container; the Windows host needs no sh/pkill.
            clean = [part for key in _PG_ROUTING for part in ("-u", key)]
            settings = [f"PGAPPNAME={app}", "PGCONNECT_TIMEOUT=5"]
            if t.passfile:
                settings.append(f"PGPASSFILE={t.passfile}")
            args = ["docker", "exec", t.container, "env", *clean, *settings, *args]
        return args

    def environment(self, app: str) -> dict:
        """Remove selected ambient libpq defaults and set the run name and timeout."""
        env = {k: v for k, v in os.environ.items() if k not in _PG_ROUTING}
        env.update(PGAPPNAME=app, PGCONNECT_TIMEOUT="5")
        if self.target.mode == "host" and self.target.passfile:
            env["PGPASSFILE"] = self.target.passfile
        return env

    def execute(self, sql: str, *, user: str | None = None, app: str = "f2c-check"):
        """Return a bounded command's captured result without logging diagnostics.

        Nonzero psql exits are returned for the caller to interpret. OS failures
        and subprocess timeouts become RuntimeFailure without raw error details.
        """
        try:
            return subprocess.run(self.command(sql, user or self.target.admin, app),
                                  env=self.environment(app), stdin=subprocess.DEVNULL,
                                  capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=10, check=False)
        except (OSError, subprocess.SubprocessError):
            raise RuntimeFailure("psql execution failed or timed out") from None

    def query(self, sql: str, *, user: str | None = None, app: str = "f2c-check") -> dict:
        """Read one JSON object, rejecting failed queries or malformed output safely."""
        result = self.execute(sql, user=user, app=app)
        if result.returncode:
            raise RuntimeFailure("DB query failed (details suppressed)")
        try:
            value = json.loads(result.stdout)
            if not isinstance(value, dict):
                raise ValueError
            return value
        except (ValueError, TypeError):
            raise RuntimeFailure("invalid DB query result") from None

    def preflight(self, mark: str) -> dict:
        """Validate cluster identity, recovery access, reserves, and the ordinary role.

        Return server connection settings only after an administrator and a real
        ordinary login both pass their checks. Reject privileged holders and
        role/database connection limits without changing roles or DB settings.
        """
        t = self.target
        info = self.query("SELECT json_build_object("
            "'system_id', (pg_control_system()).system_identifier::text, "
            "'database', current_database(), 'admin', current_user, "
            "'superuser', (SELECT rolsuper FROM pg_roles WHERE rolname=current_user), "
            "'version', current_setting('server_version_num')::int, "
            "'max_conn', current_setting('max_connections')::int, "
            "'reserved', coalesce(current_setting('reserved_connections', true), '0')::int, "
            "'super_reserved', current_setting('superuser_reserved_connections')::int)",
            app=mark + "-ctl")
        if (info["system_id"] != t.system_id or info["database"] != t.database
                or info["admin"] != t.admin or not info["superuser"]):
            raise RuntimeFailure("cluster identity or administrator privilege mismatch")
        if info["super_reserved"] < 1:
            raise RuntimeFailure("at least one existing superuser reserve is required for recovery")
        # A real ordinary login is required; superuser/reserved-role probes are misleading.
        reserved_role = ("pg_has_role(current_user, 'pg_use_reserved_connections', 'USAGE')"
                         if info["version"] >= 160000 else "false")
        role = self.query("SELECT json_build_object('user', current_user, "
            f"'superuser', rolsuper, 'reserved_role', {reserved_role}, "
            "'role_limit', rolconnlimit, 'db_limit', datconnlimit) "
            "FROM pg_roles CROSS JOIN pg_database "
            "WHERE rolname=current_user AND datname=current_database()",
            user=t.user, app=mark + "-probe")
        if (role["user"] != t.user or role["superuser"] or role["reserved_role"]
                or role["role_limit"] != -1 or role["db_limit"] != -1):
            raise RuntimeFailure("ordinary user must have no reserved privilege or role/database limit")
        return info

    def snapshot(self, mark: str) -> dict:
        """Count cluster clients and exact run-owned sessions, excluding this observer."""
        identifier(mark)
        return self.query("SELECT json_build_object('total', count(*), 'owned', "
            f"count(*) FILTER (WHERE application_name='{mark}' "
            f"AND usename='{self.target.user}' AND datname='{self.target.database}')) "
            "FROM pg_stat_activity WHERE backend_type='client backend' "
            "AND pid <> pg_backend_pid()", app=mark + "-ctl")

    def probe(self, mark: str) -> str:
        """Classify a new ordinary login as accepted, rejected, or unknown.

        Recognize only known global exhaustion messages as rejection. Other
        failures, including authentication and localized errors, remain unknown;
        the caller must also verify global occupancy before claiming exhaustion.
        """
        result = self.execute("SELECT 1", user=self.target.user, app=mark + "-probe")
        if not result.returncode:
            return "accepted" if result.stdout.strip() == "1" else "unknown"
        # libpq/psql startup failures do not reliably expose SQLSTATE. Fail closed for
        # localized/unrecognized errors; neither auth failures nor timeouts prove exhaustion.
        error = result.stderr.lower()
        if ("remaining connection slots are reserved" in error
                or "sorry, too many clients already" in error):
            return "rejected"
        return "unknown"

    def start_holder(self, mark: str, lifetime: int):
        """Start a tracked ordinary psql client with a finite server-side sleep.

        Return its Popen handle; process startup alone does not prove that a DB
        session exists. The caller must confirm it through the run's snapshot.
        """
        try:
            return subprocess.Popen(self.command(f"SELECT pg_sleep({int(lifetime)})",
                                                  self.target.user, mark),
                                    env=self.environment(mark), stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    **supervisor.detached_process_kwargs())
        except OSError:
            raise RuntimeFailure("could not start a session client") from None

    def restore(self, mark: str) -> bool:
        """Recheck cluster identity, terminate exact run-owned sessions, and verify recovery.

        Termination matches the run mark, ordinary user, and database. Recovery
        requires zero matching sessions and a successful fresh ordinary login.
        """
        identifier(mark)
        # Recheck identity on every retry, including after a DNS/container replacement.
        identity = self.query("SELECT json_build_object('system_id', "
                              "(pg_control_system()).system_identifier::text)", app=mark + "-ctl")
        if identity["system_id"] != self.target.system_id:
            raise RuntimeFailure("recovery cluster identity mismatch")
        self.query("SELECT json_build_object('terminated', "
            "coalesce(bool_and(pg_terminate_backend(pid)), true)) FROM pg_stat_activity "
            f"WHERE application_name='{mark}' AND usename='{self.target.user}' "
            f"AND datname='{self.target.database}' AND pid <> pg_backend_pid()",
            app=mark + "-ctl")
        return self.snapshot(mark)["owned"] == 0 and self.probe(mark) == "accepted"


def stop_clients(clients) -> None:
    """Best-effort terminate and reap only supplied clients, escalating after timeout."""
    for proc in clients:
        try:
            if proc.poll() is None:
                proc.terminate()  # Only Popen objects owned by this run; no PID search/reuse.
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
            else:
                proc.wait(timeout=2)
        except (OSError, subprocess.SubprocessError):
            pass


def spawn_watchdog(target: Target, mark: str, timeout: int, work_dir=None) -> dict:
    """Start independent recovery and return its handle only after the ready signal.

    Send target metadata over a pipe and use unique run paths. If readiness fails
    or startup is interrupted, stop this worker before the caller opens holders.
    """
    directory = Path(supervisor.resolve_work_dir(work_dir))
    directory.mkdir(parents=True, exist_ok=True)
    paths = {k: str(directory / f"wd_{mark}.{k}") for k in ("cancel", "ready", "log")}
    # mark is random per run; never reuse or erase another run's files.
    if any(Path(p).exists() for p in paths.values()):
        raise RuntimeFailure("watchdog run path already exists")
    proc = subprocess.Popen([sys.executable, str(Path(__file__).resolve())],
                            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, text=True, encoding="utf-8",
                            **supervisor.detached_process_kwargs())
    handle = {"process": proc, "pid": proc.pid, "tag": mark, **paths}
    try:
        json.dump({"target": asdict(target), "mark": mark, "timeout": timeout,
                   "paths": paths}, proc.stdin)
        proc.stdin.close()
        until = time.monotonic() + 15
        while not Path(paths["ready"]).exists():
            if proc.poll() is not None or time.monotonic() >= until:
                raise RuntimeFailure("recovery worker did not become ready")
            time.sleep(0.05)
    except BaseException:
        stop_clients([proc])
        raise
    print(f"[watchdog] tag={mark} timeout={timeout}s log={paths['log']}", flush=True)
    return handle


def watchdog_worker(payload: dict) -> None:
    """Validate recovery access, wait for cancellation/deadline, then retry recovery.

    Signal readiness before any holders may open. After the deadline, recover
    only the specified run until verification succeeds or cleanup cancels this
    worker; log status words without raw database errors or credentials.
    """
    db = Psql(Target(**payload["target"]))
    mark, paths = payload["mark"], payload["paths"]
    identifier(mark)
    deadline = time.monotonic() + payload["timeout"]
    db.preflight(mark)  # Recovery credentials/endpoint work before any holder can start.
    Path(paths["ready"]).touch()
    while time.monotonic() < deadline:
        if Path(paths["cancel"]).exists():
            return
        time.sleep(0.2)
    # Keep retrying on failure. Session clients also have a finite server-side sleep.
    while not Path(paths["cancel"]).exists():
        try:
            recovered = db.restore(mark)
        except Exception:
            recovered = False
        with open(paths["log"], "a", encoding="utf-8") as log:
            log.write("restored\n" if recovered else "RESTORE FAILED; retrying\n")
        if recovered:
            return
        time.sleep(2)


if __name__ == "__main__":
    try:
        watchdog_worker(json.load(sys.stdin))
    except Exception:
        sys.exit(1)  # Never print raw driver/subprocess exceptions.
