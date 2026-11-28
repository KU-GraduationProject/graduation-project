"""Manually approved PostgreSQL administration; no arbitrary SQL or production restore.

RESTORE_DB only targets an explicitly isolated, empty restore_* database. Request
parameters select operator-defined backup IDs, never files/SQL/connection strings.
NOLOGIN prevents new connections; it intentionally does not terminate sessions.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import shutil
import time

import yaml

from executor.base import ExecutionResult, blocked, succeeded
from executor.managed import check_record, seal_plan, valid_plan_digest

ACTIONS = frozenset({"RESTORE_DB", "DISABLE_DB_ROLE", "ENABLE_DB_ROLE"})
RECOVERY_MAP = {"DISABLE_DB_ROLE": "ENABLE_DB_ROLE"}
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}\Z")
ENV = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")
IDENTITY_FIELDS = {"site", "source", "service", "runtime", "target"}
SERVER_SQL = """/* leafy:admin_server */
SELECT current_database() AS database, current_user AS executor_role,
 inet_server_addr()::text AS server_addr, inet_server_port() AS server_port,
 (pg_catalog.pg_control_system()).system_identifier::text AS system_identifier,
 pg_catalog.pg_is_in_recovery() AS in_recovery,
 r.rolsuper, r.rolreplication, r.rolbypassrls, r.rolcreaterole, r.rolcreatedb
FROM pg_catalog.pg_roles r WHERE r.rolname = current_user"""
DATABASE_SQL = """/* leafy:restore_destination */
SELECT d.oid::bigint AS oid, d.datname, pg_catalog.pg_get_userbyid(d.datdba) AS owner,
 (SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'
  AND c.relkind IN ('r','p','m','f')) AS relations,
 (SELECT count(*) FROM pg_catalog.pg_stat_activity a WHERE a.datname=current_database()
  AND a.pid<>pg_backend_pid()) AS other_sessions
FROM pg_catalog.pg_database d WHERE d.datname=current_database()"""
ROLE_SQL = """/* leafy:admin_role */
SELECT r.oid::bigint AS oid, r.rolname, r.rolcanlogin,
 r.rolsuper, r.rolreplication, r.rolcreaterole, r.rolcreatedb, r.rolbypassrls,
 EXISTS(SELECT 1 FROM pg_catalog.pg_database d WHERE d.datdba=r.oid) AS database_owner,
 EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.relowner=r.oid) AS relation_owner,
 EXISTS(SELECT 1 FROM pg_catalog.pg_roles p WHERE p.oid<>r.oid
  AND pg_catalog.pg_has_role(r.oid,p.oid,'MEMBER')
  AND (p.rolsuper OR p.rolreplication OR p.rolcreaterole OR p.rolcreatedb OR p.rolbypassrls
       OR p.rolname LIKE 'pg\\_%' ESCAPE '\\')) AS privileged_membership
FROM pg_catalog.pg_roles r WHERE r.rolname=%s AND r.rolname<>current_user"""


class DatabaseAdminError(ValueError):
    pass


def validate_parameters(action, parameters):
    if action not in ACTIONS or not isinstance(parameters, dict):
        raise DatabaseAdminError("invalid_database_admin_action")
    expected = {"backup_id", "confirm_database", "allow_data_loss"} if action == "RESTORE_DB" else {"role_id"}
    if set(parameters) != expected:
        raise DatabaseAdminError("invalid_database_admin_parameters")
    for key in expected - {"allow_data_loss"}:
        if not isinstance(parameters[key], str) or not NAME.fullmatch(parameters[key]):
            raise DatabaseAdminError("invalid_database_admin_resource")
    if action == "RESTORE_DB" and parameters["allow_data_loss"] is not True:
        raise DatabaseAdminError("explicit_restore_consent_required")


def _connect(**kwargs):
    import psycopg
    from psycopg.rows import dict_row
    return psycopg.connect(**kwargs, row_factory=dict_row)


def _hash(body):
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


class DatabaseAdminExecutor:
    name = "database_admin"
    changes_system = True

    def __init__(self, config_path=None, connection_factory=None, runner=None, ledger_path=None):
        self.config_path = config_path
        self.connection_factory = connection_factory or _connect
        self.runner = runner or subprocess.run
        self.ledger_path = ledger_path or os.path.join(os.getenv("REMEDIATION_STATE_DIR", "/app/state"), "database_admin.sqlite3")

    def _config(self, target):
        path = self.config_path or os.getenv("REMEDIATION_DATABASE_ADMIN_CONFIG_PATH")
        try:
            doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) if path else None
            if (not isinstance(doc, dict) or set(doc) != {"version", "enabled", "targets"}
                    or type(doc["version"]) is not int or doc["version"] != 1 or doc["enabled"] is not True):
                raise ValueError()
            c = doc["targets"][target]
            fields = {"identity", "database", "system_identifier", "server_addr", "server_port", "executor_role",
                      "connection", "actions", "roles", "backups", "isolated_restore", "timeout_seconds"}
            if not isinstance(c, dict) or set(c) != fields:
                raise ValueError()
            ident = c["identity"]
            if (set(ident) != IDENTITY_FIELDS or ident["target"] != target or ident["service"] != "db"
                    or ident["runtime"] not in {"host", "container"}
                    or any(not isinstance(v, str) or not v.strip() or v != v.strip() or v.lower() == "unknown" for v in ident.values())):
                raise ValueError()
            if (not NAME.fullmatch(c["database"]) or not NAME.fullmatch(c["executor_role"])
                    or c["executor_role"] == "postgres" or c["executor_role"].startswith("pg_")
                    or not re.fullmatch(r"[0-9]{1,20}", c["system_identifier"])
                    or str(ipaddress.ip_address(c["server_addr"])) != c["server_addr"]
                    or type(c["server_port"]) is not int or not 1 <= c["server_port"] <= 65535
                    or type(c["timeout_seconds"]) is not int or not 1 <= c["timeout_seconds"] <= 900
                    or type(c["isolated_restore"]) is not bool
                    or not isinstance(c["actions"], list) or not c["actions"] or set(c["actions"]) - ACTIONS
                    or not isinstance(c["roles"], list) or not isinstance(c["backups"], dict)):
                raise ValueError()
            for role in c["roles"]:
                if (not isinstance(role, str) or not NAME.fullmatch(role) or role == c["executor_role"]
                        or role == "postgres" or role.startswith("pg_")):
                    raise ValueError()
            conn = c["connection"]
            if (set(conn) != {"host_env", "port_env", "user_env", "pgpassfile_env", "sslmode"}
                    or any(not isinstance(conn[k], str) or not ENV.fullmatch(conn[k]) for k in conn if k != "sslmode")
                    or conn["sslmode"] not in {"verify-full", "require", "disable"}):
                raise ValueError()
            for key, value in c["backups"].items():
                if not NAME.fullmatch(key) or set(value) != {"manifest_file", "database_id"} or not isinstance(value["manifest_file"], str):
                    raise ValueError()
            return c
        except (ValueError, TypeError, KeyError, OSError, yaml.YAMLError):
            raise DatabaseAdminError("database_admin_not_configured_or_invalid") from None

    def _environment(self, c):
        try:
            spec = c["connection"]
            host, port, user, passfile = [os.environ[spec[k + "_env"]] for k in ("host", "port", "user", "pgpassfile")]
            if (str(ipaddress.ip_address(host)) != c["server_addr"] or int(port) != c["server_port"]
                    or user != c["executor_role"] or not Path(passfile).is_absolute() or not Path(passfile).is_file()
                    or (os.name != "nt" and Path(passfile).stat().st_mode & 0o077)):
                raise ValueError()
            return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PGHOST": host, "PGHOSTADDR": host,
                    "PGPORT": str(c["server_port"]), "PGDATABASE": c["database"], "PGUSER": user,
                    "PGPASSFILE": passfile, "PGSSLMODE": spec["sslmode"], "PGCONNECT_TIMEOUT": "5",
                    "PGAPPNAME": "leafy-database-admin", "PGOPTIONS": "-c statement_timeout=" + str(c["timeout_seconds"] * 1000)}
        except (OSError, ValueError, KeyError):
            raise DatabaseAdminError("database_admin_connection_not_configured") from None

    @contextmanager
    def _connection(self, c):
        env = self._environment(c)
        conn = None
        try:
            conn = self.connection_factory(host=env["PGHOST"], hostaddr=env["PGHOSTADDR"], port=int(env["PGPORT"]),
                dbname=env["PGDATABASE"], user=env["PGUSER"], passfile=env["PGPASSFILE"], sslmode=env["PGSSLMODE"],
                connect_timeout=5, application_name="leafy-database-admin", autocommit=False,
                options=env["PGOPTIONS"], target_session_attrs="read-write")
            yield conn
        except DatabaseAdminError:
            raise
        except Exception:
            raise DatabaseAdminError("database_admin_connection_or_query_failed") from None
        finally:
            if conn is not None:
                conn.close()

    @staticmethod
    def _one(conn, sql, values=()):
        with conn.cursor() as cursor:
            cursor.execute(sql, values)
            row = cursor.fetchone()
        if not isinstance(row, dict):
            raise DatabaseAdminError("database_admin_observation_unavailable")
        return dict(row)

    def _server(self, conn, c, action):
        s = self._one(conn, SERVER_SQL)
        if (any(s.get(k) != c[k] for k in ("database", "system_identifier", "server_addr", "server_port", "executor_role"))
                or s.get("in_recovery") is not False
                or any(s.get(k) is not False for k in ("rolsuper", "rolreplication", "rolbypassrls"))
                or (action == "RESTORE_DB" and any(s.get(k) is not False for k in ("rolcreaterole", "rolcreatedb")))):
            raise DatabaseAdminError("database_admin_server_identity_or_privilege_mismatch")
        return {k: s[k] for k in ("database", "system_identifier", "server_addr", "server_port", "executor_role")}

    def _role(self, conn, c, role):
        if role not in c["roles"]:
            raise DatabaseAdminError("database_role_not_allowlisted")
        s = self._one(conn, ROLE_SQL, (role,))
        unsafe = ("rolsuper", "rolreplication", "rolcreaterole", "rolcreatedb", "rolbypassrls",
                  "database_owner", "relation_owner", "privileged_membership")
        if (s.get("rolname") != role or type(s.get("oid")) is not int or type(s.get("rolcanlogin")) is not bool
                or any(s.get(k) is not False for k in unsafe)):
            raise DatabaseAdminError("protected_database_role")
        return {k: s[k] for k in ("oid", "rolname", "rolcanlogin")}

    def _backup(self, c, key):
        try:
            spec = c["backups"][key]
            manifest_bytes = Path(spec["manifest_file"]).read_bytes()
            m = json.loads(manifest_bytes)
            path = Path(m["artifact_path"])
            if (not path.is_absolute() or path.is_symlink() or not path.is_file()
                    or m.get("format") != "postgres-custom" or m.get("verified") is not True
                    or m.get("restore_list_verified") is not True or m.get("database_id") != spec["database_id"]
                    or type(m.get("bytes")) is not int or not 5 < m["bytes"] <= 10 * 1024**3
                    or path.stat().st_size != m["bytes"]):
                raise ValueError()
            with path.open("rb") as f:
                if f.read(5) != b"PGDMP": raise ValueError()
                f.seek(0)
                checksum = hashlib.file_digest(f, "sha256").hexdigest()
            if checksum != m.get("sha256"):
                raise ValueError()
            result = self.runner(["pg_restore", "--list", str(path)], env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=c["timeout_seconds"], check=False)
            if result.returncode != 0:
                raise ValueError()
            # Require a data-bearing, ordinary custom archive, not an empty TOC.
            toc = result.stdout.decode("utf-8", errors="replace") if isinstance(result.stdout, bytes) else str(result.stdout)
            tables = sum(bool(re.match(r"^[0-9]+; [0-9]+ [0-9]+ TABLE (?!DATA )", line)) for line in toc.splitlines())
            if not 1 <= tables <= 10000:
                raise ValueError()
            return {"backup_id": key, "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                    "sha256": checksum, "bytes": m["bytes"], "database_id": m["database_id"], "tables": tables}, path
        except Exception:
            raise DatabaseAdminError("trusted_restore_backup_unavailable_or_changed") from None

    def plan_record(self, identity, targets, action_type, parameters):
        validate_parameters(action_type, parameters)
        c = self._config(identity.get("target"))
        if identity != c["identity"] or list(targets) != [identity["target"]] or action_type not in c["actions"]:
            raise DatabaseAdminError("database_admin_target_mismatch")
        pre = {}
        if action_type == "RESTORE_DB":
            if (c["isolated_restore"] is not True or not c["database"].startswith("restore_")
                    or parameters["confirm_database"] != c["database"]):
                raise DatabaseAdminError("isolated_restore_destination_required")
            pre["backup"], _ = self._backup(c, parameters["backup_id"])
        with self._connection(c) as conn:
            pre["server"] = self._server(conn, c, action_type)
            if action_type == "RESTORE_DB":
                dest = self._one(conn, DATABASE_SQL)
                if (dest.get("datname") != c["database"] or dest.get("owner") != c["executor_role"]
                        or dest.get("relations") != 0 or dest.get("other_sessions") != 0 or type(dest.get("oid")) is not int):
                    raise DatabaseAdminError("restore_destination_not_empty_or_exclusive")
                pre["database"] = dest
            else:
                pre["role"] = self._role(conn, c, parameters["role_id"])
                expected = action_type == "DISABLE_DB_ROLE"
                if pre["role"]["rolcanlogin"] is not expected:
                    raise DatabaseAdminError("database_role_state_does_not_match_requested_change")
        plan = {"executor": self.name, "identity": dict(identity), "target": identity["target"],
                "action_type": action_type, "parameters": dict(parameters),
                "operator_config": {"config_sha256": _hash(c)}, "pre_snapshot": pre}
        return {identity["target"]: seal_plan(plan)}

    def validate_record(self, record):
        try:
            original = record.target_bindings[record.identity["target"]]
            if not valid_plan_digest(original) or original["executor"] != self.name:
                return "database_admin_plan_invalid"
            fresh = self.plan_record(record.identity, record.targets, record.action_type, record.action_parameters)
            if original != fresh[record.identity["target"]]:
                return "database_admin_state_changed_reapproval_required"
            return None
        except Exception:
            return "database_admin_plan_revalidation_failed"

    def _claim(self, record, plan):
        path = Path(self.ledger_path)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.is_symlink(): raise DatabaseAdminError("unsafe_database_admin_ledger")
        db = sqlite3.connect(path, timeout=10)
        os.chmod(path, 0o600)
        db.execute("PRAGMA synchronous=FULL")
        db.execute("CREATE TABLE IF NOT EXISTS executions (rid TEXT PRIMARY KEY, target TEXT, digest TEXT, result TEXT)")
        db.execute("CREATE TABLE IF NOT EXISTS leases (target TEXT PRIMARY KEY, rid TEXT)")
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT digest,result FROM executions WHERE rid=?", (record.remediation_id,)).fetchone()
        if row:
            db.rollback(); db.close()
            if row[0] != plan["plan_digest"]: raise DatabaseAdminError("database_admin_id_conflict")
            if row[1] is None: return ExecutionResult(record.action_type, plan["target"], "UNKNOWN", detail="database_admin_previous_attempt_unresolved")
            return ExecutionResult(**json.loads(row[1]))
        if db.execute("SELECT 1 FROM leases WHERE target=?", (plan["target"],)).fetchone():
            db.rollback(); db.close()
            raise DatabaseAdminError("database_admin_target_busy")
        db.execute("INSERT INTO executions VALUES (?,?,?,NULL)", (record.remediation_id, plan["target"], plan["plan_digest"]))
        db.execute("INSERT INTO leases VALUES (?,?)", (plan["target"], record.remediation_id))
        db.commit(); db.close()
        return None

    def _finish(self, record, result):
        with sqlite3.connect(self.ledger_path, timeout=10) as db:
            db.execute("PRAGMA synchronous=FULL")
            changed = db.execute("UPDATE executions SET result=? WHERE rid=?", (json.dumps(result.as_dict()), record.remediation_id)).rowcount
            if changed != 1:
                raise DatabaseAdminError("database_admin_claim_missing")
            if result.status in {"SUCCESS", "BLOCKED"}:
                db.execute("DELETE FROM leases WHERE rid=?", (record.remediation_id,))

    def execute_record(self, record, target, approved_by=None):
        action = record.action_type
        mutated = False
        claimed = False
        try:
            check_record(record, self.name)
            if target != record.identity["target"] or (approved_by is not None and approved_by != record.approved_by):
                raise DatabaseAdminError("database_admin_approval_mismatch")
            plan = record.target_bindings[target]
            prior = self._claim(record, plan)
            if prior is not None: return prior
            claimed = True
            why = self.validate_record(record)
            if why: raise DatabaseAdminError(why)
            c = self._config(target)
            if action == "RESTORE_DB":
                backup, path = self._backup(c, record.action_parameters["backup_id"])
                if backup != plan["pre_snapshot"]["backup"]: raise DatabaseAdminError("restore_backup_changed")
                # No --clean, --create, ownership/ACL restoration or server-controlled SQL flags.
                # An empty isolated destination is checked immediately before the write.
                with self._connection(c) as conn:
                    self._server(conn, c, action)
                    if self._one(conn, DATABASE_SQL) != plan["pre_snapshot"]["database"]:
                        raise DatabaseAdminError("restore_destination_changed")
                # Restore the exact opened archive, not a path which could be
                # replaced between hash verification and pg_restore opening it.
                with path.open("rb") as source, tempfile.TemporaryFile(mode="w+b") as archive:
                    # Anonymous private copy makes later path replacement or
                    # in-place modification of the original irrelevant.
                    shutil.copyfileobj(source, archive, length=1024 * 1024)
                    archive.seek(0)
                    checksum = hashlib.file_digest(archive, "sha256").hexdigest()
                    if checksum != backup["sha256"] or os.fstat(archive.fileno()).st_size != backup["bytes"]:
                        raise DatabaseAdminError("restore_archive_changed_before_dispatch")
                    archive.seek(0)
                    check_record(record, self.name)
                    from executor.deployment import deadline
                    remaining = int(deadline(record.approval_expires_at) - time.time()) - 1
                    if remaining < 1: raise DatabaseAdminError("restore_approval_expiring")
                    mutated = True
                    result = self.runner(["pg_restore", "--no-password", "--single-transaction", "--exit-on-error", "--no-owner", "--no-privileges",
                                          "--dbname", c["database"]], stdin=archive, env=self._environment(c), stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL, timeout=min(c["timeout_seconds"], remaining), check=False)
                if result.returncode != 0: raise DatabaseAdminError("restore_effect_unconfirmed")
                with self._connection(c) as conn:
                    server = self._server(conn, c, action)
                    after = self._one(conn, DATABASE_SQL)
                if (server != plan["pre_snapshot"]["server"] or after.get("oid") != plan["pre_snapshot"]["database"]["oid"]
                        or after.get("relations") != backup["tables"] or after.get("datname") != c["database"]
                        or after.get("owner") != c["executor_role"] or after.get("other_sessions") != 0):
                    raise DatabaseAdminError("restore_postcondition_unconfirmed")
                result = succeeded(action, target, "isolated_database_restore_verified", after={"database_oid": after["oid"], "relations": after["relations"], "backup_sha256": backup["sha256"],
                    "restore_system_identifier": server["system_identifier"], "restored_database": c["database"],
                    "restore_server_addr": server["server_addr"], "restore_server_port": server["server_port"],
                    "restore_owner": after["owner"], "manifest_sha256": backup["manifest_sha256"],
                    "source_database_id": backup["database_id"], "restore_plan_digest": plan["plan_digest"]})
            else:
                role = record.action_parameters["role_id"]
                with self._connection(c) as conn:
                    self._server(conn, c, action)
                    before = self._role(conn, c, role)
                    if before != plan["pre_snapshot"]["role"]: raise DatabaseAdminError("database_role_changed")
                    # Validated identifiers only; no request SQL fragments or values.
                    # OID/state/postcondition checks keep a replacement or
                    # newly protected role from being committed accidentally.
                    check_record(record, self.name)
                    with conn.cursor() as cursor:
                        cursor.execute('ALTER ROLE "' + role + '" ' + ("NOLOGIN" if action == "DISABLE_DB_ROLE" else "LOGIN"))
                    after = self._role(conn, c, role)
                    if after["oid"] != before["oid"] or after["rolcanlogin"] is not (action == "ENABLE_DB_ROLE"):
                        raise DatabaseAdminError("database_role_postcondition_unconfirmed")
                    check_record(record, self.name)
                    mutated = True
                    conn.commit()
                result = succeeded(action, target, "database_role_login_state_verified", before=before, after=after)
        except Exception:
            result = (ExecutionResult(action, target, "UNKNOWN", detail="database_admin_effect_unconfirmed_no_retry") if mutated
                      else blocked(action, target, "database_admin_preflight_or_approval_rejected"))
        if not claimed:
            return result
        try:
            self._finish(record, result)
        except Exception:
            return ExecutionResult(action, target, "UNKNOWN", detail="database_admin_result_persistence_unconfirmed")
        return result
