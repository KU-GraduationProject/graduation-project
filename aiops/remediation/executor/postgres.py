"""Approved PostgreSQL 17 session maintenance through fixed, parameterized SQL.

No arbitrary SQL, service restart, backup, restore or schema/role mutation. A plan
pins cluster/database/TCP identity and exact backend/query incarnations before
approval. Native pg_cancel_backend/pg_terminate_backend ultimately signal a PID;
pg_stat_activity cannot be locked against the target starting its next query.
The same-statement predicates narrow that unavoidable server-side race, rather
than claiming atomic query cancellation or exactly-once database effects.

References: postgresql.org/docs/17/functions-admin.html#FUNCTIONS-ADMIN-SIGNAL
and postgresql.org/docs/17/monitoring-stats.html#MONITORING-PG-STAT-ACTIVITY-VIEW.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import time

import yaml

from executor.base import Executor, ExecutionResult, blocked, succeeded

IDENTITY_FIELDS = ("site", "service", "source", "runtime", "target")
OPERATIONS = ("terminate_idle_sessions", "cancel_long_queries")
_ENV = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")

# No raw query text is selected, returned or persisted.
SERVER_SQL = """/* leafy:server_identity */
SELECT current_database() AS database, inet_server_addr()::text AS server_addr,
       inet_server_port() AS server_port,
       (pg_catalog.pg_control_system()).system_identifier::text AS system_identifier,
       current_setting('server_version_num')::int AS server_version,
       pg_catalog.pg_is_in_recovery() AS in_recovery,
       pg_backend_pid() AS observer_pid, current_user AS executor_role,
       r.rolsuper, r.rolreplication, r.rolcreaterole, r.rolcreatedb, r.rolbypassrls,
       pg_catalog.pg_has_role(current_user, 'pg_signal_backend', 'USAGE') AS can_signal,
       pg_catalog.pg_has_role(current_user, 'pg_read_all_stats', 'USAGE') AS can_read_stats
FROM pg_catalog.pg_roles r WHERE r.rolname = current_user
"""
_BASE_FILTER = """
    a.datname = %s AND a.pid <> pg_backend_pid()
    AND a.backend_type = 'client backend'
    AND a.usename = ANY(%s::text[])
    AND a.application_name = ANY(%s::text[])
    AND a.client_addr = ANY(%s::inet[])
    AND a.usename <> current_user
    AND NOT r.rolsuper AND NOT r.rolreplication
    AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolbypassrls
    AND a.usename !~ '^pg_' AND a.usename <> 'postgres'
    AND NOT pg_catalog.pg_has_role(a.usesysid, 'pg_signal_backend', 'MEMBER')
    AND NOT pg_catalog.pg_has_role(a.usesysid, 'pg_read_all_stats', 'MEMBER')
    AND NOT pg_catalog.pg_has_role(a.usesysid, 'pg_use_reserved_connections', 'MEMBER')
"""
_FILTERS = {
    "terminate_idle_sessions": """AND a.state = 'idle' AND a.xact_start IS NULL
        AND a.backend_xid IS NULL AND a.backend_xmin IS NULL
        AND a.state_change <= clock_timestamp() - (%s * interval '1 second')""",
    # Only a transaction's first statement is eligible; an explicit BEGIN then
    # query, idle-in-transaction and replication/maintenance backends are excluded.
    "cancel_long_queries": """AND a.state = 'active' AND a.query_start IS NOT NULL
        AND a.xact_start = a.query_start
        AND a.query_start <= clock_timestamp() - (%s * interval '1 second')""",
}
_SESSION_COLUMNS = """a.pid, a.backend_start, a.query_start, a.state, a.state_change,
    a.usename, a.application_name, a.client_addr::text AS client_addr, a.xact_start"""
SELECT_SQL = {operation: "/* leafy:select:" + operation + " */\nSELECT " + _SESSION_COLUMNS +
    " FROM pg_catalog.pg_stat_activity a JOIN pg_catalog.pg_roles r ON r.oid = a.usesysid WHERE " +
    _BASE_FILTER + _FILTERS[operation] + " ORDER BY a.backend_start, a.pid LIMIT %s"
    for operation in OPERATIONS}
# The signal and complete incarnation/allowlist/state test are in ONE SQL
# statement. pg_stat_activity is a view and SELECT FOR UPDATE is not a solution.
MUTATE_SQL = {operation: "/* leafy:mutate:" + operation + " */\nWITH candidate AS MATERIALIZED (SELECT a.pid "
    "FROM pg_catalog.pg_stat_activity a JOIN pg_catalog.pg_roles r ON r.oid = a.usesysid WHERE " +
    _BASE_FILTER + _FILTERS[operation] + """
    AND a.pid = %s AND a.backend_start = %s::timestamptz
    AND a.query_start IS NOT DISTINCT FROM %s::timestamptz
    AND a.state = %s AND a.state_change = %s::timestamptz
    AND clock_timestamp() < %s::timestamptz)
SELECT """ + ("pg_catalog.pg_terminate_backend(pid, 1000)" if operation == "terminate_idle_sessions"
                  else "pg_catalog.pg_cancel_backend(pid)") + " AS signaled FROM candidate"
    for operation in OPERATIONS}
VERIFY_SQL = """/* leafy:verify */ SELECT pid, backend_start, query_start, state
FROM pg_catalog.pg_stat_activity WHERE pid = %s AND backend_start = %s::timestamptz"""


class PostgresError(ValueError):
    """Public errors are fixed codes, never libpq credentials/query text."""


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value):
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _stamp(value):
    if value is None:
        return None
    try:
        dt = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            raise ValueError()
        return dt.astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError, OverflowError):
        raise PostgresError("invalid_session_timestamp") from None


def _positive(value, low, high):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise PostgresError("invalid_postgres_limit")
    return value


def _identity(value):
    if (not isinstance(value, dict) or set(value) != set(IDENTITY_FIELDS)
            or any(not isinstance(v, str) or not v.strip() or v != v.strip() for v in value.values())
            or value.get("service") != "db" or value.get("runtime") not in {"host", "container"}
            or not _NAME.fullmatch(value.get("target", ""))):
        raise PostgresError("invalid_postgres_identity")
    return dict(value)


def _names(values, role=False):
    if (not isinstance(values, list) or not 1 <= len(values) <= 32 or
            any(not isinstance(v, str) or not 1 <= len(v) <= 128 or v != v.strip()
                or not v or any(ord(c) < 32 or ord(c) == 127 for c in v) for v in values) or
            len(set(values)) != len(values)):
        raise PostgresError("invalid_postgres_allowlist")
    if role and any(not _NAME.fullmatch(v) or v == "postgres" or v.startswith("pg_") for v in values):
        raise PostgresError("administrator_role_not_allowed")
    # application_name is a value, not an SQL identifier. JDBC's default name
    # contains spaces; it is still matched exactly through a bound text array.
    return list(values)


def _addresses(values):
    if not isinstance(values, list) or not 1 <= len(values) <= 32:
        raise PostgresError("invalid_postgres_client_allowlist")
    try:
        # Exact IPs only; broad subnets, NULL/local sockets and wildcards excluded.
        return [str(ipaddress.ip_address(v)) for v in values]
    except (ValueError, TypeError):
        raise PostgresError("invalid_postgres_client_allowlist") from None


def _connect_default(**kwargs):
    import psycopg
    from psycopg.rows import dict_row
    return psycopg.connect(**kwargs, row_factory=dict_row)


class PostgresExecutor(Executor):
    name = "postgres"
    changes_system = True

    def __init__(self, config_path=None, connection_factory=None, ledger_path=None):
        self.config_path = config_path
        self.connection_factory = connection_factory or _connect_default
        self.ledger_path = ledger_path or os.path.join(
            os.getenv("REMEDIATION_STATE_DIR", "/app/state"), "postgres_executions.sqlite")

    @classmethod
    def from_env(cls):
        return cls()

    def _config(self, target):
        path = self.config_path or os.getenv("REMEDIATION_POSTGRES_CONFIG_PATH", "")
        try:
            raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) if path else None
            if (not isinstance(raw, dict) or set(raw) != {"version", "targets"} or type(raw["version"]) is not int or raw["version"] != 1
                    or not isinstance(raw["targets"], dict)):
                raise ValueError()
            cfg = raw["targets"][target]
            required = {"identity", "system_identifier", "database", "server_addr", "server_port", "connection", "executor_role",
                        "allowed_roles", "allowed_applications", "allowed_client_addrs",
                        "min_idle_seconds", "min_query_seconds", "max_sessions"}
            if not isinstance(cfg, dict) or set(cfg) != required:
                raise ValueError()
            _identity(cfg["identity"])
            if cfg["identity"]["target"] != target or not _NAME.fullmatch(cfg["database"]):
                raise ValueError()
            if not isinstance(cfg["system_identifier"], str) or not re.fullmatch(r"[0-9]{1,20}", cfg["system_identifier"]):
                raise ValueError()
            cfg["server_addr"] = str(ipaddress.ip_address(cfg["server_addr"]))
            _positive(cfg["server_port"], 1, 65535)
            _positive(cfg["min_idle_seconds"], 30, 86400)
            _positive(cfg["min_query_seconds"], 30, 86400)
            _positive(cfg["max_sessions"], 1, 20)
            cfg["allowed_roles"] = _names(cfg["allowed_roles"], role=True)
            if (not isinstance(cfg["executor_role"], str) or not _NAME.fullmatch(cfg["executor_role"])
                    or cfg["executor_role"] == "postgres" or cfg["executor_role"].startswith("pg_")
                    or cfg["executor_role"] in cfg["allowed_roles"]):
                raise ValueError()
            cfg["allowed_applications"] = _names(cfg["allowed_applications"])
            cfg["allowed_client_addrs"] = _addresses(cfg["allowed_client_addrs"])
            conn = cfg["connection"]
            env_fields = {"host_env", "port_env", "dbname_env", "user_env", "password_env"}
            if (not isinstance(conn, dict) or set(conn) != env_fields | {"sslmode"}
                    or any(not isinstance(conn[k], str) or not _ENV.fullmatch(conn[k]) for k in env_fields)
                    or conn["sslmode"] not in {"verify-full", "require", "disable"}):
                raise ValueError()
            return cfg
        except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError):
            raise PostgresError("postgres_target_not_configured_or_invalid") from None

    def _parameters(self, cfg, parameters):
        if (not isinstance(parameters, dict) or set(parameters) - {"operation", "min_age_seconds", "max_sessions"}
                or parameters.get("operation") not in OPERATIONS):
            raise PostgresError("postgres_operation_required")
        operation = parameters["operation"]
        minimum = cfg["min_idle_seconds" if operation == "terminate_idle_sessions" else "min_query_seconds"]
        age = _positive(parameters.get("min_age_seconds", minimum), minimum, 86400)
        count = _positive(parameters.get("max_sessions", cfg["max_sessions"]), 1, cfg["max_sessions"])
        return {"operation": operation, "min_age_seconds": age, "max_sessions": count}

    @contextmanager
    def _connection(self, cfg):
        conn = None
        try:
            secret = cfg["connection"]
            values = {key: os.environ[secret[key + "_env"]] for key in ("host", "port", "dbname", "user", "password")}
            # Explicit hostaddr prevents ambient PGHOSTADDR/services from rerouting
            # an otherwise pinned host; no multi-host failover or socket default.
            host = str(ipaddress.ip_address(values["host"]))
            port = int(values["port"])
            if not 1 <= port <= 65535 or values["dbname"] != cfg["database"] or values["user"] != cfg["executor_role"] or not values["password"]:
                raise ValueError()
            conn = self.connection_factory(host=host, hostaddr=host, port=port,
                dbname=values["dbname"], user=values["user"], password=values["password"],
                sslmode=secret["sslmode"], connect_timeout=5, autocommit=True,
                application_name="leafy-remediation", target_session_attrs="read-write",
                options="-c statement_timeout=5000 -c lock_timeout=1000 -c search_path=pg_catalog")
            yield conn
        except PostgresError:
            raise
        except Exception:
            raise PostgresError("postgres_connection_or_request_failed") from None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    @staticmethod
    def _query(conn, sql, params=()):
        cursor = conn.cursor()
        try:
            cursor.execute(sql, params)
            return [dict(row) for row in cursor.fetchall()]
        finally:
            try:
                cursor.close()
            except Exception:
                pass

    def _server(self, conn, cfg):
        rows = self._query(conn, SERVER_SQL)
        if len(rows) != 1:
            raise PostgresError("postgres_server_identity_unavailable")
        row = rows[0]
        expected = {k: cfg[k] for k in ("system_identifier", "database", "server_addr", "server_port")}
        try:
            actual = {k: row[k] for k in expected}
            actual["server_addr"] = str(ipaddress.ip_address(actual["server_addr"]))
            if (actual != expected or not 170000 <= row["server_version"] < 180000
                    or row["in_recovery"] is not False
                    or any(row[k] is not False for k in ("rolsuper", "rolreplication", "rolcreaterole", "rolcreatedb", "rolbypassrls"))
                    or row["can_signal"] is not True or row["can_read_stats"] is not True
                    or row["executor_role"] != cfg["executor_role"]):
                raise ValueError()
        except (KeyError, ValueError, TypeError):
            raise PostgresError("postgres_server_identity_or_privilege_mismatch") from None
        return expected

    @staticmethod
    def _filter_params(cfg, parameters):
        return (cfg["database"], cfg["allowed_roles"], cfg["allowed_applications"],
                cfg["allowed_client_addrs"], parameters["min_age_seconds"])

    @staticmethod
    def _session(row):
        try:
            if isinstance(row["pid"], bool) or not isinstance(row["pid"], int) or row["pid"] <= 0:
                raise ValueError()
            result = {k: row[k] for k in ("pid", "state", "usename", "application_name", "client_addr")}
            result.update({k: _stamp(row[k]) for k in ("backend_start", "query_start", "state_change", "xact_start")})
            if not result["backend_start"] or not result["state_change"]:
                raise ValueError()
            return result
        except (KeyError, ValueError, TypeError):
            raise PostgresError("invalid_postgres_session_snapshot") from None

    def plan_record(self, identity, targets, action_type, parameters):
        identity = _identity(identity)
        target = identity["target"]
        if action_type != "KILL_SESSIONS" or list(targets) != [target]:
            raise PostgresError("postgres_action_target_mismatch")
        cfg = self._config(target)
        if cfg["identity"] != identity:
            raise PostgresError("postgres_identity_mapping_mismatch")
        effective = self._parameters(cfg, parameters)
        with self._connection(cfg) as conn:
            resource = self._server(conn, cfg)
            sessions = [self._session(row) for row in self._query(conn,
                SELECT_SQL[effective["operation"]], self._filter_params(cfg, effective) + (effective["max_sessions"],))]
        if not sessions or len(sessions) > effective["max_sessions"]:
            raise PostgresError("no_eligible_postgres_sessions_or_invalid_snapshot")
        return {target: {"executor": self.name, "identity": identity, "config_digest": _digest(cfg),
            "action_type": action_type, "request_parameters": dict(parameters), "parameters": effective,
            "resource": resource, "sessions": sessions}}

    def _bound(self, record):
        identity = _identity(record.identity)
        target = identity["target"]
        if record.action_type != "KILL_SESSIONS" or record.targets != [target] or record.executor_name != self.name:
            raise PostgresError("postgres_record_context_mismatch")
        cfg = self._config(target)
        plan = record.target_bindings.get(target)
        expected_keys = {"executor", "identity", "config_digest", "action_type", "request_parameters", "parameters", "resource", "sessions"}
        if (not isinstance(plan, dict) or set(plan) != expected_keys or plan["identity"] != identity
                or plan["executor"] != self.name or cfg["identity"] != identity
                or plan["config_digest"] != _digest(cfg) or plan["action_type"] != record.action_type
                or plan["request_parameters"] != record.action_parameters
                or plan["parameters"] != self._parameters(cfg, record.action_parameters)
                or plan["resource"] != {k: cfg[k] for k in ("system_identifier", "database", "server_addr", "server_port")}
                or not isinstance(plan["sessions"], list) or not 1 <= len(plan["sessions"]) <= plan["parameters"]["max_sessions"]
                or len({s.get("pid") for s in plan["sessions"]}) != len(plan["sessions"])):
            raise PostgresError("postgres_approved_plan_mismatch")
        for session in plan["sessions"]:
            if self._session(session) != session:
                raise PostgresError("postgres_approved_plan_mismatch")
        import store
        if (not record.incident_key or record.action_hash != store.action_hash(record.action_type,
                record.targets, record.ttl_seconds, record.recovery_mode, record.action_parameters)):
            raise PostgresError("postgres_approved_action_hash_mismatch")
        return cfg, plan

    def validate_record(self, record):
        try:
            cfg, plan = self._bound(record)
            with self._connection(cfg) as conn:
                self._server(conn, cfg)
            return None
        except Exception:
            return "postgres_record_or_target_validation_failed"

    @staticmethod
    def _approved(record, approved_by):
        import store
        try:
            if (record.state != store.EXECUTING or record.requires_approval is not True
                    or not record.approved_by or approved_by != record.approved_by
                    or not record.approved_at or not record.action_started_at or not store.approval_valid(record)):
                return False
            stamps = [store._parse_ts(getattr(record, key)) for key in
                      ("approval_requested_at", "approved_at", "action_started_at")]
            return all(value is not None for value in stamps) and stamps[0] <= stamps[1] <= stamps[2] <= time.time()
        except (ValueError, TypeError, AttributeError):
            return False

    @contextmanager
    def _ledger(self):
        db = None
        try:
            Path(self.ledger_path).parent.mkdir(parents=True, exist_ok=True)
            db = sqlite3.connect(self.ledger_path, timeout=2)
            db.execute("PRAGMA synchronous=FULL")
            db.execute("CREATE TABLE IF NOT EXISTS executions (rid TEXT, target TEXT, plan_hash TEXT NOT NULL, result TEXT, PRIMARY KEY(rid,target))")
            db.commit()
            yield db
        finally:
            if db is not None:
                db.close()

    def _claim(self, rid, target, plan):
        with self._ledger() as db:
            try:
                db.execute("INSERT INTO executions(rid,target,plan_hash) VALUES (?,?,?)", (rid, target, _digest(plan)))
                db.commit()
                return None
            except sqlite3.IntegrityError:
                row = db.execute("SELECT plan_hash,result FROM executions WHERE rid=? AND target=?", (rid, target)).fetchone()
                if row[0] != _digest(plan):
                    return blocked("KILL_SESSIONS", target, "postgres_execution_id_conflict")
                if row[1]:
                    return ExecutionResult(**json.loads(row[1]))
                return ExecutionResult("KILL_SESSIONS", target, "UNKNOWN", detail="postgres_previous_dispatch_unresolved")

    def _finish(self, rid, target, result):
        try:
            with self._ledger() as db:
                db.execute("UPDATE executions SET result=? WHERE rid=? AND target=?", (_canonical(result.as_dict()), rid, target))
                db.commit()
        except Exception:
            return ExecutionResult("KILL_SESSIONS", target, "UNKNOWN", detail="postgres_result_ledger_unavailable")
        return result

    def execute_record(self, record, target, approved_by=None):
        if not self._approved(record, approved_by or record.approved_by):
            return blocked("KILL_SESSIONS", target, "postgres_current_manual_approval_required")
        try:
            cfg, plan = self._bound(record)
            if target != record.identity["target"]:
                raise PostgresError("postgres_action_target_mismatch")
            if (not isinstance(record.evidence, dict) or
                    record.evidence.get("targets", {}).get(target) != plan):
                raise PostgresError("postgres_durable_plan_evidence_required")
            cached = self._claim(record.remediation_id, target, plan)
            if cached is not None:
                return cached
        except Exception:
            return blocked("KILL_SESSIONS", target, "postgres_plan_or_durable_claim_invalid")
        dispatched = False
        outcomes = []
        try:
            with self._connection(cfg) as conn:
                self._server(conn, cfg)
                for session in plan["sessions"]:
                    if not self._approved(record, approved_by or record.approved_by):
                        raise PostgresError("postgres_approval_expired_before_dispatch")
                    operation = plan["parameters"]["operation"]
                    args = self._filter_params(cfg, plan["parameters"]) + (
                        session["pid"], session["backend_start"], session["query_start"], session["state"],
                        session["state_change"], record.approval_expires_at)
                    dispatched = True  # driver errors cannot establish non-delivery
                    rows = self._query(conn, MUTATE_SQL[operation], args)
                    if not rows:
                        # Same-statement predicate rejected a stale session; the
                        # function was not called for this target incarnation.
                        if not outcomes:
                            result = blocked("KILL_SESSIONS", target, "postgres_session_changed_reapproval_required")
                            return self._finish(record.remediation_id, target, result)
                        raise PostgresError("postgres_partial_plan_changed")
                    if len(rows) != 1 or rows[0].get("signaled") is not True:
                        raise PostgresError("postgres_signal_unconfirmed")
                    confirmed = False
                    for attempt in range(3):
                        after = self._query(conn, VERIFY_SQL, (session["pid"], session["backend_start"]))
                        if not after or (operation == "cancel_long_queries" and len(after) == 1 and (
                                after[0].get("state") != "active" or _stamp(after[0].get("query_start")) != session["query_start"])):
                            confirmed = True
                            break
                        if attempt < 2:
                            time.sleep(0.05)  # bounded read-only verification; never resend the signal
                    if not confirmed:
                        raise PostgresError("postgres_effect_unconfirmed")
                    outcomes.append({"pid": session["pid"], "backend_start": session["backend_start"], "verified": True})
            result = succeeded("KILL_SESSIONS", target, "postgres_selected_sessions_effect_verified",
                               before={"operation": plan["parameters"]["operation"], "selected_count": len(plan["sessions"])},
                               after={"sessions": outcomes, "service_recovery_verified": False})
        except Exception:
            result = (ExecutionResult("KILL_SESSIONS", target, "UNKNOWN", detail="postgres_dispatch_or_effect_unconfirmed_no_retry",
                                      after={"verified_sessions": outcomes}) if dispatched else
                      blocked("KILL_SESSIONS", target, "postgres_preflight_failed_no_signal"))
        return self._finish(record.remediation_id, target, result)

    def execute(self, action, target, evidence):
        return blocked(action, target, "postgres_approved_record_required")
