"""Explicit same-cluster staged-restore cutover; retain both database copies.

No DROP DATABASE, restore-to-live, arbitrary SQL or caller-provided connection
settings. Fences commit before session draining; any later uncertain outcome is
UNKNOWN and cannot be retried. Reversal is a separately approved new cutover.
"""
from __future__ import annotations

from contextlib import contextmanager, closing
from copy import deepcopy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
import time

import yaml

from executor.base import ExecutionResult, blocked, succeeded
from executor.managed import ExecutionJournal, seal_plan, valid_plan_digest, check_record, digest

ACTIONS = frozenset({"PROMOTE_RESTORED_DB", "ROLLBACK_DB_PROMOTION"})
RECOVERY_MAP = {"PROMOTE_RESTORED_DB": "ROLLBACK_DB_PROMOTION"}
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}\Z")
RID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
HEX = re.compile(r"[a-f0-9]{64}\Z")
ENV = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")
_LOCK = threading.RLock()
SERVER = """/* leafy:promotion_server */ SELECT current_database() AS database,
 current_user AS executor_role, inet_server_addr()::text AS server_addr, inet_server_port() AS server_port,
 (pg_catalog.pg_control_system()).system_identifier::text AS system_identifier,
 pg_catalog.pg_is_in_recovery() AS in_recovery, current_setting('server_version_num')::int AS server_version,
 r.rolsuper, r.rolcreatedb, r.rolcreaterole, r.rolreplication, r.rolbypassrls
 FROM pg_catalog.pg_roles r WHERE rolname=current_user"""
DATABASE = """/* leafy:promotion_database */ SELECT d.oid::bigint AS oid, d.datname,
 pg_catalog.pg_get_userbyid(d.datdba) AS owner, d.datallowconn AS allow_connections, d.datistemplate AS is_template,
 EXISTS(SELECT 1 FROM aclexplode(coalesce(d.datacl,acldefault('d',d.datdba))) a
 WHERE a.grantee=0 AND a.privilege_type='CONNECT') AS public_connect
 FROM pg_catalog.pg_database d WHERE d.datname=%s"""
SESSIONS = """/* leafy:promotion_sessions */ SELECT a.pid, a.datid::bigint AS datid, a.usename,
 a.backend_type, a.backend_start::text AS backend_start, r.rolsuper
 FROM pg_catalog.pg_stat_activity a LEFT JOIN pg_catalog.pg_roles r ON r.rolname=a.usename
 WHERE a.datid=ANY(%s) AND a.pid<>pg_backend_pid() ORDER BY a.pid"""
PREPARED = """/* leafy:promotion_prepared */ SELECT count(*)::int AS count
 FROM pg_catalog.pg_prepared_xacts WHERE database=ANY(%s)"""
ROLE = """/* leafy:promotion_app_role */ SELECT oid::bigint AS oid, rolname,
 rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls,
 EXISTS(SELECT 1 FROM pg_roles p WHERE p.oid<>r.oid AND pg_has_role(r.oid,p.oid,'MEMBER')
 AND (p.rolsuper OR p.rolcreatedb OR p.rolcreaterole OR p.rolreplication OR p.rolbypassrls)) AS privileged_membership
 FROM pg_roles r WHERE rolname=%s"""


class PromotionError(ValueError):
    pass


def validate_parameters(action, params):
    if action not in ACTIONS or not isinstance(params, dict): raise PromotionError("invalid_database_promotion_parameters")
    if action == "ROLLBACK_DB_PROMOTION":
        if set(params) != {"parent_id"} or not isinstance(params["parent_id"], str) or not RID.fullmatch(params["parent_id"]):
            raise PromotionError("verified_promotion_parent_required")
    elif (set(params) != {"source_record_id", "confirm_database", "allow_data_loss"}
          or not isinstance(params["source_record_id"], str) or not RID.fullmatch(params["source_record_id"])
          or not isinstance(params["confirm_database"], str) or not NAME.fullmatch(params["confirm_database"])
          or params["allow_data_loss"] is not True):
        raise PromotionError("explicit_database_cutover_consent_required")


def _connect(**kwargs):
    import psycopg
    from psycopg.rows import dict_row
    return psycopg.connect(**kwargs, row_factory=dict_row)


def quote(name):
    if not isinstance(name, str) or not NAME.fullmatch(name): raise PromotionError("single_database_identifier_required")
    return '"' + name + '"'


class DatabasePromotionExecutor:
    name = "database_promotion"
    changes_system = True

    def __init__(self, config_path=None, connection_factory=None, sleep=None):
        self.config_path = config_path
        self.connection_factory = connection_factory or _connect
        self.sleep = sleep or time.sleep

    def _config(self, target):
        try:
            p = self.config_path or os.environ["REMEDIATION_DATABASE_PROMOTION_CONFIG_PATH"]
            doc = yaml.safe_load(Path(p).read_text())
            if set(doc) != {"version", "enabled", "journal_path", "targets"} or type(doc["version"]) is not int or doc["version"] != 1 or doc["enabled"] is not True:
                raise ValueError()
            c = doc["targets"][target]
            expected = {"identity", "service_database", "staging_database", "service_oid", "staging_oid", "executor_role",
                        "system_identifier", "server_addr", "server_port", "connection", "restore_ledger_path",
                        "restore_target", "restore_plan_digest", "backup_manifest_file", "application_roles",
                        "application_access", "maintenance_confirmed", "timeout_seconds"}
            if set(c) != expected or c["maintenance_confirmed"] is not True: raise ValueError()
            ident = c["identity"]
            if (set(ident) != {"site", "source", "service", "runtime", "target"} or ident["target"] != target
                    or ident["service"] != "db" or ident["runtime"] not in {"host", "container"}
                    or any(not isinstance(v, str) or not v.strip() or v.strip() != v or v.lower() == "unknown" for v in ident.values())):
                raise ValueError()
            for key in ("service_database", "staging_database", "executor_role"):
                quote(c[key])
                if c[key] in {"postgres", "template0", "template1"} or c[key].startswith("pg_"): raise ValueError()
            if c["service_database"] == c["staging_database"] or not c["staging_database"].startswith("restore_"): raise ValueError()
            if (type(c["service_oid"]) is not int or type(c["staging_oid"]) is not int or c["service_oid"] < 1
                    or c["staging_oid"] < 1 or c["service_oid"] == c["staging_oid"]
                    or not re.fullmatch(r"[0-9]{1,20}", c["system_identifier"])
                    or str(ipaddress.ip_address(c["server_addr"])) != c["server_addr"]
                    or type(c["server_port"]) is not int or not 1 <= c["server_port"] <= 65535
                    or not HEX.fullmatch(c["restore_plan_digest"]) or not RID.fullmatch(c["restore_target"])
                    or type(c["timeout_seconds"]) is not int or not 1 <= c["timeout_seconds"] <= 120): raise ValueError()
            if not isinstance(c["application_roles"], list) or not c["application_roles"] or len(c["application_roles"]) > 10 or len(set(c["application_roles"])) != len(c["application_roles"]): raise ValueError()
            for role in c["application_roles"]:
                quote(role)
                if role == c["executor_role"] or role in {"postgres", "PUBLIC"} or role.startswith("pg_"): raise ValueError()
            conn = c["connection"]
            if (set(conn) != {"host_env", "port_env", "user_env", "pgpassfile_env", "sslmode"}
                    or any(not ENV.fullmatch(str(conn[k])) for k in conn if k != "sslmode") or conn["sslmode"] not in {"verify-full", "require"}): raise ValueError()
            if conn["sslmode"] == "require" and not ipaddress.ip_address(c["server_addr"]).is_loopback:
                raise ValueError("remote promotion requires verified server certificate")
            access = c["application_access"]
            if not isinstance(access, list) or not 1 <= len(access) <= 100: raise ValueError()
            for a in access:
                if (set(a) != {"role", "kind", "schema", "name", "privilege"} or a["role"] not in c["application_roles"]
                        or a["kind"] not in {"table", "sequence", "schema"}): raise ValueError()
                quote(a["schema"]); quote(a["name"])
                permitted = {"table": {"SELECT", "INSERT", "UPDATE", "DELETE"}, "sequence": {"USAGE", "SELECT", "UPDATE"}, "schema": {"USAGE"}}
                if a["privilege"] not in permitted[a["kind"]]: raise ValueError()
            for path in (doc["journal_path"], c["restore_ledger_path"], c["backup_manifest_file"]):
                obj = Path(path)
                if not obj.is_absolute() or any(p.is_symlink() for p in (obj, *obj.parents)): raise ValueError()
            return {**c, "journal_path": doc["journal_path"]}
        except Exception:
            raise PromotionError("database_promotion_unconfigured_or_invalid") from None

    @contextmanager
    def _connection(self, c, database="postgres"):
        conn = None
        try:
            spec = c["connection"]
            host, port, user, passfile = (os.environ[spec[k+"_env"]] for k in ("host", "port", "user", "pgpassfile"))
            path = Path(passfile)
            if (host != c["server_addr"] or int(port) != c["server_port"] or user != c["executor_role"]
                    or not path.is_absolute() or path.is_symlink() or not path.is_file()
                    or (os.name != "nt" and path.stat().st_mode & 0o077)): raise ValueError()
            conn = self.connection_factory(host=host, hostaddr=host, port=int(port), dbname=database, user=user,
                passfile=passfile, sslmode=spec["sslmode"], connect_timeout=5, target_session_attrs="read-write",
                options="-c statement_timeout=" + str(c["timeout_seconds"]*1000) + " -c lock_timeout=3000",
                application_name="leafy-database-promotion", autocommit=False)
            yield conn
        except PromotionError:
            raise
        except Exception:
            raise PromotionError("database_promotion_connection_or_query_failed") from None
        finally:
            if conn is not None: conn.close()

    @staticmethod
    def _one(conn, sql, args=()):
        with conn.cursor() as cursor:
            cursor.execute(sql, args); result = cursor.fetchone()
        if not isinstance(result, dict): raise PromotionError("promotion_observation_missing")
        return dict(result)

    @staticmethod
    def _all(conn, sql, args=()):
        with conn.cursor() as cursor:
            cursor.execute(sql, args); result = cursor.fetchall()
        if not isinstance(result, list) or any(not isinstance(r, dict) for r in result): raise PromotionError("promotion_observation_invalid")
        return [dict(x) for x in result]

    def _server(self, conn, c, database="postgres"):
        s = self._one(conn, SERVER)
        if (s.get("database") != database or any(s.get(k) != c[k] for k in ("executor_role", "server_addr", "server_port", "system_identifier"))
                or s.get("in_recovery") is not False or s.get("rolcreatedb") is not True
                or any(s.get(k) is not False for k in ("rolsuper", "rolcreaterole", "rolreplication", "rolbypassrls"))
                or type(s.get("server_version")) is not int or not 160000 <= s["server_version"] < 180000):
            raise PromotionError("promotion_server_or_owner_privilege_mismatch")
        return {k: s[k] for k in ("system_identifier", "server_addr", "server_port", "executor_role", "server_version")}

    def _db(self, conn, c, name, oid=None):
        d = self._one(conn, DATABASE, (name,))
        if (d.get("datname") != name or type(d.get("oid")) is not int or (oid is not None and d["oid"] != oid)
                or d.get("owner") != c["executor_role"] or d.get("is_template") is not False
                or type(d.get("allow_connections")) is not bool or type(d.get("public_connect")) is not bool):
            raise PromotionError("promotion_database_identity_mismatch")
        return d

    def _restore(self, c, rid):
        try:
            uri = Path(c["restore_ledger_path"]).as_uri() + "?mode=ro"
            with closing(sqlite3.connect(uri, uri=True)) as db:
                row = db.execute("SELECT target,digest,result FROM executions WHERE rid=?", (rid,)).fetchone()
            result = json.loads(row[2]) if row and row[2] else None
            if (not row or row[0] != c["restore_target"] or row[1] != c["restore_plan_digest"]
                    or not isinstance(result, dict) or result.get("action") != "RESTORE_DB"
                    or result.get("target") != c["restore_target"] or result.get("status") != "SUCCESS" or result.get("verified") is not True
                    or result.get("after", {}).get("database_oid") != c["staging_oid"]
                    or result["after"].get("restore_system_identifier") != c["system_identifier"]
                    or result["after"].get("restored_database") != c["staging_database"]
                    or result["after"].get("restore_server_addr") != c["server_addr"]
                    or result["after"].get("restore_server_port") != c["server_port"]
                    or result["after"].get("restore_owner") != c["executor_role"]
                    or result["after"].get("restore_plan_digest") != row[1]): raise ValueError()
            body = Path(c["backup_manifest_file"]).read_bytes(); manifest = json.loads(body)
            if (manifest.get("verified") is not True or manifest.get("restore_list_verified") is not True
                    or manifest.get("format") != "postgres-custom"
                    or manifest.get("database_id") != c["system_identifier"]+":"+c["service_database"]
                    or manifest.get("sha256") != result["after"].get("backup_sha256")
                    or hashlib.sha256(body).hexdigest() != result["after"].get("manifest_sha256")
                    or manifest.get("database_id") != result["after"].get("source_database_id")
                    or not HEX.fullmatch(str(manifest.get("sha256")))
                    or type(result["after"].get("relations")) is not int or result["after"]["relations"] < 1): raise ValueError()
            return {"record_id": rid, "restore_plan_digest": row[1], "manifest_sha256": hashlib.sha256(body).hexdigest(),
                    "backup_sha256": manifest["sha256"], "staging_oid": c["staging_oid"]}
        except Exception:
            raise PromotionError("verified_same_service_restore_source_required") from None

    def _roles(self, conn, c):
        roles = []
        for name in c["application_roles"]:
            r = self._one(conn, ROLE, (name,))
            if (r.get("rolname") != name or type(r.get("oid")) is not int
                    or any(r.get(k) is not False for k in ("rolsuper", "rolcreatedb", "rolcreaterole", "rolreplication", "rolbypassrls", "privileged_membership"))):
                raise PromotionError("protected_application_role")
            roles.append({"name": name, "oid": r["oid"]})
        return roles

    def _access(self, c, database):
        with self._connection(c, database) as conn:
            self._server(conn, c, database)
            for a in c["application_access"]:
                function = {"table": "has_table_privilege", "sequence": "has_sequence_privilege", "schema": "has_schema_privilege"}[a["kind"]]
                resource = a["schema"] if a["kind"] == "schema" else a["schema"] + "." + a["name"]
                ok = self._one(conn, "/* leafy:promotion_access */ SELECT pg_catalog." + function + "(%s,%s,%s) AS allowed", (a["role"], resource, a["privilege"]))
                if ok.get("allowed") is not True: raise PromotionError("staging_application_grants_unverified")

    def _sessions(self, conn, c, oids):
        # pg_stat_activity can be cached within a transaction; session draining
        # must observe fresh backend exits after each termination signal.
        with conn.cursor() as cursor:
            cursor.execute("/* leafy:promotion_clear_stats */ SELECT pg_stat_clear_snapshot()")
        sessions = self._all(conn, SESSIONS, (list(oids),))
        for s in sessions:
            if (type(s.get("pid")) is not int or type(s.get("datid")) is not int or s["datid"] not in oids
                    or s.get("usename") not in c["application_roles"] or s.get("rolsuper") is not False
                    or s.get("backend_type") != "client backend" or not isinstance(s.get("backend_start"), str)):
                raise PromotionError("unexpected_or_protected_database_session")
        return sessions

    def _parent(self, c, rid):
        with ExecutionJournal(c["journal_path"]).connection() as db:
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='database_promotions'").fetchone():
                raise PromotionError("verified_database_promotion_parent_required")
            row = db.execute("SELECT body FROM database_promotions WHERE rid=?", (rid,)).fetchone()
        p = json.loads(row[0]) if row else None
        if (not isinstance(p, dict) or p.get("state") != "SUCCESS" or p.get("action_type") != "PROMOTE_RESTORED_DB" or p.get("identity") != c["identity"] or p.get("config_sha256") != digest(c)):
            raise PromotionError("verified_database_promotion_parent_required")
        return p

    def plan_record(self, identity, targets, action_type, parameters):
        validate_parameters(action_type, parameters)
        c = self._config(identity.get("target"))
        if identity != c["identity"] or list(targets) != [identity["target"]]: raise PromotionError("promotion_exact_identity_required")
        parent = self._parent(c, parameters["parent_id"]) if action_type == "ROLLBACK_DB_PROMOTION" else None
        if action_type == "PROMOTE_RESTORED_DB":
            if parameters["confirm_database"] != c["service_database"]: raise PromotionError("service_database_confirmation_mismatch")
            source = self._restore(c, parameters["source_record_id"])
            old_name, old_oid = c["service_database"], c["service_oid"]
            new_name, new_oid = c["staging_database"], c["staging_oid"]
            self._access(c, new_name)
        else:
            source = {"promotion_parent": parameters["parent_id"], "promotion_plan_digest": parent["plan_digest"]}
            old_name, old_oid = c["service_database"], parent["promoted_oid"]
            new_name, new_oid = parent["retained_database"], parent["retained_oid"]
        with self._connection(c) as conn:
            server = self._server(conn, c)
            old, new = self._db(conn, c, old_name, old_oid), self._db(conn, c, new_name, new_oid)
            if old["allow_connections"] is not True or (not parent and new["public_connect"] is not False) or (parent and new["allow_connections"] is not False):
                raise PromotionError("service_or_isolated_stage_connection_state_invalid")
            if not parent and new["allow_connections"] is not True:
                # Stage is only accessed by the verifier; PUBLIC CONNECT must be
                # revoked before the restore is eligible for promotion.
                raise PromotionError("staging_database_readonly_verification_unavailable")
            roles = self._roles(conn, c)
            sessions = self._sessions(conn, c, [old_oid, new_oid])
            if any(s["datid"] == new_oid for s in sessions): raise PromotionError("staging_or_retained_database_in_use")
            if self._one(conn, PREPARED, ([old_name, new_name],)).get("count") != 0:
                raise PromotionError("prepared_transactions_prevent_promotion")
            # No application role may connect to stage before the cutover.
            if not parent:
                for role in c["application_roles"]:
                    if self._one(conn, "/* leafy:promotion_connect */ SELECT has_database_privilege(%s,%s,'CONNECT') AS allowed", (role, new_oid)).get("allowed") is not False:
                        raise PromotionError("staging_database_not_connection_isolated")
        snapshot = {"server": server, "old": old, "new": new, "application_roles": roles, "source": source}
        plan = {"executor": self.name, "identity": identity, "target": identity["target"], "action_type": action_type,
                "parameters": dict(parameters), "operator_config": {"config_sha256": digest(c)}, "pre_snapshot": snapshot}
        return {identity["target"]: seal_plan(plan)}

    def validate_record(self, record):
        try:
            fresh = self.plan_record(record.identity, record.targets, record.action_type, record.action_parameters)
            if any(not valid_plan_digest(record.target_bindings[t]) or fresh[t] != record.target_bindings[t] for t in record.targets):
                return "database_promotion_state_changed_reapproval_required"
            return None
        except Exception:
            return "database_promotion_preflight_unavailable"

    def _fence_and_drain(self, record, c, conn, old, new):
        check_record(record, self.name)
        if self._server(conn, c) != record.target_bindings[record.identity["target"]]["pre_snapshot"]["server"]:
            raise PromotionError("promotion_server_changed")
        # Re-observe exact OIDs immediately before the committed connection fence.
        if self._db(conn, c, old["datname"], old["oid"]) != old or self._db(conn, c, new["datname"], new["oid"]) != new:
            raise PromotionError("promotion_database_changed_before_fence")
        self._sessions(conn, c, [old["oid"], new["oid"]])
        with conn.cursor() as cursor:
            cursor.execute("ALTER DATABASE " + quote(old["datname"]) + " ALLOW_CONNECTIONS false")
            cursor.execute("ALTER DATABASE " + quote(new["datname"]) + " ALLOW_CONNECTIONS false")
        check_record(record, self.name)
        conn.commit()  # New clients cannot reconnect after this durable fence.
        for _ in range(20):
            sessions = self._sessions(conn, c, [old["oid"], new["oid"]])
            if not sessions: break
            for s in sessions:
                check_record(record, self.name)
                # PID reuse and new protected role/session fail the exact predicate.
                row = self._one(conn, """/* leafy:promotion_terminate */ SELECT pg_terminate_backend(a.pid,1000) AS terminated
                  FROM pg_stat_activity a JOIN pg_roles r ON r.rolname=a.usename
                  WHERE a.pid=%s AND a.datid=%s AND a.usename=%s AND a.backend_start::text=%s
                  AND a.backend_type='client backend' AND NOT r.rolsuper""", (s["pid"], s["datid"], s["usename"], s["backend_start"]))
                if row.get("terminated") is not True: raise PromotionError("application_session_drain_unconfirmed")
            self.sleep(.05)
        else: raise PromotionError("database_session_drain_timeout")
        if self._one(conn, PREPARED, ([old["datname"], new["datname"]],)).get("count") != 0:
            raise PromotionError("prepared_transaction_appeared")

    def execute_record(self, record, target, approved_by=None):
        mutated, claimed = False, False
        journal = None
        with _LOCK:
            try:
                check_record(record, self.name)
                if target != record.identity["target"] or approved_by is not None and approved_by != record.approved_by:
                    raise PromotionError("promotion_approval_identity_mismatch")
                c = self._config(target); journal = ExecutionJournal(c["journal_path"])
                cached = journal.claim(record, target)
                if cached: return cached
                claimed = True
                why = self.validate_record(record)
                if why: raise PromotionError(why)
                plan = record.target_bindings[target]; before = plan["pre_snapshot"]
                old, new = before["old"], before["new"]
                retained = "leafy_retained_" + digest({"rid": record.remediation_id, "oid": old["oid"]})[:24]
                body = {"identity": record.identity, "plan_digest": plan["plan_digest"], "state": "EXECUTING",
                        "retained_database": retained, "retained_oid": old["oid"], "promoted_oid": new["oid"], "service_database": c["service_database"], "action_type": record.action_type, "config_sha256": digest(c)}
                with journal.connection() as db:
                    db.execute("CREATE TABLE IF NOT EXISTS database_promotions (rid TEXT PRIMARY KEY, body TEXT)")
                    db.execute("CREATE TABLE IF NOT EXISTS database_promotion_leases (target TEXT PRIMARY KEY, rid TEXT)")
                    db.execute("INSERT INTO database_promotion_leases VALUES (?,?)", (target, record.remediation_id))
                    db.execute("INSERT INTO database_promotions VALUES (?,?)", (record.remediation_id, json.dumps(body)))
                with self._connection(c) as conn:
                    collision = self._all(conn, "/* leafy:promotion_name_available */ SELECT oid FROM pg_database WHERE datname=%s", (retained,))
                    if collision: raise PromotionError("retained_database_name_already_exists")
                    check_record(record, self.name)
                    mutated = True  # Fence commit can succeed even if its reply is lost.
                    self._fence_and_drain(record, c, conn, old, new)
                    check_record(record, self.name)
                    if self._sessions(conn, c, [old["oid"], new["oid"]]): raise PromotionError("sessions_remain_before_rename")
                    with conn.cursor() as cursor:
                        cursor.execute("ALTER DATABASE " + quote(old["datname"]) + " RENAME TO " + quote(retained))
                        cursor.execute("ALTER DATABASE " + quote(new["datname"]) + " RENAME TO " + quote(c["service_database"]))
                        for role in c["application_roles"]:
                            cursor.execute("GRANT CONNECT ON DATABASE " + quote(c["service_database"]) + " TO " + quote(role))
                        cursor.execute("ALTER DATABASE " + quote(c["service_database"]) + " ALLOW_CONNECTIONS true")
                    # RENAME/ALLOW_CONNECTIONS use one transaction; SET TABLESPACE,
                    # CREATE DATABASE and DROP DATABASE are deliberately absent.
                    if self._db(conn, c, c["service_database"], new["oid"])["allow_connections"] is not True:
                        raise PromotionError("promotion_transaction_postcondition_failed")
                    if self._db(conn, c, retained, old["oid"])["allow_connections"] is not False:
                        raise PromotionError("retained_database_must_remain_fenced")
                    check_record(record, self.name)
                    conn.commit()
                with self._connection(c) as conn:
                    self._server(conn, c)
                    live = self._db(conn, c, c["service_database"], new["oid"])
                    kept = self._db(conn, c, retained, old["oid"])
                    if live["allow_connections"] is not True or kept["allow_connections"] is not False:
                        raise PromotionError("database_promotion_effect_unconfirmed")
                body["state"] = "SUCCESS"
                with journal.connection() as db:
                    db.execute("UPDATE database_promotions SET body=? WHERE rid=?", (json.dumps(body), record.remediation_id))
                result = succeeded(record.action_type, target, "database_name_cutover_verified_service_acceptance_pending",
                    after={"service_database": c["service_database"], "database_oid": new["oid"], "retained_database": retained,
                           "retained_oid": old["oid"], "application_service_recovery_verified": False})
            except Exception:
                result = (ExecutionResult(record.action_type, target, "UNKNOWN", detail="database_cutover_partial_or_unconfirmed_no_retry") if mutated
                          else blocked(record.action_type, target, "database_promotion_approval_or_preflight_rejected"))
            if not claimed: return result
            try:
                saved = journal.save(record, target, result)
                if result.ok or not mutated:
                    with journal.connection() as db:
                        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='database_promotion_leases'").fetchone():
                            db.execute("DELETE FROM database_promotion_leases WHERE target=? AND rid=?", (target, record.remediation_id))
                return saved
            except Exception: return ExecutionResult(record.action_type, target, "UNKNOWN", detail="database_promotion_journal_unavailable")
