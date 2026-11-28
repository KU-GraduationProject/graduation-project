"""Staged database cutover SQL with fake transactional PG; never a live DB."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

from executor.database_promotion import DatabasePromotionExecutor, PromotionError, validate_parameters
import store

IDENTITY = {"site": "fixture-site", "source": "fixture-pg", "service": "db", "runtime": "host", "target": "fixture-service-db"}


class FakeDatabase:
    def __init__(self):
        self.databases = {
            "leafy_service": {"oid": 101, "datname": "leafy_service", "owner": "promotion_operator", "allow_connections": True, "is_template": False, "public_connect": True, "app_connect": True},
            "restore_stage": {"oid": 202, "datname": "restore_stage", "owner": "promotion_operator", "allow_connections": True, "is_template": False, "public_connect": False, "app_connect": False}}
        self.sessions = [{"pid": 501, "datid": 101, "usename": "app_role", "backend_type": "client backend", "backend_start": "2026-11-28 00:00:00+00", "rolsuper": False}]
        self.statements, self.terminations, self.commits = [], [], 0
        self.prepared, self.access, self.superuser = 0, True, False
        self.fail_commit_number = None
        self.on_commit = None
        self.system = "123456789"
        self.operator_role = "promotion_operator"

    def connect(self, **kwargs):
        db, database = self, kwargs["dbname"]
        class Connection:
            pending = deepcopy(db.databases)
            def cursor(self):
                connection = self
                class Cursor:
                    row, rows = None, None
                    def __enter__(self): return self
                    def __exit__(self, *args): return False
                    def execute(self, sql, values=()):
                        db.statements.append((sql, values))
                        if "leafy:promotion_server" in sql:
                            self.row = {"database": database, "executor_role": db.operator_role, "server_addr": "127.0.0.1", "server_port": 55432,
                                "system_identifier": db.system, "in_recovery": False, "server_version": 170000,
                                "rolsuper": db.superuser, "rolcreatedb": True, "rolcreaterole": False, "rolreplication": False, "rolbypassrls": False}
                        elif "leafy:promotion_database" in sql:
                            row = deepcopy(connection.pending.get(values[0])); self.row = None if row is None else {k:v for k,v in row.items() if k != "app_connect"}
                        elif "leafy:promotion_app_role" in sql:
                            self.row = {"oid": 303, "rolname": values[0], "rolsuper": False, "rolcreatedb": False, "rolcreaterole": False, "rolreplication": False, "rolbypassrls": False, "privileged_membership": False}
                        elif "leafy:promotion_access" in sql: self.row = {"allowed": db.access}
                        elif "leafy:promotion_connect" in sql:
                            self.row = {"allowed": next(d["app_connect"] for d in connection.pending.values() if d["oid"] == values[1])}
                        elif "leafy:promotion_clear_stats" in sql: self.row = {}
                        elif "leafy:promotion_sessions" in sql:
                            self.rows = deepcopy([s for s in db.sessions if s["datid"] in values[0]])
                        elif "leafy:promotion_prepared" in sql: self.row = {"count": db.prepared}
                        elif "leafy:promotion_name_available" in sql:
                            self.rows = [{"oid": connection.pending[values[0]]["oid"]}] if values[0] in connection.pending else []
                        elif "leafy:promotion_terminate" in sql:
                            matching = [s for s in db.sessions if (s["pid"],s["datid"],s["usename"],s["backend_start"]) == tuple(values) and not s["rolsuper"]]
                            self.row = {"terminated": bool(matching)}
                            for s in matching: db.sessions.remove(s); db.terminations.append(s["pid"])
                        elif sql.startswith("ALTER DATABASE"):
                            names = re.findall(r'"([^"]+)"', sql)
                            if "ALLOW_CONNECTIONS" in sql: connection.pending[names[0]]["allow_connections"] = sql.endswith(" true")
                            elif "RENAME TO" in sql:
                                row = connection.pending.pop(names[0]); row["datname"] = names[1]; connection.pending[names[1]] = row
                            else: raise AssertionError("unsupported fake ALTER")
                        elif sql.startswith("GRANT CONNECT ON DATABASE"):
                            name = re.findall(r'"([^"]+)"', sql)[0]; connection.pending[name]["app_connect"] = True
                        else: raise AssertionError("unplanned SQL: " + sql)
                    def fetchone(self): return deepcopy(self.row)
                    def fetchall(self): return deepcopy(self.rows)
                return Cursor()
            def commit(self):
                db.commits += 1; db.databases = deepcopy(self.pending)
                if db.on_commit: db.on_commit(db.commits)
                if db.fail_commit_number == db.commits: raise TimeoutError("synthetic lost commit reply")
                self.pending = deepcopy(db.databases)
            def close(self): pass
        return Connection()


class PromotionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir="/private/tmp" if Path("/private/tmp").is_dir() else None)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.passfile = self.root / "pgpass"; self.passfile.write_text("synthetic-private-passfile"); self.passfile.chmod(0o600)
        self.ledger = self.root / "restore.sqlite3"
        self.backup_hash, self.plan_hash = "b"*64, "c"*64
        restored = {"action": "RESTORE_DB", "target": "fixture-stage", "status": "SUCCESS", "verified": True,
                    "after": {"database_oid": 202, "backup_sha256": self.backup_hash, "relations": 1,
                              "restore_system_identifier": "123456789", "restored_database": "restore_stage", "restore_server_addr": "127.0.0.1",
                              "restore_server_port": 55432, "restore_owner": "promotion_operator", "restore_plan_digest": self.plan_hash,
                              "source_database_id": "123456789:leafy_service"}}
        with sqlite3.connect(self.ledger) as sql:
            sql.execute("CREATE TABLE executions(rid TEXT PRIMARY KEY,target TEXT,digest TEXT,result TEXT)")
            sql.execute("INSERT INTO executions VALUES (?,?,?,?)", ("fixture-restore", "fixture-stage", self.plan_hash, json.dumps(restored)))
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text(json.dumps({"format": "postgres-custom", "verified": True, "restore_list_verified": True,
            "database_id": "123456789:leafy_service", "sha256": self.backup_hash}))
        import hashlib
        restored["after"]["manifest_sha256"] = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        with sqlite3.connect(self.ledger) as sql:
            sql.execute("UPDATE executions SET result=?", (json.dumps(restored),))
        self.config = {"version": 1, "enabled": True, "journal_path": str(self.root / "promotion.sqlite3"), "targets": {IDENTITY["target"]: {
            "identity": IDENTITY, "service_database": "leafy_service", "staging_database": "restore_stage", "service_oid": 101, "staging_oid": 202,
            "executor_role": "promotion_operator", "system_identifier": "123456789", "server_addr": "127.0.0.1", "server_port": 55432,
            "connection": {"host_env": "FIXTURE_PGHOST", "port_env": "FIXTURE_PGPORT", "user_env": "FIXTURE_PGUSER", "pgpassfile_env": "FIXTURE_PASSFILE", "sslmode": "require"},
            "restore_ledger_path": str(self.ledger), "restore_target": "fixture-stage", "restore_plan_digest": self.plan_hash,
            "backup_manifest_file": str(self.manifest), "application_roles": ["app_role"], "maintenance_confirmed": True, "timeout_seconds": 30,
            "application_access": [{"role": "app_role", "kind": "table", "schema": "public", "name": "fixture_table", "privilege": "SELECT"}]}}}
        self.path = self.root / "promotion.yml"; self.write_config()
        self.db = FakeDatabase()
        self.executor = DatabasePromotionExecutor(self.path, self.db.connect, sleep=lambda _:None)
        self.env = patch.dict(os.environ, {"FIXTURE_PGHOST":"127.0.0.1", "FIXTURE_PGPORT":"55432", "FIXTURE_PGUSER":"promotion_operator", "FIXTURE_PASSFILE":str(self.passfile)})
        self.env.start(); self.addCleanup(self.env.stop)

    def write_config(self): self.path.write_text(yaml.safe_dump(self.config))
    def record(self, action="PROMOTE_RESTORED_DB", params=None, rid="fixture-promotion"):
        params = params or {"source_record_id":"fixture-restore", "confirm_database":"leafy_service", "allow_data_loss":True}
        plans = self.executor.plan_record(IDENTITY, [IDENTITY["target"]], action, params)
        now = datetime.now(timezone.utc)
        return SimpleNamespace(remediation_id=rid, action_type=action, identity=IDENTITY, targets=[IDENTITY["target"]], action_parameters=params,
            target_bindings=plans, evidence={"targets":deepcopy(plans)}, executor_name="database_promotion", state="EXECUTING", requires_approval=True,
            approved_by="fixture-operator", incident_key="a"*64, ttl_seconds=None, recovery_mode="none",
            approval_requested_at=(now-timedelta(seconds=1)).isoformat(), approved_at=(now-timedelta(milliseconds=800)).isoformat(),
            action_started_at=(now-timedelta(milliseconds=500)).isoformat(), approval_expires_at=(now+timedelta(minutes=5)).isoformat(),
            action_hash=store.action_hash(action,[IDENTITY["target"]],None,"none",params))
    def execute(self,r): return self.executor.execute_record(r,IDENTITY["target"],r.approved_by)

    def test_cutover_retains_old_db_and_separate_rollback_restores_its_oid(self):
        r=self.record(); result=self.execute(r)
        self.assertTrue(result.ok,result)
        self.assertEqual(self.db.databases["leafy_service"]["oid"],202)
        retained=result.after["retained_database"]
        self.assertEqual(self.db.databases[retained]["oid"],101)
        self.assertFalse(self.db.databases[retained]["allow_connections"])
        self.assertTrue(self.db.databases["leafy_service"]["app_connect"])
        self.assertEqual(self.db.terminations,[501])
        self.assertFalse(any("DROP DATABASE" in s for s,_ in self.db.statements))
        prior=len(self.db.statements); self.assertTrue(self.execute(r).ok); self.assertEqual(len(self.db.statements),prior)
        undo=self.record("ROLLBACK_DB_PROMOTION",{"parent_id":r.remediation_id},"fixture-rollback")
        rolled=self.execute(undo); self.assertTrue(rolled.ok,rolled)
        self.assertEqual(self.db.databases["leafy_service"]["oid"],101)
        self.assertEqual(self.db.databases[rolled.after["retained_database"]]["oid"],202)

    def test_protected_sessions_prepared_transactions_and_missing_access_refused(self):
        self.db.sessions[0]["rolsuper"]=True
        with self.assertRaises(PromotionError): self.record()
        self.db.sessions[0]["rolsuper"]=False; self.db.prepared=1
        with self.assertRaises(PromotionError): self.record()
        self.db.prepared=0; self.db.access=False
        with self.assertRaises(PromotionError): self.record()
        self.assertEqual(self.db.commits,0)

    def test_public_or_app_connect_on_stage_is_not_an_isolated_restore(self):
        self.db.databases["restore_stage"]["public_connect"]=True
        with self.assertRaises(PromotionError): self.record()
        self.db.databases["restore_stage"]["public_connect"]=False
        self.db.databases["restore_stage"]["app_connect"]=True
        with self.assertRaises(PromotionError): self.record()

    def test_unverified_wrong_service_backup_or_stage_oid_rejected(self):
        old=json.loads(self.manifest.read_text()); old["database_id"]="123456789:another_service"
        self.manifest.write_text(json.dumps(old))
        with self.assertRaises(PromotionError): self.record()
        old["database_id"]="123456789:leafy_service"; self.manifest.write_text(json.dumps(old))
        self.db.databases["restore_stage"]["oid"]=999
        with self.assertRaises(PromotionError): self.record()
        self.assertEqual(self.db.commits,0)

    def test_expired_approval_or_new_unexpected_session_never_fences(self):
        r=self.record(); r.approval_expires_at=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
        self.assertEqual(self.execute(r).status,"BLOCKED")
        r=self.record(rid="fixture-new-session")
        self.db.sessions.append({**self.db.sessions[0],"pid":502,"usename":"unlisted_admin"})
        self.assertEqual(self.execute(r).status,"BLOCKED")
        self.assertEqual(self.db.commits,0)
        self.assertFalse(any(s.startswith("ALTER DATABASE") for s,_ in self.db.statements))

    def test_lost_fence_commit_is_unknown_and_never_retried(self):
        r=self.record(); self.db.fail_commit_number=1
        self.assertEqual(self.execute(r).status,"UNKNOWN")
        self.assertFalse(self.db.databases["leafy_service"]["allow_connections"])
        self.assertEqual(self.db.databases["leafy_service"]["oid"],101)
        count=len(self.db.statements)
        self.assertEqual(self.execute(r).status,"UNKNOWN")
        self.assertEqual(len(self.db.statements),count)
        with self.assertRaises(PromotionError): self.record("ROLLBACK_DB_PROMOTION",{"parent_id":r.remediation_id},"fixture-bad-rollback")

    def test_expiry_after_fence_preserves_both_db_names_without_rename(self):
        r=self.record()
        def expire(n): r.approval_expires_at=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
        self.db.on_commit=expire
        self.assertEqual(self.execute(r).status,"UNKNOWN")
        self.assertEqual(set(self.db.databases),{"leafy_service","restore_stage"})
        self.assertFalse(self.db.databases["leafy_service"]["allow_connections"])

    def test_disable_superuser_and_unconfirmed_maintenance_fail_closed(self):
        self.config["enabled"]=False; self.write_config()
        with self.assertRaises(PromotionError): self.record()
        self.config["enabled"]=True; self.write_config(); self.db.superuser=True
        with self.assertRaises(PromotionError): self.record()
        self.db.superuser=False; self.config["targets"][IDENTITY["target"]]["maintenance_confirmed"]=False; self.write_config()
        with self.assertRaises(PromotionError): self.record()

    def test_restore_journal_must_attest_same_cluster_not_only_matching_oid(self):
        with sqlite3.connect(self.ledger) as sql:
            result=json.loads(sql.execute("SELECT result FROM executions").fetchone()[0])
            result["after"]["restore_system_identifier"]="987654321"
            sql.execute("UPDATE executions SET result=?",(json.dumps(result),))
        with self.assertRaises(PromotionError): self.record()
        self.assertEqual(self.db.commits,0)

    def test_new_privileged_session_after_fence_is_not_killed_or_renamed(self):
        r=self.record()
        def protected(n):
            if n==1: self.db.sessions.append({"pid":502,"datid":101,"usename":"admin","backend_type":"client backend","backend_start":"2026-11-28 01:00:00+00","rolsuper":True})
        self.db.on_commit=protected
        self.assertEqual(self.execute(r).status,"UNKNOWN")
        self.assertNotIn(502,self.db.terminations)
        self.assertEqual(self.db.databases["leafy_service"]["oid"],101)

    def test_real_restore_executor_result_is_accepted_after_same_role_privilege_transition(self):
        # Use DatabaseAdminExecutor's actual output/SQLite schema, not a manually
        # fabricated success payload, while both database transports remain fake.
        from tests.test_database_admin import DatabaseAdminTests, IDENTITY as STAGE_IDENTITY
        source=DatabaseAdminTests(); source.setUp(); self.addCleanup(source.doCleanups)
        manifest=json.loads(source.manifest.read_text())
        manifest["database_id"]="123456789:leafy_service"
        source.manifest.write_text(json.dumps(manifest))
        source.cfg["targets"][STAGE_IDENTITY["target"]]["backups"]["backup_a"]["database_id"]=manifest["database_id"]
        source.write_config()
        restored=source.record(rid="fixture-restore")
        result=source.executor.execute_record(restored,STAGE_IDENTITY["target"])
        self.assertTrue(result.ok,result)
        c=self.config["targets"][IDENTITY["target"]]
        c.update(staging_database="restore_fixture",staging_oid=source.db.oid,executor_role="restore_operator",
                 restore_target=STAGE_IDENTITY["target"],restore_ledger_path=str(Path(source.executor.ledger_path).resolve()),
                 restore_plan_digest=result.after["restore_plan_digest"],backup_manifest_file=str(source.manifest.resolve()))
        stage=self.db.databases.pop("restore_stage")
        stage.update(oid=source.db.oid,datname="restore_fixture",owner="restore_operator")
        self.db.databases["restore_fixture"]=stage
        self.db.databases["leafy_service"]["owner"]="restore_operator"
        self.db.operator_role="restore_operator"  # Same owner; reviewed CREATEDB now true in promotion phase.
        self.write_config()
        with patch.dict(os.environ,{"FIXTURE_PGUSER":"restore_operator"}):
            promoted=self.execute(self.record())
        self.assertTrue(promoted.ok,promoted)
        self.assertEqual(self.db.databases["leafy_service"]["oid"],source.db.oid)

    def test_parameters_require_positive_data_loss_consent_and_exact_names(self):
        p={"source_record_id":"fixture-restore", "confirm_database":"leafy_service", "allow_data_loss":True}
        validate_parameters("PROMOTE_RESTORED_DB",p)
        for bad in ({**p,"allow_data_loss":False},{**p,"confirm_database":"postgres;DROP"},{**p,"source_record_id":None}):
            with self.assertRaises(PromotionError): validate_parameters("PROMOTE_RESTORED_DB",bad)


if __name__=="__main__": unittest.main()
