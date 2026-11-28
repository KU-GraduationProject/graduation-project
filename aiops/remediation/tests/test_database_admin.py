"""Private fixtures only: exact-cluster restore and role administration safety."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

from executor.database_admin import DatabaseAdminExecutor, validate_parameters
import store

IDENTITY = {"site": "fixture-site", "source": "fixture-pg", "service": "db", "runtime": "host", "target": "fixture-db"}


class FakeDatabase:
    def __init__(self):
        self.relations, self.other_sessions, self.role_login = 0, 0, True
        self.oid, self.role_oid, self.protected, self.system = 42, 55, False, "123456789"
        self.alters, self.commits, self.closed = [], 0, 0
        self.fail_commit = False
        self.on_query = None

    def connect(self, **kwargs):
        db = self
        class Connection:
            pending = None
            def cursor(self):
                connection = self
                class Cursor:
                    row = None
                    def __enter__(self): return self
                    def __exit__(self, *args): return False
                    def execute(self, sql, values=()):
                        if db.on_query: db.on_query(sql)
                        if "leafy:admin_server" in sql:
                            self.row = {"database": "restore_fixture", "executor_role": "restore_operator",
                                        "server_addr": "127.0.0.1", "server_port": 55432, "system_identifier": db.system,
                                        "in_recovery": False, "rolsuper": False, "rolreplication": False,
                                        "rolbypassrls": False, "rolcreaterole": False, "rolcreatedb": False}
                        elif "leafy:restore_destination" in sql:
                            self.row = {"oid": db.oid, "datname": "restore_fixture", "owner": "restore_operator",
                                        "relations": db.relations, "other_sessions": db.other_sessions}
                        elif "leafy:admin_role" in sql:
                            self.row = {"oid": db.role_oid, "rolname": values[0],
                                        "rolcanlogin": db.role_login if connection.pending is None else connection.pending,
                                        "rolsuper": db.protected, "rolreplication": False, "rolcreaterole": False,
                                        "rolcreatedb": False, "rolbypassrls": False, "database_owner": False,
                                        "relation_owner": False, "privileged_membership": False}
                        elif sql.startswith('ALTER ROLE "app_role" '):
                            db.alters.append(sql); connection.pending = sql.endswith(" LOGIN")
                        else: raise AssertionError("unplanned SQL")
                    def fetchone(self): return deepcopy(self.row)
                return Cursor()
            def commit(self):
                db.commits += 1
                if self.pending is not None: db.role_login = self.pending
                if db.fail_commit: raise TimeoutError()
            def close(self): db.closed += 1
        return Connection()


class DatabaseAdminTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.passfile = self.root / "pgpass"; self.passfile.write_text("fixture"); self.passfile.chmod(0o600)
        self.archive = self.root / "fixture.dump"; self.archive.write_bytes(b"PGDMPfixture-custom-archive")
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text(json.dumps({"artifact_path": str(self.archive), "format": "postgres-custom",
            "verified": True, "restore_list_verified": True, "database_id": "fixture-original",
            "bytes": self.archive.stat().st_size, "sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest()}))
        self.cfg = {"version": 1, "enabled": True, "targets": {IDENTITY["target"]: {
            "identity": IDENTITY, "database": "restore_fixture", "system_identifier": "123456789",
            "server_addr": "127.0.0.1", "server_port": 55432, "executor_role": "restore_operator",
            "connection": {"host_env": "FIXTURE_PGHOST", "port_env": "FIXTURE_PGPORT", "user_env": "FIXTURE_PGUSER",
                           "pgpassfile_env": "FIXTURE_PGPASSFILE", "sslmode": "require"},
            "actions": ["RESTORE_DB", "DISABLE_DB_ROLE", "ENABLE_DB_ROLE"], "roles": ["app_role"],
            "backups": {"backup_a": {"manifest_file": str(self.manifest), "database_id": "fixture-original"}},
            "isolated_restore": True, "timeout_seconds": 30}}}
        self.path = self.root / "config.yml"; self.write_config()
        self.db = FakeDatabase(); self.calls = []; self.fail_restore = False
        def runner(argv, **kwargs):
            self.calls.append((list(argv), kwargs))
            if "--list" in argv:
                return SimpleNamespace(returncode=0, stdout=b"1; 1259 111 TABLE public fixture fixture_owner\n")
            self.assertTrue(kwargs["stdin"].read().startswith(b"PGDMP"))
            self.db.relations = 1
            if self.fail_restore: raise TimeoutError()
            return SimpleNamespace(returncode=0)
        self.executor = DatabaseAdminExecutor(str(self.path), self.db.connect, runner,
                                               ledger_path=str(self.root / "ledger.sqlite3"))
        patcher = patch.dict(os.environ, {"FIXTURE_PGHOST": "127.0.0.1", "FIXTURE_PGPORT": "55432",
                                          "FIXTURE_PGUSER": "restore_operator", "FIXTURE_PGPASSFILE": str(self.passfile)})
        patcher.start(); self.addCleanup(patcher.stop)

    def write_config(self): self.path.write_text(yaml.safe_dump(self.cfg))
    def restore_params(self): return {"backup_id": "backup_a", "confirm_database": "restore_fixture", "allow_data_loss": True}
    def record(self, action="RESTORE_DB", parameters=None, rid="fixture-database", **changes):
        p = parameters if parameters is not None else self.restore_params()
        plan = self.executor.plan_record(IDENTITY, [IDENTITY["target"]], action, p)
        now = time.time()
        data = dict(remediation_id=rid, state="EXECUTING", executor_name="database_admin", action_type=action,
            action_parameters=p, identity=IDENTITY, targets=[IDENTITY["target"]], requires_approval=True,
            approved_by="fixture-admin", ttl_seconds=None, recovery_mode="none", incident_key="d" * 64,
            approval_requested_at=datetime.fromtimestamp(now - 1, timezone.utc).isoformat(),
            approved_at=datetime.fromtimestamp(now - .5, timezone.utc).isoformat(),
            action_started_at=datetime.fromtimestamp(now - .1, timezone.utc).isoformat(),
            approval_expires_at=datetime.fromtimestamp(now + 300, timezone.utc).isoformat(),
            target_bindings=plan, evidence={"targets": plan}, action_hash=store.action_hash(action, [IDENTITY["target"]], None, "none", p))
        return SimpleNamespace(**{**data, **changes})

    def test_restore_verified_empty_isolated_database_once(self):
        rec = self.record()
        result = self.executor.execute_record(rec, IDENTITY["target"])
        self.assertTrue(result.ok, result)
        self.assertEqual(result.after["restore_system_identifier"], self.db.system)
        self.assertEqual(result.after["restored_database"], rec.target_bindings[IDENTITY["target"]]["pre_snapshot"]["server"]["database"])
        self.assertEqual(result.after["restore_plan_digest"], rec.target_bindings[IDENTITY["target"]]["plan_digest"])
        self.assertEqual(result.after["source_database_id"], rec.target_bindings[IDENTITY["target"]]["pre_snapshot"]["backup"]["database_id"])
        dispatched = [call for call in self.calls if "--list" not in call[0]]
        self.assertEqual(len(dispatched), 1)
        argv, options = dispatched[0]
        self.assertIn("--single-transaction", argv)
        self.assertIn("--no-owner", argv)
        self.assertNotIn("--clean", argv); self.assertNotIn("--create", argv)
        self.assertNotIn(str(self.archive), argv)  # anonymous verified copy supplied through stdin
        self.assertFalse(any(arg.startswith("password=") for arg in argv))
        self.assertEqual(options["env"]["PGPASSFILE"], str(self.passfile))
        self.assertTrue(self.executor.execute_record(rec, IDENTITY["target"]).ok)
        self.assertEqual(len([c for c in self.calls if "--list" not in c[0]]), 1)

    def test_production_or_nonexclusive_or_nonempty_database_is_rejected(self):
        for changes in ({"isolated_restore": False}, {"database": "production"}):
            old = deepcopy(self.cfg)
            self.cfg["targets"][IDENTITY["target"]].update(changes); self.write_config()
            with self.subTest(changes=changes), self.assertRaises(ValueError): self.record()
            self.cfg = old; self.write_config()
        for attribute in ("relations", "other_sessions"):
            setattr(self.db, attribute, 1)
            with self.subTest(attribute=attribute), self.assertRaises(ValueError): self.record()
            setattr(self.db, attribute, 0)

    def test_backup_hash_changed_or_consent_missing_blocks(self):
        p = self.restore_params(); p["allow_data_loss"] = False
        with self.assertRaises(ValueError): self.record(parameters=p)
        self.archive.write_bytes(b"PGDMPtampered")
        with self.assertRaises(ValueError): self.record()

    def test_cluster_or_approval_or_state_change_prevents_restore(self):
        rec = self.record(); self.db.system = "different"
        self.assertEqual(self.executor.execute_record(rec, IDENTITY["target"]).status, "BLOCKED")
        self.assertEqual(len([c for c in self.calls if "--list" not in c[0]]), 0)
        self.db.system = "123456789"
        rec = self.record(rid="expired")
        rec.approval_expires_at = "2020-01-01T00:00:00Z"
        self.assertEqual(self.executor.execute_record(rec, IDENTITY["target"]).status, "BLOCKED")

    def test_restore_response_loss_is_unknown_and_not_reexecuted(self):
        rec = self.record(); self.fail_restore = True
        self.assertEqual(self.executor.execute_record(rec, IDENTITY["target"]).status, "UNKNOWN")
        self.assertEqual(self.executor.execute_record(rec, IDENTITY["target"]).status, "UNKNOWN")
        self.assertEqual(len([c for c in self.calls if "--list" not in c[0]]), 1)

    def test_role_disable_then_separately_approved_enable(self):
        rec = self.record("DISABLE_DB_ROLE", {"role_id": "app_role"})
        self.assertTrue(self.executor.execute_record(rec, IDENTITY["target"]).ok)
        self.assertFalse(self.db.role_login)
        restore = self.record("ENABLE_DB_ROLE", {"role_id": "app_role"}, rid="fixture-enable")
        self.assertTrue(self.executor.execute_record(restore, IDENTITY["target"]).ok)
        self.assertTrue(self.db.role_login)
        self.assertEqual(self.db.alters, ['ALTER ROLE "app_role" NOLOGIN', 'ALTER ROLE "app_role" LOGIN'])

    def test_protected_role_and_unknown_identifier_are_refused(self):
        self.db.protected = True
        with self.assertRaises(ValueError): self.record("DISABLE_DB_ROLE", {"role_id": "app_role"})
        with self.assertRaises(ValueError): validate_parameters("DISABLE_DB_ROLE", {"role_id": 'app_role";DROP'})
        self.assertEqual(self.db.alters, [])

    def test_conflicting_rid_does_not_overwrite_verified_execution(self):
        rec = self.record("DISABLE_DB_ROLE", {"role_id": "app_role"})
        self.assertTrue(self.executor.execute_record(rec, IDENTITY["target"]).ok)
        conflict = self.record("ENABLE_DB_ROLE", {"role_id": "app_role"})
        self.assertEqual(self.executor.execute_record(conflict, IDENTITY["target"]).status, "BLOCKED")
        self.assertTrue(self.executor.execute_record(rec, IDENTITY["target"]).ok)
        self.assertFalse(self.db.role_login)
        self.assertEqual(len(self.db.alters), 1)

    def test_approval_expiry_during_preflight_is_rechecked_before_sql(self):
        rec = self.record("DISABLE_DB_ROLE", {"role_id": "app_role"})
        def expire(sql): rec.approval_expires_at = "2020-01-01T00:00:00Z"
        self.db.on_query = expire
        self.assertEqual(self.executor.execute_record(rec, IDENTITY["target"]).status, "BLOCKED")
        self.assertEqual(self.db.alters, [])

    def test_commit_response_loss_is_unknown_and_does_not_retry_role_change(self):
        rec = self.record("DISABLE_DB_ROLE", {"role_id": "app_role"}); self.db.fail_commit = True
        self.assertEqual(self.executor.execute_record(rec, IDENTITY["target"]).status, "UNKNOWN")
        self.assertEqual(self.executor.execute_record(rec, IDENTITY["target"]).status, "UNKNOWN")
        self.assertEqual(len(self.db.alters), 1)

    def test_disabled_config_and_invalid_approval_do_not_create_ledger(self):
        rec = self.record(); rec.approved_by = None
        self.assertEqual(self.executor.execute_record(rec, IDENTITY["target"]).status, "BLOCKED")
        self.assertFalse((self.root / "ledger.sqlite3").exists())
        self.cfg["enabled"] = False; self.write_config()
        with self.assertRaises(ValueError): self.record()


if __name__ == "__main__": unittest.main()
