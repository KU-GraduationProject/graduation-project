"""Fixed SQL adapter tests with an injected DB; no PostgreSQL/network/subprocess."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import store
from executor.postgres import (PostgresExecutor, PostgresError, SERVER_SQL,
    SELECT_SQL, MUTATE_SQL, VERIFY_SQL)

IDENTITY = {"site": "gc", "service": "db", "source": "gc-windows", "runtime": "host", "target": "gc-postgres"}
TARGET = IDENTITY["target"]
PASSWORD = "fixture-password-must-never-appear"


def stamp(seconds_ago):
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()


def session(pid=101, **changes):
    row = {"pid": pid, "backend_start": stamp(500), "query_start": stamp(300), "state_change": stamp(300),
           "state": "idle", "xact_start": None, "usename": "leafy_app", "application_name": "leafy-backend",
           "client_addr": "127.0.0.1", "backend_type": "client backend", "rolsuper": False,
           "rolreplication": False, "rolcreaterole": False, "rolcreatedb": False, "rolbypassrls": False, "admin_member": False,
           "database": "leafy"}
    row.update(changes)
    return row


class FakeDB:
    def __init__(self):
        self.sessions = {101: session()}
        self.calls = []
        self.signals = []
        self.connections = []
        self.before_mutation = None
        self.on_identity = None
        self.lose_reply = False
        self.apply_signal = True
        self.signal_return = True
        self.info = {"database": "leafy", "server_addr": "127.0.0.1", "server_port": 5432,
            "system_identifier": "1234567890123456789", "server_version": 170005, "in_recovery": False,
            "observer_pid": 999, "executor_role": "leafy_remediator", "rolsuper": False,
            "rolreplication": False, "rolcreaterole": False, "rolcreatedb": False, "rolbypassrls": False,
            "can_signal": True, "can_read_stats": True}

    def connect(self, **kwargs):
        conn = FakeConnection(self, kwargs)
        self.connections.append(conn)
        return conn

    def eligible(self, row, operation, params):
        database, roles, apps, addrs, age = params[:5]
        if (row["database"] != database or row["pid"] == self.info["observer_pid"]
                or row["backend_type"] != "client backend" or row["usename"] not in roles
                or row["application_name"] not in apps or row["client_addr"] not in addrs
                or row["usename"] == self.info["executor_role"] or row["admin_member"]
                or any(row[k] for k in ("rolsuper", "rolreplication", "rolcreaterole", "rolcreatedb", "rolbypassrls"))):
            return False
        if operation == "terminate_idle_sessions":
            state_ok = row["state"] == "idle" and row["xact_start"] is None
            started = row["state_change"]
        else:
            state_ok = row["state"] == "active" and row["xact_start"] == row["query_start"]
            started = row["query_start"]
        return state_ok and store._parse_ts(started) <= time.time() - age

    def query(self, sql, params):
        self.calls.append((sql, deepcopy(params)))
        if sql == SERVER_SQL:
            if self.on_identity:
                self.on_identity()
            return [deepcopy(self.info)]
        if sql in SELECT_SQL.values():
            operation = next(k for k, value in SELECT_SQL.items() if value == sql)
            return [deepcopy(r) for r in sorted(self.sessions.values(), key=lambda r:r["pid"])
                    if self.eligible(r, operation, params)][:params[-1]]
        if sql in MUTATE_SQL.values():
            operation = next(k for k, value in MUTATE_SQL.items() if value == sql)
            if self.before_mutation:
                self.before_mutation()
            pid, backend_start, query_start, state, state_change, expires = params[5:]
            row = self.sessions.get(pid)
            if (not row or not self.eligible(row, operation, params) or row["backend_start"] != backend_start
                    or row["query_start"] != query_start or row["state"] != state or row["state_change"] != state_change
                    or store._parse_ts(expires) <= time.time()):
                return []
            self.signals.append((operation, pid))
            if self.apply_signal:
                if operation == "terminate_idle_sessions":
                    del self.sessions[pid]
                else:
                    self.sessions[pid]["state"] = "idle"
            if self.lose_reply:
                raise ConnectionError(PASSWORD + " SELECT private_customer_data")
            return [{"signaled": self.signal_return}]
        if sql == VERIFY_SQL:
            row = self.sessions.get(params[0])
            return [deepcopy(row)] if row and row["backend_start"] == params[1] else []
        raise AssertionError("Unexpected SQL; arbitrary statements forbidden")


class FakeConnection:
    def __init__(self, db, kwargs):
        self.db, self.kwargs = db, kwargs
        self.closed = False
        self.cursors = []

    def cursor(self):
        result = FakeCursor(self)
        self.cursors.append(result)
        return result

    def close(self):
        self.closed = True


class FakeCursor:
    def __init__(self, connection):
        self.connection = connection
        self.closed = False
        self.rows = []

    def execute(self, sql, params):
        self.rows = self.connection.db.query(sql, params)

    def fetchall(self):
        return self.rows

    def close(self):
        self.closed = True


class PostgresExecutorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "pg.json"
        self.config = {"version": 1, "targets": {TARGET: {
            "identity": dict(IDENTITY), "database": "leafy", "executor_role": "leafy_remediator", "server_addr": "127.0.0.1", "server_port": 5432,
            "system_identifier": "1234567890123456789",
            "connection": {"host_env": "TEST_PGHOST", "port_env": "TEST_PGPORT", "dbname_env": "TEST_PGDATABASE",
                "user_env": "TEST_PGUSER", "password_env": "TEST_PGPASSWORD", "sslmode": "require"},
            "allowed_roles": ["leafy_app"], "allowed_applications": ["leafy-backend"],
            "allowed_client_addrs": ["127.0.0.1"], "min_idle_seconds": 60, "min_query_seconds": 60, "max_sessions": 2}}}
        self.write_config()
        env = patch.dict(os.environ, {"TEST_PGHOST": "127.0.0.1", "TEST_PGPORT": "5432", "TEST_PGDATABASE": "leafy",
            "TEST_PGUSER": "leafy_remediator", "TEST_PGPASSWORD": PASSWORD})
        env.start()
        self.addCleanup(env.stop)
        self.db = FakeDB()
        self.executor = PostgresExecutor(str(self.path), self.db.connect, str(Path(self.tmp.name) / "ledger.sqlite"))

    def write_config(self):
        self.path.write_text(json.dumps(self.config), encoding="utf-8")

    def record(self, operation="terminate_idle_sessions", **parameters):
        params = {"operation": operation, **parameters}
        if operation == "cancel_long_queries":
            start = stamp(300)
            self.db.sessions[101].update(state="active", query_start=start, xact_start=start)
        bindings = self.executor.plan_record(dict(IDENTITY), [TARGET], "KILL_SESSIONS", params)
        return store.RemediationRecord("pg-test-1", "PostgresConnectionExhaustion", "KILL_SESSIONS", targets=[TARGET],
            identity=dict(IDENTITY), target_bindings=bindings, evidence={"targets": deepcopy(bindings)}, executor_name="postgres", requires_approval=True,
            action_parameters=params, incident_key="trusted-incident", action_hash=store.action_hash("KILL_SESSIONS", [TARGET], None, "none", params),
            recovery_mode="none", approval_requested_at=stamp(5), approved_by="UTEAM", approved_at=stamp(3),
            action_started_at=stamp(1), approval_expires_at=stamp(-300), state=store.EXECUTING)

    def test_real_adapter_uses_explicit_tcp_and_closes_connections_and_cursors(self):
        record = self.record()
        self.assertNotIn(PASSWORD, json.dumps(record.as_dict()))
        kwargs = self.db.connections[0].kwargs
        self.assertEqual((kwargs["host"], kwargs["hostaddr"], kwargs["port"], kwargs["dbname"]),
                         ("127.0.0.1", "127.0.0.1", 5432, "leafy"))
        self.assertTrue(kwargs["autocommit"])
        result = self.executor.execute_record(record, TARGET, "UTEAM")
        self.assertTrue(result.ok, result.detail)
        self.assertEqual(self.db.signals, [("terminate_idle_sessions", 101)])
        self.assertFalse(result.after["service_recovery_verified"])
        self.assertTrue(all(c.closed and all(cur.closed for cur in c.cursors) for c in self.db.connections))

    def test_cancel_query_is_a_distinct_signal_and_requires_effect_verification(self):
        result = self.executor.execute_record(self.record("cancel_long_queries"), TARGET, "UTEAM")
        self.assertTrue(result.ok, result.detail)
        self.assertEqual(self.db.signals, [("cancel_long_queries", 101)])
        self.assertIn(101, self.db.sessions)
        self.assertEqual(self.db.sessions[101]["state"], "idle")

    def test_mutation_sql_has_same_statement_full_incarnation_and_scope_predicates(self):
        record = self.record()
        self.executor.execute_record(record, TARGET, "UTEAM")
        sql, params = next((s,p) for s,p in self.db.calls if s in MUTATE_SQL.values())
        for predicate in ("a.pid = %s", "a.backend_start = %s", "a.query_start IS NOT DISTINCT FROM %s", "a.state = %s",
                          "a.state_change = %s", "a.pid <> pg_backend_pid()", "NOT r.rolsuper", "NOT r.rolreplication",
                          "a.usename = ANY(%s", "a.application_name = ANY(%s", "a.client_addr = ANY(%s",
                          "clock_timestamp() < %s", "a.xact_start IS NULL"):
            self.assertIn(predicate, sql)
        self.assertIn("pg_terminate_backend(pid, 1000)", sql)
        self.assertNotIn(PASSWORD, sql)
        self.assertEqual(params[5], 101)
        self.assertEqual(params[6], record.target_bindings[TARGET]["sessions"][0]["backend_start"])
        self.assertTrue(all("SELECT private" not in s for s,_ in self.db.calls))

    def test_idle_selection_excludes_other_apps_roles_clients_transactions_admin_and_system(self):
        cases = [dict(usename="administrator"), dict(application_name="pgAdmin"), dict(client_addr="10.0.0.2"),
                 dict(state="idle in transaction", xact_start=stamp(500)), dict(rolsuper=True),
                 dict(rolreplication=True), dict(rolcreaterole=True), dict(rolbypassrls=True), dict(admin_member=True),
                 dict(backend_type="autovacuum worker"), dict(pid=999), dict(state_change=stamp(1))]
        for index, changes in enumerate(cases, 200):
            row = session(**{"pid": index, **changes})
            self.db.sessions[row["pid"]] = row
        record = self.record()
        self.assertEqual([s["pid"] for s in record.target_bindings[TARGET]["sessions"]], [101])
        self.assertTrue(self.executor.execute_record(record, TARGET, "UTEAM").ok)
        self.assertEqual(self.db.signals, [("terminate_idle_sessions", 101)])

    def test_long_query_excludes_an_explicit_older_transaction(self):
        self.db.sessions[202] = session(202, state="active", query_start=stamp(300), xact_start=stamp(600))
        record = self.record("cancel_long_queries")
        self.assertEqual([s["pid"] for s in record.target_bindings[TARGET]["sessions"]], [101])
        self.assertTrue(self.executor.execute_record(record, TARGET, "UTEAM").ok)
        self.assertEqual(self.db.signals, [("cancel_long_queries", 101)])

    def test_reused_pid_cannot_signal_replacement_backend(self):
        record = self.record()
        self.db.before_mutation = lambda: self.db.sessions[101].update(backend_start=stamp(1))
        self.assertEqual(self.executor.execute_record(record, TARGET, "UTEAM").status, "BLOCKED")
        self.assertEqual(self.db.signals, [])

    def test_changed_query_cannot_cancel_new_query(self):
        record = self.record("cancel_long_queries")
        self.db.before_mutation = lambda: self.db.sessions[101].update(query_start=stamp(1), xact_start=stamp(1))
        self.assertEqual(self.executor.execute_record(record, TARGET, "UTEAM").status, "BLOCKED")
        self.assertEqual(self.db.signals, [])

    def test_transition_to_transaction_cannot_be_terminated(self):
        record = self.record()
        self.db.before_mutation = lambda: self.db.sessions[101].update(state="idle in transaction", xact_start=stamp(5))
        self.assertEqual(self.executor.execute_record(record, TARGET, "UTEAM").status, "BLOCKED")
        self.assertEqual(self.db.signals, [])

    def test_server_cluster_database_address_and_privilege_mismatch_prevent_signal(self):
        for field, value in (("system_identifier", "other-cluster"), ("database", "other-db"),
            ("server_addr", "10.0.0.8"), ("server_port", 5433), ("rolsuper", True), ("rolbypassrls", True), ("can_signal", False),
            ("can_read_stats", False), ("in_recovery", True), ("server_version", 160009)):
            with self.subTest(field=field):
                record = self.record()
                record.remediation_id += field
                before = self.db.info[field]
                self.db.info[field] = value
                self.assertIsNotNone(self.executor.validate_record(record))
                self.assertEqual(self.executor.execute_record(record, TARGET, "UTEAM").status, "BLOCKED")
                self.db.info[field] = before
        self.assertEqual(self.db.signals, [])

    def test_reject_expired_wrong_actor_or_missing_durable_claim_never_signal(self):
        for field, value in (("state", store.REJECTED), ("state", store.APPROVED),
            ("approval_expires_at", stamp(1)), ("requires_approval", False), ("action_started_at", None),
            ("approved_by", None), ("approved_at", stamp(-2))):
            with self.subTest(field=field):
                record = self.record()
                setattr(record, field, value)
                self.assertEqual(self.executor.execute_record(record, TARGET, "UTEAM").status, "BLOCKED")
        self.assertEqual(self.executor.execute_record(self.record(), TARGET, "UOTHER").status, "BLOCKED")
        self.assertEqual(self.db.signals, [])

    def test_expiry_after_database_preflight_still_blocks_mutation(self):
        record = self.record()
        self.db.on_identity = lambda: setattr(record, "approval_expires_at", stamp(1))
        self.assertEqual(self.executor.execute_record(record, TARGET, "UTEAM").status, "BLOCKED")
        self.assertEqual(self.db.signals, [])

    def test_unknown_parameters_and_limit_widening_cannot_form_a_plan(self):
        invalid = ({"operation": "raw_sql", "sql": "DROP DATABASE leafy"},
            {"operation": "terminate_idle_sessions", "max_sessions": 3},
            {"operation": "terminate_idle_sessions", "min_age_seconds": 59},
            {"operation": "terminate_idle_sessions", "pid": 101}, {})
        for params in invalid:
            with self.subTest(params=params), self.assertRaises(PostgresError):
                self.executor.plan_record(IDENTITY, [TARGET], "KILL_SESSIONS", params)
        self.assertEqual(self.db.calls, [])

    def test_plan_selection_count_is_bounded_and_approved_exactly(self):
        self.db.sessions.update({pid:session(pid) for pid in range(102,110)})
        record = self.record(max_sessions=1)
        self.assertEqual(len(record.target_bindings[TARGET]["sessions"]), 1)
        self.assertTrue(self.executor.execute_record(record, TARGET, "UTEAM").ok)
        self.assertEqual(len(self.db.signals), 1)
        self.assertEqual(len(self.db.sessions), 8)

    def test_configuration_change_after_approval_requires_new_review(self):
        record = self.record()
        self.config["targets"][TARGET]["max_sessions"] = 1
        self.write_config()
        self.assertEqual(self.executor.execute_record(record, TARGET, "UTEAM").status, "BLOCKED")
        self.assertEqual(self.db.signals, [])

    def test_changed_action_parameters_or_hash_do_not_match_stored_plan(self):
        record = self.record()
        record.action_parameters["max_sessions"] = 1
        self.assertEqual(self.executor.execute_record(record, TARGET, "UTEAM").status, "BLOCKED")
        record = self.record()
        record.action_hash = "forged"
        self.assertEqual(self.executor.execute_record(record, TARGET, "UTEAM").status, "BLOCKED")
        self.assertEqual(self.db.signals, [])

    def test_lost_response_is_unknown_redacted_and_not_resent_after_restart(self):
        record = self.record()
        self.db.lose_reply = True
        result = self.executor.execute_record(record, TARGET, "UTEAM")
        self.assertEqual(result.status, "UNKNOWN")
        self.assertNotIn(PASSWORD, json.dumps(result.as_dict()))
        self.assertNotIn("private_customer_data", json.dumps(result.as_dict()))
        restarted = PostgresExecutor(str(self.path), self.db.connect, self.executor.ledger_path)
        self.assertEqual(restarted.execute_record(record, TARGET, "UTEAM").status, "UNKNOWN")
        self.assertEqual(self.db.signals, [("terminate_idle_sessions", 101)])
        self.assertTrue(all(c.closed for c in self.db.connections))

    def test_duplicate_success_uses_durable_result_without_second_signal(self):
        record = self.record()
        first = self.executor.execute_record(record, TARGET, "UTEAM")
        second = self.executor.execute_record(record, TARGET, "UTEAM")
        self.assertTrue(first.ok and second.ok)
        self.assertEqual(len(self.db.signals), 1)

    def test_true_signal_without_verified_effect_is_unknown_no_retry(self):
        record = self.record()
        self.db.apply_signal = False
        result = self.executor.execute_record(record, TARGET, "UTEAM")
        self.assertEqual(result.status, "UNKNOWN")
        self.assertEqual(self.executor.execute_record(record, TARGET, "UTEAM").status, "UNKNOWN")
        self.assertEqual(len(self.db.signals), 1)

    def test_unwritable_durable_claim_stops_before_signal(self):
        record = self.record()
        blocker = Path(self.tmp.name) / "blocker"
        blocker.write_text("file, not directory")
        self.executor.ledger_path = str(blocker / "ledger.sqlite")
        self.assertEqual(self.executor.execute_record(record, TARGET, "UTEAM").status, "BLOCKED")
        self.assertEqual(self.db.signals, [])

    def test_superuser_allowlist_and_arbitrary_connection_string_are_rejected(self):
        self.config["targets"][TARGET]["allowed_roles"] = ["postgres"]
        self.write_config()
        with self.assertRaises(PostgresError):
            self.record()
        self.config["targets"][TARGET]["allowed_roles"] = ["leafy_app"]
        self.write_config()
        with patch.dict(os.environ, {"TEST_PGHOST": "postgresql://user:secret@evil/db"}), self.assertRaises(PostgresError) as raised:
            self.record()
        self.assertNotIn("secret", str(raised.exception))
        self.assertEqual(self.db.signals, [])

    def test_final_result_ledger_failure_preserves_uncertainty_and_prevents_retry(self):
        record = self.record()
        original = self.executor._ledger
        calls = []
        def ledger():
            calls.append(True)
            if len(calls) == 2:
                raise OSError("ledger result write failed")
            return original()
        with patch.object(self.executor, "_ledger", side_effect=ledger):
            result = self.executor.execute_record(record, TARGET, "UTEAM")
        self.assertEqual(result.status, "UNKNOWN")
        restarted = PostgresExecutor(str(self.path), self.db.connect, self.executor.ledger_path)
        self.assertEqual(restarted.execute_record(record, TARGET, "UTEAM").status, "UNKNOWN")
        self.assertEqual(len(self.db.signals), 1)

    def test_concurrent_duplicate_execute_dispatches_only_one_signal(self):
        from concurrent.futures import ThreadPoolExecutor
        import threading
        record = self.record()
        gate = threading.Barrier(2)
        second = PostgresExecutor(str(self.path), self.db.connect, self.executor.ledger_path)
        def run(executor):
            gate.wait()
            return executor.execute_record(record, TARGET, "UTEAM")
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(run, (self.executor, second)))
        self.assertEqual(len(self.db.signals), 1)
        self.assertTrue(any(result.ok for result in results))
        self.assertTrue(all(result.status in {"SUCCESS", "UNKNOWN"} for result in results))

    def test_environment_cannot_substitute_a_different_executor_role(self):
        record = self.record()
        with patch.dict(os.environ, {"TEST_PGUSER": "another_remediator"}):
            self.assertEqual(self.executor.execute_record(record, TARGET, "UTEAM").status, "BLOCKED")
        self.assertEqual(self.db.signals, [])

    def test_no_eligible_sessions_cannot_produce_an_approval_plan(self):
        self.db.sessions = {101: session(state="idle in transaction", xact_start=stamp(400))}
        with self.assertRaises(PostgresError):
            self.record()
        self.assertEqual(self.db.signals, [])

    def test_missing_or_changed_durable_plan_evidence_stops_before_signal(self):
        record = self.record()
        record.evidence = {}
        self.assertEqual(self.executor.execute_record(record, TARGET, "UTEAM").status, "BLOCKED")
        record = self.record()
        record.evidence["targets"][TARGET]["sessions"][0]["pid"] = 404
        self.assertEqual(self.executor.execute_record(record, TARGET, "UTEAM").status, "BLOCKED")
        self.assertEqual(self.db.signals, [])

    def test_sqlite_setup_failure_closes_ledger_connection_and_never_dispatches(self):
        import executor.postgres as module
        class BrokenLedger:
            closed = False
            def execute(self, *args):
                raise OSError("sqlite setup unavailable")
            def close(self):
                self.closed = True
        ledger = BrokenLedger()
        record = self.record()
        with patch.object(module.sqlite3, "connect", return_value=ledger):
            result = self.executor.execute_record(record, TARGET, "UTEAM")
        self.assertEqual(result.status, "BLOCKED")
        self.assertTrue(ledger.closed)
        self.assertEqual(self.db.signals, [])

    def test_exact_jdbc_application_name_with_spaces_remains_parameterized(self):
        self.config["targets"][TARGET]["allowed_applications"] = ["PostgreSQL JDBC Driver"]
        self.write_config()
        self.db.sessions[101]["application_name"] = "PostgreSQL JDBC Driver"
        record = self.record()
        self.assertTrue(self.executor.execute_record(record, TARGET, "UTEAM").ok)
        self.assertEqual(self.db.signals, [("terminate_idle_sessions", 101)])
        self.assertTrue(all("PostgreSQL JDBC Driver" not in sql for sql, _ in self.db.calls))
