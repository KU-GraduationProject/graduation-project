"""
DB 백업(BACKUP_DB) 선행 단계 (#53, 노션: RECREATE·ROLLBACK·보안 사고 ISOLATE 앞 DB 백업).

pg_dump·pg_restore 는 실행하지 않고 subprocess.run 대역으로 검증한다.
"""

import json
import os
import stat
import subprocess
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import db_backup
from executor.extended import ExtendedExecutorRouter
from tests.safety_fixtures import fake_db_backup
from tests import test_extended_controller as extended  # 모듈로 가져와 부모 테스트가 다시 돌지 않게 한다
from tests.test_phase2_integration import Phase2Base, analysis_body, approve_form

CONFIG = {"database": "leafy", "system_identifier": "7301", "sslmode": "verify-full",
          "connection": {"host_env": "PGH", "port_env": "PGP", "dbname_env": "PGD",
                         "user_env": "IGNORED_U", "password_env": "IGNORED_P", "sslmode": "verify-full"}}
ENV = {"PATH": "/usr/bin", "PGH": "db.internal", "PGP": "5432", "PGD": "leafy",
       "REMEDIATION_BACKUP_PGUSER": "leafy_backup", "REMEDIATION_BACKUP_PGPASSWORD": "fixture-secret"}


class FakeRun:
    """pg_dump 은 --file 에 덤프를 쓰고, pg_restore --list 는 성공한다."""

    def __init__(self, content=b"PGDMP fixture dump", dump_rc=0, list_rc=0, raise_on=None):
        self.content, self.dump_rc, self.list_rc, self.raise_on = content, dump_rc, list_rc, raise_on
        self.calls = []

    def __call__(self, args, env=None, **kw):
        self.calls.append((list(args), dict(env or {})))
        if self.raise_on == args[0]:
            raise subprocess.TimeoutExpired(args, 1)
        if args[0] == "pg_dump":
            if self.content is not None:
                with open(args[args.index("--file") + 1], "wb") as fh:
                    fh.write(self.content)
            return SimpleNamespace(returncode=self.dump_rc)
        return SimpleNamespace(returncode=self.list_rc)


class CreateBackupTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.settings = db_backup.BackupSettings(target="leafy-db", directory=self.tmp.name)

    def backup(self, run, rid="rid-1", env=ENV, **kw):
        settings = db_backup.BackupSettings(**{**self.settings.__dict__, **kw})
        return db_backup.create_backup(settings, CONFIG, rid, run=run, environ=env)

    def test_verified_dump_and_manifest_match_rollback_contract(self):
        run = FakeRun()
        manifest = self.backup(run)
        self.assertTrue(manifest["verified"] and manifest["restore_list_verified"])
        self.assertEqual(manifest["format"], "postgres-custom")
        self.assertEqual(manifest["database_id"], "7301:leafy")
        self.assertEqual(stat.S_IMODE(os.stat(manifest["artifact_path"]).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(manifest["manifest_path"]).st_mode), 0o600)
        with open(manifest["manifest_path"], encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["sha256"], manifest["sha256"])
        dump_args, dump_env = run.calls[0]
        self.assertEqual(dump_args[0], "pg_dump")
        self.assertNotIn("fixture-secret", " ".join(dump_args))   # 비밀번호는 명령행에 없다
        self.assertEqual(dump_env["PGPASSWORD"], "fixture-secret")
        self.assertEqual(dump_env["PGUSER"], "leafy_backup")
        self.assertNotIn("PGPASSWORD", run.calls[1][1])            # pg_restore 에는 넘기지 않는다
        self.assertEqual(run.calls[1][0][:2], ["pg_restore", "--list"])

    def test_failures_raise_and_leave_no_partial_dump(self):
        cases = {"pg_dump_failed": dict(run=FakeRun(dump_rc=1)),
                 "backup_format_invalid": dict(run=FakeRun(content=b"NOTADUMP")),
                 "pg_restore_list_failed": dict(run=FakeRun(list_rc=1)),
                 "backup_size_out_of_bounds": dict(run=FakeRun(), max_bytes=4),
                 "pg_dump_unavailable_or_timeout": dict(run=FakeRun(raise_on="pg_dump")),
                 "backup_connection_not_configured": dict(run=FakeRun(), env={"PATH": "/usr/bin"}),
                 "backup_database_mismatch": dict(run=FakeRun(), env={**ENV, "PGD": "other"})}
        for reason, kw in cases.items():
            with self.subTest(reason=reason):
                with self.assertRaises(db_backup.BackupError) as ctx:
                    self.backup(**kw)
                self.assertEqual(str(ctx.exception), reason)
                self.assertEqual([p for p in os.listdir(self.tmp.name) if p.endswith(".partial")], [])

    def test_insufficient_disk_space_is_refused_before_dumping(self):
        run = FakeRun()
        with patch("db_backup.shutil.disk_usage", return_value=SimpleNamespace(free=10)):
            with self.assertRaises(db_backup.BackupError):
                self.backup(run)
        self.assertEqual(run.calls, [])

    def test_retention_keeps_recent_backups_only(self):
        for i in range(7):
            manifest = self.backup(FakeRun(), rid=f"rid-{i}")
            past = time.time() - (7 - i) * 60
            os.utime(manifest["artifact_path"], (past, past))
        old = self.backup(FakeRun(), rid="old")
        ancient = time.time() - 30 * 86400
        os.utime(old["artifact_path"], (ancient, ancient))
        self.backup(FakeRun(), rid="latest")
        dumps = [p for p in os.listdir(self.tmp.name) if p.endswith(".dump")]
        self.assertLessEqual(len(dumps), db_backup.DEFAULT_KEEP)
        self.assertTrue(any("latest" in p for p in dumps))
        self.assertFalse(os.path.exists(old["artifact_path"]))

    def test_settings_require_explicit_target(self):
        with patch.dict(os.environ, {"REMEDIATION_BACKUP_TARGET": ""}):
            self.assertIsNone(db_backup.BackupSettings.from_env())


class DeploymentBackupGateTest(Phase2Base):
    """RECREATE·ROLLBACK 은 DB 백업이 없으면 실행하지 않는다."""
    propose = extended.ExtendedControllerTests.propose
    approve = extended.ExtendedControllerTests.approve

    def setUp(self):
        super().setUp()
        self.families = {name: extended.FamilyFixture(name, self) for name in ("postgres", "deployment", "app_api")}
        self.main.executor = ExtendedExecutorRouter(self.families, docker_executor=self.main.executor)
        self.main.db_backup_runner = fake_db_backup

    def approve_recreate(self):
        proposal, targets = self.propose("RECREATE")
        rid = proposal.json()["remediation_id"]
        self.approve("RECREATE", rid, targets)
        return self.record(rid)

    def test_backup_manifest_is_recorded_before_recreate(self):
        record = self.approve_recreate()
        self.assertEqual(self.families["deployment"].calls, ["RECREATE"])
        self.assertEqual(record.evidence["db_backup"]["sha256"], "0" * 64)

    def test_backup_failure_blocks_recreate(self):
        def failing(rid):
            raise db_backup.BackupError("pg_dump_failed")
        self.main.db_backup_runner = failing
        record = self.approve_recreate()
        self.assertEqual(record.state, "BLOCKED")
        self.assertEqual(record.results[0]["blocked_reason"], "db_backup_failed:pg_dump_failed")
        self.assertEqual(self.families["deployment"].calls, [])

    def test_unconfigured_backup_blocks_recreate(self):
        self.main.db_backup_runner = self.main._backup_for_record
        with patch.dict(os.environ, {"REMEDIATION_BACKUP_TARGET": ""}):
            record = self.approve_recreate()
        self.assertEqual(record.results[0]["blocked_reason"], "db_backup_failed:backup_not_configured")
        self.assertEqual(self.families["deployment"].calls, [])


class AttackIsolateBackupTest(Phase2Base):
    """보안 사고 ISOLATE 는 DB 백업을 시도하되, 실패해도 격리를 늦추지 않는다."""

    def isolate(self, incident_class):
        payload = json.loads(analysis_body("ISOLATE"))
        payload["analysis"]["incident_class"] = incident_class
        rid = self.post_action(json.dumps(payload).encode()).json()["remediation_id"]
        self.post_slack(approve_form("ISOLATE", rid))
        return self.record(rid)

    def test_attack_isolation_proceeds_when_backup_fails(self):
        calls = []

        def failing(rid):
            calls.append(rid)
            raise db_backup.BackupError("pg_dump_failed")
        self.main.db_backup_runner = failing
        record = self.isolate("attack")
        self.assertEqual(len(calls), 1)
        self.assertIsNotNone(record.action_verified_at)
        self.assertEqual(record.evidence["db_backup"], {"failed": "pg_dump_failed"})
        self.assertIn("disconnect", self.docker_actions())

    def test_non_attack_isolation_skips_backup(self):
        calls = []
        self.main.db_backup_runner = lambda rid: calls.append(rid)
        record = self.isolate("failure")
        self.assertEqual(calls, [])
        self.assertNotIn("db_backup", record.evidence)


if __name__ == "__main__":
    unittest.main()
