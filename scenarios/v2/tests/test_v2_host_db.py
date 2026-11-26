"""호스트 PostgreSQL 모드 전환(SCEN_ 별칭·기본값)과 안전 가드 순수 로직 테스트.

실제 DB·Docker 없이 환경변수와 argv 만 검사한다. 비밀번호가 argv 에 들어가지 않는 것,
host 모드 기본값, 미지정 시 거부, S2-d 게이트웨이 예외 허용을 확인한다.
"""
import os
import unittest
from unittest.mock import patch

from v2 import f3a_bad_image_deploy as f3a
from v2 import s2d_internal_recon as s2d
from v2.f2c_runtime import RuntimeFailure, Target

_BASE = {"SCEN_PGDATABASE": "aiops_test", "SCEN_PGADMIN": "scen_admin",
         "SCEN_PGUSER": "scen_app", "SCEN_EXPECTED_SYSTEM_ID": "123"}


class TargetFromEnvScenAliases(unittest.TestCase):
    def test_host_mode_defaults(self):
        """mode 미지정 → host, host → host.docker.internal, port → 5432."""
        with patch.dict(os.environ, _BASE, clear=True):
            t = Target.from_env(allow_injection=False)
        self.assertEqual((t.mode, t.host, t.port), ("host", "host.docker.internal", 5432))
        self.assertEqual(t.database, "aiops_test")
        self.assertEqual(t.confirmation, "host:host.docker.internal:5432:aiops_test:123")

    def test_confirm_token_required_for_injection(self):
        with patch.dict(os.environ, _BASE, clear=True):
            with self.assertRaises(RuntimeFailure):
                Target.from_env()  # allow_injection=True 기본 — 토큰 불일치
        with patch.dict(os.environ, {**_BASE,
                        "SCEN_CONFIRM_TARGET": "host:host.docker.internal:5432:aiops_test:123"},
                        clear=True):
            self.assertEqual(Target.from_env().user, "scen_app")

    def test_missing_target_refused(self):
        for drop in ("SCEN_PGDATABASE", "SCEN_PGUSER", "SCEN_EXPECTED_SYSTEM_ID"):
            env = {k: v for k, v in _BASE.items() if k != drop}
            with patch.dict(os.environ, env, clear=True):
                with self.assertRaises(RuntimeFailure):
                    Target.from_env(allow_injection=False)

    def test_f2c_names_still_work(self):
        env = {"F2C_DB_MODE": "host", "F2C_DB_NAME": "aiops_test", "F2C_ADMIN_USER": "a",
               "F2C_DB_USER": "b", "F2C_EXPECTED_SYSTEM_ID": "9", "F2C_DB_HOST": "db",
               "F2C_DB_PORT": "5555"}
        with patch.dict(os.environ, env, clear=True):
            t = Target.from_env(allow_injection=False)
        self.assertEqual((t.host, t.port, t.database), ("db", 5555, "aiops_test"))

    def test_scen_overrides_port_and_host(self):
        with patch.dict(os.environ, {**_BASE, "SCEN_PGHOST": "127.0.0.1", "SCEN_PGPORT": "5433"},
                        clear=True):
            t = Target.from_env(allow_injection=False)
        self.assertEqual((t.host, t.port), ("127.0.0.1", 5433))


class HostBackupArgv(unittest.TestCase):
    def test_host_conn_defaults_and_refusal(self):
        # 백업 역할은 관리자 우선(SCEN_PGADMIN), 없으면 SCEN_PGUSER.
        with patch.dict(os.environ, {"SCEN_PGDATABASE": "aiops_test", "SCEN_PGADMIN": "scen_admin",
                        "SCEN_PGUSER": "scen_app"}, clear=True):
            conn = f3a.host_db_conn()
        self.assertEqual((conn["host"], conn["port"], conn["database"], conn["user"]),
                         ("host.docker.internal", "5432", "aiops_test", "scen_admin"))
        with patch.dict(os.environ, {"SCEN_PGDATABASE": "aiops_test", "SCEN_PGUSER": "scen_app"},
                        clear=True):
            self.assertEqual(f3a.host_db_conn()["user"], "scen_app")  # 관리자 미지정 → user 대체
        with patch.dict(os.environ, {"SCEN_PGADMIN": "scen_admin"}, clear=True):
            with self.assertRaises(RuntimeError):
                f3a.host_db_conn()  # SCEN_PGDATABASE 미지정 → 거부

    def test_host_conn_rejects_bad_identifiers(self):
        for bad in ({"SCEN_PGDATABASE": "a;b", "SCEN_PGUSER": "u"},
                    {"SCEN_PGDATABASE": "db", "SCEN_PGUSER": "u u"},
                    {"SCEN_PGDATABASE": "db", "SCEN_PGUSER": "u", "SCEN_PGHOST": "-h"}):
            with patch.dict(os.environ, bad, clear=True):
                with self.assertRaises(RuntimeError):
                    f3a.host_db_conn()

    def test_pg_dump_host_argv_has_no_password(self):
        conn = {"pg_dump": "pg_dump", "host": "host.docker.internal", "port": "5432",
                "user": "scen_app", "database": "aiops_test"}
        argv = f3a.pg_dump_host_argv(conn)
        self.assertIn("-w", argv)                       # 프롬프트 금지
        self.assertEqual(argv[:3], ["pg_dump", "-Fc", "-w"])
        joined = " ".join(argv).lower()
        self.assertNotIn("password", joined)
        self.assertNotIn("pgpassword", joined)

    def test_host_env_passfile_only(self):
        with patch.dict(os.environ, {"PGPASSWORD": "should-be-dropped"}, clear=True):
            env = f3a.host_env({"passfile": "/run/secrets/pgpass"})
        self.assertEqual(env["PGPASSFILE"], "/run/secrets/pgpass")
        self.assertNotIn("PGPASSWORD", env)

    def test_default_mode_is_host(self):
        self.assertEqual(f3a.DB_MODE, "host")


class S2dGatewayAllowlist(unittest.TestCase):
    def test_gateway_name_allowed(self):
        s2d.assert_internal(["host.docker.internal"])   # 예외 허용 — 예외 미발생
        s2d.assert_internal(["db", "minio", "gateway.docker.internal"])

    def test_external_and_ip_still_rejected(self):
        for bad in (["evil.example.com"], ["10.0.0.5"], ["db:5432"], ["a/b"], ["host.docker.evil"]):
            with self.assertRaises(ValueError):
                s2d.assert_internal(bad)

    def test_plan_scan_with_gateway(self):
        plan = s2d.plan_scan("weak", hosts=["host.docker.internal"], ports=[5432])
        self.assertEqual(plan["hosts"], ["host.docker.internal"])
        self.assertEqual(plan["probes"], 1)


if __name__ == "__main__":
    unittest.main()
