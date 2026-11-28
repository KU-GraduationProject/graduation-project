"""Real adapter paths with fake command/HTTP transports; no service mutations."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

from executor.edge_storage_host import EdgeStorageHostExecutor, OperationsError, MARKER, ACTIONS
from executor.managed import seal_plan
import store


def identity(service="frontend", runtime="container", target="fixture-frontend"):
    return {"site": "fixture-site", "source": "fixture-source", "service": service, "runtime": runtime, "target": target}


def record(executor, ident, action, params=None, rid="fixture-record"):
    params = params or {}
    plans = executor.plan_record(ident, [ident["target"]], action, params)
    now = datetime.now(timezone.utc)
    return SimpleNamespace(remediation_id=rid, identity=ident, targets=[ident["target"]], action_type=action,
        action_parameters=params, target_bindings=plans, evidence={"targets": deepcopy(plans)},
        executor_name="operations", requires_approval=True, approved_by="fixture-operator", state="EXECUTING",
        ttl_seconds=None, recovery_mode="none", incident_key="f"*64,
        approved_at=(now-timedelta(milliseconds=800)).isoformat(), action_started_at=(now-timedelta(milliseconds=500)).isoformat(),
        approval_requested_at=(now-timedelta(seconds=1)).isoformat(),
        approval_expires_at=(now+timedelta(minutes=5)).isoformat(),
        action_hash=store.action_hash(action, [ident["target"]], None, "none", params))


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir="/private/tmp" if Path("/private/tmp").is_dir() else None)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.include = self.root / "managed.conf"; self.include.write_text(MARKER)
        self.nginxconf = self.root / "nginx.conf"; self.nginxconf.write_text("events {} http { include managed.conf; }")
        self.calls, self.svcstate, self.pid = [], 4, 123
        self.policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::fixture-bucket/*"}]}
        self.keystate = "on"
        self.config = {"version": 1, "enabled": True, "state_dir": str(self.state), "targets": {}}
        self.config_path = self.root / "operations.yml"
        self.client = None
        self.ex = EdgeStorageHostExecutor(self.config_path, runner=self.run_fake, open_files=lambda: set(), platform="win32", sleep=lambda _: None)
        self.env = patch.dict(os.environ, {"FIXTURE_KEY": "fixture-access-key", "FIXTURE_OWNER": "fixture-service-user", "FIXTURE_ROOT": "fixture-root-key"})
        self.env.start(); self.addCleanup(self.env.stop)

    def tool(self, name):
        p = self.root / name; p.write_text("synthetic binary; never executed")
        return {"binary": str(p), "binary_sha256": hashlib.sha256(p.read_bytes()).hexdigest()}

    def target(self, ident, **parts):
        self.config["targets"][ident["target"]] = {"identity": ident, "actions": sorted(ACTIONS), **parts}
        self.config_path.write_text(yaml.safe_dump(self.config))

    def nginx(self):
        ident = identity()
        spec = {"container_id": "a"*64, "image_id": "sha256:" + "b"*64, "shared_include_verified": True,
            "labels": {"io.leafy.remediation": "workload", "com.docker.compose.service": "frontend"},
            "container_binary": "/usr/sbin/nginx", "container_config": "/etc/nginx/nginx.conf",
            "container_include": "/etc/nginx/remediation/managed.conf", "mount_source": "/fixture/host-edge",
            "managed_root": str(self.root), "managed_include": str(self.include), "rate_limit_upstream": "fixture-backend:8080"}
        self.container = SimpleNamespace(attrs={"Id": spec["container_id"], "Image": spec["image_id"], "Name": "/" + ident["target"],
            "Config": {"Labels": spec["labels"]}, "HostConfig": {}, "State": {"Running": True},
            "Mounts": [{"Type": "bind", "Source": spec["mount_source"], "Destination": "/etc/nginx/remediation"}]}, reload=lambda: None)
        def exec_run(argv, **kwargs):
            res = self.run_fake(argv)
            return SimpleNamespace(exit_code=res.returncode, output=res.stdout.encode())
        self.container.exec_run = exec_run
        self.ex.docker_client = SimpleNamespace(containers=SimpleNamespace(get=lambda _: self.container))
        self.target(ident, nginx=spec)
        return ident

    def minio(self):
        ident = identity("minio", target="fixture-minio")
        private = self.root / "mc-private"
        private.mkdir(mode=0o700, exist_ok=True)
        config = private / "config.json"
        config.write_text(json.dumps({"aliases": {"fixture": {"url": "https://fixture-minio.invalid"}}}))
        config.chmod(0o600)
        self.target(ident, minio={**self.tool("mc"), "alias": "fixture", "config_dir": str(self.root / "mc-private"),
            "bucket_allowlist": ["fixture-bucket"], "root_key_env": "FIXTURE_ROOT",
            "service_accounts": {"uploader": {"key_id_env": "FIXTURE_KEY", "owner_env": "FIXTURE_OWNER"}}})
        return ident

    def run_fake(self, argv, **kwargs):
        self.calls.append(argv)
        out = ""
        if Path(argv[0]).name == "nginx" and "-T" in argv:
            out = "# configuration file /etc/nginx/remediation/managed.conf:\n" + self.include.read_text()
            out += "limit_req_zone $uri zone=leafy_remediation:10m rate=5r/s;\n"
        if Path(argv[0]).name == "mc":
            if "get-json" in argv: out = json.dumps(self.policy)
            elif "set-json" in argv: self.policy = json.loads(Path(argv[-2]).read_text())
            elif "info" in argv: out = json.dumps({"accountStatus": self.keystate, "parentUser": os.environ["FIXTURE_OWNER"]})
            elif "disable" in argv: self.keystate = "off"
            elif "enable" in argv: self.keystate = "on"
        elif Path(argv[0]).name == "sc.exe":
            if "queryex" in argv: out = f"STATE : {self.svcstate} RUNNING\nPID : {self.pid}\n"
            elif "qc" in argv: out = "BINARY_PATH_NAME : fixture-postgres\n"
            elif "stop" in argv: self.svcstate = 1
            elif "start" in argv: self.svcstate, self.pid = 4, 124
        return SimpleNamespace(returncode=0, stdout=out)

    def execute(self, r):
        return self.ex.execute_record(r, r.targets[0], r.approved_by)

    def test_disabled_and_changed_binary_or_identity_block_before_commands(self):
        ident = self.nginx()
        r = record(self.ex, ident, "BLOCK_PATH", {"path": "/private"})
        self.config["enabled"] = False; self.config_path.write_text(yaml.safe_dump(self.config))
        self.calls.clear()
        self.assertEqual(self.execute(r).status, "BLOCKED")
        self.assertEqual(self.calls, [])

    def test_nginx_literal_path_apply_and_separate_parent_restore(self):
        ident = self.nginx()
        r = record(self.ex, ident, "BLOCK_PATH", {"path": "/files"})
        self.assertTrue(self.execute(r).ok)
        self.assertIn("location = /files { return 403; }", self.include.read_text())
        self.assertTrue(any("reload" in c for c in self.calls))
        undo = record(self.ex, ident, "RESTORE_NGINX", {"parent_id": r.remediation_id}, "fixture-restore")
        self.assertTrue(self.execute(undo).ok)
        self.assertEqual(self.include.read_text(), MARKER)

    def test_nginx_reject_injection_and_unrecognized_existing_content(self):
        ident = self.nginx()
        for path in ("/x; return 200", "/x\n}", "http://outside", "/$arg"):
            with self.assertRaises(OperationsError): self.ex.plan_record(ident, [ident["target"]], "BLOCK_PATH", {"path": path})
        self.include.write_text(MARKER + "include credential-file;\n")
        with self.assertRaises(OperationsError): self.ex.plan_record(ident, [ident["target"]], "MAINTENANCE_MODE", {})

    def test_nginx_expired_approval_and_changed_state_no_mutation(self):
        ident = self.nginx()
        r = record(self.ex, ident, "BLOCK_PATH", {"path": "/files"})
        r.approval_expires_at = (datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
        self.calls.clear()
        self.assertEqual(self.execute(r).status, "BLOCKED")
        self.assertEqual(self.calls, [])
        self.assertEqual(self.include.read_text(), MARKER)

    def test_minio_anonymous_access_restriction_and_policy_restore(self):
        ident = self.minio(); old = deepcopy(self.policy)
        r = record(self.ex, ident, "RESTRICT_BUCKET", {"bucket": "fixture-bucket"})
        self.assertTrue(self.execute(r).ok)
        self.assertEqual(self.policy["Statement"], [])
        undo = record(self.ex, ident, "RESTORE_BUCKET", {"parent_id": r.remediation_id}, "fixture-restore")
        self.assertTrue(self.execute(undo).ok)
        self.assertEqual(self.policy, old)

    def test_minio_key_disable_enable_and_no_key_in_plan_or_result(self):
        ident = self.minio()
        r = record(self.ex, ident, "DISABLE_KEY", {"resource": "uploader"})
        result = self.execute(r)
        self.assertTrue(result.ok)
        self.assertEqual(self.keystate, "off")
        self.assertNotIn(os.environ["FIXTURE_KEY"], json.dumps(r.target_bindings))
        self.assertNotIn(os.environ["FIXTURE_KEY"], json.dumps(result.as_dict()))
        undo = record(self.ex, ident, "ENABLE_KEY", {"parent_id": r.remediation_id}, "fixture-restore")
        self.assertTrue(self.execute(undo).ok)
        self.assertEqual(self.keystate, "on")

    def test_root_key_and_unallowlisted_bucket_refused(self):
        ident = self.minio()
        with self.assertRaises(OperationsError): self.ex.plan_record(ident, [ident["target"]], "RESTRICT_BUCKET", {"bucket": "other"})
        with patch.dict(os.environ, {"FIXTURE_KEY": os.environ["FIXTURE_ROOT"]}):
            with self.assertRaises(OperationsError): self.ex.plan_record(ident, [ident["target"]], "DISABLE_KEY", {"resource": "uploader"})

    def test_restore_refuses_intervening_operator_changes(self):
        ident = self.minio()
        r = record(self.ex, ident, "RESTRICT_BUCKET", {"bucket": "fixture-bucket"}); self.assertTrue(self.execute(r).ok)
        self.policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny"}]}
        with self.assertRaises(OperationsError): record(self.ex, ident, "RESTORE_BUCKET", {"parent_id": r.remediation_id}, "fixture-restore")

    def test_host_postgresql_restart_observes_new_running_pid(self):
        ident = identity("db", "host", "fixture-pg")
        self.target(ident, host_service={**self.tool("sc.exe"), "service_name": "postgresql-x64-17"})
        r = record(self.ex, ident, "RESTART_HOST_SVC")
        self.assertTrue(self.execute(r).ok)
        self.assertEqual((self.svcstate, self.pid), (4, 124))
        self.assertTrue(any("stop" in c for c in self.calls)); self.assertTrue(any("start" in c for c in self.calls))

    def test_closed_logs_delete_exact_old_files_and_refuse_open_or_symlink(self):
        logs = self.root / "closed-logs"; logs.mkdir()
        old = logs / "old-2020.log"; old.write_text("synthetic closed log")
        os.utime(old, (time_zero := 1, time_zero))
        ident = identity("host-logs", "host", "fixture-logs")
        self.target(ident, clean_logs={"root": str(logs), "files": [old.name], "min_age_seconds": 86400, "max_total_bytes": 1024})
        self.ex.open_files = lambda: {old.resolve()}
        with self.assertRaises(OperationsError): record(self.ex, ident, "CLEAN_DISK")
        self.ex.open_files = lambda: set()
        r = record(self.ex, ident, "CLEAN_DISK")
        self.assertTrue(self.execute(r).ok); self.assertFalse(old.exists())
        link = logs / "linked.log"; link.symlink_to(self.include)
        self.config["targets"][ident["target"]]["clean_logs"]["files"] = [link.name]
        self.config_path.write_text(yaml.safe_dump(self.config))
        with self.assertRaises(OperationsError): record(self.ex, ident, "CLEAN_DISK")

    def test_uncertain_write_never_retries(self):
        ident = self.minio()
        r = record(self.ex, ident, "DISABLE_KEY", {"resource": "uploader"})
        original = self.ex.runner
        def fail_after_mutation(argv, **kwargs):
            result = original(argv, **kwargs)
            if "disable" in argv: raise TimeoutError()
            return result
        self.ex.runner = fail_after_mutation
        self.assertEqual(self.execute(r).status, "UNKNOWN")
        count = sum("disable" in c for c in self.calls)
        self.assertEqual(self.execute(r).status, "BLOCKED")
        self.assertEqual(sum("disable" in c for c in self.calls), count)


    def test_nginx_rate_and_maintenance_are_fixed_directives(self):
        ident = self.nginx()
        r = record(self.ex, ident, "RATE_LIMIT", {"path": "/api", "burst": 10})
        self.assertTrue(self.execute(r).ok)
        self.assertIn("limit_req zone=leafy_remediation burst=10 nodelay", self.include.read_text())
        undo = record(self.ex, ident, "RESTORE_NGINX", {"parent_id": r.remediation_id}, "fixture-undo")
        self.assertTrue(self.execute(undo).ok)
        maintenance = record(self.ex, ident, "MAINTENANCE_MODE", {}, "fixture-maintenance")
        self.assertTrue(self.execute(maintenance).ok)
        self.assertIn("location / { return 503; }", self.include.read_text())

    def test_incident_creation_deduplicates_without_copying_analysis_or_secret(self):
        ident = identity("incident-log", "host", "fixture-incidents")
        self.target(ident, github={"repository": "fixture-org/fixture-repo", "token_env": "FIXTURE_GITHUB_TOKEN"})
        issues, calls = [], []
        class Client:
            def request(self, method, url, headers=None, json=None):
                calls.append((method, url))
                if method == "POST":
                    body = {"number": 12, **json}; issues.append(body)
                elif "/search/issues?" in url:
                    body = {"incomplete_results": False, "total_count": len(issues), "items": list(issues)}
                else: body = issues[0]
                return SimpleNamespace(raise_for_status=lambda: None, json=lambda: body)
        self.ex.http_client = Client()
        with patch.dict(os.environ, {"FIXTURE_GITHUB_TOKEN": "synthetic-private-token"}):
            first = record(self.ex, ident, "RECORD_INCIDENT", {"incident_key": "a"*64})
            first.incident_key = "a"*64
            self.assertTrue(self.execute(first).ok)
            second = record(self.ex, ident, "RECORD_INCIDENT", {"incident_key": "a"*64}, "fixture-duplicate")
            second.incident_key = "a"*64
            self.assertTrue(self.execute(second).ok)
            self.assertEqual(sum(m == "POST" for m, _ in calls), 1)
            self.assertNotIn("synthetic-private-token", json.dumps(first.target_bindings))
        self.assertIn("leafy-incident:", issues[0]["body"])

    def test_nginx_invalid_candidate_restores_disk_before_any_reload(self):
        ident = self.nginx()
        r = record(self.ex, ident, "BLOCK_PATH", {"path": "/files"})
        real = self.container.exec_run
        def invalid_candidate(argv, **kwargs):
            if "-t" in argv and self.include.read_text() != MARKER:
                return SimpleNamespace(exit_code=1, output=b"synthetic rejection")
            return real(argv, **kwargs)
        self.container.exec_run = invalid_candidate
        self.calls.clear()
        self.assertEqual(self.execute(r).status, "UNKNOWN")
        self.assertEqual(self.include.read_text(), MARKER)
        self.assertFalse(any("reload" in c for c in self.calls))

    def test_replaced_nginx_container_never_reloads(self):
        ident = self.nginx()
        r = record(self.ex, ident, "BLOCK_PATH", {"path": "/files"})
        self.container.attrs["Id"] = "c"*64
        self.calls.clear()
        self.assertEqual(self.execute(r).status, "BLOCKED")
        self.assertFalse(any("reload" in c for c in self.calls))

    def test_changed_minio_transport_requires_new_approval(self):
        ident = self.minio()
        r = record(self.ex, ident, "DISABLE_KEY", {"resource": "uploader"})
        p = self.root / "mc-private/config.json"
        p.write_text(json.dumps({"aliases": {"fixture": {"url": "https://other-minio.invalid"}}}))
        result = self.execute(r)
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(self.keystate, "on")

if __name__ == "__main__": unittest.main()
