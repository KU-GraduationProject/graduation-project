"""Actual SDK call contracts, immutable deployment plans and partial-result safety."""
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from docker.types import ContainerConfig

from executor.deployment import DeploymentError, DeploymentExecutor
import store

OLD, NEW = "a" * 64, "c" * 64
CURRENT, ROLLBACK = "sha256:" + "b" * 64, "sha256:" + "d" * 64
NETWORK, MANAGEMENT = "e" * 64, "f" * 64


class Container:
    def __init__(self, fake, doc):
        self.fake, self.attrs = fake, doc

    @property
    def id(self):
        return self.attrs["Id"]

    def reload(self):
        pass

    # 증거 보존(CAPTURE)용 읽기 전용 조회. 변경 호출 기록(calls)에는 넣지 않는다.
    def logs(self, **kw):
        return b"fixture deployment log\n"

    def top(self):
        return {"Titles": ["PID", "CMD"], "Processes": [["1", "app"]]}

    def update(self, **kw):
        self.fake.calls.append(("update", self.id))
        self.attrs["HostConfig"]["RestartPolicy"] = kw["restart_policy"]

    def stop(self, **kw):
        self.fake.calls.append(("stop", self.id))
        self.attrs["State"]["Running"] = False
        if self.fake.stop_hook:
            self.fake.stop_hook()

    def rename(self, name):
        self.fake.calls.append(("rename", self.id, name))
        self.attrs["Name"] = "/" + name

    def start(self):
        self.fake.calls.append(("start", self.id))
        self.attrs["State"] = {"Running": True, "Health": {"Status": self.fake.health}}


class FakeNetwork:
    def __init__(self, fake, name, network_id):
        self.fake, self.name, self.id = fake, name, network_id

    def endpoint(self, ip, aliases):
        return {"NetworkID": self.id, "IPAddress": ip, "IPAMConfig": {"IPv4Address": ip},
                "Aliases": aliases}

    def disconnect(self, container_id):
        self.fake.calls.append(("disconnect", self.id, container_id))
        self.fake.docs[container_id]["NetworkSettings"]["Networks"].pop(self.name, None)

    def connect(self, container_id, ipv4_address, aliases):
        self.fake.calls.append(("connect", self.id, container_id))
        self.fake.docs[container_id]["NetworkSettings"]["Networks"][self.name] = self.endpoint(ipv4_address, aliases)


class FakeDocker:
    def __init__(self, service):
        self.service, self.calls = service, []
        self.health, self.stop_hook, self.create_timeout = "healthy", None, False
        self.created = None
        self.images = SimpleNamespace(get=self.image)
        self.containers = SimpleNamespace(get=self.container)
        self.networks = SimpleNamespace(get=self.network)
        self.api = SimpleNamespace(create_host_config=self.host_config,
                                   create_endpoint_config=lambda **kw: kw,
                                   create_networking_config=lambda kw: kw,
                                   create_container=self.create)
        self.network_map = {NETWORK: FakeNetwork(self, "leafy-net", NETWORK),
                            MANAGEMENT: FakeNetwork(self, "mgmt-net", MANAGEMENT)}
        labels = {"io.leafy.remediation": "workload", "com.docker.compose.project": "leafy-test",
                  "com.docker.compose.service": service}
        self.docs = {OLD: {"Id": OLD, "Image": CURRENT, "Name": "/leafy-" + service,
            "Config": {"Labels": labels, "Cmd": ["broken"], "Entrypoint": None,
                       "Env": ["PASSWORD=original-never-persist"]},
            "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}}, "Mounts": [],
            "State": {"Status": "running", "Running": True},
            "NetworkSettings": {"Networks": {
                "leafy-net": self.network_map[NETWORK].endpoint("10.210.0.7", ["leafy-" + service, service]),
                "mgmt-net": self.network_map[MANAGEMENT].endpoint("10.211.0.7", [service])}}}}

    def image(self, image_id):
        if image_id not in (CURRENT, ROLLBACK):
            raise RuntimeError("not found")
        return SimpleNamespace(attrs={"Id": image_id, "RepoTags": ["gicks/ai-ops-leafy-" + self.service + ":known"],
            "Config": {"Cmd": ["app"], "Entrypoint": None, "Env": ["PATH=/bin"], "Volumes": {}}})

    def container(self, identity):
        if identity in self.docs:
            return Container(self, self.docs[identity])
        for doc in self.docs.values():
            if doc["Name"].lstrip('/') == identity:
                return Container(self, doc)
        raise RuntimeError("not found")

    def network(self, identity):
        for network in self.network_map.values():
            if identity in (network.id, network.name):
                return network
        raise RuntimeError("network not found")

    @staticmethod
    def host_config(**kw):
        return {"PortBindings": {key: [{"HostIp": ip, "HostPort": str(port)} for ip, port in values]
                                  for key, values in kw["port_bindings"].items()},
                "MountSpecs": kw["mounts"], "RestartPolicy": kw["restart_policy"],
                "Memory": kw["mem_limit"], "MemorySwap": kw["memswap_limit"],
                "CpuQuota": kw["cpu_quota"], "CpuPeriod": kw["cpu_period"],
                "ReadonlyRootfs": kw["read_only"], "Privileged": kw["privileged"],
                "AutoRemove": kw["auto_remove"], "LogConfig": kw["log_config"]}

    def create(self, **kw):
        self.calls.append(("create", kw["image"]))
        self.created = kw
        image_config = self.image(kw["image"]).attrs["Config"]
        env = {"PATH": "/bin", **kw["environment"]}
        config = {"Cmd": kw["command"] if kw["command"] is not None else image_config["Cmd"],
                  "Entrypoint": kw["entrypoint"], "Labels": kw["labels"],
                  "Healthcheck": kw["healthcheck"], "Env": [k + "=" + v for k, v in env.items()],
                  "User": kw["user"], "WorkingDir": kw["working_dir"]}
        mounts = [{"Type": m["Type"], "Source": m["Source"], "Name": m["Source"],
                   "Destination": m["Target"], "RW": not m["ReadOnly"]} for m in kw["host_config"]["MountSpecs"]]
        networks = {}
        for identity, endpoint in kw["networking_config"].items():
            network = self.network(identity)
            networks[network.name] = network.endpoint(endpoint["ipv4_address"], endpoint["aliases"])
        self.docs[NEW] = {"Id": NEW, "Image": kw["image"], "Name": "/" + kw["name"],
                          "Config": config, "HostConfig": kw["host_config"], "Mounts": mounts,
                          "NetworkSettings": {"Networks": networks}, "State": {"Running": False}}
        if self.create_timeout:
            raise TimeoutError("reply lost after creating container")
        return {"Id": NEW}


class DeploymentExecutorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now = 2000000000
        self.path = os.path.join(self.tmp.name, "deploy.json")
        self.secret_path = os.path.join(self.tmp.name, "environment.json")
        raw = json.dumps({"SPRING_JPA_HIBERNATE_DDL_AUTO": "update", "DB_PASSWORD_DEV": "secret-never-persist",
                          "SPRING_DATASOURCE_URL": "jdbc:postgresql://verified-db:5432/leafy",
                          "DB_USERNAME_DEV": "test", "JWT_SECRET_KEY_DEV": "fake-only",
                          "STORAGE_ACCESS_KEY": "test", "STORAGE_SECRET_KEY": "test-only"}).encode()
        Path(self.secret_path).write_bytes(raw)
        self.environment_hash = hashlib.sha256(raw).hexdigest()
        self.configure("backend")

    def configure(self, service):
        self.fake = FakeDocker(service)
        target = "leafy-" + service
        self.identity = {"site": "gc", "source": "gc-host", "runtime": "container", "service": service, "target": target}
        spec = {"image_id": CURRENT, "command": ["app"], "entrypoint": None,
            "environment_file": self.secret_path, "environment_sha256": self.environment_hash,
            "healthcheck": {"test": ["CMD", "curl", "--fail", "http://localhost/health"]},
            "networks": [{"name": "leafy-net", "network_id": NETWORK, "ipv4_address": "10.210.0.7", "aliases": [target, service]},
                         {"name": "mgmt-net", "network_id": MANAGEMENT, "ipv4_address": "10.211.0.7", "aliases": [service]}],
            "ports": {"80/tcp": [{"host_ip": "127.0.0.1", "host_port": 8080}]},
            "mounts": [{"type": "bind", "source": "/operator/frontend.conf", "target": "/etc/nginx/conf.d/app.conf", "read_only": True}],
            "restart_policy": {"name": "unless-stopped"}, "logging": {"driver": "fluentd", "options": {"tag": service}},
            "memory_bytes": 512000000, "memory_swap_bytes": 512000000}
        self.rule = {"identity": self.identity, "container_id": OLD, "current_image_id": CURRENT,
            "image_repository": "gicks/ai-ops-leafy-" + service,
            "labels": copy.deepcopy(self.fake.docs[OLD]["Config"]["Labels"]),
            "actions": ["RECREATE", "ROLLBACK"], "desired": spec,
            "rollback": {"version": "known-good-v1", "schema_compatible": False,
                         "spec": {**copy.deepcopy(spec), "image_id": ROLLBACK}}, "health_timeout_seconds": 2}
        self.write()
        self.executor = DeploymentExecutor(client=self.fake, config_path=self.path,
                                            clock=lambda: self.now, sleep=self.advance)

    def advance(self, seconds):
        self.now += seconds

    def write(self):
        Path(self.path).write_text(json.dumps({"version": 1, "targets": {self.identity["target"]: self.rule}}), encoding="utf-8")

    def record(self, action="RECREATE", parameters=None):
        parameters = parameters or {}
        plan = self.executor.plan_record(self.identity, [self.identity["target"]], action, parameters)
        return SimpleNamespace(remediation_id="deployment-record", action_type=action,
            identity=copy.deepcopy(self.identity), targets=[self.identity["target"]], action_parameters=parameters,
            target_bindings=plan, evidence={"targets": copy.deepcopy(plan)}, state="EXECUTING", approved_by="UTEST",
            requires_approval=True, executor_name="deployment", ttl_seconds=None, recovery_mode="none",
            incident_key="1" * 64, action_hash=store.action_hash(action, [self.identity["target"]], None, "none", parameters),
            approval_requested_at=datetime.fromtimestamp(self.now - 10, timezone.utc).isoformat(),
            approved_at=datetime.fromtimestamp(self.now - 5, timezone.utc).isoformat(),
            action_started_at=datetime.fromtimestamp(self.now - 1, timezone.utc).isoformat(),
            approval_expires_at=datetime.fromtimestamp(self.now + 300, timezone.utc).isoformat())

    def backup(self):
        dump = Path(self.tmp.name) / "backup.dump"
        dump.write_bytes(b"PGDMP-test-operator-verified-backup")
        manifest = {"verified": True, "format": "postgres-custom", "restore_list_verified": True,
                    "database_id": "verified-gc-leafy-db",
                    "artifact_path": str(dump), "sha256": hashlib.sha256(dump.read_bytes()).hexdigest(),
                    "verified_at": datetime.fromtimestamp(self.now, timezone.utc).isoformat()}
        manifest_path = Path(self.tmp.name) / "backup.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        self.rule["rollback"].update(schema_compatible=True, backup_evidence_file=str(manifest_path),
                                     backup_database_id="verified-gc-leafy-db")
        self.write()
        return dump

    def test_recreate_real_sdk_plan_is_readonly_and_environment_is_never_recorded(self):
        record = self.record()
        self.assertEqual(self.fake.calls, [])
        encoded = json.dumps(record.target_bindings)
        self.assertNotIn("secret-never-persist", encoded)
        self.assertNotIn("original-never-persist", encoded)
        result = self.executor.execute_record(record, self.identity["target"])
        self.assertTrue(result.ok, result.detail)
        self.assertEqual(result.after["container_id"], NEW)
        self.assertTrue(result.after["requires_rebinding"])
        self.assertFalse(self.fake.docs[OLD]["State"]["Running"])
        self.assertIn("--retained-", self.fake.docs[OLD]["Name"])
        self.assertEqual(self.fake.docs[OLD]["HostConfig"]["RestartPolicy"]["Name"], "no")
        self.assertEqual(self.fake.docs[OLD]["NetworkSettings"]["Networks"], {})
        self.assertTrue(self.fake.docs[NEW]["State"]["Running"])
        self.assertNotIn("secret-never-persist", json.dumps(result.as_dict()))
        self.assertFalse(self.fake.created["use_config_proxy"])
        # Exercise Docker SDK's real serializer: slash strings in a low-level
        # ports list would accidentally create 80/tcp/tcp instead of 80/tcp.
        create = self.fake.created
        serialized = ContainerConfig("1.45", create["image"], create["command"], ports=create["ports"],
                                     healthcheck=create["healthcheck"])
        self.assertEqual(serialized["ExposedPorts"], {"80/tcp": {}})
        self.assertEqual(serialized["Healthcheck"]["Test"][0], "CMD")

    def test_backend_rollback_requires_schema_and_verified_fresh_backup(self):
        with self.assertRaises(DeploymentError):
            self.record("ROLLBACK")
        dump = self.backup()
        record = self.record("ROLLBACK", {"version": "known-good-v1"})
        self.assertEqual(self.fake.calls, [])
        result = self.executor.execute_record(record, self.identity["target"])
        self.assertTrue(result.ok, result.detail)
        self.assertEqual(result.after["image_id"], ROLLBACK)
        self.assertTrue(dump.exists())

    def test_backup_of_other_database_or_stale_manifest_does_not_authorize_rollback(self):
        self.backup()
        path = Path(self.rule["rollback"]["backup_evidence_file"])
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["database_id"] = "other-database"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(DeploymentError):
            self.record("ROLLBACK")
        manifest["database_id"] = "verified-gc-leafy-db"
        manifest["verified_at"] = datetime.fromtimestamp(self.now - 86401, timezone.utc).isoformat()
        path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaises(DeploymentError):
            self.record("ROLLBACK")
        self.assertEqual(self.fake.calls, [])

    def test_frontend_rollback_uses_operator_known_good_image(self):
        self.configure("frontend")
        record = self.record("ROLLBACK")
        self.assertTrue(self.executor.execute_record(record, self.identity["target"]).ok)

    def test_changed_backup_or_config_revokes_original_approval_before_mutation(self):
        dump = self.backup()
        record = self.record("ROLLBACK")
        dump.write_bytes(b"PGDMP-replaced-backup")
        self.assertEqual(self.executor.execute_record(record, self.identity["target"]).status, "BLOCKED")
        self.assertEqual(self.fake.calls, [])
        record = self.record()
        self.rule["desired"]["command"] = ["different"]
        self.write()
        self.assertEqual(self.executor.execute_record(record, self.identity["target"]).status, "BLOCKED")
        self.assertEqual(self.fake.calls, [])

    def test_changed_container_image_labels_and_secret_file_never_mutate(self):
        for field, value in (("Id", "9" * 64), ("Image", ROLLBACK)):
            record = self.record()
            original = self.fake.docs[OLD][field]
            self.fake.docs[OLD][field] = value
            self.assertEqual(self.executor.execute_record(record, self.identity["target"]).status, "BLOCKED")
            self.fake.docs[OLD][field] = original
        record = self.record()
        Path(self.secret_path).write_text('{}', encoding="utf-8")
        self.assertEqual(self.executor.execute_record(record, self.identity["target"]).status, "BLOCKED")
        self.assertEqual(self.fake.calls, [])

    def test_no_arbitrary_parameters_or_stateful_target(self):
        for parameters in ({"command": ["sh", "-c", "bad"]}, {"image_id": ROLLBACK}):
            with self.assertRaises(DeploymentError):
                self.record(parameters=parameters)
        with self.assertRaises(DeploymentError):
            self.executor.plan_record({**self.identity, "target": "leafy-minio", "service": "minio"},
                                      ["leafy-minio"], "RECREATE", {})
        self.assertEqual(self.fake.calls, [])

    def test_no_mutation_without_durable_claim_and_matching_evidence(self):
        record = self.record()
        record.state = "APPROVED"
        self.assertEqual(self.executor.execute_record(record, self.identity["target"]).status, "BLOCKED")
        record.state = "EXECUTING"
        record.evidence = {}
        self.assertEqual(self.executor.execute_record(record, self.identity["target"]).status, "BLOCKED")
        self.assertEqual(self.fake.calls, [])

    def test_manual_approval_canonical_action_and_unmodified_plan_are_required(self):
        record = self.record()
        for field, replacement in (("requires_approval", False), ("executor_name", "local_docker"),
                                   ("action_hash", "forged"), ("incident_key", None),
                                   ("approved_at", None), ("approved_by", None)):
            original = getattr(record, field)
            setattr(record, field, replacement)
            self.assertEqual(self.executor.execute_record(record, self.identity["target"]).status, "BLOCKED")
            setattr(record, field, original)
        self.assertEqual(self.executor.execute_record(record, self.identity["target"], "other-user").status, "BLOCKED")
        record.target_bindings[self.identity["target"]]["chosen_spec"]["command"] = ["unapproved"]
        record.evidence["targets"] = copy.deepcopy(record.target_bindings)
        self.assertEqual(self.executor.execute_record(record, self.identity["target"]).status, "BLOCKED")
        self.assertEqual(self.fake.calls, [])

    def test_readonly_preflight_delay_past_expiry_does_not_stop_old_container(self):
        record = self.record()
        original = self.fake.container
        def delayed(identity):
            result = original(identity)
            self.advance(301)
            return result
        self.fake.containers.get = delayed
        self.assertEqual(self.executor.execute_record(record, self.identity["target"]).status, "BLOCKED")
        self.assertEqual(self.fake.calls, [])

    def test_delayed_primary_network_lookup_does_not_create_with_expired_approval(self):
        record = self.record()
        original = self.fake.network
        def delayed(identity):
            result = original(identity)
            if any(call[0] == "rename" for call in self.fake.calls) and not self.fake.docs[OLD]["NetworkSettings"]["Networks"]:
                self.advance(301)
            return result
        self.fake.networks.get = delayed
        result = self.executor.execute_record(record, self.identity["target"])
        self.assertEqual(result.status, "UNKNOWN")
        self.assertNotIn("create", [call[0] for call in self.fake.calls])

    def test_expiry_before_mutation_blocks_and_mid_operation_expiry_is_unknown(self):
        record = self.record()
        record.approval_expires_at = datetime.fromtimestamp(self.now - 1, timezone.utc).isoformat()
        self.assertEqual(self.executor.execute_record(record, self.identity["target"]).status, "BLOCKED")
        self.assertEqual(self.fake.calls, [])
        record.remediation_id = "other-deployment-record"
        record.approval_expires_at = datetime.fromtimestamp(self.now + 1, timezone.utc).isoformat()
        self.fake.stop_hook = lambda: self.advance(2)
        result = self.executor.execute_record(record, self.identity["target"])
        self.assertEqual(result.status, "UNKNOWN")
        self.assertNotIn("create", [c[0] for c in self.fake.calls])
        count = len(self.fake.calls)
        self.assertEqual(self.executor.execute_record(record, self.identity["target"]).status, "UNKNOWN")
        self.assertEqual(len(self.fake.calls), count)

    def test_create_response_loss_preserves_old_and_never_retries_or_deletes(self):
        record = self.record()
        self.fake.create_timeout = True
        result = self.executor.execute_record(record, self.identity["target"])
        self.assertEqual(result.status, "UNKNOWN")
        self.assertIsNone(result.after["new_container_id"])
        self.assertIn(OLD, self.fake.docs)
        self.assertIn(NEW, self.fake.docs)
        count = len(self.fake.calls)
        self.assertEqual(self.executor.execute_record(record, self.identity["target"]).status, "UNKNOWN")
        self.assertEqual(len(self.fake.calls), count)
        self.assertFalse(any(c[0] in ("remove", "prune", "delete") for c in self.fake.calls))

    def test_stop_response_without_stopped_state_never_creates_replacement(self):
        record = self.record()
        self.fake.stop_hook = lambda: self.fake.docs[OLD]["State"].update(Running=True)
        self.assertEqual(self.executor.execute_record(record, self.identity["target"]).status, "UNKNOWN")
        self.assertNotIn("create", [call[0] for call in self.fake.calls])
        self.assertNotIn(NEW, self.fake.docs)

    def test_different_incident_cannot_mutate_target_during_existing_deployment(self):
        self.fake.docs[OLD]["HostConfig"]["RestartPolicy"] = {"Name": "no", "MaximumRetryCount": 0}
        first, second = self.record(), self.record()
        second.remediation_id = "second-incident"
        observed = []
        def simultaneous():
            observed.append(self.executor.execute_record(second, self.identity["target"]))
        self.fake.stop_hook = simultaneous
        self.assertTrue(self.executor.execute_record(first, self.identity["target"]).ok)
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0].status, "BLOCKED")
        self.assertEqual(observed[0].detail, "target_has_unresolved_deployment")
        self.assertEqual(sum(call[0] == "stop" for call in self.fake.calls), 1)

    def test_unhealthy_new_container_retains_both_ids_for_manual_reconciliation(self):
        self.fake.health = "unhealthy"
        record = self.record()
        result = self.executor.execute_record(record, self.identity["target"])
        self.assertEqual(result.status, "UNKNOWN")
        self.assertFalse(result.verified)
        self.assertEqual(result.after["new_container_id"], NEW)
        self.assertEqual(result.before["old_container_id"], OLD)
        self.assertEqual(self.fake.calls[-1], ("start", NEW))

    def test_postcreate_wrong_network_or_healthcheck_is_never_success(self):
        record = self.record()
        original = self.fake.create
        def altered(**kw):
            response = original(**kw)
            self.fake.docs[NEW]["Config"]["Healthcheck"]["Test"] = ["CMD", "true"]
            return response
        self.fake.api.create_container = altered
        self.assertEqual(self.executor.execute_record(record, self.identity["target"]).status, "UNKNOWN")

    def test_backend_recreate_cannot_change_image_or_enable_create_drop(self):
        self.rule["desired"]["image_id"] = ROLLBACK
        self.write()
        with self.assertRaises(DeploymentError):
            self.record()
        self.rule["desired"]["image_id"] = CURRENT
        raw = json.dumps({"SPRING_JPA_HIBERNATE_DDL_AUTO": "create-drop"}).encode()
        Path(self.secret_path).write_bytes(raw)
        self.rule["desired"]["environment_sha256"] = hashlib.sha256(raw).hexdigest()
        self.write()
        with self.assertRaises(DeploymentError):
            self.record()
        self.assertEqual(self.fake.calls, [])
