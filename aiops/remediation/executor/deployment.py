"""Approved Leafy backend/frontend deployment through the Docker SDK.

Only an operator-authored, digest-pinned deployment is accepted. Plans contain
secret file references and hashes, never environment values or raw Docker Config.
The Controller persists the plan and claims execution before calling this adapter.
After the first mutation any uncertain/partial result requires manual reconciliation;
the stopped original container and its volumes are retained, never auto-deleted.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import threading
import time
from typing import Literal

from pydantic import Field, field_validator, model_validator
import yaml

from agent.contract import ObservationIdentity, StrictModel
from executor.base import Executor, ExecutionResult, blocked, succeeded
from executor.identity import normalized_identity
from executor.local_docker import parse_networks, parse_resources, parse_state
import store as store_mod

IMAGE = r"^sha256:[a-f0-9]{64}$"
FULL_ID = r"^[a-f0-9]{64}$"
REPOSITORIES = {"backend": "gicks/ai-ops-leafy-backend", "frontend": "gicks/ai-ops-leafy-frontend"}


class DeploymentError(ValueError):
    pass


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    allow_nan=False).encode()).hexdigest()


def valid_plan_digest(plan):
    """Validate the portable sanitized plan before it enters an Agent ledger."""
    keys = {"executor", "identity", "target", "action_type", "parameters", "operator_config",
            "pre_snapshot", "chosen_spec", "backup_evidence", "plan_digest"}
    try:
        if set(plan) != keys or plan["executor"] != "deployment":
            return False
        snapshot = plan["pre_snapshot"]
        if set(snapshot) != {"container_id", "container_name", "image_id", "labels", "config_sha256",
                             "state", "networks", "resources", "mounts", "ports", "restart_policy"}:
            return False
        state = snapshot["state"]
        if (set(state) != {"status", "running", "paused", "started_at", "pid"}
                or state["status"] not in (None, "created", "restarting", "running", "removing", "paused", "exited", "dead")
                or type(state["running"]) is not bool or type(state["paused"]) is not bool
                or state["pid"] is not None and type(state["pid"]) is not int
                or state["started_at"] is not None and not isinstance(state["started_at"], str)):
            return False
        stable = {k: v for k, v in plan.items() if k != "plan_digest"}
        stable["pre_snapshot"] = {k: v for k, v in snapshot.items() if k != "state"}
        return digest(stable) == plan["plan_digest"]
    except (KeyError, TypeError, ValueError):
        return False


def deadline(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("timezone required")
        return parsed.timestamp()
    except (ValueError, TypeError):
        raise DeploymentError("valid_absolute_approval_deadline_required") from None


class Healthcheck(StrictModel):
    test: list[str] = Field(min_length=2)
    interval_ns: int = Field(default=5_000_000_000, ge=1_000_000)
    timeout_ns: int = Field(default=3_000_000_000, ge=1_000_000)
    retries: int = Field(default=3, ge=1, le=30)
    start_period_ns: int = Field(default=0, ge=0)

    @field_validator("test")
    @classmethod
    def direct_health_command(cls, value):
        if value[0] != "CMD" or any(not isinstance(v, str) or not v for v in value):
            raise ValueError("explicit CMD healthcheck required")
        return value

    @field_validator("start_period_ns")
    @classmethod
    def valid_start_period(cls, value):
        if 0 < value < 1_000_000:
            raise ValueError("start period must be zero or at least 1ms")
        return value

    def docker(self):
        return {"Test": self.test, "Interval": self.interval_ns, "Timeout": self.timeout_ns,
                "Retries": self.retries, "StartPeriod": self.start_period_ns}


class Network(StrictModel):
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    network_id: str = Field(pattern=FULL_ID)
    ipv4_address: str
    aliases: list[str] = Field(min_length=1)

    @field_validator("ipv4_address")
    @classmethod
    def ipv4(cls, value):
        ipaddress.IPv4Address(value)
        return value


class Port(StrictModel):
    host_ip: str
    host_port: int = Field(ge=1, le=65535)

    @field_validator("host_ip")
    @classmethod
    def scoped_ip(cls, value):
        address = ipaddress.ip_address(value)
        if address.is_unspecified:
            raise ValueError("explicit loopback or private interface required")
        return value


class Mount(StrictModel):
    type: Literal["bind", "volume"]
    source: str = Field(min_length=1)
    target: str = Field(pattern=r"^/.+")
    read_only: bool

    @model_validator(mode="after")
    def no_host_control(self):
        text = (self.source + " " + self.target).lower()
        if any(word in text for word in ("docker.sock", "docker_engine", "/proc", "/sys", "/dev")):
            raise ValueError("host control mounts forbidden")
        if self.type == "bind" and not os.path.isabs(self.source):
            raise ValueError("absolute bind source required")
        if self.target in ("/", "/etc", "/run", "/var", "/var/run"):
            raise ValueError("broad system mounts forbidden")
        return self


class RestartPolicy(StrictModel):
    name: Literal["no", "always", "unless-stopped", "on-failure"]
    maximum_retry_count: int = Field(default=0, ge=0, le=100)


class Logging(StrictModel):
    driver: Literal["json-file", "local", "fluentd", "none"] = "json-file"
    options: dict[str, str] = Field(default_factory=dict)

    @field_validator("options")
    @classmethod
    def known_options(cls, value):
        if set(value) - {"fluentd-address", "fluentd-async", "tag", "labels", "max-size", "max-file"}:
            raise ValueError("unsupported logging options")
        return value


class DesiredSpec(StrictModel):
    image_id: str = Field(pattern=IMAGE)
    command: list[str] | None
    entrypoint: list[str] | None
    environment_file: str | None = None
    environment_sha256: str | None = Field(default=None, pattern=FULL_ID)
    healthcheck: Healthcheck
    networks: list[Network] = Field(min_length=1, max_length=4)
    ports: dict[str, list[Port]] = Field(default_factory=dict)
    mounts: list[Mount] = Field(default_factory=list)
    restart_policy: RestartPolicy
    logging: Logging = Field(default_factory=Logging)
    memory_bytes: int = Field(default=0, ge=0)
    memory_swap_bytes: int = Field(default=0, ge=0)
    cpu_quota: int = Field(default=0, ge=0)
    cpu_period: int = Field(default=100000, ge=1000)
    user: str = ""
    working_dir: str = ""
    read_only_rootfs: bool = False

    @model_validator(mode="after")
    def complete_spec(self):
        if bool(self.environment_file) != bool(self.environment_sha256):
            raise ValueError("environment file and exact sha256 required together")
        if self.environment_file and not os.path.isabs(self.environment_file):
            raise ValueError("absolute secret environment file required")
        if any(not re.fullmatch(r"[1-9][0-9]{0,4}/(?:tcp|udp)", key) or int(key.split('/')[0]) > 65535
               or not bindings for key, bindings in self.ports.items()):
            raise ValueError("explicit container port and host bindings required")
        if len({n.name for n in self.networks}) != len(self.networks):
            raise ValueError("duplicate network")
        if len({m.target for m in self.mounts}) != len(self.mounts):
            raise ValueError("duplicate mount target")
        return self


class Rollback(StrictModel):
    version: str = Field(min_length=1, max_length=128)
    spec: DesiredSpec
    schema_compatible: bool = False
    backup_evidence_file: str | None = None
    backup_database_id: str | None = None


class DeploymentTarget(StrictModel):
    identity: ObservationIdentity
    container_id: str = Field(pattern=FULL_ID)
    current_image_id: str = Field(pattern=IMAGE)
    image_repository: str
    labels: dict[str, str]
    actions: list[Literal["RECREATE", "ROLLBACK"]] = Field(min_length=1)
    desired: DesiredSpec
    rollback: Rollback | None = None
    stop_timeout_seconds: int = Field(default=10, ge=1, le=60)
    health_timeout_seconds: int = Field(default=90, ge=1, le=300)

    @model_validator(mode="after")
    def actual_leafy_service(self):
        identity = normalized_identity(self.identity.model_dump())
        service = identity["service"]
        if (service not in REPOSITORIES or identity["target"] != "leafy-" + service
                or self.image_repository != REPOSITORIES[service]
                or self.labels.get("io.leafy.remediation") != "workload"
                or not self.labels.get("com.docker.compose.project")
                or self.labels.get("com.docker.compose.service") != service):
            raise ValueError("only exact Leafy backend/frontend deployment allowed")
        if self.desired.image_id != self.current_image_id:
            raise ValueError("RECREATE must use same immutable image")
        if "ROLLBACK" in self.actions and self.rollback is None:
            raise ValueError("known-good rollback version required")
        return self


class DeploymentConfig(StrictModel):
    version: Literal[1]
    targets: dict[str, DeploymentTarget]


class DeploymentExecutor(Executor):
    name = "deployment"
    changes_system = True

    def __init__(self, client=None, config_path=None, clock=time.time, sleep=time.sleep):
        self._client = client
        self.config_path = config_path
        self.clock, self.sleep = clock, sleep
        self._attempts, self._leases, self._lock = set(), {}, threading.Lock()

    @property
    def client(self):
        if self._client is None:
            import docker
            # Co-located fixed Unix socket only; never inherit DOCKER_HOST.
            self._client = docker.DockerClient(base_url="unix:///var/run/docker.sock", timeout=15)
        return self._client

    def _config(self):
        path = self.config_path or os.getenv("REMEDIATION_DEPLOYMENT_CONFIG_PATH")
        if not path:
            raise DeploymentError("deployment_config_not_configured")
        try:
            return DeploymentConfig.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
        except Exception:
            raise DeploymentError("invalid_deployment_config") from None

    def _rule(self, identity, targets, action_type):
        identity = normalized_identity(identity)
        if list(targets) != [identity["target"]] or action_type not in ("RECREATE", "ROLLBACK"):
            raise DeploymentError("one_exact_deployment_target_required")
        rule = self._config().targets.get(identity["target"])
        if rule is None or rule.identity.model_dump() != identity or action_type not in rule.actions:
            raise DeploymentError("deployment_target_not_allowed")
        return rule

    def _old(self, rule):
        container = self.client.containers.get(rule.container_id)
        container.reload()
        doc = container.attrs
        labels, host = (doc.get("Config") or {}).get("Labels") or {}, doc.get("HostConfig") or {}
        if (doc.get("Id") != rule.container_id or doc.get("Image") != rule.current_image_id
                or (doc.get("Name") or "").lstrip("/") != rule.identity.target
                or any(labels.get(k) != v for k, v in rule.labels.items())
                or host.get("Privileged") or host.get("PidMode") == "host"
                or host.get("NetworkMode") == "host" or host.get("AutoRemove")
                or any("docker.sock" in str(m) or "docker_engine" in str(m) for m in doc.get("Mounts", []))):
            raise DeploymentError("current_deployment_identity_changed")
        return container, doc

    @staticmethod
    def _snapshot(doc, labels):
        return {"container_id": doc["Id"], "container_name": doc["Name"].lstrip('/'),
                "image_id": doc["Image"], "labels": {k: (doc.get("Config") or {}).get("Labels", {}).get(k) for k in labels},
                "config_sha256": digest(doc.get("Config") or {}),
                "state": parse_state(doc), "networks": parse_networks(doc),
                "resources": parse_resources(doc), "mounts": DeploymentExecutor._mounts(doc),
                "ports": (doc.get("HostConfig") or {}).get("PortBindings") or {},
                "restart_policy": (doc.get("HostConfig") or {}).get("RestartPolicy") or {}}

    @staticmethod
    def _mounts(doc):
        return sorted([{"type": m.get("Type"), "source": m.get("Name") if m.get("Type") == "volume" else m.get("Source"),
                        "target": m.get("Destination"), "read_only": not m.get("RW", True)}
                       for m in doc.get("Mounts", [])], key=lambda m: m["target"] or "")

    @staticmethod
    def _environment(spec):
        if not spec.environment_file:
            return {}
        try:
            body = Path(spec.environment_file).read_bytes()
            values = json.loads(body)
            if (hashlib.sha256(body).hexdigest() != spec.environment_sha256 or not isinstance(values, dict)
                    or any(not isinstance(k, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k)
                           or not isinstance(v, str) for k, v in values.items())):
                raise ValueError()
            if values.get("SPRING_JPA_HIBERNATE_DDL_AUTO", "update").lower() in ("create", "create-drop", "drop"):
                raise ValueError()
            return values
        except Exception:
            raise DeploymentError("deployment_environment_unavailable_or_changed") from None

    def _image(self, rule, spec):
        image = self.client.images.get(spec.image_id)  # Existing local image only; no pull/build.
        doc = image.attrs
        references = list(doc.get("RepoTags") or []) + list(doc.get("RepoDigests") or [])
        if doc.get("Id") != spec.image_id or not any(
            ref.startswith(rule.image_repository + ":") or ref.startswith(rule.image_repository + "@") for ref in references
        ):
            raise DeploymentError("approved_local_image_repository_mismatch")
        # Explicit mounts prevent image-declared volumes from silently creating
        # new anonymous volumes or attaching state that wasn't in the plan.
        if set((doc.get("Config") or {}).get("Volumes") or {}) - {m.target for m in spec.mounts}:
            raise DeploymentError("image_requires_unplanned_volumes")
        return doc

    def _backup(self, rollback):
        if not rollback.schema_compatible or not rollback.backup_evidence_file or not rollback.backup_database_id:
            raise DeploymentError("backend_rollback_requires_schema_compatibility_and_verified_backup")
        try:
            manifest = json.loads(Path(rollback.backup_evidence_file).read_text(encoding="utf-8"))
            artifact = Path(manifest["artifact_path"])
            if artifact.resolve().is_relative_to(Path(__file__).resolve().parents[3]):
                raise ValueError("backup must remain outside the repository")
            with artifact.open("rb") as fh:
                magic = fh.read(5)
                fh.seek(0)
                actual_hash = hashlib.file_digest(fh, "sha256").hexdigest()
            age = self.clock() - deadline(manifest["verified_at"])
            if (manifest.get("verified") is not True or manifest.get("restore_list_verified") is not True
                    or manifest.get("format") != "postgres-custom" or not artifact.is_absolute()
                    or manifest.get("database_id") != rollback.backup_database_id
                    or magic != b"PGDMP" or actual_hash != manifest["sha256"]
                    or not 0 <= age <= 86400):
                raise ValueError()
            return {"manifest_path": rollback.backup_evidence_file, "artifact_path": str(artifact),
                    "sha256": manifest["sha256"], "verified_at": manifest["verified_at"],
                    "database_id": manifest["database_id"]}
        except Exception:
            raise DeploymentError("backend_rollback_backup_evidence_invalid") from None

    def plan_record(self, identity, targets, action_type, parameters):
        parameters = dict(parameters or {})
        rule = self._rule(identity, targets, action_type)
        if set(parameters) - ({"version"} if action_type == "ROLLBACK" else set()):
            raise DeploymentError("deployment_parameters_not_allowed")
        spec = rule.desired
        backup = None
        if action_type == "ROLLBACK":
            if parameters.get("version", rule.rollback.version) != rule.rollback.version:
                raise DeploymentError("rollback_version_not_allowlisted")
            spec = rule.rollback.spec
            if rule.identity.service == "backend":
                backup = self._backup(rule.rollback)
        environment = self._environment(spec)
        if rule.identity.service == "backend":
            # The current dev image can default to create-drop. Never inherit
            # that default merely because the credential file omitted a field.
            required = ("SPRING_DATASOURCE_URL", "DB_USERNAME_DEV", "DB_PASSWORD_DEV",
                        "JWT_SECRET_KEY_DEV", "STORAGE_ACCESS_KEY", "STORAGE_SECRET_KEY")
            if (not spec.environment_file or any(not environment.get(k) for k in required)
                    or environment.get("SPRING_JPA_HIBERNATE_DDL_AUTO", "").lower() not in ("none", "validate", "update")):
                raise DeploymentError("explicit_backend_credentials_and_nondestructive_schema_mode_required")
        self._image(rule, spec)
        _, old = self._old(rule)
        networks = parse_networks(old)
        if set(networks) != {n.name for n in spec.networks}:
            raise DeploymentError("unplanned_current_network_attachment")
        for network in spec.networks:
            actual = self.client.networks.get(network.network_id)
            if actual.id != network.network_id or actual.name != network.name or networks[network.name]["network_id"] != network.network_id:
                raise DeploymentError("deployment_network_identity_changed")
        snapshot = self._snapshot(old, rule.labels)
        binding = {"executor": self.name, "identity": rule.identity.model_dump(), "target": rule.identity.target,
                   "action_type": action_type, "parameters": parameters, "operator_config": rule.model_dump(),
                   "pre_snapshot": snapshot, "chosen_spec": spec.model_dump(), "backup_evidence": backup}
        stable = {**binding, "pre_snapshot": {k: v for k, v in snapshot.items() if k != "state"}}
        binding["plan_digest"] = digest(stable)
        return {rule.identity.target: binding}

    def validate_record(self, record):
        try:
            fresh = self.plan_record(record.identity, record.targets, record.action_type, record.action_parameters)
            for target in record.targets:
                binding = record.target_bindings[target]
                if (not valid_plan_digest(binding)
                        or fresh[target]["plan_digest"] != binding["plan_digest"]):
                    return "deployment_plan_changed_reapproval_required"
        except Exception:
            return "deployment_plan_validation_failed"
        return None

    def _check(self, record):
        now = self.clock()
        if (record.state != "EXECUTING" or record.requires_approval is not True
                or record.executor_name != self.name or not record.approved_by
                or not store_mod.approval_valid(record, now=now)
                or not (deadline(record.approval_requested_at) <= deadline(record.approved_at)
                        <= deadline(record.action_started_at) <= now < deadline(record.approval_expires_at))
                or not re.fullmatch(FULL_ID, record.incident_key or "")
                or record.action_hash != store_mod.action_hash(record.action_type, record.targets,
                    record.ttl_seconds, record.recovery_mode, record.action_parameters)):
            raise DeploymentError("stored_deployment_approval_or_claim_invalid")

    def _create(self, rule, spec, environment, record):
        from docker.types import LogConfig, Mount as DockerMount
        api = self.client.api
        port_bindings = {key: [(p.host_ip, p.host_port) for p in bindings] for key, bindings in spec.ports.items()}
        host = api.create_host_config(
            port_bindings=port_bindings,
            mounts=[DockerMount(target=m.target, source=m.source, type=m.type, read_only=m.read_only) for m in spec.mounts],
            restart_policy={"Name": spec.restart_policy.name, "MaximumRetryCount": spec.restart_policy.maximum_retry_count},
            log_config=LogConfig(type=spec.logging.driver, config=spec.logging.options),
            mem_limit=spec.memory_bytes, memswap_limit=spec.memory_swap_bytes,
            cpu_quota=spec.cpu_quota, cpu_period=spec.cpu_period,
            read_only=spec.read_only_rootfs, privileged=False, auto_remove=False,
        )
        primary = spec.networks[0]
        # Endpoint keys may use immutable network IDs in the Engine API. This
        # avoids resolving a same-named replacement network during create.
        actual = self.client.networks.get(primary.network_id)
        if actual.id != primary.network_id or actual.name != primary.name:
            raise DeploymentError("primary_network_identity_changed")
        networking = api.create_networking_config({primary.network_id: api.create_endpoint_config(
            ipv4_address=primary.ipv4_address, aliases=primary.aliases)})
        self._check(record)
        created = api.create_container(
            image=spec.image_id, command=spec.command, entrypoint=spec.entrypoint,
            name=rule.identity.target, detach=True, environment=environment,
            labels={**rule.labels, "io.leafy.remediation.record": record.remediation_id},
            ports=[(int(key.split('/')[0]), key.split('/')[1]) for key in spec.ports],
            host_config=host, networking_config=networking,
            healthcheck=spec.healthcheck.docker(), user=spec.user, working_dir=spec.working_dir,
            use_config_proxy=False,
        )
        container_id = created.get("Id", "")
        if not re.fullmatch(FULL_ID, container_id):
            raise DeploymentError("created_container_identity_unconfirmed")
        return container_id

    def _new(self, container_id, rule, spec, remediation_id):
        obj = self.client.containers.get(container_id)
        obj.reload()
        doc = obj.attrs
        if (doc.get("Id") != container_id or doc.get("Image") != spec.image_id
                or doc.get("Name", "").lstrip('/') != rule.identity.target
                or any((doc.get("Config") or {}).get("Labels", {}).get(k) != v for k, v in rule.labels.items())
                or (doc.get("Config") or {}).get("Labels", {}).get("io.leafy.remediation.record") != remediation_id):
            raise DeploymentError("new_deployment_identity_unconfirmed")
        return obj, doc

    def _verify(self, container_id, rule, spec, remediation_id):
        _, doc = self._new(container_id, rule, spec, remediation_id)
        networks = parse_networks(doc)
        if set(networks) != {n.name for n in spec.networks}:
            raise DeploymentError("new_deployment_networks_unconfirmed")
        for expected in spec.networks:
            actual = networks[expected.name]
            if (actual.get("network_id") != expected.network_id
                    or actual.get("ip_address") != expected.ipv4_address
                    or not set(expected.aliases).issubset(set(actual.get("aliases") or []))):
                raise DeploymentError("new_deployment_endpoint_unconfirmed")
        if self._mounts(doc) != sorted([m.model_dump() for m in spec.mounts], key=lambda m: m["target"]):
            raise DeploymentError("new_deployment_mounts_unconfirmed")
        expected_ports = {key: [{"HostIp": p.host_ip, "HostPort": str(p.host_port)} for p in ports]
                          for key, ports in spec.ports.items()}
        host = doc.get("HostConfig") or {}
        if (host.get("PortBindings") or {}) != expected_ports:
            raise DeploymentError("new_deployment_ports_unconfirmed")
        image_config = self._image(rule, spec).get("Config") or {}
        config = doc.get("Config") or {}
        environment = {}
        for item in image_config.get("Env") or []:
            key, _, value = item.partition("=")
            environment[key] = value
        environment.update(self._environment(spec))
        actual_env = {}
        for item in config.get("Env") or []:
            key, _, value = item.partition("=")
            actual_env[key] = value
        expected_health = spec.healthcheck.docker()
        if (config.get("Cmd") != (spec.command if spec.command is not None else image_config.get("Cmd"))
                or config.get("Entrypoint") != (spec.entrypoint if spec.entrypoint is not None else image_config.get("Entrypoint"))
                or actual_env != environment
                or any((config.get("Healthcheck") or {}).get(k) != v for k, v in expected_health.items())
                or config.get("User", "") != (spec.user or image_config.get("User", ""))
                or config.get("WorkingDir", "") != (spec.working_dir or image_config.get("WorkingDir", ""))
                or host.get("RestartPolicy", {}).get("Name") != spec.restart_policy.name
                or host.get("RestartPolicy", {}).get("MaximumRetryCount", 0) != spec.restart_policy.maximum_retry_count
                or host.get("LogConfig", {}).get("Type") != spec.logging.driver
                or (host.get("LogConfig", {}).get("Config") or {}) != spec.logging.options
                or host.get("Memory", 0) != spec.memory_bytes
                or host.get("MemorySwap", 0) != spec.memory_swap_bytes
                or host.get("CpuQuota", 0) != spec.cpu_quota
                or host.get("CpuPeriod", 0) != spec.cpu_period
                or bool(host.get("ReadonlyRootfs")) != spec.read_only_rootfs
                or host.get("Privileged") or host.get("AutoRemove")):
            raise DeploymentError("new_deployment_configuration_unconfirmed")
        health = (doc.get("State") or {}).get("Health") or {}
        if not (doc.get("State") or {}).get("Running") or health.get("Status") != "healthy":
            return None
        return self._snapshot(doc, rule.labels)

    def execute_record(self, record, target, approved_by=None):
        action, mutated, new_id = record.action_type, False, None
        old_name = None
        try:
            key = (record.remediation_id, target)
            with self._lock:
                if key in self._attempts:
                    return ExecutionResult(action, target, "UNKNOWN", detail="deployment_already_attempted_query_record")
            binding = record.target_bindings[target]
            evidence = ((record.evidence or {}).get("targets") or {}).get(target, {})
            self._check(record)
            if (target not in record.targets or approved_by is not None and approved_by != record.approved_by
                    or binding.get("executor") != self.name
                    or evidence != binding):
                raise DeploymentError("durable_claim_approved_plan_and_evidence_required")
            reason = self.validate_record(record)
            if reason:
                raise DeploymentError(reason)
            rule = self._rule(record.identity, record.targets, action)
            spec = DesiredSpec.model_validate(binding["chosen_spec"])
            environment = self._environment(spec)
            old, _ = self._old(rule)
            with self._lock:
                if key in self._attempts:
                    return ExecutionResult(action, target, "UNKNOWN", detail="deployment_already_attempted_query_record")
                if target in self._leases:
                    raise DeploymentError("target_has_unresolved_deployment")
                self._attempts.add(key)
                self._leases[target] = record.remediation_id
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", record.remediation_id):
                raise DeploymentError("invalid_deployment_record_id")
            retained_name = target + "--retained-" + record.remediation_id[:24]
            self._check(record)
            mutated = True
            old.update(restart_policy={"Name": "no", "MaximumRetryCount": 0})
            self._check(record)
            old.stop(timeout=rule.stop_timeout_seconds)
            old.reload()
            if (old.attrs.get("Id") != rule.container_id
                    or (old.attrs.get("State") or {}).get("Running") is not False
                    or (old.attrs.get("State") or {}).get("Restarting")
                    or (old.attrs.get("HostConfig") or {}).get("RestartPolicy", {}).get("Name") != "no"):
                raise DeploymentError("old_container_stop_or_restart_policy_unconfirmed")
            self._check(record)
            old.rename(retained_name)
            old.reload()
            if (old.attrs.get("Id") != rule.container_id
                    or old.attrs.get("Name", "").lstrip('/') != retained_name
                    or (old.attrs.get("State") or {}).get("Running") is not False):
                raise DeploymentError("retained_container_identity_unconfirmed")
            old_name = retained_name
            # Release static addresses before the replacement joins. All original
            # endpoints remain in the persisted plan for deliberate manual restore.
            for network in binding["pre_snapshot"]["networks"].values():
                actual = self.client.networks.get(network["network_id"])
                self._check(record)
                actual.disconnect(rule.container_id)
            old.reload()
            if parse_networks(old.attrs):
                raise DeploymentError("old_container_endpoint_release_unconfirmed")
            self._check(record)
            new_id = self._create(rule, spec, environment, record)
            for network in spec.networks[1:]:
                self._check(record)
                actual = self.client.networks.get(network.network_id)
                if actual.id != network.network_id or actual.name != network.name:
                    raise DeploymentError("deployment_network_changed_during_execution")
                self._check(record)
                actual.connect(new_id, ipv4_address=network.ipv4_address, aliases=network.aliases)
            new, _ = self._new(new_id, rule, spec, record.remediation_id)
            self._check(record)
            new.start()
            until = self.clock() + rule.health_timeout_seconds
            while self.clock() <= until:
                verified = self._verify(new_id, rule, spec, record.remediation_id)
                if verified:
                    with self._lock:
                        self._leases.pop(target, None)
                    return succeeded(action, target, "deployment_healthy_old_container_retained_rebind_new_id_before_next_action",
                                     before=binding["pre_snapshot"],
                                     after={**verified, "old_container_id": rule.container_id,
                                            "retained_container_name": old_name, "requires_rebinding": True})
                self.sleep(1)
            raise DeploymentError("new_deployment_health_unconfirmed")
        except Exception as exc:
            if mutated:
                return ExecutionResult(action, target, "UNKNOWN",
                    detail="deployment_partial_or_unconfirmed_manual_reconciliation_required",
                    before={"old_container_id": record.target_bindings.get(target, {}).get("pre_snapshot", {}).get("container_id")},
                    after={"new_container_id": new_id, "retained_container_name": old_name,
                           "requires_rebinding": True})
            with self._lock:
                if self._leases.get(target) == record.remediation_id:
                    self._leases.pop(target, None)
            return blocked(action, target, str(exc) if isinstance(exc, DeploymentError) else "deployment_preflight_failed")
