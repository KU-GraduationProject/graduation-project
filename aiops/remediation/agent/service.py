"""Execution boundary. Auth is checked by API; authorization is checked here too."""
from dataclasses import replace
import hashlib
import logging
import os
import time

from agent.contract import Authorization, Command
from agent.ledger import Conflict
import evidence as evidence_mod
from executor.base import RECOVERY_ACTION, ExecutorError, blocked, skipped, ExecutionResult
from executor.local_docker import LocalDockerExecutor, select_isolation_networks

PROTECTED = {"aiops-pipeline", "aiops-remediation", "remediation-agent", "leafy-db",
             "postgres", "postgresql", "loki", "grafana", "alertmanager", "prometheus",
             "ollama", "zeek", "enricher", "fluent-bit", "pipeline", "remediation",
             "remediation_agent", "network-observer"}
FORWARD = {"RESTART", "PAUSE", "ISOLATE", "THROTTLE"}


class Denied(ValueError):
    pass


class PinnedDockerExecutor(LocalDockerExecutor):
    """Use immutable ID for every Docker operation; recheck identity on each inspect."""
    def __init__(self, target, rule, client):
        self.target_name, self.rule = target, rule
        super().__init__(client=client, isolate_networks=rule.isolate_networks,
                         preserve_networks=rule.preserve_networks)

    def _container(self, target):
        if target not in (self.target_name, self.rule.container_id):
            raise ExecutorError("target_identity_mismatch")
        obj = self.client.containers.get(self.rule.container_id)
        obj.reload()
        doc = obj.attrs
        labels = (doc.get("Config") or {}).get("Labels") or {}
        host = doc.get("HostConfig") or {}
        name = (doc.get("Name") or "").lstrip("/")
        if (doc.get("Id") != self.rule.container_id or name != self.target_name
                or doc.get("Image") != self.rule.image_id
                or any(labels.get(k) != v for k, v in self.rule.labels.items())
                or labels.get("io.leafy.remediation") != "workload"
                or host.get("Privileged") or host.get("NetworkMode") == "host"
                or host.get("PidMode") == "host"
                or any("docker.sock" in str(m) or "docker_engine" in str(m)
                       for m in doc.get("Mounts", []))):
            raise ExecutorError("runtime_identity_or_privilege_mismatch")
        return obj


class AgentService:
    def __init__(self, config, ledger, mode="disabled", client_factory=None):
        if mode not in ("disabled", "live"):
            raise ValueError("AGENT_MODE must be disabled or live")
        self.config, self.ledger, self.mode = config, ledger, mode
        self.client_factory = client_factory or self._docker

    @staticmethod
    def _docker():
        import docker
        # A fixed local Unix socket. Never respect remote DOCKER_HOST / TLS env.
        return docker.DockerClient(base_url="unix:///var/run/docker.sock", timeout=15)

    def authorize(self, command, recovery=False, automatic=False):
        rule = self.config.targets.get(command.target)
        protected = command.target.lower()
        if (rule is None or protected in PROTECTED or protected.startswith("aiops-")
                or protected == os.getenv("HOSTNAME", "")
                or rule.labels.get("io.leafy.remediation") != "workload"
                or not rule.labels.get("com.docker.compose.project")
                or rule.labels.get("com.docker.compose.service") not in ("backend", "frontend", "minio")
                or rule.labels.get("com.docker.compose.service", "").lower() in PROTECTED):
            raise Denied("target_not_allowed")
        if command.action_type not in rule.actions:
            raise Denied("action_not_allowed")
        if not recovery and command.action_type in RECOVERY_ACTION and RECOVERY_ACTION[command.action_type] not in rule.actions:
            raise Denied("recovery_action_not_allowed")
        if recovery != (command.action_type not in FORWARD):
            raise Denied("wrong_operation_endpoint")
        if not automatic and command.authorization.kind != "manual":
            # Remote auto THROTTLE remains closed until Phase 4 outage validation.
            raise Denied("manual_approval_required_remote_auto_disabled")
        if not command.authorization.approved_by.strip():
            raise Denied("missing_approval_identity")
        now = time.time()
        if command.expires_at <= now or command.expires_at > now + 300:
            raise Denied("request_expired_or_lifetime_too_long")
        if recovery and (command.ttl_seconds is not None or command.recovery_mode != "none"):
            raise Denied("recovery_request_cannot_change_original_schedule")
        if not recovery:
            required = {"RESTART": "none", "PAUSE": "require_approval",
                        "ISOLATE": "require_approval", "THROTTLE": "auto"}[command.action_type]
            if command.recovery_mode != required:
                raise Denied("unsafe_recovery_mode")
            if (command.action_type == "RESTART") != (command.ttl_seconds is None):
                raise Denied("invalid_ttl")
            if command.action_type == "THROTTLE" and command.ttl_seconds > 1800:
                raise Denied("throttle_ttl_too_long")
        return rule

    def executor(self, target, rule):
        return PinnedDockerExecutor(target, rule, self.client_factory())

    def execute(self, command):
        rule = self.authorize(command)
        record, claimed = self.ledger.claim(command)
        if not claimed:
            return record
        executor = None
        may_have_mutated = False
        try:
            if self.mode != "live":
                result = skipped(command.action_type, command.target, "AGENT_MODE=disabled")
            else:
                executor = self.executor(command.target, rule)
                snapshot = executor.snapshot(rule.container_id)
                snapshot["target"] = command.target
                ok, reason = evidence_mod.verify_usable({"targets": {command.target: snapshot}},
                                                        command.action_type)
                if not ok:
                    raise Denied(reason)
                if command.action_type == "PAUSE" and snapshot["state"].get("paused"):
                    raise Denied("already_paused_not_owned_by_this_remediation")
                if command.action_type == "ISOLATE":
                    _, preserved, reason = select_isolation_networks(
                        snapshot["networks"], rule.isolate_networks, rule.preserve_networks)
                    if reason or not preserved:
                        raise Denied(reason or "management_network_not_preserved")
                # NanoCPUs / shares cannot be safely converted by the quota executor.
                # Fail closed rather than clobbering a different CPU control mode.
                if command.action_type == "THROTTLE" and snapshot["resources"].get("nano_cpus"):
                    raise Denied("nanocpu_throttle_unsupported")
                if command.action_type == "THROTTLE":
                    quota, period = (snapshot["resources"].get(k) for k in ("cpu_quota", "cpu_period"))
                    if not isinstance(quota, int) or not isinstance(period, int):
                        raise Denied("original_cpu_limits_unknown")
                    if quota > 0 and quota / (period or 100000) <= executor.cpu_quota / executor.cpu_period:
                        raise Denied("throttle_would_not_reduce_cpu_limit")
                record["evidence"] = snapshot
                if command.ttl_seconds:
                    record["deadline"] = time.time() + command.ttl_seconds
                self.ledger.save(record)  # Durable evidence and deadline BEFORE mutation.
                if command.expires_at <= time.time():
                    raise Denied("request_expired_before_mutation")
                may_have_mutated = True
                result = executor.execute(command.action_type, rule.container_id, snapshot)
                result = replace(result, target=command.target)
        except (Denied, ExecutorError) as exc:
            result = blocked(command.action_type, command.target, str(exc))
        except Exception:
            # SDK/transport failure could happen after a mutation. Never infer success/failure.
            result = ExecutionResult(command.action_type, command.target, "UNKNOWN",
                                     detail="execution_interrupted_inspect_before_manual_recovery")
        finally:
            if executor is not None:
                close = getattr(executor.client, "close", None)
                if close:
                    close()
        record["execution"] = result.as_dict()
        record["state"] = result.status
        record["verified_at"] = time.time() if result.ok else None
        # A failed reversible mutation may have partially applied: keep the lease/evidence.
        release = not may_have_mutated or (command.action_type == "RESTART" and result.ok)
        self.ledger.save(record, release=release)
        return record

    def recover(self, command, automatic=False):
        rule = self.authorize(command, recovery=True, automatic=automatic)
        original = self.ledger.get(command.remediation_id, command.target)
        if original is None or RECOVERY_ACTION.get(original["request"]["action_type"]) != command.action_type:
            raise Conflict("recovery_action_does_not_match_original")
        if automatic and original["request"]["action_type"] != "THROTTLE":
            raise Denied("automatic_reconnect_or_unpause_forbidden")
        if self.mode != "live":
            # Do not consume pending recovery while disabled.
            return {**original, "recovery": skipped(command.action_type, command.target,
                                                    "AGENT_MODE=disabled").as_dict()}
        record, claimed = self.ledger.claim_recovery(command, automatic=automatic)
        if not claimed:
            return record
        executor = None
        try:
            evidence = record["evidence"]
            if evidence.get("container_id") != rule.container_id:
                raise Denied("recovery_container_replaced")
            executor = self.executor(command.target, rule)
            if command.expires_at <= time.time():
                raise Denied("recovery_request_expired_before_mutation")
            result = executor.execute(command.action_type, rule.container_id, evidence)
            result = replace(result, target=command.target)
        except (Denied, ExecutorError) as exc:
            result = blocked(command.action_type, command.target, str(exc))
        except Exception:
            result = ExecutionResult(command.action_type, command.target, "UNKNOWN",
                                     detail="recovery_interrupted_manual_reconciliation_required")
        finally:
            if executor is not None:
                close = getattr(executor.client, "close", None)
                if close:
                    close()
        record["recovery"] = result.as_dict()
        record["recovery_state"] = result.status
        record["recovery_verified_at"] = time.time() if result.ok else None
        # Docker network verification is separate from real Zeek capture verification.
        if command.action_type == "RECONNECT" and result.ok:
            record["observation"] = "awaiting_zeek_subnet_rediscovery"
        self.ledger.save(record, release=result.ok)
        return record

    def reconcile_interrupted(self):
        # Called only after obtaining the process lifetime lock at startup.
        for record in self.ledger.all():
            changed = False
            for key in ("state", "recovery_state"):
                if record[key] == "EXECUTING":
                    record[key] = "UNKNOWN"
                    changed = True
            if changed:
                self.ledger.save(record)

    def tick(self):
        if self.mode != "live":
            return
        for record in self.ledger.all():
            if (record["request"]["action_type"] != "THROTTLE" or record["state"] != "SUCCESS"
                    or record["recovery_state"] or not record["deadline"]
                    or record["deadline"] > time.time()):
                continue
            command = Command(remediation_id=record["remediation_id"], target=record["target"],
                              action_type="UNTHROTTLE", expires_at=int(time.time()) + 60,
                              authorization=Authorization(kind="policy", approved_by="agent-ttl",
                                  decision_id=record["remediation_id"],
                                  approval_id=hashlib.sha256(("ttl:" + record["remediation_id"]).encode()).hexdigest()))
            try:
                self.recover(command, automatic=True)
            except Exception:
                logging.getLogger(__name__).exception("TTL recovery deferred: %s", record["remediation_id"])
