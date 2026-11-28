"""Incident-bound IPv4 TCP/UDP egress rules inside one pinned Docker netns.

A destination is observed data, never a built-in malicious IP. Current operator
allowlist and management networks are rechecked before approval and mutation.
No host networking, arbitrary command, image pull or DNS resolution is accepted.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import threading

import yaml

from executor.base import ExecutionResult, blocked, succeeded
from executor.identity import normalized_identity
from executor.managed import ExecutionJournal, check_record, digest, seal_plan, valid_plan_digest

ACTIONS = {"BLOCK_EGRESS", "UNBLOCK_EGRESS"}
RECOVERY_MAP = {"BLOCK_EGRESS": "UNBLOCK_EGRESS"}
_LOCK = threading.RLock()


def validate_parameters(action, parameters):
    if not isinstance(parameters, dict):
        raise ValueError("invalid_egress_parameters")
    if action == "UNBLOCK_EGRESS":
        if set(parameters) != {"parent_id"} or not isinstance(parameters["parent_id"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", parameters["parent_id"]):
            raise ValueError("verified_egress_parent_required")
        return
    if action != "BLOCK_EGRESS" or set(parameters) != {"destination_ip", "destination_port", "protocol", "flow_id"}:
        raise ValueError("observed_egress_tuple_required")
    try:
        ip = ipaddress.IPv4Address(parameters["destination_ip"])
        if str(ip) != parameters["destination_ip"] or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or str(ip) == "255.255.255.255":
            raise ValueError()
    except (ValueError, TypeError):
        raise ValueError("single_observed_ipv4_destination_required") from None
    if (type(parameters["destination_port"]) is not int or not 1 <= parameters["destination_port"] <= 65535
            or not isinstance(parameters["protocol"], str) or parameters["protocol"] not in {"tcp", "udp"}
            or not isinstance(parameters["flow_id"], str)
            or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", parameters["flow_id"])):
        raise ValueError("invalid_observed_egress_tuple")


def validate_observation(alert, parameters):
    validate_parameters("BLOCK_EGRESS", parameters)
    labels = alert.get("labels", {})
    def field(name):
        return labels.get("v2_" + name, labels.get(name))
    if (field("dst_ip") != parameters["destination_ip"]
            or str(field("dst_port")) != str(parameters["destination_port"])
            or field("protocol") != parameters["protocol"]):
        raise ValueError("egress_destination_must_match_current_alert")
    # flow_id binds this proposal to its incident, not a scenario/ground-truth ID.
    if parameters["flow_id"] != alert.get("fingerprint"):
        raise ValueError("egress_flow_must_match_incident_fingerprint")


class EgressExecutor:
    name = "egress"
    changes_system = True

    def __init__(self, config_path=None, client=None):
        self.config_path, self._client = config_path, client

    @property
    def client(self):
        if self._client is None:
            import docker
            self._client = docker.DockerClient(base_url="unix:///var/run/docker.sock", timeout=15)
        return self._client

    def _config(self):
        path = self.config_path or os.getenv("REMEDIATION_EGRESS_CONFIG_PATH")
        try:
            if not path:
                raise ValueError()
            c = yaml.safe_load(Path(path).read_text())
            if (not isinstance(c, dict) or set(c) != {"version", "enabled", "helper_image_id", "policy_file", "journal_path", "preserve_networks", "targets"}
                    or type(c["version"]) is not int or c["version"] != 1 or c["enabled"] is not True
                    or not re.fullmatch(r"sha256:[a-f0-9]{64}", str(c["helper_image_id"]))
                    or not isinstance(c["targets"], dict) or not c["targets"]
                    or not isinstance(c["preserve_networks"], list) or not c["preserve_networks"]
                    or any(not isinstance(x, str) or not x for x in c["preserve_networks"])
                    or any(not isinstance(c[k], str) or not Path(c[k]).is_absolute() for k in ("policy_file", "journal_path"))):
                raise ValueError()
            return c
        except Exception:
            raise ValueError("egress_disabled_or_invalid_private_config") from None

    def _target(self, ident, targets, config):
        ident = normalized_identity(ident)
        rule = config["targets"].get(ident["target"])
        if (targets != [ident["target"]] or not isinstance(rule, dict)
                or set(rule) != {"identity", "container_id", "image_id", "labels"}
                or rule["identity"] != ident
                or not re.fullmatch(r"[a-f0-9]{64}", str(rule["container_id"]))
                or not re.fullmatch(r"sha256:[a-f0-9]{64}", str(rule["image_id"]))
                or not isinstance(rule["labels"], dict)
                or rule["labels"].get("io.leafy.remediation") != "workload"
                or not rule["labels"].get("com.docker.compose.project")
                or rule["labels"].get("com.docker.compose.service") != ident["service"]
                or ident["service"] not in {"backend", "frontend"}):
            raise ValueError("egress_target_not_allowed")
        return rule

    def _inspect(self, rule):
        obj = self.client.containers.get(rule["container_id"])
        obj.reload()
        d = obj.attrs
        host = d.get("HostConfig") or {}
        state = d.get("State") or {}
        labels = (d.get("Config") or {}).get("Labels") or {}
        if (d.get("Id") != rule["container_id"] or d.get("Image") != rule["image_id"]
                or d.get("Name", "").lstrip("/") != rule["identity"]["target"]
                or any(labels.get(k) != v for k, v in rule["labels"].items())
                or state.get("Running") is not True or state.get("Paused")
                or host.get("NetworkMode") == "host" or str(host.get("NetworkMode", "")).startswith("container:")
                or host.get("Privileged") or host.get("PidMode") == "host"
                or any("docker.sock" in str(m) or "docker_engine" in str(m) for m in d.get("Mounts", []))):
            raise ValueError("egress_container_identity_or_namespace_changed")
        networks = (d.get("NetworkSettings") or {}).get("Networks") or {}
        if not networks:
            raise ValueError("egress_network_inventory_missing")
        return {"container_id": d["Id"], "image_id": d["Image"], "started_at": state.get("StartedAt"),
                "networks": {name: {k: values.get(k) for k in ("NetworkID", "IPAddress", "Gateway")}
                             for name, values in networks.items()}}

    def _policy(self, config, snapshot, parameters, protect=True):
        policy = yaml.safe_load(Path(config["policy_file"]).read_text())
        if not isinstance(policy, dict) or type(policy.get("version")) is not int or policy["version"] != 1 or not isinstance(policy.get("allow"), list):
            raise ValueError("current_egress_allowlist_required")
        if protect:
            address = ipaddress.IPv4Address(parameters["destination_ip"])
            for entry in policy["allow"]:
                if entry.get("match") == "endpoint":
                    if str(ipaddress.ip_address(entry["ip"])) == str(address) and entry["port"] == parameters["destination_port"]:
                        raise ValueError("authorized_destination_must_not_be_blocked")
                elif entry.get("match") != "service":
                    raise ValueError("invalid_current_allowlist")
            # Every current gateway and the workload's own addresses remain
            # protected even outside a named management network.
            for net in snapshot["networks"].values():
                for key in ("IPAddress", "Gateway"):
                    if net.get(key) and address == ipaddress.ip_address(net[key]):
                        raise ValueError("gateway_or_self_destination_must_not_be_blocked")
            allowed_services = {e["service"] for e in policy["allow"] if e.get("match") == "service"}
            for name, net in snapshot["networks"].items():
                doc = self.client.networks.get(net["NetworkID"]).attrs
                if any(name == n or name.endswith("_" + n) for n in config["preserve_networks"]):
                    subnets = (doc.get("IPAM") or {}).get("Config", [])
                    if not subnets or any(not x.get("Subnet") for x in subnets):
                        raise ValueError("management_subnet_inventory_required")
                    for subnet in subnets:
                        if address in ipaddress.ip_network(subnet["Subnet"]):
                            raise ValueError("management_destination_must_not_be_blocked")
                for cid, endpoint in (doc.get("Containers") or {}).items():
                    ip = str(endpoint.get("IPv4Address", "")).split("/")[0]
                    if not ip or address != ipaddress.ip_address(ip):
                        continue
                    peer = self.client.containers.get(cid)
                    peer.reload()
                    service = ((peer.attrs.get("Config") or {}).get("Labels") or {}).get("com.docker.compose.service")
                    if service in allowed_services:
                        raise ValueError("authorized_service_must_not_be_blocked")
        return digest(policy)

    def _journal(self, config):
        return ExecutionJournal(config["journal_path"])

    def _parent(self, config, parent_id):
        with self._journal(config).connection() as db:
            table = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='egress_blocks'").fetchone()
            if not table:
                raise ValueError("verified_egress_parent_required")
            row = db.execute("SELECT plan,status FROM egress_blocks WHERE rid=?", (parent_id,)).fetchone()
        if not row or row[1] != "SUCCESS":
            raise ValueError("verified_egress_parent_required")
        return json.loads(row[0])

    def plan_record(self, identity, targets, action_type, parameters):
        validate_parameters(action_type, parameters)
        c = self._config()
        rule = self._target(identity, targets, c)
        snap = self._inspect(rule)
        if self.client.images.get(c["helper_image_id"]).attrs.get("Id") != c["helper_image_id"]:
            raise ValueError("approved_egress_helper_not_locally_available")
        if action_type == "UNBLOCK_EGRESS":
            parent = self._parent(c, parameters["parent_id"])
            if parent["identity"] != identity or parent["pre_snapshot"] != snap:
                raise ValueError("egress_parent_target_changed")
            flow = parent["operator_config"]["flow"]
            tag = parent["operator_config"]["tag"]
        else:
            flow = dict(parameters)
            tag = "leafy-egress-" + digest({"identity": identity, "snapshot": snap, "flow": flow})[:32]
        policy_hash = self._policy(c, snap, flow, protect=action_type == "BLOCK_EGRESS")
        plan = {"executor": self.name, "identity": identity, "target": identity["target"], "action_type": action_type,
                "parameters": dict(parameters), "operator_config": {"labels": rule["labels"], "helper_image_id": c["helper_image_id"],
                "policy_hash": policy_hash, "config_hash": digest(c), "flow": flow, "tag": tag}, "pre_snapshot": snap}
        return {identity["target"]: seal_plan(plan)}

    def validate_record(self, record):
        try:
            fresh = self.plan_record(record.identity, record.targets, record.action_type, record.action_parameters)
            for target in record.targets:
                old = {k: v for k, v in record.target_bindings[target].items() if k != "transport"}
                if not valid_plan_digest(old) or fresh[target] != old:
                    return "egress_plan_changed_reapproval_required"
            return None
        except Exception:
            return "egress_plan_validation_failed"

    def capture_record(self, record, target):
        from evidence_capture import container_capture
        config = self._config()
        rule = self._target(record.identity, record.targets, config)
        self._inspect(rule)
        return container_capture(self.client.containers.get(rule["container_id"]))

    def _run(self, plan, operation, approval_record=None):
        c = self._config()
        rule = self._target(plan["identity"], [plan["target"]], c)
        if self._inspect(rule) != plan["pre_snapshot"]:
            raise ValueError("egress_namespace_changed")
        flow = plan["operator_config"]["flow"]
        spec = ["-d", flow["destination_ip"] + "/32", "-p", flow["protocol"], "--dport", str(flow["destination_port"]),
                "-m", "comment", "--comment", plan["operator_config"]["tag"], "-j", "REJECT"]
        args = ["-w", "5", "-t", "filter", operation, "OUTPUT"]
        if operation == "-I":
            args += ["1"]
        if operation != "-S":
            args += spec
        # IDs are operator pinned; fixed argv has no shell, host PID/net, mounts,
        # credentials, arbitrary image or user-controlled Docker options.
        helper = self.client.containers.create(c["helper_image_id"], command=args,
            entrypoint=["/sbin/iptables"], network_mode="container:" + rule["container_id"],
            cap_drop=["ALL"], cap_add=["NET_ADMIN"], privileged=False,
            read_only=True, user="0:0", security_opt=["no-new-privileges:true"],
            volumes={"leafy-egress-locks": {"bind": "/run", "mode": "rw"}},
            pids_limit=16, mem_limit="32m", cpu_quota=50000, detach=True)
        try:
            # Helper creation can block until an approval expires or the target
            # is replaced. Recheck after creation and immediately before start.
            if operation in {"-I", "-D"}:
                if approval_record is None:
                    raise ValueError("egress_mutation_approval_required")
                check_record(approval_record, self.name)
                if self._inspect(rule) != plan["pre_snapshot"]:
                    raise ValueError("egress_namespace_changed_before_helper_start")
            helper.start()
            result = helper.wait(timeout=15)
            if set(result) - {"StatusCode", "Error"} or type(result.get("StatusCode")) is not int or result.get("Error"):
                raise ValueError("egress_helper_result_unconfirmed")
            return result["StatusCode"]
        finally:
            helper.remove(force=True)

    def execute_record(self, record, target, approved_by=None):
        action = record.action_type
        mutated = False
        claimed = False
        with _LOCK:
            try:
                check_record(record, self.name)
                if approved_by is not None and approved_by != record.approved_by or target not in record.targets:
                    raise ValueError("egress_approval_identity_mismatch")
                c = self._config()
                journal = self._journal(c)
                cached = journal.claim(record, target)
                if cached:
                    return cached
                claimed = True
                if self.validate_record(record):
                    raise ValueError("egress_plan_changed")
                plan = record.target_bindings[target]
                native = {k: v for k, v in plan.items() if k != "transport"}
                with journal.connection() as db:
                    db.execute("CREATE TABLE IF NOT EXISTS egress_blocks (rid TEXT PRIMARY KEY, plan TEXT, status TEXT)")
                    if action == "BLOCK_EGRESS":
                        db.execute("INSERT INTO egress_blocks VALUES (?,?,?)", (record.remediation_id, json.dumps(native), "EXECUTING"))
                if self._run(native, "-S") != 0:
                    raise ValueError("egress_firewall_backend_unavailable")
                before = self._run(native, "-C")
                if before not in {0, 1}:
                    raise ValueError("egress_rule_query_failed")
                # Unexpected preexisting rule is not ours to adopt. Removing an
                # already absent rule is idempotent, but never clears other rules.
                if action == "BLOCK_EGRESS" and before == 0:
                    raise ValueError("egress_rule_already_present_manual_review")
                if action == "BLOCK_EGRESS" or before == 0:
                    check_record(record, self.name)
                    if self.validate_record(record):
                        raise ValueError("egress_changed_before_mutation")
                    mutated = True
                    if self._run(native, "-I" if action == "BLOCK_EGRESS" else "-D", record) != 0:
                        raise RuntimeError("egress_rule_mutation_unconfirmed")
                after = self._run(native, "-C")
                if after != (0 if action == "BLOCK_EGRESS" else 1):
                    raise RuntimeError("egress_rule_state_unconfirmed")
                result = succeeded(action, target, "destination_rule_present" if action == "BLOCK_EGRESS" else "owned_destination_rule_removed",
                                   after={"container_id": native["pre_snapshot"]["container_id"], "rule_tag": native["operator_config"]["tag"],
                                          "destination": native["operator_config"]["flow"], "network_connectivity_verified": False})
                with journal.connection() as db:
                    db.execute("UPDATE egress_blocks SET status=? WHERE rid=?", ("SUCCESS" if action == "BLOCK_EGRESS" else "REMOVED", record.remediation_id if action == "BLOCK_EGRESS" else record.action_parameters["parent_id"]))
                return journal.save(record, target, result)
            except Exception:
                result = (ExecutionResult(action, target, "UNKNOWN", detail="egress_mutation_unconfirmed_no_retry") if mutated
                          else blocked(action, target, "egress_preflight_or_approval_rejected"))
                try:
                    if not claimed:
                        return result
                    return journal.save(record, target, result)
                except Exception:
                    return result
