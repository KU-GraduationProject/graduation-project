"""Narrow operator-configured nginx, MinIO, service and closed-log actions.

No caller-provided command, credentials, host, file path or service name enters an
execution argv. Planning is read-only. Mutations require the Controller's durable
claim and approval, an unchanged plan and a durable local one-attempt journal.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
import time

import yaml

from executor.base import Executor, ExecutionResult, blocked, succeeded
from executor.managed import seal_plan, valid_plan_digest, check_record

ACTIONS = frozenset({"BLOCK_PATH", "RATE_LIMIT", "MAINTENANCE_MODE", "RESTORE_NGINX",
                     "RESTRICT_BUCKET", "RESTORE_BUCKET", "DISABLE_KEY", "ENABLE_KEY",
                     "RESTART_HOST_SVC", "CLEAN_DISK", "RECORD_INCIDENT"})
RESTORES = {"RESTORE_NGINX": {"BLOCK_PATH", "RATE_LIMIT", "MAINTENANCE_MODE"},
            "RESTORE_BUCKET": {"RESTRICT_BUCKET"}, "ENABLE_KEY": {"DISABLE_KEY"}}
MARKER = "# Leafy remediation managed v1\n"
IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
ENV = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
ROUTE = re.compile(r"^/[A-Za-z0-9/_-]{0,200}$")
_OPERATIONS_LOCK = threading.RLock()


class OperationsError(ValueError):
    pass


def validate_parameters(action, parameters):
    if action not in ACTIONS or not isinstance(parameters, dict):
        raise OperationsError("invalid_operations_parameters")
    if action in RESTORES:
        if set(parameters) != {"parent_id"} or not isinstance(parameters["parent_id"], str) or not IDENT.fullmatch(parameters["parent_id"]):
            raise OperationsError("verified_parent_id_required")
    elif action in {"BLOCK_PATH", "RATE_LIMIT"}:
        required = {"path"} | ({"burst"} if action == "RATE_LIMIT" else set())
        if set(parameters) != required or not isinstance(parameters["path"], str) or not ROUTE.fullmatch(parameters["path"]):
            raise OperationsError("literal_exact_nginx_path_required")
        if action == "RATE_LIMIT" and (type(parameters["burst"]) is not int or not 1 <= parameters["burst"] <= 100):
            raise OperationsError("bounded_nginx_burst_required")
    elif action == "RESTRICT_BUCKET":
        if set(parameters) != {"bucket"} or not isinstance(parameters["bucket"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", parameters["bucket"]):
            raise OperationsError("one_bucket_required")
    elif action == "DISABLE_KEY":
        if set(parameters) != {"resource"} or not isinstance(parameters["resource"], str) or not IDENT.fullmatch(parameters["resource"]):
            raise OperationsError("one_key_resource_required")
    elif action == "RECORD_INCIDENT":
        if set(parameters) != {"incident_key"} or not isinstance(parameters["incident_key"], str) or not re.fullmatch(r"[a-f0-9]{64}", parameters["incident_key"]):
            raise OperationsError("canonical_incident_key_required")
    elif parameters:
        raise OperationsError("operator_owned_configuration_required")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def file_digest(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def safe_file(path, root=None):
    p = Path(path)
    if not p.is_absolute() or any(x.is_symlink() for x in (p, *p.parents)):
        raise OperationsError("absolute_nonsymlink_file_required")
    if root is not None and not p.is_relative_to(Path(root)):
        raise OperationsError("file_outside_managed_root")
    st = p.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise OperationsError("regular_single_link_file_required")
    return p


def atomic_json(path, data, exclusive=False):
    body = json.dumps(data, sort_keys=True, allow_nan=False).encode()
    if exclusive:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(body); stream.flush(); os.fsync(stream.fileno())
    else:
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(body); stream.flush(); os.fsync(stream.fileno())
            os.replace(tmp, path)
        finally:
            tmp.unlink(missing_ok=True)
    if os.name != "nt":
        fd = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)


class EdgeStorageHostExecutor(Executor):
    name = "operations"

    def __init__(self, config_path=None, runner=None, clock=None, sleep=None, open_files=None, platform=None, http_client=None, docker_client=None):
        self.config_path = config_path
        self.runner = runner or subprocess.run
        self.clock, self.sleep = clock or time.time, sleep or time.sleep
        self.open_files = open_files or self._open_files
        self.platform = platform or sys.platform
        self.http_client = http_client
        self.docker_client = docker_client
        self._lock = _OPERATIONS_LOCK

    def _config(self):
        try:
            path = self.config_path or os.environ["REMEDIATION_OPERATIONS_CONFIG_PATH"]
            doc = yaml.safe_load(Path(path).read_text())
            if (not isinstance(doc, dict) or set(doc) != {"version", "enabled", "state_dir", "targets"}
                    or doc["version"] != 1 or doc["enabled"] is not True or not isinstance(doc["targets"], dict)):
                raise ValueError()
            state = Path(doc["state_dir"])
            if not state.is_absolute() or any(p.is_symlink() for p in (state, *state.parents)):
                raise ValueError()
            if not state.is_dir() or (os.name != "nt" and state.stat().st_mode & 0o077):
                raise ValueError()
            return doc
        except Exception:
            raise OperationsError("operations_unconfigured_or_invalid") from None

    def _target(self, identity, targets, action):
        cfg = self._config()
        if (not isinstance(identity, dict) or set(identity) != {"site", "source", "service", "runtime", "target"}
                or any(not isinstance(v, str) or not IDENT.fullmatch(v) or v.lower() in {"unknown", "none", "stdout", "stderr"} for v in identity.values())
                or list(targets) != [identity["target"]] or action not in ACTIONS):
            raise OperationsError("one_exact_operations_identity_required")
        target = cfg["targets"].get(identity["target"])
        if (not isinstance(target, dict) or target.get("identity") != identity or action not in target.get("actions", [])):
            raise OperationsError("operations_target_or_action_not_allowed")
        return cfg, target

    def _run(self, argv, *, env=None):
        # All argv construction is below; no shell or raw error text is retained.
        try:
            result = self.runner(argv, capture_output=True, text=True, timeout=20, check=False,
                                 shell=False, env=env)
            if result.returncode != 0 or len(result.stdout or "") > 131072:
                raise OperationsError("operations_command_rejected")
            return result.stdout or ""
        except Exception:
            raise OperationsError("operations_command_unavailable") from None

    def _binary(self, spec, name):
        p = safe_file(spec["binary"])
        if (p.name.lower().removesuffix(".exe") != name or not re.fullmatch(r"[a-f0-9]{64}", spec.get("binary_sha256", ""))
                or file_digest(p) != spec["binary_sha256"]):
            raise OperationsError("approved_tool_binary_changed")
        return str(p)

    def _journal(self, cfg, rid):
        if not isinstance(rid, str) or not IDENT.fullmatch(rid):
            raise OperationsError("invalid_parent_or_remediation_id")
        root = Path(cfg["state_dir"])
        return root / (rid + ".json")

    def _parent(self, cfg, identity, parameters, action):
        if set(parameters) != {"parent_id"}:
            raise OperationsError("verified_parent_id_required")
        path = self._journal(cfg, parameters["parent_id"])
        try:
            safe_file(path)
            parent = json.loads(path.read_text())
            if (parent.get("state") != "VERIFIED" or parent["plan"]["identity"] != identity
                    or parent["plan"]["action_type"] not in RESTORES[action]):
                raise ValueError()
            return parent
        except Exception:
            raise OperationsError("verified_same_identity_parent_required") from None

    def _nginx_container(self, target):
        spec = target["nginx"]
        if (not re.fullmatch(r"[a-f0-9]{64}", str(spec.get("container_id", "")))
                or not re.fullmatch(r"sha256:[a-f0-9]{64}", str(spec.get("image_id", "")))
                or spec.get("shared_include_verified") is not True or not isinstance(spec.get("labels"), dict)
                or spec["labels"].get("io.leafy.remediation") != "workload"
                or spec["labels"].get("com.docker.compose.service") != "frontend"):
            raise OperationsError("pinned_nginx_workload_required")
        if self.docker_client is None:
            import docker
            self.docker_client = docker.DockerClient(base_url="unix:///var/run/docker.sock", timeout=15)
        container = self.docker_client.containers.get(spec["container_id"])
        container.reload()
        doc = container.attrs
        labels = (doc.get("Config") or {}).get("Labels") or {}
        host = doc.get("HostConfig") or {}
        if (doc.get("Id") != spec["container_id"] or doc.get("Image") != spec["image_id"]
                or (doc.get("Name") or "").lstrip("/") != target["identity"]["target"]
                or any(labels.get(k) != v for k, v in spec["labels"].items())
                or host.get("Privileged") or host.get("NetworkMode") == "host" or host.get("PidMode") == "host"
                or not (doc.get("State") or {}).get("Running")
                or any("docker.sock" in str(m) or "docker_engine" in str(m) for m in doc.get("Mounts", []))):
            raise OperationsError("nginx_container_changed")
        if not any(m.get("Type") == "bind" and m.get("Source") == spec.get("mount_source")
                   and m.get("Destination") == str(Path(spec["container_include"]).parent)
                   for m in doc.get("Mounts", [])):
            raise OperationsError("nginx_shared_include_mount_changed")
        for key in ("container_include", "container_config", "container_binary"):
            if not isinstance(spec.get(key), str) or not spec[key].startswith("/") or ".." in Path(spec[key]).parts:
                raise OperationsError("fixed_nginx_container_paths_required")
        if Path(spec["container_binary"]).name != "nginx":
            raise OperationsError("fixed_nginx_binary_required")
        return container

    def _nginx_command(self, target, *args):
        spec = target["nginx"]
        container = self._nginx_container(target)
        try:
            result = container.exec_run([spec["container_binary"], *args, "-c", spec["container_config"]], user="0", stdout=True, stderr=False)
            if result.exit_code != 0 or not isinstance(result.output, bytes) or len(result.output) > 131072:
                raise ValueError()
            return result.output.decode("utf-8")
        except Exception:
            raise OperationsError("nginx_command_unconfirmed") from None

    def _nginx(self, target):
        spec = target["nginx"]
        path = safe_file(spec["managed_include"], spec["managed_root"])
        body = path.read_text()
        if not body.startswith(MARKER) or len(body.encode()) > 32768:
            raise OperationsError("bounded_managed_nginx_include_required")
        # Existing snippets are generated by this module; a human's unrelated
        # file must never become a restorable credential-bearing plan payload.
        if body != MARKER and not re.fullmatch(re.escape(MARKER) + r"(?:# operation [a-f0-9]{64}\n(?:location = /[A-Za-z0-9/_-]* \{ return 403; \}\n|location / \{ return 503; \}\n|location = /[A-Za-z0-9/_-]* \{ limit_req zone=leafy_remediation burst=[0-9]+ nodelay; proxy_pass http://[A-Za-z0-9_.:-]+; \}\n))+", body):
            raise OperationsError("unrecognized_nginx_managed_content")
        container = self._nginx_container(target)
        self._nginx_command(target, "-t")
        loaded = self._nginx_command(target, "-T")
        if "# configuration file " + spec["container_include"] + ":" not in loaded:
            raise OperationsError("managed_include_not_in_nginx_configuration")
        zone = bool(re.search(r"limit_req_zone\s+\$(?:request_uri|uri|http_authorization)\s+zone=leafy_remediation:[0-9]+[kKmM]\s+rate=[1-9][0-9]*r/[sm];", loaded))
        return {"managed_text": body, "rate_zone_verified": zone, "managed_sha256": hashlib.sha256(body.encode()).hexdigest(),
                "container_id": container.attrs["Id"], "image_id": container.attrs["Image"],
                "loaded_configuration_sha256": hashlib.sha256(loaded.encode()).hexdigest()}

    def _mc_transport(self, target):
        from urllib.parse import urlsplit
        spec = target["minio"]
        root = Path(spec["config_dir"])
        p = safe_file(root / "config.json")
        if os.name != "nt" and (root.stat().st_mode & 0o077 or p.stat().st_mode & 0o077):
            raise OperationsError("private_minio_config_permissions_required")
        try:
            config = json.loads(p.read_text())
            alias = config["aliases"][spec["alias"]]
            url = urlsplit(alias["url"])
            if (url.scheme != "https" or not url.hostname or url.username or url.password
                    or url.query or url.fragment or url.path not in ("", "/")):
                raise ValueError()
            return file_digest(p)
        except Exception:
            raise OperationsError("verified_https_minio_alias_required") from None

    def _mc(self, target, *args):
        spec = target["minio"]
        binary = self._binary(spec, "mc")
        alias = spec["alias"]
        if not IDENT.fullmatch(alias): raise OperationsError("invalid_minio_alias")
        env = dict(os.environ)
        # Credentials remain in private mc config, never in argv or plans.
        config_dir = Path(spec["config_dir"])
        if not config_dir.is_absolute() or any(p.is_symlink() for p in (config_dir, *config_dir.parents)):
            raise OperationsError("private_minio_config_required")
        self._mc_transport(target)
        env["MC_CONFIG_DIR"] = str(config_dir)
        return self._run([binary, *args], env=env)

    def _bucket(self, target, bucket):
        spec = target["minio"]
        if bucket not in spec.get("bucket_allowlist", []) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
            raise OperationsError("bucket_not_allowlisted")
        body = json.loads(self._mc(target, "anonymous", "get-json", spec["alias"] + "/" + bucket))
        if not isinstance(body, dict) or body.get("Version") != "2012-10-17" or not isinstance(body.get("Statement"), list):
            raise OperationsError("existing_bucket_policy_contract_required")
        return {"bucket": bucket, "policy": body, "policy_sha256": digest(body), "transport_sha256": self._mc_transport(target)}

    def _key(self, target, resource):
        spec = target["minio"]
        mapping = spec.get("service_accounts", {}).get(resource)
        if not mapping or not IDENT.fullmatch(resource): raise OperationsError("key_resource_not_allowlisted")
        keys = (mapping.get("key_id_env"), mapping.get("owner_env"), spec.get("root_key_env"))
        if any(not isinstance(k, str) or not ENV.fullmatch(k) or not os.getenv(k) for k in keys):
            raise OperationsError("private_service_account_refs_required")
        key, owner, root = (os.environ[k] for k in keys)
        if key == root or owner == root or owner.lower() in {"root", "admin", "minioadmin"}:
            raise OperationsError("root_or_admin_service_account_forbidden")
        info = json.loads(self._mc(target, "--json", "admin", "user", "svcacct", "info", spec["alias"], key))
        if info.get("parentUser") != owner or info.get("accountStatus") not in {"on", "off"}:
            raise OperationsError("service_account_owner_or_state_mismatch")
        return {"resource": resource, "key_sha256": hashlib.sha256(key.encode()).hexdigest(),
                "owner_sha256": hashlib.sha256(owner.encode()).hexdigest(), "status": info["accountStatus"],
                "transport_sha256": self._mc_transport(target)}

    def _service(self, target):
        spec = target["host_service"]
        if self.platform != "win32" or not re.fullmatch(r"postgresql(?:-[A-Za-z0-9_.-]+)?", spec["service_name"], re.I):
            raise OperationsError("windows_postgresql_service_only")
        binary = self._binary(spec, "sc")
        output = self._run([binary, "queryex", spec["service_name"]])
        state = re.search(r"STATE\s*:\s*(\d+)", output)
        pid = re.search(r"PID\s*:\s*(\d+)", output)
        if not state or not pid: raise OperationsError("service_status_unavailable")
        config = self._run([binary, "qc", spec["service_name"]])
        return {"state": int(state[1]), "pid": int(pid[1]), "service_config_sha256": hashlib.sha256(config.encode()).hexdigest()}

    @staticmethod
    def _open_files():
        try:
            import psutil
            paths = set()
            for proc in psutil.process_iter():
                try: paths.update(Path(f.path).resolve() for f in proc.open_files())
                except psutil.NoSuchProcess: continue
            return paths
        except Exception:
            raise OperationsError("complete_open_file_inventory_required") from None

    def _logs(self, target):
        spec = target["clean_logs"]
        root = Path(spec["root"])
        if (not root.is_absolute() or any(p.is_symlink() for p in (root, *root.parents))
                or any(p.lower() in {"pgdata", "postgres", "postgresql", "data", "minio", "docker", "volumes"} for p in root.parts)):
            raise OperationsError("dedicated_closed_log_root_required")
        names = spec["files"]
        if not isinstance(names, list) or not 1 <= len(names) <= 20 or len(set(names)) != len(names):
            raise OperationsError("bounded_exact_log_allowlist_required")
        minimum = spec.get("min_age_seconds", 86400)
        maximum = spec.get("max_total_bytes", 100000000)
        if type(minimum) is not int or minimum < 86400 or type(maximum) is not int or not 1 <= maximum <= 1000000000:
            raise OperationsError("invalid_closed_log_limits")
        opened = self.open_files()
        result = {}
        for name in names:
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.log", name):
                raise OperationsError("only_exact_log_filenames_allowed")
            p = safe_file(root / name, root)
            st = p.stat()
            if p.resolve() in opened or self.clock() - st.st_mtime < minimum:
                raise OperationsError("open_or_recent_log_refused")
            result[name] = {"dev": st.st_dev, "inode": st.st_ino, "size": st.st_size,
                            "mtime_ns": st.st_mtime_ns, "sha256": file_digest(p)}
        if sum(x["size"] for x in result.values()) > maximum:
            raise OperationsError("closed_log_byte_limit_exceeded")
        return {"files": result}

    def _github(self, target, method, path, body=None):
        spec = target["github"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", spec["repository"]) or not ENV.fullmatch(spec["token_env"]):
            raise OperationsError("exact_github_repository_and_token_ref_required")
        token = os.getenv(spec["token_env"])
        if not token: raise OperationsError("github_token_unconfigured")
        try:
            if self.http_client is None:
                import httpx
                self.http_client = httpx.Client(timeout=10, follow_redirects=False, trust_env=False)
            response = self.http_client.request(method, "https://api.github.com" + path,
                headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
                json=body if method == "POST" else None)
            response.raise_for_status()
            return response.json()
        except Exception:
            raise OperationsError("github_request_unconfirmed") from None

    def _incident(self, target, key):
        from urllib.parse import urlencode
        spec = target["github"]
        marker = "<!-- leafy-incident:" + key + " -->"
        query = "repo:" + spec["repository"] + ' in:body "leafy-incident:' + key + '"'
        result = self._github(target, "GET", "/search/issues?" + urlencode({"q": query, "per_page": 10}))
        if result.get("incomplete_results") is not False or type(result.get("total_count")) is not int or result["total_count"] > 1:
            raise OperationsError("incident_search_incomplete_or_ambiguous")
        items = result.get("items")
        if not isinstance(items, list) or len(items) != result["total_count"]:
            raise OperationsError("incident_search_contract_invalid")
        if items:
            item = items[0]
            if marker not in str(item.get("body", "")) or type(item.get("number")) is not int:
                raise OperationsError("incident_marker_mismatch")
            return {"incident_key": key, "number": item["number"]}
        return {"incident_key": key, "number": None}

    def plan_record(self, identity, targets, action_type, parameters):
        validate_parameters(action_type, parameters)
        cfg, target = self._target(identity, targets, action_type)
        if not isinstance(parameters, dict): raise OperationsError("parameters_mapping_required")
        parent = self._parent(cfg, identity, parameters, action_type) if action_type in RESTORES else None
        if action_type in {"BLOCK_PATH", "RATE_LIMIT"}:
            allowed = {"path"} if action_type == "BLOCK_PATH" else {"path", "burst"}
            if set(parameters) != allowed or not ROUTE.fullmatch(str(parameters.get("path", ""))):
                raise OperationsError("literal_exact_nginx_path_required")
            if action_type == "RATE_LIMIT" and (type(parameters["burst"]) is not int or not 1 <= parameters["burst"] <= 100):
                raise OperationsError("bounded_nginx_burst_required")
        elif action_type in {"MAINTENANCE_MODE", "RESTART_HOST_SVC", "CLEAN_DISK"}:
            if parameters: raise OperationsError("operator_owned_configuration_required")
        elif action_type == "RESTRICT_BUCKET":
            if set(parameters) != {"bucket"}: raise OperationsError("one_allowlisted_bucket_required")
        elif action_type == "DISABLE_KEY":
            if set(parameters) != {"resource"}: raise OperationsError("one_key_resource_required")
        if action_type in {"BLOCK_PATH", "RATE_LIMIT", "MAINTENANCE_MODE", "RESTORE_NGINX"}:
            if identity["service"] != "frontend" or identity["runtime"] != "container":
                raise OperationsError("nginx_frontend_identity_required")
            before = self._nginx(target)
            if action_type == "RATE_LIMIT" and not before["rate_zone_verified"]:
                raise OperationsError("path_or_token_rate_limit_zone_required")
        elif action_type in {"RESTRICT_BUCKET", "RESTORE_BUCKET"}:
            if identity["service"] != "minio": raise OperationsError("minio_identity_required")
            before = self._bucket(target, parent["plan"]["parameters"]["bucket"] if parent else parameters["bucket"])
        elif action_type in {"DISABLE_KEY", "ENABLE_KEY"}:
            if identity["service"] != "minio": raise OperationsError("minio_identity_required")
            before = self._key(target, parent["plan"]["parameters"]["resource"] if parent else parameters["resource"])
        elif action_type == "RESTART_HOST_SVC":
            if identity["service"] != "db" or identity["runtime"] != "host": raise OperationsError("host_db_identity_required")
            before = self._service(target)
            if before["state"] != 4: raise OperationsError("running_service_required_for_restart")
        elif action_type == "RECORD_INCIDENT":
            if set(parameters) != {"incident_key"} or not re.fullmatch(r"[a-f0-9]{64}", str(parameters["incident_key"])):
                raise OperationsError("canonical_incident_key_required")
            before = self._incident(target, parameters["incident_key"])
        else:
            if identity["runtime"] != "host": raise OperationsError("host_log_identity_required")
            before = self._logs(target)
        if parent and before != parent["after"]:
            raise OperationsError("operator_state_changed_do_not_restore")
        plan = {"executor": self.name, "identity": identity, "target": identity["target"], "action_type": action_type,
                "parameters": parameters, "operator_config": target, "pre_snapshot": before}
        if parent:
            # Parent hash, not arbitrary restore content, becomes approval evidence.
            plan["pre_snapshot"] = {**before, "parent_plan_digest": parent["plan"]["plan_digest"]}
        return {identity["target"]: seal_plan(plan)}

    def validate_record(self, record):
        try:
            fresh = self.plan_record(record.identity, record.targets, record.action_type, record.action_parameters)
            if any(not valid_plan_digest(record.target_bindings[t]) or fresh[t]["plan_digest"] != record.target_bindings[t]["plan_digest"] for t in record.targets):
                return "operations_state_changed_reapproval_required"
        except Exception:
            return "operations_preflight_unavailable"
        return None

    def _write_nginx(self, target, body):
        spec = target["nginx"]
        p = safe_file(spec["managed_include"], spec["managed_root"])
        tmp = p.with_name(p.name + ".leafy-tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w") as stream:
                stream.write(body); stream.flush(); os.fsync(stream.fileno())
            original = p.read_text()
            os.replace(tmp, p)
            try:
                self._nginx_command(target, "-t")
            except Exception:
                # nginx has not received reload yet. Restore only the exact
                # candidate we just wrote, so a third-party edit is not clobbered.
                if p.read_text() == body:
                    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "w") as stream:
                        stream.write(original); stream.flush(); os.fsync(stream.fileno())
                    os.replace(tmp, p)
                raise
            self._nginx_command(target, "-s", "reload")
        finally: tmp.unlink(missing_ok=True)

    def _mutate(self, record, plan, cfg, target):
        action, params = record.action_type, record.action_parameters
        before = plan["pre_snapshot"]
        parent = self._parent(cfg, record.identity, params, action) if action in RESTORES else None
        if action in {"BLOCK_PATH", "RATE_LIMIT", "MAINTENANCE_MODE", "RESTORE_NGINX"}:
            if parent: body = parent["plan"]["pre_snapshot"]["managed_text"]
            else:
                line = "# operation " + plan["plan_digest"] + "\n"
                if action == "BLOCK_PATH": line += "location = " + params["path"] + " { return 403; }\n"
                elif action == "MAINTENANCE_MODE": line += "location / { return 503; }\n"
                else:
                    upstream = target["nginx"].get("rate_limit_upstream", "")
                    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", upstream): raise OperationsError("fixed_nginx_upstream_required")
                    line += f'location = {params["path"]} {{ limit_req zone=leafy_remediation burst={params["burst"]} nodelay; proxy_pass http://{upstream}; }}\n'
                body = before["managed_text"] + line
            self._write_nginx(target, body)
            after = self._nginx(target)
            if after["managed_text"] != body: raise OperationsError("nginx_readback_mismatch")
            return after
        if action in {"RESTRICT_BUCKET", "RESTORE_BUCKET"}:
            bucket = before["bucket"]
            policy = parent["plan"]["pre_snapshot"]["policy"] if parent else {"Version": "2012-10-17", "Statement": []}
            path = self._journal(cfg, record.remediation_id).with_suffix(".policy.json")
            atomic_json(path, policy, exclusive=True)
            try:
                self._mc(target, "anonymous", "set-json", str(path), target["minio"]["alias"] + "/" + bucket)
            finally: path.unlink(missing_ok=True)
            after = self._bucket(target, bucket)
            if after["policy_sha256"] != digest(policy): raise OperationsError("bucket_policy_readback_mismatch")
            return after
        if action in {"DISABLE_KEY", "ENABLE_KEY"}:
            resource = before["resource"]
            spec = target["minio"]
            key = os.environ[spec["service_accounts"][resource]["key_id_env"]]
            desired = parent["plan"]["pre_snapshot"]["status"] if parent else "off"
            self._mc(target, "--json", "admin", "user", "svcacct", "enable" if desired == "on" else "disable", spec["alias"], key)
            after = self._key(target, resource)
            if after["status"] != desired: raise OperationsError("key_state_readback_mismatch")
            return after
        if action == "RESTART_HOST_SVC":
            spec = target["host_service"]
            binary = self._binary(spec, "sc")
            self._run([binary, "stop", spec["service_name"]])
            for _ in range(50):
                stopped = self._service(target)
                if stopped["state"] == 1: break
                self.sleep(.2)
            else: raise OperationsError("service_stop_unconfirmed")
            self._run([binary, "start", spec["service_name"]])
            for _ in range(50):
                after = self._service(target)
                if after["state"] == 4 and after["pid"] > 0 and after["pid"] != before["pid"]:
                    return after
                self.sleep(.2)
            raise OperationsError("service_restart_unconfirmed")
        if action == "RECORD_INCIDENT":
            key = params["incident_key"]
            existing = self._incident(target, key)
            if existing["number"] is not None:
                return existing
            # Different signed requests for the same incident share this claim.
            claim = self._journal(cfg, "incident-" + key)
            atomic_json(claim, {"state": "CREATING", "incident_key": key}, exclusive=True)
            marker = "<!-- leafy-incident:" + key + " -->"
            number = self._github(target, "POST", "/repos/" + target["github"]["repository"] + "/issues",
                {"title": "Leafy incident " + key[:12], "body": marker + "\n\nObservation identity: `" + json.dumps(record.identity, sort_keys=True) + "`"}).get("number")
            if type(number) is not int or number < 1:
                raise OperationsError("incident_creation_unconfirmed")
            created = self._github(target, "GET", "/repos/" + target["github"]["repository"] + "/issues/" + str(number))
            if marker not in str(created.get("body", "")) or created.get("number") != number:
                raise OperationsError("incident_creation_unconfirmed")
            after = {"incident_key": key, "number": number}
            atomic_json(claim, {"state": "VERIFIED", **after})
            return after
        # Irreversible deletion: only the exact old, closed allowlisted .log
        # files and byte hashes approved before execution. Never recurse/glob.
        root = Path(target["clean_logs"]["root"])
        removed = 0
        for name, expected in before["files"].items():
            now = self._logs({**target, "clean_logs": {**target["clean_logs"], "files": [name]}})["files"][name]
            if now != expected: raise OperationsError("closed_log_changed")
            p = safe_file(root / name, root)
            os.unlink(p)
            if p.exists(): raise OperationsError("closed_log_delete_unconfirmed")
            removed += expected["size"]
        return {"removed_bytes": removed, "removed_files": sorted(before["files"]), "free_space_recovery_verified": False}

    def execute_record(self, record, target, approved_by=None):
        # A single configured executor serializes approval revalidation and
        # mutation. The Controller/Agent's single-worker lease is still required.
        with self._lock:
            return self._execute_record(record, target, approved_by)

    def _execute_record(self, record, target, approved_by=None):
        try:
            check_record(record, self.name)
            if record.action_type == "RECORD_INCIDENT" and record.action_parameters["incident_key"] != record.incident_key:
                raise OperationsError("incident_key_must_match_stored_record")
            if target != record.identity["target"] or approved_by and approved_by != record.approved_by:
                raise OperationsError("operations_approval_identity_mismatch")
            reason = self.validate_record(record)
            if reason: return blocked(record.action_type, target, reason)
            cfg, operator = self._target(record.identity, record.targets, record.action_type)
            plan = record.target_bindings[target]
            path = self._journal(cfg, record.remediation_id)
            with self._lock:
                if path.exists():
                    old = json.loads(safe_file(path).read_text())
                    if old.get("plan", {}).get("plan_digest") != plan["plan_digest"]:
                        return blocked(record.action_type, target, "operations_id_payload_conflict")
                    return ExecutionResult(record.action_type, target, "UNKNOWN", detail="operations_already_claimed_no_retry")
                journal = {"plan": plan, "state": "EXECUTING"}
                atomic_json(path, journal, exclusive=True)
        except Exception:
            return blocked(record.action_type, target, "operations_approval_or_preflight_rejected")
        try:
            # Recheck expiry after durable claim; never renew an approval.
            check_record(record, self.name)
            after = self._mutate(record, plan, cfg, operator)
            journal.update(state="VERIFIED", after=after)
            atomic_json(path, journal)
            # Result deliberately excludes raw mc status, config and credentials.
            return succeeded(record.action_type, target, "operations_effect_verified",
                             before={"plan_digest": plan["plan_digest"]}, after={"journal_id": record.remediation_id, "effect_sha256": digest(after)})
        except Exception:
            journal["state"] = "UNKNOWN"
            try: atomic_json(path, journal)
            except Exception: pass
            return ExecutionResult(record.action_type, target, "UNKNOWN", detail="operations_partial_or_unconfirmed_no_retry")
