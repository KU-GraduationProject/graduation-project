"""Bounded observation adapters; no arbitrary URLs, shell strings or captures.

Logger writes require a conditional (ETag/If-Match) administration contract.
Adapter-owned leases persist the original value BEFORE any write. TTL never
restores over an operator's intervening update. Capture data stays private.
"""
from __future__ import annotations

from datetime import datetime, timezone
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from urllib.parse import quote, urlsplit
import uuid

import httpx
import yaml

from executor.base import Executor, ExecutionResult, blocked, succeeded

ACTIONS = frozenset({"SET_LOG_LEVEL", "RESTORE_LOG_LEVEL", "PACKET_CAPTURE", "SILENCE_ALERT", "EXPIRE_SILENCE"})
RECOVERY_MAP = {"SET_LOG_LEVEL": "RESTORE_LOG_LEVEL", "SILENCE_ALERT": "EXPIRE_SILENCE"}
LEVELS = {"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "OFF"}
IDENTITY_FIELDS = ("site", "source", "service", "runtime", "target")
RID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
LOGGER = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}\Z")


def validate_parameters(action, parameters):
    if action not in ACTIONS or not isinstance(parameters, dict):
        raise ValueError("invalid_observation_action")
    fields = {
        "SET_LOG_LEVEL": {"logger", "level", "duration_seconds"},
        "RESTORE_LOG_LEVEL": {"source_record_id"},
        "PACKET_CAPTURE": {"duration_seconds", "packet_limit", "snaplen"},
        "SILENCE_ALERT": {"alertname", "duration_seconds"},
        "EXPIRE_SILENCE": {"source_record_id"},
    }[action]
    if set(parameters) != fields:
        raise ValueError("invalid_observation_parameters")
    for key in ("source_record_id", "logger", "alertname"):
        if key in parameters and (not isinstance(parameters[key], str)
                or not (RID if key == "source_record_id" else LOGGER).fullmatch(parameters[key])):
            raise ValueError("invalid_observation_resource")
    if "level" in parameters and (not isinstance(parameters["level"], str) or parameters["level"] not in LEVELS):
        raise ValueError("invalid_log_level")
    for key, maximum in (("duration_seconds", 3600 if action != "PACKET_CAPTURE" else 60),
                         ("packet_limit", 10000), ("snaplen", 512)):
        if key in parameters and (type(parameters[key]) is not int or not 1 <= parameters[key] <= maximum):
            raise ValueError("unbounded_observation_parameter")
    if action == "PACKET_CAPTURE" and parameters["snaplen"] < 64:
        raise ValueError("capture_snaplen_too_small")
    return dict(parameters)


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _origin(value):
    if not isinstance(value, str):
        raise ValueError("private_https_origin_required")
    url = urlsplit(value)
    if (url.scheme != "https" or not url.hostname or url.username or url.password
            or url.query or url.fragment or url.path not in ("", "/")):
        raise ValueError("private_https_origin_required")
    return value.rstrip("/")


class ObservabilityExecutor(Executor):
    name = "observability"

    def __init__(self, config_path=None, client=None, docker_client=None, clock=time.time):
        self.config_path, self._http, self._docker = config_path, client, docker_client
        self.clock = clock

    @property
    def http(self):
        if self._http is None:
            self._http = httpx.Client(timeout=10, follow_redirects=False, trust_env=False)
        return self._http

    @property
    def docker(self):
        if self._docker is None:
            import docker
            self._docker = docker.DockerClient(base_url="unix:///var/run/docker.sock", timeout=15)
        return self._docker

    def _config(self):
        path = self.config_path or os.getenv("REMEDIATION_OBSERVABILITY_CONFIG_PATH")
        if not path:
            raise ValueError("observability_not_configured")
        try:
            cfg = yaml.safe_load(Path(path).read_text())
            if (not isinstance(cfg, dict) or set(cfg) != {"version", "enabled", "state_dir", "targets"}
                    or type(cfg["version"]) is not int or cfg["version"] != 1 or cfg["enabled"] is not True
                    or not Path(cfg["state_dir"]).is_absolute() or not isinstance(cfg["targets"], dict)):
                raise ValueError()
            return cfg
        except Exception:
            raise ValueError("invalid_or_disabled_observability_config") from None

    def _rule(self, identity, targets, action):
        cfg = self._config()
        if (not isinstance(identity, dict) or set(identity) != set(IDENTITY_FIELDS)
                or any(not isinstance(v, str) or not v.strip() or v != v.strip() for v in identity.values())
                or list(targets) != [identity["target"]]):
            raise ValueError("one_exact_observation_target_required")
        rule = cfg["targets"].get(identity["target"])
        if (not isinstance(rule, dict) or rule.get("identity") != identity or action not in rule.get("actions", [])
                or not isinstance(rule.get("labels"), dict)
                or set(rule) - {"identity", "labels", "actions", "logger_api", "token_env", "container_id", "image_id", "packet_capture", "alertmanager"}):
            raise ValueError("observation_target_not_allowlisted")
        if "logger_api" in rule and (not isinstance(rule["logger_api"], dict) or set(rule["logger_api"]) != {"origin", "conditional_updates_verified", "allowed_loggers"}):
            raise ValueError("invalid_logger_config")
        if "logger_api" in rule and (not isinstance(rule["logger_api"]["allowed_loggers"], list)
                or any(not isinstance(name, str) or not LOGGER.fullmatch(name) for name in rule["logger_api"]["allowed_loggers"])):
            raise ValueError("invalid_allowed_logger_names")
        if "packet_capture" in rule and (not isinstance(rule["packet_capture"], dict) or set(rule["packet_capture"]) - {"artifact_volume"} != {"helper_image_id", "max_bytes", "max_total_bytes"}):
            raise ValueError("invalid_capture_config")
        if "alertmanager" in rule and (not isinstance(rule["alertmanager"], dict) or set(rule["alertmanager"]) != {"origin"}):
            raise ValueError("invalid_alertmanager_config")
        return cfg, rule

    @contextmanager
    def _db(self, cfg):
        directory = Path(cfg["state_dir"])
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory.is_symlink():
            raise ValueError("unsafe_observation_state_directory")
        os.chmod(directory, 0o700)
        path = directory / "observation.sqlite3"
        db = sqlite3.connect(path, timeout=5, isolation_level=None)
        os.chmod(path, 0o600)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("CREATE TABLE IF NOT EXISTS records (rid TEXT PRIMARY KEY, scope TEXT NOT NULL, body TEXT NOT NULL)")
        try:
            with db:
                yield db
        finally:
            db.close()

    def _load(self, cfg, rid):
        with self._db(cfg) as db:
            row = db.execute("SELECT body FROM records WHERE rid=?", (rid,)).fetchone()
        return json.loads(row[0]) if row else None

    def _save(self, cfg, row):
        with self._db(cfg) as db:
            db.execute("UPDATE records SET body=? WHERE rid=?", (json.dumps(row), row["rid"]))

    def _transition(self, cfg, original, replacement):
        with self._db(cfg) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT body FROM records WHERE rid=?", (original["rid"],)).fetchone()
            if not row or json.loads(row[0]) != original:
                return False
            db.execute("UPDATE records SET body=? WHERE rid=?", (json.dumps(replacement), original["rid"]))
            db.commit()
        return True

    def _claim(self, cfg, record, scope, initial):
        row = {"rid": record.remediation_id, "scope": scope, "identity": record.identity,
               "request_hash": _hash({"action": record.action_type, "parameters": record.action_parameters,
                                      "plan": record.target_bindings}), "state": "PENDING", **initial}
        with self._db(cfg) as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT body FROM records WHERE rid=?", (record.remediation_id,)).fetchone()
            if existing:
                old = json.loads(existing[0])
                if old["request_hash"] != row["request_hash"]:
                    raise ValueError("observation_record_payload_conflict")
                return old, False
            if scope and db.execute("SELECT 1 FROM records WHERE scope=? AND json_extract(body,'$.state') IN ('PENDING','APPLIED','UNKNOWN','RESTORING')", (scope,)).fetchone():
                raise ValueError("observation_scope_has_unresolved_lease")
            db.execute("INSERT INTO records VALUES (?,?,?)", (record.remediation_id, scope, json.dumps(row)))
            db.commit()
        return row, True

    def _headers(self, rule):
        key = rule.get("token_env")
        token = os.getenv(key, "") if isinstance(key, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{1,127}", key) else ""
        if not token:
            raise ValueError("observation_token_not_configured")
        return {"Authorization": "Bearer " + token}

    def _logger(self, rule, name):
        logger = rule.get("logger_api") or {}
        if logger.get("conditional_updates_verified") is not True or name not in logger.get("allowed_loggers", []):
            raise ValueError("conditional_logger_contract_not_verified")
        url = _origin(logger["origin"]) + "/actuator/loggers/" + quote(name, safe="")
        response = self.http.get(url, headers=self._headers(rule))
        if response.status_code != 200:
            raise ValueError("logger_read_unavailable")
        body, version = response.json(), response.headers.get("etag")
        level = body.get("configuredLevel")
        if (not isinstance(version, str) or not version or len(version) > 256 or "\n" in version or "\r" in version
                or level is not None and level not in LEVELS):
            raise ValueError("conditional_logger_version_required")
        return url, {"configured_level": level, "etag": version}

    def _container(self, identity, rule):
        if identity["runtime"] != "container":
            raise ValueError("capture_requires_container_namespace")
        cid = rule.get("container_id")
        image = rule.get("image_id")
        if not isinstance(cid, str) or not re.fullmatch(r"[a-f0-9]{64}", cid):
            raise ValueError("full_capture_container_id_required")
        container = self.docker.containers.get(cid)
        container.reload()
        doc = container.attrs
        labels, host = (doc.get("Config") or {}).get("Labels") or {}, doc.get("HostConfig") or {}
        if (doc.get("Id") != cid or doc.get("Image") != image or doc.get("Name", "").lstrip("/") != identity["target"]
                or not rule["labels"] or any(labels.get(k) != v for k, v in rule["labels"].items())
                or labels.get("io.leafy.remediation") != "workload" or host.get("Privileged")
                or host.get("NetworkMode") == "host" or host.get("PidMode") == "host"
                or not (doc.get("State") or {}).get("Running")
                or any("docker.sock" in str(m) or "docker_engine" in str(m) for m in doc.get("Mounts", []))):
            raise ValueError("capture_container_identity_changed")
        return {"container_id": cid, "image_id": image, "started_at": doc["State"].get("StartedAt"),
                "labels": {k: labels.get(k) for k in rule["labels"]}}

    @staticmethod
    def _silence_owned(actual, expected):
        try:
            matchers = lambda rows: sorted((m["name"], m["value"], m["isRegex"], m["isEqual"]) for m in rows)
            instant = lambda value: datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
            return (matchers(actual["matchers"]) == matchers(expected["matchers"])
                    and actual["comment"] == expected["comment"] and actual["createdBy"] == expected["createdBy"]
                    and instant(actual["startsAt"]) == instant(expected["startsAt"])
                    and instant(actual["endsAt"]) == instant(expected["endsAt"]))
        except (TypeError, ValueError, KeyError):
            return False

    def plan_record(self, identity, targets, action_type, parameters):
        from executor.managed import seal_plan
        parameters = validate_parameters(action_type, parameters)
        cfg, rule = self._rule(identity, targets, action_type)
        if action_type == "SET_LOG_LEVEL":
            _, pre = self._logger(rule, parameters["logger"])
        elif action_type == "RESTORE_LOG_LEVEL":
            row = self._load(cfg, parameters["source_record_id"])
            if not row or row["identity"] != identity or row.get("kind") != "logger" or row["state"] != "APPLIED":
                raise ValueError("verified_logger_parent_required")
            _, current = self._logger(rule, row["logger"])
            if current != row["applied"]:
                raise ValueError("logger_changed_after_remediation")
            pre = {"parent": row["rid"], "logger": row["logger"], "current": current, "original": row["original"]}
        elif action_type == "PACKET_CAPTURE":
            pre = self._container(identity, rule)
            helper = (rule.get("packet_capture") or {}).get("helper_image_id", "")
            if not isinstance(helper, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", helper):
                raise ValueError("pinned_capture_helper_required")
            image = self.docker.images.get(helper)  # Never pull an image.
            if image.attrs.get("Id") != helper:
                raise ValueError("capture_helper_image_changed")
            maximum = (rule.get("packet_capture") or {}).get("max_bytes", 0)
            if type(maximum) is not int or not 1024 <= maximum <= 16 * 1024 * 1024 or (parameters["snaplen"] + 16) * parameters["packet_limit"] + 24 > maximum:
                raise ValueError("capture_exceeds_private_artifact_budget")
            total = rule["packet_capture"].get("max_total_bytes")
            if type(total) is not int or not maximum <= total <= 1024 * 1024 * 1024:
                raise ValueError("private_capture_storage_quota_required")
            volume = rule["packet_capture"].get("artifact_volume")
            if volume is not None and (not isinstance(volume, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", volume)):
                raise ValueError("invalid_private_capture_volume")
            capture_root = Path(cfg["state_dir"]) / "captures"
            used = sum(p.stat().st_size for p in capture_root.rglob("*") if p.is_file() and not p.is_symlink()) if capture_root.exists() else 0
            if used + maximum > total:
                raise ValueError("private_capture_storage_quota_exhausted")
            pre["helper_image_id"] = helper
        elif action_type == "SILENCE_ALERT":
            origin = _origin((rule.get("alertmanager") or {})["origin"])
            response = self.http.get(origin + "/api/v2/status", headers=self._headers(rule))
            if response.status_code != 200:
                raise ValueError("alertmanager_unavailable")
            pre = {"alertname": parameters["alertname"], "identity": identity}
        else:
            row = self._load(cfg, parameters["source_record_id"])
            if not row or row["identity"] != identity or row.get("kind") != "silence" or row["state"] != "APPLIED":
                raise ValueError("verified_silence_parent_required")
            origin = _origin(rule["alertmanager"]["origin"])
            response = self.http.get(origin + "/api/v2/silence/" + row["silence_id"], headers=self._headers(rule))
            if response.status_code != 200 or not self._silence_owned(response.json(), row["expected"]):
                raise ValueError("silence_changed_after_creation")
            pre = {"parent": row["rid"], "silence_id": row["silence_id"]}
        plan = {"executor": self.name, "identity": identity, "target": identity["target"], "action_type": action_type,
                "parameters": parameters, "operator_config": {**rule, "state_dir": cfg["state_dir"]}, "pre_snapshot": pre}
        return {identity["target"]: seal_plan(plan)}

    def validate_record(self, record):
        from executor.managed import valid_plan_digest
        try:
            fresh = self.plan_record(record.identity, record.targets, record.action_type, record.action_parameters)
            if any(not valid_plan_digest(record.target_bindings[t]) or record.target_bindings[t]["plan_digest"] != fresh[t]["plan_digest"] for t in record.targets):
                return "observation_plan_changed_reapproval_required"
        except Exception:
            return "observation_plan_validation_failed"
        return None

    def execute_record(self, record, target, approved_by=None):
        from executor.managed import check_record
        mutated = False
        cfg = row = None
        action = record.action_type
        try:
            check_record(record, self.name)
            if target != record.identity["target"] or approved_by not in (None, record.approved_by):
                raise ValueError("observation_approval_mismatch")
            cfg, rule = self._rule(record.identity, record.targets, action)
            # Idempotent reads precede fresh-plan checking: our successful write
            # necessarily changes the original snapshot.
            existing = self._load(cfg, record.remediation_id)
            if existing:
                expected = _hash({"action": action, "parameters": record.action_parameters, "plan": record.target_bindings})
                if existing["request_hash"] != expected:
                    raise ValueError("observation_record_payload_conflict")
                return self._cached(action, target, existing)
            if self.validate_record(record):
                raise ValueError("observation_plan_changed_reapproval_required")
            p = record.action_parameters
            pre = record.target_bindings[target]["pre_snapshot"]
            if action == "SET_LOG_LEVEL":
                url, current = self._logger(rule, p["logger"])
                row, claimed = self._claim(cfg, record, _hash([record.identity, p["logger"]]),
                    {"kind": "logger", "logger": p["logger"], "original": current, "operator_hash": _hash(rule),
                     "desired": p["level"], "due_at": self.clock() + p["duration_seconds"]})
                if not claimed:
                    return self._cached(action, target, row)
                check_record(record, self.name)
                mutated = True
                response = self.http.post(url, headers={**self._headers(rule), "If-Match": current["etag"]}, json={"configuredLevel": p["level"]})
                if response.status_code not in (200, 204):
                    if response.status_code == 412:
                        row["state"] = "NEEDS_REVIEW"; self._save(cfg, row)
                        return blocked(action, target, "logger_changed_before_write")
                    raise ValueError("logger_write_unconfirmed")
                _, applied = self._logger(rule, p["logger"])
                if applied["configured_level"] != p["level"] or applied["etag"] == current["etag"]:
                    raise ValueError("logger_effect_unconfirmed")
                row.update(state="APPLIED", applied=applied)
                self._save(cfg, row)
                return succeeded(action, target, "logger_level_verified_ttl_lease_persisted", after={"due_at": row["due_at"]})
            if action == "RESTORE_LOG_LEVEL":
                row, claimed = self._claim(cfg, record, "", {"kind": "logger_restore", "parent": pre["parent"]})
                if not claimed:
                    return self._cached(action, target, row)
                parent = self._load(cfg, pre["parent"])
                result = self._restore_logger(cfg, rule, parent)
                row["state"] = "COMPLETE" if result["state"] == "RESTORED" else "NEEDS_REVIEW"
                self._save(cfg, row)
                return succeeded(action, target, "original_logger_level_restored") if row["state"] == "COMPLETE" else blocked(action, target, "logger_restore_requires_review")
            if action == "PACKET_CAPTURE":
                row, claimed = self._claim(cfg, record, _hash(["capture-storage", cfg["state_dir"]]), {"kind": "capture"})
                if not claimed:
                    return self._cached(action, target, row)
                check_record(record, self.name)
                mutated = True
                artifact = self._capture(cfg, rule, record, pre)
                row.update(state="COMPLETE", artifact=artifact)
                self._save(cfg, row)
                return succeeded(action, target, "bounded_capture_artifact_verified", after=artifact)
            if action == "SILENCE_ALERT":
                row, claimed = self._claim(cfg, record, "", {"kind": "silence"})
                if not claimed:
                    return self._cached(action, target, row)
                origin = _origin(rule["alertmanager"]["origin"])
                matchers = [{"name": k, "value": v, "isRegex": False, "isEqual": True}
                            for k, v in {**record.identity, "alertname": p["alertname"]}.items()]
                start = datetime.fromtimestamp(self.clock(), timezone.utc)
                payload = {"matchers": matchers, "startsAt": start.isoformat(),
                           "endsAt": datetime.fromtimestamp(self.clock() + p["duration_seconds"], timezone.utc).isoformat(),
                           "createdBy": "leafy-remediation", "comment": "Approved remediation " + record.remediation_id}
                check_record(record, self.name)
                mutated = True
                response = self.http.post(origin + "/api/v2/silences", headers=self._headers(rule), json=payload)
                if response.status_code != 200:
                    raise ValueError("silence_creation_unconfirmed")
                sid = response.json().get("silenceID")
                if not isinstance(sid, str) or not re.fullmatch(r"[A-Fa-f0-9-]{36}", sid):
                    raise ValueError("invalid_silence_identifier")
                response = self.http.get(origin + "/api/v2/silence/" + sid, headers=self._headers(rule))
                actual = response.json() if response.status_code == 200 else {}
                if not self._silence_owned(actual, payload) or actual.get("status", {}).get("state") != "active":
                    raise ValueError("silence_scope_unconfirmed")
                row.update(state="APPLIED", silence_id=sid, expected=payload)
                self._save(cfg, row)
                return succeeded(action, target, "identity_scoped_silence_verified", after={"silence_id": sid, "ends_at": payload["endsAt"]})
            row, claimed = self._claim(cfg, record, "", {"kind": "silence_restore", "parent": pre["parent"]})
            if not claimed:
                return self._cached(action, target, row)
            parent = self._load(cfg, pre["parent"])
            origin = _origin(rule["alertmanager"]["origin"])
            response = self.http.get(origin + "/api/v2/silence/" + parent["silence_id"], headers=self._headers(rule))
            current = response.json() if response.status_code == 200 else {}
            if not self._silence_owned(current, parent["expected"]):
                raise ValueError("silence_changed_after_creation")
            check_record(record, self.name)
            mutated = True
            response = self.http.delete(origin + "/api/v2/silence/" + parent["silence_id"], headers=self._headers(rule))
            if response.status_code != 200:
                raise ValueError("silence_expiration_unconfirmed")
            response = self.http.get(origin + "/api/v2/silence/" + parent["silence_id"], headers=self._headers(rule))
            if response.status_code != 200 or response.json().get("status", {}).get("state") != "expired":
                raise ValueError("silence_expiration_unconfirmed")
            row["state"] = "COMPLETE"; parent["state"] = "RESTORED"
            self._save(cfg, parent); self._save(cfg, row)
            return succeeded(action, target, "owned_silence_expired")
        except Exception:
            if row and cfg:
                row["state"] = "UNKNOWN" if mutated else "NEEDS_REVIEW"
                try: self._save(cfg, row)
                except Exception: pass
            return ExecutionResult(action, target, "UNKNOWN", detail="observation_effect_unconfirmed_no_retry") if mutated else blocked(action, target, "observation_preflight_rejected")

    def _cached(self, action, target, row):
        if row["state"] in ("APPLIED", "COMPLETE", "RESTORED"):
            return succeeded(action, target, "durable_observation_result_reused", after=row.get("artifact", {}))
        return ExecutionResult(action, target, "UNKNOWN", detail="observation_lease_unresolved_no_retry")

    def _restore_logger(self, cfg, rule, row):
        if not row or row["state"] != "APPLIED" or row.get("operator_hash") != _hash(rule):
            return {"state": "NEEDS_REVIEW"}
        url, current = self._logger(rule, row["logger"])
        if current != row["applied"]:
            row["state"] = "NEEDS_REVIEW"; self._save(cfg, row)
            return {"state": row["state"], "reason": "intervening_logger_change"}
        replacement = {**row, "state": "RESTORING"}
        if not self._transition(cfg, row, replacement):
            return {"state": "NEEDS_REVIEW", "reason": "logger_lease_claimed_elsewhere"}
        row = replacement
        try:
            response = self.http.post(url, headers={**self._headers(rule), "If-Match": current["etag"]}, json={"configuredLevel": row["original"]["configured_level"]})
            if response.status_code == 412:
                row["state"] = "NEEDS_REVIEW"; self._save(cfg, row)
                return {"state": row["state"], "reason": "intervening_logger_change"}
            if response.status_code not in (200, 204):
                raise ValueError()
            _, after = self._logger(rule, row["logger"])
            if after["configured_level"] != row["original"]["configured_level"]:
                raise ValueError()
            row["state"] = "RESTORED"; self._save(cfg, row)
            return {"state": "RESTORED"}
        except Exception:
            row["state"] = "UNKNOWN"; self._save(cfg, row)
            return {"state": "UNKNOWN"}

    def run_due(self, store=None):
        """Restore adapter-owned durable TTL leases. No blind retry after crash."""
        try:
            cfg = self._config()
        except ValueError:
            return []
        with self._db(cfg) as db:
            rows = [json.loads(r[0]) for r in db.execute("SELECT body FROM records")]
        result = []
        for row in rows:
            if row.get("kind") != "logger" or row["state"] != "APPLIED" or row["due_at"] > self.clock():
                continue
            try:
                _, rule = self._rule(row["identity"], [row["identity"]["target"]], "SET_LOG_LEVEL")
                restored = self._restore_logger(cfg, rule, row)
            except Exception:
                restored = {"state": "NEEDS_REVIEW", "reason": "logger_restore_unavailable"}
            result.append({"remediation_id": row["rid"], "action_type": "RESTORE_LOG_LEVEL", **restored})
        return result

    def _capture(self, cfg, rule, record, pre):
        from executor.managed import check_record
        p = record.action_parameters
        # Recheck storage after the exclusive capture lease is persisted.
        self.plan_record(record.identity, record.targets, record.action_type, p)
        self._container(record.identity, rule)  # Match immutable ID again before helper creation.
        directory = Path(cfg["state_dir"]) / "captures" / uuid.uuid4().hex
        directory.mkdir(mode=0o700, parents=True)
        path = directory / "traffic.pcap"
        helper = None
        volume = rule["packet_capture"].get("artifact_volume")
        mount_source = volume or str(directory)
        output = "/capture/" + (directory.name + "/" if volume else "") + "traffic.pcap"
        try:
            helper = self.docker.containers.create(
                pre["helper_image_id"], entrypoint=["timeout", str(p["duration_seconds"]) + "s", "tcpdump"],
                command=["-nn", "-p", "-i", "any", "-s", str(p["snaplen"]), "-c", str(p["packet_limit"]), "-w", output],
                network_mode="container:" + pre["container_id"], user="0:0", read_only=True,
                cap_drop=["ALL"], cap_add=["NET_RAW"], security_opt=["no-new-privileges:true"],
                volumes={mount_source: {"bind": "/capture", "mode": "rw"}}, pids_limit=32,
                mem_limit=64 * 1024 * 1024, log_config={"Type": "none"}, auto_remove=False)
            check_record(record, self.name)
            if self._container(record.identity, rule) != {k: v for k, v in pre.items() if k != "helper_image_id"}:
                raise ValueError("capture_target_changed_after_helper_creation")
            helper.start()
            status = helper.wait(timeout=p["duration_seconds"] + 10)
            if status.get("StatusCode") not in (0, 124):
                raise ValueError("capture_helper_failed")
            if path.is_symlink() or not path.is_file() or not 24 <= path.stat().st_size <= rule["packet_capture"]["max_bytes"]:
                raise ValueError("capture_artifact_unbounded_or_missing")
            with path.open("rb") as fh:
                if fh.read(4) not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
                    raise ValueError("capture_artifact_not_pcap")
            os.chmod(path, 0o600)
            # Artifact IDs only: no raw packets or destination addresses in audit.
            return {"artifact_id": directory.name, "bytes": path.stat().st_size,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        finally:
            if helper is not None:
                try: helper.stop(timeout=2)
                except Exception: pass
                helper.remove(force=True)
