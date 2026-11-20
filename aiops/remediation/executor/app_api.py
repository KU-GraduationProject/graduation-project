"""Operator-contracted application admin API executor.

No Leafy admin endpoint is assumed here. An operator must supply a verified API
contract and exact allowlists. Requests use HTTPS, conditional writes and stable
idempotency keys; uncertain writes are never retried by this adapter.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
from string import Formatter
import time
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError
import yaml

from executor.base import ExecutionResult, Executor, blocked, succeeded
import store as store_mod

CONFIG_ENV = "REMEDIATION_APP_API_CONFIG_PATH"
ACTIONS = frozenset({"LOCK_ACCOUNT", "REVOKE_SESSION", "DISABLE_FEATURE",
                     "UNLOCK_ACCOUNT", "ENABLE_FEATURE"})
FEATURE_ACTIONS = frozenset({"DISABLE_FEATURE", "ENABLE_FEATURE"})
IDENTITY_FIELDS = ("site", "service", "source", "runtime", "target")
PLACEHOLDERS = frozenset({"resource_id", "target", "action_type", "duration_seconds", "reason", "expires_at"})
RESOURCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
JSON_FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
PROTECTED_ROLES = frozenset({"admin", "administrator", "superadmin", "superuser", "root", "owner", "system", "service"})
PROTECTED_RESOURCES = frozenset({"admin", "administrator", "root", "system", "service"})


def _protected_role(value):
    normalized = re.sub(r"[^a-z0-9]", "", value.lower().removeprefix("role_"))
    return normalized in PROTECTED_ROLES or "admin" in normalized


class AppApiError(ValueError):
    pass


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Readback(StrictModel):
    path: str
    target_field: str
    resource_field: str
    action_field: str
    version_field: str
    state_fields: dict[str, Any] = Field(min_length=1)
    role_field: str | None = None
    expires_at_field: str | None = None
    idempotency_field: str | None = None


class ActionContract(StrictModel):
    method: Literal["POST", "PUT", "PATCH", "DELETE"]
    path: str
    body: dict[str, Any]
    readback: Readback


class ApiTarget(StrictModel):
    identity: dict[str, str]
    api_contract_verified: Literal[True]
    contract_source: str = Field(min_length=1, max_length=1024)
    base_url: str
    token_env: str | None = None
    token_file: str | None = None
    token_header: Literal["Authorization", "X-API-Key"] = "Authorization"
    token_scheme: Literal["Bearer", "Token", "raw"] = "Bearer"
    timeout_seconds: int = Field(default=10, ge=1, le=30)
    account_allowlist: list[str] = Field(default_factory=list)
    feature_allowlist: list[str] = Field(default_factory=list)
    allowed_account_roles: list[str] = Field(default_factory=list)
    actions: dict[str, ActionContract] = Field(min_length=1)


class ApiConfig(StrictModel):
    version: Literal[1]
    targets: dict[str, ApiTarget] = Field(min_length=1)


def _identity(value):
    if (not isinstance(value, dict) or set(value) != set(IDENTITY_FIELDS)
            or any(not isinstance(value[k], str) or not value[k].strip()
                   or value[k] != value[k].strip() or value[k].lower() in {"unknown", "none", "n/a", "stdout", "stderr"}
                   for k in IDENTITY_FIELDS)
            or value["runtime"] not in {"container", "host"}):
        raise AppApiError("invalid_app_identity")
    return dict(value)


def _origin(value):
    try:
        parsed = urlsplit(value)
        port = parsed.port
        host = parsed.hostname
        if (parsed.scheme != "https" or not host or parsed.username or parsed.password
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment or port == 0):
            raise ValueError()
        if host.lower() in {"localhost", "metadata.google.internal", "metadata"} or host.lower().endswith(".localhost"):
            raise ValueError()
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]", host)
                    or re.fullmatch(r"[0-9.]+", host) or host.lower().startswith("0x")):
                raise ValueError()
        else:
            if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved:
                raise ValueError()
    except (ValueError, TypeError):
        raise AppApiError("invalid_app_api_origin") from None
    return value.rstrip("/")


def _fields(value):
    """Validate simple placeholders; attribute/index traversal and format specs are forbidden."""
    found = set()
    if isinstance(value, str):
        try:
            for _, field, spec, conversion in Formatter().parse(value):
                if field is not None:
                    if field not in PLACEHOLDERS or spec or conversion:
                        raise ValueError()
                    found.add(field)
        except ValueError:
            raise AppApiError("invalid_app_api_template") from None
    elif isinstance(value, dict):
        for key, part in value.items():
            if not isinstance(key, str) or "{" in key or "}" in key:
                raise AppApiError("invalid_app_api_body_key")
            found.update(_fields(part))
    elif isinstance(value, list):
        for part in value:
            found.update(_fields(part))
    elif value is not None and type(value) not in (bool, int, float):
        raise AppApiError("invalid_app_api_template_value")
    return found


def _path(value):
    if (not isinstance(value, str) or not value.startswith("/") or value.startswith("//")
            or any(c in value for c in ("?", "#", "\\", "%", "\r", "\n"))
            or any(segment in {".", ".."} for segment in value.split("/"))
            or "://" in value):
        raise AppApiError("invalid_app_api_path")
    _fields(value)
    return value


def _render(value, context):
    if isinstance(value, str):
        if value.startswith("{") and value.endswith("}") and value[1:-1] in PLACEHOLDERS:
            key = value[1:-1]
            if key not in context:
                raise AppApiError("missing_app_api_template_parameter")
            return context[key]
        try:
            return value.format_map(context)
        except (KeyError, ValueError):
            raise AppApiError("missing_app_api_template_parameter") from None
    if isinstance(value, dict):
        return {k: _render(v, context) for k, v in value.items()}
    if isinstance(value, list):
        return [_render(v, context) for v in value]
    return value


def _field(document, path):
    current = document
    for key in path.split("."):
        if not isinstance(current, dict) or key not in current:
            raise AppApiError("app_api_readback_field_missing")
        current = current[key]
    return current


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _digest(value):
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _instant(value):
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError()
        return result.timestamp()
    except (ValueError, TypeError, OverflowError):
        raise AppApiError("invalid_app_api_timestamp") from None


class AppApiExecutor(Executor):
    name = "app_api"
    changes_system = True

    def __init__(self, client=None, config_path=None):
        self._client = client
        self.config_path = config_path

    def _config(self):
        path = self.config_path or os.getenv(CONFIG_ENV)
        if not path:
            raise AppApiError("app_api_not_configured")
        try:
            config = ApiConfig.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
        except (OSError, ValueError, ValidationError, yaml.YAMLError):
            raise AppApiError("invalid_app_api_config") from None
        for target, row in config.targets.items():
            identity = _identity(row.identity)
            if target != identity["target"] or not RESOURCE.fullmatch(target):
                raise AppApiError("app_api_target_identity_mismatch")
            _origin(row.base_url)
            if bool(row.token_env) == bool(row.token_file):
                raise AppApiError("app_api_requires_one_secret_reference")
            if row.token_env and not ENV_NAME.fullmatch(row.token_env):
                raise AppApiError("invalid_app_api_secret_reference")
            if row.token_file and not Path(row.token_file).is_absolute():
                raise AppApiError("invalid_app_api_secret_reference")
            for allowed in (row.account_allowlist, row.feature_allowlist):
                if len(allowed) != len(set(allowed)) or any(not RESOURCE.fullmatch(v) for v in allowed):
                    raise AppApiError("invalid_app_api_resource_allowlist")
            if any(v.lower() in PROTECTED_RESOURCES for v in row.account_allowlist):
                raise AppApiError("protected_app_account")
            if any(v != v.strip() or not v or _protected_role(v) for v in row.allowed_account_roles):
                raise AppApiError("protected_app_role")
            for action, contract in row.actions.items():
                if action not in ACTIONS:
                    raise AppApiError("unsupported_app_api_action")
                rb = contract.readback
                _path(contract.path)
                _path(rb.path)
                request_fields = _fields(contract.path) | _fields(contract.body)
                if "resource_id" not in request_fields or "resource_id" not in _fields(rb.path):
                    raise AppApiError("app_api_resource_binding_required")
                if _fields(contract.path) - {"resource_id", "target", "action_type"} or _fields(rb.path) - {"resource_id", "target", "action_type"}:
                    raise AppApiError("unsafe_app_api_path_parameter")
                paths = [rb.target_field, rb.resource_field, rb.action_field, rb.version_field,
                         *rb.state_fields, *(p for p in (rb.role_field, rb.expires_at_field, rb.idempotency_field) if p)]
                if any(not JSON_FIELD.fullmatch(p) for p in paths):
                    raise AppApiError("invalid_app_api_readback_field")
                if any(type(v) not in (str, bool, int) or isinstance(v, str) and ("{" in v or "}" in v)
                       for v in rb.state_fields.values()):
                    raise AppApiError("invalid_app_api_expected_state")
                if action in {"LOCK_ACCOUNT", "REVOKE_SESSION", "UNLOCK_ACCOUNT"} and (
                        not row.account_allowlist or not row.allowed_account_roles or not rb.role_field):
                    raise AppApiError("app_api_account_role_contract_required")
                if action in FEATURE_ACTIONS and not row.feature_allowlist:
                    raise AppApiError("app_api_feature_allowlist_required")
                if action == "LOCK_ACCOUNT" and (not rb.expires_at_field or not
                        request_fields.intersection({"duration_seconds", "expires_at"})):
                    raise AppApiError("app_api_bounded_lock_contract_required")
        return config

    def _parameters(self, row, action, parameters):
        if action not in ACTIONS or action not in row.actions:
            raise AppApiError("app_api_action_not_configured")
        if not isinstance(parameters, dict):
            raise AppApiError("invalid_app_api_parameters")
        resource_key = "feature_id" if action in FEATURE_ACTIONS else "account_id"
        allowed_keys = {resource_key, "reason"} | ({"duration_seconds"} if action == "LOCK_ACCOUNT" else set())
        if set(parameters) - allowed_keys:
            raise AppApiError("unsupported_app_api_parameter")
        resource = parameters.get(resource_key)
        allowlist = row.feature_allowlist if action in FEATURE_ACTIONS else row.account_allowlist
        if not isinstance(resource, str) or not RESOURCE.fullmatch(resource) or resource not in allowlist:
            raise AppApiError("app_api_resource_not_allowed")
        result = {resource_key: resource}
        reason = parameters.get("reason", "approved_remediation")
        if not isinstance(reason, str) or not reason or len(reason) > 256 or any(c in reason for c in ("\r", "\n")):
            raise AppApiError("invalid_app_api_reason")
        result["reason"] = reason
        if action == "LOCK_ACCOUNT":
            duration = parameters.get("duration_seconds")
            if type(duration) is not int or not 1 <= duration <= 86400:
                raise AppApiError("app_api_lock_duration_required")
            result["duration_seconds"] = duration
        return result, resource

    @contextmanager
    def _client_scope(self):
        if self._client is not None:
            yield self._client
        else:
            # trust_env=False avoids forwarding the admin credential through ambient proxies.
            with httpx.Client(follow_redirects=False, trust_env=False, timeout=10) as client:
                yield client

    def _headers(self, row):
        try:
            token = os.getenv(row.token_env, "") if row.token_env else Path(row.token_file).read_text(encoding="utf-8").strip()
        except OSError:
            raise AppApiError("app_api_secret_unavailable") from None
        if not token or token != token.strip() or any(c in token for c in ("\r", "\n")):
            raise AppApiError("app_api_secret_unavailable")
        prefix = "" if row.token_scheme == "raw" else row.token_scheme + " "
        return {row.token_header: prefix + token, "Accept": "application/json"}

    def _request(self, row, method, path, **kwargs):
        url = _origin(row.base_url) + _path(path)
        with self._client_scope() as client:
            return client.request(method, url, timeout=row.timeout_seconds, follow_redirects=False, **kwargs)

    def _read(self, row, contract, context, headers):
        response = self._request(row, "GET", _render(contract.readback.path, context), headers=headers)
        if not 200 <= response.status_code < 300:
            raise AppApiError("app_api_preflight_or_readback_failed")
        try:
            document = response.json()
        except (ValueError, TypeError):
            raise AppApiError("invalid_app_api_readback") from None
        rb = contract.readback
        if (_field(document, rb.target_field) != context["target"]
                or _field(document, rb.resource_field) != context["resource_id"]):
            raise AppApiError("app_api_returned_identity_mismatch")
        version = _field(document, rb.version_field)
        if type(version) not in (str, int) or not str(version) or any(c in str(version) for c in ("\r", "\n")):
            raise AppApiError("invalid_app_api_resource_version")
        role = None
        if context["action_type"] not in FEATURE_ACTIONS:
            role = _field(document, rb.role_field)
            if not isinstance(role, str) or role not in row.allowed_account_roles or _protected_role(role):
                raise AppApiError("protected_or_unapproved_app_role")
        state = {path: _field(document, path) for path in rb.state_fields}
        return document, {"target": context["target"], "resource_id": context["resource_id"],
                          "version": str(version), "role": role, "state": state}

    @staticmethod
    def _desired(contract, summary):
        return all(type(summary["state"].get(k)) is type(v) and summary["state"][k] == v
                   for k, v in contract.readback.state_fields.items())

    def _resolve(self, identity, targets, action_type, parameters):
        identity = _identity(identity)
        config = self._config()
        if list(targets or ()) != [identity["target"]]:
            raise AppApiError("app_api_targets_do_not_match_identity")
        row = config.targets.get(identity["target"])
        if row is None or row.identity != identity:
            raise AppApiError("unmapped_app_api_identity")
        params, resource = self._parameters(row, action_type, parameters)
        context = {"target": identity["target"], "resource_id": resource, "action_type": action_type, **params}
        return row, row.actions[action_type], params, context

    def plan_record(self, identity, targets, action_type, parameters):
        row, contract, params, context = self._resolve(identity, targets, action_type, parameters)
        try:
            _, summary = self._read(row, contract, context, self._headers(row))
        except httpx.HTTPError:
            raise AppApiError("app_api_preflight_unavailable") from None
        if self._desired(contract, summary):
            raise AppApiError("app_api_desired_state_already_present")
        return {identity["target"]: {"executor": self.name, "identity": dict(identity),
                "action_type": action_type, "parameters": params,
                "config_sha256": _digest(row.model_dump()), "resource": summary}}

    def _validate(self, record, check_state=True):
        if (record.executor_name != self.name
                or not re.fullmatch(r"[a-f0-9]{64}", record.incident_key or "")
                or record.action_hash != store_mod.action_hash(
                    record.action_type, record.targets, record.ttl_seconds,
                    record.recovery_mode, record.action_parameters)):
            raise AppApiError("durable_app_api_incident_and_action_required")
        row, contract, params, context = self._resolve(record.identity, record.targets,
                                                       record.action_type, record.action_parameters)
        bindings = record.target_bindings
        if not isinstance(bindings, dict) or set(bindings) != {context["target"]}:
            raise AppApiError("stored_app_api_plan_required")
        plan = bindings[context["target"]]
        if (plan.get("executor") != self.name or plan.get("identity") != record.identity
                or plan.get("action_type") != record.action_type or plan.get("parameters") != params
                or plan.get("config_sha256") != _digest(row.model_dump())):
            raise AppApiError("approved_app_api_contract_changed_reapproval_required")
        headers = self._headers(row)
        _, current = self._read(row, contract, context, headers)
        approved = plan.get("resource")
        if current != approved:
            raise AppApiError("app_api_resource_changed_reapproval_required")
        if check_state and self._desired(contract, current):
            raise AppApiError("app_api_desired_state_already_present")
        return row, contract, params, context, headers, current

    def validate_record(self, record):
        try:
            self._validate(record)
            return None
        except (AppApiError, httpx.HTTPError, AttributeError, TypeError, ValueError) as exc:
            return str(exc) if isinstance(exc, AppApiError) else "app_api_validation_unavailable"

    def _approval_context(self, record, target, approved_by):
        now = time.time()
        if (record.action_type in {"UNLOCK_ACCOUNT", "ENABLE_FEATURE"}
                and not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", getattr(record, "recovery_of", "") or "")):
            raise AppApiError("app_api_restoration_requires_verified_parent")
        if (record.state != "EXECUTING" or not record.requires_approval
                or not record.approved_by or approved_by != record.approved_by
                or not store_mod.approval_valid(record, now=now)
                or not (_instant(record.approval_requested_at) <= _instant(record.approved_at)
                        <= _instant(record.action_started_at) <= now)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", record.remediation_id)
                or target not in record.targets
                or (record.evidence or {}).get("targets", {}).get(target)
                   != record.target_bindings.get(target)):
            raise AppApiError("app_api_requires_durable_manual_approval_and_evidence")

    def execute_record(self, record, target, approved_by=None):
        action = getattr(record, "action_type", "UNKNOWN")
        # Controller must first durably claim an unexpired manual approval.
        try:
            self._approval_context(record, target, approved_by)
            row, contract, params, context, headers, before = self._validate(record)
            started = time.time()
            context["expires_at"] = datetime.fromtimestamp(
                started + params.get("duration_seconds", 0), timezone.utc).isoformat()
            body = _render(contract.body, context)
            key = _digest([record.remediation_id, target, action])
            headers = {**headers, "Idempotency-Key": key, "If-Match": before["version"]}
            path = _render(contract.path, context)
            # A slow preflight GET can consume the approval window. Check again
            # after all reads and immediately before the single mutation request.
            self._approval_context(record, target, approved_by)
        except (AppApiError, httpx.HTTPError, AttributeError, TypeError, ValueError) as exc:
            reason = str(exc) if isinstance(exc, AppApiError) else "app_api_precondition_failed"
            return blocked(action, target, reason)
        try:
            # Exactly one mutation request. No fallback endpoint or transport retry.
            response = self._request(row, contract.method, path, headers=headers, json=body)
            if not 200 <= response.status_code < 300:
                raise AppApiError("app_api_mutation_not_confirmed")
            document, after = self._read(row, contract, context, self._headers(row))
            rb = contract.readback
            if (_field(document, rb.action_field) != action or not self._desired(contract, after)
                    or after["version"] == before["version"]):
                raise AppApiError("app_api_effect_not_verified")
            if rb.idempotency_field and _field(document, rb.idempotency_field) != key:
                raise AppApiError("app_api_operation_identity_mismatch")
            if action == "LOCK_ACCOUNT":
                expiry = _instant(_field(document, rb.expires_at_field))
                # A backend-enforced expiry is mandatory; no silent permanent locks.
                if expiry <= started or expiry > started + params["duration_seconds"] + 5:
                    raise AppApiError("app_api_lock_expiry_not_bounded")
                after["lock_expires_at"] = datetime.fromtimestamp(expiry, timezone.utc).isoformat()
            after["action_type"] = action
            after["operation_key"] = key
            return succeeded(action, target, "app_api_effect_verified", before=before, after=after)
        except (AppApiError, httpx.HTTPError, ValueError, TypeError):
            return ExecutionResult(action, target, "UNKNOWN", False,
                                   "app_api_mutation_outcome_unknown_manual_review_required", before=before)
