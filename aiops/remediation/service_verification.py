"""Read-only service recovery checks, independent of executor effect verification.

Only operator-authored exact-identity profiles select URLs, PromQL and thresholds.
An action receipt is never proof of service recovery. Multiple fresh health AND
metric observations after the action are required before service recovery time exists.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import time
import threading
from functools import wraps
from typing import Literal
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, model_validator
import yaml

import store as states

CONFIG_ENV = "REMEDIATION_SERVICE_VERIFICATION_PATH"
ELIGIBLE = frozenset({states.VERIFIED, states.RECOVERY_PENDING,
                     states.RECOVERY_APPROVAL_REQUIRED, states.RECOVERED})
IDENTITY_FIELDS = frozenset(states.IDENTITY_FIELDS)
_verification_lock = threading.RLock()  # Same single-process constraint as RecordStore.


def _serialized(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        with _verification_lock:
            return fn(*args, **kwargs)
    return wrapped


class VerificationError(ValueError):
    pass


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class HealthCheck(StrictModel):
    url: str
    expected_status: int = Field(default=200, ge=200, le=299)
    json_equals: dict = Field(min_length=1)
    token_env: str | None = None


class MetricCheck(StrictModel):
    name: str = Field(min_length=1, max_length=64)
    query: str = Field(min_length=1, max_length=4096)
    # PromQL expressions timestamp their *evaluation*. A separate timestamp()
    # query is required to prove freshness of underlying scraped observations.
    freshness_query: str = Field(min_length=1, max_length=4096)
    minimum: float | None = None
    maximum: float | None = None
    max_age_seconds: int = Field(default=60, ge=1, le=300)

    @model_validator(mode="after")
    def bounds(self):
        if self.minimum is None and self.maximum is None:
            raise ValueError("metric threshold required")
        for value in (self.minimum, self.maximum):
            if value is not None and not math.isfinite(value):
                raise ValueError("finite metric threshold required")
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError("metric bounds reversed")
        return self


class ServiceProfile(StrictModel):
    identity: dict[str, str]
    health: HealthCheck
    prometheus_url: str
    metrics: list[MetricCheck] = Field(min_length=1, max_length=8)
    prometheus_token_env: str | None = None
    allow_insecure_http: bool = False
    consecutive_samples: int = Field(default=3, ge=2, le=10)
    min_interval_seconds: int = Field(default=10, ge=1, le=120)
    timeout_seconds: int = Field(default=600, ge=10, le=3600)
    request_timeout_seconds: int = Field(default=3, ge=1, le=10)


class VerificationConfig(StrictModel):
    version: Literal[1]
    profiles: list[ServiceProfile] = Field(max_length=100)


def _timestamp(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.timestamp() if parsed.tzinfo else None
    except (ValueError, TypeError, OverflowError):
        return None


def _iso(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def _digest(profile):
    body = json.dumps(profile.model_dump(), sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(body.encode()).hexdigest()


def _url(value, allow_http, base=False):
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in ({"https", "http"} if allow_http else {"https"})
                or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or parsed.port == 0
                or "\\" in value or any(ord(c) < 33 for c in value)
                or (base and parsed.path not in ("", "/"))):
            raise ValueError()
    except (ValueError, TypeError):
        raise VerificationError("invalid_service_check_url") from None
    return value.rstrip("/") if base else value


def _profile(identity, config_path=None):
    path = config_path or os.getenv(CONFIG_ENV)
    if not path:
        return None
    try:
        config = VerificationConfig.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
        seen = set()
        found = None
        for row in config.profiles:
            if (set(row.identity) != IDENTITY_FIELDS
                    or any(not v.strip() or v != v.strip() or v.lower() == "unknown"
                           for v in row.identity.values())):
                raise ValueError()
            key = tuple(sorted(row.identity.items()))
            if key in seen:
                raise ValueError()
            seen.add(key)
            _url(row.health.url, row.allow_insecure_http)
            _url(row.prometheus_url, row.allow_insecure_http, base=True)
            for name in (row.health.token_env, row.prometheus_token_env):
                if name and not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", name):
                    raise ValueError()
            if len({m.name for m in row.metrics}) != len(row.metrics):
                raise ValueError()
            if row.identity == identity:
                found = row
        return found
    except (OSError, ValueError, TypeError, yaml.YAMLError):
        raise VerificationError("invalid_service_verification_config") from None


def plan_record(record, config_path=None):
    """Pin the operator profile before approval; never accept check URLs from RCA."""
    try:
        row = _profile(record.identity, config_path)
        if row is None:
            return {"state": "UNCONFIGURED", "reason": "service_profile_required", "consecutive": 0}
        return {"state": "PENDING", "profile_sha256": _digest(row), "consecutive": 0,
                "required_samples": row.consecutive_samples}
    except VerificationError as exc:
        return {"state": "BLOCKED", "reason": str(exc), "consecutive": 0}


def _headers(token_env):
    result = {"Accept": "application/json"}
    if token_env:
        token = os.getenv(token_env, "")
        if not token or token != token.strip() or any(c in token for c in ("\r", "\n")):
            raise VerificationError("service_check_credential_unavailable")
        result["Authorization"] = "Bearer " + token
    return result


def _get(client, url, timeout, token_env=None, params=None):
    # No redirects, ambient proxies, mutations or URLs supplied by an event/LLM.
    with client.stream("GET", url, params=params, headers=_headers(token_env),
                       timeout=timeout, follow_redirects=False) as response:
        if response.status_code != 200:
            raise VerificationError("service_check_http_failed")
        body = bytearray()
        for chunk in response.iter_bytes():
            body.extend(chunk)
            if len(body) > 65536:
                raise VerificationError("service_check_response_too_large")
        try:
            return response.status_code, json.loads(body)
        except (ValueError, TypeError):
            raise VerificationError("service_check_invalid_json") from None


def _contains(actual, expected):
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(k in actual and _contains(actual[k], v)
                                                for k, v in expected.items())
    return type(actual) is type(expected) and actual == expected


def _save(store, record, expected_state, **fields):
    store.update_if_state(record.remediation_id, expected_state, **fields)
    # A failed flush rolls the store back to copied records. Do not return the
    # mutated, detached object as a durably confirmed recovery.
    return store.get(record.remediation_id) or record


def _query(template, record):
    if "__CONTAINER_ID__" not in template:
        return template
    container_id = None
    if record.action_type in {"RECREATE", "ROLLBACK"} and len(record.results) == 1:
        container_id = (record.results[0].get("after") or {}).get("container_id")
    elif len(record.targets) == 1:
        binding = record.target_bindings.get(record.targets[0], {})
        container_id = (binding.get("container") or {}).get("container_id")
    if not isinstance(container_id, str) or not re.fullmatch(r"[a-f0-9]{64}", container_id):
        raise VerificationError("service_metric_container_identity_required")
    return template.replace("__CONTAINER_ID__", container_id)


def _observe(profile, now, action_at, previous_timestamps, client, record):
    code, health = _get(client, profile.health.url, profile.request_timeout_seconds,
                        profile.health.token_env)
    if code != profile.health.expected_status or not _contains(health, profile.health.json_equals):
        raise VerificationError("service_health_not_ready")
    samples = {}
    for metric in profile.metrics:
        observed = []
        for query in (metric.query, metric.freshness_query):
            _, body = _get(client, profile.prometheus_url.rstrip("/") + "/api/v1/query",
                           profile.request_timeout_seconds, profile.prometheus_token_env,
                           params={"query": _query(query, record), "time": str(now)})
            try:
                results = body["data"]["result"]
                if (body["status"] != "success" or body["data"]["resultType"] != "vector"
                        or not isinstance(results, list) or len(results) != 1):
                    raise ValueError()
                raw_ts, raw_value = results[0]["value"]
                if isinstance(raw_ts, bool) or isinstance(raw_value, bool):
                    raise ValueError()
                ts, value = float(raw_ts), float(raw_value)
                if not math.isfinite(ts) or not math.isfinite(value):
                    raise ValueError()
                if not 0 <= now - ts <= metric.max_age_seconds:
                    raise ValueError()
                observed.append(value)
            except (KeyError, TypeError, ValueError, IndexError):
                raise VerificationError("service_metric_missing_or_ambiguous") from None
        value, ts = observed  # Freshness query's value is a scrape timestamp.
        if (ts < action_at or not 0 <= now - ts <= metric.max_age_seconds
                or ts <= previous_timestamps.get(metric.name, float("-inf"))):
            raise VerificationError("service_metric_not_fresh")
        if ((metric.minimum is not None and value < metric.minimum)
                or (metric.maximum is not None and value > metric.maximum)):
            raise VerificationError("service_metric_out_of_bounds")
        samples[metric.name] = {"value": value, "timestamp": ts}
    return samples


@_serialized
def verify_record(store, record, now=None, config_path=None, client=None):
    """Read-only checks; failures never alter action state or trigger another action."""
    record = store.get(record.remediation_id) or record
    expected_state = record.state
    use_wall_clock = now is None
    now = time.time() if use_wall_clock else now
    if (record.state not in ELIGIBLE or not record.action_verified_at
            or not record.results or not all(r.get("verified") and r.get("status") == "SUCCESS"
                                            for r in record.results)):
        return record
    verification = dict(record.service_verification or {})
    if verification.get("state") in {"RECOVERED", "HEALTHY_INTERMEDIATE", "TIMEOUT", "BLOCKED", "UNCONFIGURED"}:
        return record
    action_at = _timestamp(record.action_verified_at)
    alert_at = _timestamp(record.alert_active_at)
    if action_at is None or alert_at is None or action_at < alert_at or now < action_at:
        verification.update(state="BLOCKED", reason="service_verification_invalid_timing", consecutive=0)
        return _save(store, record, expected_state, service_verification=verification)
    try:
        profile = _profile(record.identity, config_path)
        if profile is None or verification.get("profile_sha256") != _digest(profile):
            raise VerificationError("service_profile_changed_reapproval_required")
        if now >= action_at + profile.timeout_seconds:
            verification.update(state="TIMEOUT", reason="service_recovery_not_confirmed", consecutive=0)
            return _save(store, record, expected_state, service_verification=verification)
        last = verification.get("last_checked_at")
        if last is not None and now - last < profile.min_interval_seconds:
            return record
        prior = {k: v["timestamp"] for k, v in verification.get("metrics", {}).items()}
        if client is None:
            with httpx.Client(trust_env=False, follow_redirects=False) as own_client:
                samples = _observe(profile, now, action_at, prior, own_client, record)
        else:
            samples = _observe(profile, now, action_at, prior, client, record)
        confirmed_now = time.time() if use_wall_clock else now
        if (confirmed_now >= action_at + profile.timeout_seconds
                or any(confirmed_now - samples[m.name]["timestamp"] > m.max_age_seconds for m in profile.metrics)):
            verification.update(state="TIMEOUT", reason="service_check_window_elapsed", consecutive=0)
            return _save(store, record, expected_state, service_verification=verification)
        count = verification.get("consecutive", 0) + 1
        verification.update(state="CHECKING", consecutive=count, last_checked_at=confirmed_now,
                            metrics=samples, health_verified=True)
        verification.pop("reason", None)
        # Record confirmation time after the stable observation window, never
        # the receipt time of a command or an earlier effect verification.
        if count >= profile.consecutive_samples:
            if record.plan_steps and record.plan_step < len(record.plan_steps) - 1:
                verification.update(state="HEALTHY_INTERMEDIATE")
                return _save(store, record, expected_state, service_verification=verification)
            recovered_at = confirmed_now
            verification.update(state="RECOVERED", verified_at=_iso(recovered_at))
            return _save(store, record, expected_state, service_verification=verification,
                         service_recovered_at=_iso(recovered_at))
    except (VerificationError, httpx.HTTPError, ValueError, TypeError) as exc:
        reason = str(exc) if isinstance(exc, VerificationError) else "service_check_unavailable"
        # Do not store URLs, credentials, raw response bodies or exception text.
        config_blocked = reason in {"service_profile_changed_reapproval_required", "invalid_service_verification_config"}
        verification.update(state="BLOCKED" if config_blocked else "CHECKING", reason=reason, consecutive=0, last_checked_at=now,
                            health_verified=False)
    return _save(store, record, expected_state, service_verification=verification)


def run_due(store, now=None):
    return [verify_record(store, record, now=now) for record in store.all()
            if record.state in ELIGIBLE and not record.service_recovered_at]
