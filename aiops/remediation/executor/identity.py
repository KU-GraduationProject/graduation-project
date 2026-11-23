"""Operator-verified observation -> execution bindings; never infer a local target.

The configuration is read before approval and again before mutation. A changed
configuration, Agent, image or container invalidates the original approval.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import Field, ValidationError
import yaml

from agent.contract import ObservationIdentity, StrictModel, Target

FIELDS = ("site", "service", "source", "runtime", "target")
UNKNOWN = {"", "unknown", "none", "n/a", "stdout", "stderr"}


class IdentityError(ValueError):
    pass


class TargetBinding(StrictModel):
    identity: ObservationIdentity
    executor: Literal["remote", "local_docker"]
    agent_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    agent_url: str = ""
    container: Target


class BindingConfig(StrictModel):
    version: Literal[1]
    bindings: list[TargetBinding]


def normalized_identity(identity):
    if not isinstance(identity, dict) or any(
        not isinstance(identity.get(k), str) or identity[k].strip().lower() in UNKNOWN
        or identity[k] != identity[k].strip() for k in FIELDS
    ):
        raise IdentityError("missing_or_ambiguous_identity")
    try:
        parsed = ObservationIdentity.model_validate({k: identity[k] for k in FIELDS})
    except ValidationError:
        raise IdentityError("invalid_observation_identity") from None
    if parsed.runtime != "container":
        raise IdentityError("host_executor_not_implemented")
    return parsed.model_dump()


def configured_bindings():
    path = os.getenv("REMEDIATION_TARGET_BINDINGS_PATH", "")
    if not path:
        raise IdentityError("target_bindings_not_configured")
    try:
        config = BindingConfig.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
    except (OSError, ValueError, yaml.YAMLError):
        raise IdentityError("invalid_target_bindings_config") from None
    # One source maps to one execution host. Duplicate rows may never pick the
    # first match or silently route observations to a second PC.
    hosts = {}
    keys = set()
    for binding in config.bindings:
        identity = normalized_identity(binding.identity.model_dump())
        key = tuple(identity[k] for k in FIELDS)
        if key in keys:
            raise IdentityError("ambiguous_target_binding")
        keys.add(key)
        source = (identity["site"], identity["source"])
        host = (binding.executor, binding.agent_id, binding.agent_url)
        if source in hosts and hosts[source] != host:
            raise IdentityError("ambiguous_agent_mapping")
        hosts[source] = host
        labels = binding.container.labels
        if (labels.get("io.leafy.remediation") != "workload"
                or not labels.get("com.docker.compose.project")
                or labels.get("com.docker.compose.service") != identity["service"]
                or identity["service"] not in ("backend", "frontend", "minio")):
            raise IdentityError("unsafe_target_binding")
        if binding.executor == "remote":
            from urllib.parse import urlsplit
            url = urlsplit(binding.agent_url)
            if (url.scheme != "https" or not url.hostname or not url.hostname.endswith(".ts.net")
                    or url.username or url.password or url.query or url.fragment
                    or url.path not in ("", "/")):
                raise IdentityError("invalid_agent_origin")
        elif binding.agent_url:
            raise IdentityError("local_binding_cannot_have_agent_url")
    return config.bindings


def _configured(identity, targets, executor):
    identity = normalized_identity(identity)
    if list(targets or ()) != [identity["target"]]:
        raise IdentityError("action_targets_do_not_match_observation")
    candidates = [b for b in configured_bindings() if b.identity.model_dump() == identity]
    if len(candidates) != 1:
        raise IdentityError("unmapped_observation_target")
    binding = candidates[0]
    if binding.executor != getattr(executor, "name", None):
        raise IdentityError("executor_mapping_mismatch")
    if binding.executor == "remote" and (
        binding.agent_url.rstrip("/") != getattr(executor, "base_url", None)
    ):
        raise IdentityError("agent_mapping_mismatch")
    return binding


def configured_target_binding(identity, targets, executor):
    """Return only the operator mapping, without inspecting or mutating Docker."""
    return _configured(identity, targets, executor).model_dump()


def snapshot_matches(binding, snapshot):
    expected = binding["container"]
    if not isinstance(snapshot, dict) or snapshot.get("available") is not True:
        return "target_snapshot_unavailable"
    if (snapshot.get("container_id") != expected["container_id"]
            or snapshot.get("image_id") != expected["image_id"]
            or snapshot.get("container_name") != binding["identity"]["target"]
            or any((snapshot.get("labels") or {}).get(k) != v for k, v in expected["labels"].items())):
        return "target_replaced_or_identity_changed_reapproval_required"
    return None


def bind_targets(identity, targets, executor):
    if not getattr(executor, "changes_system", True):
        return {}
    binding = _configured(identity, targets, executor)
    document = binding.model_dump()
    try:
        snapshot = executor.snapshot(identity["target"])
    except Exception:
        raise IdentityError("target_snapshot_unavailable") from None
    if binding.executor == "remote" and (
        snapshot.get("agent_id") != binding.agent_id or snapshot.get("identity") != document["identity"]
    ):
        raise IdentityError("agent_observation_identity_mismatch")
    reason = snapshot_matches(document, snapshot)
    if reason:
        raise IdentityError(reason)
    return {identity["target"]: document}


def validate_bindings(record, executor):
    if not getattr(executor, "changes_system", True):
        return None
    try:
        current = bind_targets(record.identity, record.targets, executor)
        if current != record.target_bindings:
            return "approved_target_binding_changed_reapproval_required"
        if any(record.action_type not in row["container"]["actions"] for row in current.values()):
            return "action_not_allowed_by_target_binding"
    except (IdentityError, AttributeError):
        return "target_binding_validation_failed"
    return None
